package db

// db_plan_v3_migration_test.go proves migration 0041 (D-299) on POPULATED
// databases, the same way db_plan_v2_migration_test.go proves 0039:
//
//   - every assignment on an older free / plus_beta version that is IN FORCE
//     moves to v3 (close + open at now(), source and end preserved);
//   - an assignment that has NOT STARTED (a scheduled cycle-boundary
//     downgrade) is repointed to the v3 row of the same name in place;
//   - closed history is untouched, and the v1/v2 plan rows stay byte-for-byte;
//   - an estate jumping 38 -> 41 in ONE runner transaction (where 0039's v2
//     rows start at exactly the same now()) still lands on v3.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const gpt6LunaRoute = "session_enrichment.gpt-6-luna.v1"

// inForcePlan returns the (name, version) in force for acct right now.
func inForcePlan(ctx context.Context, t *testing.T, pool *pgxpool.Pool, acct string) (string, int) {
	t.Helper()
	var name string
	var version int
	if err := pool.QueryRow(ctx,
		`SELECT p.name, p.version FROM account_plans ap JOIN plans p ON p.plan_id = ap.plan_id
		  WHERE ap.account_id = $1::uuid AND ap.effective_from <= now()
		    AND (ap.effective_until IS NULL OR ap.effective_until > now())
		  ORDER BY ap.effective_from DESC LIMIT 1`, acct).Scan(&name, &version); err != nil {
		t.Fatalf("resolve in-force plan for %s: %v", acct, err)
	}
	return name, version
}

func planID(ctx context.Context, t *testing.T, pool *pgxpool.Pool, name string, version int) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(ctx, `SELECT plan_id::text FROM plans WHERE name=$1 AND version=$2`, name, version).Scan(&id); err != nil {
		t.Fatalf("read %s v%d plan_id: %v", name, version, err)
	}
	return id
}

func newAccount(ctx context.Context, t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(ctx, `INSERT INTO accounts DEFAULT VALUES RETURNING account_id::text`).Scan(&id); err != nil {
		t.Fatalf("insert account: %v", err)
	}
	return id
}

func insertAssignment(ctx context.Context, t *testing.T, pool *pgxpool.Pool, acct, plan string, from time.Time, until *time.Time) {
	t.Helper()
	if _, err := pool.Exec(ctx,
		`INSERT INTO account_plans (account_id, plan_id, effective_from, effective_until, source)
		 VALUES ($1::uuid, $2::uuid, $3, $4, 'paddle')`, acct, plan, from, until); err != nil {
		t.Fatalf("insert assignment: %v", err)
	}
}

func sameMillis(a, b time.Time) bool {
	return a.UTC().Round(time.Millisecond).Equal(b.UTC().Round(time.Millisecond))
}

// planRow is one plans row as the v3 checks read it.
type planRow struct {
	daily, monthly, conc, retention int
	digest                          bool
	pool, label                     string
	route                           *string
}

func readPlan(ctx context.Context, t *testing.T, pool *pgxpool.Pool, name string, version int) planRow {
	t.Helper()
	var r planRow
	if err := pool.QueryRow(ctx,
		`SELECT daily_cap, monthly_cap, concurrency_cap, results_retention_days, digest_weekly, budget_pool, label, route_id
		   FROM plans WHERE name=$1 AND version=$2`, name, version).
		Scan(&r.daily, &r.monthly, &r.conc, &r.retention, &r.digest, &r.pool, &r.label, &r.route); err != nil {
		t.Fatalf("read %s v%d: %v", name, version, err)
	}
	return r
}

func routeIs(r *string, want string) bool { return r != nil && *r == want }

// checkV3Catalogue pins the v3 rows (the ruled caps, the GPT-6 Luna pin,
// everything else copied from v2) and that v2 was not touched.
func checkV3Catalogue(ctx context.Context, t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	free3, plus3 := readPlan(ctx, t, pool, "free", 3), readPlan(ctx, t, pool, "plus_beta", 3)
	if free3 != (planRow{100, 3000, 2, free3.retention, free3.digest, "free", "Signed-in Free", free3.route}) {
		t.Fatalf("free v3 = %+v, want 100/3000/2 pool free label Signed-in Free", free3)
	}
	if plus3 != (planRow{500, 15000, 4, 365, true, "plus_beta", "Plus", plus3.route}) {
		t.Fatalf("plus v3 = %+v, want 500/15000/4 retention 365 digest pool plus_beta label Plus", plus3)
	}
	if !routeIs(free3.route, gpt6LunaRoute) || !routeIs(plus3.route, gpt6LunaRoute) {
		t.Fatalf("v3 route pins = free %v plus %v, want %s on both", free3.route, plus3.route, gpt6LunaRoute)
	}
	// Plan rows are immutable: v2 is still exactly what 0039 published.
	plus2, free2 := readPlan(ctx, t, pool, "plus_beta", 2), readPlan(ctx, t, pool, "free", 2)
	if plus2.daily != 25 || plus2.monthly != 120 || !routeIs(plus2.route, "session_enrichment.sol.v1") {
		t.Fatalf("plus v2 changed: %+v", plus2)
	}
	if free2.daily != 20 || free2.monthly != 100 || free2.route != nil {
		t.Fatalf("free v2 changed: %+v", free2)
	}
}

// gpt6Route is the route_registry facts checkGPT6LunaRoute compares.
type gpt6Route struct {
	active, pinned                            bool
	endpoint, apiVersion, deployment, dialect string
	priceVersion                              string
	routeVersion, promptVersion               int64
	maxOut                                    int
	inPrice, outPrice                         float64
}

// checkGPT6LunaRoute pins the new route: inactive, unbound, NOT plan-pinned
// (a default candidate), route_version 2, the shipped price snapshot, its kill
// switch - and that luna.v1 is untouched and still the live default.
func checkGPT6LunaRoute(ctx context.Context, t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	var r gpt6Route
	if err := pool.QueryRow(ctx,
		`SELECT active, plan_pinned, endpoint, api_version, deployment, dialect, price_version,
		        route_version, prompt_version, max_output_tokens, input_price_per_mtok, output_price_per_mtok
		   FROM route_registry WHERE route_id = $1`, gpt6LunaRoute).
		Scan(&r.active, &r.pinned, &r.endpoint, &r.apiVersion, &r.deployment, &r.dialect, &r.priceVersion,
			&r.routeVersion, &r.promptVersion, &r.maxOut, &r.inPrice, &r.outPrice); err != nil {
		t.Fatalf("read gpt-6 luna route: %v", err)
	}
	want := gpt6Route{
		deployment: "gpt-6-luna", dialect: "chat_completions", priceVersion: "unset",
		routeVersion: 2, promptVersion: 1, maxOut: 1024, inPrice: 0.10, outPrice: 0.50, // 1024: D-313 / T-414
	}
	if r != want {
		t.Fatalf("gpt-6 luna route = %+v, want %+v (inactive, unpinned, unbound)", r, want)
	}
	var switches int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM kill_switches WHERE scope='route' AND key=$1 AND active=false`, gpt6LunaRoute).
		Scan(&switches); err != nil || switches != 1 {
		t.Fatalf("gpt-6 luna kill switch rows = %d err=%v, want exactly 1 (inactive)", switches, err)
	}
	var lunaActive bool
	var lunaDeployment string
	if err := pool.QueryRow(ctx,
		`SELECT active, deployment FROM route_registry WHERE route_id='session_enrichment.luna.v1'`).
		Scan(&lunaActive, &lunaDeployment); err != nil {
		t.Fatalf("read luna.v1: %v", err)
	}
	if !lunaActive || lunaDeployment != "luna" {
		t.Fatalf("luna.v1 = active:%v deployment:%q, want untouched (active, luna)", lunaActive, lunaDeployment)
	}
}

func TestPopulatedMigration40To41MovesAssignmentsToV3(t *testing.T) {
	pool := newThrowawayDB(t, "sbci_planv3_")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	if err := migratePrefix(ctx, pool, 40); err != nil {
		t.Fatalf("migrate to 40: %v", err)
	}
	plusV1, plusV2 := planID(ctx, t, pool, "plus_beta", 1), planID(ctx, t, pool, "plus_beta", 2)
	freeV1, freeV2 := planID(ctx, t, pool, "free", 1), planID(ctx, t, pool, "free", 2)

	started := time.Now().UTC().Add(-48 * time.Hour)
	boundary := time.Now().UTC().Add(240 * time.Hour)
	histFrom, histUntil := started.Add(-96*time.Hour), started

	plusPlain := newAccount(ctx, t, pool)     // plus v2, open
	plusScheduled := newAccount(ctx, t, pool) // plus v2 until boundary, free v2 scheduled after
	plusLegacy := newAccount(ctx, t, pool)    // plus v1, open (a purchase on a v1 price)
	freeExplicit := newAccount(ctx, t, pool)  // free v2, open (post-0039 cancellation)
	freeV1Acct := newAccount(ctx, t, pool)    // plus v1 history, closed; then free v1 open
	unassigned := newAccount(ctx, t, pool)    // no row: resolves the code default

	insertAssignment(ctx, t, pool, plusPlain, plusV2, started, nil)
	insertAssignment(ctx, t, pool, plusScheduled, plusV2, started, &boundary)
	insertAssignment(ctx, t, pool, plusScheduled, freeV2, boundary, nil)
	insertAssignment(ctx, t, pool, plusLegacy, plusV1, started, nil)
	insertAssignment(ctx, t, pool, freeExplicit, freeV2, started, nil)
	insertAssignment(ctx, t, pool, freeV1Acct, plusV1, histFrom, &histUntil) // closed history
	insertAssignment(ctx, t, pool, freeV1Acct, freeV1, started, nil)

	if err := migratePrefix(ctx, pool, 41); err != nil {
		t.Fatalf("migrate 40 -> 41 over populated account_plans: %v", err)
	}
	checkV3Catalogue(ctx, t, pool)
	checkGPT6LunaRoute(ctx, t, pool)

	// Every assigned account is in force on v3 of its own plan.
	for acct, want := range map[string]string{
		plusPlain: "plus_beta", plusScheduled: "plus_beta", plusLegacy: "plus_beta",
		freeExplicit: "free", freeV1Acct: "free",
	} {
		if name, version := inForcePlan(ctx, t, pool, acct); name != want || version != 3 {
			t.Fatalf("account %s is on %s v%d, want %s v3", acct, name, version, want)
		}
	}
	// The unassigned account gained no row (it resolves DefaultFreePlanVersion).
	var rows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM account_plans WHERE account_id=$1::uuid`, unassigned).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("unassigned account rows = %d err=%v, want 0", rows, err)
	}

	// The scheduled account: the moved row ends at the preserved boundary, and
	// the pending downgrade now lands on free v3 (repointed in place, same
	// start), so nothing overlaps.
	var until *time.Time
	if err := pool.QueryRow(ctx,
		`SELECT ap.effective_until FROM account_plans ap JOIN plans p ON p.plan_id = ap.plan_id
		  WHERE ap.account_id = $1::uuid AND p.name='plus_beta' AND p.version=3`, plusScheduled).Scan(&until); err != nil {
		t.Fatalf("read moved scheduled row: %v", err)
	}
	if until == nil || !sameMillis(*until, boundary) {
		t.Fatalf("moved scheduled row ends at %v, want the preserved boundary %v", until, boundary)
	}
	var pendingVersion int
	var pendingFrom time.Time
	if err := pool.QueryRow(ctx,
		`SELECT p.version, ap.effective_from FROM account_plans ap JOIN plans p ON p.plan_id = ap.plan_id
		  WHERE ap.account_id = $1::uuid AND p.name='free'`, plusScheduled).Scan(&pendingVersion, &pendingFrom); err != nil {
		t.Fatalf("read pending downgrade: %v", err)
	}
	if pendingVersion != 3 || !sameMillis(pendingFrom, boundary) {
		t.Fatalf("pending downgrade = free v%d from %v, want free v3 from the unchanged boundary %v", pendingVersion, pendingFrom, boundary)
	}

	// Closed history is untouched: the plus v1 window still reads plus v1 with
	// its original end.
	var histVersion int
	var gotUntil time.Time
	if err := pool.QueryRow(ctx,
		`SELECT p.version, ap.effective_until FROM account_plans ap JOIN plans p ON p.plan_id = ap.plan_id
		  WHERE ap.account_id = $1::uuid AND p.name='plus_beta'`, freeV1Acct).Scan(&histVersion, &gotUntil); err != nil {
		t.Fatalf("read history row: %v", err)
	}
	if histVersion != 1 || !sameMillis(gotUntil, histUntil) {
		t.Fatalf("history row = plus v%d until %v, want plus v1 until %v (untouched)", histVersion, gotUntil, histUntil)
	}
	// The source tag survived every move: 5 moved rows + 1 repointed row.
	var paddleRows int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM account_plans ap JOIN plans p ON p.plan_id = ap.plan_id
		  WHERE p.version = 3 AND ap.source = 'paddle'`).Scan(&paddleRows); err != nil || paddleRows != 6 {
		t.Fatalf("v3 rows carrying source=paddle = %d err=%v, want 6 (5 moved + 1 repointed)", paddleRows, err)
	}
}

// TestPopulatedMigration38To41InOneTransactionLandsOnV3 covers the
// same-instant case: the runner applies every pending migration in ONE
// transaction, so 0039's freshly opened v2 rows start at exactly the now()
// 0041 sees. They have not started yet in 0041's eyes, so they must be
// repointed rather than skipped (a strict "< now()" alone would leave a
// subscriber on plus_beta v2 forever).
func TestPopulatedMigration38To41InOneTransactionLandsOnV3(t *testing.T) {
	pool := newThrowawayDB(t, "sbci_planv3jump_")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	if err := migratePrefix(ctx, pool, 38); err != nil {
		t.Fatalf("migrate to 38: %v", err)
	}
	acct := newAccount(ctx, t, pool)
	insertAssignment(ctx, t, pool, acct, planID(ctx, t, pool, "plus_beta", 1), time.Now().UTC().Add(-48*time.Hour), nil)

	if err := migratePrefix(ctx, pool, 41); err != nil {
		t.Fatalf("migrate 38 -> 41 in one transaction: %v", err)
	}
	if name, version := inForcePlan(ctx, t, pool, acct); name != "plus_beta" || version != 3 {
		t.Fatalf("subscriber is on %s v%d after 38 -> 41, want plus_beta v3", name, version)
	}
	var stale int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM account_plans ap JOIN plans p ON p.plan_id = ap.plan_id
		  WHERE ap.account_id = $1::uuid AND p.version = 2`, acct).Scan(&stale); err != nil || stale != 0 {
		t.Fatalf("rows still on a v2 plan = %d err=%v, want 0", stale, err)
	}
}
