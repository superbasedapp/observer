package db

// db_plan_v5_migration_test.go proves migrations 0078 + 0079 (ruling R-AI1,
// enrichment token budgets) on POPULATED databases, the way
// db_plan_v4_migration_test.go proves 0043:
//
//   - v5 = v4 with enrichment_tier set ('free' / 'paid'), every other column
//     copied (the count caps and route stay, inert under a tier, so a binary
//     predating the tier still serves after a rollback);
//   - every assignment on an older free / plus_beta version that is IN FORCE
//     moves to v5, a not-yet-started one is repointed in place;
//   - the two tiers and the gpt-oss-20b route are seeded, the route inactive
//     and plan-pinned, and a published tier row can be neither updated nor
//     deleted.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudtestpg/pgthrow"
)

const gptOSS20bRoute = "session_enrichment.gpt-oss-20b.v1"

func planTier(ctx context.Context, t *testing.T, pool *pgxpool.Pool, name string, version int) *string {
	t.Helper()
	var tier *string
	if err := pool.QueryRow(ctx, `SELECT enrichment_tier FROM plans WHERE name=$1 AND version=$2`, name, version).Scan(&tier); err != nil {
		t.Fatalf("read %s v%d enrichment_tier: %v", name, version, err)
	}
	return tier
}

func checkV5Catalogue(ctx context.Context, t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	for name, wantTier := range map[string]string{"free": "free", "plus_beta": "paid"} {
		v4, v5 := readPlan(ctx, t, pool, name, 4), readPlan(ctx, t, pool, name, 5)
		if !routeIs(v5.route, haikuRoute) || !routeIs(v4.route, haikuRoute) {
			t.Fatalf("%s route pins v4 %v v5 %v, want %s copied (inert under a tier)", name, v4.route, v5.route, haikuRoute)
		}
		v4.route, v5.route = nil, nil
		if v5 != v4 {
			t.Fatalf("%s v5 = %+v, want v4's columns %+v copied", name, v5, v4)
		}
		if got := planTier(ctx, t, pool, name, 5); got == nil || *got != wantTier {
			t.Fatalf("%s v5 enrichment_tier = %v, want %s", name, got, wantTier)
		}
		if got := planTier(ctx, t, pool, name, 4); got != nil {
			t.Fatalf("%s v4 enrichment_tier = %v, want NULL (v4 keeps its count caps)", name, *got)
		}
	}
	for tier, want := range map[string]struct {
		route    string
		evidence int
	}{
		"free": {gptOSS20bRoute, 4000},
		"paid": {"session_enrichment.gpt-oss-120b.v1", 12000},
	} {
		var route string
		var evidence int
		var session, daily, monthly int64
		if err := pool.QueryRow(ctx,
			`SELECT route_id, evidence_token_budget, session_token_budget, daily_token_budget, monthly_token_budget
			   FROM enrichment_tiers WHERE tier=$1 AND version=1`, tier).Scan(&route, &evidence, &session, &daily, &monthly); err != nil {
			t.Fatalf("read tier %s: %v", tier, err)
		}
		if route != want.route || evidence != want.evidence || session <= 0 || daily < session/2 || monthly < daily {
			t.Fatalf("tier %s = %s %d %d/%d/%d", tier, route, evidence, session, daily, monthly)
		}
	}
	var active, pinned bool
	var dialect string
	var maxOut int
	if err := pool.QueryRow(ctx,
		`SELECT active, plan_pinned, dialect, max_output_tokens FROM route_registry WHERE route_id=$1`, gptOSS20bRoute).
		Scan(&active, &pinned, &dialect, &maxOut); err != nil {
		t.Fatalf("read 20b route: %v", err)
	}
	if active || !pinned || dialect != "openai_compatible" || maxOut != 4096 {
		t.Fatalf("20b route active=%v pinned=%v dialect=%s max=%d, want inactive, pinned, openai_compatible, 4096", active, pinned, dialect, maxOut)
	}
}

func TestPopulatedMigration78To79MovesAssignmentsToV5(t *testing.T) {
	pool := pgthrow.NewEmptyDB(t, "sbci_planv5_")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	if err := migratePrefix(ctx, pool, 78); err != nil {
		t.Fatalf("migrate to 78: %v", err)
	}
	plusV4, freeV4 := planID(ctx, t, pool, "plus_beta", 4), planID(ctx, t, pool, "free", 4)
	plusV2 := planID(ctx, t, pool, "plus_beta", 2)

	started := time.Now().UTC().Add(-48 * time.Hour)
	boundary := time.Now().UTC().Add(240 * time.Hour)
	histFrom, histUntil := started.Add(-96*time.Hour), started

	plusPlain := newAccount(ctx, t, pool)
	plusScheduled := newAccount(ctx, t, pool)
	freeExplicit := newAccount(ctx, t, pool)
	withHistory := newAccount(ctx, t, pool)
	unassigned := newAccount(ctx, t, pool)

	insertAssignment(ctx, t, pool, plusPlain, plusV4, started, nil)
	insertAssignment(ctx, t, pool, plusScheduled, plusV4, started, &boundary)
	insertAssignment(ctx, t, pool, plusScheduled, freeV4, boundary, nil)
	insertAssignment(ctx, t, pool, freeExplicit, freeV4, started, nil)
	insertAssignment(ctx, t, pool, withHistory, plusV2, histFrom, &histUntil)
	insertAssignment(ctx, t, pool, withHistory, freeV4, started, nil)

	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate 78 -> head over populated account_plans: %v", err)
	}
	checkV5Catalogue(ctx, t, pool)

	for acct, want := range map[string]string{
		plusPlain: "plus_beta", plusScheduled: "plus_beta", freeExplicit: "free", withHistory: "free",
	} {
		if name, version := inForcePlan(ctx, t, pool, acct); name != want || version != 5 {
			t.Fatalf("account %s is on %s v%d, want %s v5", acct, name, version, want)
		}
	}
	var rows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM account_plans WHERE account_id=$1::uuid`, unassigned).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("unassigned account rows = %d err=%v, want 0", rows, err)
	}

	// The moved Plus row keeps the scheduled boundary as its end, and the
	// pending downgrade lands on free v5 at that boundary.
	var until *time.Time
	if err := pool.QueryRow(ctx,
		`SELECT ap.effective_until FROM account_plans ap JOIN plans p ON p.plan_id = ap.plan_id
		  WHERE ap.account_id = $1::uuid AND p.name='plus_beta' AND p.version=5`, plusScheduled).Scan(&until); err != nil {
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
	if pendingVersion != 5 || !sameMillis(pendingFrom, boundary) {
		t.Fatalf("pending downgrade = free v%d from %v, want free v5 from %v", pendingVersion, pendingFrom, boundary)
	}
	// The closed v4 row of a moved account keeps its source and is closed.
	var closedSource string
	if err := pool.QueryRow(ctx,
		`SELECT ap.source FROM account_plans ap JOIN plans p ON p.plan_id = ap.plan_id
		  WHERE ap.account_id = $1::uuid AND p.version=4 AND ap.effective_until IS NOT NULL`, plusPlain).Scan(&closedSource); err != nil {
		t.Fatalf("read closed v4 row: %v", err)
	}
	if closedSource != "paddle" {
		t.Fatalf("closed v4 row source = %q, want paddle", closedSource)
	}
	// Closed history is untouched.
	var histVersion int
	var gotUntil time.Time
	if err := pool.QueryRow(ctx,
		`SELECT p.version, ap.effective_until FROM account_plans ap JOIN plans p ON p.plan_id = ap.plan_id
		  WHERE ap.account_id = $1::uuid AND p.name='plus_beta'`, withHistory).Scan(&histVersion, &gotUntil); err != nil {
		t.Fatalf("read history row: %v", err)
	}
	if histVersion != 2 || !sameMillis(gotUntil, histUntil) {
		t.Fatalf("history row = plus v%d until %v, want plus v2 until %v (untouched)", histVersion, gotUntil, histUntil)
	}

	// A published tier is immutable: no UPDATE, no DELETE.
	for _, stmt := range []string{
		`UPDATE enrichment_tiers SET evidence_token_budget = 5000 WHERE tier='free' AND version=1`,
		`DELETE FROM enrichment_tiers WHERE tier='free' AND version=1`,
	} {
		if _, err := pool.Exec(ctx, stmt); err == nil || !strings.Contains(err.Error(), "immutable") {
			t.Fatalf("%s: err = %v, want the immutability refusal", stmt, err)
		}
	}
	// A tier can only name a route that exists.
	if _, err := pool.Exec(ctx,
		`INSERT INTO enrichment_tiers (tier, version, route_id, evidence_token_budget, session_token_budget, daily_token_budget, monthly_token_budget)
		 VALUES ('free', 2, 'session_enrichment.no-such-route.v1', 4000, 60000, 250000, 3000000)`); err == nil {
		t.Fatal("a tier naming a missing route was accepted")
	}
}

// TestPopulatedMigration38ToHeadInOneTransactionLandsOnV5: 0039 opens v2 rows
// at now(), 0041 and 0043 repoint them, and 0079 must repoint them once more
// to v5 within the same runner pass.
func TestPopulatedMigration38ToHeadInOneTransactionLandsOnV5(t *testing.T) {
	pool := pgthrow.NewEmptyDB(t, "sbci_planv5jump_")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	if err := migratePrefix(ctx, pool, 38); err != nil {
		t.Fatalf("migrate to 38: %v", err)
	}
	acct := newAccount(ctx, t, pool)
	insertAssignment(ctx, t, pool, acct, planID(ctx, t, pool, "plus_beta", 1), time.Now().UTC().Add(-48*time.Hour), nil)

	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate 38 -> head: %v", err)
	}
	if name, version := inForcePlan(ctx, t, pool, acct); name != "plus_beta" || version != 5 {
		t.Fatalf("subscriber is on %s v%d after 38 -> head, want plus_beta v5", name, version)
	}
	checkV5Catalogue(ctx, t, pool)
}
