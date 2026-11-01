package db

// db_plan_v4_migration_test.go proves migration 0043 ("Pin Haiku") on
// POPULATED databases, the same way db_plan_v3_migration_test.go proves 0041:
//
//   - v4 = v3 with only the route pin moved to the Claude Haiku 5.5 route;
//   - every assignment on an older free / plus_beta version that is IN FORCE
//     moves to v4, a not-yet-started one is repointed in place;
//   - v1/v2/v3 plan rows stay byte-for-byte (v3 still pins GPT-6 Luna);
//   - an estate jumping 38 -> head in ONE runner transaction lands on v4.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const haikuRoute = "session_enrichment.claude-haiku-5-5.v1"

func checkV4Catalogue(ctx context.Context, t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	for _, name := range []string{"free", "plus_beta"} {
		v3, v4 := readPlan(ctx, t, pool, name, 3), readPlan(ctx, t, pool, name, 4)
		if !routeIs(v4.route, haikuRoute) {
			t.Fatalf("%s v4 route = %v, want %s", name, v4.route, haikuRoute)
		}
		if !routeIs(v3.route, gpt6LunaRoute) {
			t.Fatalf("%s v3 route = %v, want the historical %s (v3 is immutable)", name, v3.route, gpt6LunaRoute)
		}
		// Everything but the route is copied from v3.
		v4.route, v3.route = nil, nil
		if v4 != v3 {
			t.Fatalf("%s v4 = %+v, want v3's columns %+v with only the route moved", name, v4, v3)
		}
	}
	if f, p := readPlan(ctx, t, pool, "free", 4), readPlan(ctx, t, pool, "plus_beta", 4); f.daily != 100 || f.monthly != 3000 || p.daily != 500 || p.monthly != 15000 {
		t.Fatalf("v4 caps free %d/%d plus %d/%d, want 100/3000 and 500/15000", f.daily, f.monthly, p.daily, p.monthly)
	}
}

func TestPopulatedMigration42To43MovesAssignmentsToV4(t *testing.T) {
	pool := newThrowawayDB(t, "sbci_planv4_")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	if err := migratePrefix(ctx, pool, 42); err != nil {
		t.Fatalf("migrate to 42: %v", err)
	}
	plusV3, freeV3 := planID(ctx, t, pool, "plus_beta", 3), planID(ctx, t, pool, "free", 3)
	plusV2 := planID(ctx, t, pool, "plus_beta", 2)

	started := time.Now().UTC().Add(-48 * time.Hour)
	boundary := time.Now().UTC().Add(240 * time.Hour)
	histFrom, histUntil := started.Add(-96*time.Hour), started

	plusPlain := newAccount(ctx, t, pool)     // plus v3, open
	plusScheduled := newAccount(ctx, t, pool) // plus v3 until boundary, free v3 scheduled after
	freeExplicit := newAccount(ctx, t, pool)  // free v3, open
	withHistory := newAccount(ctx, t, pool)   // plus v2 closed history, then free v3 open
	unassigned := newAccount(ctx, t, pool)    // no row: resolves the code default

	insertAssignment(ctx, t, pool, plusPlain, plusV3, started, nil)
	insertAssignment(ctx, t, pool, plusScheduled, plusV3, started, &boundary)
	insertAssignment(ctx, t, pool, plusScheduled, freeV3, boundary, nil)
	insertAssignment(ctx, t, pool, freeExplicit, freeV3, started, nil)
	insertAssignment(ctx, t, pool, withHistory, plusV2, histFrom, &histUntil)
	insertAssignment(ctx, t, pool, withHistory, freeV3, started, nil)

	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate 42 -> head over populated account_plans: %v", err)
	}
	checkV4Catalogue(ctx, t, pool)

	for acct, want := range map[string]string{
		plusPlain: "plus_beta", plusScheduled: "plus_beta", freeExplicit: "free", withHistory: "free",
	} {
		if name, version := inForcePlan(ctx, t, pool, acct); name != want || version != 4 {
			t.Fatalf("account %s is on %s v%d, want %s v4", acct, name, version, want)
		}
	}
	var rows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM account_plans WHERE account_id=$1::uuid`, unassigned).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("unassigned account rows = %d err=%v, want 0", rows, err)
	}

	// The pending downgrade lands on free v4 at the unchanged boundary, and the
	// moved Plus row keeps that boundary as its end.
	var until *time.Time
	if err := pool.QueryRow(ctx,
		`SELECT ap.effective_until FROM account_plans ap JOIN plans p ON p.plan_id = ap.plan_id
		  WHERE ap.account_id = $1::uuid AND p.name='plus_beta' AND p.version=4`, plusScheduled).Scan(&until); err != nil {
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
	if pendingVersion != 4 || !sameMillis(pendingFrom, boundary) {
		t.Fatalf("pending downgrade = free v%d from %v, want free v4 from %v", pendingVersion, pendingFrom, boundary)
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
}

// TestPopulatedMigration38ToHeadInOneTransactionLandsOnV4: 0039 opens v2 rows
// at now(), 0041 repoints them to v3 (same now()), and 0043 must repoint them
// again to v4 in the same runner transaction.
func TestPopulatedMigration38ToHeadInOneTransactionLandsOnV4(t *testing.T) {
	pool := newThrowawayDB(t, "sbci_planv4jump_")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	if err := migratePrefix(ctx, pool, 38); err != nil {
		t.Fatalf("migrate to 38: %v", err)
	}
	acct := newAccount(ctx, t, pool)
	insertAssignment(ctx, t, pool, acct, planID(ctx, t, pool, "plus_beta", 1), time.Now().UTC().Add(-48*time.Hour), nil)

	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate 38 -> head in one transaction: %v", err)
	}
	if name, version := inForcePlan(ctx, t, pool, acct); name != "plus_beta" || version != 4 {
		t.Fatalf("subscriber is on %s v%d after 38 -> head, want plus_beta v4", name, version)
	}
	var stale int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM account_plans ap JOIN plans p ON p.plan_id = ap.plan_id
		  WHERE ap.account_id = $1::uuid AND p.version IN (2, 3)`, acct).Scan(&stale); err != nil || stale != 0 {
		t.Fatalf("rows still on a v2/v3 plan = %d err=%v, want 0", stale, err)
	}
	checkV4Catalogue(ctx, t, pool)
}
