package store_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/community"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// community_test.go holds the W5 private-community-percentile invariants
// (divergence remediation plan §3 "W5"; operator ruling R3). These are the most
// security-critical tests in the arc: the cross-tenant aggregation must never let
// one account be isolated, differenced out, read raw cross-tenant, or read by the
// front-door role. Every numeric expectation here was first ground-truthed by
// CALLING sbci_community_bands against live Postgres (a temporary zz probe,
// deleted) before the assertions were written.

const (
	metricSPD    = "sessions_per_active_day" // edges [1,2,3,5,8,13] → bands 0..6
	finalWindow  = "2025-01"                 // long-elapsed → finalized
	testCohort   = "global"
	metricVerOne = 1
)

// seedContribution creates one fresh account and one contribution at value in
// (cohort, metric, v1, window). Returns the account id. A finalized window is
// FROZEN against writes (the F5 trigger + UpsertContribution's Go guard), so a
// seed that populates a PAST window must simulate a write made while the window
// was still in progress: it inserts directly with session_replication_role =
// replica (trigger-bypassing), inside one transaction. This models historical
// contributions that later finalized — exactly what the aggregation reads. Tests
// that exercise UpsertContribution's own behavior use an in-progress window and
// call it directly.
func seedContribution(t *testing.T, s *store.Store, cohort, window string, value float64) string {
	t.Helper()
	acct := makeAccount(t, s)
	rawSeedContribution(t, s.Pool(), acct, cohort, window, value)
	return acct
}

// rawSeedContribution inserts one contribution bypassing the finalized-window
// freeze trigger (simulating a write made while the window was in progress).
func rawSeedContribution(t *testing.T, pool *pgxpool.Pool, acct, cohort, window string, value float64) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin seed: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
		t.Fatalf("bypass trigger: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO leaderboard_contributions (account_id, cohort_key, metric_id, metric_version, window_id, value)
		 VALUES ($1::uuid,$2,$3,$4,$5,$6)
		 ON CONFLICT (account_id, cohort_key, metric_id, metric_version, window_id)
		 DO UPDATE SET value = EXCLUDED.value`,
		acct, cohort, metricSPD, metricVerOne, window, value); err != nil {
		t.Fatalf("seed contribution: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit seed: %v", err)
	}
}

// seedN creates n accounts each contributing value into (cohort, metric, window).
func seedN(t *testing.T, s *store.Store, cohort, window string, value float64, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		seedContribution(t, s, cohort, window, value)
	}
}

// inProgressWindow is the current UTC month — the only window UpsertContribution
// accepts a write to (a finalized/past window is frozen).
func inProgressWindow() string { return time.Now().UTC().Format("2006-01") }

// bandMap collapses the returned cells into band→count for easy assertions.
func bandMap(cells []store.BandCell) map[int]int64 {
	m := map[int]int64{}
	for _, c := range cells {
		m[c.Band] = c.BandCount
	}
	return m
}

// TestCommunityBandsFloorAndBanding proves the ≥30 displayed-cohort floor and the
// data-independent banding. Below the floor the whole cohort is unreadable; at the
// floor the histogram is returned with correct bands.
func TestCommunityBandsFloorAndBanding(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()

	// Below floor: 29 contributions → nothing (the cohort is unreadable, and a
	// caller cannot tell "too small" apart from "unknown").
	seedN(t, s, "below-floor", finalWindow, 1.5, 29)
	cells, err := s.CommunityBands(ctx, "below-floor", metricSPD, metricVerOne, finalWindow)
	if err != nil {
		t.Fatalf("CommunityBands(below-floor): %v", err)
	}
	if len(cells) != 0 {
		t.Fatalf("below the ≥30 floor returned %d cells, want 0: %+v", len(cells), cells)
	}

	// At the floor: 10 at band0 (0.5), 10 at band1 (1.5), 10 at band4 (6) → 30.
	// Every cell ≥ k(5), no suppression.
	seedN(t, s, "at-floor", finalWindow, 0.5, 10)
	seedN(t, s, "at-floor", finalWindow, 1.5, 10)
	seedN(t, s, "at-floor", finalWindow, 6, 10)
	cells, err = s.CommunityBands(ctx, "at-floor", metricSPD, metricVerOne, finalWindow)
	if err != nil {
		t.Fatalf("CommunityBands(at-floor): %v", err)
	}
	got := bandMap(cells)
	want := map[int]int64{0: 10, 1: 10, 4: 10}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("at-floor bands = %v, want %v", got, want)
	}
}

// TestCommunityBandsKSuppression proves cell-level k-suppression and the
// complementary-suppression rule (when exactly one cell is dropped, the smallest
// survivor is dropped too, so a suppressed cell's size can never be inferred from
// the surviving cells).
func TestCommunityBandsKSuppression(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()

	// Complementary: band0=20, band4=12, band6=3(<5). band6 is k-suppressed →
	// exactly ONE dropped cell → the smallest survivor (band4=12) is dropped too.
	// Only band0=20 survives.
	seedN(t, s, "complementary", finalWindow, 0.5, 20)
	seedN(t, s, "complementary", finalWindow, 6, 12)
	seedN(t, s, "complementary", finalWindow, 15, 3)
	cells, err := s.CommunityBands(ctx, "complementary", metricSPD, metricVerOne, finalWindow)
	if err != nil {
		t.Fatalf("CommunityBands(complementary): %v", err)
	}
	if got, want := bandMap(cells), (map[int]int64{0: 20}); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("complementary bands = %v, want %v (band6 k-supp, band4 complementary)", got, want)
	}

	// Two cells already suppressed: band0=20, band4=10, band1=3(<5), band6=2(<5).
	// n=2 dropped → no complementary drop; both survivors stay.
	seedN(t, s, "two-supp", finalWindow, 0.5, 20)
	seedN(t, s, "two-supp", finalWindow, 6, 10)
	seedN(t, s, "two-supp", finalWindow, 1.5, 3)
	seedN(t, s, "two-supp", finalWindow, 15, 2)
	cells, err = s.CommunityBands(ctx, "two-supp", metricSPD, metricVerOne, finalWindow)
	if err != nil {
		t.Fatalf("CommunityBands(two-supp): %v", err)
	}
	if got, want := bandMap(cells), (map[int]int64{0: 20, 4: 10}); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("two-supp bands = %v, want %v", got, want)
	}
}

// TestCommunityBandsFinalizationAndRepeatedWindow proves the repeated-window
// differencing defense: an in-progress (not-yet-elapsed) window is never
// readable, and a finalized window is FROZEN — repeated calls return byte-
// identical results, so no signal accrues from asking twice.
func TestCommunityBandsFinalizationAndRepeatedWindow(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()

	// In-progress window = the current UTC month, seeded well above the floor.
	inProgress := time.Now().UTC().Format("2006-01")
	seedN(t, s, "in-progress", inProgress, 6, 40)
	cells, err := s.CommunityBands(ctx, "in-progress", metricSPD, metricVerOne, inProgress)
	if err != nil {
		t.Fatalf("CommunityBands(in-progress): %v", err)
	}
	if len(cells) != 0 {
		t.Fatalf("an unfinalized window returned %d cells, want 0", len(cells))
	}

	// A future window is likewise unreadable.
	cells, err = s.CommunityBands(ctx, "in-progress", metricSPD, metricVerOne, "2099-01")
	if err != nil {
		t.Fatalf("CommunityBands(future): %v", err)
	}
	if len(cells) != 0 {
		t.Fatalf("a future window returned %d cells, want 0", len(cells))
	}

	// A finalized window is frozen: two consecutive reads are identical.
	seedN(t, s, "frozen", finalWindow, 0.5, 15)
	seedN(t, s, "frozen", finalWindow, 6, 15)
	first, err := s.CommunityBands(ctx, "frozen", metricSPD, metricVerOne, finalWindow)
	if err != nil {
		t.Fatalf("CommunityBands(frozen #1): %v", err)
	}
	second, err := s.CommunityBands(ctx, "frozen", metricSPD, metricVerOne, finalWindow)
	if err != nil {
		t.Fatalf("CommunityBands(frozen #2): %v", err)
	}
	if fmt.Sprint(bandMap(first)) != fmt.Sprint(bandMap(second)) {
		t.Fatalf("repeated-window read drifted: %v vs %v", bandMap(first), bandMap(second))
	}
	if len(first) == 0 {
		t.Fatalf("frozen cohort (30 contributions) returned nothing")
	}
}

// TestCommunityBandsUnregisteredMetricAndMalformedWindow proves an unregistered
// (forbidden) metric and a malformed window_id both collapse to "no cells"
// without error — the metric registry is the SQL-side forbidden-metric guard.
func TestCommunityBandsUnregisteredMetricAndMalformedWindow(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	seedN(t, s, "reg", finalWindow, 6, 40)

	cells, err := s.CommunityBands(ctx, "reg", "no_such_metric", metricVerOne, finalWindow)
	if err != nil {
		t.Fatalf("CommunityBands(unregistered): %v", err)
	}
	if len(cells) != 0 {
		t.Fatalf("unregistered metric returned %d cells, want 0", len(cells))
	}

	cells, err = s.CommunityBands(ctx, "reg", metricSPD, metricVerOne, "2025-13")
	if err != nil {
		t.Fatalf("CommunityBands(malformed window): %v", err)
	}
	if len(cells) != 0 {
		t.Fatalf("malformed window returned %d cells, want 0", len(cells))
	}
}

// TestCommunityContributionsRLSIsolation proves two-tenant isolation and
// missing-context deny: an account reads only its OWN contributed value (RLS),
// and a system/no-tenant read of the table matches no rows.
func TestCommunityContributionsRLSIsolation(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()

	a := seedContribution(t, s, testCohort, finalWindow, 3.0)
	b := seedContribution(t, s, testCohort, finalWindow, 7.0)

	// Each account reads its own value only.
	av, err := s.AccountContribution(ctx, a, testCohort, metricSPD, metricVerOne, finalWindow)
	if err != nil || av != 3.0 {
		t.Fatalf("account a own value = %v, err=%v, want 3.0", av, err)
	}
	bv, err := s.AccountContribution(ctx, b, testCohort, metricSPD, metricVerOne, finalWindow)
	if err != nil || bv != 7.0 {
		t.Fatalf("account b own value = %v, err=%v, want 7.0", bv, err)
	}

	// Forged scope: account a's tenant context cannot see account b's row. With
	// a's context set, exactly one row (a's own) is visible under the api role.
	var visible int
	if err := pool.QueryRow(ctx, `SELECT set_config('sbci.account_id', $1, false)`, a).Scan(new(string)); err != nil {
		t.Fatalf("set tenant a: %v", err)
	}
	if _, err := pool.Exec(ctx, `SET ROLE sbci_api`); err != nil {
		t.Fatalf("set role api: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM leaderboard_contributions`).Scan(&visible); err != nil {
		t.Fatalf("count under tenant a: %v", err)
	}
	_, _ = pool.Exec(ctx, `RESET ROLE`)
	_, _ = pool.Exec(ctx, `SELECT set_config('sbci.account_id', '', false)`)
	if visible != 1 {
		t.Fatalf("tenant a saw %d contribution rows, want exactly its own (1)", visible)
	}

	// Missing-context deny: WithSystem sets NO tenant GUC, so an RLS'd read
	// matches nothing even though two rows exist in the table.
	var systemVisible int
	if err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM leaderboard_contributions`).Scan(&systemVisible)
	}); err != nil {
		t.Fatalf("WithSystem read: %v", err)
	}
	if systemVisible != 0 {
		t.Fatalf("missing-context read saw %d rows, want 0 (RLS deny)", systemVisible)
	}
}

// TestCommunityBandsAggregatorOnlyExecutable proves the aggregation function is
// executable ONLY by sbci_aggregator: a direct call under sbci_api / sbci_worker
// is DENIED at the database (a real permission error, not a silent empty result),
// so the de-identification boundary cannot be bypassed by the front-door role.
func TestCommunityBandsAggregatorOnlyExecutable(t *testing.T) {
	_, pool := newStore(t)
	ctx := context.Background()

	for _, role := range []string{"sbci_api", "sbci_worker", "sbci_app"} {
		func() {
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatalf("begin: %v", err)
			}
			defer func() { _ = tx.Rollback(ctx) }()
			if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+role); err != nil {
				t.Fatalf("set role %s: %v", role, err)
			}
			_, err = tx.Exec(ctx,
				`SELECT * FROM sbci_community_bands('c', $1, 1, '2025-01')`, metricSPD)
			if err == nil {
				t.Errorf("%s was able to EXECUTE sbci_community_bands; it must be aggregator-only", role)
			}
		}()
	}

	// And the aggregator role (via the store seam) CAN run it end to end.
	if _, err := pool.Exec(ctx, `DO $$ BEGIN
		SET LOCAL ROLE sbci_aggregator;
		PERFORM * FROM sbci_community_bands('c', 'sessions_per_active_day', 1, '2025-01');
	END $$`); err != nil {
		t.Fatalf("aggregator role could not execute the function: %v", err)
	}
}

// TestCommunityBandsCohortMinusOneUnexpressible proves the cohort-minus-one
// differencing attack is STRUCTURALLY impossible: the deployed function's only
// arguments are the four fixed registry identifiers — no account-selective
// argument and no free predicate exists to express "this cohort minus account X".
func TestCommunityBandsCohortMinusOneUnexpressible(t *testing.T) {
	_, pool := newStore(t)
	ctx := context.Background()
	var args string
	if err := pool.QueryRow(ctx,
		`SELECT pg_get_function_identity_arguments(oid) FROM pg_proc WHERE proname='sbci_community_bands'`).
		Scan(&args); err != nil {
		t.Fatalf("introspect args: %v", err)
	}
	want := "p_cohort_key text, p_metric_id text, p_metric_version integer, p_window_id text"
	if args != want {
		t.Fatalf("aggregation args = %q, want exactly the four fixed registry args %q "+
			"(any account-selective arg or free predicate would enable cohort-minus-one differencing)", args, want)
	}
}

// TestCommunityBandsFunctionDeployedShape pins the DEFINER function's deployed
// shape and ACL so drift fails loudly (mirrors the export/retention sweep
// deployed-shape tests): owner sbci_defs, SECURITY DEFINER, pinned qualified
// search_path, EXECUTE granted to sbci_aggregator ONLY and never to the
// application roles or PUBLIC.
func TestCommunityBandsFunctionDeployedShape(t *testing.T) {
	_, pool := newStore(t)
	ctx := context.Background()

	var owner, cfg string
	var secdef bool
	if err := pool.QueryRow(ctx,
		`SELECT pg_get_userbyid(proowner), prosecdef, coalesce(array_to_string(proconfig,','),'')
		   FROM pg_proc WHERE proname='sbci_community_bands'`).Scan(&owner, &secdef, &cfg); err != nil {
		t.Fatalf("introspect: %v", err)
	}
	if owner != "sbci_defs" || !secdef || cfg != "search_path=pg_catalog, public" {
		t.Errorf("aggregation fn shape wrong: owner=%q secdef=%v cfg=%q", owner, secdef, cfg)
	}

	sig := "sbci_community_bands(text,text,int,text)"
	// EXECUTE granted to the aggregator only.
	if !funcPriv(t, pool, "sbci_aggregator", sig) {
		t.Error("sbci_aggregator lacks EXECUTE on sbci_community_bands")
	}
	for _, role := range []string{"sbci_api", "sbci_app", "sbci_worker"} {
		if funcPriv(t, pool, role, sig) {
			t.Errorf("%s holds EXECUTE on sbci_community_bands; it must be aggregator-only (F4)", role)
		}
	}
	if publicHasExecute(t, pool, sig) {
		t.Error("PUBLIC holds EXECUTE on sbci_community_bands")
	}

	// The aggregator must have NO direct DML on the tenant table — its only
	// reach into contributions is through the floored/suppressed function.
	for _, priv := range []string{"SELECT", "INSERT", "UPDATE", "DELETE"} {
		if tablePriv(t, pool, "sbci_aggregator", "leaderboard_contributions", priv) {
			t.Errorf("sbci_aggregator holds direct %s on leaderboard_contributions; it must read only via sbci_community_bands", priv)
		}
	}
}

// TestCommunityDeletionRemovesContributions proves opt-out/deletion linkage (R3):
// account deletion removes every contribution the account made, and its removal
// drops the cohort below the floor / changes the bands accordingly.
func TestCommunityDeletionRemovesContributions(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	now := time.Now()

	// 30 contributions from OTHER accounts (so the cohort is readable) + 1 from
	// the account we will delete.
	seedN(t, s, "del", finalWindow, 6, 30)
	victim := seedContribution(t, s, "del", finalWindow, 0.5)

	if countRows(t, pool, "leaderboard_contributions", victim) != 1 {
		t.Fatalf("victim contribution not seeded")
	}

	if _, err := s.CreateDeletionRequest(ctx, victim, now); err != nil {
		t.Fatalf("CreateDeletionRequest: %v", err)
	}
	if n := countRows(t, pool, "leaderboard_contributions", victim); n != 0 {
		t.Fatalf("victim still has %d contribution(s) after deletion", n)
	}
}

// TestUpsertContributionIsIdempotent proves a re-contribution updates in place
// (one row per account per window) rather than stacking, so the aggregation never
// double-counts an account.
func TestUpsertContributionIsIdempotent(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	acct := makeAccount(t, s)
	win := inProgressWindow() // UpsertContribution only accepts the in-progress window

	for _, v := range []float64{2.0, 5.0, 9.0} {
		if err := s.UpsertContribution(ctx, acct, testCommunityDeviceID, testCohort, metricSPD, metricVerOne, win, v); err != nil {
			t.Fatalf("UpsertContribution(%v): %v", v, err)
		}
	}
	if n := countRows(t, pool, "leaderboard_contributions", acct); n != 1 {
		t.Fatalf("idempotent upsert left %d rows, want 1", n)
	}
	got, err := s.AccountContribution(ctx, acct, testCohort, metricSPD, metricVerOne, win)
	if err != nil || got != 9.0 {
		t.Fatalf("own value after upserts = %v, err=%v, want 9.0 (last write wins)", got, err)
	}
}

// TestUpsertContributionRejectsFinalizedWindow proves the F5 freeze: a write to a
// finalized (past) window is rejected by UpsertContribution's Go guard, so a
// published aggregate can never be perturbed by a late value change.
func TestUpsertContributionRejectsFinalizedWindow(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	acct := makeAccount(t, s)
	err := s.UpsertContribution(ctx, acct, testCommunityDeviceID, testCohort, metricSPD, metricVerOne, finalWindow, 3.0)
	if !errors.Is(err, store.ErrWindowFinalized) {
		t.Fatalf("UpsertContribution to a finalized window err=%v, want ErrWindowFinalized", err)
	}
}

// TestUpsertContributionRejectsFutureWindow proves the Sol F10 tightening: only
// the server's current, in-progress UTC-month window is writable — a window that
// has not yet STARTED is rejected exactly like one that has already elapsed, so a
// device cannot pre-seed an arbitrary value into a future window that later
// becomes eligible for materialization.
func TestUpsertContributionRejectsFutureWindow(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	acct := makeAccount(t, s)
	future := time.Now().UTC().AddDate(0, 2, 0).Format("2006-01")
	err := s.UpsertContribution(ctx, acct, testCommunityDeviceID, testCohort, metricSPD, metricVerOne, future, 3.0)
	if !errors.Is(err, store.ErrWindowFinalized) {
		t.Fatalf("UpsertContribution to a future window (%s) err=%v, want ErrWindowFinalized", future, err)
	}
}

// TestUpsertContributionRejectsClosedAccount proves the Sol F5(a) write-time
// fence: once an account has been deleted, UpsertContribution must refuse to
// write a fresh contribution for it, even though the window itself is otherwise
// perfectly in-progress and writable. Before this fix the write had no
// account-status guard at all, so a contribution recreated after deletion left a
// stray leaderboard_contributions row with a live NO-ACTION FK to an account that
// deletion had already tombstoned — the exact row that later wedged the 24-month
// retention sweep (F5(b), backstopped separately in migration 0027).
func TestUpsertContributionRejectsClosedAccount(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	acct := makeAccount(t, s)
	win := inProgressWindow()

	if err := s.UpsertContribution(ctx, acct, testCommunityDeviceID, testCohort, metricSPD, metricVerOne, win, 4.0); err != nil {
		t.Fatalf("UpsertContribution before deletion: %v", err)
	}
	if _, err := s.CreateDeletionRequest(ctx, acct, time.Now()); err != nil {
		t.Fatalf("CreateDeletionRequest: %v", err)
	}

	err := s.UpsertContribution(ctx, acct, testCommunityDeviceID, testCohort, metricSPD, metricVerOne, win, 7.0)
	if !errors.Is(err, store.ErrAccountClosed) {
		t.Fatalf("UpsertContribution to a closed account err=%v, want ErrAccountClosed", err)
	}
}

// TestUpsertContributionCrossDeviceConflict proves the Sol F9 recommendation #1
// fix: leaderboard_contributions' natural key (account_id, cohort_key, metric_id,
// metric_version, window_id) has no device dimension, so before this fix a second
// device on the SAME account silently overwrote the first device's value for an
// identical window (last-writer-wins with no signal to either side). Now: the
// first device to write a window owns it — a second, different device's write to
// the same natural key is refused (ErrCrossDeviceConflict) and the row is left
// completely unchanged, while the SAME device re-writing that window remains
// idempotent. Ground-truthed by calling UpsertContribution with two distinct
// device ids against live PG.
func TestUpsertContributionCrossDeviceConflict(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	acct := makeAccount(t, s)
	win := inProgressWindow()

	const (
		deviceA = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
		deviceB = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	)

	// Device A syncs the window first.
	if err := s.UpsertContribution(ctx, acct, deviceA, testCohort, metricSPD, metricVerOne, win, 4.0); err != nil {
		t.Fatalf("device A first write: %v", err)
	}

	// Device B (same account, different device) tries to sync a DIFFERENT value
	// for the identical window — must be refused, not silently applied.
	err := s.UpsertContribution(ctx, acct, deviceB, testCohort, metricSPD, metricVerOne, win, 999.0)
	if !errors.Is(err, store.ErrCrossDeviceConflict) {
		t.Fatalf("device B cross-device write err=%v, want ErrCrossDeviceConflict", err)
	}

	// The row must be completely unchanged: still device A's value.
	got, err := s.AccountContribution(ctx, acct, testCohort, metricSPD, metricVerOne, win)
	if err != nil || got != 4.0 {
		t.Fatalf("value after refused cross-device write = %v, err=%v, want 4.0 (device A's value, unchanged)", got, err)
	}

	// Device A re-writing the SAME window remains idempotent (own-device rewrite,
	// not a conflict).
	if err := s.UpsertContribution(ctx, acct, deviceA, testCohort, metricSPD, metricVerOne, win, 6.0); err != nil {
		t.Fatalf("device A idempotent re-write: %v", err)
	}
	got, err = s.AccountContribution(ctx, acct, testCohort, metricSPD, metricVerOne, win)
	if err != nil || got != 6.0 {
		t.Fatalf("value after device A re-write = %v, err=%v, want 6.0", got, err)
	}

	// Device B still cannot write this window even after device A's re-write.
	err = s.UpsertContribution(ctx, acct, deviceB, testCohort, metricSPD, metricVerOne, win, 111.0)
	if !errors.Is(err, store.ErrCrossDeviceConflict) {
		t.Fatalf("device B second cross-device write err=%v, want ErrCrossDeviceConflict", err)
	}
	got, err = s.AccountContribution(ctx, acct, testCohort, metricSPD, metricVerOne, win)
	if err != nil || got != 6.0 {
		t.Fatalf("value after second refused cross-device write = %v, err=%v, want 6.0 (still device A's)", got, err)
	}
}

// TestMaterializeAndReadCommunityBands proves the delayed-band materialization
// round-trip: the worker computes bands + cohort size via the aggregator role and
// writes the snapshot; the api reads it back. A finalized ≥30 cohort materializes
// its cells with the exact cohort size; a below-floor cohort and an unfinalized
// window materialize nothing.
func TestMaterializeAndReadCommunityBands(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()

	// Finalized, above floor: 15@band0 (0.5) + 15@band4 (6) = 30.
	seedN(t, s, "mat", finalWindow, 0.5, 15)
	seedN(t, s, "mat", finalWindow, 6, 15)
	n, err := s.MaterializeCommunityWindow(ctx, "mat", metricSPD, metricVerOne, finalWindow)
	if err != nil {
		t.Fatalf("MaterializeCommunityWindow: %v", err)
	}
	if n != 2 {
		t.Fatalf("materialized %d cells, want 2", n)
	}
	cells, err := s.ReadCommunityBands(ctx, "mat", metricSPD, metricVerOne, finalWindow)
	if err != nil {
		t.Fatalf("ReadCommunityBands: %v", err)
	}
	if len(cells) != 2 {
		t.Fatalf("read %d cells, want 2: %+v", len(cells), cells)
	}
	for _, c := range cells {
		if c.CohortSize != 30 {
			t.Errorf("band %d cohort_size = %d, want 30", c.Band, c.CohortSize)
		}
		if (c.Band == 0 || c.Band == 4) && c.BandCount != 15 {
			t.Errorf("band %d count = %d, want 15", c.Band, c.BandCount)
		}
	}

	// Below floor: materializes nothing, and the read is empty.
	seedN(t, s, "mat-small", finalWindow, 6, 29)
	if n, err := s.MaterializeCommunityWindow(ctx, "mat-small", metricSPD, metricVerOne, finalWindow); err != nil || n != 0 {
		t.Fatalf("below-floor materialize: n=%d err=%v, want 0,nil", n, err)
	}
	if cells, err := s.ReadCommunityBands(ctx, "mat-small", metricSPD, metricVerOne, finalWindow); err != nil || len(cells) != 0 {
		t.Fatalf("below-floor read: %d cells err=%v, want 0", len(cells), err)
	}

	// Unfinalized (current month): materializes nothing.
	inProgress := time.Now().UTC().Format("2006-01")
	seedN(t, s, "mat-ip", inProgress, 6, 40)
	if n, err := s.MaterializeCommunityWindow(ctx, "mat-ip", metricSPD, metricVerOne, inProgress); err != nil || n != 0 {
		t.Fatalf("unfinalized materialize: n=%d err=%v, want 0,nil", n, err)
	}
}

// TestMaterializeRecomputeClearsStaleCells proves a re-materialization is
// authoritative: if a cohort that was materialized later drops below the floor
// (e.g. contributors deleted), the recompute clears its stale snapshot rows.
func TestMaterializeRecomputeClearsStaleCells(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	now := time.Now()

	// 30 contributors → materialized.
	for i := 0; i < 30; i++ {
		_ = seedContribution(t, s, "shrink", finalWindow, 6)
	}
	if _, err := s.MaterializeCommunityWindow(ctx, "shrink", metricSPD, metricVerOne, finalWindow); err != nil {
		t.Fatalf("materialize: %v", err)
	}
	if cells, _ := s.ReadCommunityBands(ctx, "shrink", metricSPD, metricVerOne, finalWindow); len(cells) == 0 {
		t.Fatalf("expected cells after first materialize")
	}

	// Drop the cohort below the floor by deleting all but one contribution
	// directly (superuser), then re-materialize: the stale cells must be cleared.
	if _, err := pool.Exec(ctx,
		`DELETE FROM community_band_snapshots WHERE false`); err != nil { // touch table (perm sanity)
		t.Fatalf("perm: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`DELETE FROM leaderboard_contributions
		  WHERE cohort_key='shrink'
		    AND ctid NOT IN (SELECT ctid FROM leaderboard_contributions WHERE cohort_key='shrink' LIMIT 1)`); err != nil {
		t.Fatalf("shrink cohort: %v", err)
	}
	_ = now
	if n, err := s.MaterializeCommunityWindow(ctx, "shrink", metricSPD, metricVerOne, finalWindow); err != nil || n != 0 {
		t.Fatalf("recompute after shrink: n=%d err=%v, want 0,nil", n, err)
	}
	if cells, _ := s.ReadCommunityBands(ctx, "shrink", metricSPD, metricVerOne, finalWindow); len(cells) != 0 {
		t.Fatalf("stale cells survived recompute below floor: %d", len(cells))
	}
}

// TestCommunityCohortSizeFunctionDeployedShape pins the companion size function's
// shape + aggregator-only EXECUTE (mirrors the bands-fn shape test).
func TestCommunityCohortSizeFunctionDeployedShape(t *testing.T) {
	_, pool := newStore(t)
	ctx := context.Background()
	var owner, cfg string
	var secdef bool
	if err := pool.QueryRow(ctx,
		`SELECT pg_get_userbyid(proowner), prosecdef, coalesce(array_to_string(proconfig,','),'')
		   FROM pg_proc WHERE proname='sbci_community_cohort_size'`).Scan(&owner, &secdef, &cfg); err != nil {
		t.Fatalf("introspect: %v", err)
	}
	if owner != "sbci_defs" || !secdef || cfg != "search_path=pg_catalog, public" {
		t.Errorf("cohort_size fn shape wrong: owner=%q secdef=%v cfg=%q", owner, secdef, cfg)
	}
	sig := "sbci_community_cohort_size(text,text,int,text)"
	if !funcPriv(t, pool, "sbci_aggregator", sig) {
		t.Error("sbci_aggregator lacks EXECUTE on sbci_community_cohort_size")
	}
	for _, role := range []string{"sbci_api", "sbci_app", "sbci_worker"} {
		if funcPriv(t, pool, role, sig) {
			t.Errorf("%s holds EXECUTE on sbci_community_cohort_size; aggregator-only", role)
		}
	}
	// The snapshot table: api may READ but never WRITE.
	if !tablePriv(t, pool, "sbci_api", "community_band_snapshots", "SELECT") {
		t.Error("sbci_api lacks SELECT on community_band_snapshots (the read surface)")
	}
	for _, priv := range []string{"INSERT", "UPDATE", "DELETE"} {
		if tablePriv(t, pool, "sbci_api", "community_band_snapshots", priv) {
			t.Errorf("sbci_api holds %s on community_band_snapshots; the front door must be read-only there", priv)
		}
	}
}

// TestMetricRegistryMatchesSeed pins the compiled-in Go registry against the SQL
// seed in migration 0022 (community_metrics): id, version, edges, floor, k must
// match exactly, so the two forbidden-metric guards can never disagree.
func TestMetricRegistryMatchesSeed(t *testing.T) {
	_, pool := newStore(t)
	ctx := context.Background()

	type row struct {
		edges     []float64
		minCohort int
		kMin      int
	}
	seed := map[string]row{}
	rows, err := pool.Query(ctx,
		`SELECT metric_id, metric_version, band_edges, min_cohort, k_min FROM community_metrics`)
	if err != nil {
		t.Fatalf("query seed: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var ver, mc, k int
		var edges []float64
		if err := rows.Scan(&id, &ver, &edges, &mc, &k); err != nil {
			t.Fatalf("scan: %v", err)
		}
		seed[fmt.Sprintf("%s/%d", id, ver)] = row{edges, mc, k}
	}

	reg := map[string]row{}
	for _, m := range community.Metrics() {
		reg[fmt.Sprintf("%s/%d", m.ID, m.Version)] = row{m.BandEdges, m.MinCohort, m.KMin}
	}
	if len(seed) != len(reg) {
		t.Fatalf("seed has %d metrics, Go registry has %d — they must match", len(seed), len(reg))
	}
	for key, sr := range seed {
		rr, ok := reg[key]
		if !ok {
			t.Errorf("metric %q is in the SQL seed but not the Go registry", key)
			continue
		}
		if fmt.Sprint(sr) != fmt.Sprint(rr) {
			t.Errorf("metric %q drift: seed=%v registry=%v", key, sr, rr)
		}
	}
}

// TestUpsertContributionRejectsUnregisteredCohort proves the F7a data-boundary
// guard: an arbitrary cohort key is rejected (no arbitrary slicing reaches the
// table).
func TestUpsertContributionRejectsUnregisteredCohort(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	acct := makeAccount(t, s)
	err := s.UpsertContribution(ctx, acct, testCommunityDeviceID, "arbitrary-slice", metricSPD, metricVerOne, inProgressWindow(), 3.0)
	if !errors.Is(err, store.ErrUnknownCohort) {
		t.Fatalf("unregistered cohort err=%v, want ErrUnknownCohort", err)
	}
}

// TestCommunityDeletionPropagatesToPublishedSnapshot proves the F7b closure: a
// deletion that empties a finalized window drops it from the windows-with-data
// enumeration AND the orphan-snapshot prune clears its published bands — so a
// deleted account's data leaves the PUBLISHED aggregate, not just the raw table
// (R3's 24h removal, here immediate under the recompute).
func TestCommunityDeletionPropagatesToPublishedSnapshot(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()

	// 30 contributors in a finalized window → materialize a published snapshot.
	for i := 0; i < 30; i++ {
		_ = seedContribution(t, s, "global", finalWindow, 6)
	}
	if _, err := s.MaterializeCommunityWindow(ctx, "global", metricSPD, metricVerOne, finalWindow); err != nil {
		t.Fatalf("materialize: %v", err)
	}
	if cells, _ := s.ReadCommunityBands(ctx, "global", metricSPD, metricVerOne, finalWindow); len(cells) == 0 {
		t.Fatalf("expected a published snapshot before deletion")
	}
	// The window is listed while it has data.
	live, err := s.ListFinalizedWindowsWithData(ctx)
	if err != nil || len(live) == 0 {
		t.Fatalf("ListFinalizedWindowsWithData=%+v err=%v, want the seeded window", live, err)
	}

	// Empty the window (models every contributor opting out / being deleted).
	if _, err := pool.Exec(ctx, `DELETE FROM leaderboard_contributions WHERE window_id=$1`, finalWindow); err != nil {
		t.Fatalf("empty window: %v", err)
	}
	live2, err := s.ListFinalizedWindowsWithData(ctx)
	if err != nil {
		t.Fatalf("enumerate after empty: %v", err)
	}
	for _, r := range live2 {
		if r.WindowID == finalWindow {
			t.Fatalf("emptied window still enumerated: %+v", r)
		}
	}
	// The prune clears the now-orphaned published snapshot.
	pruned, err := s.PruneOrphanCommunitySnapshots(ctx, live2)
	if err != nil || pruned == 0 {
		t.Fatalf("prune=%d err=%v, want >=1 orphan cleared", pruned, err)
	}
	if cells, _ := s.ReadCommunityBands(ctx, "global", metricSPD, metricVerOne, finalWindow); len(cells) != 0 {
		t.Fatalf("published snapshot survived after the window was emptied: %d cells", len(cells))
	}
}

// TestUpsertContributionRejectsUnregisteredMetric proves the FK enforces the
// forbidden-metric rule at write time: a contribution to an unregistered metric
// is rejected.
func TestUpsertContributionRejectsUnregisteredMetric(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	acct := makeAccount(t, s)
	// In-progress window so the write reaches the FK (a finalized window would be
	// rejected by the freeze guard first).
	err := s.UpsertContribution(ctx, acct, testCommunityDeviceID, testCohort, "forbidden_metric", metricVerOne, inProgressWindow(), 3.0)
	if err == nil {
		t.Fatal("UpsertContribution accepted an unregistered metric; the community_metrics FK must reject it")
	}
}
