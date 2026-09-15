package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// The W4 entitlement-plan suite (cloud-intelligence divergence remediation plan
// §3 W4, operator ruling R4). It pins the two LIVE conflicts the plan named
// (review finding 12): the cap consulted by a reservation must re-resolve on a
// plan change, and each plan draws from its OWN budget pool.

func poolBalance(t *testing.T, pool *pgxpool.Pool, name string) int64 {
	t.Helper()
	var used int64
	if err := pool.QueryRow(context.Background(),
		`SELECT used FROM budget_pools WHERE pool = $1`, name).Scan(&used); err != nil {
		t.Fatalf("read budget pool %s: %v", name, err)
	}
	return used
}

// midMonth is an anchor safely inside a calendar month, so "the next cycle
// boundary" is unambiguous and a test that runs at UTC midnight on the 1st does
// not accidentally straddle a rollover (repo memory: the UTC-midnight test
// class).
func midMonth() time.Time { return time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC) }

// TestPlanResolutionDefaultsToFree pins absence-means-free: an account with no
// account_plans row resolves the seeded free v1 plan, which is why migration
// 0012 needs no backfill for accounts that predate it.
func TestPlanResolutionDefaultsToFree(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	acct := makeAccount(t, s)

	a, err := s.ResolveAllowance(ctx, acct, store.FeatureSessionEnrichment, midMonth())
	if err != nil {
		t.Fatalf("ResolveAllowance: %v", err)
	}
	if a.Plan.Name != store.PlanFree || a.Plan.Version != store.DefaultFreePlanVersion {
		t.Fatalf("default plan = %s v%d, want %s v%d",
			a.Plan.Name, a.Plan.Version, store.PlanFree, store.DefaultFreePlanVersion)
	}
	// Migration 0039 raised the free daily burst 5 -> 20 in the v2 row;
	// the monthly ceiling and concurrency are unchanged.
	if a.DailyCap != 20 || a.MonthlyCap != 100 || a.ConcurrencyCap != 2 {
		t.Fatalf("free caps = %d/%d/%d, want 20/100/2", a.DailyCap, a.MonthlyCap, a.ConcurrencyCap)
	}
	if a.Plan.RouteID != "" {
		t.Fatalf("free plan route_id = %q, want empty (the feature default route)", a.Plan.RouteID)
	}
	if a.BudgetPool != "free" {
		t.Fatalf("free plan pool = %q, want %q", a.BudgetPool, "free")
	}
	if a.Overridden {
		t.Fatal("a freshly-seeded entitlements row must NOT override the plan")
	}
}

// TestMidCycleUpgradeRaisesConsultedCapImmediately is the review-finding-12 fix
// for usage_cycles' snapshotted cap: the 21st daily reservation is refused on
// free (v2 cap 20), and after an upgrade — with the SAME daily counter still at
// 20, mid-window — it succeeds against the plus_beta cap of 25.
//
// It also pins that a purchase takes effect IMMEDIATELY. Plus v2 is strictly
// more generous than free v2 on every axis (25/120/4 against 20/100/2), so the
// cap comparison classifies it as an upgrade with no special case. If a future
// plan revision ever set a paid cap BELOW the free one, that comparison would
// read the purchase as a downgrade and defer it to the next cycle boundary -
// this test is what would catch it.
func TestMidCycleUpgradeRaisesConsultedCapImmediately(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	acct := makeAccount(t, s)
	now := midMonth()

	for i := 0; i < 20; i++ {
		if _, err := s.ReserveAllowance(ctx, acct, store.FeatureSessionEnrichment, now); err != nil {
			t.Fatalf("reserve %d on free: %v", i+1, err)
		}
		// Free the concurrency slot (cap 2) so the DAILY window is what binds.
		var rid string
		if err := pool.QueryRow(ctx,
			`SELECT id::text FROM usage_reservations WHERE account_id=$1::uuid AND state='reserved'
			  ORDER BY created_at DESC LIMIT 1`, acct).Scan(&rid); err != nil {
			t.Fatalf("find reservation: %v", err)
		}
		if err := s.SettleReservation(ctx, acct, rid); err != nil {
			t.Fatalf("settle: %v", err)
		}
	}
	if _, err := s.ReserveAllowance(ctx, acct, store.FeatureSessionEnrichment, now); !errors.Is(err, store.ErrDailyLimit) {
		t.Fatalf("21st reservation on free = %v, want ErrDailyLimit", err)
	}

	res, err := s.AssignPlan(ctx, acct, store.PlanPlusBeta, store.LatestPlanVersion, time.Time{}, now)
	if err != nil {
		t.Fatalf("AssignPlan: %v", err)
	}
	if res.Deferred {
		t.Fatal("an UPGRADE must take effect mid-cycle, not be deferred")
	}
	if res.EffectiveFrom.After(now) {
		t.Fatalf("upgrade effective_from = %s, want no later than now (%s)", res.EffectiveFrom, now)
	}

	// Same day, same monthly window, counter still at 20 — the CAP moved.
	if _, err := s.ReserveAllowance(ctx, acct, store.FeatureSessionEnrichment, now); err != nil {
		t.Fatalf("21st reservation after upgrade: %v, want success", err)
	}
	snap, err := s.Usage(ctx, acct, store.FeatureSessionEnrichment, now)
	if err != nil {
		t.Fatalf("Usage: %v", err)
	}
	if snap.DailyUsed != 21 || snap.DailyCap != 25 {
		t.Fatalf("after upgrade: daily %d/%d, want 21/25 (counter keeps counting, ceiling moves)",
			snap.DailyUsed, snap.DailyCap)
	}
	// Ruling 2026-09-15 (W5 hosted contract): Plus is a real purchasable plan
	// now, so the label was updated from the stale "entitlement simulation"
	// copy (migration 0037) to the plain "Plus" — this assertion follows that
	// ruling rather than the superseded R4 wording.
	if snap.Plan != store.PlanPlusBeta || snap.PlanLabel != "Plus" {
		t.Fatalf("plan surface = %q / %q, want plus_beta / \"Plus\"", snap.Plan, snap.PlanLabel)
	}
}

// TestDowngradeDefersToCycleEnd pins the other half of R4: a plan change that
// LOWERS any cap is floored at the next monthly cycle boundary, enforced on the
// assignment write. The running plan stays in force until then.
func TestDowngradeDefersToCycleEnd(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	acct := makeAccount(t, s)
	now := midMonth()

	if _, err := s.AssignPlan(ctx, acct, store.PlanPlusBeta, store.LatestPlanVersion, time.Time{}, now); err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	down, err := s.AssignPlan(ctx, acct, store.PlanFree, store.LatestPlanVersion, time.Time{}, now)
	if err != nil {
		t.Fatalf("downgrade: %v", err)
	}
	if !down.Deferred {
		t.Fatal("a downgrade must be deferred to the cycle boundary")
	}
	boundary := store.NextMonthlyCycleStart(now)
	if !down.EffectiveFrom.Equal(boundary) {
		t.Fatalf("downgrade effective_from = %s, want the next cycle start %s", down.EffectiveFrom, boundary)
	}

	// Still Plus right now, and still Plus one second before the boundary.
	for _, at := range []time.Time{now, boundary.Add(-time.Second)} {
		a, err := s.ResolveAllowance(ctx, acct, store.FeatureSessionEnrichment, at)
		if err != nil {
			t.Fatalf("ResolveAllowance at %s: %v", at, err)
		}
		if a.Plan.Name != store.PlanPlusBeta {
			t.Fatalf("at %s the plan is %s, want plus_beta until the cycle ends", at, a.Plan.Name)
		}
	}
	// At the boundary the downgrade is in force.
	a, err := s.ResolveAllowance(ctx, acct, store.FeatureSessionEnrichment, boundary)
	if err != nil {
		t.Fatalf("ResolveAllowance at boundary: %v", err)
	}
	if a.Plan.Name != store.PlanFree || a.DailyCap != 20 {
		t.Fatalf("at the boundary: plan %s cap %d, want free / 20", a.Plan.Name, a.DailyCap)
	}
	// A caller cannot backdate a downgrade past the boundary either.
	acct2 := makeAccount(t, s)
	if _, err := s.AssignPlan(ctx, acct2, store.PlanPlusBeta, store.LatestPlanVersion, time.Time{}, now); err != nil {
		t.Fatalf("upgrade acct2: %v", err)
	}
	forced, err := s.AssignPlan(ctx, acct2, store.PlanFree, store.LatestPlanVersion, now.Add(time.Hour), now)
	if err != nil {
		t.Fatalf("downgrade with an explicit early effective_from: %v", err)
	}
	if !forced.EffectiveFrom.Equal(boundary) {
		t.Fatalf("an explicit mid-cycle downgrade date was honoured (%s); it must be floored to %s",
			forced.EffectiveFrom, boundary)
	}
}

// TestPlusDrawsItsOwnBudgetPool pins R4's "Plus's OWN budget pool, never the
// free pool": a Plus reservation increments plus_beta and leaves free untouched.
func TestPlusDrawsItsOwnBudgetPool(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	acct := makeAccount(t, s)
	now := midMonth()

	freeBefore, plusBefore := poolBalance(t, pool, "free"), poolBalance(t, pool, "plus_beta")
	if _, err := s.ReserveAllowance(ctx, acct, store.FeatureSessionEnrichment, now); err != nil {
		t.Fatalf("reserve on free: %v", err)
	}
	if got := poolBalance(t, pool, "free"); got != freeBefore+1 {
		t.Fatalf("free pool = %d, want %d (a free reservation draws the free pool)", got, freeBefore+1)
	}
	if got := poolBalance(t, pool, "plus_beta"); got != plusBefore {
		t.Fatalf("plus_beta pool moved (%d) on a FREE reservation", got)
	}

	if _, err := s.AssignPlan(ctx, acct, store.PlanPlusBeta, store.LatestPlanVersion, time.Time{}, now); err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	freeAfterUpgrade := poolBalance(t, pool, "free")
	rid, err := s.ReserveAllowance(ctx, acct, store.FeatureSessionEnrichment, now)
	if err != nil {
		t.Fatalf("reserve on plus: %v", err)
	}
	if got := poolBalance(t, pool, "plus_beta"); got != plusBefore+1 {
		t.Fatalf("plus_beta pool = %d, want %d", got, plusBefore+1)
	}
	if got := poolBalance(t, pool, "free"); got != freeAfterUpgrade {
		t.Fatalf("the FREE pool moved (%d, want %d) on a PLUS reservation — R4 forbids it", got, freeAfterUpgrade)
	}

	// A refund returns the unit to the pool it was drawn from, even after the
	// account has been moved back to free.
	if _, err := s.AssignPlan(ctx, acct, store.PlanFree, store.LatestPlanVersion, time.Time{}, now); err != nil {
		t.Fatalf("downgrade: %v", err)
	}
	if err := s.ReleaseReservation(ctx, acct, rid, false); err != nil {
		t.Fatalf("release: %v", err)
	}
	if got := poolBalance(t, pool, "plus_beta"); got != plusBefore {
		t.Fatalf("plus_beta pool = %d after refund, want %d", got, plusBefore)
	}
	if got := poolBalance(t, pool, "free"); got != freeAfterUpgrade {
		t.Fatalf("the refund credited the FREE pool (%d, want %d) — it must credit the pool the reservation drew from",
			got, freeAfterUpgrade)
	}
}

// TestOverlappingOpenAssignmentRejected pins the database-level guard: at most
// one open (effective_until IS NULL) assignment per account.
func TestOverlappingOpenAssignmentRejected(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	acct := makeAccount(t, s)
	now := midMonth()

	if _, err := s.AssignPlan(ctx, acct, store.PlanPlusBeta, store.LatestPlanVersion, time.Time{}, now); err != nil {
		t.Fatalf("AssignPlan: %v", err)
	}
	var planID string
	if err := pool.QueryRow(ctx,
		`SELECT plan_id::text FROM plans WHERE name = $1 AND version = 1`, store.PlanFree).Scan(&planID); err != nil {
		t.Fatalf("read free plan id: %v", err)
	}
	_, err := pool.Exec(ctx,
		`INSERT INTO account_plans (account_id, plan_id, effective_from) VALUES ($1::uuid, $2::uuid, $3)`,
		acct, planID, now)
	if err == nil {
		t.Fatal("a second OPEN assignment was accepted; the partial unique index must reject it")
	}

	// The store path refuses rather than silently rewriting a running grant it
	// cannot close without producing a zero-length window: re-assigning at the
	// SAME instant the running assignment started is exactly that case.
	if _, e := s.AssignPlan(ctx, acct, store.PlanPlusBeta, store.LatestPlanVersion, now, now); !errors.Is(e, store.ErrPlanAssignmentConflict) {
		t.Fatalf("same-instant reassignment = %v, want ErrPlanAssignmentConflict", e)
	}

	var open int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM account_plans WHERE account_id=$1::uuid AND effective_until IS NULL`,
		acct).Scan(&open); err != nil {
		t.Fatalf("count open assignments: %v", err)
	}
	if open != 1 {
		t.Fatalf("account has %d open assignments, want exactly 1", open)
	}
}

// TestAccountPlansRLSIsolation pins that account_plans is a TENANT table: one
// account's transaction can neither read nor write another's assignment.
func TestAccountPlansRLSIsolation(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	a := makeAccount(t, s)
	b := makeAccount(t, s)
	now := midMonth()

	if _, err := s.AssignPlan(ctx, a, store.PlanPlusBeta, store.LatestPlanVersion, time.Time{}, now); err != nil {
		t.Fatalf("AssignPlan(a): %v", err)
	}

	// B sees its own (default free) plan, never A's upgrade.
	ab, err := s.ResolveAllowance(ctx, b, store.FeatureSessionEnrichment, now)
	if err != nil {
		t.Fatalf("ResolveAllowance(b): %v", err)
	}
	if ab.Plan.Name != store.PlanFree {
		t.Fatalf("account B resolved plan %s — it must not see account A's assignment", ab.Plan.Name)
	}

	// Directly: inside B's tenant context, A's rows are invisible.
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer conn.Release()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE sbci_app`); err != nil {
		t.Fatalf("set role: %v", err)
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('sbci.account_id', $1, true)`, b); err != nil {
		t.Fatalf("set tenant: %v", err)
	}
	var visible int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM account_plans WHERE account_id = $1::uuid`, a).Scan(&visible); err != nil {
		t.Fatalf("cross-tenant read: %v", err)
	}
	if visible != 0 {
		t.Fatalf("account B saw %d of account A's assignments through RLS", visible)
	}
	// And cannot write one for A either (the policy's WITH CHECK).
	var planID string
	if err := tx.QueryRow(ctx,
		`SELECT plan_id::text FROM plans WHERE name=$1 AND version=1`, store.PlanPlusBeta).Scan(&planID); err != nil {
		t.Fatalf("read plan id: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO account_plans (account_id, plan_id, effective_from) VALUES ($1::uuid, $2::uuid, now())`,
		a, planID); err == nil {
		t.Fatal("account B inserted an assignment for account A — the RLS WITH CHECK must refuse it")
	}
}

// TestPlansAreImmutable pins the versioned-immutable contract: the application
// role may only read plans, and even the owner cannot UPDATE one.
func TestPlansAreImmutable(t *testing.T) {
	_, pool := newStore(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `UPDATE plans SET daily_cap = 999 WHERE name = 'free'`); err == nil {
		t.Fatal("a plans row was UPDATEd; plan definitions are immutable (publish a new version)")
	}
	var canWrite bool
	if err := pool.QueryRow(ctx,
		`SELECT has_table_privilege('sbci_app', 'plans', 'UPDATE')`).Scan(&canWrite); err != nil {
		t.Fatalf("check grant: %v", err)
	}
	if canWrite {
		t.Fatal("sbci_app holds UPDATE on plans; it must hold SELECT only")
	}
}

// TestUsageWarnThresholds pins the 70/90/100% warning ladder, including the
// 69% no-warning boundary directly below it.
func TestUsageWarnThresholds(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	acct := makeAccount(t, s)
	now := midMonth()
	// A round cap makes the percentage boundaries exact.
	setEntitlement(t, pool, acct, 100, 1000, 100)

	setCycleUsed := func(used int) {
		t.Helper()
		if _, err := pool.Exec(ctx,
			`INSERT INTO usage_cycles (account_id, feature, cycle_kind, window_key, cap, used)
			 VALUES ($1::uuid, $2, 'daily', $3, 100, $4)
			 ON CONFLICT (account_id, feature, cycle_kind, window_key)
			 DO UPDATE SET used = EXCLUDED.used`,
			acct, store.FeatureSessionEnrichment, store.DailyWindowKey(now), used); err != nil {
			t.Fatalf("set daily used=%d: %v", used, err)
		}
	}
	dailyWarning := func() (store.UsageWarning, bool) {
		t.Helper()
		snap, err := s.Usage(ctx, acct, store.FeatureSessionEnrichment, now)
		if err != nil {
			t.Fatalf("Usage: %v", err)
		}
		for _, w := range snap.Warnings {
			if w.Window == "daily" {
				return w, true
			}
		}
		return store.UsageWarning{}, false
	}

	for _, tc := range []struct {
		used      int
		wantLevel string // "" ⇒ no warning at all
	}{
		{69, ""},
		{70, store.UsageLevelWarn},
		{89, store.UsageLevelWarn},
		{90, store.UsageLevelCritical},
		{99, store.UsageLevelCritical},
		{100, store.UsageLevelExhausted},
	} {
		setCycleUsed(tc.used)
		w, ok := dailyWarning()
		if tc.wantLevel == "" {
			if ok {
				t.Fatalf("used=%d produced a %q warning; nothing is expected below 70%%", tc.used, w.Level)
			}
			continue
		}
		if !ok {
			t.Fatalf("used=%d produced no warning, want %q", tc.used, tc.wantLevel)
		}
		if w.Level != tc.wantLevel {
			t.Fatalf("used=%d level = %q, want %q", tc.used, w.Level, tc.wantLevel)
		}
		if w.Used != tc.used || w.Cap != 100 {
			t.Fatalf("used=%d warning carries %d/%d", tc.used, w.Used, w.Cap)
		}
	}

	// Well below every threshold ⇒ an EMPTY list, not a null and not a warning.
	setCycleUsed(1)
	snap, err := s.Usage(ctx, acct, store.FeatureSessionEnrichment, now)
	if err != nil {
		t.Fatalf("Usage: %v", err)
	}
	if snap.Warnings == nil {
		t.Fatal("Warnings must be an empty slice, never nil (it is serialized to JSON)")
	}
	if len(snap.Warnings) != 0 {
		t.Fatalf("warnings at 1%% = %+v, want none", snap.Warnings)
	}
}

// TestUsageSurfacesPlanLabel pins that /v1/usage carries the plan label
// verbatim. The label itself was the R4 "entitlement simulation" copy (never
// read as a purchased subscription) until the 2026-09-15 ruling made Plus a
// real purchasable plan (migration 0037 updates the seeded label to "Plus");
// this test follows that ruling.
func TestUsageSurfacesPlanLabel(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	acct := makeAccount(t, s)
	now := midMonth()

	snap, err := s.Usage(ctx, acct, store.FeatureSessionEnrichment, now)
	if err != nil {
		t.Fatalf("Usage: %v", err)
	}
	if snap.Plan != store.PlanFree || snap.PlanLabel != "Signed-in Free" || snap.BudgetPool != "free" {
		t.Fatalf("free surface = %q / %q / %q", snap.Plan, snap.PlanLabel, snap.BudgetPool)
	}
	if _, err := s.AssignPlan(ctx, acct, store.PlanPlusBeta, store.LatestPlanVersion, time.Time{}, now); err != nil {
		t.Fatalf("AssignPlan: %v", err)
	}
	snap, err = s.Usage(ctx, acct, store.FeatureSessionEnrichment, now)
	if err != nil {
		t.Fatalf("Usage after upgrade: %v", err)
	}
	if snap.PlanLabel != "Plus" {
		t.Fatalf("plus label = %q, want the exact 2026-09-15 copy \"Plus\"", snap.PlanLabel)
	}
	// Migration 0039's v2 row: the monthly cap is 120, the COGS ceiling for the
	// more expensive pinned model (500 was v1's).
	if snap.BudgetPool != "plus_beta" || snap.MonthlyCap != 120 || snap.ConcurrencyCap != 4 {
		t.Fatalf("plus surface = pool %q, monthly %d, concurrency %d; want plus_beta/120/4",
			snap.BudgetPool, snap.MonthlyCap, snap.ConcurrencyCap)
	}
}

// TestAssignUnknownPlanRejected pins the fail-closed lookup.
func TestAssignUnknownPlanRejected(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	acct := makeAccount(t, s)
	if _, err := s.AssignPlan(ctx, acct, "enterprise_unicorn", store.LatestPlanVersion, time.Time{}, midMonth()); !errors.Is(err, store.ErrPlanNotFound) {
		t.Fatalf("AssignPlan(unknown) = %v, want ErrPlanNotFound", err)
	}
}

// --- F11: every downgrade lands on a cycle boundary --------------------------

// TestDowngradeCeilsToACycleBoundary is the F11 regression. The old rule floored
// a downgrade to "the next boundary after NOW", which only covers a downgrade
// taking effect immediately: a downgrade SCHEDULED for a future mid-cycle
// instant was already past that boundary, so it was honoured as asked and landed
// half-way through a monthly counter the developer was part-way through
// spending. The rule is now "ceil the REQUESTED instant to the boundary at or
// after it", and Deferred is derived from the resulting instant rather than from
// which branch produced it.
func TestDowngradeCeilsToACycleBoundary(t *testing.T) {
	utc := func(y int, m time.Month, d, h int) time.Time {
		return time.Date(y, m, d, h, 0, 0, 0, time.UTC)
	}
	cases := []struct {
		name          string
		now           time.Time
		effectiveFrom time.Time
		want          time.Time
		wantDeferred  bool
	}{
		{
			// The headline case. Requested on Oct 20 to take effect Nov 15;
			// the boundary after NOW is Nov 1, which Nov 15 is already past, so
			// the old rule left it mid-cycle.
			name:          "future mid-cycle date is ceiled, not honoured",
			now:           utc(2026, time.October, 20, 12),
			effectiveFrom: utc(2026, time.November, 15, 9),
			want:          utc(2026, time.December, 1, 0),
			wantDeferred:  true,
		},
		{
			name:          "immediate downgrade floors to the next boundary",
			now:           utc(2026, time.October, 20, 12),
			effectiveFrom: time.Time{},
			want:          utc(2026, time.November, 1, 0),
			wantDeferred:  true,
		},
		{
			name:          "a past date is raised to now, then ceiled",
			now:           utc(2026, time.October, 20, 12),
			effectiveFrom: utc(2026, time.January, 3, 0),
			want:          utc(2026, time.November, 1, 0),
			wantDeferred:  true,
		},
		{
			// A boundary-exact request stays: the cycle it starts has no
			// part-spent allowance to protect.
			name:          "a boundary-exact future request is untouched",
			now:           utc(2026, time.October, 20, 12),
			effectiveFrom: utc(2026, time.December, 1, 0),
			want:          utc(2026, time.December, 1, 0),
			wantDeferred:  true,
		},
		{
			name:          "a far-future mid-cycle date ceils within its own month",
			now:           utc(2026, time.October, 20, 12),
			effectiveFrom: utc(2027, time.March, 2, 1),
			want:          utc(2027, time.April, 1, 0),
			wantDeferred:  true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, _ := newStore(t)
			ctx := context.Background()
			acct := makeAccount(t, s)
			// Start on Plus so the move to free is a genuine downgrade.
			if _, err := s.AssignPlan(ctx, acct, store.PlanPlusBeta, store.LatestPlanVersion, time.Time{}, c.now); err != nil {
				t.Fatalf("upgrade: %v", err)
			}
			got, err := s.AssignPlan(ctx, acct, store.PlanFree, store.LatestPlanVersion, c.effectiveFrom, c.now)
			if err != nil {
				t.Fatalf("downgrade: %v", err)
			}
			if !got.EffectiveFrom.Equal(c.want) {
				t.Fatalf("effective_from = %s, want %s (every downgrade lands on a cycle boundary)",
					got.EffectiveFrom.Format(time.RFC3339), c.want.Format(time.RFC3339))
			}
			if got.Deferred != c.wantDeferred {
				t.Fatalf("Deferred = %v, want %v", got.Deferred, c.wantDeferred)
			}
			// And the plan actually in force follows the recorded instant: still
			// Plus a second before, free at it.
			before, err := s.ResolveAllowance(ctx, acct, store.FeatureSessionEnrichment, c.want.Add(-time.Second))
			if err != nil {
				t.Fatalf("ResolveAllowance before: %v", err)
			}
			if before.Plan.Name != store.PlanPlusBeta {
				t.Fatalf("one second before the boundary the plan is %s, want plus_beta", before.Plan.Name)
			}
			at, err := s.ResolveAllowance(ctx, acct, store.FeatureSessionEnrichment, c.want)
			if err != nil {
				t.Fatalf("ResolveAllowance at: %v", err)
			}
			if at.Plan.Name != store.PlanFree {
				t.Fatalf("at the boundary the plan is %s, want free", at.Plan.Name)
			}
		})
	}
}

// TestScheduledUpgradeReportsDeferred pins the second half of F11: Deferred
// means "does not take effect yet", so a future-dated UPGRADE (which is NOT
// ceiled — raising a ceiling mid-cycle takes nothing away) reports itself
// deferred rather than claiming to be immediate.
func TestScheduledUpgradeReportsDeferred(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	acct := makeAccount(t, s)
	now := midMonth()
	future := now.Add(72 * time.Hour)

	up, err := s.AssignPlan(ctx, acct, store.PlanPlusBeta, store.LatestPlanVersion, future, now)
	if err != nil {
		t.Fatalf("scheduled upgrade: %v", err)
	}
	if !up.EffectiveFrom.Equal(future) {
		t.Fatalf("a scheduled UPGRADE was moved to %s; upgrades are not ceiled", up.EffectiveFrom)
	}
	if !up.Deferred {
		t.Fatal("a scheduled future upgrade reported Deferred=false — it does not take effect yet")
	}
	// An immediate upgrade is still immediate.
	acct2 := makeAccount(t, s)
	imm, err := s.AssignPlan(ctx, acct2, store.PlanPlusBeta, store.LatestPlanVersion, time.Time{}, now)
	if err != nil {
		t.Fatalf("immediate upgrade: %v", err)
	}
	if imm.Deferred {
		t.Fatal("an immediate upgrade reported Deferred=true")
	}
}

// --- F12: no overlapping assignment windows ---------------------------------

// TestOverlappingFiniteAssignmentsRejected is the F12 regression. 0012's partial
// unique index only forbids two OPEN rows, so two FINITE windows could overlap
// freely — and resolvePlanTx's "ORDER BY effective_from DESC LIMIT 1" would then
// pick one of two equally-valid answers with nothing to say which. Migration
// 0014's exclusion constraint makes the overlap unrepresentable.
func TestOverlappingFiniteAssignmentsRejected(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	acct := makeAccount(t, s)
	now := midMonth()

	var freePlan, plusPlan string
	for name, dst := range map[string]*string{store.PlanFree: &freePlan, store.PlanPlusBeta: &plusPlan} {
		if err := pool.QueryRow(ctx,
			`SELECT plan_id::text FROM plans WHERE name = $1 ORDER BY version DESC LIMIT 1`, name).Scan(dst); err != nil {
			t.Fatalf("read plan id %s: %v", name, err)
		}
	}

	// A closed window: [now, now+10d).
	if _, err := pool.Exec(ctx,
		`INSERT INTO account_plans (account_id, plan_id, effective_from, effective_until)
		 VALUES ($1::uuid, $2::uuid, $3, $4)`,
		acct, plusPlan, now, now.AddDate(0, 0, 10)); err != nil {
		t.Fatalf("seed the first finite window: %v", err)
	}

	overlaps := []struct {
		name        string
		from, until time.Time
	}{
		{"starts inside", now.AddDate(0, 0, 5), now.AddDate(0, 0, 20)},
		{"ends inside", now.AddDate(0, 0, -5), now.AddDate(0, 0, 5)},
		{"strictly contains", now.AddDate(0, 0, -5), now.AddDate(0, 0, 20)},
		{"strictly contained", now.AddDate(0, 0, 2), now.AddDate(0, 0, 3)},
	}
	for _, c := range overlaps {
		t.Run(c.name, func(t *testing.T) {
			_, err := pool.Exec(ctx,
				`INSERT INTO account_plans (account_id, plan_id, effective_from, effective_until)
				 VALUES ($1::uuid, $2::uuid, $3, $4)`,
				acct, freePlan, c.from, c.until)
			if err == nil {
				t.Fatal("an OVERLAPPING finite assignment was accepted; the exclusion constraint must reject it")
			}
		})
	}

	// An ADJACENT window is legal: half-open ranges make [a,b) and [b,c)
	// disjoint. This is exactly the shape AssignPlan's close-then-open produces,
	// so a constraint that rejected it would break the normal path.
	if _, err := pool.Exec(ctx,
		`INSERT INTO account_plans (account_id, plan_id, effective_from, effective_until)
		 VALUES ($1::uuid, $2::uuid, $3, $4)`,
		acct, freePlan, now.AddDate(0, 0, 10), now.AddDate(0, 0, 20)); err != nil {
		t.Fatalf("an ADJACENT window was rejected: %v", err)
	}

	// And another account's overlapping window is unaffected (the constraint is
	// per-account).
	other := makeAccount(t, s)
	if _, err := pool.Exec(ctx,
		`INSERT INTO account_plans (account_id, plan_id, effective_from, effective_until)
		 VALUES ($1::uuid, $2::uuid, $3, $4)`,
		other, freePlan, now, now.AddDate(0, 0, 10)); err != nil {
		t.Fatalf("another account's identical window was rejected: %v", err)
	}
}

// TestAssignPlanChainStillPassesUnderTheExclusion walks a realistic sequence of
// assignments end to end, proving the F12 constraint does not fire on the store's
// own close-then-open path (the risk when adding an exclusion constraint to a
// table an existing writer already maintains).
func TestAssignPlanChainStillPassesUnderTheExclusion(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	acct := makeAccount(t, s)
	now := midMonth()

	if _, err := s.AssignPlan(ctx, acct, store.PlanPlusBeta, store.LatestPlanVersion, time.Time{}, now); err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	down, err := s.AssignPlan(ctx, acct, store.PlanFree, store.LatestPlanVersion, time.Time{}, now)
	if err != nil {
		t.Fatalf("deferred downgrade: %v", err)
	}
	// A later upgrade, after the deferred downgrade has taken effect.
	after := down.EffectiveFrom.Add(48 * time.Hour)
	if _, err := s.AssignPlan(ctx, acct, store.PlanPlusBeta, store.LatestPlanVersion, time.Time{}, after); err != nil {
		t.Fatalf("upgrade after the boundary: %v", err)
	}

	var rows int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM account_plans WHERE account_id = $1::uuid`, acct).Scan(&rows); err != nil {
		t.Fatalf("count assignments: %v", err)
	}
	if rows != 3 {
		t.Fatalf("the assignment chain wrote %d rows, want 3", rows)
	}
	for _, at := range []time.Time{now, down.EffectiveFrom, after} {
		if _, err := s.ResolveAllowance(ctx, acct, store.FeatureSessionEnrichment, at); err != nil {
			t.Fatalf("ResolveAllowance at %s: %v", at, err)
		}
	}
}
