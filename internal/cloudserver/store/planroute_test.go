package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// The migration-0039 suite: plan v2 allowances (free 20/day, Plus 120/month) and
// the PER-PLAN route pin, whose whole point is that a paid plan degrades to the
// default model rather than to no service.

const solRoute = "session_enrichment.sol.v1"

// bindSolRoute moves the seeded Sol route from its shipped state (inactive,
// unbound) to the state an operator leaves it in after deploying gpt-5.6-sol:
// bound and active.
func bindSolRoute(t *testing.T, s *store.Store) {
	t.Helper()
	ctx := context.Background()
	if err := s.SetRouteBinding(ctx, solRoute, store.RouteBinding{
		TenantID: "tenant", SubscriptionID: "sub", ARMResourceID: "/arm/sol",
		EndpointAudience: "https://cognitiveservices.azure.com/.default",
		Endpoint:         "https://sbci-test-foundry.openai.azure.com", APIVersion: "2026-05-01",
	}); err != nil {
		t.Fatalf("SetRouteBinding(sol): %v", err)
	}
	if err := s.SetRouteActive(ctx, solRoute, true); err != nil {
		t.Fatalf("SetRouteActive(sol, true): %v", err)
	}
}

// TestFreePlanV2Allowance pins the LITERAL v2 free numbers (not just
// "whatever DefaultFreePlanVersion points at"): daily 5 -> 20, monthly 100
// unchanged, and no route pin.
func TestFreePlanV2Allowance(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	acct := makeAccount(t, s)

	a, err := s.ResolveAllowance(ctx, acct, store.FeatureSessionEnrichment, midMonth())
	if err != nil {
		t.Fatalf("ResolveAllowance: %v", err)
	}
	if a.Plan.Name != store.PlanFree || a.Plan.Version != 2 {
		t.Fatalf("fresh account resolves %s v%d, want free v2", a.Plan.Name, a.Plan.Version)
	}
	if a.DailyCap != 20 || a.MonthlyCap != 100 || a.ConcurrencyCap != 2 {
		t.Fatalf("free v2 caps = %d/%d/%d, want 20/100/2", a.DailyCap, a.MonthlyCap, a.ConcurrencyCap)
	}
	if a.Plan.RouteID != "" {
		t.Fatalf("free v2 route_id = %q, want empty (feature default)", a.Plan.RouteID)
	}
}

// TestPlusPlanV2AllowanceAndRoutePin pins the paid side: monthly 500 -> 120 (the
// COGS cap), daily/concurrency unchanged, the Sol route pinned, and the v1-only
// columns (digest entitlement, retention window) carried forward by the
// INSERT ... SELECT rather than silently reset to their defaults.
func TestPlusPlanV2AllowanceAndRoutePin(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	acct := makeAccount(t, s)
	now := midMonth()

	if _, err := s.AssignPlan(ctx, acct, store.PlanPlusBeta, store.LatestPlanVersion, time.Time{}, now); err != nil {
		t.Fatalf("AssignPlan(plus, latest): %v", err)
	}
	a, err := s.ResolveAllowance(ctx, acct, store.FeatureSessionEnrichment, now)
	if err != nil {
		t.Fatalf("ResolveAllowance: %v", err)
	}
	if a.Plan.Version != 2 {
		t.Fatalf("latest plus version = %d, want 2", a.Plan.Version)
	}
	if a.DailyCap != 25 || a.MonthlyCap != 120 || a.ConcurrencyCap != 4 {
		t.Fatalf("plus v2 caps = %d/%d/%d, want 25/120/4", a.DailyCap, a.MonthlyCap, a.ConcurrencyCap)
	}
	if a.Plan.RouteID != solRoute {
		t.Fatalf("plus v2 route_id = %q, want %q", a.Plan.RouteID, solRoute)
	}
	if a.BudgetPool != "plus_beta" {
		t.Fatalf("plus v2 pool = %q, want plus_beta (never the free pool)", a.BudgetPool)
	}
	if !a.Plan.DigestWeekly || a.Plan.ResultsRetentionDays != 365 {
		t.Fatalf("plus v2 carried digest_weekly=%v retention=%d, want true/365 copied from v1",
			a.Plan.DigestWeekly, a.Plan.ResultsRetentionDays)
	}
}

// TestResolveRouteForPlanFallsBackWhenPinnedRouteCannotServe is the
// customer-outage guard. The Sol route ships INACTIVE and UNBOUND (production
// has no gpt-5.6-sol deployment), so a Plus account must keep being served by
// the live Luna default - with the fallback SIGNALLED, never silent.
func TestResolveRouteForPlanFallsBackWhenPinnedRouteCannotServe(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()

	def, err := s.ResolveRoute(ctx, store.FeatureSessionEnrichment)
	if err != nil {
		t.Fatalf("ResolveRoute(default): %v", err)
	}

	// 1) As shipped: inactive.
	got, fb, err := s.ResolveRouteForPlan(ctx, store.FeatureSessionEnrichment, solRoute)
	if err != nil {
		t.Fatalf("ResolveRouteForPlan(inactive sol) = error %v, want the default route", err)
	}
	if got.RouteID != def.RouteID {
		t.Fatalf("inactive pinned route served %q, want the default %q", got.RouteID, def.RouteID)
	}
	if !fb.Fell() || fb.RouteID != solRoute || fb.Reason != store.PlanRouteInactive {
		t.Fatalf("fallback signal = %+v, want {%s, %s}", fb, solRoute, store.PlanRouteInactive)
	}

	// 2) Active but never bound: still not callable, same degradation, different
	// reason - the two states are distinguishable by an operator.
	if err := s.SetRouteActive(ctx, solRoute, true); err != nil {
		t.Fatalf("SetRouteActive(sol, true): %v", err)
	}
	got, fb, err = s.ResolveRouteForPlan(ctx, store.FeatureSessionEnrichment, solRoute)
	if err != nil {
		t.Fatalf("ResolveRouteForPlan(unbound sol): %v", err)
	}
	if got.RouteID != def.RouteID || fb.Reason != store.PlanRouteUnbound {
		t.Fatalf("unbound pinned route served %q reason %q, want %q / %q",
			got.RouteID, fb.Reason, def.RouteID, store.PlanRouteUnbound)
	}
}

// TestResolveRouteForPlanServesBoundPinnedRoute is the other side: once the
// deployment exists and an operator has bound + activated the route, a pinned
// plan actually runs on it and NO fallback is reported.
func TestResolveRouteForPlanServesBoundPinnedRoute(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	bindSolRoute(t, s)

	got, fb, err := s.ResolveRouteForPlan(ctx, store.FeatureSessionEnrichment, solRoute)
	if err != nil {
		t.Fatalf("ResolveRouteForPlan(bound sol): %v", err)
	}
	if got.RouteID != solRoute || got.Deployment != "gpt-5.6-sol" {
		t.Fatalf("served route = %q / %q, want %q / gpt-5.6-sol", got.RouteID, got.Deployment, solRoute)
	}
	if got.MaxOutputTokens != 4096 {
		t.Fatalf("sol max_output_tokens = %d, want 4096 (reasoning tokens are completion tokens here)",
			got.MaxOutputTokens)
	}
	if fb.Fell() {
		t.Fatalf("bound + active pinned route reported a fallback: %+v", fb)
	}
}

// TestResolveRouteForPlanUnpinnedIsTheDefault pins the free path: an empty pin
// is exactly ResolveRoute, with no fallback signal (nothing degraded).
func TestResolveRouteForPlanUnpinnedIsTheDefault(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()

	def, err := s.ResolveRoute(ctx, store.FeatureSessionEnrichment)
	if err != nil {
		t.Fatalf("ResolveRoute: %v", err)
	}
	got, fb, err := s.ResolveRouteForPlan(ctx, store.FeatureSessionEnrichment, "")
	if err != nil {
		t.Fatalf("ResolveRouteForPlan(unpinned): %v", err)
	}
	if got.RouteID != def.RouteID || fb.Fell() {
		t.Fatalf("unpinned resolution = %q fallback %+v, want %q / none", got.RouteID, fb, def.RouteID)
	}
}

// TestResolveRouteForPlanErrorsOnMissingRoute is the ONE hard error: a plan
// pinning a route_id that was never seeded is a catalogue mistake no fallback
// can make correct.
func TestResolveRouteForPlanErrorsOnMissingRoute(t *testing.T) {
	s, _ := newStore(t)
	_, _, err := s.ResolveRouteForPlan(context.Background(), store.FeatureSessionEnrichment, "session_enrichment.nope.v1")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ResolveRouteForPlan(missing) = %v, want ErrNotFound", err)
	}
}

// TestResolveRouteForPlanRefusesAnotherFeaturesRoute: a pin that names a route
// registered for a DIFFERENT feature degrades to this feature's default (it is
// a catalogue mistake, not a reason to take a paying customer's service away)
// and says so.
func TestResolveRouteForPlanRefusesAnotherFeaturesRoute(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx,
		`INSERT INTO route_registry (route_id, feature, deployment, dialect, endpoint, api_version)
		 VALUES ('other_feature.v1', 'some_other_feature', 'gpt-5.6-sol', 'chat_completions', 'https://e', '2026-05-01')`); err != nil {
		t.Fatalf("seed foreign-feature route: %v", err)
	}
	def, err := s.ResolveRoute(ctx, store.FeatureSessionEnrichment)
	if err != nil {
		t.Fatalf("ResolveRoute: %v", err)
	}
	got, fb, err := s.ResolveRouteForPlan(ctx, store.FeatureSessionEnrichment, "other_feature.v1")
	if err != nil {
		t.Fatalf("ResolveRouteForPlan(foreign feature): %v", err)
	}
	if got.RouteID != def.RouteID || fb.Reason != store.PlanRouteFeatureMismatch {
		t.Fatalf("foreign-feature pin served %q reason %q, want %q / %q",
			got.RouteID, fb.Reason, def.RouteID, store.PlanRouteFeatureMismatch)
	}
}

// insertTestRoute seeds a minimal route_registry row against a synthetic
// feature (never "session_enrichment") so these cases are self-contained and
// don't interact with the real luna/sol rows the migrations seed.
func insertTestRoute(t *testing.T, pool *pgxpool.Pool, feature, routeID string, version int64, active, planPinned bool) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO route_registry (route_id, feature, deployment, route_version, active, plan_pinned)
		 VALUES ($1, $2, 'test-deployment', $3, $4, $5)`,
		routeID, feature, version, active, planPinned); err != nil {
		t.Fatalf("insertTestRoute(%s): %v", routeID, err)
	}
}

// TestResolveRouteScenarios is the table-driven ordering-trap suite (the
// kickoff doc's §3 "handle that when flipping it on"): the four shapes the
// feature-default resolver must get right once a second active
// session_enrichment route exists at the same route_version as the default.
// Each case gets its own fresh database (a fresh newStore call) so a
// synthetic feature name is unnecessary for isolation between cases, but is
// used anyway to keep every case readable without cross-referencing the
// migration-seeded rows.
func TestResolveRouteScenarios(t *testing.T) {
	const feature = "test_feature_route_scenarios"

	tests := []struct {
		name   string
		seed   func(t *testing.T, pool *pgxpool.Pool)
		wantID string
	}{
		{
			name: "one active route resolves trivially",
			seed: func(t *testing.T, pool *pgxpool.Pool) {
				insertTestRoute(t, pool, feature, "route.solo", 1, true, false)
			},
			wantID: "route.solo",
		},
		{
			name: "two active same version, one plan-pinned - pinned is never the default",
			seed: func(t *testing.T, pool *pgxpool.Pool) {
				insertTestRoute(t, pool, feature, "route.default", 1, true, false)
				insertTestRoute(t, pool, feature, "route.pinned", 1, true, true)
			},
			wantID: "route.default",
		},
		{
			name: "two active same version, neither pinned - deterministic tiebreak",
			seed: func(t *testing.T, pool *pgxpool.Pool) {
				insertTestRoute(t, pool, feature, "route.zzz", 1, true, false)
				insertTestRoute(t, pool, feature, "route.aaa", 1, true, false)
			},
			wantID: "route.aaa", // lexically lowest route_id wins the tie
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, pool := newStore(t)
			tt.seed(t, pool)
			got, err := s.ResolveRoute(context.Background(), feature)
			if err != nil {
				t.Fatalf("ResolveRoute: %v", err)
			}
			if got.RouteID != tt.wantID {
				t.Fatalf("ResolveRoute(%s) = %q, want %q", feature, got.RouteID, tt.wantID)
			}
		})
	}
}

// TestResolveRouteForPlanScenarioPinnedRouteInactive is the fourth
// table-driven scenario, kept separate because it exercises
// ResolveRouteForPlan (the per-account degrade path), not ResolveRoute (the
// feature-default pick): a plan pinned to a route that is active=false must
// still resolve the feature's live default, with the fallback signalled.
func TestResolveRouteForPlanScenarioPinnedRouteInactive(t *testing.T) {
	const feature = "test_feature_route_scenarios_pinned"
	s, pool := newStore(t)
	insertTestRoute(t, pool, feature, "route.default", 1, true, false)
	insertTestRoute(t, pool, feature, "route.pinned", 1, false /* inactive */, true)

	got, fb, err := s.ResolveRouteForPlan(context.Background(), feature, "route.pinned")
	if err != nil {
		t.Fatalf("ResolveRouteForPlan: %v", err)
	}
	if got.RouteID != "route.default" {
		t.Fatalf("ResolveRouteForPlan(inactive pin) = %q, want the feature default %q", got.RouteID, "route.default")
	}
	if !fb.Fell() || fb.RouteID != "route.pinned" || fb.Reason != store.PlanRouteInactive {
		t.Fatalf("fallback signal = %+v, want {route.pinned, %s}", fb, store.PlanRouteInactive)
	}
}

// featureCoverageFor is a small lookup helper over FeatureDefaultCoverage's
// result slice, since tests only ever care about one feature at a time out of
// however many route_registry happens to carry.
func featureCoverageFor(t *testing.T, coverage []store.FeatureCoverage, feature string) store.FeatureCoverage {
	t.Helper()
	for _, c := range coverage {
		if c.Feature == feature {
			return c
		}
	}
	t.Fatalf("FeatureDefaultCoverage did not report feature %q at all (coverage=%+v)", feature, coverage)
	return store.FeatureCoverage{}
}

// TestFeatureDefaultCoverage is the PG-backed half of the adversarial-review
// follow-up: excluding plan_pinned routes from ResolveRoute's candidate set
// can leave a feature with NO eligible default if the only active route left
// is plan_pinned. FeatureDefaultCoverage is the readiness signal that catches
// it - proven here against a real database, not just the pure classifier.
func TestFeatureDefaultCoverage(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()

	// 1) As shipped: the real session_enrichment feature has ONE active
	// non-pinned route (Luna) plus the inactive plan-pinned Sol row - covered.
	coverage, err := s.FeatureDefaultCoverage(ctx)
	if err != nil {
		t.Fatalf("FeatureDefaultCoverage: %v", err)
	}
	if got := featureCoverageFor(t, coverage, store.FeatureSessionEnrichment); !got.HasDefault {
		t.Fatalf("session_enrichment coverage = %+v, want HasDefault=true (Luna is active + unpinned)", got)
	}

	// 2) A synthetic feature whose ONLY route is a normal active, unpinned one
	// - covered.
	const featureOK = "test_feature_coverage_ok"
	insertTestRoute(t, pool, featureOK, "route.ok", 1, true, false)
	coverage, err = s.FeatureDefaultCoverage(ctx)
	if err != nil {
		t.Fatalf("FeatureDefaultCoverage: %v", err)
	}
	if got := featureCoverageFor(t, coverage, featureOK); !got.HasDefault {
		t.Fatalf("%s coverage = %+v, want HasDefault=true", featureOK, got)
	}

	// 3) The outage the review flagged: a feature whose ONLY route is active
	// but plan_pinned - ResolveRoute has nothing left to resolve to, and
	// FeatureDefaultCoverage must say so.
	const featureOutage = "test_feature_coverage_outage"
	insertTestRoute(t, pool, featureOutage, "route.pinned_only", 1, true, true)
	coverage, err = s.FeatureDefaultCoverage(ctx)
	if err != nil {
		t.Fatalf("FeatureDefaultCoverage: %v", err)
	}
	if got := featureCoverageFor(t, coverage, featureOutage); got.HasDefault {
		t.Fatalf("%s coverage = %+v, want HasDefault=false (the only route is plan_pinned)", featureOutage, got)
	}
	if _, err := s.ResolveRoute(ctx, featureOutage); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ResolveRoute(%s) = %v, want ErrNotFound (confirms the coverage signal matches reality)", featureOutage, err)
	}

	// 4) The SAME outage reached by deactivating the real default: turn off
	// Luna (leaving only the inactive, plan-pinned Sol row for
	// session_enrichment) and confirm coverage flips to false and ResolveRoute
	// itself now fails - this is the exact single-activation outage mode an
	// operator could cause mid-migration.
	if err := s.SetRouteActive(ctx, "session_enrichment.luna.v1", false); err != nil {
		t.Fatalf("SetRouteActive(luna, false): %v", err)
	}
	coverage, err = s.FeatureDefaultCoverage(ctx)
	if err != nil {
		t.Fatalf("FeatureDefaultCoverage: %v", err)
	}
	if got := featureCoverageFor(t, coverage, store.FeatureSessionEnrichment); got.HasDefault {
		t.Fatalf("session_enrichment coverage after deactivating Luna = %+v, want HasDefault=false", got)
	}
	if _, err := s.ResolveRoute(ctx, store.FeatureSessionEnrichment); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ResolveRoute(session_enrichment) after deactivating Luna = %v, want ErrNotFound", err)
	}
}

// TestPlanPinnedRouteIsNeverTheFeatureDefault is the free-account protection:
// activating the Sol route must not put FREE traffic on it. Both rows are
// session_enrichment at route_version 1, so without the plan_pinned marker the
// default pick would be decided by nothing but row order.
func TestPlanPinnedRouteIsNeverTheFeatureDefault(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	bindSolRoute(t, s)

	def, err := s.ResolveRoute(ctx, store.FeatureSessionEnrichment)
	if err != nil {
		t.Fatalf("ResolveRoute: %v", err)
	}
	if def.RouteID == solRoute {
		t.Fatalf("the feature default resolved the plan-pinned route %q; free accounts would be served by Sol", solRoute)
	}
	if def.Deployment != "luna" {
		t.Fatalf("feature default deployment = %q, want luna", def.Deployment)
	}
	// The digest feature's documented fallback to the session_enrichment route
	// must land on the same default, not on the plan-pinned row.
	dig, err := s.ResolveRouteForFeature(ctx, store.FeatureProjectDigest)
	if err != nil {
		t.Fatalf("ResolveRouteForFeature(project_digest): %v", err)
	}
	if dig.RouteID != def.RouteID {
		t.Fatalf("digest fallback route = %q, want the session_enrichment default %q", dig.RouteID, def.RouteID)
	}
}
