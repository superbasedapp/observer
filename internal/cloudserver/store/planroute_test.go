package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// The migration-0039/0041 suite: the per-plan allowances (0039 v2, then 0041
// v3: free 100/day + 3000/month, Plus 500/day + 15000/month) and the PER-PLAN
// route pin, whose whole point is that a paid plan degrades to the default
// model rather than to no service.

const (
	solRoute = "session_enrichment.sol.v1"
	// gpt6LunaRoute is migration 0041's GPT-6 Luna route (D-299): the route
	// both v3 plans pin, shipped inactive and unbound.
	gpt6LunaRoute = "session_enrichment.gpt-6-luna.v1"
	// haikuRoute is migration 0042's Claude Haiku 5.5 route, which both v4 plans
	// pin (0043), shipped inactive and unbound.
	haikuRoute = "session_enrichment.claude-haiku-5-5.v1"
	// lunaV1Route is the original feature default (0004).
	lunaV1Route = "session_enrichment.luna.v1"
)

// bindSolRoute moves the seeded Sol route from its shipped state (inactive,
// unbound) to the state an operator leaves it in after deploying gpt-5.6-sol:
// bound and active.
func bindSolRoute(t *testing.T, s *store.Store) {
	t.Helper()
	bindAndActivate(t, s, solRoute, "/arm/sol")
}

// bindAndActivate binds a seeded route to a synthetic Foundry endpoint and
// activates it - the state an operator leaves a route in after deploying it.
func bindAndActivate(t *testing.T, s *store.Store, routeID, arm string) {
	t.Helper()
	ctx := context.Background()
	if err := s.SetRouteBinding(ctx, routeID, store.RouteBinding{
		TenantID: "tenant", SubscriptionID: "sub", ARMResourceID: arm,
		EndpointAudience: "https://cognitiveservices.azure.com/.default",
		Endpoint:         "https://sbci-test-foundry.openai.azure.com", APIVersion: "2026-05-01",
	}); err != nil {
		t.Fatalf("SetRouteBinding(%s): %v", routeID, err)
	}
	if err := s.SetRouteActive(ctx, routeID, true); err != nil {
		t.Fatalf("SetRouteActive(%s, true): %v", routeID, err)
	}
}

// TestFreePlanV4Allowance pins the LITERAL v4 free numbers (not just
// "whatever DefaultFreePlanVersion points at"): daily 100 and monthly 3000
// (0041, kept by 0043), concurrency unchanged, and the Claude Haiku 5.5
// route pinned (0043).
func TestFreePlanV4Allowance(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	acct := makeAccount(t, s)

	a, err := s.ResolveAllowance(ctx, acct, store.FeatureSessionEnrichment, midMonth())
	if err != nil {
		t.Fatalf("ResolveAllowance: %v", err)
	}
	if a.Plan.Name != store.PlanFree || a.Plan.Version != 4 {
		t.Fatalf("fresh account resolves %s v%d, want free v4", a.Plan.Name, a.Plan.Version)
	}
	if a.DailyCap != 100 || a.MonthlyCap != 3000 || a.ConcurrencyCap != 2 {
		t.Fatalf("free v4 caps = %d/%d/%d, want 100/3000/2", a.DailyCap, a.MonthlyCap, a.ConcurrencyCap)
	}
	if a.Plan.RouteID != haikuRoute {
		t.Fatalf("free v4 route_id = %q, want %q", a.Plan.RouteID, haikuRoute)
	}
	if a.BudgetPool != "free" || a.Plan.Label != "Signed-in Free" {
		t.Fatalf("free v4 pool/label = %q / %q, want free / Signed-in Free (copied forward)", a.BudgetPool, a.Plan.Label)
	}
}

// TestPlusPlanV4AllowanceAndRoutePin pins the paid side: 5x free on both
// windows (500/day, 15000/month), concurrency 4 unchanged, the route pin
// moved to Claude Haiku 5.5 by 0043, and the columns neither 0041 nor 0043
// moves (digest entitlement, retention window, label) carried forward by the
// INSERT ... SELECT rather than silently reset.
func TestPlusPlanV4AllowanceAndRoutePin(t *testing.T) {
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
	if a.Plan.Version != 4 {
		t.Fatalf("latest plus version = %d, want 4", a.Plan.Version)
	}
	if a.DailyCap != 500 || a.MonthlyCap != 15000 || a.ConcurrencyCap != 4 {
		t.Fatalf("plus v4 caps = %d/%d/%d, want 500/15000/4", a.DailyCap, a.MonthlyCap, a.ConcurrencyCap)
	}
	if a.Plan.RouteID != haikuRoute {
		t.Fatalf("plus v4 route_id = %q, want %q", a.Plan.RouteID, haikuRoute)
	}
	if a.BudgetPool != "plus_beta" {
		t.Fatalf("plus v4 pool = %q, want plus_beta (never the free pool)", a.BudgetPool)
	}
	if !a.Plan.DigestWeekly || a.Plan.ResultsRetentionDays != 365 || a.Plan.Label != "Plus" {
		t.Fatalf("plus v4 carried digest_weekly=%v retention=%d label=%q, want true/365/Plus copied forward",
			a.Plan.DigestWeekly, a.Plan.ResultsRetentionDays, a.Plan.Label)
	}
}

// TestGPT6LunaRouteShipsInactiveThenBecomesTheDefault is the D-299 route
// contract end to end: as shipped, both v3 plans pin the GPT-6 Luna route but
// it is inactive and unbound, so jobs DEGRADE to the live luna.v1 default with
// the fallback signalled (never a fleet-wide refusal); once an operator binds
// and activates it, a pinned plan runs on it with no fallback, and it is also
// the FEATURE default (route_version 2 outranks luna.v1's 1), which the
// project-digest fallback follows.
func TestGPT6LunaRouteShipsInactiveThenBecomesTheDefault(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()

	r, err := s.RouteByID(ctx, gpt6LunaRoute)
	if err != nil {
		t.Fatalf("RouteByID(%s): %v", gpt6LunaRoute, err)
	}
	if r.Active || r.Endpoint != "" || r.APIVersion != "" {
		t.Fatalf("gpt-6 luna as shipped = active:%v endpoint:%q api:%q, want inactive + unbound", r.Active, r.Endpoint, r.APIVersion)
	}
	if r.Deployment != "gpt-6-luna" || r.Dialect != "chat_completions" || r.RouteVersion != 2 || r.PromptVersion != 1 {
		t.Fatalf("gpt-6 luna route = %+v, want deployment gpt-6-luna, chat_completions, route_version 2, prompt_version 1", r)
	}
	// max_output_tokens 1024 caps the answer length (operator ruling D-313, T-414).
	if r.InputPricePerMTok != 0.10 || r.OutputPricePerMTok != 0.50 || r.MaxOutputTokens != 1024 {
		t.Fatalf("gpt-6 luna snapshot = in %v out %v max %d, want 0.10 / 0.50 / 1024",
			r.InputPricePerMTok, r.OutputPricePerMTok, r.MaxOutputTokens)
	}
	ks, err := s.KillSwitches(ctx, gpt6LunaRoute)
	if err != nil || ks.RouteActive {
		t.Fatalf("gpt-6 luna kill switch = %+v err=%v, want a seeded, inactive sentinel", ks, err)
	}

	// 1) As shipped: the pinned route degrades to luna.v1, signalled.
	got, fb, err := s.ResolveRouteForPlan(ctx, store.FeatureSessionEnrichment, gpt6LunaRoute)
	if err != nil {
		t.Fatalf("ResolveRouteForPlan(inactive gpt-6 luna): %v", err)
	}
	if got.RouteID != lunaV1Route || !fb.Fell() || fb.Reason != store.PlanRouteInactive {
		t.Fatalf("as shipped: served %q fallback %+v, want %q with an inactive fallback", got.RouteID, fb, lunaV1Route)
	}
	def, err := s.ResolveRoute(ctx, store.FeatureSessionEnrichment)
	if err != nil || def.RouteID != lunaV1Route {
		t.Fatalf("feature default as shipped = %q err=%v, want %q (the new route is inactive)", def.RouteID, err, lunaV1Route)
	}

	// 2) Bound + active: served directly, and it is the feature default.
	bindAndActivate(t, s, gpt6LunaRoute, "/arm/gpt-6-luna")
	got, fb, err = s.ResolveRouteForPlan(ctx, store.FeatureSessionEnrichment, gpt6LunaRoute)
	if err != nil || got.RouteID != gpt6LunaRoute || fb.Fell() {
		t.Fatalf("bound + active: served %q fallback %+v err=%v, want %q with no fallback", got.RouteID, fb, err, gpt6LunaRoute)
	}
	def, err = s.ResolveRoute(ctx, store.FeatureSessionEnrichment)
	if err != nil || def.RouteID != gpt6LunaRoute {
		t.Fatalf("feature default after activation = %q err=%v, want %q (route_version 2 wins)", def.RouteID, err, gpt6LunaRoute)
	}
	dig, err := s.ResolveRouteForFeature(ctx, store.FeatureProjectDigest)
	if err != nil || dig.RouteID != gpt6LunaRoute {
		t.Fatalf("digest fallback after activation = %q err=%v, want %q", dig.RouteID, err, gpt6LunaRoute)
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
	if err := s.SetRouteActive(ctx, lunaV1Route, false); err != nil {
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
