package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

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
