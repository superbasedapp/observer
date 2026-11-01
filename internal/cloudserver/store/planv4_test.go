package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// bindHaikuRoute leaves migration 0042's Haiku route in the state
// `observer-cloud route bind-anthropic --activate` leaves it in.
func bindHaikuRoute(t *testing.T, s *store.Store) {
	t.Helper()
	ctx := context.Background()
	if err := s.SetRouteBinding(ctx, haikuRoute, store.RouteBinding{
		TenantID: "anthropic", SubscriptionID: "default", ARMResourceID: "anthropic:messages:claude-haiku-5-5",
		EndpointAudience: "https://api.anthropic.com", Endpoint: "https://api.anthropic.com", APIVersion: "2023-06-01",
	}); err != nil {
		t.Fatalf("SetRouteBinding(haiku): %v", err)
	}
	if err := s.SetRouteActive(ctx, haikuRoute, true); err != nil {
		t.Fatalf("SetRouteActive(haiku): %v", err)
	}
}

// TestPlanV4PinsHaikuAndRoutesDirectly is the "Pin Haiku" contract (0043):
// both current plans pin the Haiku route; as shipped (route inactive) a pinned
// plan still degrades to the live default with the fallback signalled, and
// once the route is bound and active every plan routes to it DIRECTLY, with no
// plan_route_unavailable fallback. v3 stays readable, still pinning GPT-6 Luna.
func TestPlanV4PinsHaikuAndRoutesDirectly(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	now := midMonth()
	free := makeAccount(t, s)
	plus := makeAccount(t, s)
	if _, err := s.AssignPlan(ctx, plus, store.PlanPlusBeta, store.LatestPlanVersion, time.Time{}, now); err != nil {
		t.Fatalf("AssignPlan(plus, latest): %v", err)
	}

	pins := map[string]string{}
	for _, acct := range []string{free, plus} {
		a, err := s.ResolveAllowance(ctx, acct, store.FeatureSessionEnrichment, now)
		if err != nil {
			t.Fatalf("ResolveAllowance: %v", err)
		}
		if a.Plan.Version != 4 || a.Plan.RouteID != haikuRoute {
			t.Fatalf("%s resolves v%d pinned %q, want v4 pinned %q", a.Plan.Name, a.Plan.Version, a.Plan.RouteID, haikuRoute)
		}
		pins[a.Plan.Name] = a.Plan.RouteID
	}
	if len(pins) != 2 {
		t.Fatalf("plans resolved = %v, want free and plus_beta", pins)
	}

	// As shipped: the Haiku route is inactive, so the pin degrades, signalled.
	got, fb, err := s.ResolveRouteForPlan(ctx, store.FeatureSessionEnrichment, haikuRoute)
	if err != nil {
		t.Fatalf("ResolveRouteForPlan(inactive haiku): %v", err)
	}
	if got.RouteID != lunaV1Route || !fb.Fell() || fb.Reason != store.PlanRouteInactive {
		t.Fatalf("as shipped: served %q fallback %+v, want %q with an inactive fallback", got.RouteID, fb, lunaV1Route)
	}

	// Bound + active: served directly, no fallback; also the feature default.
	bindHaikuRoute(t, s)
	got, fb, err = s.ResolveRouteForPlan(ctx, store.FeatureSessionEnrichment, haikuRoute)
	if err != nil || got.RouteID != haikuRoute || fb.Fell() {
		t.Fatalf("bound + active: served %q fallback %+v err=%v, want %q with no fallback", got.RouteID, fb, err, haikuRoute)
	}
	if got.Dialect != "anthropic_messages" || got.Deployment != "claude-haiku-5-5" {
		t.Fatalf("served route = %s / %s, want anthropic_messages / claude-haiku-5-5", got.Dialect, got.Deployment)
	}
	def, err := s.ResolveRoute(ctx, store.FeatureSessionEnrichment)
	if err != nil || def.RouteID != haikuRoute {
		t.Fatalf("feature default after activation = %q err=%v, want %q (route_version 3)", def.RouteID, err, haikuRoute)
	}

	// v3 history is readable and unchanged.
	for _, name := range []string{"free", "plus_beta"} {
		var route *string
		if err := pool.QueryRow(ctx, `SELECT route_id FROM plans WHERE name=$1 AND version=3`, name).
			Scan(&route); err != nil {
			t.Fatalf("read %s v3: %v", name, err)
		}
		if route == nil || *route != gpt6LunaRoute {
			t.Fatalf("%s v3 route = %v, want the historical %q", name, route, gpt6LunaRoute)
		}
	}
}

// TestActiveRoutesListsEveryActiveRouteOfAFeature pins the read the
// `route bind-anthropic --exclusive` retirement uses: plan-pinned routes are
// included (a pinned route is live for its plan), inactive ones are not.
func TestActiveRoutesListsEveryActiveRouteOfAFeature(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	bindSolRoute(t, s) // plan-pinned, now active
	bindHaikuRoute(t, s)
	routes, err := s.ActiveRoutes(ctx, store.FeatureSessionEnrichment)
	if err != nil {
		t.Fatalf("ActiveRoutes: %v", err)
	}
	var ids []string
	for _, r := range routes {
		ids = append(ids, r.RouteID)
	}
	want := []string{haikuRoute, lunaV1Route, solRoute} // route_id order
	if len(ids) != len(want) {
		t.Fatalf("active routes = %v, want %v", ids, want)
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("active routes = %v, want %v", ids, want)
		}
	}
}
