package entitlements

import (
	"fmt"
	"slices"
	"testing"
	"time"
)

// TestAIGatewayCatalogRows pins the hosted AI gateway packaging (L-172;
// decision 4 of L-174; plan 3.13): which catalog plan carries which AI
// gateway allowance, read the way the gateway's meter reads it (Evaluate,
// then Cap and Has). One row per plan the packaging names.
//
//   - personal_free v3 (the personal floor) and personal_pro v3 list the
//     capability with their allowance; Business v3 sells 1M requests and 64
//     in flight.
//   - Business v1 and v2 already list org.aigateway but set no cap: the team
//     floor (team_lapsed v2) sets 0, so they hold 0, "not in the plan", never
//     unlimited (plan R10). Team lists no capability and holds 0.
//   - A v1 or v2 personal document composes with the v3 floor, so it holds
//     Personal Free's allowance until the issuer replaces it.
//   - Dedicated and self-hosted documents cannot carry an AI gateway cap at
//     all (they run their own gateway; uncapped by plan).
func TestAIGatewayCatalogRows(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0)
	cases := []struct {
		plan        string
		version     int
		has         bool
		requests    int64
		concurrency int64
		set         bool
	}{
		{plan: "personal_free", version: 3, has: true, requests: PersonalFreeAIGWRequests, concurrency: PersonalFreeAIGWConcurrency, set: true},
		{plan: "personal_pro", version: 3, has: true, requests: PersonalProAIGWRequests, concurrency: PersonalProAIGWConcurrency, set: true},
		{plan: "personal_free", version: 2, has: true, requests: PersonalFreeAIGWRequests, concurrency: PersonalFreeAIGWConcurrency, set: true},
		{plan: "personal_pro", version: 2, has: true, requests: PersonalFreeAIGWRequests, concurrency: PersonalFreeAIGWConcurrency, set: true},
		{plan: "business", version: 3, has: true, requests: BusinessAIGWRequests, concurrency: BusinessAIGWConcurrency, set: true},
		{plan: "business", version: 2, has: true, requests: 0, concurrency: 0, set: true},
		{plan: "business", version: 1, has: true, requests: 0, concurrency: 0, set: true},
		{plan: "team", version: 1, has: false, requests: 0, concurrency: 0, set: true},
		{plan: "team_lapsed", version: 2, has: false, requests: 0, concurrency: 0, set: true},
		{plan: "dedicated", version: 1, has: true},
		{plan: "self_hosted", version: 1, has: true},
		{plan: "community", version: 1, has: true},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%s_v%d", tc.plan, tc.version), func(t *testing.T) {
			t.Parallel()
			b, ok := Plan(tc.plan, tc.version)
			if !ok {
				t.Fatalf("no catalog plan %s v%d", tc.plan, tc.version)
			}
			d := mustDoc(t, b, "org-a")
			e := Evaluate(b.Kind, &d, now)
			if e.Source() != SourceDocument {
				t.Fatalf("source = %s (%s)", e.Source(), e.Fallback())
			}
			if got := e.Has(CapabilityAIGateway); got != tc.has {
				t.Fatalf("Has(%s) = %v, want %v", CapabilityAIGateway, got, tc.has)
			}
			req, conc := e.Cap(CapAIGWRequestsMonthly), e.Cap(CapAIGWConcurrency)
			if req.Set != tc.set || conc.Set != tc.set || req.Unlimited || conc.Unlimited {
				t.Fatalf("caps set = %v/%v unlimited %v/%v, want set %v", req.Set, conc.Set, req.Unlimited, conc.Unlimited, tc.set)
			}
			if req.N != tc.requests || conc.N != tc.concurrency {
				t.Fatalf("caps = %d requests / %d in flight, want %d / %d", req.N, conc.N, tc.requests, tc.concurrency)
			}
			if !tc.set && (slices.Contains(capsFor(b.Kind), CapAIGWRequestsMonthly) || slices.Contains(capsFor(b.Kind), CapAIGWConcurrency)) {
				t.Fatalf("kind %s may carry an AI gateway cap; it must not", b.Kind)
			}
		})
	}
}

// TestAIGatewayFloors: both pooled floors set the AI gateway caps (so an
// absent document cap always falls back to a stated value), the team floor
// at 0, and a floor alone answers the way the plan says: a personal org with
// no document holds Personal Free's allowance, a team org with none holds 0.
func TestAIGatewayFloors(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0)
	personal := Evaluate(KindPersonal, nil, now)
	if !personal.Has(CapabilityAIGateway) || personal.Cap(CapAIGWRequestsMonthly).N != PersonalFreeAIGWRequests || personal.Cap(CapAIGWConcurrency).N != PersonalFreeAIGWConcurrency {
		t.Fatalf("personal floor: has %v, caps %+v / %+v", personal.Has(CapabilityAIGateway), personal.Cap(CapAIGWRequestsMonthly), personal.Cap(CapAIGWConcurrency))
	}
	team := Evaluate(KindTeam, nil, now)
	if team.Has(CapabilityAIGateway) {
		t.Fatal("the team floor grants the AI gateway")
	}
	for _, n := range []CapName{CapAIGWRequestsMonthly, CapAIGWConcurrency} {
		if c := team.Cap(n); !c.Set || c.Unlimited || c.N != 0 {
			t.Fatalf("team floor %s = %+v, want a set 0", n, c)
		}
	}
	f, _ := Floor(KindTeam)
	if f.Plan.Name != "team_lapsed" || f.Plan.Version != 2 {
		t.Fatalf("team floor = %+v, want team_lapsed v2", f.Plan)
	}
}

// TestAIGatewayAllowancesRise: Pro above Free, Business above Pro, on both
// axes (a refusal offers the larger plan from these).
func TestAIGatewayAllowancesRise(t *testing.T) {
	t.Parallel()
	free, _ := Plan("personal_free", 0)
	pro, _ := Plan("personal_pro", 0)
	biz, _ := Plan("business", 0)
	for _, n := range []CapName{CapAIGWRequestsMonthly, CapAIGWConcurrency} {
		if !(free.Caps[n] > 0 && pro.Caps[n] > free.Caps[n] && biz.Caps[n] > pro.Caps[n]) {
			t.Errorf("%s: free %d, pro %d, business %d; want rising", n, free.Caps[n], pro.Caps[n], biz.Caps[n])
		}
	}
	if got := GrantingPlans(KindTeam, CapabilityAIGateway); len(got) != 1 || got[0].Plan.Name != "business" || got[0].Plan.Version != 3 {
		t.Errorf("GrantingPlans(team, aigateway) = %+v", got)
	}
}

// TestOnFloorPlan: one case per answer. The floor alone and a document of
// the floor's plan (any version) are on the floor; a plan above it is not;
// an unknown kind is not.
func TestOnFloorPlan(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0)
	doc := func(name string, version int) *Document {
		b, err := Compose(name, version, "org-1", 1, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		return &Document{Body: b}
	}
	cases := []struct {
		name string
		kind Kind
		d    *Document
		want bool
	}{
		{"personal floor alone", KindPersonal, nil, true},
		{"personal_free v3 document", KindPersonal, doc("personal_free", 3), true},
		{"personal_free v2 document", KindPersonal, doc("personal_free", 2), true},
		{"personal_pro v3 document", KindPersonal, doc("personal_pro", 3), false},
		{"team floor alone", KindTeam, nil, true},
		{"business v3 document", KindTeam, doc("business", 3), false},
		{"unknown kind", "nope", nil, false},
	}
	for _, tc := range cases {
		if got := Evaluate(tc.kind, tc.d, now).OnFloorPlan(); got != tc.want {
			t.Errorf("%s: OnFloorPlan = %v, want %v", tc.name, got, tc.want)
		}
	}
}
