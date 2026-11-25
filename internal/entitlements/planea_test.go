package entitlements

import (
	"fmt"
	"slices"
	"testing"
	"time"
)

// TestPlaneACatalogRows pins the Plane A packaging (plan-of-record D14, D20;
// W4-5): which catalog plan carries which Plane A allowance and request
// rate, read the way the gateway reads them (Evaluate, then Cap). One row
// per plan the packaging names.
//
//   - Business v2 sells the gateway: 10M events and 50 GB a month, and a
//     request rate above the team floor's.
//   - Business v1 and Team stay as released: no Plane A allowance of their
//     own, so the team floor's 0 applies (the gateway is not part of them).
//   - Dedicated and self-hosted documents cannot carry a Plane A cap at
//     all: they meter, and cap only where the org sets its own cap.
func TestPlaneACatalogRows(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0)
	teamFloor, _ := Floor(KindTeam)
	floorRPS := teamFloor.Caps[CapRequestsRPS]
	cases := []struct {
		plan    string
		version int
		// events and gb are the effective caps; set false means no cap.
		events, gb int64
		set        bool
		// rpsAbove: the effective requests.rps is above the team floor's.
		rpsAbove bool
	}{
		{plan: "business", version: 3, events: 10_000_000, gb: 50, set: true, rpsAbove: true},
		{plan: "business", version: 2, events: 10_000_000, gb: 50, set: true, rpsAbove: true},
		{plan: "business", version: 1, events: 0, gb: 0, set: true},
		{plan: "team", version: 1, events: 0, gb: 0, set: true},
		// L-166: the personal v2 rows carry their own allowance; a v1
		// document (issued before L-166) still composes with the v2 floor
		// at the host, so it holds Personal Free's allowance until the
		// issuer replaces it.
		{plan: "personal_free", version: 3, events: PersonalFreePlaneAEvents, gb: PersonalFreePlaneAGB, set: true},
		{plan: "personal_pro", version: 3, events: PersonalProPlaneAEvents, gb: PersonalProPlaneAGB, set: true},
		{plan: "personal_free", version: 2, events: PersonalFreePlaneAEvents, gb: PersonalFreePlaneAGB, set: true},
		{plan: "personal_pro", version: 2, events: PersonalProPlaneAEvents, gb: PersonalProPlaneAGB, set: true},
		{plan: "personal_free", version: 1, events: PersonalFreePlaneAEvents, gb: PersonalFreePlaneAGB, set: true},
		{plan: "personal_pro", version: 1, events: PersonalFreePlaneAEvents, gb: PersonalFreePlaneAGB, set: true},
		{plan: "dedicated", version: 1},
		{plan: "self_hosted", version: 1},
		{plan: "community", version: 1},
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
			ev, gb := e.Cap(CapPlaneAEventsMonthly), e.Cap(CapPlaneAGBMonthly)
			if ev.Set != tc.set || gb.Set != tc.set || ev.Unlimited || gb.Unlimited {
				t.Fatalf("caps set = %v/%v unlimited %v/%v, want set %v", ev.Set, gb.Set, ev.Unlimited, gb.Unlimited, tc.set)
			}
			if ev.N != tc.events || gb.N != tc.gb {
				t.Fatalf("caps = %d events / %d GB, want %d / %d", ev.N, gb.N, tc.events, tc.gb)
			}
			if tc.rpsAbove {
				rps, burst := e.Cap(CapRequestsRPS), e.Cap(CapRequestsBurst)
				if !rps.Set || rps.N <= floorRPS || burst.N < rps.N {
					t.Fatalf("requests = %d rps / %d burst, want above the team floor's %d", rps.N, burst.N, floorRPS)
				}
			}
			if !tc.set && (slices.Contains(capsFor(b.Kind), CapPlaneAEventsMonthly) || slices.Contains(capsFor(b.Kind), CapPlaneAGBMonthly)) {
				t.Fatalf("kind %s may carry a Plane A cap; it must only meter", b.Kind)
			}
		})
	}
}

// TestHighestBusinessVersionSellsPlaneA: a version-0 lookup (what a price
// mapped without a version, the metering tests and Compose(…, 0) use)
// resolves to the version that carries the Plane A allowance.
func TestHighestBusinessVersionSellsPlaneA(t *testing.T) {
	t.Parallel()
	b, ok := Plan("business", 0)
	if !ok || b.Caps[CapPlaneAEventsMonthly] != 10_000_000 || b.Caps[CapPlaneAGBMonthly] != 50 {
		t.Fatalf("highest business = v%d caps %v", b.Plan.Version, b.Caps)
	}
}

// TestPersonalPlansSellPlaneA pins operator ruling L-166 (2026-11-24): the
// newest Personal Free and Personal Pro hold the AI Apps gateway capability
// and their allowance, Pro's above Free's on both axes, and the personal
// floor is the version that sells it (a personal org with no document at
// all may send traces).
func TestPersonalPlansSellPlaneA(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0)
	free, okF := Plan("personal_free", 0)
	pro, okP := Plan("personal_pro", 0)
	if !okF || !okP {
		t.Fatal("no personal plans in the catalog")
	}
	for _, b := range []Body{free, pro} {
		if !slices.Contains(b.Capabilities, CapabilityPlaneAGateway) {
			t.Errorf("%s v%d does not list %s", b.Plan.Name, b.Plan.Version, CapabilityPlaneAGateway)
		}
	}
	if pro.Caps[CapPlaneAEventsMonthly] <= free.Caps[CapPlaneAEventsMonthly] || pro.Caps[CapPlaneAGBMonthly] <= free.Caps[CapPlaneAGBMonthly] {
		t.Errorf("Pro's allowance %v is not above Free's %v", pro.Caps, free.Caps)
	}
	floor, _ := Floor(KindPersonal)
	if floor.Plan != free.Plan {
		t.Errorf("personal floor = %+v, want the newest Personal Free %+v", floor.Plan, free.Plan)
	}
	e := Evaluate(KindPersonal, nil, now)
	if !e.Has(CapabilityPlaneAGateway) {
		t.Fatal("a personal org on the floor alone is not entitled to the gateway")
	}
	if c := e.Cap(CapPlaneAEventsMonthly); !c.Set || c.N != PersonalFreePlaneAEvents {
		t.Fatalf("floor events cap = %+v", c)
	}
	// The team kind is unchanged: its floor still grants no gateway.
	if Evaluate(KindTeam, nil, now).Has(CapabilityPlaneAGateway) {
		t.Fatal("the team floor grants the gateway")
	}
}
