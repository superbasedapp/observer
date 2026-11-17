package components

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// TestResolveAvailabilityRows is one row per case of the two new resolver
// rows (plan 06 18.3.2, 18.3.7): not_available at layer 2 and not_entitled
// at layer 3, and their place in the table.
func TestResolveAvailabilityRows(t *testing.T) {
	t.Parallel()
	type want struct {
		id      string
		state   State
		reason  Reason
		because string
	}
	allBut := func(drop ...string) []string {
		var out []string
		for _, id := range IDs() {
			if !containsID(drop, id) {
				out = append(out, id)
			}
		}
		return out
	}
	cases := []struct {
		name    string
		in      ResolveInput
		want    []want
		wantErr string
	}{
		{
			name: "outside the availability ceiling is not_available",
			in: ResolveInput{
				Binary: BinaryOrg, Selected: []string{"org.saml"},
				Governance: &Governance{Availability: &Availability{Allow: allBut("org.saml")}},
			},
			want:    []want{{"org.saml", StateBlocked, ReasonNotAvailable, ""}, {"org.scim", StateAvailable, ReasonNotSelected, ""}},
			wantErr: "org.saml: not available here",
		},
		{
			name: "blocked at layer 2 while entitled is not_available",
			in: ResolveInput{
				Binary: BinaryOrg, Selected: []string{"org.saml"},
				Governance: &Governance{
					Availability: &Availability{Allow: allBut("org.saml")},
					Entitled:     &Entitlement{Allow: IDs()},
				},
			},
			want: []want{{"org.saml", StateBlocked, ReasonNotAvailable, ""}},
		},
		{
			name: "available but not entitled is not_entitled",
			in: ResolveInput{
				Binary: BinaryOrg, Selected: []string{"org.saml"},
				Governance: &Governance{
					Availability: &Availability{Allow: IDs()},
					Entitled:     &Entitlement{Allow: allBut("org.saml")},
				},
			},
			want:    []want{{"org.saml", StateBlocked, ReasonNotEntitled, ""}},
			wantErr: "org.saml: not included in this organization's plan",
		},
		{
			name: "both layers cleared leaves the selection active",
			in: ResolveInput{
				Binary: BinaryOrg, Selected: []string{"org.saml"},
				Governance: &Governance{Availability: &Availability{Allow: IDs()}, Entitled: &Entitlement{Allow: IDs()}},
			},
			want: []want{{"org.saml", StateActive, ReasonSelected, ""}},
		},
		{
			name: "an empty pinned availability set leaves core only",
			in: ResolveInput{
				Binary: BinaryOrg, Selected: []string{"org.saml"},
				Governance: &Governance{Availability: &Availability{}},
			},
			want: []want{{"org.core", StateActive, ReasonCore, ""}, {"org.saml", StateBlocked, ReasonNotAvailable, ""}},
		},
		{
			name: "an empty pinned entitlement leaves core only",
			in: ResolveInput{
				Binary: BinaryOrg, Selected: []string{"org.saml"},
				Governance: &Governance{Entitled: &Entitlement{}},
			},
			want: []want{{"org.core", StateActive, ReasonCore, ""}, {"org.saml", StateBlocked, ReasonNotEntitled, ""}},
		},
		{
			name: "availability beats the local ceiling in the reported reason",
			in: ResolveInput{
				Binary: BinaryOrg, Selected: []string{"org.saml"},
				Governance: &Governance{
					CeilingPinned: true,
					Availability:  &Availability{Allow: allBut("org.saml")},
				},
			},
			want: []want{{"org.saml", StateBlocked, ReasonNotAvailable, ""}},
		},
		{
			name: "availability beats a policy deny in the reported reason",
			in: ResolveInput{
				Binary: BinaryOrg,
				Governance: &Governance{
					Policy:       &PolicySets{Deny: []string{"org.saml"}},
					Availability: &Availability{Allow: allBut("org.saml")},
				},
			},
			want: []want{{"org.saml", StateBlocked, ReasonNotAvailable, ""}},
		},
		{
			name: "a not-compiled row stays absent whatever the layers say",
			in: ResolveInput{
				Binary: BinaryOrg, Compiled: []string{"org.core"},
				Governance: &Governance{Availability: &Availability{}},
			},
			want: []want{{"org.saml", StateAbsent, ReasonNotCompiled, ""}},
		},
		{
			name: "a dependant of an unavailable component is blocked through it",
			in: ResolveInput{
				Binary: BinaryOrg, Selected: []string{"org.security.relay"},
				Governance: &Governance{Availability: &Availability{Allow: allBut("org.security")}},
			},
			want: []want{
				{"org.security", StateBlocked, ReasonNotAvailable, ""},
				{"org.security.relay", StateBlocked, ReasonDeniedDependency, "org.security"},
			},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res := Resolve(tc.in)
			for _, w := range tc.want {
				d, ok := res.Decision(w.id)
				if !ok {
					t.Fatalf("no decision for %s", w.id)
				}
				if d.State != w.state || d.Reason != w.reason || d.Because != w.because {
					t.Errorf("%s = %+v, want %s/%s/%q", w.id, d, w.state, w.reason, w.because)
				}
			}
			joined := strings.Join(res.Errors, "\n")
			if tc.wantErr != "" && !strings.Contains(joined, tc.wantErr) {
				t.Errorf("errors %q lack %q", joined, tc.wantErr)
			}
		})
	}
}

// TestAvailabilityRowsSitAboveTheCeiling pins the table position: after
// "not compiled" and before "outside the local ceiling", availability then
// entitlement (plan 06 18.3.2).
func TestAvailabilityRowsSitAboveTheCeiling(t *testing.T) {
	t.Parallel()
	var order []Reason
	for _, r := range resolveRules {
		order = append(order, r.reason)
	}
	idx := func(r Reason) int {
		for i, x := range order {
			if x == r {
				return i
			}
		}
		return -1
	}
	if !(idx(ReasonNotCompiled) < idx(ReasonNotAvailable) &&
		idx(ReasonNotAvailable) < idx(ReasonNotEntitled) &&
		idx(ReasonNotEntitled) < idx(ReasonAboveCeiling)) {
		t.Fatalf("rule order wrong: %v", order)
	}
}

// TestGovernanceWithoutNewLayersIsUngovernedForAvailability is the single
// mode golden: a nil Availability and Entitled change nothing for any
// binary, with or without the existing governance inputs. The existing
// TestResolveTable, TestResolveGovernanceTable and
// TestResolveDefaultsPerDistro pass unchanged beside it.
func TestGovernanceWithoutNewLayersIsUngovernedForAvailability(t *testing.T) {
	t.Parallel()
	gov := []*Governance{
		{},
		{CeilingPinned: true, Ceiling: []string{"codeintel"}},
		{Policy: &PolicySets{Allow: []string{"codeintel"}, Deny: []string{"remote"}}},
	}
	for _, b := range Binaries() {
		for _, sel := range [][]string{nil, IDs()} {
			base := Resolve(ResolveInput{Binary: b, Selected: sel})
			withEmpty := Resolve(ResolveInput{Binary: b, Selected: sel, Governance: &Governance{}})
			if !reflect.DeepEqual(base, withEmpty) {
				t.Errorf("%s: empty Governance changes the result", b)
			}
			for _, g := range gov {
				g := g
				a := Resolve(ResolveInput{Binary: b, Selected: sel, Governance: g})
				cp := *g
				cp.Availability, cp.Entitled = nil, nil
				if !reflect.DeepEqual(a, Resolve(ResolveInput{Binary: b, Selected: sel, Governance: &cp})) {
					t.Errorf("%s: nil layers change the result", b)
				}
			}
		}
	}
	for _, shape := range []Shape{ShapeSingle, ShapeDedicated} {
		if got := EvaluateAvailability(&platformcontract.AvailabilityBody{}, shape, Subject{Org: "o"}, All()); got != nil {
			t.Errorf("%s evaluates to %v, want nil (no ceiling)", shape, got)
		}
	}
}

// TestLayersNeverWiden is the monotonicity property: adding availability or
// entitlement to any governance never activates a component the layer above
// did not.
func TestLayersNeverWiden(t *testing.T) {
	t.Parallel()
	sets := [][]string{nil, {"org.saml"}, {"org.security", "org.security.relay"}, PooledFloor(ForBinary(BinaryOrg)), IDs()}
	bases := []*Governance{
		nil,
		{CeilingPinned: true, Ceiling: []string{"org.saml", "org.scim"}},
		{Policy: &PolicySets{Allow: []string{"org.saml", "org.security"}}},
	}
	for bi, base := range bases {
		before := Resolve(ResolveInput{Binary: BinaryOrg, Selected: IDs(), Governance: base})
		beforeActive := toSet(before.Active())
		for _, av := range sets {
			for _, en := range sets {
				var g Governance
				if base != nil {
					g = *base
				}
				g.Availability = &Availability{Allow: av}
				g.Entitled = &Entitlement{Allow: en}
				after := Resolve(ResolveInput{Binary: BinaryOrg, Selected: IDs(), Governance: &g})
				for _, id := range after.Active() {
					if !beforeActive[id] {
						t.Errorf("base %d: %s active only with the extra layers (av=%v en=%v)", bi, id, av, en)
					}
				}
			}
		}
	}
}

// TestEveryRowHasReach is the pin: a catalog row without a valid Reach (a
// new row that neither sets ReachOf(stability) nor is grandfathered) fails.
func TestEveryRowHasReach(t *testing.T) {
	t.Parallel()
	for _, c := range All() {
		if !c.Reach.Valid() {
			t.Errorf("%s: Reach %s is missing or invalid; set Reach: ReachOf(Stability...) on the row", c.ID, c.Reach)
		}
	}
	for id := range grandfathered {
		if _, ok := Get(id); !ok {
			t.Errorf("grandfathered id %s is not in the catalog; delete it from the table", id)
		}
	}
	for _, s := range []Stability{StabilityExperimental, StabilityPreview, StabilityStable, StabilityDeprecated} {
		if !ReachOf(s).Valid() {
			t.Errorf("ReachOf(%s) is invalid", s)
		}
	}
}

// TestReachByStage is one row per stage of 18.3.3's table.
func TestReachByStage(t *testing.T) {
	t.Parallel()
	cases := []struct {
		s       Stability
		pooled  bool
		offer   bool
		private bool
	}{
		{StabilityExperimental, false, true, true},
		{StabilityPreview, false, true, true},
		{StabilityStable, true, true, true},
		{StabilityDeprecated, false, true, true},
	}
	for _, tc := range cases {
		r := ReachOf(tc.s)
		if r.Has(ReachPooled) != tc.pooled || r.Has(ReachPooledOffer) != tc.offer || r.Has(ReachSingle|ReachDedicated) != tc.private {
			t.Errorf("%s: reach %s", tc.s, r)
		}
	}
}

// TestGrandfatheredReach is one row per branch of the grandfather rule.
func TestGrandfatheredReach(t *testing.T) {
	t.Parallel()
	cases := []struct {
		id   string
		want Reach
	}{
		{"org.saml", ReachSingle | ReachDedicated | ReachPooled | ReachPooledOffer}, // image: in
		{"org.pollers.cc", ReachSingle | ReachDedicated | ReachPooledOffer},         // image: off
		{"org.sor.s3", ReachSingle | ReachDedicated},                                // image: per deploy
		{"org.harness", ReachSingle | ReachDedicated},                               // image: separate
		{"codeintel", ReachSingle | ReachDedicated | ReachPooled | ReachPooledOffer},
	}
	for _, tc := range cases {
		c, ok := Get(tc.id)
		if !ok || c.Reach != tc.want {
			t.Errorf("%s reach = %s, want %s", tc.id, c.Reach, tc.want)
		}
	}
}

// TestLaunchOpen pins the launch-open list: sorted output, real org rows,
// each offerable in pooled, and the floor is the pooled-on rows plus it.
func TestLaunchOpen(t *testing.T) {
	t.Parallel()
	got := LaunchOpen()
	if !sort.StringsAreSorted(got) || len(got) != len(launchOpen) {
		t.Fatalf("LaunchOpen = %v", got)
	}
	floor := toSet(PooledFloor(All()))
	for _, id := range got {
		c, ok := Get(id)
		if !ok || c.Binary != BinaryOrg {
			t.Errorf("launch-open id %s is not an org row", id)
			continue
		}
		if !c.Reach.Has(ReachPooledOffer) {
			t.Errorf("launch-open id %s is not offerable in pooled", id)
		}
		if !floor[id] {
			t.Errorf("launch-open id %s missing from the floor", id)
		}
	}
	// A row that is neither pooled-on nor launch-open is off at the floor.
	if floor["org.log.kafka"] || floor["org.aigateway"] {
		t.Errorf("floor opened a preview-off row: %v", PooledFloor(All()))
	}
	if !floor["org.saml"] || !floor["org.core"] {
		t.Errorf("floor lacks a pooled-on or core row")
	}
	// The floor cannot open a row whose Reach is not offerable.
	rows := []Component{{ID: "org.pollers.cc", Class: ClassServer, Reach: ReachSingle | ReachDedicated}}
	if len(PooledFloor(rows)) != 0 {
		t.Errorf("floor opened a launch-open id that is not offerable")
	}
}

// TestEvaluateAvailability is one row per case of the pooled evaluation.
func TestEvaluateAvailability(t *testing.T) {
	t.Parallel()
	offer := ReachSingle | ReachDedicated | ReachPooledOffer
	on := offer | ReachPooled
	rows := []Component{
		{ID: "org.core", Class: ClassCore, Reach: on},
		{ID: "stable", Class: ClassServer, Stability: StabilityStable, Reach: on},
		{ID: "preview", Class: ClassServer, Stability: StabilityPreview, Reach: offer},
		{ID: "exp", Class: ClassServer, Stability: StabilityExperimental, Reach: offer},
		{ID: "private", Class: ClassServer, Stability: StabilityStable, Reach: ReachSingle | ReachDedicated},
	}
	entry := func(id string, r platformcontract.Reach, orgs []string, cohort string) platformcontract.ComponentAvailability {
		return platformcontract.ComponentAvailability{Component: id, Reach: r, Orgs: orgs, Cohort: cohort, Reason: "r", Author: "a"}
	}
	body := func(es ...platformcontract.ComponentAvailability) *platformcontract.AvailabilityBody {
		return &platformcontract.AvailabilityBody{Components: es}
	}
	subj := Subject{Org: "acme", Cohorts: []string{"ring2"}}
	cases := []struct {
		name  string
		body  *platformcontract.AvailabilityBody
		shape Shape
		want  []string
	}{
		{"no envelope: the floor", nil, ShapePooled, []string{"org.core", "stable"}},
		{"unknown shape allows nothing", body(), Shape("x"), nil},
		{"no entry falls to the floor", body(), ShapePooled, []string{"org.core", "stable"}},
		{"off narrows a stable row", body(entry("stable", platformcontract.ReachOff, nil, "")), ShapePooled, []string{"org.core"}},
		{"stage-default is the floor rule", body(entry("preview", platformcontract.ReachStageDefault, nil, "")), ShapePooled, []string{"org.core", "stable"}},
		{"named lists the org", body(entry("preview", platformcontract.ReachNamed, []string{"acme"}, "")), ShapePooled, []string{"org.core", "preview", "stable"}},
		{"named for another org", body(entry("preview", platformcontract.ReachNamed, []string{"other"}, "")), ShapePooled, []string{"org.core", "stable"}},
		{"named narrows a stable row to its orgs", body(entry("stable", platformcontract.ReachNamed, []string{"other"}, "")), ShapePooled, []string{"org.core"}},
		{"named cannot widen a non-offerable row", body(entry("private", platformcontract.ReachNamed, []string{"acme"}, "")), ShapePooled, []string{"org.core", "stable"}},
		{"named opens experimental for a named org", body(entry("exp", platformcontract.ReachNamed, []string{"acme"}, "")), ShapePooled, []string{"exp", "org.core", "stable"}},
		{"cohort member", body(entry("preview", platformcontract.ReachCohort, nil, "ring2")), ShapePooled, []string{"org.core", "preview", "stable"}},
		{"cohort non-member", body(entry("preview", platformcontract.ReachCohort, nil, "ring3")), ShapePooled, []string{"org.core", "stable"}},
		{"cohort never opens experimental", body(entry("exp", platformcontract.ReachCohort, nil, "ring2")), ShapePooled, []string{"org.core", "stable"}},
		{"unknown reach fails closed", body(entry("stable", platformcontract.Reach("bogus"), nil, "")), ShapePooled, []string{"org.core"}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := EvaluateAvailability(tc.body, tc.shape, subj, rows)
			if got == nil {
				t.Fatal("nil availability for a pooled or unknown shape")
			}
			if !reflect.DeepEqual(append([]string(nil), got.Allow...), tc.want) {
				t.Errorf("allow = %v, want %v", got.Allow, tc.want)
			}
		})
	}
}

// TestCheckEnvelope is one row per catalog-side refusal.
func TestCheckEnvelope(t *testing.T) {
	t.Parallel()
	mk := func(id string, r platformcontract.Reach, orgs []string, cohort string) platformcontract.AvailabilityBody {
		return platformcontract.AvailabilityBody{Components: []platformcontract.ComponentAvailability{
			{Component: id, Reach: r, Orgs: orgs, Cohort: cohort, Reason: "r", Author: "a"},
		}}
	}
	cases := []struct {
		name string
		body platformcontract.AvailabilityBody
		want string
	}{
		{"fine: off", mk("org.saml", platformcontract.ReachOff, nil, ""), ""},
		{"fine: cohort on a preview row", mk("org.log.kafka", platformcontract.ReachCohort, nil, "ring2"), ""},
		{"unknown component", mk("org.nope", platformcontract.ReachOff, nil, ""), "org.nope: unknown component"},
		{"core listed", mk("org.core", platformcontract.ReachOff, nil, ""), "org.core: core is always available"},
		{"widening a non-offerable row", mk("org.harness", platformcontract.ReachNamed, []string{"o"}, ""), "org.harness: not offerable in pooled"},
	}
	for _, tc := range cases {
		err := CheckEnvelope(tc.body)
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: %v", tc.name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: err %v, want %q", tc.name, err, tc.want)
		}
	}
}

// TestParseDenyList is one row per accepted and refused shape.
func TestParseDenyList(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		in      string
		wantErr string
		entries int
	}{
		{"one entry", "version = 1\n[[deny]]\ncomponent = \"org.pollers.cc\"\nreason = \"leak\"\nauthor = \"ops\"\n", "", 1},
		{"scoped to orgs", "version = 1\n[[deny]]\ncomponent = \"org.pollers.cc\"\norgs = [\"a\", \"b\"]\nreason = \"x\"\nauthor = \"ops\"\n", "", 1},
		{"same component two scopes", "version = 1\n[[deny]]\ncomponent = \"org.saml\"\norgs=[\"a\"]\nreason=\"x\"\nauthor=\"o\"\n[[deny]]\ncomponent = \"org.saml\"\nreason=\"x\"\nauthor=\"o\"\n", "", 2},
		{"empty list", "version = 1\n", "", 0},
		{"not toml", "version = [", "components.ParseDenyList", 0},
		{"wrong version", "version = 2\n", "version must be 1", 0},
		{"missing version", "[[deny]]\ncomponent = \"org.saml\"\nreason=\"x\"\nauthor=\"o\"\n", "version must be 1", 0},
		{"unknown key", "version = 1\nallow = [\"org.saml\"]\n", "unknown keys: allow", 0},
		{"unknown entry key", "version = 1\n[[deny]]\ncomponent=\"org.saml\"\nreason=\"x\"\nauthor=\"o\"\nwiden=true\n", "unknown keys", 0},
		{"unknown component", "version = 1\n[[deny]]\ncomponent=\"org.nope\"\nreason=\"x\"\nauthor=\"o\"\n", "unknown component", 0},
		{"core refused", "version = 1\n[[deny]]\ncomponent=\"org.core\"\nreason=\"x\"\nauthor=\"o\"\n", "core and cannot be denied", 0},
		{"reason required", "version = 1\n[[deny]]\ncomponent=\"org.saml\"\nauthor=\"o\"\n", "reason is required", 0},
		{"author required", "version = 1\n[[deny]]\ncomponent=\"org.saml\"\nreason=\"x\"\n", "author is required", 0},
		{"blank org", "version = 1\n[[deny]]\ncomponent=\"org.saml\"\norgs=[\" \"]\nreason=\"x\"\nauthor=\"o\"\n", "blank org", 0},
		{"repeated org", "version = 1\n[[deny]]\ncomponent=\"org.saml\"\norgs=[\"a\",\"a\"]\nreason=\"x\"\nauthor=\"o\"\n", "listed twice", 0},
		{"repeated scope", "version = 1\n[[deny]]\ncomponent=\"org.saml\"\nreason=\"x\"\nauthor=\"o\"\n[[deny]]\ncomponent=\"org.saml\"\nreason=\"y\"\nauthor=\"o\"\n", "listed twice for the same scope", 0},
		{"wrong type", "version = 1\n[[deny]]\ncomponent=3\nreason=\"x\"\nauthor=\"o\"\n", "components.ParseDenyList", 0},
		{"too large", "version = 1\n# " + strings.Repeat("x", maxDenyListBytes), "over the", 0},
	}
	for _, tc := range cases {
		d, err := ParseDenyList([]byte(tc.in))
		if tc.wantErr == "" {
			if err != nil || len(d.Entries) != tc.entries {
				t.Errorf("%s: %v, %d entries", tc.name, err, len(d.Entries))
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%s: err %v, want %q", tc.name, err, tc.wantErr)
		}
		if len(d.Entries) != 0 {
			t.Errorf("%s: a failed parse returned entries", tc.name)
		}
	}
}

// TestDenyListOnlyNarrows is the break-glass property: for any starting
// availability, Narrow returns a subset, and the empty list returns the same
// set.
func TestDenyListOnlyNarrows(t *testing.T) {
	t.Parallel()
	rows := ForBinary(BinaryOrg)
	d, err := ParseDenyList([]byte("version = 1\n[[deny]]\ncomponent=\"org.saml\"\nreason=\"x\"\nauthor=\"o\"\n[[deny]]\ncomponent=\"org.scim\"\norgs=[\"acme\"]\nreason=\"x\"\nauthor=\"o\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	starts := []*Availability{nil, {}, {Allow: []string{"org.saml", "org.scim", "org.core"}}, {Allow: PooledFloor(rows)}}
	for _, org := range []string{"acme", "other"} {
		for _, av := range starts {
			got := d.Narrow(av, org, rows)
			base := toSet(nil)
			if av == nil {
				for _, c := range rows {
					base[c.ID] = true
				}
			} else {
				base = toSet(av.Allow)
			}
			for _, id := range got.Allow {
				if !base[id] {
					t.Errorf("org %s: %s appears after narrowing but not before", org, id)
				}
				if d.Denies(id, org) {
					t.Errorf("org %s: %s still allowed though denied", org, id)
				}
			}
			same := (DenyList{Version: 1}).Narrow(av, org, rows)
			if len(same.Allow) != len(base) {
				t.Errorf("empty list changed the set: %d vs %d", len(same.Allow), len(base))
			}
		}
	}
	if !d.Denies("org.saml", "x") || d.Denies("org.scim", "other") || !d.Denies("org.scim", "acme") {
		t.Error("Denies scope wrong")
	}
	// Feeding the narrowed set to the resolver blocks the denied row.
	res := Resolve(ResolveInput{
		Binary: BinaryOrg, Selected: []string{"org.saml"},
		Governance: &Governance{Availability: d.Narrow(nil, "acme", rows)},
	})
	if dec, _ := res.Decision("org.saml"); dec.Reason != ReasonNotAvailable {
		t.Errorf("org.saml = %+v", dec)
	}
}

// TestCheckEnvelopeExperimental (plan 06 18.3.7): an envelope that tries to
// make an experimental component generally available, by opening it to a
// cohort, is refused at verification; naming the org is allowed. No shipped
// org row is experimental today, so the catalog here is synthetic.
func TestCheckEnvelopeExperimental(t *testing.T) {
	t.Parallel()
	offer := ReachSingle | ReachDedicated | ReachPooledOffer
	synthetic := map[string]Component{
		"exp": {ID: "exp", Class: ClassServer, Stability: StabilityExperimental, Reach: offer},
	}
	get := func(id string) (Component, bool) { c, ok := synthetic[id]; return c, ok }
	entry := func(r platformcontract.Reach, orgs []string, cohort string) platformcontract.AvailabilityBody {
		return platformcontract.AvailabilityBody{Components: []platformcontract.ComponentAvailability{
			{Component: "exp", Reach: r, Orgs: orgs, Cohort: cohort, Reason: "r", Author: "a"},
		}}
	}
	if err := checkEnvelope(entry(platformcontract.ReachCohort, nil, "ring2"), get); err == nil || !strings.Contains(err.Error(), "experimental components are open to named orgs only") {
		t.Fatalf("cohort on an experimental row: %v", err)
	}
	if err := checkEnvelope(entry(platformcontract.ReachNamed, []string{"acme"}, ""), get); err != nil {
		t.Fatalf("named on an experimental row: %v", err)
	}
	if err := checkEnvelope(entry(platformcontract.ReachStageDefault, nil, ""), get); err != nil {
		t.Fatalf("stage-default on an experimental row: %v", err)
	}
}
