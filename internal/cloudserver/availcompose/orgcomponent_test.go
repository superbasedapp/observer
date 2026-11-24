package availcompose

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/components"
	pc "github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// TestOrgComponentsAreNamedOffers: every per-org component is a catalog row
// an envelope may open to named orgs in pooled (ReachPooledOffer), is not on
// the pooled launch floor (so off is its default: SR-17 keeps org.security
// off unless staff turn it on), and is not core.
func TestOrgComponentsAreNamedOffers(t *testing.T) {
	t.Parallel()
	if len(OrgComponents()) != len(orgComponentIDs) {
		t.Fatalf("OrgComponents() = %v, table %v: an id is not in the catalog", OrgComponents(), orgComponentIDs)
	}
	for _, id := range orgComponentIDs {
		c, ok := components.Get(id)
		if !ok {
			t.Fatalf("%s is not in the catalog", id)
		}
		if c.Class == components.ClassCore || !c.Reach.Has(components.ReachPooledOffer) {
			t.Errorf("%s: class %s reach %s; a per-org component must be offerable in pooled", id, c.Class, c.Reach)
		}
		if onFloor(id) || slices.Contains(components.LaunchOpen(), id) {
			t.Errorf("%s is on the pooled launch floor; off must stay its default", id)
		}
	}
}

func TestOffered(t *testing.T) {
	t.Parallel()
	named := &pc.AvailabilityBody{IssuedAt: rowCheckTime, Components: []pc.ComponentAvailability{
		{Component: "org.security", Reach: pc.ReachNamed, Orgs: []string{orgA}, Reason: "r", Author: "staff:a"},
	}}
	off := &pc.AvailabilityBody{IssuedAt: rowCheckTime, Components: []pc.ComponentAvailability{
		{Component: "org.security", Reach: pc.ReachOff, Reason: "r", Author: "staff:a"},
	}}
	cohort := &pc.AvailabilityBody{IssuedAt: rowCheckTime, Components: []pc.ComponentAvailability{
		{Component: "org.security", Reach: pc.ReachCohort, Cohort: "ring-1", Reason: "r", Author: "staff:a"},
	}}
	empty := &pc.AvailabilityBody{IssuedAt: rowCheckTime}
	cases := []struct {
		name string
		body *pc.AvailabilityBody
		org  string
		comp string
		want bool
	}{
		{"named, the org", named, orgA, "org.security", true},
		{"named, another org", named, orgB, "org.security", false},
		{"off", off, orgA, "org.security", false},
		{"cohort (membership is the host's)", cohort, orgA, "org.security", false},
		{"no row: floor (off)", empty, orgA, "org.security", false},
		{"no envelope: floor (off)", nil, orgA, "org.security", false},
		{"no envelope: a launch-open component", nil, orgA, "org.vendorconn", true},
		{"unknown component", named, orgA, "no.such", false},
	}
	for _, c := range cases {
		if got := Offered(c.body, c.comp, c.org); got != c.want {
			t.Errorf("%s: Offered = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestToggleTable: one case per toggle rule row, plus the refusals.
func TestToggleTable(t *testing.T) {
	t.Parallel()
	namedA := []byte(`{"reach":"named","orgs":["` + orgA + `"]}`)
	namedAB := []byte(`{"reach":"named","orgs":["` + orgB + `","` + orgA + `"]}`) // sorted: orgB < orgA
	cases := []struct {
		name    string
		current []byte
		org     string
		on      bool
		changed bool
		want    string // the value written ("" = removed)
		err     string
	}{
		{"no row, on", nil, orgA, true, true, string(namedA), ""},
		{"no row, off", nil, orgA, false, false, "", ""},
		{"named, on, add", namedA, orgB, true, true, string(namedAB), ""},
		{"named, on, already", namedA, orgA, true, false, string(namedA), ""},
		{"named, off, remove one", namedAB, orgB, false, true, string(namedA), ""},
		{"named, off, the last", namedA, orgA, false, true, "", ""},
		{"named, off, not listed", namedA, orgB, false, false, string(namedA), ""},
		{"off, on", []byte(`{"reach":"off"}`), orgA, true, true, string(namedA), ""},
		{"off, off", []byte(`{"reach":"off"}`), orgA, false, false, `{"reach":"off"}`, ""},
		{"stage default, on", []byte(`{"reach":"stage-default"}`), orgA, true, true, string(namedA), ""},
		{"stage default, off", []byte(`{"reach":"stage-default"}`), orgA, false, false, `{"reach":"stage-default"}`, ""},
		{"cohort, on", []byte(`{"reach":"cohort","cohort":"ring-1"}`), orgA, true, false, "", "cohort"},
		{"cohort, off", []byte(`{"reach":"cohort","cohort":"ring-1"}`), orgA, false, false, "", "cohort"},
		{"unreadable row", []byte(`{"reach":"named","bogus":1}`), orgA, true, false, "", "does not decode"},
		{"unknown reach", []byte(`{"reach":"sometimes"}`), orgA, true, false, "", "unknown reach"},
		{"bad org id", nil, "acme", true, false, "", "not an org id"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got, err := Toggle("org.security", c.current, c.org, c.on)
			if c.err != "" {
				if err == nil || !errors.Is(err, ErrToggle) || !strings.Contains(err.Error(), c.err) {
					t.Fatalf("Toggle err = %v, want ErrToggle naming %q", err, c.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.Changed != c.changed {
				t.Errorf("Changed = %v, want %v", got.Changed, c.changed)
			}
			if string(got.Value) != c.want {
				t.Errorf("Value = %s, want %s", got.Value, c.want)
			}
			if got.Changed && got.Value != nil {
				if err := ValidateInput(SectionComponents, "org.security", got.Value); err != nil {
					t.Errorf("the toggled value does not validate: %v", err)
				}
			}
			// The written state is the one asked for.
			if got.Changed && InputOffered("org.security", got.Value, c.org) != c.on {
				t.Errorf("after the toggle the input offers %v to the org, want %v", !c.on, c.on)
			}
		})
	}
	if _, err := Toggle("org.digest", nil, orgA, true); !errors.Is(err, ErrToggle) {
		t.Errorf("a component outside the per-org table: %v", err)
	}
}

// TestToggleRulesCoverEveryReach: every reach (and no row) has a rule for
// on and off, on and off the floor.
func TestToggleRulesCoverEveryReach(t *testing.T) {
	t.Parallel()
	for _, r := range append([]pc.Reach{""}, pc.KnownReaches()...) {
		for _, on := range []bool{true, false} {
			for _, floor := range []bool{true, false} {
				if _, ok := toggleRuleFor(r, on, floor); !ok {
					t.Errorf("no toggle rule for reach %q on=%v floor=%v", r, on, floor)
				}
			}
		}
	}
}

func TestInputOffered(t *testing.T) {
	t.Parallel()
	v, _ := json.Marshal(map[string]any{"reach": "named", "orgs": []string{orgA}})
	if !InputOffered("org.security", v, orgA) || InputOffered("org.security", v, orgB) {
		t.Error("named input offered wrongly")
	}
	if InputOffered("org.security", nil, orgA) {
		t.Error("no row offered org.security (it is not on the floor)")
	}
	if InputOffered("org.security", []byte(`{"reach":"bogus"}`), orgA) {
		t.Error("an invalid row offered the component")
	}
}
