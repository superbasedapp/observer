package entitlements

import (
	"sort"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/components"
)

// serverBinaries are the binaries whose rows are server components (plan 06
// 17.2: the entitlement capability keys are the catalog's server rows).
func serverBinaries() []components.Binary {
	return []components.Binary{components.BinaryOrg, components.BinaryHarness, components.BinaryEdge}
}

// TestEveryServerRowHasAnEntitlementMapping is plan 07 M7b.1's acceptance
// test (plan 06 17.2): every non-core server catalog row has exactly one
// mapping row, and every mapping row names a real non-core server row. A
// new server component fails here until its gate is decided.
func TestEveryServerRowHasAnEntitlementMapping(t *testing.T) {
	t.Parallel()
	server := map[string]bool{}
	for _, b := range serverBinaries() {
		for _, c := range components.ForBinary(b) {
			if c.Class == components.ClassCore {
				continue
			}
			server[c.ID] = true
			if _, ok := GateOf(c.ID); !ok {
				t.Errorf("server component %s (%s) has no entitlement mapping row in capability.go", c.ID, b)
			}
		}
	}
	seen := map[string]bool{}
	for _, r := range gateRows() {
		if seen[r.id] {
			t.Errorf("mapping row %s appears twice", r.id)
		}
		seen[r.id] = true
		if !server[r.id] {
			t.Errorf("mapping row %s names no non-core server component", r.id)
		}
		if r.gate != GateIncluded && r.gate != GatePlan {
			t.Errorf("mapping row %s has unknown gate %q", r.id, r.gate)
		}
		if r.why == "" {
			t.Errorf("mapping row %s gives no reason", r.id)
		}
	}
	if len(seen) != len(server) {
		t.Errorf("%d mapping rows for %d server components", len(seen), len(server))
	}
}

// TestCoreIsNeverMapped: core is always entitled and never a capability.
func TestCoreIsNeverMapped(t *testing.T) {
	t.Parallel()
	for _, id := range components.IDs() {
		c, _ := components.Get(id)
		if c.Class == components.ClassCore {
			if _, ok := GateOf(id); ok {
				t.Errorf("core component %s has a mapping row", id)
			}
		}
	}
}

// TestGatedIDsPartitionTheMapping: the two gates partition the mapped ids.
func TestGatedIDsPartitionTheMapping(t *testing.T) {
	t.Parallel()
	all := append(GatedIDs(GateIncluded), GatedIDs(GatePlan)...)
	sort.Strings(all)
	mapped := mappedIDs()
	if len(all) != len(mapped) {
		t.Fatalf("gates cover %d ids, mapping has %d", len(all), len(mapped))
	}
	for i := range all {
		if all[i] != mapped[i] {
			t.Fatalf("gates and mapping differ at %d: %s vs %s", i, all[i], mapped[i])
		}
	}
	if gateReason("org.saml") == "" || gateReason("no.such") != "" {
		t.Error("gateReason does not follow the table")
	}
}

// TestFeatureRowsNameNoComponent: a feature row is a capability no catalog
// component stands for, so its id never names a component, it is plan-gated
// and it gives its reason; the ids are unique across both tables.
func TestFeatureRowsNameNoComponent(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for _, r := range gateRows() {
		seen[r.id] = true
	}
	for _, r := range featureRows() {
		if _, ok := components.Get(r.id); ok {
			t.Errorf("feature row %s names a catalog component: map it in gateRows instead", r.id)
		}
		if seen[r.id] {
			t.Errorf("feature row %s repeats a mapping id", r.id)
		}
		seen[r.id] = true
		if r.gate != GatePlan {
			t.Errorf("feature row %s has gate %q, want %q", r.id, r.gate, GatePlan)
		}
		if r.why == "" {
			t.Errorf("feature row %s gives no reason", r.id)
		}
	}
	if g, ok := GateOf(CapabilityOwnIdP); !ok || g != GatePlan {
		t.Errorf("GateOf(%s) = %q, %v; want plan", CapabilityOwnIdP, g, ok)
	}
}
