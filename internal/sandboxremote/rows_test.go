package sandboxremote

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
)

// TestVendorTableMatchesRegistryRows keeps the registry rows (what
// selection reads) and the vendor table (what the drivers do) one story:
// the same tiers and sources, the lifetime cap is the shortest plan's, the
// PTY owner follows GuestPTY, reattach follows Reattach.
func TestVendorTableMatchesRegistryRows(t *testing.T) {
	for _, id := range VendorIDs() {
		v, _ := VendorFor(id)
		row, ok := sandboxbackend.Get(id)
		if !ok {
			t.Fatalf("%s: no registry row", id)
		}
		tiers := v.TierList()
		if len(tiers) != len(row.Net.Egress) {
			t.Errorf("%s: vendor tiers %v, row %v", id, tiers, row.Net.Egress)
		}
		for _, tr := range tiers {
			if !row.OffersTier(tr) || row.Net.EgressSource[tr] != v.Tiers[tr].Source {
				t.Errorf("%s: tier %s source row %s vendor %s", id, tr, row.Net.EgressSource[tr], v.Tiers[tr].Source)
			}
		}
		if row.LifetimeCapSeconds != v.MinLifetimeMinutes()*60 {
			t.Errorf("%s: row lifetime %d, vendor shortest plan %d min", id, row.LifetimeCapSeconds, v.MinLifetimeMinutes())
		}
		if (row.Term.PTYOwner == sandboxbackend.PTYGuestHelper) != v.GuestPTY {
			t.Errorf("%s: PTY owner %s, vendor guest PTY %v", id, row.Term.PTYOwner, v.GuestPTY)
		}
		if (row.Term.Reattach == sandboxbackend.ReattachBackendNative) != v.Reattach {
			t.Errorf("%s: reattach %s, vendor %v", id, row.Term.Reattach, v.Reattach)
		}
		// The guest PTY reattach is the guest helper's, never the vendor's
		// (lane SBX-UPD): only a GuestPTY row may carry it.
		if v.GuestReattach && !v.GuestPTY {
			t.Errorf("%s: guest reattach without a guest PTY", id)
		}
		if !v.RelayStdin && row.Capture.HookPath == sandboxbackend.HookRelay {
			t.Errorf("%s: relay hook path without a documented second stdin stream", id)
		}
	}
}
