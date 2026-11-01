package cost

import "testing"

// TestWave1021FreeGatewayRows pins the 2026-10-21 vendor-catalog $0 row:
// kimchi's own dev gateway model resolves as a known zero, and only under
// its provider-prefixed spelling.
func TestWave1021FreeGatewayRows(t *testing.T) {
	tbl := NewTable()
	p, ok := tbl.Lookup("kimchi-dev/gemma-4-31b")
	if !ok {
		t.Fatal("kimchi-dev/gemma-4-31b not priced")
	}
	if p.Input != 0 || p.Output != 0 || p.CacheRead != 0 {
		t.Fatalf("kimchi-dev/gemma-4-31b = %+v, want all zero", p)
	}
	h, ok := tbl.Lookup("hy4-preview")
	if !ok || h.Input != 0.834 || h.Output != 2.501 || h.CacheRead != 0.042 {
		t.Fatalf("hy4-preview = %+v (ok=%v), want the gateway catalog rate", h, ok)
	}
	// hy3's row must not leak onto hy4.
	if h3, _ := tbl.Lookup("hy3"); h3 == h {
		t.Fatal("hy3 and hy4-preview resolved to the same row")
	}
}
