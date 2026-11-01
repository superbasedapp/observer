package diag

import (
	"strings"
	"testing"
)

// TestCrossmountRowNamesTheReason pins the R-013 doctor row: off names the
// reason, on counts the foreign homes, and a host with no foreign side has no
// row at all.
func TestCrossmountRowNamesTheReason(t *testing.T) {
	off := crossmountCheck("--no-crossmount was given", 0)
	if off.Name != "crossmount" || !strings.Contains(off.Message, "--no-crossmount was given") {
		t.Fatalf("off row = %+v, want it to name the reason", off)
	}
	on := crossmountCheck("", 2)
	if !strings.Contains(on.Message, "2 foreign home") {
		t.Fatalf("on row = %+v, want the foreign home count", on)
	}
	prev := crossmountHostFn
	t.Cleanup(func() { crossmountHostFn = prev })
	crossmountHostFn = func() bool { return false }
	if _, ok := checkCrossmountRow(); ok {
		t.Fatal("a host with no foreign side got a crossmount row")
	}
	crossmountHostFn = func() bool { return true }
	c, ok := checkCrossmountRow()
	if !ok || !strings.Contains(c.Message, "test binary") {
		t.Fatalf("row in a test binary = %+v (%v), want the test-binary reason", c, ok)
	}
}
