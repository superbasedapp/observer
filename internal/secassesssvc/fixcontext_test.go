package secassesssvc

import (
	"strings"
	"testing"
)

// TestFixContext: the seam answers for an imported assessment rule id and for
// nothing else, and the answer is Observer's own sentence.
func TestFixContext(t *testing.T) {
	got, ok := FixContext("other/assess.tm.stride-t")
	if !ok || !strings.Contains(got, "STRIDE, Tampering") || !strings.Contains(got, "regression test") {
		t.Fatalf("FixContext = %q, %v", got, ok)
	}
	if got, ok := FixContext("other/assess.pt.wstg-athz"); !ok || !strings.Contains(got, "WSTG ATHZ, Authorization") {
		t.Errorf("pen test rule id: %q, %v", got, ok)
	}
	for _, id := range []string{"", "G101", "other/assess.cspm.cwe-89", "other/assess.tm.something-the-agent-named"} {
		if got, ok := FixContext(id); ok || got != "" {
			t.Errorf("FixContext(%q) = %q, %v; want none", id, got, ok)
		}
	}
}
