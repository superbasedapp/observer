package sandboxvm

import (
	"strings"
	"testing"
)

// TestGuestShareReadOnly (D4): the spec's read-only paths go to the write
// witness, as a copy.
func TestGuestShareReadOnly(t *testing.T) {
	s := testSpec()
	got := GuestShareReadOnly(s)
	if strings.Join(got, ",") != strings.Join(s.ReadOnly, ",") || len(got) == 0 {
		t.Fatalf("%v", got)
	}
	got[0] = "/changed"
	if s.ReadOnly[0] == "/changed" {
		t.Fatal("not a copy")
	}
}
