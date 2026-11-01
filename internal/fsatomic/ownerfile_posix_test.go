//go:build !windows

package fsatomic

import (
	"os"
	"testing"
)

// TestPOSIXOwnerOnlyNeedsTheOwner (WINFIX4 audit finding 5): a 0600 file
// another uid owns (one an administrator planted) is refused; before, only
// the permission bits were read.
func TestPOSIXOwnerOnlyNeedsTheOwner(t *testing.T) {
	cases := []struct {
		name  string
		mode  uint32
		owner uint32
		known bool
		self  int
		want  bool
	}{
		{"mine, 0600", 0o600, 1000, true, 1000, true},
		{"root planted, 0600", 0o600, 0, true, 1000, false},
		{"mine, 0640", 0o640, 1000, true, 1000, false},
		{"no owner reported, 0600", 0o600, 0, false, 1000, true},
	}
	for _, c := range cases {
		if got := posixOwnerOnly(os.FileMode(c.mode), c.owner, c.known, c.self); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}
