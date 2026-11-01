//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"runtime"
	"testing"
)

// TestWholeRootPathPerOS: a writable bind of a whole file system root is
// refused on every OS: "/" on POSIX, a drive or share root on Windows.
func TestWholeRootPathPerOS(t *testing.T) {
	roots, others := []string{"/", "//"}, []string{"/srv", "/srv/"}
	if runtime.GOOS == "windows" {
		roots, others = []string{`C:\`, `c:\.`, `\\host\share\`}, []string{`C:\srv`, `C:\Users\x`}
	}
	for _, p := range roots {
		if !wholeRootPath(p) || checkManagedPath(p, true) != sandboxRefusedWholeRoot {
			t.Errorf("%q is a whole root and was not refused (%q)", p, checkManagedPath(p, true))
		}
	}
	for _, p := range others {
		if wholeRootPath(p) {
			t.Errorf("%q is not a whole root", p)
		}
	}
}
