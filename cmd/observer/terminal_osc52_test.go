//go:build !sbo_omit_terminals

package main

import (
	"strings"
	"testing"
)

// TestSandboxOSC52Rule (ruling P-175): only a sandboxed run is filtered,
// and only while the opt-in is off; a run that allows it says so.
func TestSandboxOSC52Rule(t *testing.T) {
	cases := []struct {
		sandboxed, allowed, strips bool
		notice                     bool
	}{
		{false, false, false, false},
		{false, true, false, false},
		{true, false, true, false},
		{true, true, false, true},
	}
	for _, c := range cases {
		if got := sandboxStripsOSC52(c.sandboxed, c.allowed); got != c.strips {
			t.Errorf("sandboxed=%v allowed=%v: strips %v", c.sandboxed, c.allowed, got)
		}
		if got := sandboxOSC52Notice(c.sandboxed, c.allowed); (got != "") != c.notice || (got != "" && !strings.Contains(got, "allow_osc52_clipboard")) {
			t.Errorf("sandboxed=%v allowed=%v: notice %q", c.sandboxed, c.allowed, got)
		}
	}
	if sandboxCLIOSC52Label(false) != "" || sandboxCLIOSC52Label(true) != ", allow_osc52_clipboard" {
		t.Fatal("CLI label")
	}
}
