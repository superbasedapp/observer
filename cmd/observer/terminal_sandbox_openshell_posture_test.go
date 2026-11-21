//go:build !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestOpenShellGatewayDriftUnknownWhenConfigFailsToLoad pins audit finding
// O4-A5: a daemon config that does not load cannot name the state dir (it
// may be a custom [terminal.sandbox.openshell].state_dir), so the read-back
// reports unknown instead of reading the default state dir and finding it
// clean.
func TestOpenShellGatewayDriftUnknownWhenConfigFailsToLoad(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(p, []byte("[terminal.sandbox.openshell\nstate_dir = \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := openShellGatewayDriftObserved(p); got != sandboxGatewayDriftUnknown {
		t.Fatalf("a config that does not load: drift %d, want unknown (%d)", got, sandboxGatewayDriftUnknown)
	}
}
