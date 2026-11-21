//go:build linux && !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxopenshell"
)

// TestOpenShellInstallIDUnknownUnitMints drives the id read end to end: a
// legacy id whose unit cannot be read (a passing systemctl failure) is not
// adopted; a fresh id is minted and bound, and the legacy file names it.
func TestOpenShellInstallIDUnknownUnitMints(t *testing.T) {
	const legacyID = "0123456789abcdef"
	dir := filepath.Join(t.TempDir(), "sandbox-openshell")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, sandboxopenshell.LegacyInstallIDFile), []byte(legacyID+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	unknown := func(string) (string, bool) { return openShellUnitAnswer(false, "") }
	if got := openShellReadInstallIDWith(dir, unknown); got != "" {
		t.Fatalf("the read-only resolver adopted the legacy id on an unknown answer: %q", got)
	}
	got, err := openShellInstallIDWith(dir, unknown)
	if err != nil {
		t.Fatal(err)
	}
	if got == legacyID || got == "" {
		t.Fatalf("an unknown unit answer adopted the legacy id: %q", got)
	}
}
