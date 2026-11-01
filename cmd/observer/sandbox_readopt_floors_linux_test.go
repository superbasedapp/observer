//go:build linux && !sbo_omit_terminals_sandbox_oci_readopt && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestReadoptCLIRefusesWhenTheFloorsCannotBeRead (R-166, LEFT2-SBX audit
// finding 8): a CLI `observer sandbox readopt` or `restore` whose org floors
// cannot be read is refused with the named org_floors_unreadable reason,
// through the real readoptToday, instead of re-adopting against no floor.
func TestReadoptCLIRefusesWhenTheFloorsCannotBeRead(t *testing.T) {
	prevHere := policyResourceInstalledHere.Load()
	prevPath := daemonConfigPathSetting.Load()
	t.Cleanup(func() {
		policyResourceInstalledHere.Store(prevHere)
		daemonConfigPathSetting.Store(prevPath)
	})
	policyResourceInstalledHere.Store(false) // a CLI process
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	// The database path is a directory: the store cannot be opened, so the
	// floors in force cannot be known.
	body := "[observer]\ndb_path = " + `"` + filepath.ToSlash(dir) + `"` + "\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	daemonConfigPathSetting.Store(&cfgPath)
	err := readoptPolicyCheck(&readoptPolicy{Backend: "oci-runc", Tier: "none"})
	if err == nil || !strings.Contains(err.Error(), "org_floors_unreadable") {
		t.Fatalf("readopt with unreadable org floors: %v, want a refusal naming org_floors_unreadable", err)
	}
}
