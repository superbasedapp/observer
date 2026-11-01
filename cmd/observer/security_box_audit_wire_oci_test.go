//go:build !sbo_omit_security && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// security_box_audit_wire_oci_test.go holds the OCI plan half of the
// SEC-BOX merge-audit finding 4 pin (security_box_audit_wire_test.go),
// built wherever terminal_sandbox_oci.go is.

// TestSecurityReturnStepPlanConfigPath (audit finding 4): the daemon writes
// its own resolved, absolute config path into the OCI plan, the path the
// helper's return-step scan then carries.
func TestSecurityReturnStepPlanConfigPath(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "daemon.toml")
	prevCfg := daemonConfigPath()
	setDaemonConfigPath(cfgPath)
	t.Cleanup(func() { setDaemonConfigPath(prevCfg) })
	want, err := config.ResolveGlobalPath(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if p := ociPlanConfigPath(); p != want || !filepath.IsAbs(p) {
		t.Fatalf("plan config %q, want %q", p, want)
	}
}
