//go:build linux && !sbo_omit_security && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"path/filepath"
	"testing"
)

// security_box_audit_wire_linux_test.go holds the Linux-only half of the
// SEC-BOX merge-audit finding 4 pin (security_box_audit_wire_test.go): the
// OCI helper (terminal_sandbox_oci_run.go) is built on Linux only.

// TestSecurityReturnStepHelperCarriesPlanConfig (audit finding 4): the OCI
// helper's return-step scan carries the plan's config path, and no scan is
// made while none is bound.
func TestSecurityReturnStepHelperCarriesPlanConfig(t *testing.T) {
	ctx := context.Background()
	abs := filepath.Join(t.TempDir(), "config.toml")
	prevScan := sandboxReturnScan
	t.Cleanup(func() { sandboxReturnScan = prevScan })
	var got string
	sandboxReturnScan = func(_ context.Context, in sandboxReturnScanInput) error { got = in.ConfigPath; return nil }
	if err := ociReturnScan(abs)(ctx, sandboxReturnScanInput{}); err != nil || got != abs {
		t.Fatalf("helper scan config %q %v, want %s", got, err, abs)
	}
	sandboxReturnScan = nil
	if ociReturnScan(abs) != nil {
		t.Fatal("a scan was made with none bound")
	}
}
