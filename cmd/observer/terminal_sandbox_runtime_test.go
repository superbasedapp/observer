//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"os"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// The sandbox test runtime the OCI and MXC tests share (R-008: it lived in
// the OCI test file, so `-tags sbo_omit_terminals_sandbox_oci` broke the
// MXC tests).

// ociTestRuntime builds a runtime over cfg.
func ociTestRuntime(t *testing.T, cfg config.Config) *sandboxRuntime {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	rt, err := newSandboxRuntime(cfg.Terminal.Sandbox, nil, t.TempDir(), exe, nil)
	if err != nil {
		t.Fatal(err)
	}
	rt.applyDaemonConfig(cfg)
	return rt
}
