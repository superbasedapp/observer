//go:build linux && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxoci"
)

// TestOCIRefusalsNameTheirRow (Linux live re-check on the Docker sandbox
// 2026-10-23, N5): a run's refusals name the plan's own row, so an
// oci-runsc refusal no longer reads "observer sandbox (oci-runc)"; a plan
// from before the oci-runsc row (no backend) is oci-runc.
func TestOCIRefusalsNameTheirRow(t *testing.T) {
	for _, c := range []struct{ backend, want string }{
		{"", sandboxoci.RuntimeOCIRunc},
		{sandboxoci.RuntimeOCIRunc, sandboxoci.RuntimeOCIRunc},
		{sandboxoci.RuntimeOCIRunsc, sandboxoci.RuntimeOCIRunsc},
	} {
		var out bytes.Buffer
		code := driveOCIRun(context.Background(), ociPlanFile{Backend: c.backend}, nil, nil, ociTerm{out: &out})
		if code != sandboxHelperFailCode || !strings.Contains(out.String(), "observer sandbox ("+c.want+"): no inner launch") {
			t.Fatalf("backend %q: code %d, %q", c.backend, code, out.String())
		}
	}
}
