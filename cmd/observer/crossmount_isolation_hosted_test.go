//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"io"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// TestSandboxHostedHonoursCrossmountIsolation (LEFT2 audit S5): the
// `sandbox hosted` subtree has its own PersistentPreRunE, which cobra runs
// instead of the root's. Run through Execute, --no-crossmount must still
// record the isolation reason there, before the subtree's own check.
func TestSandboxHostedHonoursCrossmountIsolation(t *testing.T) {
	stageRealHome(t)
	hostedActiveForTest(t, false)
	root := newRootCmd()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"sandbox", "hosted", "status", "--no-crossmount"})
	_ = root.Execute() // inactive: the subtree refuses, after the isolation step
	if r := crossmount.DetectionOffReason(); !strings.Contains(r, "--no-crossmount") {
		t.Fatalf("DetectionOffReason() = %q under `sandbox hosted --no-crossmount`, want the flag named", r)
	}
}
