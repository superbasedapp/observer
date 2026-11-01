package main

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// TestAgyGateWatchdogBelowHostTimeout pins that Observer's own hook
// watchdog fires before agy's hook timeout on both registered gates
// (guard-enforcement fix, 2026-10-15): agy's PreToolUse is FAIL-CLOSED (a
// timeout denies), so the watchdog must answer first with Observer's own
// reason, and PreInvocation fails open, so a late answer would be ignored.
func TestAgyGateWatchdogBelowHostTimeout(t *testing.T) {
	t.Parallel()
	cases := []struct {
		event       string
		wantFailure integration.FailurePolicy
	}{
		{"PreToolUse", integration.HostBlocks},
		{"PreInvocation", integration.HostProceeds},
	}
	for _, tc := range cases {
		t.Run(tc.event, func(t *testing.T) {
			b, ok := resolveHookBinding("antigravity-cli", tc.event)
			if !ok || !b.Wired || b.HostTimeout <= 0 {
				t.Fatalf("binding %+v ok=%v, want a wired gate with a host timeout", b, ok)
			}
			if b.HostOnFailure != tc.wantFailure {
				t.Fatalf("HostOnFailure = %q, want %q", b.HostOnFailure, tc.wantFailure)
			}
			budget := hookGateBudget(defaultHookMaxRuntime, hookFailurePlan{Cap: b.Cap, Dialect: b.Dialect, HostTimeout: b.HostTimeout})
			if budget <= 0 || budget >= b.HostTimeout {
				t.Fatalf("watchdog budget %v, want below the host timeout %v", budget, b.HostTimeout)
			}
		})
	}
}
