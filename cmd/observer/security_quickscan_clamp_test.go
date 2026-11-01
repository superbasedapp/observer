//go:build !sbo_omit_security

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// TestQuickScanClampDoctorDetails (lane LEFT2-SEC item R-039): doctor names
// every registered gate hook whose vendor timeout is too short for the
// chosen quick-scan budget, with the clamped value, and nothing for a
// budget every timeout fits.
func TestQuickScanClampDoctorDetails(t *testing.T) {
	caps := []integration.Capability{{
		Tool: "toolx",
		Hook: integration.HookSpec{Bindings: []integration.HookBinding{
			{Cap: integration.HookCapToolGate, NativeEvent: "PreToolUse", Registered: true, HostTimeout: 10 * time.Second},
			{Cap: integration.HookCapToolGate, NativeEvent: "NotRegistered", HostTimeout: 5 * time.Second},
			{Cap: integration.HookCapSessionLifecycle, NativeEvent: "SessionStart", Registered: true, HostTimeout: 5 * time.Second},
		}},
	}}
	got := quickScanClampDetails(30*time.Second, caps)
	if len(got) != 1 || !strings.Contains(got[0], "toolx PreToolUse hook timeout 10s") || !strings.Contains(got[0], "clamped to 6s") {
		t.Fatalf("details %q", got)
	}
	if got := quickScanClampDetails(2*time.Second, caps); len(got) != 0 {
		t.Fatalf("a budget that fits named %q", got)
	}
	// The real registry: the default budget fits every registered gate.
	if got := quickScanClampDetails(0, integration.Capabilities()); len(got) != 0 {
		t.Fatalf("the default 2 s budget is clamped on %q", got)
	}
}

// TestQuickScanClampDoctorUsesTheSignedBudgets (LEFT2 audit E4): doctor
// judges the clamp with the budgets the hook uses, the effective signed
// budget of each active project (the default where none is signed), never
// the local config value alone.
func TestQuickScanClampDoctorUsesTheSignedBudgets(t *testing.T) {
	caps := []integration.Capability{{
		Tool: "toolx",
		Hook: integration.HookSpec{Bindings: []integration.HookBinding{
			{Cap: integration.HookCapToolGate, NativeEvent: "PreToolUse", Registered: true, HostTimeout: 10 * time.Second},
		}},
	}}
	rep := securityStatusReport{Projects: []securityProjectState{{quickScanBudget: 30 * time.Second}, {quickScanBudget: 2 * time.Second}}}
	got := quickScanClampDetailsForReport(rep, caps)
	if len(got) != 1 || !strings.Contains(got[0], "the 30s budget") {
		t.Fatalf("details %q, want the signed 30 s budget's clamp", got)
	}
	if got := quickScanClampDetailsForReport(securityStatusReport{}, caps); len(got) != 0 {
		t.Fatalf("no active project reads the default 2 s budget, which fits: %q", got)
	}
}

// TestHookQuickScanBudgetCountsTheHooksOwnTime (LEFT2 audit E4): the hook
// clamps the scan below the host timeout less the time it already spent.
func TestHookQuickScanBudgetCountsTheHooksOwnTime(t *testing.T) {
	now := time.Now()
	plan := hookFailurePlan{HostTimeout: 10 * time.Second, Started: now.Add(-3 * time.Second)}
	if got, _ := hookQuickScanBudget(10*time.Second, plan, now); got != 3*time.Second {
		t.Fatalf("budget %v, want 3s (10s timeout, 3s spent, two 2s margins)", got)
	}
	if got, _ := hookQuickScanBudget(10*time.Second, hookFailurePlan{HostTimeout: 10 * time.Second}, now); got != 6*time.Second {
		t.Fatalf("no start recorded: %v, want 6s", got)
	}
}
