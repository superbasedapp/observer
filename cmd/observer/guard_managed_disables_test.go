package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestManagedDisableRemovedVerdict pins the guard event the start-time strip
// records: a guard_error flag naming the removed rules, degraded_from
// managed_disable_removed, so it rides the guard_events push to the org.
func TestManagedDisableRemovedVerdict(t *testing.T) {
	at := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	v := managedDisableRemovedVerdict([]string{"S-791", "S-792"}, at)
	if v.Verdict.Decision != policy.DecisionFlag || v.Verdict.RuleID != guard.GuardErrorRuleID || !v.GuardError {
		t.Fatalf("verdict = %+v", v.Verdict)
	}
	if v.DegradedFrom != managedDisableRemovedKind || !strings.Contains(v.Verdict.Reason, "S-791, S-792") {
		t.Fatalf("degraded_from %q reason %q", v.DegradedFrom, v.Verdict.Reason)
	}
	if !v.Input.Timestamp.Equal(at) {
		t.Fatalf("timestamp %v", v.Input.Timestamp)
	}
}

// TestStripManagedGuardDisablesAtStartNoGuard: no guard (guard off) removes
// nothing and records nothing.
func TestStripManagedGuardDisablesAtStartNoGuard(t *testing.T) {
	processManagedDisableRemoval.Store(nil)
	cfg := config.Config{}
	cfg.Guard.Rules.Disable = []string{"S-791"}
	stripManagedGuardDisables(context.Background(), t.TempDir()+"/config.toml", cfg, nil, nil, quietLogger())
	if processManagedDisableRemoval.Load() != nil {
		t.Fatal("a removal was recorded with no guard")
	}
}
