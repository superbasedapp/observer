package store

import (
	"context"
	"testing"
	"time"
)

// TestSummarizeGuardEventsEnforcedByOrg pins FU-235: the summary splits out
// the enforced verdicts the ORG policy layer produced (source "org"), so a
// block under an org-locked rule on an observe node is counted and named.
func TestSummarizeGuardEventsEnforcedByOrg(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	rows := []struct {
		source   string
		enforced bool
	}{
		{"org", true},     // an org-locked deny that blocked
		{"org", true},     // another
		{"org", false},    // an org rule that only flagged
		{"builtin", true}, // a local per-rule enforced deny
		{"", false},       // a legacy row with no source
	}
	var seed []GuardEventRow
	for i, r := range rows {
		ev := guardEventFixture("s1", "R-101", t0Guard.Add(time.Duration(i)*time.Second))
		ev.Source = r.source
		ev.Enforced = r.enforced
		if r.enforced {
			ev.Decision = "deny"
		}
		seed = append(seed, ev)
	}
	if _, err := s.InsertGuardEvents(ctx, seed); err != nil {
		t.Fatalf("seed: %v", err)
	}
	sum, err := s.SummarizeGuardEvents(ctx, t0Guard.Add(-time.Hour))
	if err != nil {
		t.Fatalf("SummarizeGuardEvents: %v", err)
	}
	if sum.Total != 5 || sum.Enforced != 3 || sum.EnforcedByOrg != 2 {
		t.Fatalf("summary = total %d enforced %d by org %d, want 5 / 3 / 2", sum.Total, sum.Enforced, sum.EnforcedByOrg)
	}
}
