// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestPostHocFlagOfABlockedCallIsNotADuplicate (WINNODE2 item 10): a store
// that records attempted calls (Copilot's session-state keeps a call its
// preToolUse hook denied) must not add a weaker post-hoc row (enforced=0,
// a builtin source) for a call the pre-execution gate already blocked. A
// post-hoc flag of another target, of a call outside the window, or one
// with no pre-execution block is kept.
func TestPostHocFlagOfABlockedCallIsNotADuplicate(t *testing.T) {
	t.Parallel()
	s, database := newTestStore(t)
	ctx := context.Background()
	at := time.Date(2026, 10, 28, 13, 7, 39, 0, time.UTC)
	pid, err := s.UpsertProject(ctx, "/home/dev/payments-api", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSession(ctx, models.Session{ID: "cp1", ProjectID: pid, Tool: "copilot-cli", StartedAt: at}); err != nil {
		t.Fatal(err)
	}
	// The three recorded calls: the blocked one two seconds after the
	// deny, a call on another target, and the same target half an hour
	// later (merge fix for audit H2: the window is 10 s and the record is
	// matched on its own action row, so each carries its real target).
	var acts []models.Action
	for i, c := range []struct {
		target string
		off    time.Duration
	}{{"npm run build", 2 * time.Second}, {"npm test", 2 * time.Second}, {"npm run build", 30 * time.Minute}} {
		acts = append(acts, models.Action{
			SessionID: "cp1", ProjectID: pid, Timestamp: at.Add(c.off), ActionType: "run_command",
			Target: c.target, Tool: "copilot-cli", SourceFile: "seed", SourceEventID: fmt.Sprintf("cp1-%d", i),
		})
	}
	if _, err := s.InsertActions(ctx, acts); err != nil {
		t.Fatal(err)
	}
	var ids []int64
	rs, err := database.QueryContext(ctx, `SELECT id FROM actions WHERE session_id = 'cp1' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	for rs.Next() {
		var id int64
		if err := rs.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	_ = rs.Close()
	hookDeny := guard.ActionVerdict{
		Input: guard.ActionInput{SessionID: "cp1", Tool: "copilot-cli", ActionType: "run_command", Target: "npm run build", Timestamp: at},
		Kind:  policy.KindToolCall, Category: "budget", Enforced: true,
		Verdict: policy.Verdict{
			Decision: policy.DecisionDeny, RuleID: "B-602", Severity: policy.SeverityHigh,
			Reason: "Organization budget B-602: over the daily cap.", Source: policy.SourceOrgBudget,
		},
	}
	if _, err := s.PersistGuardVerdicts(ctx, []guard.ActionVerdict{hookDeny}); err != nil {
		t.Fatal(err)
	}
	postHoc := func(target string, ts time.Time, actionID int64) guard.ActionVerdict {
		return guard.ActionVerdict{
			Input: guard.ActionInput{SessionID: "cp1", Tool: "copilot-cli", ActionType: "run_command", Target: target, Timestamp: ts, ActionID: actionID},
			Kind:  policy.KindToolCall, Category: "budget",
			Verdict: policy.Verdict{
				Decision: policy.DecisionFlag, RuleID: "B-602", Severity: policy.SeverityHigh,
				Reason: "daily budget exceeded", Source: "builtin",
			},
		}
	}
	cases := []struct {
		name string
		v    guard.ActionVerdict
		kept bool
	}{
		{"the blocked call's post-hoc record", postHoc("npm run build", at.Add(2*time.Second), ids[0]), false},
		{"another target", postHoc("npm test", at.Add(2*time.Second), ids[1]), true},
		{"the same target outside the window", postHoc("npm run build", at.Add(30*time.Minute), ids[2]), true},
	}
	want := 1
	for _, tc := range cases {
		if _, err := s.PersistGuardVerdicts(ctx, []guard.ActionVerdict{tc.v}); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if tc.kept {
			want++
		}
		rows, err := s.LoadGuardEventsForSession(ctx, "cp1")
		if err != nil || len(rows) != want {
			t.Fatalf("%s: %d rows (err %v), want %d", tc.name, len(rows), err, want)
		}
	}
	rows, _ := s.LoadGuardEventsForSession(ctx, "cp1")
	enforced := 0
	for _, r := range rows {
		if r.TargetExcerpt == "npm run build" && r.Enforced && r.Source == policy.SourceOrgBudget {
			enforced++
		}
	}
	if enforced != 1 {
		t.Fatalf("the blocked call has %d enforced org_budget rows, want 1: %+v", enforced, rows)
	}
}
