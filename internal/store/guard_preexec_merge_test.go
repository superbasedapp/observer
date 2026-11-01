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

// preExecFixture seeds one copilot-cli session and inserts one action per
// offset (same tool, action type and target), returning their ids in order.
func preExecFixture(t *testing.T, s *Store, session, target string, at time.Time, offsets ...time.Duration) []int64 {
	t.Helper()
	ctx := context.Background()
	pid, err := s.UpsertProject(ctx, "/home/dev/"+session, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSession(ctx, models.Session{ID: session, ProjectID: pid, Tool: "copilot-cli", StartedAt: at}); err != nil {
		t.Fatal(err)
	}
	var acts []models.Action
	for i, off := range offsets {
		acts = append(acts, models.Action{
			SessionID: session, ProjectID: pid, Timestamp: at.Add(off), ActionType: "run_command",
			Target: target, Tool: "copilot-cli", SourceFile: "seed", SourceEventID: fmt.Sprintf("%s-%d", session, i),
		})
	}
	if _, err := s.InsertActions(ctx, acts); err != nil {
		t.Fatal(err)
	}
	var ids []int64
	rs, err := s.db.QueryContext(ctx, `SELECT id FROM actions WHERE session_id = ? ORDER BY id`, session)
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	for rs.Next() {
		var id int64
		if err := rs.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if len(ids) != len(offsets) {
		t.Fatalf("seeded %d actions, want %d", len(ids), len(offsets))
	}
	return ids
}

func preExecDeny(session, target, rule string, at time.Time) guard.ActionVerdict {
	return guard.ActionVerdict{
		Input: guard.ActionInput{SessionID: session, Tool: "copilot-cli", ActionType: "run_command", Target: target, Timestamp: at},
		Kind:  policy.KindToolCall, Category: "destructive", Enforced: true,
		Verdict: policy.Verdict{
			Decision: policy.DecisionDeny, RuleID: rule, Severity: policy.SeverityCritical,
			Reason: "blocked before it ran", Source: policy.SourceOrg,
		},
	}
}

func postHocFlag(session, target, rule string, at time.Time, actionID int64) guard.ActionVerdict {
	return guard.ActionVerdict{
		Input: guard.ActionInput{SessionID: session, Tool: "copilot-cli", ActionType: "run_command", Target: target, Timestamp: at, ActionID: actionID},
		Kind:  policy.KindToolCall, Category: "destructive",
		Verdict: policy.Verdict{
			Decision: policy.DecisionFlag, RuleID: rule, Severity: policy.SeverityCritical,
			Reason: "seen after the fact", Source: "builtin",
		},
	}
}

// keptPostHoc lists the post-hoc rows the session kept, as "rule@action".
func keptPostHoc(t *testing.T, s *Store, session string) map[string]bool {
	t.Helper()
	rows, err := s.LoadGuardEventsForSession(context.Background(), session)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, r := range rows {
		if r.ActionID != nil {
			out[fmt.Sprintf("%s@%d", r.RuleID, *r.ActionID)] = true
		}
	}
	return out
}

// TestPreExecDenyAbsorbsOnlyItsOwnRecord is the WINNODE2 audit H2 scenario:
// one enforced R-112 deny, the blocked call's own post-hoc record a second
// later, two retries that ran 40 s and 100 s later, and an R-160 flag on the
// blocked call's record. Only the R-112 record of the blocked call is
// dropped; the retries and the other rule's flag are kept.
func TestPreExecDenyAbsorbsOnlyItsOwnRecord(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	at := time.Date(2026, 10, 28, 13, 7, 39, 0, time.UTC)
	const target = "Remove-Item -Recurse -Force C:\\Users\\dev\\payments-api"
	ids := preExecFixture(t, s, "h2a", target, at, time.Second, 40*time.Second, 100*time.Second)
	if _, err := s.PersistGuardVerdicts(ctx, []guard.ActionVerdict{preExecDeny("h2a", target, "R-112", at)}); err != nil {
		t.Fatal(err)
	}
	batch := []guard.ActionVerdict{
		postHocFlag("h2a", target, "R-112", at.Add(time.Second), ids[0]),
		postHocFlag("h2a", target, "R-112", at.Add(40*time.Second), ids[1]),
		postHocFlag("h2a", target, "R-112", at.Add(100*time.Second), ids[2]),
		postHocFlag("h2a", target, "R-160", at.Add(time.Second), ids[0]),
	}
	if _, err := s.PersistGuardVerdicts(ctx, batch); err != nil {
		t.Fatal(err)
	}
	got := keptPostHoc(t, s, "h2a")
	want := map[string]bool{
		fmt.Sprintf("R-112@%d", ids[1]): true,
		fmt.Sprintf("R-112@%d", ids[2]): true,
		fmt.Sprintf("R-160@%d", ids[0]): true,
	}
	if len(got) != len(want) {
		t.Fatalf("kept post-hoc rows %v, want %v", got, want)
	}
	for k := range want {
		if !got[k] {
			t.Fatalf("kept post-hoc rows %v, missing %s", got, k)
		}
	}
}

// TestTwoPreExecDeniesEachAbsorbTheirOwnRecord: two denies on one target,
// three seconds apart, each absorb the record nearest to them; a third call
// on the same target inside both windows is nobody's nearest and is kept.
func TestTwoPreExecDeniesEachAbsorbTheirOwnRecord(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	at := time.Date(2026, 10, 28, 14, 0, 0, 0, time.UTC)
	const target = "npm publish"
	ids := preExecFixture(t, s, "h2b", target, at, 500*time.Millisecond, 3500*time.Millisecond, 6*time.Second)
	denies := []guard.ActionVerdict{
		preExecDeny("h2b", target, "R-112", at),
		preExecDeny("h2b", target, "R-112", at.Add(3*time.Second)),
	}
	if _, err := s.PersistGuardVerdicts(ctx, denies); err != nil {
		t.Fatal(err)
	}
	// One record per batch: the choice must not depend on the batching.
	for i, off := range []time.Duration{500 * time.Millisecond, 3500 * time.Millisecond, 6 * time.Second} {
		if _, err := s.PersistGuardVerdicts(ctx, []guard.ActionVerdict{postHocFlag("h2b", target, "R-112", at.Add(off), ids[i])}); err != nil {
			t.Fatal(err)
		}
	}
	got := keptPostHoc(t, s, "h2b")
	if len(got) != 1 || !got[fmt.Sprintf("R-112@%d", ids[2])] {
		t.Fatalf("kept post-hoc rows %v, want only R-112@%d (the third call)", got, ids[2])
	}
}
