package store

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestAttributeSubagentRow is THE MATCH's table (guardsubagent.go), one
// row per clause.
func TestAttributeSubagentRow(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 11, 10, 14, 6, 42, 235_000_000, time.UTC)
	c := func(id int64, sid, hash string, dt time.Duration) subagentActionCandidate {
		return subagentActionCandidate{ActionID: id, SessionID: sid, TargetHash: hash, At: at.Add(dt)}
	}
	cases := []struct {
		name   string
		hash   string
		cands  []subagentActionCandidate
		wantOK bool
		wantID int64
	}{
		{"the tool_use a moment before the hook", "h1", []subagentActionCandidate{c(1, "r:agent:a", "h1", -250*time.Millisecond)}, true, 1},
		{"another target never matches", "h1", []subagentActionCandidate{c(1, "r:agent:a", "h2", 0)}, false, 0},
		{"too long before", "h1", []subagentActionCandidate{c(1, "r:agent:a", "h1", -61*time.Second)}, false, 0},
		{"too long after", "h1", []subagentActionCandidate{c(1, "r:agent:a", "h1", 11*time.Second)}, false, 0},
		{"the nearest wins", "h1", []subagentActionCandidate{c(1, "r:agent:a", "h1", -30*time.Second), c(2, "r:agent:b", "h1", -time.Second)}, true, 2},
		{"a tie goes to the lower action id", "h1", []subagentActionCandidate{c(5, "r:agent:a", "h1", time.Second), c(4, "r:agent:b", "h1", -time.Second)}, true, 4},
		{"an empty hash never matches", "", []subagentActionCandidate{c(1, "r:agent:a", "", 0)}, false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := attributeSubagentRow(tc.hash, at, tc.cands)
			if ok != tc.wantOK || (ok && got.ActionID != tc.wantID) {
				t.Fatalf("attributeSubagentRow = (%+v, %v), want (id %d, %v)", got, ok, tc.wantID, tc.wantOK)
			}
		})
	}
}

// TestSubagentRoot pins the sidechain id parse.
func TestSubagentRoot(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		id, root string
		ok       bool
	}{
		{"p1:agent:a1", "p1", true},
		{"p1", "", false},
		{":agent:a1", "", false},
		{"p1:agent:", "", false},
	} {
		if root, ok := subagentRoot(tc.id); root != tc.root || ok != tc.ok {
			t.Errorf("subagentRoot(%q) = (%q, %v), want (%q, %v)", tc.id, root, ok, tc.root, tc.ok)
		}
	}
}

// TestGuardFeedAttributesSubagentHookRows is the live shape of 2026-11-10:
// a sub-agent's commit was asked by the hook, which stored the verdict
// under the ROOT session with no action anchor. The sub-agent's own feed
// must show it (anchored on the sub-agent's message), and the root's feed
// keeps it, marked with the sub-agent.
func TestGuardFeedAttributesSubagentHookRows(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	root := t.TempDir()
	ts := time.Date(2026, 11, 10, 14, 6, 41, 994_000_000, time.UTC)
	const parent = "p1"
	subA, subB := parent+":agent:a1", parent+":agent:b2"
	commit := `git commit -q -m "fix: x"`
	push := "git push origin main"
	if _, err := s.Ingest(ctx, []models.ToolEvent{
		{SourceFile: "fa", SourceEventID: "tu_a", SessionID: subA, ProjectRoot: root, Timestamp: ts, Tool: models.ToolClaudeCode, ActionType: models.ActionRunCommand, Target: commit, MessageID: "msg_a", Success: false},
		{SourceFile: "fb", SourceEventID: "tu_b", SessionID: subB, ProjectRoot: root, Timestamp: ts.Add(5 * time.Minute), Tool: models.ToolClaudeCode, ActionType: models.ActionRunCommand, Target: push, MessageID: "msg_b", Success: false},
		{SourceFile: "fp", SourceEventID: "tu_p", SessionID: parent, ProjectRoot: root, Timestamp: ts.Add(10 * time.Minute), Tool: models.ToolClaudeCode, ActionType: models.ActionRunCommand, Target: "ls", MessageID: "msg_p", Success: true},
	}, nil, IngestOptions{}); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if _, err := s.InsertGuardEvents(ctx, []GuardEventRow{
		// The hook's verdict on sub-agent A's commit, filed under the root.
		{TS: ts.Add(250 * time.Millisecond), SessionID: parent, Tool: "claude-code", EventKind: "shell_exec", RuleID: "S-793", Decision: "ask", Enforced: true, Source: "pack:security", TargetHash: sha256Hex(commit), TargetExcerpt: commit},
		// The hook's verdict on sub-agent B's push.
		{TS: ts.Add(5*time.Minute + 250*time.Millisecond), SessionID: parent, Tool: "claude-code", EventKind: "shell_exec", RuleID: "S-792", Decision: "deny", Enforced: true, Source: "pack:security", TargetHash: sha256Hex(push), TargetExcerpt: push},
		// A verdict on the root's own call matches no sub-agent action.
		{TS: ts.Add(10*time.Minute + 250*time.Millisecond), SessionID: parent, Tool: "claude-code", EventKind: "shell_exec", RuleID: "R-170", Decision: "deny", Enforced: true, Source: "org", TargetHash: sha256Hex("ls"), TargetExcerpt: "ls"},
	}); err != nil {
		t.Fatalf("insert guard events: %v", err)
	}

	gotA, err := s.LoadGuardEventsForSessionWithMessageAnchor(ctx, subA)
	if err != nil {
		t.Fatalf("load sub-agent A: %v", err)
	}
	if len(gotA) != 1 || gotA[0].RuleID != "S-793" || gotA[0].SubagentSessionID != subA || gotA[0].MessageID != "msg_a" || gotA[0].SessionID != parent {
		t.Fatalf("sub-agent A feed = %+v, want the root's S-793 ask attributed to it on msg_a", gotA)
	}
	gotB, err := s.LoadGuardEventsForSessionWithMessageAnchor(ctx, subB)
	if err != nil {
		t.Fatalf("load sub-agent B: %v", err)
	}
	if len(gotB) != 1 || gotB[0].RuleID != "S-792" {
		t.Fatalf("sub-agent B feed = %+v, want only its own S-792 deny", gotB)
	}
	gotP, err := s.LoadGuardEventsForSessionWithMessageAnchor(ctx, parent)
	if err != nil {
		t.Fatalf("load root: %v", err)
	}
	if len(gotP) != 3 {
		t.Fatalf("root feed = %d rows, want all 3 (the root keeps its sub-agents' verdicts)", len(gotP))
	}
	want := map[string]string{"S-793": subA, "S-792": subB, "R-170": ""}
	for _, r := range gotP {
		if r.SubagentSessionID != want[r.RuleID] {
			t.Errorf("root row %s attributed to %q, want %q", r.RuleID, r.SubagentSessionID, want[r.RuleID])
		}
		if r.SubagentSessionID != "" && r.MessageID != "" {
			t.Errorf("root row %s anchored on a sub-agent message %q (the root's messages never hold it)", r.RuleID, r.MessageID)
		}
	}
}
