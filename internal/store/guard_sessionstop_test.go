package store

import (
	"context"
	"testing"
	"time"
)

// TestPromptSessionStops pins the stopped-conversation taint read: only
// enforced ask/deny user_prompt rows of the same tool and session count,
// newest first.
func TestPromptSessionStops(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	at := time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)
	row := func(session, tool, kind, rule, sev, decision string, enforced bool, i int) GuardEventRow {
		return GuardEventRow{
			TS: at.Add(time.Duration(i) * time.Second), SessionID: session, Tool: tool, EventKind: kind,
			RuleID: rule, Severity: sev, Decision: decision, Enforced: enforced, Source: "builtin",
		}
	}
	rows := []GuardEventRow{
		row("conv-1", "antigravity-cli", "user_prompt", "R-172", "critical", "deny", true, 1),
		row("conv-1", "antigravity-cli", "user_prompt", "R-190", "high", "flag", false, 2),    // warned: no stop
		row("conv-1", "antigravity-cli", "user_prompt", "R-172", "critical", "flag", true, 3), // a redact: no stop
		row("conv-1", "antigravity-cli", "shell_exec", "R-101", "critical", "deny", true, 4),  // a tool call
		row("conv-1", "codex", "user_prompt", "R-172", "critical", "deny", true, 5),           // another tool
		row("conv-2", "antigravity-cli", "user_prompt", "R-172", "critical", "deny", true, 6), // another session
		row("conv-1", "antigravity-cli", "user_prompt", "B-621", "high", "deny", true, 7),
		row("conv-1", "antigravity-cli", "user_prompt", "R-190", "high", "ask", true, 8),
	}
	if _, err := s.InsertGuardEvents(ctx, rows); err != nil {
		t.Fatalf("InsertGuardEvents: %v", err)
	}
	cases := []struct {
		name, tool, session string
		want                []string
	}{
		{"newest first, stops only", "antigravity-cli", "conv-1", []string{"R-190", "B-621", "R-172"}},
		{"other session", "antigravity-cli", "conv-2", []string{"R-172"}},
		{"nothing stopped", "antigravity-cli", "conv-9", nil},
		{"empty session", "antigravity-cli", "", nil},
		{"empty tool", "", "conv-1", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.PromptSessionStops(ctx, tc.tool, tc.session)
			if err != nil {
				t.Fatalf("PromptSessionStops: %v", err)
			}
			var ids []string
			for _, g := range got {
				ids = append(ids, g.RuleID)
			}
			if len(ids) != len(tc.want) {
				t.Fatalf("stops = %v, want %v", ids, tc.want)
			}
			for i := range ids {
				if ids[i] != tc.want[i] {
					t.Fatalf("stops = %v, want %v", ids, tc.want)
				}
			}
			if len(got) > 0 && got[0].Severity == "" {
				t.Fatalf("severity not read: %+v", got[0])
			}
		})
	}
}
