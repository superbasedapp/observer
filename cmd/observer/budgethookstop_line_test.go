package main

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// TestBudgetHookStopClause (WINNODE item 8), one row per case: the budget
// line names the hook-path stop on a node with budget authority, for the
// tools whose hooks ran here and whose capability can deny; nothing on a node
// without the authority.
func TestBudgetHookStopClause(t *testing.T) {
	cc, _ := integration.For("claude-code")
	if cc.BudgetHookStop() == integration.BudgetHookStopNone {
		t.Fatal("precondition: claude-code has a pre-send hook stop")
	}
	noStop := ""
	for _, c := range integration.Capabilities() {
		if c.BudgetHookStop() == integration.BudgetHookStopNone {
			noStop = c.Tool
			break
		}
	}
	cases := []struct {
		name    string
		granted bool
		tools   []string
		want    string // "" means no clause
	}{
		{"individual node", false, []string{"claude-code"}, ""},
		{"managed, claude-code hooks ran", true, []string{"claude-code"}, "; hook-path stop: claude-code (" + string(cc.BudgetHookStop()) + ")"},
		{"managed, no hooks ran", true, nil, "; hook-path stop: none"},
		{"managed, only a tool with no stop seam", true, []string{noStop}, "; hook-path stop: none"},
		{"managed, an unknown tool is ignored", true, []string{"not-a-tool"}, "; hook-path stop: none"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := budgetHookStopClause(tc.granted, tc.tools)
			if tc.want == "" {
				if got != "" {
					t.Fatalf("clause = %q, want none", got)
				}
				return
			}
			if !strings.HasPrefix(got, tc.want) {
				t.Fatalf("clause = %q, want prefix %q", got, tc.want)
			}
		})
	}
}
