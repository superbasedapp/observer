package cursorusage

import (
	"strings"
	"testing"
)

// One case per rule-table row, in table order, plus precedence checks.
func TestClassifyAndExplain(t *testing.T) {
	const nodeOneDetail = "The cursor-agent turn started at 11:13:23 UTC had 3 failed request attempts (LostConnection x3), and the session ended while Cursor was still retrying."
	for _, tc := range []struct {
		name     string
		ev       Evidence
		want     Reason
		contains []string
	}{
		{
			"node1_unfinished_turn",
			Evidence{Prompts: 1, UnfinishedTurns: 1, FailedAttempts: 3, LatestTurnDetail: nodeOneDetail},
			ReasonUnfinishedTurn,
			[]string{"1 turn never finished", "LostConnection x3", "unknown, not zero"},
		},
		{"unfinished_beats_failed", Evidence{UnfinishedTurns: 2, FailedTurns: 1}, ReasonUnfinishedTurn, []string{"2 turns never finished"}},
		{"failed_turn", Evidence{Prompts: 1, FailedTurns: 1, LatestTurnDetail: "ended with outcome error"}, ReasonFailedTurn, []string{"1 turn ended without a successful outcome", "ended with outcome error."}},
		{"response_hook_without_usage", Evidence{Prompts: 2, ResponseHooks: 2}, ReasonResponseWithoutUsage, []string{"afterAgentResponse hook arrived for 2 responses"}},
		{"hooks_wired_but_silent", Evidence{Prompts: 1, FinishHooks: HookWiringComplete}, ReasonFinishHooksSilent, []string{"1 prompt was recorded", "neither Cursor's stop nor afterAgentResponse", "Both hooks are registered", "most likely never finished"}},
		{"hooks_not_registered", Evidence{Prompts: 2, FinishHooks: HookWiringIncomplete}, ReasonFinishHooksMissing, []string{"2 prompts were recorded", "not both registered", "observer init --cursor"}},
		{"prompt_but_no_finish_hook_wiring_unknown", Evidence{Prompts: 1}, ReasonNoFinishHook, []string{"1 prompt was recorded", "neither Cursor's stop nor afterAgentResponse", "most likely never finished", "observer doctor cursor"}},
		{"unfinished_beats_wiring", Evidence{Prompts: 1, UnfinishedTurns: 1, FinishHooks: HookWiringIncomplete}, ReasonUnfinishedTurn, []string{"1 turn never finished"}},
		{"nothing_recorded", Evidence{}, ReasonNoEvidence, []string{"no prompt or turn record says why"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Classify(tc.ev); got != tc.want {
				t.Fatalf("Classify = %s, want %s", got, tc.want)
			}
			note := Explain(tc.ev, 0)
			for _, want := range tc.contains {
				if !strings.Contains(note, want) {
					t.Errorf("note missing %q:\n%s", want, note)
				}
			}
			if strings.ContainsRune(note, '\u2014') {
				t.Errorf("user-facing copy must use plain hyphens: %s", note)
			}
			if Remedy(tc.want) == "" {
				t.Errorf("reason %s has no remedy", tc.want)
			}
		})
	}
}

func TestExplainContextBudgetNeverImpliesUsage(t *testing.T) {
	n := Explain(Evidence{Prompts: 1}, 12363)
	if !strings.Contains(n, "not billed usage") {
		t.Fatalf("budget clause missing: %s", n)
	}
	if strings.Contains(Explain(Evidence{Prompts: 1}, 0), "not billed usage") {
		t.Fatal("budget clause without a budget")
	}
}

// Live finding D4 (2026-09-28): the remedy and the note may tell the user to
// run `observer init --cursor` ONLY when the finish hooks are not registered.
// With them registered the advice would change nothing; with the state
// unknown (the org drawer) it must not be asserted either.
func TestInitAdviceOnlyWhenFinishHooksUnregistered(t *testing.T) {
	for _, tc := range []struct {
		wiring   HookWiring
		wantInit bool
	}{
		{HookWiringComplete, false},
		{HookWiringIncomplete, true},
		{HookWiringUnknown, false},
	} {
		ev := Evidence{Prompts: 3, FinishHooks: tc.wiring}
		note := Explain(ev, 0)
		remedy := Remedy(Classify(ev))
		gotNoteInit := strings.Contains(note, "run `observer init --cursor`")
		gotRemedyInit := strings.HasPrefix(remedy, "run `observer init --cursor`")
		if gotNoteInit != tc.wantInit || gotRemedyInit != tc.wantInit {
			t.Errorf("wiring %d: note init=%v remedy init=%v, want %v\nnote: %s\nremedy: %s",
				tc.wiring, gotNoteInit, gotRemedyInit, tc.wantInit, note, remedy)
		}
	}
	// Wiring never changes the evidence-bearing reasons ahead of it.
	if Classify(Evidence{Prompts: 1, ResponseHooks: 1, FinishHooks: HookWiringComplete}) != ReasonResponseWithoutUsage {
		t.Error("a response hook row must still win over the wiring rows")
	}
	// WithoutDetail keeps the wiring (the org metadata-only note path).
	if (Evidence{FinishHooks: HookWiringComplete, LatestTurnDetail: "x"}).WithoutDetail().FinishHooks != HookWiringComplete {
		t.Error("WithoutDetail dropped FinishHooks")
	}
}
