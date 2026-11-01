package controlcoverage_test

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/controlcoverage"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// hookFacts wires the real internal/hook dialect facts, the same pair
// tools/guardcoveragegen passes.
var hookFacts = controlcoverage.RuleSeamFacts{
	PromptCaps:    hook.PromptDialectSeamCaps,
	ToolAskProbed: hook.ToolGateAskProbed,
}

// laneWant is one lane's expected seam, outcomes and a caveat fragment
// ("" = no caveat required).
type laneWant struct {
	seam            controlcoverage.RuleSeam
	flag, ask, deny controlcoverage.RuleOutcome
	caveat          string
}

const (
	blocks   = controlcoverage.RuleBlocks
	asks     = controlcoverage.RuleAsks
	resend   = controlcoverage.RuleAsksResend
	warns    = controlcoverage.RuleWarns
	toModel  = controlcoverage.RuleWarnsModel
	records  = controlcoverage.RuleRecordsOnly
	hookSeam = controlcoverage.RuleSeamHook
	proxy    = controlcoverage.RuleSeamProxy
	capture  = controlcoverage.RuleSeamCapture
)

// TestRuleCoveragePinnedTools pins what a developer experiences per rule
// decision on a handful of tools, matching the guard-enforcement fix's
// proven behaviour (2026-10-15). A registry or dialect edit that changes one
// of these answers must change this table on purpose.
func TestRuleCoveragePinnedTools(t *testing.T) {
	cases := []struct {
		tool         string
		prompt, call laneWant
	}{
		// Claude Code: systemMessage warns, exit 2 blocks, resend confirms;
		// PreToolUse has the native ask and a systemMessage flag notice.
		{
			models.ToolClaudeCode,
			laneWant{hookSeam, warns, resend, blocks, ""},
			laneWant{hookSeam, warns, asks, blocks, ""},
		},
		// Codex: no permissionDecision ask, so an ask on a tool blocks.
		{
			models.ToolCodex,
			laneWant{hookSeam, warns, resend, blocks, ""},
			laneWant{hookSeam, warns, blocks, blocks, "spawn_agent"},
		},
		// Antigravity CLI: PreInvocation warns or aborts (atomic: an ask
		// blocks); the tool gate's force_ask is the native prompt.
		{
			models.ToolAntigravityCLI,
			laneWant{hookSeam, warns, blocks, blocks, "title request"},
			laneWant{hookSeam, records, asks, blocks, "interactive agy"},
		},
		// Cline CLI plugin: beforeModel stops or rewrites, no notice; the
		// tool gate asks with Cline's own approval.
		{
			models.ToolClineCLI,
			laneWant{hookSeam, records, blocks, blocks, "no stop reason"},
			laneWant{hookSeam, records, asks, blocks, "y/N"},
		},
		// Cursor: beforeSubmitPrompt stops (no notice field); the per-class
		// events ask natively while preToolUse cannot.
		{
			models.ToolCursor,
			laneWant{hookSeam, records, resend, blocks, ""},
			laneWant{hookSeam, records, asks, blocks, "On preToolUse an ask blocks."},
		},
		// OpenCode plugin shim: a toast warns, a throw stops, resend confirms.
		{
			models.ToolOpenCode,
			laneWant{hookSeam, warns, resend, blocks, "toasts"},
			laneWant{hookSeam, warns, blocks, blocks, "TUI toasts"},
		},
		// pi: notify warns, ctx.ui.confirm asks natively, handled blocks.
		{
			models.ToolPi,
			laneWant{hookSeam, warns, asks, blocks, "print or json"},
			laneWant{hookSeam, warns, asks, blocks, ""},
		},
		// Copilot CLI: additionalContext reaches the model only.
		{
			models.ToolCopilotCLI,
			laneWant{hookSeam, toModel, resend, blocks, "assistant's reply"},
			laneWant{hookSeam, records, asks, blocks, "headless"},
		},
		// Kiro CLI: the prompt hook cannot block, it only informs the model.
		{
			models.ToolKiroCLI,
			laneWant{hookSeam, toModel, toModel, toModel, "cannot stop"},
			laneWant{hookSeam, records, blocks, blocks, "workspace agents"},
		},
		// goose: no prompt hook; the proxy acts while routed.
		{
			models.ToolGoose,
			laneWant{proxy, records, resend, blocks, "Observer proxy"},
			laneWant{hookSeam, records, blocks, blocks, "Code Mode"},
		},
		// Crush: no UserPromptSubmit; deny-only tool gate.
		{
			models.ToolCrush,
			laneWant{proxy, records, resend, blocks, "Observer proxy"},
			laneWant{hookSeam, records, blocks, blocks, "sub-agents"},
		},
		// Aider: no hook surface at all.
		{
			models.ToolAider,
			laneWant{proxy, records, resend, blocks, "Observer proxy"},
			laneWant{capture, records, records, records, ""},
		},
	}
	byTool := map[string]controlcoverage.ToolRuleCoverage{}
	for _, r := range controlcoverage.RuleCoverage(hookFacts) {
		byTool[r.Tool] = r
	}
	check := func(t *testing.T, lane string, got controlcoverage.RuleLaneCoverage, want laneWant) {
		t.Helper()
		if got.Seam != want.seam || got.Flag != want.flag || got.Ask != want.ask || got.Deny != want.deny {
			t.Errorf("%s = %s flag=%s ask=%s deny=%s, want %s flag=%s ask=%s deny=%s",
				lane, got.Seam, got.Flag, got.Ask, got.Deny, want.seam, want.flag, want.ask, want.deny)
		}
		if want.caveat != "" && !strings.Contains(strings.Join(got.Caveats, " | "), want.caveat) {
			t.Errorf("%s caveats %q lack %q", lane, got.Caveats, want.caveat)
		}
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			r, ok := byTool[tc.tool]
			if !ok {
				t.Fatalf("no rule coverage row for %s", tc.tool)
			}
			check(t, "prompt", r.Prompt, tc.prompt)
			check(t, "tool call", r.ToolCall, tc.call)
		})
	}
}

// TestRuleCoverageVocabularyAndText pins the invariants every row holds: the
// outcomes come from the closed vocabulary, every row names the tool, and no
// generated text carries an em or en dash.
func TestRuleCoverageVocabularyAndText(t *testing.T) {
	known := map[controlcoverage.RuleOutcome]bool{}
	for _, o := range controlcoverage.RuleOutcomes() {
		known[o] = true
	}
	rows := controlcoverage.RuleCoverage(hookFacts)
	if len(rows) == 0 {
		t.Fatal("no rule coverage rows")
	}
	for _, r := range rows {
		if r.Name == "" {
			t.Errorf("%s: empty name", r.Tool)
		}
		for _, l := range []controlcoverage.RuleLaneCoverage{r.Prompt, r.ToolCall} {
			for _, o := range []controlcoverage.RuleOutcome{l.Flag, l.Ask, l.Deny} {
				if !known[o] {
					t.Errorf("%s: outcome %q outside the vocabulary", r.Tool, o)
				}
			}
			for _, c := range l.Caveats {
				if strings.ContainsAny(c, "\u2013\u2014") {
					t.Errorf("%s: caveat carries a dash: %q", r.Tool, c)
				}
			}
		}
	}
}
