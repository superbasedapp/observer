package controlcoverage

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestLaneFromPromptCaps pins the prompt ladder's mapping onto outcomes, one
// row per seam capability shape.
func TestLaneFromPromptCaps(t *testing.T) {
	cases := []struct {
		name            string
		caps            guard.PromptSeamCaps
		flag, ask, deny RuleOutcome
	}{
		{"capture lane", guard.PromptSeamCapture, RuleRecordsOnly, RuleRecordsOnly, RuleRecordsOnly},
		{"proxy", guard.PromptSeamProxy, RuleRecordsOnly, RuleAsksResend, RuleBlocks},
		{"warn only, model", guard.PromptSeamWarnOnly, RuleWarnsModel, RuleWarnsModel, RuleWarnsModel},
		{"stop and notice", guard.PromptSeamCaps{Warn: true, Reenter: true, Block: true}, RuleWarns, RuleAsksResend, RuleBlocks},
		{"native confirm", guard.PromptSeamCaps{Warn: true, Confirm: true, Reenter: true, Block: true}, RuleWarns, RuleAsks, RuleBlocks},
		{"block only", guard.PromptSeamCaps{Block: true}, RuleRecordsOnly, RuleBlocks, RuleBlocks},
		{"redact only", guard.PromptSeamCaps{Redact: true}, RuleRecordsOnly, RuleRedacts, RuleRedacts},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := laneFromPromptCaps(RuleSeamHook, "", tc.caps)
			if l.Flag != tc.flag || l.Ask != tc.ask || l.Deny != tc.deny {
				t.Fatalf("got flag=%s ask=%s deny=%s, want %s %s %s", l.Flag, l.Ask, l.Deny, tc.flag, tc.ask, tc.deny)
			}
		})
	}
}

// TestToolDecisionOutcome pins the tool-gate table (ResolveEmission plus the
// flag notice), one row per (decision, channel shape).
func TestToolDecisionOutcome(t *testing.T) {
	askBlock := policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: true}
	blockOnly := policy.Capabilities{PreExecution: true, CanBlock: true}
	notice := integration.HookBinding{WarnField: "systemMessage"}
	silent := integration.HookBinding{}
	cases := []struct {
		name string
		d    policy.Decision
		caps policy.Capabilities
		b    integration.HookBinding
		want RuleOutcome
	}{
		{"deny on a blocking gate", policy.DecisionDeny, blockOnly, silent, RuleBlocks},
		{"deny on an observe channel", policy.DecisionDeny, policy.Capabilities{}, silent, RuleRecordsOnly},
		{"ask with a native ask", policy.DecisionAsk, askBlock, silent, RuleAsks},
		{"ask without one blocks", policy.DecisionAsk, blockOnly, silent, RuleBlocks},
		{"ask on an observe channel", policy.DecisionAsk, policy.Capabilities{}, silent, RuleRecordsOnly},
		{"flag with a warn field", policy.DecisionFlag, blockOnly, notice, RuleWarns},
		{"flag without one", policy.DecisionFlag, askBlock, silent, RuleRecordsOnly},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := toolDecisionOutcome(tc.d, tc.caps, tc.b); got != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
}

// TestDifferenceCaveat pins the secondary-gate caveat wording.
func TestDifferenceCaveat(t *testing.T) {
	primary := RuleLaneCoverage{Flag: RuleRecordsOnly, Ask: RuleAsks, Deny: RuleBlocks}
	cases := []struct {
		name  string
		other RuleLaneCoverage
		want  string
	}{
		{"same answers", RuleLaneCoverage{Event: "e", Flag: RuleRecordsOnly, Ask: RuleAsks, Deny: RuleBlocks}, ""},
		{"ask differs", RuleLaneCoverage{Event: "preToolUse", Flag: RuleRecordsOnly, Ask: RuleBlocks, Deny: RuleBlocks}, "On preToolUse an ask blocks."},
		{"two differ", RuleLaneCoverage{Event: "x", Flag: RuleWarns, Ask: RuleBlocks, Deny: RuleBlocks}, "On x a flag warns and an ask blocks."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := differenceCaveat(primary, tc.other); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
