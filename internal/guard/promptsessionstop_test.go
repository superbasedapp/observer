package guard

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestPromptSessionStopped pins the stopped-conversation taint read: the
// newest content stop wins, a budget stop never taints, and no lookup or
// no session is never a taint.
func TestPromptSessionStopped(t *testing.T) {
	t.Parallel()
	secret := PromptSessionStop{RuleID: "R-172", Severity: "critical"}
	budget := PromptSessionStop{RuleID: "B-621", Severity: "high"}
	cases := []struct {
		name    string
		lookup  PromptSessionStopLookup
		session string
		want    PromptSessionStop
		wantOK  bool
	}{
		{"no lookup wired", nil, "s1", PromptSessionStop{}, false},
		{"no session", func(string, string) []PromptSessionStop { return []PromptSessionStop{secret} }, "", PromptSessionStop{}, false},
		{"nothing stopped", func(string, string) []PromptSessionStop { return nil }, "s1", PromptSessionStop{}, false},
		{"a content stop taints", func(string, string) []PromptSessionStop { return []PromptSessionStop{secret} }, "s1", secret, true},
		{"budget stops are skipped to an earlier content stop", func(string, string) []PromptSessionStop {
			return []PromptSessionStop{budget, budget, secret}
		}, "s1", secret, true},
		{"budget stops alone never taint", func(string, string) []PromptSessionStop { return []PromptSessionStop{budget} }, "s1", PromptSessionStop{}, false},
		{"a fail-closed guard error never taints", func(string, string) []PromptSessionStop {
			return []PromptSessionStop{{RuleID: GuardErrorRuleID, Severity: "high"}}
		}, "s1", PromptSessionStop{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			g := &Guard{}
			if tc.lookup != nil {
				g.SetPromptSessionStopLookup(tc.lookup)
			}
			got, ok := g.PromptSessionStopped("antigravity-cli", tc.session)
			if ok != tc.wantOK || got != tc.want {
				t.Fatalf("PromptSessionStopped = %+v ok=%v, want %+v ok=%v", got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

// TestTaintedSessionPromptVerdict pins the verdict a tainted turn gets and
// how a silent-block seam resolves and records it.
func TestTaintedSessionPromptVerdict(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		stop    PromptSessionStop
		wantSev policy.Severity
	}{
		{"keeps the stopping rule's severity", PromptSessionStop{RuleID: "R-172", Severity: "critical"}, policy.SeverityCritical},
		{"unparseable severity is high", PromptSessionStop{RuleID: "R-190", Severity: ""}, policy.SeverityHigh},
	}
	silentBlock := PromptSeamCaps{Warn: true, Block: true, BlockSilent: true}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pv := TaintedSessionPromptVerdict(tc.stop)
			if pv.Verdict.RuleID != tc.stop.RuleID || pv.Verdict.Decision != policy.DecisionDeny ||
				pv.Verdict.Severity != tc.wantSev || pv.Outcome != PromptOutcomeBlocked ||
				pv.DegradedFrom != DegradedFromTaintedSession ||
				!strings.Contains(pv.Verdict.Reason, "Start a new conversation") ||
				!strings.Contains(pv.Verdict.Reason, tc.stop.RuleID) {
				t.Fatalf("verdict = %+v", pv)
			}
			pv = pv.WithAction(silentBlock, "hook")
			if pv.Action != PromptActionBlock || !pv.BlockSilent {
				t.Fatalf("action = %q silent %v, want block, silent", pv.Action, pv.BlockSilent)
			}
			em := PromptEmission(pv)
			av := newTestGuard(t, guardCfg(), nil).ActionVerdictFromPrompt(pv, em, ActionInput{SessionID: "s1", Tool: "antigravity-cli"})
			if !av.Enforced || !av.SilentStop || av.SuppressAlert || !alertsRegardlessOfSeverity(av) {
				t.Fatalf("action verdict enforced=%v silent=%v suppress=%v", av.Enforced, av.SilentStop, av.SuppressAlert)
			}
		})
	}
}

// TestWithActionBlockSilent pins that only a block on a BlockSilent seam is
// a silent stop: the same seam's warning is not.
func TestWithActionBlockSilent(t *testing.T) {
	t.Parallel()
	caps := PromptSeamCaps{Warn: true, Block: true, BlockSilent: true}
	flag := PromptVerdict{Verdict: policy.Verdict{Decision: policy.DecisionFlag, RuleID: "R-172"}, Outcome: PromptOutcomeWarned}
	pv := flag.WithAction(caps, "hook")
	av := newTestGuard(t, guardCfg(), nil).ActionVerdictFromPrompt(pv, PromptEmission(pv), ActionInput{})
	if pv.Action != PromptActionWarn || av.SilentStop || !av.SuppressAlert {
		t.Fatalf("warn on a silent-block seam: action %q silent %v suppress %v", pv.Action, av.SilentStop, av.SuppressAlert)
	}
	ask := PromptVerdict{Verdict: policy.Verdict{Decision: policy.DecisionAsk, RuleID: "R-172"}, Outcome: PromptOutcomeBlocked}
	if got, wanted := ResolvePromptAction(policy.DecisionAsk, caps); got != PromptActionBlock || wanted != PromptActionConfirm {
		t.Fatalf("ask on warn+block = %q (wanted %q), want block degraded from confirm", got, wanted)
	}
	if pv := ask.WithAction(caps, "hook"); pv.Action != PromptActionBlock || pv.Outcome != PromptOutcomeBlocked {
		t.Fatalf("ask resolved to %q outcome %q", pv.Action, pv.Outcome)
	}
}
