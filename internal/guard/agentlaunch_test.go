package guard

import (
	"os"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestAgentLaunchAsksEveryTime pins R-168's guard-side rules (lane
// cli-2): the launcher verbs come from the registry, a launch asks in the
// default observe mode, no local approval lifts the ask (one yes is never
// a standing pass), and on a host that cannot ask the deny names no
// approve command.
func TestAgentLaunchAsksEveryTime(t *testing.T) {
	t.Parallel()
	calls := 0
	g, err := New(Options{
		Config: guardCfg(), Home: "/home/u",
		ReadFile: func(string) ([]byte, error) { return nil, os.ErrNotExist },
	})
	if err != nil {
		t.Fatalf("guard.New: %v", err)
	}
	g.SetApprovalLookup(func(string, string, string) (bool, error) { calls++; return true, nil })
	ev := policy.Event{
		Kind: policy.KindShellExec, ActionType: "run_command",
		Target: "observer claude -- -p hi", SessionID: "sA", ProjectRoot: "/home/u/proj",
		Caps: policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: true},
	}
	v, _ := g.EvaluateHook(ev)
	if v.Verdict.RuleID != "R-168" || v.Verdict.Decision != policy.DecisionAsk {
		t.Fatalf("verdict = %s %s (%q), want an R-168 ask", v.Verdict.RuleID, v.Verdict.Decision, v.Verdict.Reason)
	}
	if v.DegradedFrom != "" || calls != 0 {
		t.Fatalf("a grant was consulted or applied: degraded_from=%q lookups=%d", v.DegradedFrom, calls)
	}
	em := ExplainDegradedAsk(ResolveEmission(v.Verdict, policy.Capabilities{PreExecution: true, CanBlock: true}), v, "sA")
	if em.Permission != "deny" || !strings.Contains(em.Reason, "No approval covers it") || strings.Contains(em.Reason, "guard approve") {
		t.Fatalf("degraded deny = %q %q", em.Permission, em.Reason)
	}
	// The tool gate's failure posture is unchanged on an observe-mode node.
	if g.GateEnforcement().Tool {
		t.Fatal("R-168 made the observe-mode tool gate fail closed")
	}
}
