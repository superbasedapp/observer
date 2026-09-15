package guard

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestResolveEmission pins the §6.2 capability-degradation table —
// one case per row of the documented mapping, plus the F5 invariant
// (a degradation is always RECORDED, never a silent allow).
func TestResolveEmission(t *testing.T) {
	t.Parallel()
	full := policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: true}
	noAsk := policy.Capabilities{PreExecution: true, CanBlock: true}
	postHoc := policy.Capabilities{}

	cases := []struct {
		name         string
		decision     policy.Decision
		caps         policy.Capabilities
		wantPerm     string
		wantDegraded string
		wantEnforced bool
	}{
		{"allow stands", policy.DecisionAllow, full, "allow", "", false},
		{"flag proceeds (D2)", policy.DecisionFlag, full, "allow", "", false},
		{"ask native", policy.DecisionAsk, full, "ask", "", true},
		{"ask degrades to deny on no-ask blocker (F5)", policy.DecisionAsk, noAsk, "deny", "ask", true},
		{"ask degrades to recorded allow post-hoc", policy.DecisionAsk, postHoc, "allow", "ask", false},
		{"deny on blocker", policy.DecisionDeny, full, "deny", "", true},
		{"deny degrades to recorded allow post-hoc", policy.DecisionDeny, postHoc, "allow", "deny", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			em := ResolveEmission(policy.Verdict{
				Decision: tc.decision, RuleID: "R-X",
				Reason: "what happened.", Advice: "What to do.",
			}, tc.caps)
			if em.Permission != tc.wantPerm || em.DegradedFrom != tc.wantDegraded || em.Enforced != tc.wantEnforced {
				t.Errorf("emission = %+v, want perm=%s degraded=%q enforced=%v",
					em, tc.wantPerm, tc.wantDegraded, tc.wantEnforced)
			}
			if em.Reason != "what happened. What to do." {
				t.Errorf("reason composition = %q", em.Reason)
			}
		})
	}
}

// recordingNotifier captures Notify calls for alert tests.
type recordingNotifier struct{ titles []string }

func (r *recordingNotifier) Notify(title, _ string) { r.titles = append(r.titles, title) }

// TestMaybeAlert pins the [guard.alerts] gating: min_severity
// threshold, the desktop=false kill-switch, guard_error always
// alerting, and no-rule verdicts staying silent.
func TestMaybeAlert(t *testing.T) {
	t.Parallel()
	mk := func(desktop bool, minSev string) (*Guard, *recordingNotifier) {
		n := &recordingNotifier{}
		cfg := guardCfg()
		cfg.Alerts.Desktop = desktop
		cfg.Alerts.MinSeverity = minSev
		g, err := New(Options{
			Config: cfg, Home: "/home/u", Notifier: n,
			ReadFile: func(string) ([]byte, error) { return nil, os.ErrNotExist },
		})
		if err != nil {
			t.Fatalf("guard.New: %v", err)
		}
		return g, n
	}
	verdict := func(sev policy.Severity, ruleID string) ActionVerdict {
		return ActionVerdict{
			Input: ActionInput{Tool: "claude-code"},
			Verdict: policy.Verdict{
				RuleID: ruleID, Severity: sev,
				Decision: policy.DecisionFlag, Reason: "r",
			},
		}
	}

	g, n := mk(true, "high")
	g.MaybeAlert(verdict(policy.SeverityCritical, "R-101")) // >= high: fires
	g.MaybeAlert(verdict(policy.SeverityWarn, "R-150"))     // below: silent
	g.MaybeAlert(ActionVerdict{})                           // no rule hit: silent
	if len(n.titles) != 1 || !strings.Contains(n.titles[0], "R-101") {
		t.Errorf("alerts = %v, want one R-101 alert", n.titles)
	}

	// guard_error alerts regardless of its severity vs threshold.
	g, n = mk(true, "critical")
	ge := verdict(policy.SeverityHigh, GuardErrorRuleID)
	ge.GuardError = true
	g.MaybeAlert(ge)
	if len(n.titles) != 1 {
		t.Errorf("guard_error alert suppressed below threshold: %v", n.titles)
	}

	// desktop=false drops the notifier entirely.
	g, n = mk(false, "info")
	g.MaybeAlert(verdict(policy.SeverityCritical, "R-101"))
	if len(n.titles) != 0 {
		t.Errorf("alerts fired with desktop=false: %v", n.titles)
	}

	// FIX-3 (phase-2 review): SuppressAlert silences a toast even at
	// Critical severity — the prompt-submit hook lane's own
	// "already shown in-band" case (a routine ask-once secret
	// interrupt, R-172 = SeverityCritical on the rule row itself,
	// independent of severity threshold).
	g, n = mk(true, "high")
	suppressed := verdict(policy.SeverityCritical, "R-172")
	suppressed.SuppressAlert = true
	g.MaybeAlert(suppressed)
	if len(n.titles) != 0 {
		t.Errorf("SuppressAlert did not silence a Critical-severity toast: %v", n.titles)
	}

	// ... but SuppressAlert never silences a genuine GuardError, same
	// as the severity-threshold gate above.
	g, n = mk(true, "critical")
	geSuppressed := verdict(policy.SeverityHigh, GuardErrorRuleID)
	geSuppressed.GuardError = true
	geSuppressed.SuppressAlert = true
	g.MaybeAlert(geSuppressed)
	if len(n.titles) != 1 {
		t.Errorf("SuppressAlert silenced a guard_error alert: %v", n.titles)
	}
}

// TestEvaluateHook covers the pre-execution seam: verdict shaping (no
// ActionID anchor), record-worthiness, and the taint snapshot being
// consumed (not populated) on this path.
func TestEvaluateHook(t *testing.T) {
	t.Parallel()
	cfg := guardCfg()
	cfg.Mode = "enforce"
	g, err := New(Options{
		Config: cfg, Home: "/home/u",
		ReadFile: func(string) ([]byte, error) { return nil, os.ErrNotExist },
	})
	if err != nil {
		t.Fatalf("guard.New: %v", err)
	}

	// Enforce mode: R-101 denies. The target is the HOME-anchored
	// form — the hook path carries no ProjectRoot (documented
	// boundary approximation), so the outside-project half of R-101
	// can't fire; the ~/-targeting half can.
	v, worthy := g.EvaluateHook(policy.Event{
		Kind: policy.KindShellExec, ActionType: "run_command",
		Target: "rm -rf ~", SessionID: "sH",
		Caps: policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: true},
	})
	if !worthy || v.Verdict.RuleID != "R-101" || v.Verdict.Decision != policy.DecisionDeny {
		t.Errorf("verdict = %+v (worthy=%v), want R-101 deny", v.Verdict, worthy)
	}
	if v.Input.ActionID != 0 {
		t.Error("hook verdict carries an action anchor — pre-execution has none")
	}
	if v.Category != "destructive" {
		t.Errorf("category = %q", v.Category)
	}

	// Benign command: not record-worthy.
	if _, worthy := g.EvaluateHook(policy.Event{
		Kind: policy.KindShellExec, ActionType: "run_command",
		Target: "go test ./...", SessionID: "sH",
	}); worthy {
		t.Error("benign command record-worthy")
	}

	// The hook path consumes taint state but never populates it: a
	// hook-evaluated mcp call leaves the tracker empty.
	if _, _ = g.EvaluateHook(policy.Event{
		Kind: policy.KindMCPCall, ActionType: "mcp_call",
		Target: "mcp__github__get_file", SessionID: "sT",
	}); g.taint.Snapshot("sT", 0, time.Now().UTC()).Tainted() {
		t.Error("hook evaluation populated taint — marking is the watcher's job (results exist post-hoc)")
	}
}
