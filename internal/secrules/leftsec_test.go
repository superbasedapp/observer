package secrules

import (
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestUnknownPackageActions (lane LEFT-SEC milestone 1): S-744 and S-748
// pick their row by the check's [security.deps] action. The default action
// keeps today's decisions (the golden rows of TestInstallGateDecisionTable);
// ask asks in both modes; deny asks in observe and denies in enforce; a
// not-set-up note always takes the default row.
func TestUnknownPackageActions(t *testing.T) {
	chk := func(v policy.InstallVerdict, action, reason string) policy.InstallCheck {
		return policy.InstallCheck{Ecosystem: "npm", Name: "pkg", Verdict: v, Action: action, Reason: reason}
	}
	rows := []struct {
		name             string
		check            policy.InstallCheck
		rule             string
		observe, enforce policy.Decision
	}{
		{"unknown, default", chk(policy.InstallUnknownName, "", ""), "S-744", policy.DecisionFlag, policy.DecisionFlag},
		{"unknown, default spelled out", chk(policy.InstallUnknownName, policy.InstallActionDefault, ""), "S-744", policy.DecisionFlag, policy.DecisionFlag},
		{"unknown, ask", chk(policy.InstallUnknownName, policy.InstallActionAsk, ""), "S-744", policy.DecisionAsk, policy.DecisionAsk},
		{"unknown, deny", chk(policy.InstallUnknownName, policy.InstallActionDeny, ""), "S-744", policy.DecisionAsk, policy.DecisionDeny},
		{"unknown, an action outside the picker", chk(policy.InstallUnknownName, "allow", ""), "S-744", policy.DecisionFlag, policy.DecisionFlag},
		{"not set up note, deny", chk(policy.InstallUnknownName, policy.InstallActionDeny, reasonNotSetUp), "S-744", policy.DecisionFlag, policy.DecisionFlag},
		{"online unknown, default", chk(policy.InstallOnlineUnknown, "", ""), "S-748", policy.DecisionFlag, policy.DecisionAsk},
		{"online unknown, ask", chk(policy.InstallOnlineUnknown, policy.InstallActionAsk, ""), "S-748", policy.DecisionAsk, policy.DecisionAsk},
		{"online unknown, deny", chk(policy.InstallOnlineUnknown, policy.InstallActionDeny, ""), "S-748", policy.DecisionAsk, policy.DecisionDeny},
		{"malicious ignores the action", chk(policy.InstallMalicious, policy.InstallActionAsk, ""), "S-741", policy.DecisionAsk, policy.DecisionDeny},
	}
	for _, r := range rows {
		for _, m := range []struct {
			mode policy.Mode
			want policy.Decision
		}{{policy.ModeObserve, r.observe}, {policy.ModeEnforce, r.enforce}} {
			ev := policy.Event{
				Security: depsSec(r.check), Kind: policy.KindShellExec, Target: "npm install pkg", ActionType: "run_command",
				Cwd: "/r", ProjectRoot: "/r", Caps: policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: true}, Now: time.Unix(1, 0),
			}
			v := depsEngine(t, m.mode).Evaluate(ev)
			if v.Decision != m.want || v.RuleID != r.rule {
				t.Errorf("%s %s: %s %s, want %s %s", r.name, m.mode, v.RuleID, v.Decision, r.rule, m.want)
			}
		}
	}
}

// TestPushHeldPastReflogCap (lane LEFT-SEC milestone 1, SECP-18 "the reflog
// caps"): when every history-only finding is held only past a reflog cap
// the push is asked in observe and in enforce (never allowed, no longer
// denied); one finding held inside the caps keeps today's deny; under the
// commit gate floor the capped push takes the unknown cell (deny).
func TestPushHeldPastReflogCap(t *testing.T) {
	rows := []struct {
		name             string
		sec              policy.Security
		observe, enforce policy.Decision
	}{
		{"held, no cap (today)", policy.Security{Posture: policy.SecurityPostureBlocking, Blocking: 1, BlockingHistoryOnly: 1}, policy.DecisionAsk, policy.DecisionDeny},
		{"held only past a cap", policy.Security{Posture: policy.SecurityPostureBlocking, Blocking: 1, BlockingHistoryOnly: 1, BlockingHistoryCapped: 1}, policy.DecisionAsk, policy.DecisionAsk},
		{"one of two past a cap", policy.Security{Posture: policy.SecurityPostureBlocking, Blocking: 2, BlockingHistoryOnly: 2, BlockingHistoryCapped: 1}, policy.DecisionAsk, policy.DecisionDeny},
		{"capped but one in the tree", policy.Security{Posture: policy.SecurityPostureBlocking, Blocking: 2, BlockingHistoryOnly: 1, BlockingHistoryCapped: 1}, policy.DecisionAsk, policy.DecisionDeny},
		{"past a cap under the floor", policy.Security{Posture: policy.SecurityPostureBlocking, Blocking: 1, BlockingHistoryOnly: 1, BlockingHistoryCapped: 1, CommitGateFloor: policy.CommitGateFloorQuickScan}, policy.DecisionDeny, policy.DecisionDeny},
	}
	for _, r := range rows {
		for _, m := range []struct {
			mode policy.Mode
			want policy.Decision
		}{{policy.ModeObserve, r.observe}, {policy.ModeEnforce, r.enforce}} {
			sec := r.sec
			v := gateEngine(t, m.mode).Evaluate(shellEvent("git push origin main", true, &sec))
			if v.RuleID != "S-792" || v.Decision != m.want {
				t.Errorf("%s %s: %s %s, want S-792 %s", r.name, m.mode, v.RuleID, v.Decision, m.want)
			}
		}
	}
	// The commit gate is unchanged by a capped hold.
	sec := policy.Security{Posture: policy.SecurityPostureBlocking, Blocking: 1, BlockingHistoryOnly: 1, BlockingHistoryCapped: 1}
	if v := gateEngine(t, policy.ModeEnforce).Evaluate(shellEvent("git commit -m x", true, &sec)); v.Decision != policy.DecisionAllow {
		t.Errorf("a commit with a capped history-only hold: %+v", v)
	}
}
