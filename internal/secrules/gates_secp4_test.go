package secrules

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secposture/gatetable"
)

// TestCommitGateFloorColumn (lane SEC-P4 decision 9): one row per gate
// state under the project's commit gate floor. Each cell is the managed
// floor column of the section 4.8 table (gatetable.Gate) in observe and
// enforce alike, on a channel that can ask and one that cannot; the same
// states without the floor keep the golden individual columns
// (TestCommitGateDecisionTable).
func TestCommitGateFloorColumn(t *testing.T) {
	floor := func(s policy.Security) *policy.Security {
		s.CommitGateFloor = policy.CommitGateFloorQuickScan
		return &s
	}
	rows := []struct {
		name  string
		cmd   string
		state *policy.Security
		rule  string
		cell  gatetable.GateOutcome
	}{
		{"clean", "git commit -m x", floor(policy.Security{Posture: policy.SecurityPostureClean}), "", gatetable.GateAllow},
		{"blocking commit S-791", "git commit -m x", floor(policy.Security{Posture: policy.SecurityPostureBlocking, Blocking: 1}), "S-791", gatetable.GateDeny},
		{"blocking push S-792", "git push origin main", floor(policy.Security{Posture: policy.SecurityPostureBlocking, Blocking: 1}), "S-792", gatetable.GateDeny},
		{"dirty, quick scan clean", "git commit -m x", floor(policy.Security{Posture: policy.SecurityPostureDirty, QuickScan: policy.QuickScanClean}), "", gatetable.GateAllow},
		{"dirty, quick scan not clean S-793", "git commit -m x", floor(policy.Security{Posture: policy.SecurityPostureDirty, QuickScan: policy.QuickScanUnknown}), "S-793", gatetable.GateWaitScanDeny},
		{"dirty, quick scan blocking S-793", "git push origin main", floor(policy.Security{Posture: policy.SecurityPostureDirty, QuickScan: policy.QuickScanBlocking}), "S-793", gatetable.GateWaitScanDeny},
		{"unknown S-794", "git commit -m x", floor(policy.Security{Posture: policy.SecurityPostureUnknown}), "S-794", gatetable.GateDeny},
		{"history-only hold, push to the remote that has it", "git push origin main", floor(*heldOn("origin")), "", gatetable.GateAllow},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			if got := gatetable.AfterQuickScan(gatetable.Gate(r.state.Posture, gatetable.GateManagedFloor), r.state.QuickScan); r.cell != gatetable.GateAllow && got == gatetable.GateAllow {
				t.Fatalf("table cell %s, row expects %s", got, r.cell)
			}
			want := "allow"
			if r.cell != gatetable.GateAllow {
				want = "deny"
			}
			for _, mode := range []policy.Mode{policy.ModeObserve, policy.ModeEnforce} {
				for _, canAsk := range []bool{true, false} {
					v := gateEngine(t, mode).Evaluate(shellEvent(r.cmd, canAsk, r.state))
					em := guard.ResolveEmission(v, policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: canAsk})
					if em.Permission != want || v.RuleID != r.rule {
						t.Fatalf("mode %s canAsk %v: %s %s (verdict %+v), want %s %s", mode, canAsk, em.Permission, v.RuleID, v, want, r.rule)
					}
				}
			}
		})
	}
	// The floor value "ask" (or none) is the node's own commit gate.
	st := &policy.Security{Posture: policy.SecurityPostureUnknown, CommitGateFloor: "ask"}
	if v := gateEngine(t, policy.ModeObserve).Evaluate(shellEvent("git commit -m x", true, st)); v.RuleID != "S-794" || v.Decision != policy.DecisionAsk {
		t.Fatalf("an ask floor: %+v, want the individual S-794 ask", v)
	}
}
