package secrules_test

// The commit gate tables that resolve the emitted permission through
// internal/guard. They live in the external test package because guard
// imports this package (it lints the org layer against the full pack,
// internal/guard/orgpack.go), so an in-package test importing guard would
// be an import cycle.

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secposture/gatetable"
	"github.com/marmutapp/superbased-observer/internal/secrules"
)

// TestCommitGateDecisionTable is one row per state and column of section
// 4.8's individual-node columns: observe on a channel that can ask,
// observe on a host that cannot ask or a headless run (D-791 Q27), and
// enforce. Each cell is the emitted permission after ResolveEmission.
func TestCommitGateDecisionTable(t *testing.T) {
	type cell struct{ observeAsk, observeNoAsk, enforceAsk string }
	rows := []struct {
		name  string
		cmd   string
		state *policy.Security
		rule  string
		want  cell
	}{
		{"absent", "git commit -m x", &policy.Security{Posture: policy.SecurityPostureAbsent}, "", cell{"allow", "allow", "allow"}},
		{"clean", "git commit -m x", &policy.Security{Posture: policy.SecurityPostureClean}, "", cell{"allow", "allow", "allow"}},
		{"blocking commit S-791", "git commit -m x", &policy.Security{Posture: policy.SecurityPostureBlocking, Blocking: 2}, "S-791", cell{"ask", "deny", "deny"}},
		{"blocking push S-792", "git push origin main", &policy.Security{Posture: policy.SecurityPostureBlocking}, "S-792", cell{"ask", "deny", "deny"}},
		{"dirty, quick scan clean", "git commit -m x", &policy.Security{Posture: policy.SecurityPostureDirty, QuickScan: policy.QuickScanClean}, "", cell{"allow", "allow", "allow"}},
		{"dirty, quick scan blocking S-793", "git commit -m x", &policy.Security{Posture: policy.SecurityPostureDirty, QuickScan: policy.QuickScanBlocking}, "S-793", cell{"ask", "deny", "ask"}},
		{"dirty, quick scan unfinished S-793", "git commit -m x", &policy.Security{Posture: policy.SecurityPostureDirty, QuickScan: policy.QuickScanUnknown}, "S-793", cell{"ask", "deny", "ask"}},
		{"dirty, no quick scan S-793", "git commit -m x", &policy.Security{Posture: policy.SecurityPostureDirty}, "S-793", cell{"ask", "deny", "ask"}},
		{"unknown S-794", "git commit -m x", &policy.Security{Posture: policy.SecurityPostureUnknown}, "S-794", cell{"ask", "deny", "ask"}},
		{"not a commit", "git status", &policy.Security{Posture: policy.SecurityPostureBlocking}, "", cell{"allow", "allow", "allow"}},
		{"stash is flag only", "git stash", &policy.Security{Posture: policy.SecurityPostureBlocking}, "", cell{"allow", "allow", "allow"}},
		{"plumbing commit S-791", "git commit-tree HEAD^{tree} -m x", &policy.Security{Posture: policy.SecurityPostureBlocking}, "S-791", cell{"ask", "deny", "deny"}},
		// Lane sec-gate3 audit finding 2: a finding only an unpushed commit
		// holds open gates the push, not another commit.
		{"history-only hold, commit", "git commit -m x", &policy.Security{Posture: policy.SecurityPostureBlocking, Blocking: 1, BlockingHistoryOnly: 1}, "", cell{"allow", "allow", "allow"}},
		{"history-only hold, push S-792", "git push origin main", &policy.Security{Posture: policy.SecurityPostureBlocking, Blocking: 1, BlockingHistoryOnly: 1}, "S-792", cell{"ask", "deny", "deny"}},
		{"history-only hold and one in the tree, commit S-791", "git commit -m x", &policy.Security{Posture: policy.SecurityPostureBlocking, Blocking: 2, BlockingHistoryOnly: 1}, "S-791", cell{"ask", "deny", "deny"}},
		// Lane sec-gate4 milestone 1a: the push gate compares against the
		// push's own remote.
		{"history-only hold, push to the remote that has it", "git push origin main", secrules.HeldOnForTest("origin"), "", cell{"allow", "allow", "allow"}},
		{"history-only hold, push -u to the remote that has it", "git push -u origin feature", secrules.HeldOnForTest("origin"), "", cell{"allow", "allow", "allow"}},
		{"history-only hold, push to the other remote S-792", "git push backup main", secrules.HeldOnForTest("origin"), "S-792", cell{"ask", "deny", "deny"}},
		{"history-only hold, push with no remote S-792", "git push", secrules.HeldOnForTest("origin"), "S-792", cell{"ask", "deny", "deny"}},
		{"history-only hold, push to a URL S-792", "git push https://example.invalid/r.git main", secrules.HeldOnForTest("origin"), "S-792", cell{"ask", "deny", "deny"}},
		{"history-only hold, push --all S-792", "git push --all origin", secrules.HeldOnForTest("origin"), "S-792", cell{"ask", "deny", "deny"}},
		{"history-only hold, push in another repository S-792", "git -C ../other push origin main", secrules.HeldOnForTest("origin"), "S-792", cell{"ask", "deny", "deny"}},
		{"history-only hold and one in the tree, push to the remote S-792", "git push origin main", &policy.Security{
			Posture: policy.SecurityPostureBlocking, Blocking: 2, BlockingHistoryOnly: 1, BlockingHistoryOnlyOn: map[string]int{"origin": 1},
		}, "S-792", cell{"ask", "deny", "deny"}},
		{"history-only hold, capped list, commit S-791", "git commit -m x", &policy.Security{Posture: policy.SecurityPostureBlocking, Blocking: 1, BlockingHistoryOnly: 1, Overflow: true}, "S-791", cell{"ask", "deny", "deny"}},
		// Audit finding 5: a plain push goes to the signed default push
		// remote; audit finding 3: a command line that may change where the
		// push goes is an unknown target.
		{"history-only hold, plain push to the default that has it", "git push", secrules.HeldOnDefaultForTest("origin", "origin"), "", cell{"allow", "allow", "allow"}},
		{"history-only hold, plain push to a default that lacks it S-792", "git push", secrules.HeldOnDefaultForTest("origin", "upstream"), "S-792", cell{"ask", "deny", "deny"}},
		{"history-only hold, push upstream with origin the default S-792", "git push upstream main", secrules.HeldOnDefaultForTest("origin", "origin"), "S-792", cell{"ask", "deny", "deny"}},
		{"history-only hold, plain push with a -c override S-792", "git -c branch.main.pushRemote=upstream push", secrules.HeldOnDefaultForTest("origin", "origin"), "S-792", cell{"ask", "deny", "deny"}},
		{"history-only hold, -c pushurl S-792", "git -c remote.origin.pushurl=/tmp/x push origin main", secrules.HeldOnForTest("origin"), "S-792", cell{"ask", "deny", "deny"}},
		{"history-only hold, GIT_CONFIG_COUNT S-792", "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=remote.origin.pushurl GIT_CONFIG_VALUE_0=/tmp/x git push origin main", secrules.HeldOnForTest("origin"), "S-792", cell{"ask", "deny", "deny"}},
		// Audit finding 3: a write to the remote-tracking state while the
		// posture is blocking.
		{"history-only hold, update-ref a tracking ref S-792", "git update-ref refs/remotes/backup/x HEAD", secrules.HeldOnForTest("origin"), "S-792", cell{"ask", "deny", "deny"}},
		{"history-only hold, fetch . into a tracking ref S-792", "git fetch . HEAD:refs/remotes/backup/x", secrules.HeldOnForTest("origin"), "S-792", cell{"ask", "deny", "deny"}},
		{"history-only hold, remote set-url S-792", "git remote set-url backup /tmp/x", secrules.HeldOnForTest("origin"), "S-792", cell{"ask", "deny", "deny"}},
		{"history-only hold, redirect into a tracking ref S-792", "echo 0 > .git/refs/remotes/backup/main", secrules.HeldOnForTest("origin"), "S-792", cell{"ask", "deny", "deny"}},
		{"history-only hold, plain fetch", "git fetch origin", secrules.HeldOnForTest("origin"), "", cell{"allow", "allow", "allow"}},
		{"clean, update-ref a tracking ref", "git update-ref refs/remotes/backup/x HEAD", &policy.Security{Posture: policy.SecurityPostureClean}, "", cell{"allow", "allow", "allow"}},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			emit := func(mode policy.Mode, canAsk bool) (string, policy.Verdict, guard.Emission) {
				v := secrules.GateEngineForTest(t, mode).Evaluate(secrules.ShellEventForTest(r.cmd, canAsk, r.state))
				em := guard.ResolveEmission(v, policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: canAsk})
				em = guard.ExplainDegradedAsk(em, guard.ActionVerdict{Verdict: v}, "s1")
				return em.Permission, v, em
			}
			got := cell{}
			var v policy.Verdict
			var noAsk guard.Emission
			got.observeAsk, v, _ = emit(policy.ModeObserve, true)
			got.observeNoAsk, _, noAsk = emit(policy.ModeObserve, false)
			got.enforceAsk, _, _ = emit(policy.ModeEnforce, true)
			if got != r.want {
				t.Fatalf("cells = %+v, want %+v (verdict %+v)", got, r.want, v)
			}
			if r.rule != "" && v.RuleID != r.rule {
				t.Fatalf("rule = %q, want %q", v.RuleID, r.rule)
			}
			if r.want.observeNoAsk == "deny" && !strings.Contains(noAsk.Reason, "observer guard approve") {
				t.Fatalf("headless deny does not name observer guard approve: %q", noAsk.Reason)
			}
		})
	}
}

// TestPushGateNamesTheHeldCommitAndRemote (lane sec-gate4 milestone 3a):
// the S-792 detail names the held commit the push's remote lacks and the
// remote; with no readable remote it says so; the advice names the push.
func TestPushGateNamesTheHeldCommitAndRemote(t *testing.T) {
	eng := secrules.GateEngineForTest(t, policy.ModeEnforce)
	st := secrules.HeldOnForTest("origin")
	v := eng.Evaluate(secrules.ShellEventForTest("git push backup main", true, st))
	if v.RuleID != "S-792" || !strings.Contains(v.Reason, "held by commit abababababab, not on remote backup yet") {
		t.Fatalf("push to backup = %+v", v)
	}
	v = eng.Evaluate(secrules.ShellEventForTest("git push", true, st))
	if v.RuleID != "S-792" || !strings.Contains(v.Reason, "held by commit abababababab, and this push's remote cannot be read off the command") {
		t.Fatalf("push with no remote = %+v", v)
	}
	// On a host that cannot ask, the deny leads with the `observer guard
	// approve` sentence, and the same reply names the held commit and the
	// remote.
	ev := secrules.ShellEventForTest("git push backup main", false, st)
	v = secrules.GateEngineForTest(t, policy.ModeObserve).Evaluate(ev)
	em := guard.ResolveEmission(v, ev.Caps)
	em = guard.ExplainDegradedAsk(em, guard.ActionVerdict{Verdict: v}, "s1")
	if em.Permission != "deny" || !strings.Contains(em.Reason, "observer guard approve S-792 --session s1") ||
		!strings.Contains(em.Reason, "held by commit abababababab, not on remote backup yet") {
		t.Fatalf("headless S-792 = %+v", em)
	}
	for _, r := range secrules.GateRules() {
		if r.ID == "S-792" && strings.HasPrefix(r.Doc, "agent push") && !strings.Contains(r.Advice, "approve this push") {
			t.Fatalf("S-792 advice = %q", r.Advice)
		}
		if r.ID == "S-791" && !strings.Contains(r.Advice, "approve this commit") {
			t.Fatalf("S-791 advice = %q", r.Advice)
		}
	}
}

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
		{"history-only hold, push to the remote that has it", "git push origin main", floor(*secrules.HeldOnForTest("origin")), "", gatetable.GateAllow},
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
					v := secrules.GateEngineForTest(t, mode).Evaluate(secrules.ShellEventForTest(r.cmd, canAsk, r.state))
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
	if v := secrules.GateEngineForTest(t, policy.ModeObserve).Evaluate(secrules.ShellEventForTest("git commit -m x", true, st)); v.RuleID != "S-794" || v.Decision != policy.DecisionAsk {
		t.Fatalf("an ask floor: %+v, want the individual S-794 ask", v)
	}
}
