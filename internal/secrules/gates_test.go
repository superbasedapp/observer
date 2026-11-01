package secrules

import (
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

func gateEngine(t *testing.T, mode policy.Mode) *policy.Engine {
	t.Helper()
	eng, err := policy.New(policy.Config{Mode: mode, Home: "/home/u", ExtraRules: GateRules()})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	return eng
}

func shellEvent(cmd string, canAsk bool, st *policy.Security) policy.Event {
	return policy.Event{
		Security: st,
		Kind:     policy.KindShellExec, ActionType: "run_command", Target: cmd,
		Cwd: "/r", ProjectRoot: "/r", SessionID: "s1",
		Caps: policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: canAsk},
		Now:  time.Unix(1, 0),
	}
}

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
		{"history-only hold, push to the remote that has it", "git push origin main", heldOn("origin"), "", cell{"allow", "allow", "allow"}},
		{"history-only hold, push -u to the remote that has it", "git push -u origin feature", heldOn("origin"), "", cell{"allow", "allow", "allow"}},
		{"history-only hold, push to the other remote S-792", "git push backup main", heldOn("origin"), "S-792", cell{"ask", "deny", "deny"}},
		{"history-only hold, push with no remote S-792", "git push", heldOn("origin"), "S-792", cell{"ask", "deny", "deny"}},
		{"history-only hold, push to a URL S-792", "git push https://example.invalid/r.git main", heldOn("origin"), "S-792", cell{"ask", "deny", "deny"}},
		{"history-only hold, push --all S-792", "git push --all origin", heldOn("origin"), "S-792", cell{"ask", "deny", "deny"}},
		{"history-only hold, push in another repository S-792", "git -C ../other push origin main", heldOn("origin"), "S-792", cell{"ask", "deny", "deny"}},
		{"history-only hold and one in the tree, push to the remote S-792", "git push origin main", &policy.Security{
			Posture: policy.SecurityPostureBlocking, Blocking: 2, BlockingHistoryOnly: 1, BlockingHistoryOnlyOn: map[string]int{"origin": 1},
		}, "S-792", cell{"ask", "deny", "deny"}},
		{"history-only hold, capped list, commit S-791", "git commit -m x", &policy.Security{Posture: policy.SecurityPostureBlocking, Blocking: 1, BlockingHistoryOnly: 1, Overflow: true}, "S-791", cell{"ask", "deny", "deny"}},
		// Audit finding 5: a plain push goes to the signed default push
		// remote; audit finding 3: a command line that may change where the
		// push goes is an unknown target.
		{"history-only hold, plain push to the default that has it", "git push", heldOnDefault("origin", "origin"), "", cell{"allow", "allow", "allow"}},
		{"history-only hold, plain push to a default that lacks it S-792", "git push", heldOnDefault("origin", "upstream"), "S-792", cell{"ask", "deny", "deny"}},
		{"history-only hold, push upstream with origin the default S-792", "git push upstream main", heldOnDefault("origin", "origin"), "S-792", cell{"ask", "deny", "deny"}},
		{"history-only hold, plain push with a -c override S-792", "git -c branch.main.pushRemote=upstream push", heldOnDefault("origin", "origin"), "S-792", cell{"ask", "deny", "deny"}},
		{"history-only hold, -c pushurl S-792", "git -c remote.origin.pushurl=/tmp/x push origin main", heldOn("origin"), "S-792", cell{"ask", "deny", "deny"}},
		{"history-only hold, GIT_CONFIG_COUNT S-792", "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=remote.origin.pushurl GIT_CONFIG_VALUE_0=/tmp/x git push origin main", heldOn("origin"), "S-792", cell{"ask", "deny", "deny"}},
		// Audit finding 3: a write to the remote-tracking state while the
		// posture is blocking.
		{"history-only hold, update-ref a tracking ref S-792", "git update-ref refs/remotes/backup/x HEAD", heldOn("origin"), "S-792", cell{"ask", "deny", "deny"}},
		{"history-only hold, fetch . into a tracking ref S-792", "git fetch . HEAD:refs/remotes/backup/x", heldOn("origin"), "S-792", cell{"ask", "deny", "deny"}},
		{"history-only hold, remote set-url S-792", "git remote set-url backup /tmp/x", heldOn("origin"), "S-792", cell{"ask", "deny", "deny"}},
		{"history-only hold, redirect into a tracking ref S-792", "echo 0 > .git/refs/remotes/backup/main", heldOn("origin"), "S-792", cell{"ask", "deny", "deny"}},
		{"history-only hold, plain fetch", "git fetch origin", heldOn("origin"), "", cell{"allow", "allow", "allow"}},
		{"clean, update-ref a tracking ref", "git update-ref refs/remotes/backup/x HEAD", &policy.Security{Posture: policy.SecurityPostureClean}, "", cell{"allow", "allow", "allow"}},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			emit := func(mode policy.Mode, canAsk bool) (string, policy.Verdict, guard.Emission) {
				v := gateEngine(t, mode).Evaluate(shellEvent(r.cmd, canAsk, r.state))
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

// heldOn is a posture with one history-only finding the named remote
// already has.
func heldOn(remote string) *policy.Security {
	return &policy.Security{
		Posture: policy.SecurityPostureBlocking, Blocking: 1, BlockingHistoryOnly: 1,
		BlockingHistoryOnlyOn: map[string]int{remote: 1},
		HeldCommits:           []policy.HeldCommit{{Commit: strings.Repeat("ab", 20), Remotes: []string{remote}}},
	}
}

// heldOnDefault is heldOn with the signed default push remote.
func heldOnDefault(remote, def string) *policy.Security {
	s := heldOn(remote)
	s.DefaultPushRemote = def
	return s
}

// TestRemoteStateGateFileWrites (audit finding 3): the Write and Edit
// tools' writes into the remote-tracking state are S-792's while the
// posture is blocking: it asks in observe mode (R-114, which denies writes
// to git's own files in enforce, only flags there), and in enforce the
// write is denied.
func TestRemoteStateGateFileWrites(t *testing.T) {
	eng := gateEngine(t, policy.ModeObserve)
	enf := gateEngine(t, policy.ModeEnforce)
	for _, tc := range []struct {
		action, path string
		want         string
	}{
		{"write_file", "/r/.git/refs/remotes/backup/main", "S-792"},
		{"edit_file", "/r/.git/config", "S-792"},
		{"write_file", "/r/.git/packed-refs", "S-792"},
		{"read_file", "/r/.git/config", ""},
	} {
		ev := policy.Event{
			Security: heldOn("origin"), Kind: policy.KindFileAccess, ActionType: tc.action, Target: tc.path,
			Cwd: "/r", ProjectRoot: "/r", SessionID: "s1",
			Caps: policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: true}, Now: time.Unix(1, 0),
		}
		v := eng.Evaluate(ev)
		if tc.want == "" {
			if v.RuleID == "S-792" {
				t.Fatalf("%s %s = %+v, want no S-792", tc.action, tc.path, v)
			}
			continue
		}
		if v.RuleID != tc.want || v.Decision != policy.DecisionAsk {
			t.Fatalf("observe %s %s = %+v, want %s ask", tc.action, tc.path, v, tc.want)
		}
		if v := enf.Evaluate(ev); v.Decision != policy.DecisionDeny {
			t.Fatalf("enforce %s %s = %+v, want deny", tc.action, tc.path, v)
		}
	}
}

// TestPushGateNamesTheHeldCommitAndRemote (lane sec-gate4 milestone 3a):
// the S-792 detail names the held commit the push's remote lacks and the
// remote; with no readable remote it says so; the advice names the push.
func TestPushGateNamesTheHeldCommitAndRemote(t *testing.T) {
	eng := gateEngine(t, policy.ModeEnforce)
	st := heldOn("origin")
	v := eng.Evaluate(shellEvent("git push backup main", true, st))
	if v.RuleID != "S-792" || !strings.Contains(v.Reason, "held by commit abababababab, not on remote backup yet") {
		t.Fatalf("push to backup = %+v", v)
	}
	v = eng.Evaluate(shellEvent("git push", true, st))
	if v.RuleID != "S-792" || !strings.Contains(v.Reason, "held by commit abababababab, and this push's remote cannot be read off the command") {
		t.Fatalf("push with no remote = %+v", v)
	}
	// On a host that cannot ask, the deny leads with the `observer guard
	// approve` sentence, and the same reply names the held commit and the
	// remote.
	ev := shellEvent("git push backup main", false, st)
	v = gateEngine(t, policy.ModeObserve).Evaluate(ev)
	em := guard.ResolveEmission(v, ev.Caps)
	em = guard.ExplainDegradedAsk(em, guard.ActionVerdict{Verdict: v}, "s1")
	if em.Permission != "deny" || !strings.Contains(em.Reason, "observer guard approve S-792 --session s1") ||
		!strings.Contains(em.Reason, "held by commit abababababab, not on remote backup yet") {
		t.Fatalf("headless S-792 = %+v", em)
	}
	for _, r := range GateRules() {
		if r.ID == "S-792" && strings.HasPrefix(r.Doc, "agent push") && !strings.Contains(r.Advice, "approve this push") {
			t.Fatalf("S-792 advice = %q", r.Advice)
		}
		if r.ID == "S-791" && !strings.Contains(r.Advice, "approve this commit") {
			t.Fatalf("S-791 advice = %q", r.Advice)
		}
	}
}

// TestCommitGateRewordings: rewordings of one denied commit reach the
// same rule (the classifier keys on the parsed intent).
func TestCommitGateRewordings(t *testing.T) {
	eng := gateEngine(t, policy.ModeEnforce)
	st := &policy.Security{Posture: policy.SecurityPostureBlocking}
	for _, cmd := range []string{
		`git commit -m "wip"`,
		`git -c user.name=x commit --message="try again"`,
		`bash -c 'git commit -qm third'`,
		`git config alias.c commit && git c -m four`,
	} {
		if v := eng.Evaluate(shellEvent(cmd, true, st)); v.RuleID != "S-791" || v.Decision != policy.DecisionDeny {
			t.Errorf("%q = %+v, want S-791 deny", cmd, v)
		}
	}
}

// TestCommitGateMCP: an MCP commit tool reaches the gate.
func TestCommitGateMCP(t *testing.T) {
	eng := gateEngine(t, policy.ModeEnforce)
	ev := policy.Event{Security: &policy.Security{Posture: policy.SecurityPostureUnknown}, Kind: policy.KindMCPCall, ActionType: "mcp_call", Target: "mcp__github__push_files", Now: time.Unix(1, 0)}
	if v := eng.Evaluate(ev); v.RuleID != "S-794" {
		t.Fatalf("mcp = %+v", v)
	}
}

// TestCommitGateWithoutSecurity: an event the seam did not fill (the
// module inactive) matches nothing; a filled event with no posture is
// unknown, never clean.
func TestCommitGateWithoutSecurity(t *testing.T) {
	eng := gateEngine(t, policy.ModeEnforce)
	if v := eng.Evaluate(shellEvent("git commit -m x", true, nil)); v.RuleID != "" {
		t.Fatalf("no Security = %+v, want no match", v)
	}
	if v := eng.Evaluate(shellEvent("git commit -m x", true, &policy.Security{})); v.RuleID != "S-794" {
		t.Fatalf("zero posture = %+v, want S-794", v)
	}
}

// TestRuleIDsInPillarRanges pins every row to its section 4.7 range.
func TestRuleIDsInPillarRanges(t *testing.T) {
	all := append(GateRules(), SecretRules()...)
	for _, r := range all {
		switch {
		case r.ID >= "S-721" && r.ID <= "S-739":
		case r.ID >= "S-791" && r.ID <= "S-799":
		default:
			t.Errorf("rule %s outside its range", r.ID)
		}
		if r.Source != policy.SourcePackSecurity {
			t.Errorf("rule %s source %q", r.ID, r.Source)
		}
	}
}
