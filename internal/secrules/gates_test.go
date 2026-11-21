package secrules

import (
	"strings"
	"testing"
	"time"

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
