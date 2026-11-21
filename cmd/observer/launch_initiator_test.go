//go:build !sbo_omit_terminals

package main

import (
	"context"
	"os"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/agentlaunch"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/peerproc"
	"github.com/marmutapp/superbased-observer/internal/termrun"
)

// TestLaunchInitiatorFacts walks the resolver's I/O half with fakes: the
// nearest live agent wins, a daemon terminal's run gives its correlated
// session, the bridge gives its row's session, an unidentified caller is
// judged by its hint alone.
func TestLaunchInitiatorFacts(t *testing.T) {
	// Process tree: 500 (observer launch) <- 400 (shell) <- 300 (agent A,
	// a daemon terminal's child) <- 200 (agent B, bridged) <- 1.
	tree := map[int][]int{500: {400, 300, 200, 1}, 400: {300, 200, 1}, 600: {1}}
	l := launchInitiator{
		ancestors:  func(pid int) []int { return tree[pid] },
		agentRoots: func() map[int]string { return map[int]string{300: "run-a"} },
		sessionFor: func(run string) (string, bool) { return map[string]string{"run-a": "sess-a"}[run], run == "run-a" },
		liveSession: func(_ context.Context, pid int) (string, bool) {
			return map[int]string{200: "sess-b"}[pid], pid == 200
		},
	}
	ctx := context.Background()
	for _, tc := range []struct {
		name       string
		front      agentlaunch.Front
		pid        int
		env        bool
		envSession string
		want       termrun.Origin
	}{
		{"nearest agent is the daemon terminal", agentlaunch.FrontCLI, 500, false, "", termrun.Origin{Initiator: termrun.InitiatorAgent, ParentSessionID: "sess-a"}},
		{"no agent above", agentlaunch.FrontCLI, 600, false, "", termrun.Origin{Initiator: termrun.InitiatorHumanCLI}},
		{"dashboard caller with no agent above", agentlaunch.FrontDashboard, 600, false, "", termrun.Origin{Initiator: termrun.InitiatorHumanDashboard}},
		{"unidentified caller with a marker", agentlaunch.FrontCLI, 0, true, "sess-env", termrun.Origin{Initiator: termrun.InitiatorAgent, ParentSessionID: "sess-env"}},
		{"unidentified caller without a marker is unknown, never a human", agentlaunch.FrontCLI, 0, false, "", termrun.Origin{Initiator: termrun.InitiatorUnknown}},
		{"the caller itself is bridged", agentlaunch.FrontDashboard, 200, false, "", termrun.Origin{Initiator: termrun.InitiatorAgent, ParentSessionID: "sess-b"}},
	} {
		if got := l.origin(ctx, tc.front, tc.pid, tc.env, tc.envSession); got != tc.want {
			t.Errorf("%s: origin = %+v, want %+v", tc.name, got, tc.want)
		}
	}
	// A daemon terminal with no correlated session yet: still the agent's.
	l.sessionFor = func(string) (string, bool) { return "", false }
	if got := l.origin(ctx, agentlaunch.FrontCLI, 500, false, ""); got != (termrun.Origin{Initiator: termrun.InitiatorAgent}) {
		t.Errorf("uncorrelated agent terminal: origin = %+v", got)
	}
}

// TestAgentRootsOf pins which daemon terminals count as an agent's: a live,
// non-setup run of a registry tool with a child pid; never the plain shell.
func TestAgentRootsOf(t *testing.T) {
	snap := []dashapi.LaunchInfo{
		{ID: "h-agent", RunID: "run-agent", Tool: "claude-code"},
		{ID: "h-shell", RunID: "run-shell", Tool: "shell"},
		{ID: "h-exited", RunID: "run-exited", Tool: "codex", Exited: true},
		{ID: "h-setup", RunID: "run-setup", Tool: "codex", Setup: true},
		{ID: "h-norun", Tool: "codex"},
		{ID: "h-nopid", RunID: "run-nopid", Tool: "codex"},
	}
	pids := map[string]int{"h-agent": 10, "h-shell": 11, "h-exited": 12, "h-setup": 13, "h-norun": 14}
	got := agentRootsOf(snap, func(h string) (int, bool) { p, ok := pids[h]; return p, ok })
	if len(got) != 1 || got[10] != "run-agent" {
		t.Fatalf("agentRootsOf = %v, want only pid 10 -> run-agent", got)
	}
}

// TestAgentSessionEnv reads only the allowlisted marker.
func TestAgentSessionEnv(t *testing.T) {
	env := map[string]string{"CLAUDE_CODE_SESSION_ID": "sess-1", "CLAUDECODE": "1"}
	if ok, id := agentSessionEnv(func(k string) string { return env[k] }); !ok || id != "sess-1" {
		t.Fatalf("agentSessionEnv = %v %q", ok, id)
	}
	if ok, _ := agentSessionEnv(func(string) string { return "" }); ok {
		t.Fatal("an empty environment reported a marker")
	}
}

// TestLaunchInitiatorRealAncestry runs the resolver over this process's
// real ancestry (peerproc.Ancestors): a bridge row for this test's parent
// process makes a launch from this process an agent's.
func TestLaunchInitiatorRealAncestry(t *testing.T) {
	if !peerproc.Supported() {
		t.Skip("no ancestry lookup on this platform")
	}
	parent := os.Getppid()
	l := launchInitiator{
		ancestors: peerproc.Ancestors,
		liveSession: func(_ context.Context, pid int) (string, bool) {
			return "sess-parent", pid == parent
		},
	}
	got := l.origin(context.Background(), agentlaunch.FrontCLI, os.Getpid(), false, "")
	if got != (termrun.Origin{Initiator: termrun.InitiatorAgent, ParentSessionID: "sess-parent"}) {
		t.Fatalf("origin over the real ancestry = %+v", got)
	}
}

// TestInitiatorVocabularyMatches pins the dashboard's copy of the default
// initiator to internal/termrun's closed set (the dashboard compiles
// without termrun, so it cannot import it).
func TestInitiatorVocabularyMatches(t *testing.T) {
	for _, pair := range [][2]string{
		{dashapi.InitiatorHumanDashboard, string(termrun.InitiatorHumanDashboard)},
		{dashapi.InitiatorAgent, string(termrun.InitiatorAgent)},
		{dashapi.InitiatorUnknown, string(termrun.InitiatorUnknown)},
		// The pending codes the dashboard maps (lane cli-2 fixes-1).
		{dashapi.PendingCodeConfirmRequired, agentlaunch.CodeConfirmRequired},
		{dashapi.PendingCodeTooMany, agentlaunch.CodeTooManyPending},
		{dashapi.PendingCodeNotFound, agentlaunch.CodePendingNotFound},
		{dashapi.PendingCodeConfirmRefused, agentlaunch.CodeConfirmRefused},
	} {
		if pair[0] != pair[1] {
			t.Errorf("dashapi %q != %q", pair[0], pair[1])
		}
	}
}
