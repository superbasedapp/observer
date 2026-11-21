//go:build !sbo_omit_terminals

package main

import (
	"context"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/agentlaunch"
	"github.com/marmutapp/superbased-observer/internal/procmodel"
	"github.com/marmutapp/superbased-observer/internal/termrun"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// TestDashboardChildrenDropTheDaemonsAgentMarker pins lane cli-2 fixes-3,
// audit L4: a daemon started from an agent's shell carries that agent's
// session marker, and no child it spawns for the dashboard (a terminal,
// sandboxed or not, a GUI launch, a setup session) inherits it, nor gets
// it from a caller's extra environment; every other variable still passes.
func TestDashboardChildrenDropTheDaemonsAgentMarker(t *testing.T) {
	for _, k := range procmodel.SessionTokenEnvKeys {
		t.Setenv(k, "sess-of-the-daemons-shell")
	}
	t.Setenv("SBO_TEST_KEEP_ME", "kept")
	marker := procmodel.SessionTokenEnvKeys[0]
	envs := map[string][]string{
		"terminal":           launchChildEnv(termsvc.LaunchRequest{Tool: "claude-code", RunID: "run-1", ExtraEnv: []string{marker + "=sess-from-the-caller"}}, "tok"),
		"sandboxed terminal": launchChildEnv(termsvc.LaunchRequest{Tool: "claude-code", RunID: "run-2", Sandboxed: true}, "tok"),
		"gui":                guiChildEnv([]string{"SBO_TEST_WRAP=1"}),
		"setup":              setupChildEnv(),
	}
	for name, env := range envs {
		kept := false
		for _, kv := range env {
			if isAgentSessionMarkerEnv(kv) {
				t.Errorf("%s child env carries the agent marker %q", name, kv)
			}
			if kv == "SBO_TEST_KEEP_ME=kept" {
				kept = true
			}
		}
		if !kept {
			t.Errorf("%s child env dropped an ordinary variable", name)
		}
	}
	cases := []struct {
		kv   string
		want bool
	}{
		{marker + "=x", true},
		{marker + "=", true},
		{marker + "_OTHER=x", false},
		{"X" + marker + "=x", false},
		{strings.ToLower(marker) + "=x", runtime.GOOS == "windows"},
		{"PATH=/bin", false},
		{"noequals", false},
	}
	for _, tc := range cases {
		if got := isAgentSessionMarkerEnv(tc.kv); got != tc.want {
			t.Errorf("isAgentSessionMarkerEnv(%q) = %v, want %v", tc.kv, got, tc.want)
		}
	}
}

// TestDaemonJudgesTheChainUpToItself: the daemon's resolver stops at its
// own pid, so the agent whose shell started the daemon (its marker in the
// daemon's environment, its live session above the daemon) does not make a
// human's process in a dashboard terminal an agent's, while a daemon
// terminal running an agent is still found below the daemon.
func TestDaemonJudgesTheChainUpToItself(t *testing.T) {
	const caller, shell, daemon, agentShell = 900, 800, 700, 600
	l := launchInitiator{
		ancestors: func(pid int) []int {
			return map[int][]int{caller: {shell, daemon, agentShell, 1}}[pid]
		},
		envMarker: func(pids []int) (string, bool) {
			for _, p := range pids {
				if p == daemon || p == agentShell {
					return "sess-that-started-the-daemon", true
				}
			}
			return "", false
		},
		liveSession: func(_ context.Context, pid int) (string, bool) { return "sess-bridge", pid == agentShell },
		daemonPID:   daemon,
	}
	ctx := context.Background()
	if got := l.origin(ctx, agentlaunch.FrontCLI, caller, false, ""); got.Initiator != termrun.InitiatorHumanCLI {
		t.Fatalf("a human in a dashboard terminal = %+v, want human_cli", got)
	}
	if got := l.origin(l.snapshotCaller(ctx, caller), agentlaunch.FrontCLI, caller, false, ""); got.Initiator != termrun.InitiatorHumanCLI {
		t.Fatalf("with the accept-time snapshot = %+v, want human_cli", got)
	}
	// Not under the daemon: the whole chain is judged.
	whole := l
	whole.daemonPID = 0
	if got := whole.origin(ctx, agentlaunch.FrontCLI, caller, false, ""); got.Initiator != termrun.InitiatorAgent {
		t.Fatalf("the whole chain = %+v, want agent", got)
	}
	// A daemon terminal running an agent is below the daemon.
	l.agentRoots = func() map[int]string { return map[int]string{shell: "run-agent"} }
	if got := l.origin(ctx, agentlaunch.FrontCLI, caller, false, ""); got.Initiator != termrun.InitiatorAgent {
		t.Fatalf("a daemon terminal's agent = %+v, want agent", got)
	}
	// The client's own hint still counts.
	l.agentRoots = nil
	if got := l.origin(ctx, agentlaunch.FrontCLI, caller, true, "sess-hint"); got != (termrun.Origin{Initiator: termrun.InitiatorAgent, ParentSessionID: "sess-hint"}) {
		t.Fatalf("a hinted caller = %+v", got)
	}
}
