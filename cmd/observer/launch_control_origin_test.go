//go:build !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/agentlaunch"
	"github.com/marmutapp/superbased-observer/internal/attachsock"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/termrun"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// TestLaunchControlRecordsOrigin pins lane cli-2 on the daemon side of
// `observer launch`: the resolved origin reaches the one launch path, the
// returned run, the live list and the history list, so a detached
// (headless) run reads who started it everywhere. An agent's launch is held
// first (fixes-1); a human's confirm starts it as the agent's.
func TestLaunchControlRecordsOrigin(t *testing.T) {
	f := newFakeTermsvc()
	c := f.control(false)
	c.pending = newPendingLaunchStore()
	c.confirmer = func(context.Context) agentlaunch.ConfirmFacts {
		return agentlaunch.ConfirmFacts{Origin: termrun.Origin{Initiator: termrun.InitiatorHumanCLI}}
	}
	var sawHint attachsock.LaunchSpec
	c.origin = func(_ context.Context, spec attachsock.LaunchSpec) (termrun.Origin, error) {
		sawHint = spec
		return termrun.Origin{Initiator: termrun.InitiatorAgent, ParentSessionID: "sess-parent"}, nil
	}
	held, err := c.LaunchDetached(context.Background(), attachsock.LaunchSpec{Tool: "claude", Project: "/w", AgentEnv: true, AgentEnvSession: "sess-env"})
	if err != nil || held.State != attachsock.StatePending || len(f.specs) != 0 {
		t.Fatalf("an agent's launch = %+v %v, specs %+v; want held", held, err, f.specs)
	}
	ri, err := c.ConfirmLaunch(context.Background(), held.PendingID)
	if err != nil {
		t.Fatalf("ConfirmLaunch: %v", err)
	}
	if !sawHint.AgentEnv || sawHint.AgentEnvSession != "sess-env" {
		t.Fatalf("the resolver did not see the client's hint: %+v", sawHint)
	}
	if len(f.specs) != 1 || f.specs[0].Initiator != "agent" || f.specs[0].ParentSessionID != "sess-parent" {
		t.Fatalf("launch spec = %+v", f.specs)
	}
	if ri.Initiator != "agent" || ri.ParentSessionID != "sess-parent" {
		t.Fatalf("returned run = %+v", ri)
	}
	ended := f.now.Add(-time.Hour)
	f.history = []store.TerminalRunSummary{{
		RunID: "run-old-0001", Tool: "codex", Kind: "fresh", LaunchedAt: f.now.Add(-2 * time.Hour), EndedAt: &ended,
		Initiator: "human_cli",
	}}
	runs, err := c.Runs(context.Background())
	if err != nil {
		t.Fatalf("Runs: %v", err)
	}
	got := map[string]attachsock.RunInfo{}
	for _, r := range runs {
		got[r.RunID] = r
	}
	if live := got["run-new-0001"]; live.Initiator != "agent" || live.ParentSessionID != "sess-parent" || live.State != attachsock.StateRunning {
		t.Fatalf("live headless run = %+v", live)
	}
	if hist := got["run-old-0001"]; hist.Initiator != "human_cli" || hist.State != attachsock.StateEnded {
		t.Fatalf("history run = %+v", hist)
	}

	// `observer terminals ls` shows who started each run and its parent.
	var out bytes.Buffer
	printRunTable(&out, runs)
	text := out.String()
	for _, want := range []string{"STARTED BY", "PARENT", "agent", "sess-parent", "you (cli)"} {
		if !strings.Contains(text, want) {
			t.Fatalf("terminals ls output lacks %q:\n%s", want, text)
		}
	}
	// `observer terminals show` too.
	out.Reset()
	printRun(launchOutput{stdout: &out}, got["run-new-0001"], false)
	if !strings.Contains(out.String(), "started by") || !strings.Contains(out.String(), "parent session") {
		t.Fatalf("terminals show output:\n%s", out.String())
	}
}

// TestAttachHostRecordsOrigin pins the attach launch's half (`observer
// <tool> --attach`): the resolver sees the endpoint's caller pid and the
// client's hint, and its origin reaches the terminal service's request.
func TestAttachHostRecordsOrigin(t *testing.T) {
	launcher := &fakeAttachLauncher{res: termsvc.LaunchResult{Handle: "H", RunID: "R"}}
	var sawPID int
	host := newAttachHost(launcher, successAttachMgr{}, nil).withOrigin(func(ctx context.Context, req attachsock.SpawnRequest) (termrun.Origin, error) {
		sawPID, _ = attachsock.CallerPID(ctx)
		if !req.AgentEnv || req.AgentEnvSession != "sess-env" {
			t.Errorf("the resolver did not see the client's hint: %+v", req)
		}
		return termrun.Origin{Initiator: termrun.InitiatorHumanCLI}, nil
	})
	ctx := attachsock.WithCallerPID(context.Background(), 4242)
	if _, err := host.LaunchAttachable(ctx, attachsock.SpawnRequest{Tool: "claude-code", Subcommand: "claude", AgentEnv: true, AgentEnvSession: "sess-env"}); err != nil {
		t.Fatalf("LaunchAttachable: %v", err)
	}
	if sawPID != 4242 {
		t.Fatalf("resolver saw caller pid %d, want 4242", sawPID)
	}
	if got := launcher.lastReq.Origin; got != (termrun.Origin{Initiator: termrun.InitiatorHumanCLI}) {
		t.Fatalf("attach request origin = %+v", got)
	}
}
