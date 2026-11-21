//go:build !sbo_omit_terminals && !windows

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/agentlaunch"
	"github.com/marmutapp/superbased-observer/internal/attachsock"
	"github.com/marmutapp/superbased-observer/internal/localipc"
	"github.com/marmutapp/superbased-observer/internal/termrun"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// agentCallerDaemon serves the attach endpoint like serveFakeDaemon, with
// the launch control's attribution replaced by a switch: while agent is
// true the caller (this test process, over the real socket) is an agent's.
// The hold store, the confirm rule and the control ops are the real ones.
func agentCallerDaemon(t *testing.T, f *fakeTermsvc, agent *atomic.Bool) *launchControl {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := localipc.Endpoint(filepath.Join(dir, "observer.db"))
	if err != nil {
		t.Skipf("no attach endpoint here: %v", err)
	}
	ln, err := localipc.ListenSocket(endpoint)
	if err != nil {
		t.Skipf("cannot listen on the attach endpoint: %v", err)
	}
	origin := func() termrun.Origin {
		if agent.Load() {
			return termrun.Origin{Initiator: termrun.InitiatorAgent, ParentSessionID: "sess-parent"}
		}
		return termrun.Origin{Initiator: termrun.InitiatorHumanCLI}
	}
	c := f.control(true)
	c.pending = newPendingLaunchStore()
	c.origin = func(context.Context, attachsock.LaunchSpec) (termrun.Origin, error) { return origin(), nil }
	c.confirmer = func(context.Context) agentlaunch.ConfirmFacts { return agentlaunch.ConfirmFacts{Origin: origin()} }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	host := newAttachHost(nil, nil, nil).withControl(c)
	go func() {
		defer close(done)
		_ = attachsock.Serve(ctx, ln, host, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	}()
	old := controlCall
	controlCall = func(ctx context.Context, _ string, req attachsock.ControlRequest) (attachsock.ControlResult, error) {
		return attachsock.ControlCall(ctx, endpoint, req)
	}
	t.Cleanup(func() {
		controlCall = old
		cancel()
		_ = ln.Close()
		<-done
	})
	return c
}

// TestAgentLaunchIsHeldUntilAHumanConfirms is the end-to-end pin of the
// plans orchestrator's ruling on audit M2: over the real attach socket, an
// agent's `observer launch` starts nothing and exits 6 naming the hold; an
// agent's confirm is refused and leaves the hold; a human's confirm starts
// exactly that launch once, recording the agent; a second confirm finds
// nothing.
func TestAgentLaunchIsHeldUntilAHumanConfirms(t *testing.T) {
	requireTerminalsActive(t)
	f := newFakeTermsvc()
	f.probe = liveProbe()
	var agent atomic.Bool
	agent.Store(true)
	agentCallerDaemon(t, f, &agent)

	out, errb, code := runVerb(t, "launch", "claude", "--project", "/home/dev/repo", "--detach", "--json")
	if code != launchExitPending {
		t.Fatalf("an agent's launch exit %d, want %d (stdout %q, stderr %q)", code, launchExitPending, out, errb)
	}
	var held attachsock.RunInfo
	if err := json.Unmarshal([]byte(out), &held); err != nil || held.State != attachsock.StatePending || !strings.HasPrefix(held.PendingID, "pend-") || held.Initiator != "agent" {
		t.Fatalf("held run = %+v (%v)", held, err)
	}
	if len(f.specs) != 0 {
		t.Fatalf("an agent's launch started before any confirm: %+v", f.specs)
	}
	// Without --json the human line names the confirm command.
	_, errb, code = runVerb(t, "launch", "claude", "--project", "/home/dev/repo")
	if code != launchExitPending || !strings.Contains(errb, "observer terminals confirm pend-") {
		t.Fatalf("text pending output: exit %d, stderr %q", code, errb)
	}
	// `terminals ls` shows the holds first.
	out, _, _ = runVerb(t, "terminals", "ls")
	if !strings.Contains(out, held.PendingID) || !strings.Contains(out, attachsock.StatePending) {
		t.Fatalf("terminals ls does not list the hold:\n%s", out)
	}

	// An agent may not confirm; the hold stays.
	_, errb, code = runVerb(t, "terminals", "confirm", held.PendingID, "--json")
	if code != launchExitUnavailable || len(f.specs) != 0 {
		t.Fatalf("an agent's confirm: exit %d, stderr %q, specs %+v", code, errb, f.specs)
	}

	// A human's confirm starts it once, as the agent's launch.
	agent.Store(false)
	out, errb, code = runVerb(t, "terminals", "confirm", held.PendingID, "--json")
	if code != 0 {
		t.Fatalf("a human's confirm: exit %d, stderr %q", code, errb)
	}
	if len(f.specs) != 1 || f.specs[0].Initiator != "agent" || f.specs[0].ParentSessionID != "sess-parent" || f.specs[0].Tool != "claude-code" {
		t.Fatalf("confirmed launch spec = %+v", f.specs)
	}
	var started attachsock.RunInfo
	if err := json.Unmarshal([]byte(out), &started); err != nil || started.RunID != "run-new-0001" || started.State != attachsock.StateRunning {
		t.Fatalf("confirmed run = %+v (%v)", started, err)
	}
	if _, _, code = runVerb(t, "terminals", "confirm", held.PendingID); code != launchExitUnavailable || len(f.specs) != 1 {
		t.Fatalf("a second confirm: exit %d, specs %d (single use)", code, len(f.specs))
	}

	// The second hold (the text launch above) can be rejected.
	out, _, _ = runVerb(t, "terminals", "ls", "--json")
	var list struct {
		Runs []attachsock.RunInfo `json:"runs"`
	}
	_ = json.Unmarshal([]byte(out), &list)
	var second string
	for _, r := range list.Runs {
		if r.State == attachsock.StatePending {
			second = r.PendingID
		}
	}
	if second == "" {
		t.Fatalf("the second hold is not listed: %s", out)
	}
	if _, errb, code = runVerb(t, "terminals", "reject", second); code != 0 {
		t.Fatalf("reject: exit %d %q", code, errb)
	}
	if _, _, code = runVerb(t, "terminals", "confirm", second); code != launchExitUnavailable || len(f.specs) != 1 {
		t.Fatalf("a rejected hold was confirmed: exit %d", code)
	}
}

// TestAgentAttachLaunchIsHeld pins the attach spawn's half: an agent's
// `observer <tool> --attach` spawns nothing and is refused with
// confirm_required naming the hold; a human's confirm starts that request.
func TestAgentAttachLaunchIsHeld(t *testing.T) {
	launcher := &fakeAttachLauncher{res: termsvc.LaunchResult{Handle: "H", RunID: "R"}}
	store := newPendingLaunchStore()
	old := detachConfirmedAttach
	detached := 0
	detachConfirmedAttach = func(attachsock.Session) { detached++ }
	defer func() { detachConfirmedAttach = old }()
	host := newAttachHost(launcher, successAttachMgr{}, nil).withPending(store).withOrigin(func(context.Context, attachsock.SpawnRequest) (termrun.Origin, error) {
		return termrun.Origin{Initiator: termrun.InitiatorAgent, ParentSessionID: "sess-parent"}, nil
	})
	_, err := host.LaunchAttachable(context.Background(), attachsock.SpawnRequest{Tool: "claude-code", Subcommand: "claude", Dir: "/w"})
	var ce *attachsock.ControlError
	if !errors.As(err, &ce) || ce.Code != agentlaunch.CodeConfirmRequired || !strings.Contains(ce.Message, "observer terminals confirm pend-") {
		t.Fatalf("an agent's attach launch = %v, want confirm_required", err)
	}
	if launcher.launchCalls != 0 {
		t.Fatalf("an agent's attach launch spawned %d times before a confirm", launcher.launchCalls)
	}
	holds := store.holds.List()
	if len(holds) != 1 {
		t.Fatalf("holds = %+v", holds)
	}
	held, out, err := store.confirm(context.Background(), holds[0].ID, agentlaunch.ConfirmFacts{Origin: termrun.Origin{Initiator: termrun.InitiatorHumanCLI}})
	if err != nil || out.run == nil || out.run.RunID != "R" || held.Tool != "claude-code" {
		t.Fatalf("confirm = %+v %+v %v", held, out.run, err)
	}
	if launcher.launchCalls != 1 || launcher.lastReq.Origin.Initiator != termrun.InitiatorAgent || launcher.lastReq.Origin.ParentSessionID != "sess-parent" {
		t.Fatalf("confirmed attach launch: calls %d, origin %+v", launcher.launchCalls, launcher.lastReq.Origin)
	}
	if detached != 1 {
		t.Fatalf("the confirmed attach launch was detached %d times, want 1 (no client is attached)", detached)
	}
}
