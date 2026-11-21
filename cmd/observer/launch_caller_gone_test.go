//go:build !sbo_omit_terminals

package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/agentlaunch"
	"github.com/marmutapp/superbased-observer/internal/attachsock"
	"github.com/marmutapp/superbased-observer/internal/peerproc"
	"github.com/marmutapp/superbased-observer/internal/termrun"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// launch_caller_gone_test.go pins lane cli-2 fixes-3, audit M1, against the
// real confirm and launch checks: an attach caller that is no longer the
// process that connected (it exited, its pid was reused, or its start was
// never read) is refused a confirm and a launch, never judged by what its
// pid reads as now.

// helperWaitStdin is set in the environment of a helper child that waits
// until its stdin closes.
const helperWaitStdin = "OBSERVER_TEST_HELPER_WAIT_STDIN"

// TestHelperWaitForStdin is not a test: run as a child process with
// helperWaitStdin set, it waits until its stdin closes and exits.
func TestHelperWaitForStdin(t *testing.T) {
	if os.Getenv(helperWaitStdin) == "" {
		t.Skip("helper process only")
	}
	_, _ = io.Copy(io.Discard, os.Stdin)
}

// goneCaller starts a helper process, reads its start token while it runs,
// ends it and returns its pid and that token: a caller that connected and
// is gone.
func goneCaller(t *testing.T) (int, string) {
	t.Helper()
	if _, ok := peerproc.StartToken(os.Getpid()); !ok {
		t.Skip("no process start token on this platform")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperWaitForStdin$")
	cmd.Env = append(os.Environ(), helperWaitStdin+"=1")
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	tok, ok := peerproc.StartToken(cmd.Process.Pid)
	_ = in.Close()
	_ = cmd.Wait()
	if !ok {
		t.Fatal("no start token for a running helper")
	}
	return cmd.Process.Pid, tok
}

// callerCtx is a context as the attach endpoint leaves it for pid, with the
// start token it read at accept ("" none).
func callerCtx(pid int, start string) context.Context {
	return attachsock.WithCallerStart(attachsock.WithCallerPID(context.Background(), pid), start)
}

// TestConfirmRefusesACallerThatIsGone drives the real confirmer
// (launchConfirmer over the production readers) and the confirm op.
func TestConfirmRefusesACallerThatIsGone(t *testing.T) {
	pid, tok := goneCaller(t)
	self, _ := peerproc.StartToken(os.Getpid())
	confirm := launchConfirmer(withProcessReaders(launchInitiator{}))
	for _, tc := range []struct {
		name     string
		ctx      context.Context
		gone     bool
		wantRule string
	}{
		{"exited after connecting", callerCtx(pid, tok), true, "K0-caller-gone"},
		{"pid now names another process", callerCtx(os.Getpid(), tok), true, "K0-caller-gone"},
		{"start not read at connect", callerCtx(os.Getpid(), ""), true, "K0-caller-gone"},
		{"still the process that connected", callerCtx(os.Getpid(), self), false, ""},
	} {
		f := confirm(tc.ctx)
		if f.CallerGone != tc.gone || (tc.gone && f.GoneWhy == "") {
			t.Errorf("%s: facts = %+v, want gone %v", tc.name, f, tc.gone)
			continue
		}
		if !tc.gone {
			continue
		}
		if ok, why, rule := agentlaunch.MayConfirm(f); ok || rule != tc.wantRule || why == "" {
			t.Errorf("%s: MayConfirm = %v %q (%s), want refused by %s", tc.name, ok, why, rule, tc.wantRule)
		}
	}

	// The confirm op itself: refused, and the hold is not consumed.
	fk := newFakeTermsvc()
	c := fk.control(false)
	c.pending = newPendingLaunchStore()
	c.confirmer = confirm
	c.origin = func(context.Context, attachsock.LaunchSpec) (termrun.Origin, error) {
		return termrun.Origin{Initiator: termrun.InitiatorAgent, ParentSessionID: "sess-parent"}, nil
	}
	held, err := c.LaunchDetached(context.Background(), attachsock.LaunchSpec{Tool: "claude", Project: "/w"})
	if err != nil || held.State != attachsock.StatePending {
		t.Fatalf("hold = %+v %v", held, err)
	}
	_, err = c.ConfirmLaunch(callerCtx(pid, tok), held.PendingID)
	var ce *attachsock.ControlError
	if !errors.As(err, &ce) || ce.Code != agentlaunch.CodeConfirmRefused {
		t.Fatalf("a gone caller's confirm = %v, want %s", err, agentlaunch.CodeConfirmRefused)
	}
	if len(fk.specs) != 0 || len(c.pending.holds.List()) != 1 {
		t.Fatalf("a gone caller's confirm started (%d) or consumed the hold", len(fk.specs))
	}
}

// TestLaunchRefusesACallerThatIsGone: an `observer launch` and an attach
// launch whose caller is gone are refused with caller_gone, neither held
// nor run as a human's.
func TestLaunchRefusesACallerThatIsGone(t *testing.T) {
	pid, tok := goneCaller(t)
	li := withProcessReaders(launchInitiator{})
	ctx := callerCtx(pid, tok)

	fk := newFakeTermsvc()
	c := fk.control(false)
	c.pending = newPendingLaunchStore()
	c.origin = attachLaunchOrigin(li)
	_, err := c.LaunchDetached(ctx, attachsock.LaunchSpec{Tool: "claude", Project: "/w"})
	var ce *attachsock.ControlError
	if !errors.As(err, &ce) || ce.Code != agentlaunch.CodeCallerGone {
		t.Fatalf("a gone caller's launch = %v, want %s", err, agentlaunch.CodeCallerGone)
	}
	if len(fk.specs) != 0 || len(c.pending.holds.List()) != 0 {
		t.Fatalf("a gone caller's launch ran (%d) or was held", len(fk.specs))
	}
	if code := launchExitCodes[agentlaunch.CodeCallerGone]; code != launchExitUnavailable {
		t.Fatalf("caller_gone exits %d, want %d", code, launchExitUnavailable)
	}

	launcher := &fakeAttachLauncher{res: termsvc.LaunchResult{Handle: "H", RunID: "R"}}
	host := newAttachHost(launcher, successAttachMgr{}, nil).withPending(newPendingLaunchStore()).withOrigin(attachSpawnOrigin(li))
	_, err = host.LaunchAttachable(ctx, attachsock.SpawnRequest{Tool: "claude-code", Subcommand: "claude"})
	if !errors.As(err, &ce) || ce.Code != agentlaunch.CodeCallerGone || launcher.launchCalls != 0 {
		t.Fatalf("a gone caller's attach launch = %v (spawned %d), want %s", err, launcher.launchCalls, agentlaunch.CodeCallerGone)
	}
}

// TestSnapshotWidensTheChain: the ancestors and the marker read at accept
// count when the request is judged, though the caller's ancestry changed
// since (an intermediate ancestor exited and reparented it).
func TestSnapshotWidensTheChain(t *testing.T) {
	ancestry := map[int][]int{500: {400, 300}}
	markers := map[int]string{400: "sess-at-connect"}
	l := launchInitiator{
		ancestors: func(pid int) []int { return ancestry[pid] },
		envMarker: func(pids []int) (string, bool) {
			for _, p := range pids {
				if v, ok := markers[p]; ok {
					return v, true
				}
			}
			return "", false
		},
		liveSession: func(_ context.Context, pid int) (string, bool) {
			return "sess-bridge", pid == 300
		},
	}
	ctx := l.snapshotCaller(context.Background(), 500)
	// Since accept, 400 exited: 500 was reparented to init and 400's
	// environment can no longer be read.
	ancestry[500] = []int{1}
	delete(markers, 400)
	if got := l.origin(ctx, agentlaunch.FrontCLI, 500, false, ""); got != (termrun.Origin{Initiator: termrun.InitiatorAgent, ParentSessionID: "sess-bridge"}) {
		t.Fatalf("origin with the accept-time chain = %+v, want the agent ancestor 300", got)
	}
	l.liveSession = nil
	if got := l.origin(ctx, agentlaunch.FrontCLI, 500, false, ""); got != (termrun.Origin{Initiator: termrun.InitiatorAgent, ParentSessionID: "sess-at-connect"}) {
		t.Fatalf("origin with the accept-time marker = %+v", got)
	}
	// A snapshot of another pid is not used.
	if got := l.origin(ctx, agentlaunch.FrontCLI, 600, false, ""); got.Initiator != termrun.InitiatorHumanCLI {
		t.Fatalf("a snapshot leaked to pid 600: %+v", got)
	}
}
