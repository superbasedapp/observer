//go:build linux && !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/agentlaunch"
	"github.com/marmutapp/superbased-observer/internal/attachsock"
	"github.com/marmutapp/superbased-observer/internal/localipc"
	"github.com/marmutapp/superbased-observer/internal/peerproc"
	"github.com/marmutapp/superbased-observer/internal/termrun"
)

// launch_confirm_gone_linux_test.go pins lane cli-2 fixes-3, audit M1, over
// the real attach socket: a process connects, hands the connection to a
// child it starts, and exits; the child sends the confirm. The endpoint
// recorded the parent's pid, whose ancestry and environment are gone, so
// before the fix the confirm read as a human's and was allowed.

// Helper roles, set in the helper's environment.
const (
	helperForkRole     = "OBSERVER_TEST_HELPER_FORK_ROLE"
	helperForkEndpoint = "OBSERVER_TEST_HELPER_FORK_ENDPOINT"
	helperForkHold     = "OBSERVER_TEST_HELPER_FORK_HOLD"
	helperForkParent   = "OBSERVER_TEST_HELPER_FORK_PARENT"
)

// TestHelperForkConfirm is not a test. Role "parent" dials the endpoint,
// starts itself as role "child" holding the connection, and exits at once.
// Role "child" waits until the parent is gone, then sends the confirm over
// the inherited connection and prints the outcome. Role "direct" dials and
// confirms from its own process.
func TestHelperForkConfirm(t *testing.T) {
	role := os.Getenv(helperForkRole)
	if role == "" {
		t.Skip("helper process only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	req := attachsock.ControlRequest{Op: "confirm", Run: os.Getenv(helperForkHold)}
	switch role {
	case "parent":
		conn, err := attachsock.Dial(os.Getenv(helperForkEndpoint))
		if err != nil {
			fmt.Println("outcome=dial-error", err)
			return
		}
		f, err := conn.(*net.UnixConn).File()
		if err != nil {
			fmt.Println("outcome=file-error", err)
			return
		}
		child := exec.Command(os.Args[0], "-test.run=^TestHelperForkConfirm$")
		child.Env = append(os.Environ(), helperForkRole+"=child", helperForkParent+"="+strconv.Itoa(os.Getpid()))
		child.ExtraFiles = []*os.File{f}
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		if err := child.Start(); err != nil {
			fmt.Println("outcome=start-error", err)
		}
		// Exit without waiting: the child carries the connection on.
	case "child":
		parent, _ := strconv.Atoi(os.Getenv(helperForkParent))
		for os.Getppid() == parent && ctx.Err() == nil {
			time.Sleep(10 * time.Millisecond)
		}
		conn, err := net.FileConn(os.NewFile(3, "attach"))
		if err != nil {
			fmt.Println("outcome=fileconn-error", err)
			return
		}
		printOutcome(attachsock.ControlOn(ctx, conn, req))
	case "direct":
		printOutcome(attachsock.ControlCall(ctx, os.Getenv(helperForkEndpoint), req))
	}
}

func printOutcome(_ attachsock.ControlResult, err error) {
	var ce *attachsock.ControlError
	switch {
	case err == nil:
		fmt.Println("outcome=confirmed")
	case errors.As(err, &ce):
		fmt.Printf("outcome=%s %s\n", ce.Code, ce.Message)
	default:
		fmt.Println("outcome=error", err)
	}
}

// TestConfirmFromAConnectionWhoseOpenerExitedIsRefused is the M1 bypass,
// end to end over the real endpoint and the real confirmer.
func TestConfirmFromAConnectionWhoseOpenerExitedIsRefused(t *testing.T) {
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
	fk := newFakeTermsvc()
	c := fk.control(false)
	c.pending = newPendingLaunchStore()
	// The real confirmer with only the start check, so the outcome turns on
	// the caller being gone and on nothing in this test's own environment.
	li := launchInitiator{startOf: peerproc.StartToken}
	c.confirmer = launchConfirmer(li)
	var started atomic.Int32
	held, err := c.pending.hold(agentlaunch.Pending{Tool: "codex", Origin: termrun.Origin{Initiator: termrun.InitiatorAgent}},
		func(context.Context) (pendingOutcome, error) { started.Add(1); return pendingOutcome{}, nil })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	host := newAttachHost(nil, nil, nil).withControl(c).withCallerSnapshot(li.snapshotCaller)
	go func() {
		defer close(done)
		_ = attachsock.Serve(ctx, ln, host, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	}()
	t.Cleanup(func() { cancel(); _ = ln.Close(); <-done })

	run := func(role string) string {
		cmd := exec.Command(os.Args[0], "-test.run=^TestHelperForkConfirm$", "-test.v")
		cmd.Env = append(os.Environ(), helperForkRole+"="+role, helperForkEndpoint+"="+endpoint, helperForkHold+"="+held.ID)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("helper %s: %v\n%s", role, err, out)
		}
		return string(out)
	}
	if out := run("parent"); !strings.Contains(out, "outcome="+agentlaunch.CodeConfirmRefused) || !strings.Contains(out, "gone") {
		t.Fatalf("a confirm sent after the connecting process exited was not refused:\n%s", out)
	}
	if started.Load() != 0 || len(c.pending.holds.List()) != 1 {
		t.Fatalf("the refused confirm started (%d) or consumed the hold", started.Load())
	}
	// The control leg: a caller that stays until the reply confirms.
	if out := run("direct"); !strings.Contains(out, "outcome=confirmed") || started.Load() != 1 {
		t.Fatalf("a confirm from the connecting process itself: started %d\n%s", started.Load(), out)
	}
}
