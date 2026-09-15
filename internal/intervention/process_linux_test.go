//go:build linux

package intervention

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const (
	helperMarker = "SBO_INTERVENTION_HELPER"
	helperMode   = "SBO_INTERVENTION_HELPER_MODE"
)

// TestProcessHelper is re-executed by the tests below. Every resulting process
// is a child owned by the current test; no adapter, service, or unrelated host
// process is ever selected.
func TestProcessHelper(t *testing.T) {
	if os.Getenv(helperMarker) != "1" {
		return
	}
	switch os.Getenv(helperMode) {
	case "protected":
		if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
			os.Exit(2)
		}
		_, _ = fmt.Fprintln(os.Stdout, "ready")
		select {}
	case "ignore-term":
		signal.Ignore(syscall.SIGTERM)
		_, _ = fmt.Fprintln(os.Stdout, "ready")
		select {}
	case "exec":
		_, _ = fmt.Fprintln(os.Stdout, "ready")
		if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if err := unix.Exec("/bin/sleep", []string{"sleep", "30"}, os.Environ()); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	default:
		_, _ = fmt.Fprintln(os.Stdout, "ready")
		select {}
	}
}

type ownedChild struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	waited bool
}

func startOwnedChild(t *testing.T, mode string) *ownedChild {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestProcessHelper$")
	cmd.Env = helperEnvironment(mode)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	var stdin io.WriteCloser
	if mode == "exec" {
		stdin, err = cmd.StdinPipe()
		if err != nil {
			t.Fatalf("StdinPipe: %v", err)
		}
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start owned helper: %v", err)
	}
	child := &ownedChild{cmd: cmd, stdin: stdin}
	t.Cleanup(func() { child.cleanup() })

	ready := make(chan string, 1)
	go func() {
		line, readErr := bufio.NewReader(stdout).ReadString('\n')
		if readErr != nil {
			ready <- "read ready: " + readErr.Error()
			return
		}
		if strings.TrimSpace(line) != "ready" {
			ready <- "unexpected ready line: " + line
			return
		}
		ready <- ""
	}()
	select {
	case problem := <-ready:
		if problem != "" {
			t.Fatalf("%s; stderr=%q", problem, stderr.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("helper readiness timed out; stderr=%q", stderr.String())
	}
	return child
}

func helperEnvironment(mode string) []string {
	env := make([]string, 0, len(os.Environ())+2)
	for _, item := range os.Environ() {
		if strings.HasPrefix(item, helperMarker+"=") || strings.HasPrefix(item, helperMode+"=") {
			continue
		}
		env = append(env, item)
	}
	return append(env, helperMarker+"=1", helperMode+"="+mode)
}

func (c *ownedChild) cleanup() {
	if c == nil || c.waited || c.cmd == nil || c.cmd.Process == nil {
		return
	}
	_ = c.cmd.Process.Kill()
	_ = c.cmd.Wait()
	c.waited = true
}

func (c *ownedChild) wait() error {
	if c.waited {
		return nil
	}
	c.waited = true
	return c.cmd.Wait()
}

func inspectOwned(t *testing.T, child *ownedChild) Identity {
	t.Helper()
	id, err := Inspect(context.Background(), child.cmd.Process.Pid)
	if err != nil {
		t.Fatalf("Inspect owned pid %d: %v", child.cmd.Process.Pid, err)
	}
	return id
}

func requireOwnedAlive(t *testing.T, child *ownedChild) Identity {
	t.Helper()
	return inspectOwned(t, child)
}

func TestAcquireRejectsMismatchedIdentityWithoutSignalling(t *testing.T) {
	child := startOwnedChild(t, "")
	original := inspectOwned(t, child)

	tests := []struct {
		name   string
		mutate func(*Identity)
	}{
		{name: "boot", mutate: func(id *Identity) { id.BootID += "-other" }},
		{name: "start", mutate: func(id *Identity) { id.StartTicks++ }},
		{name: "uid", mutate: func(id *Identity) { id.UID++ }},
		{name: "executable device", mutate: func(id *Identity) { id.Executable.Device++ }},
		{name: "executable inode", mutate: func(id *Identity) { id.Executable.Inode++ }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			expected := original
			tc.mutate(&expected)
			process, err := Acquire(context.Background(), expected)
			if process != nil || !errors.Is(err, ErrIdentityMismatch) {
				t.Fatalf("Acquire() = (%v, %v), want nil, ErrIdentityMismatch", process, err)
			}
			if current := requireOwnedAlive(t, child); current != original {
				t.Fatalf("mismatch attempt changed child identity: got %+v want %+v", current, original)
			}
		})
	}
}

func TestAcquireRejectsInvalidSelfAndDuplicate(t *testing.T) {
	child := startOwnedChild(t, "")
	id := inspectOwned(t, child)

	invalid := []Identity{
		{},
		func() Identity { bad := id; bad.PID = 1; return bad }(),
		func() Identity { bad := id; bad.BootID = " " + bad.BootID; return bad }(),
		func() Identity { bad := id; bad.Executable.Inode = 0; return bad }(),
	}
	for i, expected := range invalid {
		if process, err := Acquire(context.Background(), expected); process != nil || !errors.Is(err, ErrInvalidIdentity) {
			t.Fatalf("invalid[%d] Acquire() = (%v, %v), want nil, ErrInvalidIdentity", i, process, err)
		}
	}

	self, err := Inspect(context.Background(), os.Getpid())
	if err != nil {
		t.Fatalf("Inspect self: %v", err)
	}
	if process, err := Acquire(context.Background(), self); process != nil || !errors.Is(err, ErrSelfTarget) {
		t.Fatalf("self Acquire() = (%v, %v), want nil, ErrSelfTarget", process, err)
	}

	first, err := Acquire(context.Background(), id)
	if err != nil {
		t.Fatalf("first Acquire: %v", err)
	}
	defer func() { _ = first.Close() }()
	if second, err := Acquire(context.Background(), id); second != nil || !errors.Is(err, ErrAlreadyAcquired) {
		t.Fatalf("duplicate Acquire() = (%v, %v), want nil, ErrAlreadyAcquired", second, err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	third, err := Acquire(context.Background(), id)
	if err != nil {
		t.Fatalf("Acquire after Close: %v", err)
	}
	if err := third.Close(); err != nil {
		t.Fatalf("third Close: %v", err)
	}
}

func TestTerminateObservedAndUnrelatedOwnedSiblingUnaffected(t *testing.T) {
	target := startOwnedChild(t, "")
	sibling := startOwnedChild(t, "")
	siblingID := inspectOwned(t, sibling)

	process, err := Acquire(context.Background(), inspectOwned(t, target))
	if err != nil {
		t.Fatalf("Acquire target: %v", err)
	}
	defer func() { _ = process.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result, err := process.Terminate(ctx)
	if err != nil {
		t.Fatalf("Terminate: %v", err)
	}
	if !result.Observed || result.AlreadyExited {
		t.Fatalf("Terminate result = %+v, want observed new exit", result)
	}
	if err := target.wait(); err == nil {
		t.Fatal("target Wait succeeded, want signal exit")
	}
	if current := requireOwnedAlive(t, sibling); current != siblingID {
		t.Fatalf("sibling identity changed: got %+v want %+v", current, siblingID)
	}
}

func TestTerminateTimeoutThenExplicitKill(t *testing.T) {
	target := startOwnedChild(t, "ignore-term")
	id := inspectOwned(t, target)
	process, err := Acquire(context.Background(), id)
	if err != nil {
		t.Fatalf("Acquire target: %v", err)
	}
	defer func() { _ = process.Close() }()

	termCtx, termCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	result, err := process.Terminate(termCtx)
	termCancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Terminate error = %v, want context deadline", err)
	}
	if result.Observed {
		t.Fatalf("Terminate result = %+v, want unobserved", result)
	}
	if current := requireOwnedAlive(t, target); current != id {
		t.Fatalf("SIGTERM timeout changed identity: got %+v want %+v", current, id)
	}

	killCtx, killCancel := context.WithTimeout(context.Background(), 2*time.Second)
	result, err = process.Kill(killCtx)
	killCancel()
	if err != nil {
		t.Fatalf("explicit Kill: %v", err)
	}
	if !result.Observed || result.AlreadyExited {
		t.Fatalf("Kill result = %+v, want observed new exit", result)
	}
	if err := target.wait(); err == nil {
		t.Fatal("target Wait succeeded, want SIGKILL exit")
	}

	againCtx, againCancel := context.WithTimeout(context.Background(), time.Second)
	result, err = process.Kill(againCtx)
	againCancel()
	if err != nil {
		t.Fatalf("Kill exited target: %v", err)
	}
	if !result.Observed || !result.AlreadyExited {
		t.Fatalf("Kill exited result = %+v, want observed already-exited", result)
	}
}

func TestSignalDeliveryAndExitObservationAreSeparate(t *testing.T) {
	target := startOwnedChild(t, "ignore-term")
	process, err := Acquire(context.Background(), inspectOwned(t, target))
	if err != nil {
		t.Fatalf("Acquire target: %v", err)
	}
	defer func() { _ = process.Close() }()

	signalCtx, signalCancel := context.WithTimeout(context.Background(), time.Second)
	result, err := process.SignalTerminate(signalCtx)
	signalCancel()
	if err != nil || result.Observed {
		t.Fatalf("SignalTerminate = (%+v, %v), want successful unobserved delivery", result, err)
	}
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	result, err = process.WaitExit(waitCtx)
	waitCancel()
	if !errors.Is(err, context.DeadlineExceeded) || result.Observed {
		t.Fatalf("WaitExit after ignored TERM = (%+v, %v), want unobserved deadline", result, err)
	}

	killCtx, killCancel := context.WithTimeout(context.Background(), 2*time.Second)
	result, err = process.SignalKill(killCtx)
	if err != nil || result.Observed {
		killCancel()
		t.Fatalf("SignalKill = (%+v, %v), want successful unobserved delivery", result, err)
	}
	result, err = process.WaitExit(killCtx)
	killCancel()
	if err != nil || !result.Observed || result.AlreadyExited {
		t.Fatalf("WaitExit after KILL = (%+v, %v), want observed new exit", result, err)
	}
	if err := target.wait(); err == nil {
		t.Fatal("target Wait succeeded, want SIGKILL exit")
	}
}

func TestOperationCancellationDoesNotSignal(t *testing.T) {
	target := startOwnedChild(t, "")
	id := inspectOwned(t, target)
	process, err := Acquire(context.Background(), id)
	if err != nil {
		t.Fatalf("Acquire target: %v", err)
	}
	defer func() { _ = process.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	cancel()
	result, err := process.Terminate(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Terminate error = %v, want context canceled", err)
	}
	if result.Observed {
		t.Fatalf("Terminate result = %+v, want unobserved", result)
	}
	if current := requireOwnedAlive(t, target); current != id {
		t.Fatalf("canceled operation changed target: got %+v want %+v", current, id)
	}

	// Cancellation after point-in-time revalidation must still be observed
	// before the signal syscall.
	afterInspectCtx, afterInspectCancel := context.WithTimeout(context.Background(), time.Second)
	process.inspect = func(context.Context, int) (Identity, error) {
		afterInspectCancel()
		return id, nil
	}
	result, err = process.Terminate(afterInspectCtx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Terminate canceled after inspect error = %v, want context canceled", err)
	}
	if result.Observed {
		t.Fatalf("Terminate canceled after inspect result = %+v, want unobserved", result)
	}
	if current := requireOwnedAlive(t, target); current != id {
		t.Fatalf("post-inspect cancellation changed target: got %+v want %+v", current, id)
	}
	process.inspect = Inspect

	killCtx, killCancel := context.WithTimeout(context.Background(), 2*time.Second)
	if result, err := process.Kill(killCtx); err != nil || !result.Observed {
		t.Fatalf("cleanup Kill = (%+v, %v)", result, err)
	}
	killCancel()
	_ = target.wait()
}

func TestOperationInspectionFailureIsNotExitEvidence(t *testing.T) {
	for _, inspectionErr := range []error{ErrProcessGone, ErrPermission, ErrInspectionUnavailable} {
		t.Run(inspectionErr.Error(), func(t *testing.T) {
			target := startOwnedChild(t, "")
			id := inspectOwned(t, target)
			process, err := Acquire(context.Background(), id)
			if err != nil {
				t.Fatalf("Acquire target: %v", err)
			}
			defer func() { _ = process.Close() }()
			process.inspect = func(context.Context, int) (Identity, error) {
				return Identity{}, inspectionErr
			}

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			result, err := process.Terminate(ctx)
			cancel()
			if !errors.Is(err, inspectionErr) {
				t.Fatalf("Terminate error = %v, want %v", err, inspectionErr)
			}
			if result.Observed {
				t.Fatalf("Terminate result = %+v, inspection failure is not exit evidence", result)
			}
			if current := requireOwnedAlive(t, target); current != id {
				t.Fatalf("inspection failure changed target: got %+v want %+v", current, id)
			}

			process.inspect = Inspect
			killCtx, killCancel := context.WithTimeout(context.Background(), 2*time.Second)
			if result, err := process.Kill(killCtx); err != nil || !result.Observed {
				t.Fatalf("cleanup Kill = (%+v, %v)", result, err)
			}
			killCancel()
			_ = target.wait()
		})
	}
}

func TestExecReplacementIsRefusedBeforeSignal(t *testing.T) {
	target := startOwnedChild(t, "exec")
	original := inspectOwned(t, target)
	process, err := Acquire(context.Background(), original)
	if err != nil {
		t.Fatalf("Acquire target: %v", err)
	}
	defer func() { _ = process.Close() }()
	if _, err := io.WriteString(target.stdin, "exec\n"); err != nil {
		t.Fatalf("release exec helper: %v", err)
	}
	_ = target.stdin.Close()

	var replacement Identity
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		replacement, err = Inspect(context.Background(), original.PID)
		if err == nil && replacement.Executable != original.Executable {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil || replacement.Executable == original.Executable {
		t.Fatalf("exec replacement not observed: identity=%+v error=%v", replacement, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	result, err := process.Terminate(ctx)
	cancel()
	if !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("Terminate after exec error = %v, want ErrIdentityMismatch", err)
	}
	if result.Observed {
		t.Fatalf("Terminate result = %+v, want unobserved", result)
	}
	if current := requireOwnedAlive(t, target); current != replacement {
		t.Fatalf("replacement was signalled: got %+v want %+v", current, replacement)
	}
}

func TestWaitForExitRequiresDocumentedReadiness(t *testing.T) {
	tests := []struct {
		name    string
		revents int16
		wantErr error
	}{
		{name: "readable is exit", revents: unix.POLLIN},
		{name: "invalid fd", revents: unix.POLLNVAL, wantErr: unix.EBADF},
		{name: "poll error", revents: unix.POLLERR, wantErr: unix.EIO},
		{name: "readable with poll error", revents: unix.POLLIN | unix.POLLERR, wantErr: unix.EIO},
		{name: "hangup alone", revents: unix.POLLHUP, wantErr: errors.New("hangup")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err := waitForExitWith(ctx, 42, func(fds []unix.PollFd, _ int) (int, error) {
				fds[0].Revents = tc.revents
				return 1, nil
			})
			if tc.wantErr == nil && err != nil {
				t.Fatalf("waitForExitWith error = %v, want nil", err)
			}
			if tc.wantErr != nil && err == nil {
				t.Fatalf("waitForExitWith error = nil, want failure for %v", tc.wantErr)
			}
			if errors.Is(tc.wantErr, unix.EBADF) && !errors.Is(err, unix.EBADF) {
				t.Fatalf("waitForExitWith error = %v, want EBADF", err)
			}
			if errors.Is(tc.wantErr, unix.EIO) && !errors.Is(err, unix.EIO) {
				t.Fatalf("waitForExitWith error = %v, want EIO", err)
			}
		})
	}
}

func TestInspectDistinguishesGoneFromExistingZombie(t *testing.T) {
	if _, err := Inspect(context.Background(), 1<<30); !errors.Is(err, ErrProcessGone) {
		t.Fatalf("Inspect nonexistent pid error = %v, want ErrProcessGone", err)
	}

	cmd := exec.Command("/bin/true")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start owned true child: %v", err)
	}
	waited := false
	t.Cleanup(func() {
		if !waited {
			_ = cmd.Wait()
		}
	})
	deadline := time.Now().Add(2 * time.Second)
	zombie := false
	for time.Now().Before(deadline) {
		raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", cmd.Process.Pid))
		if err == nil && bytes.Contains(raw, []byte("State:\tZ")) {
			zombie = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !zombie {
		t.Fatal("owned child did not reach zombie state")
	}
	if _, err := Inspect(context.Background(), cmd.Process.Pid); !errors.Is(err, ErrInspectionUnavailable) {
		t.Fatalf("Inspect zombie error = %v, want ErrInspectionUnavailable", err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("reap owned true child: %v", err)
	}
	waited = true
}

func TestParseUniformUIDRequiresCompleteSinglePrincipal(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want int
		ok   bool
	}{
		{name: "ordinary uid", raw: "Name:\tfixture\nUid:\t1000\t1000\t1000\t1000\n", want: 1000, ok: true},
		{name: "real root", raw: "Uid:\t0\t0\t0\t0\n", want: 0, ok: true},
		{name: "missing", raw: "Name:\tfixture\n", ok: false},
		{name: "too few", raw: "Uid:\t1000\t1000\t1000\n", ok: false},
		{name: "malformed", raw: "Uid:\t1000\tbad\t1000\t1000\n", ok: false},
		{name: "negative", raw: "Uid:\t-1\t-1\t-1\t-1\n", ok: false},
		{name: "setuid transition", raw: "Uid:\t1000\t0\t0\t0\n", ok: false},
		{name: "filesystem uid differs", raw: "Uid:\t1000\t1000\t1000\t0\n", ok: false},
		{name: "extra field", raw: "Uid:\t1000\t1000\t1000\t1000\t1000\n", ok: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseUniformUID([]byte(tc.raw))
			if got != tc.want || ok != tc.ok {
				t.Fatalf("parseUniformUID() = (%d, %v), want (%d, %v)", got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestTerminateRequiresDeadline(t *testing.T) {
	target := startOwnedChild(t, "")
	id := inspectOwned(t, target)
	process, err := Acquire(context.Background(), id)
	if err != nil {
		t.Fatalf("Acquire target: %v", err)
	}
	defer func() { _ = process.Close() }()
	if result, err := process.Terminate(context.Background()); !errors.Is(err, ErrUnboundedContext) || result.Observed {
		t.Fatalf("unbounded Terminate = (%+v, %v), want unobserved ErrUnboundedContext", result, err)
	}
	if current := requireOwnedAlive(t, target); current != id {
		t.Fatalf("unbounded operation changed target: got %+v want %+v", current, id)
	}
}
