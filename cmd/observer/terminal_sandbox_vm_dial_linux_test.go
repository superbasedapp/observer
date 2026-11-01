//go:build linux && !sbo_omit_terminals_sandbox_vm && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// terminal_sandbox_vm_dial_linux_test.go covers D6 of the microVM row's
// first live run (2026-10-24): Cloud Hypervisor's API socket appears
// before the VMM listens on it, and one launch in about sixteen ended
// "vmm.ping: connection refused" because the helper dialled once.

// refused is a dial error carrying ECONNREFUSED, as net.Dial reports it.
func refused() error {
	return &net.OpError{Op: "dial", Net: "unix", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
}

// TestVMHostRetriesARefusedAPISocket (D6): the first dials of the API
// socket are refused (bound, not yet listening); the helper retries and the
// run goes through.
func TestVMHostRetriesARefusedAPISocket(t *testing.T) {
	r := newVMRig(t)
	env := r.env()
	var n atomic.Int32
	env.apiDial = func(ctx context.Context, sock string, pid int) (net.Conn, error) {
		if n.Add(1) <= 3 {
			return nil, refused()
		}
		return vmDialAPI(ctx, sock, pid)
	}
	if code := vmHostRun(r.plan, r.h, []string{"/home/u/.local/bin/observer", "claude"}, env); code != 0 {
		t.Fatalf("exit %d: %s", code, r.termOut.String())
	}
	if n.Load() <= 3 {
		t.Fatalf("dialled %d times", n.Load())
	}
}

// TestVMHostRefusedAPISocketIsBounded (D6): a socket that never listens
// ends the launch within the boot window, never a hang.
func TestVMHostRefusedAPISocketIsBounded(t *testing.T) {
	r := newVMRig(t)
	env := r.env()
	env.bootWindow = 600 * time.Millisecond
	env.apiDial = func(context.Context, string, int) (net.Conn, error) { return nil, refused() }
	start := time.Now()
	if code := vmHostRun(r.plan, r.h, []string{"/bin/true"}, env); code == 0 {
		t.Fatal("a VMM that never listened was used")
	}
	if took := time.Since(start); took > 10*time.Second {
		t.Fatalf("took %s", took)
	}
}

// TestVMDialRetryingWaitsForALateListener (D6): a unix socket that is bound
// but not yet listening refuses (the VMM's window); the dial retries until
// the listener comes up, then connects; past the deadline it gives up with
// the refusal; another error is never retried.
func TestVMDialRetryingWaitsForALateListener(t *testing.T) {
	dir, err := os.MkdirTemp("", "vmdial")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "api.sock")
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: sock}); err != nil {
		t.Fatal(err)
	}
	dial := func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", sock)
	}
	if _, err := dial(context.Background()); !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("a bound socket that does not listen: %v", err)
	}
	if _, err := vmDialRetrying(context.Background(), time.Now().Add(150*time.Millisecond), dial); !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("past the deadline: %v", err)
	}
	go func() {
		time.Sleep(300 * time.Millisecond)
		_ = unix.Listen(fd, 4)
	}()
	start := time.Now()
	c, err := vmDialRetrying(context.Background(), time.Now().Add(5*time.Second), dial)
	if err != nil {
		t.Fatalf("the late listener: %v", err)
	}
	_ = c.Close()
	if took := time.Since(start); took < 250*time.Millisecond || took > 3*time.Second {
		t.Fatalf("connected after %s", took)
	}
	var calls int
	other := errors.New("not a refusal")
	if _, err := vmDialRetrying(context.Background(), time.Now().Add(5*time.Second), func(context.Context) (net.Conn, error) { calls++; return nil, other }); !errors.Is(err, other) || calls != 1 {
		t.Fatalf("another error: %v after %d calls", err, calls)
	}
}
