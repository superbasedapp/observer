//go:build unix

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestIsPipeOrSocket pins the fd-shape guard that keeps emitOOBLaunchHello from
// adopting (and then CLOSING) an fd that is not the daemon-handed OOB pipe. The
// regression this guards: every descendant of an `observer <tool>` launcher
// inherits OBSERVER_OOB_FD=3 in its environment while the pipe itself is
// close-on-exec, so a hook process's fd 3 was the Go runtime's epoll descriptor
// and closing it crashed the hook ("epollwait on fd 3 failed with 9").
func TestIsPipeOrSocket(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if !isPipeOrSocket(int(w.Fd())) {
		t.Fatalf("pipe write end reported as not a pipe")
	}
	if !isPipeOrSocket(int(r.Fd())) {
		t.Fatalf("pipe read end reported as not a pipe")
	}

	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fds[0])
	defer syscall.Close(fds[1])
	if !isPipeOrSocket(fds[0]) {
		t.Fatalf("unix socket reported as not a socket")
	}

	f, err := os.Create(filepath.Join(t.TempDir(), "regular"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if isPipeOrSocket(int(f.Fd())) {
		t.Fatalf("regular file reported as a pipe/socket")
	}

	// A closed / never-opened descriptor must never be adopted.
	tmp, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	probe := int(tmp.Fd())
	tmp.Close()
	if isPipeOrSocket(probe) {
		t.Fatalf("closed fd %d reported as a pipe/socket", probe)
	}

	// The guard must reject the runtime's own epoll fd if it ever lands at the
	// inherited number: an epoll descriptor is an anonymous inode, neither a
	// FIFO nor a socket.
	ep, err := syscall.EpollCreate1(0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(ep)
	if isPipeOrSocket(ep) {
		t.Fatalf("epoll fd reported as a pipe/socket")
	}
}

// TestEmitOOBLaunchHelloIgnoresNonChannelFD proves the end-to-end behaviour:
// with OBSERVER_OOB_FD pointing at a regular file (the inherited-env shape a
// hook process sees), the emitter is a no-op and the fd is left OPEN — it must
// not be closed out from under whoever owns it.
func TestEmitOOBLaunchHelloIgnoresNonChannelFD(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "notachannel"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	t.Setenv(envOOBFD, itoa(int(f.Fd())))
	t.Setenv(envOOBAuth, "token")

	end := emitOOBLaunchHello()
	end(0)

	if oobChannelActive() {
		t.Fatalf("channel reported active for a non-pipe fd")
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil {
		t.Fatalf("fd was closed by the emitter: %v", err)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
