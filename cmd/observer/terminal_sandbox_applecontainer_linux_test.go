//go:build linux && !sbo_omit_terminals_sandbox_apple_container && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/marmutapp/superbased-observer/internal/sandboxapple"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote/relaymux"
)

// terminal_sandbox_applecontainer_linux_test.go covers the Apple container
// init's Linux half: the in-guest check over the live 1.6.0 mount tables
// (D-A3) and the capture relay's tunnel end to end (D-A4).

func appleLiveMountInfo(t *testing.T, name string) func() ([]byte, error) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "internal", "sandboxapple", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return func() ([]byte, error) { return b, nil }
}

// TestAppleGuestCheckRefusesTheDroppedPin (D-A3): on the mount table 1.6.0
// gave the old shape (the .git pin silently gone), the box refuses to start
// the agent with built_below_plan; on the fixed shape's table it starts; a
// read-only path the kernel still lets root write is refused too.
func TestAppleGuestCheckRefusesTheDroppedPin(t *testing.T) {
	ws := "/Users/dev/src/app"
	ia := sandboxapple.InitArgs{Mounts: []string{ws, ws + "/.git"}, ReadOnly: []string{ws + "/.git/config"}}
	erofs := func(string) error { return unix.EROFS }
	v := appleGuestCheck(ia, appleLiveMountInfo(t, "mountinfo_live_da3.txt"), erofs)
	if v.Code != sandboxapple.VerdictBuiltBelowPlan || !strings.Contains(v.Reason, ws+"/.git is not mounted") {
		t.Fatalf("the dropped pin: %+v", v)
	}
	ia.ReadOnly = []string{ws + "/.git/config", ws + "/.git/hooks", ws + "/.git/commondir"}
	if v := appleGuestCheck(ia, appleLiveMountInfo(t, "mountinfo_live.txt"), erofs); !v.OK() {
		t.Fatalf("the fixed shape: %+v", v)
	}
	writable := func(p string) error {
		if strings.HasSuffix(p, "commondir") {
			return nil
		}
		return unix.EROFS
	}
	if v := appleGuestCheck(ia, appleLiveMountInfo(t, "mountinfo_live.txt"), writable); v.OK() || !strings.Contains(v.Reason, "commondir is writable") {
		t.Fatalf("a writable read-only path: %+v", v)
	}
	if v := appleGuestCheck(ia, func() ([]byte, error) { return nil, errors.New("no proc") }, erofs); v.OK() {
		t.Fatal("an unreadable mount table passed")
	}
}

// TestAppleFromOutsideRefusesABoxProcess: a connection from a process in the
// same pid namespace (any process in the box, the agent included) is not
// the runtime's forwarder.
func TestAppleFromOutsideRefusesABoxProcess(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.sock")
	ln, err := net.Listen("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := net.Dial("unix", p)
		if err == nil {
			time.Sleep(200 * time.Millisecond)
			_ = c.Close()
		}
	}()
	c, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if appleFromOutside(c) {
		t.Fatal("a connection from inside the box's pid namespace was taken for the forwarder")
	}
}

// TestAppleTunnelEndToEnd (D-A4): the host side dials the published tunnel
// (failing while nothing listens), the box's init takes the handshake,
// writes the box record and serves the relay socket in the guest socket dir
// for the agent's uid, the launch environment arrives inside the tunnel,
// and a connection to the guest relay socket reaches the host's own relay.
func TestAppleTunnelEndToEnd(t *testing.T) {
	prev := appleTunnelPeer
	appleTunnelPeer = func(net.Conn) bool { return true }
	t.Cleanup(func() { appleTunnelPeer = prev })
	root := t.TempDir()
	hostSock := filepath.Join(root, "h")
	guestTunnel := filepath.Join(root, "g", "mux.sock")
	guestSock := filepath.Join(root, "gs")
	if err := os.Mkdir(hostSock, 0o700); err != nil {
		t.Fatal(err)
	}
	relay, err := net.Listen("unix", filepath.Join(hostSock, sandboxrelayd.RelaySocketName))
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	go func() {
		for {
			c, err := relay.Accept()
			if err != nil {
				return
			}
			go func() {
				b := make([]byte, 5)
				_, _ = io.ReadFull(c, b)
				_, _ = c.Write(append([]byte("host-relay:"), b...))
				_ = c.Close()
			}()
		}
	}()
	secret := []byte(strings.Repeat("ab", 32))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	connected := make(chan struct{})
	lost := make(chan error, 1)
	go appleTunnelHost(ctx, func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", guestTunnel)
	}, relaymux.HostOptions{
		Options: relaymux.Options{RunID: "RunLive_0123456789abcd", Secret: secret}, Rand: rand.Reader,
		Kinds: appleTunnelKinds(hostSock, false), Dial: appleTunnelDial(hostSock),
		Record: []byte(`{"v":1}`), Env: []string{"HOME=/Users/dev", "ANTHROPIC_BASE_URL=http://127.0.0.1:8820"},
	}, 10*time.Second, func() { close(connected) }, func(err error) { lost <- err })
	// The host dials before the guest listens: those dials fail and retry.
	time.Sleep(300 * time.Millisecond)
	ia := sandboxapple.InitArgs{Relay: "RunLive_0123456789abcd", UID: os.Getuid(), GID: os.Getgid()}
	tun, err := appleServeGuestTunnelAt(ia, secret, 10*time.Second, guestTunnel, guestSock)
	if err != nil {
		t.Fatal(err)
	}
	defer tun.stop()
	select {
	case <-connected:
	case err := <-lost:
		t.Fatalf("lost: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("the host side never connected")
	}
	if !slices.Equal(tun.env, []string{"HOME=/Users/dev", "ANTHROPIC_BASE_URL=http://127.0.0.1:8820"}) {
		t.Fatalf("env %q", tun.env)
	}
	if b, err := os.ReadFile(filepath.Join(guestSock, sandboxrelayd.BoxRecordName)); err != nil || string(b) != `{"v":1}` {
		t.Fatalf("record %q %v", b, err)
	}
	if fi, err := os.Stat(guestSock); err != nil || fi.Mode().Perm() != 0o700 || !ownedByMe(fi) {
		t.Fatalf("guest socket dir %v %v", fi, err)
	}
	if fi, err := os.Stat(filepath.Dir(guestTunnel)); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("tunnel dir %v %v", fi, err)
	}
	c, err := net.Dial("unix", filepath.Join(guestSock, sandboxrelayd.RelaySocketName))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte("hello"))
	reply, _ := io.ReadAll(c)
	_ = c.Close()
	if string(reply) != "host-relay:hello" {
		t.Fatalf("reply %q", reply)
	}
	if _, err := os.Lstat(filepath.Join(guestSock, "proxy.sock")); err == nil {
		t.Fatal("a proxy socket was served while the host forwards none")
	}
}

// TestAppleTunnelHostGivesUp: with no box answering, the host side reports
// the tunnel lost after its window (the helper then ends the run).
func TestAppleTunnelHostGivesUp(t *testing.T) {
	lost := make(chan error, 1)
	appleTunnelHost(context.Background(), func(context.Context) (net.Conn, error) { return nil, errors.New("no such socket") },
		relaymux.HostOptions{Options: relaymux.Options{RunID: "r1", Secret: []byte(strings.Repeat("x", 32))}, Rand: rand.Reader, Dial: appleTunnelDial(t.TempDir())},
		300*time.Millisecond, nil, func(err error) { lost <- err })
	select {
	case err := <-lost:
		if err == nil || !strings.Contains(err.Error(), "no such socket") {
			t.Fatalf("lost with %v", err)
		}
	default:
		t.Fatal("the host side did not give up")
	}
}
