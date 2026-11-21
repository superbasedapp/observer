//go:build linux && !sbo_omit_terminals

package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/peerproc"
)

// TestCallerGateIdentifiesARealBoxProcess (Linux, real /proc): a box root
// (here a shell standing in for a sandboxed terminal's host helper) starts
// a grandchild that connects to a loopback listener; the real lookup
// attributes the connection to the grandchild, finds the root among its
// ancestors and refuses it. A connection from this test process (the
// owner's side, outside every box) passes.
func TestCallerGateIdentifiesARealBoxProcess(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not found")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback listener: %v", err)
	}
	defer func() { _ = ln.Close() }()
	port := ln.Addr().(*net.TCPAddr).Port
	// root: sh -> bash (a child, not exec'd: the trailing true) -> /dev/tcp.
	script := fmt.Sprintf(`%s -c 'exec 3<>/dev/tcp/127.0.0.1/%d; read -r _ <&3'; true`, bash, port)
	root := exec.Command("sh", "-c", script) //nolint:gosec // G204: a fixed test command
	if err := root.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Process.Kill(); _ = root.Wait() }()
	_ = ln.(*net.TCPListener).SetDeadline(time.Now().Add(10 * time.Second))
	conn, err := ln.Accept()
	if err != nil {
		t.Fatalf("the box process never connected: %v", err)
	}
	defer func() { _ = conn.Close() }()
	server := netip.MustParseAddrPort(conn.LocalAddr().String())
	boxClient := netip.MustParseAddrPort(conn.RemoteAddr().String())

	g := callerGateSources{
		snapshot: func() []dashapi.LaunchInfo {
			return []dashapi.LaunchInfo{{ID: "h-box", RunID: "run-real", Sandboxed: true, Isolation: &dashapi.LaunchIsolation{Class: "process", Backend: "bwrap", EgressTier: "host"}}}
		},
		pidFor:   func(string) (int, bool) { return root.Process.Pid, true },
		markers:  func() []sandboxCLIMarker { return nil },
		cliAlive: func(int, string) bool { return false },
		exposures: func(context.Context) ([]exposedBox, string, bool) {
			return []exposedBox{{RunID: "run-real", TreeContained: true}}, "sandboxed run run-real is live", false
		},
		find: peerproc.Find,
	}
	reason, refused := g.check(context.Background(), boxClient, server, true)
	if !refused || !strings.Contains(reason, "inside sandboxed run run-real") {
		t.Fatalf("the box process was not refused: %q %v", reason, refused)
	}
	// The owner's side: this test process connects too.
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	own, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = own.Close() }()
	srvSide := <-accepted
	defer func() { _ = srvSide.Close() }()
	ownClient := netip.MustParseAddrPort(srvSide.RemoteAddr().String())
	if reason, refused := g.check(context.Background(), ownClient, server, true); refused {
		t.Fatalf("a process outside every box was refused: %s", reason)
	}
}
