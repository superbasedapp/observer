package main

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/listenhandover"
)

// TestProxyHandoverPrepareDrainExec walks the daemon's half of an in-place
// restart (L-168 (ii)): the proxy's listener is recorded, duplicated, paused
// while the in-flight requests finish (bounded), and named in the re-exec's
// environment.
func TestProxyHandoverPrepareDrainExec(t *testing.T) {
	if !listenhandover.Supported() {
		t.Skip("no hand-over on this OS")
	}
	h := &proxyHandover{}
	if ok, err := h.prepare(); ok || err != nil {
		t.Fatalf("prepare with no proxy = %v %v, want nothing to hand over", ok, err)
	}
	if env := h.execEnv([]string{"A=1"}, nil); len(env) != 1 {
		t.Fatalf("execEnv with nothing prepared changed the env: %v", env)
	}
	var out bytes.Buffer
	ln, err := h.listen("127.0.0.1:0", nil, &out)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if !h.proxyServed() || out.Len() != 0 {
		t.Fatalf("served=%v out=%q", h.proxyServed(), out.String())
	}
	if ok, err := h.prepare(); !ok || err != nil || !h.handingOver() {
		t.Fatalf("prepare = %v %v", ok, err)
	}

	// The drain waits for the in-flight requests, then reports drained.
	left := 3
	if !h.drainForRestart(context.Background(), func() int { left--; return left }, 5*time.Second) {
		t.Fatal("the drain did not finish once nothing was in flight")
	}
	// A request that never finishes: the drain gives up at its bound.
	start := time.Now()
	if h.drainForRestart(context.Background(), func() int { return 1 }, 250*time.Millisecond) {
		t.Fatal("the drain reported drained with a request in flight")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("the drain overran its bound")
	}
	// While paused, a connection waits in the backlog: dialing succeeds.
	c, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("a connection during the drain was not taken into the backlog: %v", err)
	}
	_ = c.Close()

	env := h.execEnv([]string{"A=1"}, nil)
	if len(env) != 3 || !strings.HasPrefix(env[1], listenhandover.EnvFD+"=") || env[2] != listenhandover.EnvAddr+"=127.0.0.1:0" {
		t.Fatalf("exec env = %v", env)
	}
}
