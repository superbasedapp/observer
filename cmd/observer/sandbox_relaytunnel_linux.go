//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxremote/relaymux"
)

// sandbox_relaytunnel_linux.go is the guest half of the capture relay's
// tunnel (one owner, lane SBX-P4): inside a VM-class box the init listens
// (a unix socket the Apple container runtime publishes, an AF_VSOCK port
// under Cloud Hypervisor), takes the first handshake from outside the box
// that succeeds, serves the guest socket dir for the agent's uid over it,
// and keeps accepting re-opened, re-keyed sessions from the host helper.

// guestTunnel is the box side of the tunnel while the agent runs.
type guestTunnel struct {
	env         []string
	ln          net.Listener
	mu          sync.Mutex
	cur         *relaymux.Guest
	done        chan struct{}
	once        sync.Once
	stopSockets func()
	peer        func(net.Conn) bool
}

func (t *guestTunnel) guest() *relaymux.Guest {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.cur
}

func (t *guestTunnel) stop() {
	t.once.Do(func() {
		close(t.done)
		_ = t.ln.Close()
		if t.stopSockets != nil {
			t.stopSockets()
		}
		if g := t.guest(); g != nil {
			g.Close()
		}
	})
}

// deadliner is a listener that can bound an Accept.
type deadliner interface{ SetDeadline(time.Time) error }

// guestTunnelServe takes the first handshake on ln from a peer peer accepts
// within window, serves the guest sockets in sockDir (for owner when set)
// and keeps accepting re-opened sessions until stop.
func guestTunnelServe(ln net.Listener, peer func(net.Conn) bool, runID string, secret []byte, window time.Duration, sockDir string, owner *guestSocketOwner) (*guestTunnel, error) {
	t := &guestTunnel{ln: ln, done: make(chan struct{}), peer: peer}
	deadline := time.Now().Add(window)
	opts := relaymux.Options{RunID: runID, Secret: secret}
	var last error = errors.New("no connection from the host helper")
	for t.cur == nil {
		if !time.Now().Before(deadline) {
			_ = ln.Close()
			return nil, last
		}
		if dl, ok := ln.(deadliner); ok {
			_ = dl.SetDeadline(deadline)
		}
		c, err := ln.Accept()
		if err != nil {
			last = err
			continue
		}
		if !peer(c) {
			_ = c.Close()
			last = errors.New("a connection from inside the box was refused")
			continue
		}
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		g, err := relaymux.DialGuest(ctx, c, opts)
		cancel()
		if err != nil {
			_ = c.Close()
			last = err
			continue
		}
		t.cur = g
	}
	if dl, ok := ln.(deadliner); ok {
		_ = dl.SetDeadline(time.Time{})
	}
	hello := t.cur.Hello()
	t.env = hello.Env
	stopSockets, err := guestServeSocketsFor(t.guest, hello, sockDir, owner, false)
	if err != nil {
		t.stop()
		return nil, err
	}
	t.stopSockets = stopSockets
	if err := t.cur.Ready(); err != nil {
		t.stop()
		return nil, err
	}
	go t.reaccept(opts)
	return t, nil
}

// reaccept serves re-opened sessions: each accepted handshake replaces the
// current session (the sockets ask the current one), the old one ends.
func (t *guestTunnel) reaccept(opts relaymux.Options) {
	for {
		c, err := t.ln.Accept()
		if err != nil {
			select {
			case <-t.done:
				return
			default:
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if !t.peer(c) {
			_ = c.Close()
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		g, err := relaymux.DialGuest(ctx, c, opts)
		cancel()
		if err != nil {
			_ = c.Close()
			continue
		}
		_ = g.Ready()
		t.mu.Lock()
		old := t.cur
		t.cur = g
		t.mu.Unlock()
		if old != nil {
			old.Close()
		}
	}
}
