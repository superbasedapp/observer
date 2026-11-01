//go:build !windows && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote/relaymux"
)

// sandbox_relaytunnel_notwindows.go holds the capture relay tunnel's dial
// side, used only by the Apple container (darwin) and microVM (linux)
// drivers, so it is excluded from Windows (WINFIX4 lint: unused there). Its
// companion sandbox_relaytunnel.go keeps relayTunnelKinds, read on every
// platform.

// relayTunnelHost is the host half of the capture relay's tunnel (D-A4):
// a host unix socket mounted into the guest cannot be connected there, so
// the guest's init listens on a socket published to the host
// (--publish-socket) and this side dials in. It dials until a handshake
// succeeds (the runtime accepts and closes a connection while nothing
// listens in the guest yet, live 2026-10-24), serves the session, and dials
// again when a session ends, until ctx ends. connected is called after the
// first handshake; lost is called once, and the loop ends, when no session
// can be had for window (the caller ends the run: capture is never
// silently missing).
func relayTunnelHost(ctx context.Context, dial func(context.Context) (net.Conn, error), opts relaymux.HostOptions, window time.Duration, connected func(), lost func(error)) {
	deadline := time.Now().Add(window)
	var last error
	for ctx.Err() == nil {
		c, err := dial(ctx)
		if err == nil {
			h, herr := relaymux.ServeHost(ctx, c, opts)
			if herr == nil {
				if connected != nil {
					connected()
					connected = nil
				}
				select {
				case <-h.Done():
				case <-ctx.Done():
					h.Close()
					return
				}
				deadline = time.Now().Add(window)
				continue
			}
			_ = c.Close()
			err = herr
		}
		last = err
		if !time.Now().Before(deadline) {
			if lost != nil {
				lost(last)
			}
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// relayTunnelSockets maps a tunnel kind to the host service's socket in the
// run's socket dir.
var relayTunnelSockets = map[string]string{
	relaymux.KindRelay:   sandboxrelayd.RelaySocketName,
	relaymux.KindProxy:   sandbox.ProxySocketName,
	relaymux.KindGateway: sandbox.GatewaySocketName,
}

// relayTunnelDial connects one tunnel stream to the run's own host service.
func relayTunnelDial(sockDir string) func(context.Context, string) (io.ReadWriteCloser, error) {
	return func(ctx context.Context, kind string) (io.ReadWriteCloser, error) {
		name, ok := relayTunnelSockets[kind]
		if !ok {
			return nil, fmt.Errorf("no host service for %q", kind)
		}
		var d net.Dialer
		return d.DialContext(ctx, "unix", filepath.Join(sockDir, name))
	}
}
