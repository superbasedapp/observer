//go:build !windows && !sbo_omit_terminals_sandbox_apple_container && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"io"
	"net"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxremote/relaymux"
)

// terminal_sandbox_applecontainer_tunnel_notwindows.go holds the Apple
// container driver's tunnel aliases, called only on darwin (and a Linux
// test), so they are excluded from Windows (WINFIX4 lint: unused there).
// appleTunnelKinds stays in terminal_sandbox_applecontainer.go.

// appleTunnelHost is relayTunnelHost (D-A4: the guest's init listens on a
// socket published to the host and this side dials in).
func appleTunnelHost(ctx context.Context, dial func(context.Context) (net.Conn, error), opts relaymux.HostOptions, window time.Duration, connected func(), lost func(error)) {
	relayTunnelHost(ctx, dial, opts, window, connected, lost)
}

// appleTunnelDial is relayTunnelDial.
func appleTunnelDial(sockDir string) func(context.Context, string) (io.ReadWriteCloser, error) {
	return relayTunnelDial(sockDir)
}
