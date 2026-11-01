//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"io/fs"
	"os"
	"path/filepath"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote/relaymux"
)

// sandbox_relaytunnel.go is the host half of the capture relay's tunnel
// into a VM-class box (one owner, lane SBX-P4): the Apple container row
// dials the socket its guest publishes (--publish-socket), the microVM row
// dials the guest's AF_VSOCK port through Cloud Hypervisor's hybrid vsock
// socket. Either way the guest listens, this side dials, runs the relay
// mux's home side over the connection (the relay, the proxy and the
// gateway as the run's tier allows, under per-run keyed frames, home side
// first) and dials again when a session ends.

// relayTunnelKinds are the connection kinds the run's host services offer
// the box through the tunnel: the relay always, the model proxy when its
// forward is serving, the gateway when the tier has one.
func relayTunnelKinds(sockDir string, gateway bool) map[string]bool {
	k := map[string]bool{relaymux.KindRelay: true}
	if fi, err := os.Lstat(filepath.Join(sockDir, sandbox.ProxySocketName)); err == nil && fi.Mode()&fs.ModeSocket != 0 {
		k[relaymux.KindProxy] = true
	}
	if gateway {
		k[relaymux.KindGateway] = true
	}
	return k
}
