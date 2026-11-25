//go:build (linux || darwin) && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"net"
	"path/filepath"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
)

// serveRelay starts the box side of the capture relay for the run h names:
// it reads the host run record, writes the box record into the socket dir
// (bound read-only in the box), and serves relay.sock with the forwarder,
// peer credentials checked (sandboxrelayd.PeerSameUser: SO_PEERCRED on
// Linux, LOCAL_PEERCRED on macOS). The returned stop removes the run
// record. The bwrap helper (sandbox_helpers_linux.go), the re-adopt helper
// and the macOS helper (terminal_sandbox_macdriver_darwin.go) share it.
func serveRelay(ctx context.Context, h sandbox.HostArgs) (func(), error) {
	rec, err := sandboxrelayd.ReadRun(h.ObserverDir, h.RelayRun)
	if err != nil {
		return nil, err
	}
	// The run's liveness lock, held for this helper's life: if it is
	// killed with SIGKILL the kernel drops the lock and the daemon's sweep
	// ends the run (its session claims, its record) without a restart
	// (P-040). A lock that cannot be taken keeps the earlier rule (the run
	// lives while its record does), so it does not fail the launch.
	unhold, herr := sandboxrelayd.HoldRun(h.ObserverDir, h.RelayRun)
	if herr != nil {
		unhold = func() {}
	}
	if err := sandboxrelayd.WriteBoxRecord(h.SockDir, rec); err != nil {
		unhold()
		return nil, err
	}
	ln, err := net.Listen("unix", filepath.Join(h.SockDir, sandboxrelayd.RelaySocketName))
	if err != nil {
		unhold()
		return nil, err
	}
	fw := &sandboxrelayd.Forwarder{
		Run:        rec,
		DialDaemon: dialSandboxRelay(h.ObserverDir),
		DaemonAddr: sandboxRelayAddr(h.ObserverDir),
		Rules:      relayRules,
		Peer:       sandboxrelayd.PeerSameUser,
		// Continuous hook verification (sandbox plan section 5.2): the
		// launch's registration is read now, before the box is released,
		// and again on a timer and before each spooled replay.
		HookProbe: relayHookProbe(rec),
	}
	fw.ReadLaunchHooks()
	go func() { _ = fw.Serve(ctx, ln) }()
	return func() {
		_ = ln.Close()
		_ = sandboxrelayd.RemoveRun(h.ObserverDir, h.RelayRun)
		unhold()
	}, nil
}
