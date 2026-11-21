//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"net"
	"net/http"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxnet"
)

// sandbox_helpers_credlane_linux.go is the Linux host helper's model-proxy
// forward and the seams of credential injection for LOCAL runs (lane N3,
// SBX-NET-2). The forward is the raw byte pipe it always was, unless this
// helper set up a credential lane for its run (the box env hook below,
// which runs before the box starts): then each box connection goes
// through a stamping hop (sandboxnet.StampHop) that names the run on every
// request, the same headers the hosted relay's home side sets. The seams
// are nil unless the credentials files are compiled
// (sandbox_cred_local_linux.go sets them from init), and each does nothing
// while terminals.sandbox.credentials is not selected.

// localCredBoxEnvHook sets up a local run's credential lane and returns the
// box env with the run's sentinel in the tool's key variable (env unchanged
// when no lane is set up).
var localCredBoxEnvHook func(h sandbox.HostArgs, env []string) []string

// localCredStampHook returns the stamp of runID's lane in this helper, or
// nil when it has none.
var localCredStampHook func(runID string) func(http.Header)

// localCredEndHook ends runID's lane in this helper (its injection record
// removed) when the forward stops.
var localCredEndHook func(runID string)

// localCredBoxEnv applies localCredBoxEnvHook (env unchanged when unset).
func localCredBoxEnv(h sandbox.HostArgs, env []string) []string {
	if localCredBoxEnvHook == nil {
		return env
	}
	return localCredBoxEnvHook(h, env)
}

// serveModelProxyForward serves the run's model-proxy socket ln onto the
// proxy at h.ProxyAddr until ctx is done or the returned stop is called;
// stop closes ln, waits for the forward to end and ends the run's lane.
func serveModelProxyForward(ctx context.Context, ln net.Listener, h sandbox.HostArgs) (stop func()) {
	target := h.ProxyAddr
	dialProxy := func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", target)
	}
	var (
		mu  sync.Mutex
		hop *sandboxnet.StampHop
	)
	// hopFor is the run's stamping hop, built at the first box connection
	// after a lane exists (nil: no lane, the raw pipe).
	hopFor := func() *sandboxnet.StampHop {
		if localCredStampHook == nil {
			return nil
		}
		stamp := localCredStampHook(h.RelayRun)
		if stamp == nil {
			return nil
		}
		mu.Lock()
		defer mu.Unlock()
		if hop == nil {
			hop, _ = sandboxnet.NewStampHop(dialProxy, stamp)
		}
		return hop
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = sandboxnet.ServeForward(ctx, ln, func(ctx context.Context) (net.Conn, error) {
			if hp := hopFor(); hp != nil {
				return hp.Conn()
			}
			return dialProxy(ctx)
		})
		mu.Lock()
		if hop != nil {
			_ = hop.Close()
		}
		mu.Unlock()
		if localCredEndHook != nil {
			localCredEndHook(h.RelayRun)
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			_ = ln.Close()
			<-done
		})
	}
}
