//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"sync"
	"sync/atomic"

	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
)

// relaySessionClaims is the running relay daemon of this process (nil
// until serveSandboxRelay starts one): the one owner of which run's hooks
// speak for which session, read by credential injection's session fold
// (sandbox_cred_local_fold.go, F-003). nil keeps every stamped turn in its
// run's namespace.
var relaySessionClaims atomic.Pointer[sandboxrelayd.Daemon]

// relaySessionClaim reports whether runID's relayed hooks speak for session
// id in this process's relay daemon, and whether that claim was fresh (the
// node did not record the session when the run first claimed it); false,
// false with no daemon running.
func relaySessionClaim(runID, id string) (claimed, fresh bool) {
	return relaySessionClaims.Load().SessionClaim(runID, id)
}

// relayRunEndHooks run with the id of every run the relay daemon ends
// (relayOnRunEnd), so per-run state kept elsewhere ends with the run.
var (
	relayRunEndMu    sync.Mutex
	relayRunEndHooks []func(runID string)
)

// onRelayRunEnd registers f to run when a relay run ends.
func onRelayRunEnd(f func(runID string)) {
	relayRunEndMu.Lock()
	defer relayRunEndMu.Unlock()
	relayRunEndHooks = append(relayRunEndHooks, f)
}

// relayRunEnded runs the registered hooks for runID.
func relayRunEnded(runID string) {
	relayRunEndMu.Lock()
	hooks := append([]func(string){}, relayRunEndHooks...)
	relayRunEndMu.Unlock()
	for _, f := range hooks {
		f(runID)
	}
}

// relayFreshStoreFactory builds the relay daemon's FreshStore for its
// observer dir (nil: freshness in memory only). The credentials files set
// it (sandbox_cred_local_fold.go), since only an injected local run's
// session fold reads freshness.
var relayFreshStoreFactory func(observerDir string) sandboxrelayd.FreshSessions

// relayFreshStoreFor is the FreshStore for observerDir, nil when none.
func relayFreshStoreFor(observerDir string) sandboxrelayd.FreshSessions {
	if relayFreshStoreFactory == nil {
		return nil
	}
	return relayFreshStoreFactory(observerDir)
}
