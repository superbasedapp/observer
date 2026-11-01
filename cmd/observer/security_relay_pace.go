//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// security_relay_pace.go paces the dependency scan's relay batches to the
// org relay's own per-node budget (SECP-26, lane LEFT-SHARED): half of the
// rate the relay last sent (orgcontract.SecurityLookupPerMinuteHeader), so
// an org that lowered its rate is not driven into the 429 path; until a
// relay sends one (an older server) half of the default, as before.

// depsRelayPerMinute is the per-node budget the relay last sent, 0 when
// none (a test swaps it).
var depsRelayPerMinute = orgclient.SecurityRelayPerMinute

// depsRelayIntervalFor is the pause between two scan batches for a per-node
// budget (pure): a minute over half the budget, so the bucket refills faster
// than the scan drains it; the default budget when perMinute is not known.
func depsRelayIntervalFor(perMinute int) time.Duration {
	if perMinute <= 0 {
		perMinute = orgcontract.SecurityLookupDefaultPerMinute
	}
	half := perMinute / 2
	if half < 1 {
		return 2 * time.Minute / time.Duration(perMinute)
	}
	return time.Minute / time.Duration(half)
}

// depsRelayInterval is the pause in force now.
func depsRelayInterval() time.Duration { return depsRelayIntervalFor(depsRelayPerMinute()) }
