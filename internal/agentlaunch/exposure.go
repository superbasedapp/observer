package agentlaunch

import (
	"fmt"
	"strings"

	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// exposure.go decides whether a live sandboxed run can reach the daemon's
// loopback control plane (security ledger LAUNCH-1). The dashboard's caller
// check (cmd/observer/loopback_caller.go, internal/callerid) uses it to know
// which live boxes could be a loopback caller: while one of them is live, a
// caller the daemon cannot identify is refused, and every caller is refused
// while such a box has no known root process. The attach socket is not
// affected: no box can reach it (bwrap hides its directory, Landlock ABI 9
// denies the connect, the MXC pipe DACL admits no AppContainer, Seatbelt
// denies the observer directory and every unix connect), so `observer
// launch` stays the owner's path while such a run is live.

// BoxRun is one live run's recorded isolation evidence, plain strings from
// termrun.Isolation or terminal_run (migration 179).
type BoxRun struct {
	RunID string
	// Class is the isolation class built ("" or "none": not sandboxed).
	Class string
	// Backend is the outermost backend id ("" when not recorded).
	Backend string
	// Tier is the egress tier the run was built with.
	Tier string
	// HostLoopbackRelay is the backend row's capability that its relay
	// rides the host's loopback (sandboxbackend.RelaySingleLoopbackPortToken,
	// the MXC rows), resolved at the cmd boundary behind the sandbox
	// component's build tag so this package does not link the registry.
	HostLoopbackRelay bool
	// DeniesObserverPorts is the backend row's capability that its own
	// enforcement refuses every Observer listener
	// (sandboxbackend.Network.DeniesObserverPorts, the Landlock row),
	// resolved at the same boundary.
	DeniesObserverPorts bool
	// TreeContained is the backend row's declared capability that every
	// process of its box stays a descendant of the box's root
	// (sandboxbackend.Capability.TreeContained, the bwrap row only: a PID
	// namespace of its own and --die-with-parent). Without it (the MXC rows,
	// whose orphans leave the tree; the OCI rows, whose processes run under
	// the runtime's shim) the caller check cannot use ancestry to clear a
	// caller and refuses every caller while such a box is exposed. Resolved
	// at the same boundary.
	TreeContained bool
	// Marker is the sandboxed CLI launch's watch marker that keeps the run
	// counted ("" for a daemon terminal); the caller names it in the
	// refusal.
	Marker string
}

// exposureRow is one ordered row of the exposure table: a row returns
// (exposed, decided); the first deciding row wins, and a run no row
// decides is not exposed.
type exposureRow struct {
	id     string
	decide func(r BoxRun) (exposed, decided bool)
	why    string
}

// exposureRows are walked top-down (TestLoopbackExposureRows).
var exposureRows = []exposureRow{
	{"X1-not-sandboxed", func(r BoxRun) (bool, bool) {
		return false, r.Class == "" || r.Class == "none"
	}, ""},
	{"X2-observer-ports-denied", func(r BoxRun) (bool, bool) {
		// A row whose own enforcement refuses every Observer listener (the
		// Landlock row's TCP deny list) cannot reach the dashboard, even on
		// the host tier: it does not gate.
		return false, r.DeniesObserverPorts
	}, ""},
	{"X3-host-tier", func(r BoxRun) (bool, bool) {
		// The host tier shares the host's network namespace: bwrap's
		// `egress = "host"` escape hatch (SR27-SBX-2).
		return true, vocab.Tier(r.Tier) == vocab.TierHost
	}, "it shares the host's network (egress tier host)"},
	{"X4-host-loopback-relay", func(r BoxRun) (bool, bool) {
		// A row whose relay rides host loopback (the MXC rows: one port per
		// run, but host loopback inside the box is unrestricted, SBX-BE-15)
		// reaches every loopback listener of the host.
		return true, r.HostLoopbackRelay
	}, "its backend reaches the host's loopback"},
}

// Exposure is a live run that can reach the loopback control plane.
type Exposure struct {
	Run BoxRun
	Why string
	// Rule is the deciding row id.
	Rule string
}

// Reason is the refusal line for a spawn route.
func (e Exposure) Reason() string {
	return fmt.Sprintf("refused while sandboxed run %s is live: %s, so a process inside it could call this dashboard; "+
		"stop that run, or launch with `observer launch` from your own terminal (security ledger LAUNCH-1)", e.Run.RunID, e.Why)
}

// Describe is the exposure as a clause for another refusal line.
func (e Exposure) Describe() string {
	return fmt.Sprintf("sandboxed run %s is live and %s", e.Run.RunID, e.Why)
}

// LoopbackExposure returns the first live run that can reach the daemon's
// loopback control plane.
func LoopbackExposure(runs []BoxRun) (Exposure, bool) {
	all := LoopbackExposures(runs)
	if len(all) == 0 {
		return Exposure{}, false
	}
	return all[0], true
}

// LoopbackExposures returns every live run that can reach the daemon's
// loopback control plane, in input order.
func LoopbackExposures(runs []BoxRun) []Exposure {
	var out []Exposure
	for _, r := range runs {
		r.Backend = strings.TrimSpace(r.Backend)
		for _, row := range exposureRows {
			exposed, decided := row.decide(r)
			if !decided {
				continue
			}
			if exposed {
				out = append(out, Exposure{Run: r, Why: row.why, Rule: row.id})
			}
			break
		}
	}
	return out
}
