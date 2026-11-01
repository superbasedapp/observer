package main

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/policyfam/nodefeatures"
	"github.com/marmutapp/superbased-observer/internal/policyfam/nodefeatures/lkgsidecar"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// launch_terminals_gate.go is the terminals.feature row of the launch gate
// table (OSH-R-003): the org's node.features terminals decision
// (terminals.enabled, sandbox_required) for a launch on the CLI path. The
// daemon's own PTY entries ask the same decision through termsvc's
// TerminalGate (daemonTerminalGate); this row is the CLI path's copy of it,
// so an `observer <tool>` launch, the inner launcher of a dashboard or
// attach PTY, and the launches the daemon starts itself (Arena, benchmark,
// GUI, a box's host-side walk) are judged by the one decision function,
// nodefeatures.TerminalDecision.
//
// A launch the daemon starts reads the daemon's live handle; a standalone
// launcher reads the terminals file the daemon writes beside the database
// (lkgsidecar.TerminalsFile, a sibling of the tools.disallow sidecar so that
// file keeps the shape older binaries decode). A file that is present but cannot be read
// (unreadable, oversize, malformed, written by a newer build) cannot be
// evaluated: on a managed node that refuses the launch (fail closed, the
// org's decision is authoritative there); on an individual node it keeps
// the old fail-open answer. An absent sidecar is "no org body", allowed on
// both, exactly as the daemon's nil spec is.

// unevaluableSidecarReasons are the sidecar read outcomes that say a file is
// there but its content is unknown. Absent and grant-expired are answers
// (no body, an offboarded node), not failures.
var unevaluableSidecarReasons = map[string]bool{
	lkgsidecar.ReasonUnreadable:   true,
	lkgsidecar.ReasonOversize:     true,
	lkgsidecar.ReasonMalformed:    true,
	lkgsidecar.ReasonSchemaTooNew: true,
}

// terminalSidecarVerdict is the CLI path's terminals decision over a
// sidecar read: (allowed, reason). managed is asked only when the sidecar
// cannot be evaluated; granted only when a feature access grant could lift
// a "terminals disabled" refusal (it never lifts sandbox_required).
func terminalSidecarVerdict(f *lkgsidecar.TerminalsFile, readReason string, sandboxed bool, managed func() (bool, error), granted func() (int64, bool)) (bool, string) {
	if unevaluableSidecarReasons[readReason] {
		m, err := managed()
		if err != nil {
			return false, fmt.Sprintf("the organization's terminal policy cannot be checked: %v", err)
		}
		if m {
			return false, fmt.Sprintf("the organization's terminal policy cannot be read on this managed node (%s); start the Observer daemon (observer start) so it rewrites it, or ask your admin", readReason)
		}
		return true, ""
	}
	if f == nil || f.Terminals == nil {
		return true, ""
	}
	spec := &nodefeatures.PolicySpec{Terminals: nodefeatures.TerminalsRule{
		FeatureRule:     nodefeatures.FeatureRule{Governed: true, Enabled: f.Terminals.Enabled},
		SandboxRequired: f.Terminals.SandboxRequired,
	}}
	d := nodefeatures.TerminalDecision(spec, sandboxed)
	if d.Allowed {
		return true, ""
	}
	if nodefeatures.TerminalDecisionEnabled(spec, sandboxed).Allowed && granted != nil {
		if id, ok := granted(); ok && id > 0 {
			return true, fmt.Sprintf("allowed by org grant #%d", id)
		}
	}
	return false, d.Reason
}

// launchNodeManaged reports whether database's node is managed: a managed
// enrolment, or one whose org switched it to enterprise (orgclient.NodeManaged,
// operator rulings P-204 and P-205).
func launchNodeManaged(ctx context.Context, database *sql.DB) (bool, error) {
	if database == nil {
		return false, nil
	}
	return orgclient.NodeManaged(ctx, store.New(database))
}

// sidecarTerminalGate is the terminals decision of a standalone launcher,
// read from the sidecar the config resolves.
func sidecarTerminalGate(r *launchGateRun) (bool, string) {
	f, reason := lkgsidecar.ReadTerminals(lkgsidecar.TerminalsPath(config.ResolveFeaturesSidecarPath(r.cfg, "")))
	return terminalSidecarVerdict(f, reason, r.inSandbox(),
		func() (bool, error) { return launchNodeManaged(r.ctx, r.database) },
		func() (int64, bool) {
			if r.database == nil {
				return 0, false
			}
			return daemonFeatureGrant(store.New(r.database))(nodefeatures.FeatureTerminals)
		})
}

// launchTerminalGate is the row's decision source: the daemon's live handle
// when this process is the daemon, else the sidecar.
func launchTerminalGate(r *launchGateRun) (bool, string) {
	if processNodeFeatures.Load() != nil {
		return daemonTerminalGate(r.inSandbox())
	}
	return sidecarTerminalGate(r)
}

// gateTerminalFeature refuses a launch the org's terminals decision refuses.
func gateTerminalFeature(r *launchGateRun) launchGateStep {
	if r.terminalGate == nil {
		return launchGateStep{}
	}
	ok, reason := r.terminalGate(r)
	if ok {
		return launchGateStep{}
	}
	msg := fmt.Sprintf("observer %s: refusing to start the AI process: %s", r.tool, reason)
	return launchGateStep{refuse: newVisibleLauncherError(fmt.Errorf("%s", msg), msg)}
}
