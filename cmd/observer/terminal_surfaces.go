package main

import "github.com/marmutapp/superbased-observer/internal/dashapi"

// terminal_surfaces.go is the core view of the terminal stack (lane MP-L1K,
// T-715): what `observer start` and `observer dashboard` read from it, typed
// through dashboard interfaces and two narrow seams so neither file names a
// terminals-component package. buildTerminalSurfaces fills it in a build with
// the terminals component (attach_standalone.go); terminals_omit.go returns
// the zero value (every surface honestly disabled) in a build without it.

// terminalLiveCounter reports how many dashboard terminal sessions are live
// (the update drain counts them). *termsession.Manager satisfies it.
type terminalLiveCounter interface {
	LiveCount() int
}

// terminalManager is what the daemon wiring needs from the ONE shared
// terminal session manager beyond the dashboard's LaunchManager seam.
// *termsession.Manager satisfies it.
type terminalManager interface {
	terminalLiveCounter
	SetOnStandingLocalTakeover(fn func(handle, revokedHolder string))
}

// terminalSurfaces is the decoupled per-surface result start.go consumes: the
// dashboard launch manager (nil unless [handoff].allow_dashboard_launch), its
// status provider, and the attach-socket host (nil unless
// [terminal.attach].enabled), all derived from ONE shared terminal stack,
// plus its single teardown func. A nil field is the honest "surface
// disabled" state for that capability alone; the OTHER surface is
// unaffected.
type terminalSurfaces struct {
	launchMgr    dashapi.LaunchManager
	launchStatus dashapi.TerminalStatusProvider
	// policyStop resolves a dashboard terminal run's node-intervention
	// policy-stop explanation (policystop.go). Populated whenever launchMgr
	// is (the launch manager's gate is the natural gate for this too: a
	// policy stop only ever concerns a dashboard-launched PTY run); nil
	// otherwise, which is the honest "nothing to show" seam state.
	policyStop dashapi.PolicyStopProvider
	attachHost attachSocketHost
	// sandboxProber is the B9 dashapi.SandboxProber (nil only when NO
	// terminal stack was built at all: no PTY backend, or neither surface
	// requested). start.go / dashboard.go wire it into
	// dashapi.Options.SandboxProber; a nil value is the honest "sandbox
	// feature absent" state (endpoint reports disabled, launch validation
	// 501s), and a non-nil holder with the feature switched off reports the
	// same disabled_by_config verdict while staying able to pick a later
	// save up without a restart.
	sandboxProber dashapi.SandboxProber
	// toolInstalls is the dashboard-install record + uninstall seam (nil
	// interface unless the launch manager is wired AND a DB exists).
	toolInstalls dashapi.ToolInstallLedger
	// mgr is the one-owner session manager (nil when no stack was built).
	// Exposed so start.go can register post-construction hooks
	// (SetOnStandingLocalTakeover) and the update drain can count live
	// sessions; the dashboard itself keeps talking through the LaunchManager
	// interface.
	mgr   terminalManager
	close func()
}

// sandboxCountingManager is the terminal manager the surfaces hand out, with
// the terminal service's count of live sandboxed runs beside it (sandbox
// plan v2 section 5.5): the update drain asks for it through an optional
// interface, so a manager without the service answers nothing.
type sandboxCountingManager struct {
	terminalManager
	svc interface{ LiveSandboxedCount() int }
}

// LiveSandboxedCount reports the live sandboxed runs (zero with no service).
func (m sandboxCountingManager) LiveSandboxedCount() int {
	if m.svc == nil {
		return 0
	}
	return m.svc.LiveSandboxedCount()
}
