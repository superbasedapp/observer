package dashapi

import (
	"errors"
	"time"
)

// Errors the cmd adapter maps a GUI launch failure onto, so the handler can
// pick an honest status without importing termsvc.
var (
	// ErrLaunchGUIUnsupported signals the daemon has no GUI-spawn seam wired
	// (501) - the feature is absent on this build/config, the same class as
	// ErrLaunchUnsupported for the PTY seam. Never a silent fallback.
	ErrLaunchGUIUnsupported = errors.New("GUI launch is not configured on this daemon")
	// ErrLaunchGUINotLaunchable signals the id is not an ADVERTISED GUI launch
	// row (400): unknown, UNVERIFIED (no grounded executable), or a product the
	// harness lifecycle policy no longer advertises.
	ErrLaunchGUINotLaunchable = errors.New("no launchable IDE or desktop app with this id")
)

// GUILaunchSpec is the dashboard's server-derived GUI launch request. ID is the
// client's only free input and is a registry MAP KEY (never argv); ProjectRoot
// is the one client-influenced path and is canonicalized + allow-list-checked
// by the application service before the spawn. Deliberately absent, because a
// GUI launch has none of them: Subcommand (there is no `observer <verb>`),
// Model, Sandbox, WorkspaceSource, Rows/Cols (there is no PTY).
type GUILaunchSpec struct {
	ID          string
	ProjectRoot string
	// Initiator and ParentSessionID: who started this launch (lane cli-2),
	// as FreshLaunchSpec. Additive.
	Initiator       string
	ParentSessionID string
}

// GUILaunchResult is what a successful GUI launch returns. There is no handle:
// a detached app has no PTY for the browser to dock, so the response is a
// receipt (what started, with which pid, and whether routing actually reached
// it) rather than a terminal token.
type GUILaunchResult struct {
	RunID       string
	PID         int
	ID          string
	Label       string
	WrapApplied bool
	WrapNote    string
	// WrapReason is the structured cause when WrapApplied is false (the
	// guilaunch.WrapReason closed vocabulary); empty when applied.
	WrapReason string
	Notes      []string
}

// GUIRunInfo is one row of the live GUI-run list on GET /api/terminal/sessions.
// It is NOT a LaunchInfo: there is no handle, no viewer count, no writer
// holder, no geometry - a detached app has none of those. Exited rows are
// retained for the daemon's lifetime (bounded), because "the app I launched has
// since been closed" is the useful answer.
type GUIRunInfo struct {
	RunID       string    `json:"run_id"`
	ID          string    `json:"id"`
	Label       string    `json:"label"`
	PID         int       `json:"pid"`
	LaunchedAt  time.Time `json:"launched_at"`
	WrapApplied bool      `json:"wrap_applied"`
	WrapNote    string    `json:"wrap_note"`
	// Notes are the launch-composition advisories (the packaged-app / open(1)
	// launcher-stub pid caveat, an ignored project directory) so the run list
	// never shows a bare "exited (1)" for a stub whose app is still running.
	// Always a real array on the wire - never null - like Hosts.
	Notes    []string `json:"notes"`
	Exited   bool     `json:"exited"`
	ExitCode int      `json:"exit_code"`
}
