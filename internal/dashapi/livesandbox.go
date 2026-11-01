package dashapi

import (
	"context"
	"errors"
	"time"
)

// livesandbox.go is the dashboard's seam onto the daemon's live sandboxed
// runs (sandbox plan v2 section 5.5, ledger SBX-UPD-1). A dashboard restart
// with a live sandboxed run asks instead of ending it: the restart route
// answers 409 live_sandboxed_runs with the runs, and the dialog's two answers
// ("end the runs and restart", "restart when they finish") come back through
// this seam. cmd implements it over the terminal service; nil (the default,
// and every build without the terminal stack) keeps the restart route
// exactly as it was.

// ErrRestartUnsupported is the restart refusal of a process that cannot
// re-exec itself (a native Windows daemon). The restart route answers it 501,
// and before it ends any live sandboxed run for an "end and restart" answer
// (Options.RestartPreflight), so no run is ended for a restart that cannot
// happen.
var ErrRestartUnsupported = errors.New("restart from the dashboard is not supported on this OS - relaunch the daemon manually")

// Live-run answers the restart route accepts in its POST body
// ({"live_runs": "<answer>"}).
const (
	// LiveRunsEnd ends the live sandboxed runs, then restarts.
	LiveRunsEnd = "end"
	// LiveRunsWhenFinished schedules the restart for when the count of live
	// sandboxed runs reaches zero (cancellable).
	LiveRunsWhenFinished = "when_finished"
	// LiveRunsCancel cancels a pending restart and a pending update apply.
	LiveRunsCancel = "cancel"
	// LiveRunsEndOnly ends the live sandboxed runs and does not restart (the
	// CLI's `--end-sandboxed-runs` before a systemctl restart or a component
	// change).
	LiveRunsEndOnly = "end_only"
	// LiveRunsApplyWhenFinished asks a deferred update apply to run again
	// when the count reaches zero.
	LiveRunsApplyWhenFinished = "apply_when_finished"
)

// LiveRunsErrorCode is the 409 error code of a restart refused because
// sandboxed runs are live.
const LiveRunsErrorCode = "live_sandboxed_runs"

// LiveRunsHeader carries the live sandboxed run count on GET and POST
// /api/admin/restart whenever the seam is wired, so the CLI can tell a
// daemon with none from a daemon that predates the question (which sends no
// header).
const LiveRunsHeader = "X-Observer-Live-Sandboxed-Runs"

// LiveSandboxRun is one live sandboxed run as the question shows it.
type LiveSandboxRun struct {
	RunID        string `json:"run_id"`
	Tool         string `json:"tool"`
	Backend      string `json:"backend"`
	AgeSeconds   int64  `json:"age_seconds"`
	NativeResume bool   `json:"native_resume"`
}

// LiveSandboxRunsState is the seam's snapshot.
type LiveSandboxRunsState struct {
	// Runs are the live sandboxed runs, oldest first.
	Runs []LiveSandboxRun
	// RestartPending is set while a "restart when they finish" waits;
	// RestartPendingSince is when it was chosen.
	RestartPending      bool
	RestartPendingSince time.Time
	// UpdateDeferred reports that an update apply was deferred for these
	// runs (posture deferred_live_sandbox); UpdatePending that its "apply
	// when they finish" waits.
	UpdateDeferred bool
	UpdatePending  bool
	// Policy is [terminal.sandbox].live_run_update_policy in force ("defer"
	// or "ask_immediately"): how soon a deferred update asks.
	Policy string
}

// LiveSandboxRuns is the daemon's live sandboxed run seam.
type LiveSandboxRuns interface {
	// State reports the live runs and any pending answer.
	State() LiveSandboxRunsState
	// EndRuns ends every live sandboxed run with a recorded reason (native
	// resume stays offered where the tool has it) and returns how many.
	EndRuns(ctx context.Context) (int, error)
	// RestartWhenFinished schedules a restart for when no sandboxed run is
	// live.
	RestartWhenFinished() error
	// CancelPending cancels a pending restart and a pending update apply,
	// reporting whether anything was pending.
	CancelPending() bool
	// ApplyUpdateWhenFinished re-runs the deferred update apply when no
	// sandboxed run is live.
	ApplyUpdateWhenFinished() error
}
