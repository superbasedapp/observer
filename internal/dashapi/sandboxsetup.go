package dashapi

import (
	"context"
	"errors"
)

// Sandbox installation lifecycle (plan of record
// docs/plans/sandbox-installation-lifecycle-plan-2026-11-06.md, section 3.6):
// the wire shapes of the setup routes and the seam the dashboard and the CLI
// call. The planning is internal/sandboxsetup's (pure); the facts, the
// runner and the routes are cmd/observer's.

// SandboxSetupStep is one planned step of a backend's setup.
type SandboxSetupStep struct {
	// Prereq is the prerequisite id (internal/sandboxsetup's table, or the
	// generic "component" and "enable").
	Prereq string `json:"prereq"`
	// Kind is sandboxsetup.Kind.
	Kind  string `json:"kind"`
	Label string `json:"label"`
	// State is sandboxsetup.StepState (done, missing, unknown, blocked,
	// not_applicable, in_flight, not_allowed).
	State string `json:"state"`
	// Class is sandboxsetup.Class after the switches in force (auto,
	// terminal, elevated, guide, never).
	Class string `json:"class"`
	// Channel is sandboxsetup.Channel.
	Channel string `json:"channel"`
	Display string `json:"display,omitempty"`
	// DisplayIsCommand: Display is a command line to paste into a terminal,
	// not a sentence (a surface offers "Copy command" only then).
	DisplayIsCommand bool `json:"display_is_command,omitempty"`
	// Fields are the credential names a credential step asks for, in the
	// order the provider documents them (E2B_API_KEY; MODAL_TOKEN_ID and
	// MODAL_TOKEN_SECRET; ...). Names only, never a value.
	Fields []string `json:"fields,omitempty"`
	// Command is the CLI form of a credential step (`observer sandbox
	// hosted connect <provider>`), which asks for each field and stores it
	// the same way; a surface shows it where it cannot take the key itself.
	Command    string `json:"command,omitempty"`
	Reason     string `json:"reason,omitempty"`
	Disclosure string `json:"disclosure,omitempty"`
	// Action is the step's button label when its class's own label would
	// not say what it does ("Put the API key in the box"); omitted
	// otherwise, and a surface then labels the button by class.
	Action string `json:"action,omitempty"`
	// After is what the person must do afterwards ("relogin", "reboot",
	// "engine_restart", "daemon_restart").
	After string `json:"after,omitempty"`
	Docs  string `json:"docs,omitempty"`
	// CanRun: a Run button.
	CanRun bool `json:"can_run"`
	// CanUndo: an Undo button.
	CanUndo bool `json:"can_undo"`
	// UndoRefused names what keeps an undo Observer would otherwise offer
	// (live_runs, live_runs_unknown, kill_switch, elevation_off; absent when
	// Undo is offered or there is nothing to undo). The step's reason holds
	// the sentence.
	UndoRefused string `json:"undo_refused,omitempty"`
	// UndoAlso is what an offered Undo changes beyond this row (a step whose
	// one setting every hosted row reads), as a sentence the dashboard shows
	// before the undo runs; absent otherwise.
	UndoAlso string `json:"undo_also,omitempty"`
	// Record is the step's latest install record (subject_kind sandbox).
	Record *ToolInstallRecord `json:"record,omitempty"`
	// Consent is what a pinned download shows before the click.
	Consent *SandboxSetupConsent `json:"consent,omitempty"`
}

// SandboxSetupConsent is a pinned download's consent: shown before the
// click, echoed by the run request.
type SandboxSetupConsent struct {
	Pin     string `json:"pin"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
	Bytes   int64  `json:"bytes"`
	// Source is vendor_release or org_mirror.
	Source string `json:"source"`
	URL    string `json:"url,omitempty"`
}

// SandboxSetupPlan is one backend's ordered setup.
type SandboxSetupPlan struct {
	Backend string             `json:"backend"`
	Label   string             `json:"label"`
	Steps   []SandboxSetupStep `json:"steps"`
	// Next is the index of the first step not done (-1: none).
	Next  int  `json:"next"`
	Ready bool `json:"ready"`
	// Unconfirmed: a passive plan with nothing left Observer can see to do;
	// only the active check can say it is ready ("set up, run Check to
	// confirm").
	Unconfirmed bool `json:"unconfirmed,omitempty"`
	// Blocked is why the row can never run here ("" when it can).
	Blocked string `json:"blocked,omitempty"`
	// Beta is why the backend's setup is beta ("" when it is not); a
	// label only, never a gate (operator ruling P-256).
	Beta string `json:"beta,omitempty"`
	// Checked: the plan follows an active check ("Check this machine").
	Checked bool `json:"checked"`
	// Fingerprint is what a run request must name.
	Fingerprint string `json:"fingerprint"`
}

// SandboxSetupSummary is one offered row on this host.
type SandboxSetupSummary struct {
	Backend string `json:"backend"`
	Label   string `json:"label"`
	Ready   bool   `json:"ready"`
	// Unconfirmed: set up as far as Observer can see without running
	// anything; the active check confirms it.
	Unconfirmed bool   `json:"unconfirmed,omitempty"`
	Blocked     string `json:"blocked,omitempty"`
	// Beta is why the backend's setup is beta ("" when it is not).
	Beta string `json:"beta,omitempty"`
	// Next is the next step's label ("" when ready, unconfirmed or blocked).
	Next string `json:"next,omitempty"`
}

// The closed SandboxSetupRunRequest.Action vocabulary.
const (
	SandboxSetupActionRun    = "run"
	SandboxSetupActionUndo   = "undo"
	SandboxSetupActionUpdate = "update"
	SandboxSetupActionRepair = "repair"
)

// SandboxSetupRunRequest is the body of POST .../setup/{backend}/run. It
// names a step and a plan; every argv is server-derived.
type SandboxSetupRunRequest struct {
	Step string `json:"step"`
	// Action is run, undo, update or repair.
	Action      string               `json:"action"`
	Fingerprint string               `json:"fingerprint"`
	Consent     *SandboxSetupConsent `json:"consent,omitempty"`
	// FromFile is a pinned download's offline path (plan section 6).
	FromFile string `json:"from_file,omitempty"`
	// Key is the typed API key of a hosted_connect step only; never logged,
	// never stored outside the keychain.
	Key string `json:"key,omitempty"`
	// Fields are the typed credential values of a hosted_connect step whose
	// provider needs more than one (keyed by the step's Fields names); never
	// logged, never stored outside the keychain.
	Fields map[string]string `json:"fields,omitempty"`
}

// The closed SandboxSetupStarted.Kind vocabulary.
const (
	SandboxSetupStartedTerminal = "terminal"
	SandboxSetupStartedOp       = "op"
	SandboxSetupStartedDone     = "done"
)

// SandboxSetupStarted is what a run answers.
type SandboxSetupStarted struct {
	// Kind is terminal (a setup PTY), op (an in-process operation) or done.
	Kind string `json:"kind"`
	// Handle is the setup PTY of kind terminal.
	Handle string `json:"handle,omitempty"`
	Label  string `json:"label,omitempty"`
	// OpID is the in-process operation of kind op.
	OpID string `json:"op_id,omitempty"`
	// Plan is the fresh plan of kind done.
	Plan *SandboxSetupPlan `json:"plan,omitempty"`
	// Note is one sentence about the step's effect, when it has one (a
	// [terminal.sandbox] change the running Observer did not confirm).
	Note string `json:"note,omitempty"`
}

// SandboxSetupLiveApplier is the optional half of SandboxSetup a daemon's
// seam implements: ApplyLive makes the daemon's sandbox seams read
// [terminal.sandbox] again now, so a change binds on the next launch without
// a restart. The Settings > Sandbox isolation save calls it after its write,
// and POST /api/terminal/sandbox/setup/<backend>/apply calls it for a CLI.
type SandboxSetupLiveApplier interface {
	ApplyLive(ctx context.Context)
}

// SandboxSetupOp is an in-process operation's progress (a pinned download).
type SandboxSetupOp struct {
	ID string `json:"id"`
	// Status is internal/toolinstall's status vocabulary.
	Status string `json:"status"`
	Done   int64  `json:"done_bytes"`
	Total  int64  `json:"total_bytes"`
	Error  string `json:"error,omitempty"`
}

// SandboxSetup is the seam onto sandbox setup: the dashboard's routes and
// the CLI call it. Options.SandboxSetup nil means it is not in this build
// (the routes answer 501).
type SandboxSetup interface {
	// Summary is one row per offered backend on this host.
	Summary(ctx context.Context) ([]SandboxSetupSummary, error)
	// Plan is a backend's plan from passive facts (no exec, no dial).
	Plan(ctx context.Context, backend string) (SandboxSetupPlan, error)
	// Check runs the active check (the person's click) and returns the
	// plan with checked set.
	Check(ctx context.Context, backend string) (SandboxSetupPlan, error)
	// Run carries out one step. surface is "dashboard" or "cli".
	Run(ctx context.Context, backend string, req SandboxSetupRunRequest, surface string) (SandboxSetupStarted, error)
	// Op reports an in-process operation (ok false: unknown id).
	Op(ctx context.Context, id string) (SandboxSetupOp, bool)
}

// The closed error codes of the setup routes ({"error": ..., "code": ...}).
const (
	SandboxSetupCodePlanChanged         = "plan_changed"
	SandboxSetupCodeNotAllowedByOrg     = "not_allowed_by_org"
	SandboxSetupCodeInstallDisabled     = "install_disabled"
	SandboxSetupCodeElevationDisabled   = "elevation_disabled"
	SandboxSetupCodeConsentRequired     = "consent_required"
	SandboxSetupCodeLiveRuns            = "live_runs"
	SandboxSetupCodeStepNotRunnable     = "step_not_runnable"
	SandboxSetupCodeUnknownStep         = "unknown_step"
	SandboxSetupCodeNotInBuild          = "not_in_build"
	SandboxSetupCodeTerminalUnavailable = "terminal_unavailable"
)

// SandboxSetupCodes is the closed error-code list, in the plan's order.
func SandboxSetupCodes() []string {
	return []string{
		SandboxSetupCodePlanChanged, SandboxSetupCodeNotAllowedByOrg, SandboxSetupCodeInstallDisabled,
		SandboxSetupCodeElevationDisabled, SandboxSetupCodeConsentRequired, SandboxSetupCodeLiveRuns,
		SandboxSetupCodeStepNotRunnable, SandboxSetupCodeUnknownStep, SandboxSetupCodeNotInBuild,
		SandboxSetupCodeTerminalUnavailable,
	}
}

// ErrSandboxSetupNotInBuild is what every method of a build without sandbox
// setup returns (the routes answer 501, code not_in_build).
var ErrSandboxSetupNotInBuild = errors.New("sandbox setup is not in this build")
