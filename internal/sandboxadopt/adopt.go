package sandboxadopt

import "time"

// Action is what the daemon does with one container of this install whose
// host helper is gone.
type Action string

// The closed Action vocabulary.
const (
	// ActionOffer keeps the run and offers it for re-adoption (the
	// dashboard and `observer sandbox runs`) until the bound.
	ActionOffer Action = "offer"
	// ActionHold keeps the run while an update waits on live runs: it
	// counts as live and its bound does not run out (SBX-UPD deferral).
	ActionHold Action = "hold"
	// ActionReap ends the run and removes the container, as before this
	// package existed.
	ActionReap Action = "reap"
)

// Code names why a decision was taken. The values are stable: they are
// shown on the CLI and the dashboard and recorded on the run.
type Code string

// The closed Code vocabulary.
const (
	CodeOffered            Code = "readopt_offered"
	CodeHeldForUpdate      Code = "readopt_held_update_deferred"
	CodeRecordMissing      Code = "record_missing"
	CodeRecordNotOwned     Code = "record_not_owned"
	CodePlanMissing        Code = "plan_missing"
	CodeNotThisInstall     Code = "labels_mismatch"
	CodeNotRunning         Code = "not_running"
	CodeCLIRun             Code = "cli_run"
	CodeEngineEndsRun      Code = "engine_mode_ends_run"
	CodeBuiltBelowPlan     Code = "built_below_plan"
	CodeProtectedChanged   Code = "protected_paths_changed"
	CodeDeclined           Code = "declined"
	CodeBoundExpired       Code = "bound_expired"
	CodeComponentInactive  Code = "component_inactive"
	CodeSocketDirUnusable  Code = "socket_dir_unusable"
	CodeRestoreLostCapture Code = "restore_lost_capture"
)

// DefaultBound is how long a run nobody re-adopts is kept before it is
// reaped as before (decision 1 of lane GATES-SBX: 10 minutes).
const DefaultBound = 10 * time.Minute

// CheckpointRetention is how long a checkpointed run (its re-keyed relay
// record and its export, up to the cap) is kept waiting for a restore while
// the component is on; the daemon's sweep then removes both (audit F9).
const CheckpointRetention = 24 * time.Hour

// The bound's limits.
const (
	MinBound = time.Minute
	MaxBound = 24 * time.Hour
)

// ClampBound applies the default to zero and keeps a bound in its limits.
func ClampBound(d time.Duration) time.Duration {
	switch {
	case d <= 0:
		return DefaultBound
	case d < MinBound:
		return MinBound
	case d > MaxBound:
		return MaxBound
	}
	return d
}

// Facts are what the caller read about one container whose host helper is
// gone. Every field is a fact; nothing here is a wish.
type Facts struct {
	// Active: the re-adoption component is selected on this node.
	Active bool
	// RecordIntact: the kept run facts were read and parsed.
	RecordIntact bool
	// RecordOwned: they are owner-only files of this user, read without
	// following a link.
	RecordOwned bool
	// PlanKept: the run's plan (its bind plan and host services) was kept
	// when the run started.
	PlanKept bool
	// LabelsMatch: the container carries this install's labels and this
	// run's id.
	LabelsMatch bool
	// Running: the engine reports the container running.
	Running bool
	// CLIRun: the run belongs to a sandboxed CLI launch, whose own process
	// owns the terminal (its stored row is ended with process_gone).
	CLIRun bool
	// Engine is the engine's own word on its mode.
	Engine EngineFacts
	// ReadBackOK is the existing read-back of the live container against
	// the kept plan; ReadBackReason is its refusal.
	ReadBackOK     bool
	ReadBackReason string
	// ProtectedIntact: the run's protected paths are still read-only in
	// the container and the per-run socket dir is the run's own.
	ProtectedIntact bool
	ProtectedReason string
	// Declined: the user chose to end the run instead.
	Declined bool
	// UpdateDeferred: an update apply is deferred for live sandboxed runs.
	UpdateDeferred bool
	// OfferedAt is when the run was first offered (zero: now).
	OfferedAt time.Time
	Now       time.Time
	Bound     time.Duration
}

// Decision is the outcome for one container.
type Decision struct {
	Action Action
	Code   Code
	Reason string
	// Expires is when an offered run is reaped (zero unless offered).
	Expires time.Time
}

// rule is one row of the decision table: when match holds, the action and
// code apply; reason renders the line shown to the user.
type rule struct {
	name   string
	match  func(Facts) bool
	action Action
	code   Code
	reason func(Facts) string
}

func fixed(s string) func(Facts) string { return func(Facts) string { return s } }

// rules is walked top-down; the first row that matches decides. A run that
// passes every refusal row is held while an update waits on it, reaped
// once its bound ran out, and otherwise offered.
var rules = []rule{
	{
		"component off", func(f Facts) bool { return !f.Active }, ActionReap, CodeComponentInactive,
		fixed("re-adoption is off on this node (terminals.sandbox.oci.readopt), so the run ends as before"),
	},
	{
		"record missing", func(f Facts) bool { return !f.RecordIntact }, ActionReap, CodeRecordMissing,
		fixed("the run's kept record is missing or unreadable"),
	},
	{
		"record not owned", func(f Facts) bool { return !f.RecordOwned }, ActionReap, CodeRecordNotOwned,
		fixed("the run's kept record is not an owner-only file of this user"),
	},
	{
		"plan missing", func(f Facts) bool { return !f.PlanKept }, ActionReap, CodePlanMissing,
		fixed("the run's plan was not kept when it started (it started before re-adoption was on)"),
	},
	{
		"labels", func(f Facts) bool { return !f.LabelsMatch }, ActionReap, CodeNotThisInstall,
		fixed("the container does not carry this install's and this run's labels"),
	},
	{
		"not running", func(f Facts) bool { return !f.Running }, ActionReap, CodeNotRunning,
		fixed("the container is not running"),
	},
	{
		"cli run", func(f Facts) bool { return f.CLIRun }, ActionReap, CodeCLIRun,
		fixed("a sandboxed CLI launch owns its terminal; it ends as before and its tool's own resume applies"),
	},
	{
		"engine mode", func(f Facts) bool { keeps, _ := EngineKeeps(f.Engine); return !keeps }, ActionReap, CodeEngineEndsRun,
		func(f Facts) string { _, why := EngineKeeps(f.Engine); return why },
	},
	{
		"read-back", func(f Facts) bool { return !f.ReadBackOK }, ActionReap, CodeBuiltBelowPlan,
		func(f Facts) string { return "the container no longer matches its plan: " + f.ReadBackReason },
	},
	{
		"protected paths", func(f Facts) bool { return !f.ProtectedIntact }, ActionReap, CodeProtectedChanged,
		func(f Facts) string { return "the run's protected paths or socket dir changed: " + f.ProtectedReason },
	},
	{
		"declined", func(f Facts) bool { return f.Declined }, ActionReap, CodeDeclined,
		fixed("you chose to end the run"),
	},
	{
		"update deferred", func(f Facts) bool { return f.UpdateDeferred }, ActionHold, CodeHeldForUpdate,
		fixed("an update waits on live sandboxed runs; this run counts as live until it is re-adopted or ended"),
	},
	{
		"bound", func(f Facts) bool { return !f.Now.Before(expiry(f)) }, ActionReap, CodeBoundExpired,
		fixed("nobody re-adopted the run in time, so it ends as before"),
	},
}

func expiry(f Facts) time.Time {
	at := f.OfferedAt
	if at.IsZero() {
		at = f.Now
	}
	return at.Add(ClampBound(f.Bound))
}

// Decide walks the table for one container.
func Decide(f Facts) Decision {
	for _, r := range rules {
		if r.match(f) {
			d := Decision{Action: r.action, Code: r.code, Reason: r.reason(f)}
			if r.action == ActionHold {
				d.Expires = expiry(f)
			}
			return d
		}
	}
	return Decision{
		Action: ActionOffer, Code: CodeOffered, Expires: expiry(f),
		Reason: "the container is still running and matches its plan; re-adopt it with `observer sandbox readopt <run>`",
	}
}

// CountsLive reports whether a decision keeps the run in the live-run count
// (the restart and update gate).
func (d Decision) CountsLive() bool { return d.Action == ActionOffer || d.Action == ActionHold }

// RingMarker is the first line of a re-adopted run's terminal: the
// scrollback before the re-adoption is gone, and capture resumes at the
// next event.
const RingMarker = "[observer] This sandboxed run was re-adopted after its helper went away. " +
	"Earlier output is not shown (the scrollback starts empty), and capture resumes at the next event; " +
	"the gap is recorded on the run."
