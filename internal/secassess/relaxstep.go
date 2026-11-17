package secassess

import "time"

// relaxstep.go is the lifecycle of one relaxation in force (plan section
// 13.5): a pure transition table the daemon-lifetime reconcile loop and the
// runs list walk, so the decision "create, renew, end" is one table with a test
// row each and no I/O.

// RelaxState is where a relaxation is in its life.
type RelaxState string

// The relaxation states.
const (
	// RelaxPendingBind: a session-scoped approval waiting for the run's
	// terminal to be bound to its session.
	RelaxPendingBind RelaxState = "pending_bind"
	// RelaxActive: the approval row exists and is being renewed.
	RelaxActive RelaxState = "active"
	// RelaxOrgGrant: an org grant covers the rule (nothing to create or
	// renew; it ends at its own expiry).
	RelaxOrgGrant RelaxState = "org_grant"
	// RelaxNotBound: no session was bound in time; the relaxation never took
	// effect and is never widened.
	RelaxNotBound RelaxState = "not_bound"
	// RelaxExisting: a row for the key already existed (the developer's own);
	// it covers the run and is never extended or removed by the run.
	RelaxExisting RelaxState = "existing"
	// RelaxLost: the run's row was changed or removed by someone else; the run
	// stops managing it.
	RelaxLost RelaxState = "lost"
	// RelaxFailed: the row could not be created.
	RelaxFailed RelaxState = "failed"
	// RelaxEnded: over (the closed reason is on the record).
	RelaxEnded RelaxState = "ended"
	// RelaxTierOn: the tier relaxation, in force for the life of the run.
	RelaxTierOn RelaxState = "tier"
)

// The end reasons.
const (
	EndTerminalExit = "terminal_exit"
	EndExpired      = "expired"
	EndCancelled    = "cancelled"
)

// The lifetime constants of a local approval.
const (
	// ShortTTL is how long an approval row lives between renewals: a dead
	// daemon leaves a relaxation for at most this long.
	ShortTTL = 10 * time.Minute
	// BindDeadline is how long a session-scoped relaxation waits for its
	// session.
	BindDeadline = 5 * time.Minute
	// MinGrantWindow is the least time an org grant must still run for a held
	// run to start under it (a grant about to end is not worth a run).
	MinGrantWindow = 10 * time.Minute
	// ReconcileEvery is the reconcile loop's tick.
	ReconcileEvery = time.Minute
	// BindMinConfidence is the correlation confidence only the launcher's
	// out-of-band echo reaches (termrun.SourceOOB); a discovered or heuristic
	// link is below it and never binds a relaxation.
	BindMinConfidence = 0.95
	// ManagedMaxMinutes is the cap on a managed node's window.
	ManagedMaxMinutes = 60
	// MinMinutes and MaxMinutes bound relaxation_max_minutes.
	MinMinutes = 5
	MaxMinutes = 240
)

// StepAction is what the reconcile loop does for a step.
type StepAction string

// The step actions.
const (
	ActionNone   StepAction = "none"
	ActionCreate StepAction = "create"
	ActionRenew  StepAction = "renew"
	ActionDelete StepAction = "delete"
)

// StepInput is what RelaxStep reads for one relaxation.
type StepInput struct {
	State RelaxState
	// Route is self (a local approval) or org_request.
	Route Route
	Now   time.Time
	// LaunchedAt and MaxMinutes give the hard cap.
	LaunchedAt time.Time
	MaxMinutes int
	// TerminalLive: the run's terminal handle is still live.
	TerminalLive bool
	// SessionBound: the terminal resolved to a session at BindMinConfidence.
	SessionBound bool
}

// StepResult is the transition.
type StepResult struct {
	Row       string
	Next      RelaxState
	Action    StepAction
	EndReason string
}

type stepRow struct {
	ID     string
	when   func(StepInput) bool
	next   func(StepInput) RelaxState
	action func(StepInput) StepAction
	reason string
}

func (in StepInput) hardCap() time.Time {
	return in.LaunchedAt.Add(time.Duration(in.MaxMinutes) * time.Minute)
}

func (in StepInput) hasRow() bool {
	return in.Route == RouteSelf && in.State == RelaxActive
}

func same(in StepInput) RelaxState { return in.State }

func ended(StepInput) RelaxState { return RelaxEnded }

func deleteIfRow(in StepInput) StepAction {
	if in.hasRow() {
		return ActionDelete
	}
	return ActionNone
}

func none(StepInput) StepAction { return ActionNone }

// closedStates never change again.
func closedState(s RelaxState) bool {
	switch s {
	case RelaxEnded, RelaxNotBound, RelaxExisting, RelaxLost, RelaxFailed:
		return true
	}
	return false
}

// stepRows is THE reconcile table, first match wins.
var stepRows = []stepRow{
	{"S1", func(in StepInput) bool { return closedState(in.State) }, same, none, ""},
	{"S2", func(in StepInput) bool { return !in.TerminalLive }, ended, deleteIfRow, EndTerminalExit},
	{"S3", func(in StepInput) bool { return !in.Now.Before(in.hardCap()) }, ended, deleteIfRow, EndExpired},
	{"S4", func(in StepInput) bool {
		return in.State == RelaxPendingBind && in.Route == RouteSelf && in.SessionBound
	}, func(StepInput) RelaxState { return RelaxActive }, func(StepInput) StepAction { return ActionCreate }, ""},
	{"S5", func(in StepInput) bool {
		return in.State == RelaxPendingBind && !in.Now.Before(in.LaunchedAt.Add(BindDeadline))
	}, func(StepInput) RelaxState { return RelaxNotBound }, none, ""},
	{"S6", func(in StepInput) bool { return in.hasRow() }, same, func(StepInput) StepAction { return ActionRenew }, ""},
	{"S7", func(StepInput) bool { return true }, same, none, ""},
}

// RelaxStep walks the table for one relaxation.
func RelaxStep(in StepInput) StepResult {
	for _, r := range stepRows {
		if r.when(in) {
			return StepResult{Row: r.ID, Next: r.next(in), Action: r.action(in), EndReason: r.reason}
		}
	}
	return StepResult{Row: "S0", Next: in.State, Action: ActionNone}
}

// StepRowIDs lists the table's row ids (the tests walk it).
func StepRowIDs() []string {
	out := make([]string, 0, len(stepRows))
	for _, r := range stepRows {
		out = append(out, r.ID)
	}
	return out
}

// RenewExpiry is the expiry a renewed row is given: ShortTTL from now, never
// past the hard cap.
func RenewExpiry(now, launchedAt time.Time, maxMinutes int) time.Time {
	exp := now.Add(ShortTTL)
	if hard := launchedAt.Add(time.Duration(maxMinutes) * time.Minute); exp.After(hard) {
		return hard
	}
	return exp
}

// EffectiveMinutes is the window in force: the configured value clamped to the
// bounds, and on a managed or unresolved node capped at ManagedMaxMinutes.
func EffectiveMinutes(t Tenancy, own int) int {
	m := own
	if m < MinMinutes {
		m = MinMinutes
	}
	if m > MaxMinutes {
		m = MaxMinutes
	}
	if t != TenancyIndividual && m > ManagedMaxMinutes {
		m = ManagedMaxMinutes
	}
	return m
}

// EffectiveScope is the scope in force: project only on an individual node that
// asked for it, session everywhere else.
func EffectiveScope(t Tenancy, own string) string {
	if t == TenancyIndividual && own == ScopeProject {
		return ScopeProject
	}
	return ScopeSession
}
