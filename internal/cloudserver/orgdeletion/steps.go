package orgdeletion

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
)

// Step is a driver position: the step column of org_deletion_requests and
// account_deletion_followups.
type Step string

// The org deletion steps, in table order, then the cancel path.
const (
	StepAnnounce      Step = "announce"
	StepCoolingOff    Step = "cooling_off"
	StepCancelBilling Step = "cancel_billing"
	StepFence         Step = "fence"
	StepAwaitHost     Step = "await_host"
	StepFinalize      Step = "finalize"
	StepRestore       Step = "restore"
	// StepDone is the finished position of both tables.
	StepDone Step = "done"
)

// The account follow-up steps, in table order.
const (
	StepPersonalOrg     Step = "personal_org"
	StepMemberships     Step = "memberships"
	StepDeactivate      Step = "deactivate"
	StepAwaitDeactivate Step = "await_deactivate"
	StepDeleteIdentity  Step = "delete_identity"
	StepFinish          Step = "finish"
)

// The request states (org_deletion_requests.state): the word the console
// shows.
const (
	StateCoolingOff = "cooling_off"
	StateCanceled   = "canceled"
	StatePurging    = "purging"
	StateDone       = "done"
	StateBlocked    = "blocked"
)

// StepRow is one row of a step table.
type StepRow struct {
	// Step is the position.
	Step Step
	// Next is where an advance moves the request.
	Next Step
	// Why says what the step does.
	Why string
}

// OrgSteps is the org deletion step table in order (the cancel path's
// restore row last). One test case per row. A function, so no caller can
// change it.
func OrgSteps() []StepRow {
	return []StepRow{
		{StepAnnounce, StepCoolingOff, "move the org to pending_deletion at a new generation and tell its host (set_state)"},
		{StepCoolingOff, StepCancelBilling, "wait until purge_after; the owner may cancel until then"},
		{StepCancelBilling, StepFence, "cancel the org's live subscription through the billing seam (no live subscription: nothing to do)"},
		{StepFence, StepAwaitHost, "journal the org, then move it to purging, evict its runtimes, queue purged behind, disable its OIDC client"},
		{StepAwaitHost, StepFinalize, "wait until the host acked purged: its fenced purge of every store completed"},
		{StepFinalize, StepDone, "record the org purged, remove its memberships, journal done"},
		{StepRestore, StepDone, "a canceled request: the org back to active at a new generation"},
	}
}

// AccountSteps is the account follow-up step table in order. One test case
// per row.
func AccountSteps() []StepRow {
	return []StepRow{
		{StepPersonalOrg, StepMemberships, "open the personal org's deletion with no window (or bring an open one forward)"},
		{StepMemberships, StepDeactivate, "remove every membership of the account"},
		{StepDeactivate, StepAwaitDeactivate, "queue members_deactivate for every org the subject signed in to and leave each team org's admins a notice"},
		{StepAwaitDeactivate, StepDeleteIdentity, "wait until every members_deactivate intent was acked (blocked after the grace period)"},
		{StepDeleteIdentity, StepFinish, "delete the WorkOS user (not found is success)"},
		{StepFinish, StepDone, "forget the subjects; the follow-up is done"},
	}
}

// stepPattern is the SQL CHECK on both step columns (cloud 0120).
var stepPattern = regexp.MustCompile(`^[a-z_]{1,40}$`)

// next returns the row's next step in table.
func next(table []StepRow, s Step) (Step, error) {
	for _, r := range table {
		if r.Step == s {
			return r.Next, nil
		}
	}
	return "", fmt.Errorf("orgdeletion: step %q is not in the table", s)
}

// remaining returns the steps from s to the end of the table's main path (the
// rows before restore), s included; the whole path for "".
func remaining(table []StepRow, s Step) []Step {
	var out []Step
	started := s == ""
	for _, r := range table {
		if r.Step == StepRestore {
			break
		}
		if r.Step == s {
			started = true
		}
		if started {
			out = append(out, r.Step)
		}
	}
	return out
}

// validateTables checks both tables: every step and next fits the SQL CHECK,
// no step repeats, every next is a step of the table or done.
func validateTables() error {
	for name, table := range map[string][]StepRow{"org": OrgSteps(), "account": AccountSteps()} {
		seen := map[Step]bool{}
		for _, r := range table {
			if !stepPattern.MatchString(string(r.Step)) || !stepPattern.MatchString(string(r.Next)) {
				return fmt.Errorf("orgdeletion: %s step %q or its next %q does not fit the step column", name, r.Step, r.Next)
			}
			if seen[r.Step] {
				return fmt.Errorf("orgdeletion: %s step %q repeats", name, r.Step)
			}
			seen[r.Step] = true
		}
		for _, r := range table {
			if r.Next != StepDone && !slices.ContainsFunc(table, func(x StepRow) bool { return x.Step == r.Next }) {
				return fmt.Errorf("orgdeletion: %s step %q moves to unknown step %q", name, r.Step, r.Next)
			}
		}
	}
	return nil
}

// OutcomeKind is what one step run came to.
type OutcomeKind string

// The outcome kinds.
const (
	// OutcomeAdvance: the step finished; the request moves to the next step
	// (a transition step's store method has already moved it).
	OutcomeAdvance OutcomeKind = "advance"
	// OutcomeWait: nothing is wrong; run the step again at Until.
	OutcomeWait OutcomeKind = "wait"
	// OutcomeBlock: a named reason staff must clear; the request stays.
	OutcomeBlock OutcomeKind = "block"
	// OutcomeRetry: the step failed; run it again after the backoff.
	OutcomeRetry OutcomeKind = "retry"
)

// ClassedError is a step failure with an enum-like class for the
// last_error_class column (never a message that could carry data).
type ClassedError struct {
	Class string
	Err   error
}

// Error describes the failure.
func (e *ClassedError) Error() string { return e.Class + ": " + e.Err.Error() }

// Unwrap returns the cause.
func (e *ClassedError) Unwrap() error { return e.Err }

// Classed wraps err with class.
func Classed(class string, err error) error {
	if err == nil {
		return nil
	}
	return &ClassedError{Class: class, Err: err}
}

// classPattern is the SQL CHECK on last_error_class and blocked_reason.
var classPattern = regexp.MustCompile(`^[a-z0-9_:.-]{1,80}$`)

// ClassOf returns err's class: a ClassedError's when it fits the column,
// else "internal".
func ClassOf(err error) string {
	var c *ClassedError
	if errors.As(err, &c) && classPattern.MatchString(c.Class) {
		return c.Class
	}
	return "internal"
}

// ErrSeamUnwired is returned by a billing or identity seam this deployment
// has not wired. The step blocks with a named reason instead of retrying.
var ErrSeamUnwired = errors.New("orgdeletion: the seam is not wired on this deployment")

// ErrBillingRefused is wrapped by a billing seam whose provider refused the
// cancellation for a reason a retry cannot fix (a 4xx other than a rate
// limit, a subscription id the provider does not accept). The step blocks
// with [ReasonBillingRefused] so staff see it instead of an hourly retry.
var ErrBillingRefused = errors.New("orgdeletion: the billing provider refused the cancellation")

// The block reasons (blocked_reason; enum words).
const (
	ReasonBillingSeamUnwired  = "billing_seam_unwired"
	ReasonBillingRefused      = "billing_cancel_refused"
	ReasonIdentitySeamUnwired = "identity_seam_unwired"
	ReasonHostRefused         = "host_refused"
	ReasonHostPurgeOverdue    = "host_purge_overdue"
	ReasonDeactivateOverdue   = "deactivation_overdue"
	ReasonDeactivateRefused   = "deactivation_refused"
	// ReasonFollowupUnverified: an account follow-up row does not match a
	// finished account deletion of its account, or names a personal org the
	// account did not create (FR-12). Nothing is removed or purged for it.
	ReasonFollowupUnverified = "followup_unverified"
)

// The wait classes (last_error_class while a step waits; enum words): why
// await_host is still waiting, so staff see more than a silent poll (FR-23).
const (
	// WaitHostAckPending: the purged intent is queued and not yet answered.
	WaitHostAckPending = "host_ack_pending"
	// WaitHostIntentMissing: no purged intent is in the outbox.
	WaitHostIntentMissing = "host_intent_missing"
)

// HostWaitClass names a waiting host step's reason: the outbox's own error
// class when it has one ("host:" + class, when it fits the column), else
// pending or missing.
func HostWaitClass(ack HostAck) string {
	switch {
	case !ack.Queued:
		return WaitHostIntentMissing
	case ack.Class != "" && classPattern.MatchString("host:"+ack.Class):
		return "host:" + ack.Class
	}
	return WaitHostAckPending
}
