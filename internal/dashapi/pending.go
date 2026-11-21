package dashapi

import (
	"context"
	"time"
)

// pending.go is the dashboard's view of launches the daemon holds for a
// human (lane cli-2 fixes-1, the plans orchestrator's ruling on audit M2:
// "ask on each launch"). When a launch route's caller is attributed to an
// agent, the dashboard does not start the launch: it hands the daemon a
// hold whose action replays that exact request, and answers 202 with the
// hold. A human confirms it on the Terminals page or with `observer
// terminals confirm <id>`; it is single use and expires. The daemon owns the
// store (cmd/observer launch_pending.go over internal/agentlaunch.Holds);
// these are plain types so the dashboard compiles without the terminals
// component.

// The initiator a held launch records (internal/termrun's closed set; the
// dashboard cannot import termrun, pinned equal in cmd/observer).
const (
	// InitiatorAgent: an agent session started the launch.
	InitiatorAgent = "agent"
	// InitiatorUnknown: the caller could not be identified.
	InitiatorUnknown = "unknown"
)

// Pending refusal codes (internal/agentlaunch's, repeated for the same
// reason as the initiators above).
const (
	PendingCodeConfirmRequired = "confirm_required"
	PendingCodeTooMany         = "too_many_pending"
	PendingCodeNotFound        = "pending_not_found"
	PendingCodeConfirmRefused  = "confirm_refused"
)

// PendingCodeDuplicateMember is the dashboard's own refusal of an agent's
// launch body that names a member twice under the case folding the launch
// handlers' JSON decode uses (lane cli-2 fixes-3, audit M2): the decode
// keeps the last one, so the confirm card could not say what runs; such a
// body is never held.
const PendingCodeDuplicateMember = "duplicate_member"

// PendingLaunch is one held launch: what a human confirms, with every
// field the held request is bound to in Details (agentlaunch.Pending's
// rules: environment by name only, secret-looking values masked).
type PendingLaunch struct {
	ID string `json:"id"`
	// Front is where the launch was asked for: dashboard or cli.
	Front string `json:"front"`
	// What is the one line a human confirms.
	What    string `json:"what"`
	Tool    string `json:"tool,omitempty"`
	Project string `json:"project,omitempty"`
	Sandbox string `json:"sandbox,omitempty"`
	// Details are every field the held request is bound to, in order
	// (lane cli-2 fixes-2): the confirm card shows them all.
	Details []PendingLaunchDetail `json:"details,omitempty"`
	// Initiator and ParentSessionID are what the launch will record.
	Initiator       string    `json:"initiator"`
	ParentSessionID string    `json:"parent_session_id,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	ExpiresAt       time.Time `json:"expires_at"`
}

// PendingLaunchDetail is one bound field of a held launch.
type PendingLaunchDetail struct {
	Label string `json:"label"`
	Value string `json:"value"`
	Warn  bool   `json:"warn,omitempty"`
}

// PendingLaunchResult is what starting a held launch answered: the replayed
// request's status, content type and body (a JSON document).
type PendingLaunchResult struct {
	Status      int
	ContentType string
	Body        []byte
}

// PendingLaunchError is a coded refusal of a hold, confirm or reject.
type PendingLaunchError struct {
	Code    string
	Message string
}

// Error implements error.
func (e *PendingLaunchError) Error() string { return e.Message }

// PendingLaunches is the daemon's store of held launches as the dashboard
// uses it.
type PendingLaunches interface {
	// Hold records a launch and the action that starts exactly it.
	Hold(p PendingLaunch, start func(ctx context.Context) (PendingLaunchResult, error)) (PendingLaunch, error)
	// List returns the live holds, oldest first.
	List() []PendingLaunch
	// Confirm starts a held launch once, for a confirming caller of the
	// given initiator (an agent is refused, confirm_refused).
	Confirm(ctx context.Context, id, confirmerInitiator string) (PendingLaunch, PendingLaunchResult, error)
	// Reject drops a held launch without starting it.
	Reject(id string) (PendingLaunch, error)
}
