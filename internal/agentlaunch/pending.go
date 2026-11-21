package agentlaunch

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/termrun"
)

// pending.go holds an agent's launch for a human (lane cli-2 fixes-1, the
// plans orchestrator's ruling on audit M2; the operator's decision is "ask
// on each launch"). When the daemon attributes a launch to an agent it does
// not start it: it holds the exact request it was asked to make and starts
// it only when a human confirms that one held launch, once, before it
// expires. No grant lets a later launch through (R-168's no-grant rule, on
// the daemon side).
//
// This file is the pure half: the hold and confirm decision tables and the
// in-memory store of held launches (one owner, the daemon; the cmd layer
// supplies the clock, the id source and, per hold, the action that starts
// the launch). A held launch is bound to the exact request by construction:
// its action closes over that request, the store hands the action out
// exactly once, and a confirm names the hold by its id, never by a request.

// DefaultPendingTTL is how long a held launch waits for its confirm.
const DefaultPendingTTL = 10 * time.Minute

// MaxPending bounds the held launches at once, so a caller cannot fill the
// daemon's memory with holds.
const MaxPending = 32

// Hold and confirm refusal codes, beside the launch codes.
const (
	// CodeConfirmRequired: the launch is held for a human's confirm (a
	// result, not a failure: the CLI exits with its own code).
	CodeConfirmRequired = "confirm_required"
	// CodeTooManyPending: MaxPending launches are already held.
	CodeTooManyPending = "too_many_pending"
	// CodePendingNotFound: no held launch has that id (never held,
	// confirmed, rejected or expired).
	CodePendingNotFound = "pending_not_found"
	// CodeConfirmRefused: the confirming caller may not confirm (an
	// agent, a process inside a box, or a caller that is no longer the
	// process that connected).
	CodeConfirmRefused = "confirm_refused"
)

// ErrPendingNotFound is what Take returns for an unknown or expired id.
var ErrPendingNotFound = errors.New("agentlaunch: no held launch with that id (it was confirmed, rejected or expired)")

// holdRow is one ordered row of the hold decision: it decides (true) or
// passes.
type holdRow struct {
	id     string
	decide func(o termrun.Origin) (hold, done bool)
}

// holdRows are walked top-down (TestShouldHoldRows, one case per row).
var holdRows = []holdRow{
	// An agent's launch is held, every time.
	{"P1-agent-held", func(o termrun.Origin) (bool, bool) { return true, o.Initiator == termrun.InitiatorAgent }},
	// An unidentified caller is not held (the owner's browser under WSL2
	// is often unidentified); it is recorded unknown instead.
	{"P2-unknown-runs", func(o termrun.Origin) (bool, bool) { return false, o.Initiator == termrun.InitiatorUnknown }},
	{"P3-human-runs", func(termrun.Origin) (bool, bool) { return false, true }},
}

// ShouldHold reports whether a launch of this origin is held for a human,
// and the deciding row.
func ShouldHold(o termrun.Origin) (bool, string) {
	for _, r := range holdRows {
		if hold, done := r.decide(o.Normalized()); done {
			return hold, r.id
		}
	}
	return false, ""
}

// ConfirmFacts is what the boundary resolved about a confirming caller.
type ConfirmFacts struct {
	// Origin is the confirming caller's attribution (Attribute).
	Origin termrun.Origin
	// InBox: the caller runs inside a live Observer box (the dashboard's
	// caller check, internal/callerid, refuses those before any handler).
	InBox bool
	// CallerGone: the identified caller is no longer the process that
	// connected (CallerPresent: it exited, its pid names another process,
	// or its start could not be read), so its ancestry and environment
	// can no longer be judged (lane cli-2 fixes-3, audit M1). GoneWhy is
	// CallerPresent's line.
	CallerGone bool
	GoneWhy    string
}

// confirmRow is one ordered row of the confirm decision.
type confirmRow struct {
	id     string
	decide func(f ConfirmFacts) (allow, done bool, why string)
}

// confirmRows are walked top-down (TestMayConfirmRows, one case per row).
var confirmRows = []confirmRow{
	// A caller that is gone cannot be judged: a process that connected,
	// handed its connection to a child and exited would otherwise read as
	// a human (audit M1).
	{"K0-caller-gone", func(f ConfirmFacts) (bool, bool, string) {
		return false, f.CallerGone, "the process that connected to confirm is gone (" + f.GoneWhy + "), so the daemon cannot tell whether an agent started it; confirm from a shell that waits for the reply"
	}},
	{"K1-in-box", func(f ConfirmFacts) (bool, bool, string) {
		return false, f.InBox, "a process inside an Observer sandbox may not confirm a launch"
	}},
	{"K2-agent", func(f ConfirmFacts) (bool, bool, string) {
		return false, f.Origin.Normalized().Initiator == termrun.InitiatorAgent, "this caller descends from an agent session (or carries its marker); an agent may not confirm a launch, a human confirms it"
	}},
	// An unidentified caller may confirm, as it may launch (P2): the
	// owner's browser under WSL2 is often unidentified. A named residual
	// (security ledger LAUNCH-2).
	{"K3-otherwise", func(ConfirmFacts) (bool, bool, string) { return true, true, "" }},
}

// MayConfirm decides whether a caller may confirm a held launch: ok, the
// refusal line when not, and the deciding row.
func MayConfirm(f ConfirmFacts) (ok bool, why, rule string) {
	for _, r := range confirmRows {
		if allow, done, w := r.decide(f); done {
			return allow, w, r.id
		}
	}
	return false, "no rule decided", ""
}

// Pending is one held launch as the surfaces show it: the request's own
// tool, project and sandbox and, in Details, every field it is bound to
// that changes what runs, the tool's arguments and the clone remote
// included (lane cli-2 fixes-2, audit M-B). A forwarded environment is
// shown by its names only, and the value of a secret-looking argument or
// request member is masked (scrub.MaskSecretArgs, scrub.SecretName;
// fixes-3, audit L3), so a detail can show less than the confirm sends,
// never something else.
type Pending struct {
	ID string
	// Front is where the launch was asked for (dashboard or cli).
	Front Front
	// What is the one-line description a human confirms ("observer launch
	// codex in /w/proj, sandbox auto").
	What string
	// Tool, Project and Sandbox are the request's own fields ("" when the
	// request did not name one).
	Tool, Project, Sandbox string
	// Details are every field the held request is bound to that changes
	// what runs, in order (lane cli-2 fixes-2, audit M-B): what a human
	// confirms is shown whole, never summarized away.
	Details []PendingDetail
	// Origin is the agent attribution the launch will record.
	Origin    termrun.Origin
	CreatedAt time.Time
	ExpiresAt time.Time
}

// PendingDetail is one bound field of a held launch as a human reads it.
type PendingDetail struct {
	Label string
	Value string
	// Warn marks a field the human should look at twice (an unsandboxed
	// run, a sign-in copied into a box, a forwarded environment).
	Warn bool
}

// Holds is the store of held launches. Each carries an action of type T
// that starts exactly the held request. Safe for concurrent use.
type Holds[T any] struct {
	mu      sync.Mutex
	entries map[string]holdEntry[T]
	now     func() time.Time
	newID   func() (string, error)
	ttl     time.Duration
	max     int
}

type holdEntry[T any] struct {
	p      Pending
	action T
}

// NewHolds builds a store over a clock and an id source (both injected).
func NewHolds[T any](now func() time.Time, newID func() (string, error)) *Holds[T] {
	return &Holds[T]{entries: map[string]holdEntry[T]{}, now: now, newID: newID, ttl: DefaultPendingTTL, max: MaxPending}
}

// sweepLocked drops every expired hold.
func (h *Holds[T]) sweepLocked() {
	now := h.now()
	for id, e := range h.entries {
		if !now.Before(e.p.ExpiresAt) {
			delete(h.entries, id)
		}
	}
}

// Hold records p (its id, creation and expiry are set here) with the action
// that starts it, and returns the held launch.
func (h *Holds[T]) Hold(p Pending, action T) (Pending, error) {
	id, err := h.newID()
	if err != nil {
		return Pending{}, fmt.Errorf("agentlaunch: hold id: %w", err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sweepLocked()
	if len(h.entries) >= h.max {
		return Pending{}, refuse(CodeTooManyPending, "launch", "%d launches already wait for a human's confirm; confirm or reject one first", h.max)
	}
	p.ID, p.CreatedAt = id, h.now()
	p.ExpiresAt = p.CreatedAt.Add(h.ttl)
	p.Origin = p.Origin.Normalized()
	h.entries[id] = holdEntry[T]{p: p, action: action}
	return p, nil
}

// List returns the live holds, oldest first.
func (h *Holds[T]) List() []Pending {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sweepLocked()
	out := make([]Pending, 0, len(h.entries))
	for _, e := range h.entries {
		out = append(out, e.p)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Take removes the hold and returns it with its action: single use, so a
// second confirm of the same id finds nothing. ErrPendingNotFound for an
// unknown or expired id.
func (h *Holds[T]) Take(id string) (Pending, T, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sweepLocked()
	e, ok := h.entries[id]
	if !ok {
		var zero T
		return Pending{}, zero, ErrPendingNotFound
	}
	delete(h.entries, id)
	return e.p, e.action, nil
}
