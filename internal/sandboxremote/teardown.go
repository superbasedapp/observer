package sandboxremote

import (
	"fmt"
	"sort"
	"time"
)

// teardown.go is the leak-free teardown state machine (sandbox plan v2
// sections 5.5 and 5.7, lane SBX-P7). A paid box must never outlive its run
// unseen:
//
//   - a create INTENT is recorded owner-only before the create call, so a
//     daemon killed mid-call still knows a box may exist;
//   - the vendor id is recorded the moment the create returns;
//   - every box carries the run id as a label where the vendor has metadata,
//     so a create whose response was lost can be found by listing;
//   - teardown is pull, verify, delete, and the record is removed only after
//     the vendor confirms the delete (its own get or list no longer shows
//     the box);
//   - a killed daemon relies on the vendor timeout every create sets, and at
//     the next start the dashboard lists the leftover records with their
//     ages; the vendor is called only when the user confirms.
//
// The transitions are a table (CLAUDE.md rule 5): an event not in the table
// for the current state is refused, never guessed.

// TeardownVersion is the stored record's version.
const TeardownVersion = 1

// State is a run's teardown state.
type State string

// The closed State vocabulary.
const (
	// StateIntent: recorded before the create call; no vendor id yet.
	StateIntent State = "intent"
	// StateCreateLost: the create call's outcome is unknown (the response
	// was lost, the daemon died during it): a box may exist under the run's
	// label, and the vendor timeout ends it if nobody finds it.
	StateCreateLost State = "create_lost"
	// StateCreated: the vendor returned the box id.
	StateCreated State = "created"
	// StateRunning: the agent runs in the box.
	StateRunning State = "running"
	// StatePulling: the transcripts are being pulled before delete.
	StatePulling State = "pulling"
	// StateDeleting: the delete was sent and is not yet confirmed.
	StateDeleting State = "deleting"
	// StateGone: the vendor confirmed the box is gone (or it never
	// existed); the record may be removed.
	StateGone State = "gone"
)

// Event is what happened.
type Event string

// The closed Event vocabulary.
const (
	EvCreateOK      Event = "create_ok"
	EvCreateFailed  Event = "create_failed"
	EvCreateLost    Event = "create_lost"
	EvFoundByLabel  Event = "found_by_label"
	EvNotFound      Event = "not_found"
	EvStarted       Event = "started"
	EvPullBegin     Event = "pull_begin"
	EvPullDone      Event = "pull_done"
	EvPullFailed    Event = "pull_failed"
	EvDeleteSent    Event = "delete_sent"
	EvDeleteConfirm Event = "delete_confirmed"
	EvDeleteFailed  Event = "delete_failed"
	EvAdopt         Event = "adopt"
)

// transitions is the table: state -> event -> next state.
var transitions = map[State]map[Event]State{
	StateIntent: {
		EvCreateOK: StateCreated, EvCreateFailed: StateGone, EvCreateLost: StateCreateLost,
	},
	StateCreateLost: {
		// Listing by the run label found the box, or proved there is none.
		EvFoundByLabel: StateCreated, EvNotFound: StateGone,
	},
	StateCreated: {
		EvStarted: StateRunning, EvPullBegin: StatePulling, EvDeleteSent: StateDeleting, EvNotFound: StateGone,
	},
	StateRunning: {
		EvPullBegin: StatePulling, EvDeleteSent: StateDeleting, EvNotFound: StateGone, EvAdopt: StateRunning,
	},
	StatePulling: {
		// A failed pull never blocks the delete: the transcript copy pulled
		// at the last checkpoint stays, and a box left running bills.
		EvPullDone: StatePulling, EvPullFailed: StatePulling, EvDeleteSent: StateDeleting, EvNotFound: StateGone,
	},
	StateDeleting: {
		EvDeleteConfirm: StateGone, EvNotFound: StateGone, EvDeleteFailed: StateCreated,
	},
}

// ErrTransition reports an event the table does not allow.
var ErrTransition = fmt.Errorf("teardown: event not allowed in this state")

// Next returns the state after ev, or ErrTransition.
func Next(s State, ev Event) (State, error) {
	if n, ok := transitions[s][ev]; ok {
		return n, nil
	}
	return s, fmt.Errorf("%w: %s on %s", ErrTransition, ev, s)
}

// Record is one run's teardown record (node-local, owner-only).
type Record struct {
	Version  int    `json:"version"`
	RunID    string `json:"run_id"`
	Provider string `json:"provider"`
	Endpoint string `json:"endpoint"`
	Region   string `json:"region"`
	// Label is the metadata label the box carries (the run id under the
	// install's key).
	Label string `json:"label"`
	// VendorID is the box id ("" until the create returns).
	VendorID string `json:"vendor_id,omitempty"`
	// Extra holds vendor identifiers beside the box id (Vercel's sandbox
	// name), never a secret.
	Extra map[string]string `json:"extra,omitempty"`
	State State             `json:"state"`
	// CreatedAt is when the intent was recorded; Deadline is when the
	// vendor timeout ends the box at the latest.
	CreatedAt time.Time `json:"created_at"`
	Deadline  time.Time `json:"deadline"`
	// SecretFiles are the owner-only per-box secret files (an E2B envd
	// access token) removed with the record.
	SecretFiles []string `json:"secret_files,omitempty"`
	// LastError is the last vendor error, already redacted.
	LastError string `json:"last_error,omitempty"`
	// DiffError says why the box's staged diff was not saved home
	// (redacted; live run 2 finding F-A: a failed pull was silent).
	DiffError string `json:"diff_error,omitempty"`
}

// NewIntent is the record written before the create call.
func NewIntent(runID, provider, endpoint, region, label string, now time.Time, timeout time.Duration) Record {
	return Record{
		Version: TeardownVersion, RunID: runID, Provider: provider, Endpoint: endpoint, Region: region,
		Label: label, State: StateIntent, CreatedAt: now.UTC(), Deadline: now.UTC().Add(timeout),
	}
}

// Apply moves the record by ev.
func (r *Record) Apply(ev Event) error {
	n, err := Next(r.State, ev)
	if err != nil {
		return err
	}
	r.State = n
	return nil
}

// Removable reports whether the record may be deleted: only when the vendor
// confirmed the box is gone.
func (r Record) Removable() bool { return r.State == StateGone }

// DiffErrorLine is one kept line of a run whose staged diff was not saved
// home: the record that held the reason is removed once the provider
// confirms the box gone, so the reason is kept here (P-094 residual, lane
// SHR-FOLLOWUPS) and `observer sandbox hosted status` prints it. Redacted
// like the record (the reason was redacted when it was set).
type DiffErrorLine struct {
	RunID    string    `json:"run_id"`
	Provider string    `json:"provider"`
	At       time.Time `json:"at"`
	Error    string    `json:"error"`
}

// MaxKeptDiffErrors bounds the kept lines (the oldest go first).
const MaxKeptDiffErrors = 50

// KeepDiffError appends rec's diff error, when it has one, to lines (oldest
// first), once per run, keeping at most MaxKeptDiffErrors. Pure.
func KeepDiffError(lines []DiffErrorLine, rec Record, now time.Time) []DiffErrorLine {
	if rec.DiffError == "" {
		return lines
	}
	out := make([]DiffErrorLine, 0, len(lines)+1)
	for _, l := range lines {
		if l.RunID != rec.RunID {
			out = append(out, l)
		}
	}
	out = append(out, DiffErrorLine{RunID: rec.RunID, Provider: rec.Provider, At: now.UTC(), Error: rec.DiffError})
	if len(out) > MaxKeptDiffErrors {
		out = out[len(out)-MaxKeptDiffErrors:]
	}
	return out
}

// Leftover is one row of the dashboard's leftover-box list.
type Leftover struct {
	RunID    string `json:"run_id"`
	Provider string `json:"provider"`
	Region   string `json:"region"`
	VendorID string `json:"vendor_id,omitempty"`
	State    State  `json:"state"`
	// AgeSeconds is how long ago the box was created.
	AgeSeconds int64 `json:"age_seconds"`
	// ExpiresInSeconds is how long until the vendor timeout ends it at the
	// latest (0 when past).
	ExpiresInSeconds int64 `json:"expires_in_seconds"`
	// Action is what confirming does: "delete", or "find_and_delete" for a
	// lost create (list by label, then delete).
	Action string `json:"action"`
	// Adoptable: the vendor can reattach to the running process (a re-adopt
	// is offered before delete).
	Adoptable bool `json:"adoptable"`
}

// Leftovers lists the records a start finds that are not gone, oldest
// first, with ages; live is the set of run ids that still have a live run
// in this daemon (never listed).
func Leftovers(recs []Record, live map[string]bool, now time.Time) []Leftover {
	var out []Leftover
	for _, r := range recs {
		if r.State == StateGone || live[r.RunID] {
			continue
		}
		l := Leftover{
			RunID: r.RunID, Provider: r.Provider, Region: r.Region, VendorID: r.VendorID, State: r.State,
			AgeSeconds: int64(now.Sub(r.CreatedAt) / time.Second), Action: "delete",
		}
		if d := r.Deadline.Sub(now); d > 0 {
			l.ExpiresInSeconds = int64(d / time.Second)
		}
		if r.VendorID == "" {
			l.Action = "find_and_delete"
		}
		if v, ok := VendorFor(r.Provider); ok && (v.Reattach || v.GuestReattach && r.Extra[ExtraGuestAttach] == "1") && r.VendorID != "" && r.State == StateRunning && l.ExpiresInSeconds > 0 {
			l.Adoptable = true
		}
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AgeSeconds > out[j].AgeSeconds })
	return out
}

// The run record's Extra keys a re-adoption reads (lane SBX-UPD): the
// guest PTY keeper is running for the run, and the run's tier, tool and
// host workspace root (none of them a secret).
const (
	ExtraGuestAttach = "guest_attach"
	ExtraTier        = "tier"
	ExtraTool        = "tool"
	ExtraRoot        = "root"
)
