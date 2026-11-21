package openshellorg

import "time"

// The org-side reap table (g1-design.md sections 3.6, 4.6, 7.4 and 7.8,
// lane G3): for every box in an Observer workspace and every ledger row the
// worker reads, the first matching row says what to do. The worker's
// executor carries the action out; "collect first when returned_at is unset"
// is the executor's rule for every action that deletes (G1-R40, G1-D62), so
// a row never has to say it.
//
// "Gone" is only the gateway's exact not-found answer: BoxSeen false means
// the list did not hold the box, and the executor confirms with the exact
// answer before it settles anything.

// ReapAction is what the worker does with one box.
type ReapAction string

// The closed reap actions.
const (
	ReapNone ReapAction = "none"
	// ReapDelete deletes the box; there is nothing to collect (no ledger
	// row, a settled row, a box that never ran a call).
	ReapDelete ReapAction = "delete"
	// ReapCollectDelete stops the box if it runs, collects it when its work
	// never came back, deletes it and settles the ledger.
	ReapCollectDelete ReapAction = "collect_delete"
	// ReapRestoreCollectDelete restores the recorded network policy first
	// (spec drift), then collects and deletes.
	ReapRestoreCollectDelete ReapAction = "restore_collect_delete"
	// ReapHold moves a quiet live box to holding (H2 seen by the worker).
	ReapHold ReapAction = "hold"
	// ReapStop stops a holding box (then held) or a held box found running.
	ReapStop ReapAction = "stop"
	// ReapStart starts a resuming box (then created).
	ReapStart ReapAction = "start"
	// ReapRestop retries the stop of a collect_failed box found running.
	ReapRestop ReapAction = "restop"
	// ReapDeleteUnstoppable deletes a collect_failed box after three
	// unconfirmed re-stops, without collect, audited (G1-R31).
	ReapDeleteUnstoppable ReapAction = "delete_unstoppable"
	// ReapSettleGone settles a row whose box the gateway no longer has.
	ReapSettleGone ReapAction = "settle_gone"
)

// MaxUnconfirmedRestops is how many reaper passes a collect_failed box's
// re-stop may go unconfirmed before delete_unstoppable (G1-R31).
const MaxUnconfirmedRestops = 3

// ReapFacts are one box's inputs.
type ReapFacts struct {
	Now time.Time
	// BoxSeen: the gateway lists the box; BoxRunning: it is not stopped.
	BoxSeen    bool
	BoxRunning bool
	// BoxCreatedAt is when the box came to be, for an unledgered box:
	// the gateway's created_time, else when the worker first saw it
	// (G3-R4). Zero is unknown, and an unknown age is never old.
	BoxCreatedAt time.Time
	// Ledger: a ledger row exists for the box.
	Ledger           bool
	State            BoxState
	StateSince       time.Time
	MintedAt         time.Time
	LastMintAt       time.Time
	HeldAt           time.Time
	HoldExpiresAt    time.Time
	ReturnedAt       time.Time
	DiscardRequested bool
	CloneStartedAt   time.Time
	// HasProvider: the run clones through a repository provider (its
	// provider_profile is set). R15's deadline guards the provider's
	// credential, so a provider-less clone is never reaped by it (G3-A4).
	HasProvider      bool
	ProviderDetached bool
	// LastDecideAt is the last front decide for the run (any RPC, and the
	// front's 30 s re-check of every open stream). The quiet rows key on it
	// (G3-A5, the design's H2 "no decide for 120 s").
	LastDecideAt time.Time
	// MemberGone: an admin revoked the member, or they were disabled,
	// removed or are no longer allowed (never a member's own logout).
	MemberGone bool
	// Drift: the detective check found the box wider than its recorded
	// spec, or a provider attached outside a clone window.
	Drift bool
	// HoldAllowed: an H2 hold would be honoured now (hold_policy and the
	// held quotas, DecideHold).
	HoldAllowed        bool
	UnconfirmedRestops int
	MaxRunMinutes      int
	MaxHoldHours       int
	TokenTTL           time.Duration
	SyncInterval       time.Duration
	CloneDeadline      time.Duration
}

// ReapDecision is the walk's answer.
type ReapDecision struct {
	Rule   string
	Action ReapAction
	Reason EndReason
}

// The table's time bounds.
const (
	// CreateGrace is how long a box may exist while its ledger row is still
	// minted (the created event in flight) before it is reaped.
	CreateGrace = 2 * time.Minute
)

// QuietAfter is how long a created box may go without a front decide
// before the worker treats its node as gone (H2 seen by the worker, G3-A5):
// the front re-decides every open stream every FrontRecheckSeconds, so four
// missed re-checks (120 s) mean no stream is open and no call is made.
const QuietAfter = 4 * FrontRecheckSeconds * time.Second

// quietSince is when the box was last known busy: its last decide, or its
// move to created when no decide came yet.
func (f ReapFacts) quietSince() time.Time { return laterOf(f.LastDecideAt, f.StateSince) }

// unledgeredGrace is how long a box with no ledger row is left alone
// (G3-R4): its mint may be on the api process while this pass's ledger
// read is older, so two sync intervals plus the token lifetime pass
// before it is treated as made around the front.
func (f ReapFacts) unledgeredGrace() time.Duration { return 2*f.SyncInterval + f.TokenTTL }

// endingGrace is how long an ending row waits for the node's own ended
// report (its return and teardown are in flight).
func (f ReapFacts) endingGrace() time.Duration { return f.TokenTTL + f.SyncInterval }

func (f ReapFacts) stuck() bool { return Stuck(f.State, f.StateSince, f.Now) }

func (f ReapFacts) since(t time.Time) time.Duration {
	if t.IsZero() {
		return 0
	}
	return f.Now.Sub(t)
}

// reapRow is one row of the reap table.
type reapRow struct {
	ID     string
	Match  func(f ReapFacts) bool
	Action ReapAction
	Reason func(f ReapFacts) EndReason
}

func reason(r EndReason) func(ReapFacts) EndReason { return func(ReapFacts) EndReason { return r } }

func endingReason(f ReapFacts) EndReason {
	if !f.ReturnedAt.IsZero() {
		return EndReturned
	}
	return EndUnreturned
}

func liveOrHeld(s BoxState) bool {
	switch s {
	case BoxCreated, BoxHolding, BoxHeld, BoxResuming, BoxEnding:
		return true
	}
	return false
}

// reapTable is the reap table, walked top-down.
var reapTable = []reapRow{
	// A box with no ledger row: every box in an Observer workspace is
	// Observer's, so one made around the front is caught here (OSH-60).
	// A young one is left alone and counted (G3-R4): its ledger row may
	// still be on its way.
	{"R1-unledgered", func(f ReapFacts) bool {
		return f.BoxSeen && !f.Ledger && !f.BoxCreatedAt.IsZero() && f.since(f.BoxCreatedAt) > f.unledgeredGrace()
	}, ReapDelete, reason("")},
	{"R1b-unledgered-young", func(f ReapFacts) bool { return f.BoxSeen && !f.Ledger }, ReapNone, reason("")},
	// A settled row whose box is still there.
	{"R2-settled-box", func(f ReapFacts) bool { return f.Ledger && f.State.Terminal() && f.BoxSeen }, ReapDelete, reason("")},
	{"R3-settled", func(f ReapFacts) bool { return !f.Ledger || f.State.Terminal() }, ReapNone, reason("")},
	// A mint whose create never came, or a box the front never reported.
	{"R4-minted-box", func(f ReapFacts) bool {
		return f.State == BoxMinted && f.BoxSeen && f.since(f.MintedAt) > CreateGrace
	}, ReapDelete, reason(EndNeverCreated)},
	{"R5-minted-expired", func(f ReapFacts) bool {
		return f.State == BoxMinted && !f.BoxSeen && f.since(f.MintedAt) > time.Duration(f.MaxRunMinutes)*time.Minute+f.TokenTTL
	}, ReapSettleGone, reason(EndNeverCreated)},
	{"R6-minted", func(f ReapFacts) bool { return f.State == BoxMinted }, ReapNone, reason("")},
	// The gateway no longer has the box.
	{"R7-ending-gone", func(f ReapFacts) bool {
		return f.State == BoxEnding && !f.BoxSeen && f.since(f.StateSince) > f.endingGrace()
	}, ReapSettleGone, endingReason},
	{"R8-gone", func(f ReapFacts) bool { return !f.BoxSeen && f.State != BoxEnding }, ReapSettleGone, reason(EndAdmin)},
	{"R9-ending-wait", func(f ReapFacts) bool { return !f.BoxSeen }, ReapNone, reason("")},
	// A collect that failed: kept stopped for an admin's decision; a
	// running one is re-stopped, and three unconfirmed re-stops delete it.
	{"R10-unstoppable", func(f ReapFacts) bool {
		return f.State == BoxCollectFailed && f.BoxRunning && f.UnconfirmedRestops >= MaxUnconfirmedRestops
	}, ReapDeleteUnstoppable, reason(EndDeleteUnstoppable)},
	{"R11-restop", func(f ReapFacts) bool { return f.State == BoxCollectFailed && f.BoxRunning }, ReapRestop, reason("")},
	{"R12-collect-failed", func(f ReapFacts) bool { return f.State == BoxCollectFailed }, ReapNone, reason("")},
	// The detective check's drift.
	{"R13-drift", func(f ReapFacts) bool { return f.Drift && liveOrHeld(f.State) }, ReapRestoreCollectDelete, reason(EndSpecDrift)},
	// A member an admin revoked, or disabled, removed or no longer allowed.
	{"R14-member-gone", func(f ReapFacts) bool { return f.MemberGone }, ReapCollectDelete, reason(EndMemberRevoked)},
	// The clone deadline (G1-R12): a provider still attached past the
	// deadline. Only a run with a provider (G3-A4); a provider-less clone
	// has no credential to guard and ends by the other rows.
	{"R15-clone-deadline", func(f ReapFacts) bool {
		return f.HasProvider && !f.CloneStartedAt.IsZero() && !f.ProviderDetached && f.CloneDeadline > 0 && f.since(f.CloneStartedAt) > f.CloneDeadline
	}, ReapCollectDelete, reason(EndCloneDeadline)},
	// Stuck moves (G1-R43): collect when needed, then delete.
	{"R16-stuck", func(f ReapFacts) bool { return (f.State == BoxHolding || f.State == BoxResuming) && f.stuck() }, ReapCollectDelete, reason(EndStuck)},
	{"R17-holding", func(f ReapFacts) bool { return f.State == BoxHolding }, ReapStop, reason("")},
	{"R18-resuming", func(f ReapFacts) bool { return f.State == BoxResuming }, ReapStart, reason("")},
	// Held boxes: never left running; a discard; the expiry.
	{"R19-held-running", func(f ReapFacts) bool { return f.State == BoxHeld && f.BoxRunning }, ReapStop, reason("")},
	{"R20-held-discard", func(f ReapFacts) bool { return f.State == BoxHeld && f.DiscardRequested }, ReapCollectDelete, reason(EndDiscard)},
	{"R21-held-expired", func(f ReapFacts) bool {
		return f.State == BoxHeld && !f.Now.Before(EffectiveHoldExpiry(f.HoldExpiresAt, f.HeldAt, f.MaxHoldHours))
	}, ReapCollectDelete, reason(EndHoldExpired)},
	{"R22-held", func(f ReapFacts) bool { return f.State == BoxHeld }, ReapNone, reason("")},
	// A live box past max_run_minutes (counted from its last move to
	// created, so a resumed box gets its own run).
	{"R23-max-run", func(f ReapFacts) bool {
		return f.State == BoxCreated && f.MaxRunMinutes > 0 && f.since(f.StateSince) > time.Duration(f.MaxRunMinutes)*time.Minute
	}, ReapCollectDelete, reason(EndMaxRun)},
	// A quiet live box: its node is gone (H2 seen by the worker); held when
	// holding is allowed, else collected and deleted.
	{"R24-quiet-hold", func(f ReapFacts) bool {
		return f.State == BoxCreated && f.HoldAllowed && f.since(f.quietSince()) > QuietAfter
	}, ReapHold, reason("")},
	{"R25-quiet-end", func(f ReapFacts) bool {
		return f.State == BoxCreated && f.since(f.quietSince()) > QuietAfter
	}, ReapCollectDelete, reason(EndUnreturned)},
	// An ending box still there after the node's grace: the node ended
	// without a return, or died mid-teardown.
	{"R26-ending", func(f ReapFacts) bool { return f.State == BoxEnding && f.since(f.StateSince) > f.endingGrace() }, ReapCollectDelete, endingReason},
	{"R27-live", func(ReapFacts) bool { return true }, ReapNone, reason("")},
}

func laterOf(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// DecideReap walks the reap table.
func DecideReap(f ReapFacts) ReapDecision {
	for _, r := range reapTable {
		if r.Match(f) {
			return ReapDecision{Rule: r.ID, Action: r.Action, Reason: r.Reason(f)}
		}
	}
	return ReapDecision{Rule: "none", Action: ReapNone}
}

// DrainAction is what a drain pass does with one ledger row (design 7.4):
// every live or held box is collected when its work never came back and
// deleted; a collect_failed box blocks a plain drain and is deleted without
// collect only under force.
func DrainAction(s BoxState, force bool) (ReapAction, EndReason) {
	switch {
	case s.Terminal():
		return ReapNone, ""
	case s == BoxCollectFailed && force:
		return ReapDeleteUnstoppable, EndDiscardWithoutCollect
	case s == BoxCollectFailed:
		return ReapNone, ""
	case s == BoxMinted:
		return ReapDelete, EndNeverCreated
	}
	return ReapCollectDelete, EndDrain
}
