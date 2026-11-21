package openshellorg

import "time"

// BoxState is a box ledger row's state (section 9.2).
type BoxState string

// The closed ledger states.
const (
	BoxMinted        BoxState = "minted"
	BoxCreated       BoxState = "created"
	BoxHolding       BoxState = "holding"
	BoxHeld          BoxState = "held"
	BoxResuming      BoxState = "resuming"
	BoxEnding        BoxState = "ending"
	BoxEnded         BoxState = "ended"
	BoxExpired       BoxState = "expired"
	BoxReaped        BoxState = "reaped"
	BoxCollectFailed BoxState = "collect_failed"
)

// AllBoxStates is the closed state set, in lifecycle order.
func AllBoxStates() []BoxState {
	return []BoxState{
		BoxMinted, BoxCreated, BoxHolding, BoxHeld, BoxResuming,
		BoxEnding, BoxEnded, BoxExpired, BoxReaped, BoxCollectFailed,
	}
}

// Valid reports whether s is a member of the closed set.
func (s BoxState) Valid() bool {
	for _, k := range AllBoxStates() {
		if k == s {
			return true
		}
	}
	return false
}

// Live reports whether the state counts as a live box for the concurrency
// quotas.
func (s BoxState) Live() bool {
	return s == BoxMinted || s == BoxCreated || s == BoxResuming || s == BoxEnding
}

// HeldCount reports whether the state counts against the held quotas: a
// box on its way to held, a held box, and a collect_failed box (kept stopped
// for an admin decision, section 7.3).
func (s BoxState) HeldCount() bool {
	return s == BoxHolding || s == BoxHeld || s == BoxCollectFailed
}

// Terminal reports whether no move leaves the state.
func (s BoxState) Terminal() bool { return s == BoxEnded || s == BoxExpired || s == BoxReaped }

// Actor is who asks for a ledger move. Every move is written through
// openshellctl; the actor says which feed path asked.
type Actor string

// The closed actors.
const (
	// ActorMint is the api role's mint (T6 records minted; T7r moves a held
	// box to resuming).
	ActorMint Actor = "mint"
	// ActorFront is a front event the api role accepted (section 7.7).
	ActorFront Actor = "front"
	// ActorNode is a node's own report: ended, hold (H1, H3), discard.
	ActorNode Actor = "node"
	// ActorWorker is the worker: hold and resume moves, the collect, the
	// reaper, expiry and the drain.
	ActorWorker Actor = "worker"
	// ActorAdmin is an admin route or verb (discard, discard without
	// collect, drain --force).
	ActorAdmin Actor = "admin"
)

// moveRow is one legal ledger move.
type moveRow struct {
	From BoxState
	To   BoxState
	By   Actor
	// Why names the design rule the row implements.
	Why string
}

// moveTable is the box ledger's state machine (sections 3.2, 3.6, 4.6, 7.4
// and 7.7), walked top-down. A move that is not listed is illegal. It
// already allows the moves lane G3's worker makes: the stuck holding and
// resuming moves (a stop or start not confirmed within StuckAfter: collect
// when needed, then delete, or collect_failed), and it lets nothing but an
// admin decision, drain --force or the reaper's delete_unstoppable leave
// collect_failed (the collect_failed exclusion, G1-R43).
var moveTable = []moveRow{
	{BoxMinted, BoxCreated, ActorFront, "7.7 event created"},
	{BoxMinted, BoxEnded, ActorNode, "3.2 a launch that ended before its create"},
	{BoxMinted, BoxEnded, ActorFront, "7.7 event create_refused (the gateway refused the create; F-L3R-4)"},
	{BoxMinted, BoxReaped, ActorWorker, "7.4 a mint whose create never came"},
	{BoxCreated, BoxEnding, ActorFront, "7.7 event ending (after F6's delete)"},
	{BoxCreated, BoxEnding, ActorNode, "3.2 step 10 end without a return"},
	{BoxCreated, BoxEnded, ActorNode, "3.2 step 10 returned and deleted (E1)"},
	{BoxCreated, BoxHolding, ActorNode, "3.6 H1 or H3"},
	{BoxCreated, BoxHolding, ActorFront, "3.6 H2 disconnected"},
	{BoxCreated, BoxHolding, ActorWorker, "3.6 H2 seen by the worker"},
	{BoxCreated, BoxReaped, ActorWorker, "7.4 reaper (collect first when unreturned)"},
	{BoxCreated, BoxCollectFailed, ActorWorker, "4.6 a reaper collect that failed"},
	{BoxEnding, BoxEnded, ActorNode, "3.2 step 10 returned after F6"},
	{BoxEnding, BoxEnded, ActorWorker, "4.6 collected and deleted"},
	{BoxEnding, BoxReaped, ActorWorker, "7.4 reaper"},
	{BoxEnding, BoxCollectFailed, ActorWorker, "4.6 a collect that failed"},
	{BoxHolding, BoxHeld, ActorWorker, "3.6 stop confirmed"},
	{BoxHolding, BoxReaped, ActorWorker, "7.4 stuck holding: collect when needed, then delete"},
	{BoxHolding, BoxCollectFailed, ActorWorker, "7.4 stuck holding: the collect failed"},
	{BoxHeld, BoxResuming, ActorMint, "3.6 T7r"},
	{BoxHeld, BoxExpired, ActorWorker, "7.4 hold expiry after its collect"},
	{BoxHeld, BoxReaped, ActorWorker, "3.6 discard, drain or admin collect, then delete"},
	{BoxHeld, BoxCollectFailed, ActorWorker, "4.6 a collect that failed"},
	{BoxResuming, BoxCreated, ActorWorker, "3.6 start confirmed"},
	{BoxResuming, BoxReaped, ActorWorker, "7.4 stuck resuming: collect when needed, then delete"},
	{BoxResuming, BoxCollectFailed, ActorWorker, "7.4 stuck resuming: the collect failed"},
	{BoxCollectFailed, BoxReaped, ActorAdmin, "4.6 discard without collect, or drain --force"},
	{BoxCollectFailed, BoxReaped, ActorWorker, "4.6 delete_unstoppable after three unconfirmed re-stops"},
}

// CanMove reports whether actor by may move a row from one state to another.
func CanMove(from, to BoxState, by Actor) bool {
	for _, r := range moveTable {
		if r.From == from && r.To == to && r.By == by {
			return true
		}
	}
	return false
}

// StuckAfter is how long a box may stay in holding or resuming before the
// worker treats the stop or start as unconfirmed (section 7.4).
const StuckAfter = 10 * time.Minute

// Stuck reports whether a row in state since the given time is a stuck move.
func Stuck(s BoxState, since, now time.Time) bool {
	return (s == BoxHolding || s == BoxResuming) && !since.IsZero() && now.Sub(since) > StuckAfter
}

// HoldPolicy is the org's hold_policy (section 3.6).
type HoldPolicy string

// The closed hold policies.
const (
	HoldOff                HoldPolicy = "off"
	HoldOnDisconnect       HoldPolicy = "on_disconnect"
	HoldOnDisconnectAndEnd HoldPolicy = "on_disconnect_and_end"
)

// Valid reports whether p is a member of the closed set.
func (p HoldPolicy) Valid() bool {
	return p == HoldOff || p == HoldOnDisconnect || p == HoldOnDisconnectAndEnd
}

// HoldTrigger is what asks for a hold.
type HoldTrigger string

// The closed hold triggers.
const (
	// TriggerEnd (H1): the run ended and the member's hold_on_end is on, or
	// the run's recorded return_to_node is false.
	TriggerEnd HoldTrigger = "H1"
	// TriggerDisconnect (H2): the laptop or a stream was lost for 60 s.
	TriggerDisconnect HoldTrigger = "H2"
	// TriggerExplicit (H3): the member asked from any of their nodes.
	TriggerExplicit HoldTrigger = "H3"
)

// Valid reports whether t is a member of the closed set.
func (t HoldTrigger) Valid() bool {
	return t == TriggerEnd || t == TriggerDisconnect || t == TriggerExplicit
}

// HoldFacts are the inputs of a hold decision.
type HoldFacts struct {
	Trigger HoldTrigger
	// Policy is the run's hold_policy recorded at mint.
	Policy HoldPolicy
	// ReturnToNode is the run's return_to_node recorded at mint.
	ReturnToNode bool
	Quotas       Quotas
	// Usage counts the box itself as live.
	Usage Usage
}

// holdRow is one row of the hold table: when Match is true, Allowed says
// whether the policy lets the trigger hold.
type holdRow struct {
	ID      string
	Match   func(f HoldFacts) bool
	Allowed bool
}

// holdTable decides whether a trigger may hold under the recorded policy,
// walked top-down (section 3.6 and G1-R38).
var holdTable = []holdRow{
	{"policy-off", func(f HoldFacts) bool { return f.Policy == HoldOff }, false},
	{"H1-forced", func(f HoldFacts) bool { return f.Trigger == TriggerEnd && !f.ReturnToNode }, true},
	{"H1-end", func(f HoldFacts) bool { return f.Trigger == TriggerEnd && f.Policy == HoldOnDisconnectAndEnd }, true},
	{"H1-other", func(f HoldFacts) bool { return f.Trigger == TriggerEnd }, false},
	{"H2", func(f HoldFacts) bool { return f.Trigger == TriggerDisconnect }, true},
	{"H3", func(f HoldFacts) bool { return f.Trigger == TriggerExplicit }, true},
}

// DecideHold answers whether the trigger holds the box (ReasonNone) or the
// run is treated as ended instead (ReasonHoldUnavailable): holding off, a
// trigger the policy does not cover, or the member or the org over a held
// quota. It also answers the deciding row's id.
func DecideHold(f HoldFacts) (rule string, r Reason) {
	if !f.Trigger.Valid() || !f.Policy.Valid() {
		return "invalid", ReasonHoldUnavailable
	}
	for _, row := range holdTable {
		if !row.Match(f) {
			continue
		}
		if !row.Allowed {
			return row.ID, ReasonHoldUnavailable
		}
		if q := CheckHoldQuota(f.Quotas, f.Usage); q != ReasonNone {
			return row.ID + "-quota", q
		}
		return row.ID, ReasonNone
	}
	return "none", ReasonHoldUnavailable
}

// HoldExpiresAt is the expiry recorded when a box is held.
func HoldExpiresAt(heldAt time.Time, maxHoldHours int) time.Time {
	return heldAt.Add(time.Duration(maxHoldHours) * time.Hour)
}

// EffectiveHoldExpiry is the expiry the reaper and T7r apply: min(the
// recorded hold_expires_at, held_at plus the current max_hold_hours), so
// lowering the setting takes effect on boxes already held (G1-R29).
func EffectiveHoldExpiry(recorded, heldAt time.Time, currentMaxHoldHours int) time.Time {
	now := HoldExpiresAt(heldAt, currentMaxHoldHours)
	if recorded.IsZero() || now.Before(recorded) {
		return now
	}
	return recorded
}

// CollectFailReason is a collect_failed row's closed reason (section 9.2).
type CollectFailReason string

// The closed collect failure reasons.
const (
	CollectTimeout          CollectFailReason = "timeout"
	CollectSizeCap          CollectFailReason = "size_cap"
	CollectTreeCheck        CollectFailReason = "tree_check"
	CollectGitExecConfig    CollectFailReason = "git_exec_config"
	CollectStartFailed      CollectFailReason = "start_failed"
	CollectStoreWriteFailed CollectFailReason = "store_write_failed"
	CollectSpecDrift        CollectFailReason = "spec_drift"
)

// AllCollectFailReasons is the closed set.
func AllCollectFailReasons() []CollectFailReason {
	return []CollectFailReason{
		CollectTimeout, CollectSizeCap, CollectTreeCheck,
		CollectGitExecConfig, CollectStartFailed, CollectStoreWriteFailed, CollectSpecDrift,
	}
}

// EndReason is a ledger row's closed end reason.
type EndReason string

// The closed end reasons.
const (
	EndReturned              EndReason = "returned"
	EndUnreturned            EndReason = "ended_unreturned"
	EndHoldUnavailable       EndReason = "hold_unavailable"
	EndHoldExpired           EndReason = "hold_expired"
	EndDiscard               EndReason = "discard"
	EndDrain                 EndReason = "drain"
	EndAdmin                 EndReason = "admin"
	EndSpecDrift             EndReason = "spec_drift"
	EndCloneDeadline         EndReason = "clone_deadline"
	EndMaxRun                EndReason = "max_run"
	EndMemberRevoked         EndReason = "member_revoked"
	EndStuck                 EndReason = "stuck_move"
	EndNeverCreated          EndReason = "never_created"
	EndDeleteUnstoppable     EndReason = "delete_unstoppable"
	EndDiscardWithoutCollect EndReason = "discard_without_collect"
)

// AllEndReasons is the closed set.
func AllEndReasons() []EndReason {
	return []EndReason{
		EndReturned, EndUnreturned, EndHoldUnavailable, EndHoldExpired,
		EndDiscard, EndDrain, EndAdmin, EndSpecDrift, EndCloneDeadline, EndMaxRun,
		EndMemberRevoked, EndStuck, EndNeverCreated, EndDeleteUnstoppable, EndDiscardWithoutCollect,
	}
}

// BoxFacts is a box ledger row as the pure rules see it.
type BoxFacts struct {
	Found bool
	// RunID is the ledger key: the box's original run id.
	RunID string
	// ActiveRunID is the run id that may use the box now (a resume moves it).
	ActiveRunID string
	MemberID    string
	NodeID      string
	State       BoxState
	StateSince  time.Time
	SpecDigest  string
	// ReturnToNode and HoldPolicy are recorded at mint.
	ReturnToNode   bool
	HoldPolicy     HoldPolicy
	ReturnMintedAt time.Time
	ReturnedAt     time.Time
	HeldAt         time.Time
	HoldExpiresAt  time.Time
	// CreatedAt is when the box was created (max_run_minutes counts from
	// it); zero when not known.
	CreatedAt time.Time
}

// ResumeFacts are T7r's inputs.
type ResumeFacts struct {
	Box      BoxFacts
	MemberID string
	// NewRunID is the resuming node's new run id.
	NewRunID string
	Quotas   Quotas
	// Usage counts the held box as held (not live).
	Usage Usage
	// RecompiledDigest is the digest of the box's spec compiled again under
	// today's org values.
	RecompiledDigest string
	Now              time.Time
}

// ResumeAction is what T7r tells the mint to do on allow.
type ResumeAction string

// The resume actions.
const (
	// ResumeMove moves the held box to resuming with the new run id.
	ResumeMove ResumeAction = "move"
	// ResumeReuse is an idempotent retry: the box is already resuming for
	// this new run id, so the mint answers a fresh token and moves nothing.
	ResumeReuse ResumeAction = "reuse"
)

// CheckResume is mint rule T7r (section 3.6). It answers the action on
// allow, or the refusal.
func CheckResume(f ResumeFacts) (ResumeAction, Reason) {
	b := f.Box
	switch {
	case !b.Found || b.MemberID != f.MemberID:
		return "", ReasonRunNotYours
	case b.State == BoxResuming && b.ActiveRunID == f.NewRunID:
		return ResumeReuse, ReasonNone
	case b.State != BoxHeld:
		return "", ReasonRunNotHeld
	case !f.Now.Before(EffectiveHoldExpiry(b.HoldExpiresAt, b.HeldAt, f.Quotas.MaxHoldHours)):
		return "", ReasonHoldExpired
	}
	if r := CheckResumeQuota(f.Quotas, f.Usage); r != ReasonNone {
		return "", r
	}
	if f.RecompiledDigest == "" || f.RecompiledDigest != b.SpecDigest {
		return "", ReasonSpecChangedSinceHold
	}
	return ResumeMove, ReasonNone
}

// EndedReport is a node's runs/{run}/ended report as rule E1 reads it.
type EndedReport struct {
	Returned bool
	Hold     bool
	// Disconnected: the node's agent stream was cut for a reason that is
	// not the run's end (FX3 item 9), so the hold is judged as trigger H2
	// (a disconnect), not H1. It holds only with Hold.
	Disconnected bool
	// Now is when the report arrived (the max_run check of a disconnect).
	Now time.Time
	// OrgEnded is set when the organization itself ended the run before the
	// report: the member's sign-in was revoked by an admin (or the member
	// was disabled), or the org is draining (FX4 fix round 1, F-P6B-1). No
	// hold is accepted then, whatever the node asks or the recorded
	// return_to_node forces: the worker collects the work and deletes the
	// box, and the answer carries this reason so the node says the
	// organization ended the run.
	OrgEnded Reason
}

// EndedOutcome is what the server records for an ended report.
type EndedOutcome string

// The ended outcomes.
const (
	// EndedRefused leaves the row as it was (a forged returned claim).
	EndedRefused EndedOutcome = "refused"
	// EndedReturned moves the row to ended and sets returned_at.
	EndedReturned EndedOutcome = "ended_returned"
	// EndedHold moves the row to holding; the worker stops the box.
	EndedHold EndedOutcome = "hold"
	// EndedUnreturned moves the row to ending; the worker collects, then
	// deletes.
	EndedUnreturned EndedOutcome = "ended_unreturned"
)

// JudgeEnded is rule E1 (section 5.4, G1-R36 and G1-R42). returned = true
// is accepted only when the run's recorded return_to_node is true and a
// return token was minted for it; otherwise the report is refused and
// returned_at stays unset. hold = true is accepted only when the box can be
// held (DecideHold with trigger H1); one that cannot is answered
// hold_unavailable and the run is treated as ended unreturned.
func JudgeEnded(rep EndedReport, box BoxFacts, q Quotas, u Usage) (EndedOutcome, Reason) {
	if rep.Returned {
		switch {
		case !box.ReturnToNode:
			return EndedRefused, ReasonReturnWithheld
		case box.ReturnMintedAt.IsZero():
			return EndedRefused, ReasonReturnNotTaken
		}
		return EndedReturned, ReasonNone
	}
	if rep.OrgEnded != ReasonNone {
		// A revoked member's or a drained org's run is never held (F-P6B-1:
		// a hold recorded here was collected and deleted seconds later, and
		// the node told the member the box was held).
		return EndedUnreturned, rep.OrgEnded
	}
	if rep.Hold && rep.Disconnected && !disconnectHoldable(rep, box, q) {
		// Defence in depth (FX3-A3): a run past its max_run_minutes, or a
		// box no longer live, ended for the run's own reason, whatever the
		// node says; holding it as a disconnect would keep a finished box
		// for max_hold_hours.
		return EndedUnreturned, ReasonHoldUnavailable
	}
	if rep.Hold || !box.ReturnToNode {
		// The recorded return_to_node = false forces a hold whenever one is
		// possible (H1, G1-R38), whether or not the node asked for it.
		trigger := TriggerEnd
		if rep.Hold && rep.Disconnected {
			trigger = TriggerDisconnect
		}
		_, r := DecideHold(HoldFacts{
			Trigger: trigger, Policy: box.HoldPolicy,
			ReturnToNode: box.ReturnToNode, Quotas: q, Usage: u,
		})
		if r == ReasonNone {
			return EndedHold, ReasonNone
		}
		if rep.Hold {
			return EndedUnreturned, ReasonHoldUnavailable
		}
	}
	return EndedUnreturned, ReasonNone
}

// disconnectHoldable reports whether a disconnect (H2) may hold the box:
// the box is live (created) and the run is within max_run_minutes (an
// unknown creation time or report time does not refuse).
func disconnectHoldable(rep EndedReport, box BoxFacts, q Quotas) bool {
	if box.State != BoxCreated {
		return false
	}
	if q.MaxRunMinutes > maxRunMinutesUnlimited && !box.CreatedAt.IsZero() && !rep.Now.IsZero() &&
		rep.Now.Sub(box.CreatedAt) > time.Duration(q.MaxRunMinutes)*time.Minute {
		return false
	}
	return true
}

// DiscardFacts are the inputs of a discard of a held box.
type DiscardFacts struct {
	Box      BoxFacts
	MemberID string
	// ByAdmin is an admin's discard (admin:members).
	ByAdmin bool
	// WithoutCollect is an admin's audited discard without collect.
	WithoutCollect bool
}

// DiscardAction is what a discard does.
type DiscardAction string

// The discard actions.
const (
	// DiscardCollectThenDelete asks the worker to collect (when returned_at
	// is unset), then delete.
	DiscardCollectThenDelete DiscardAction = "collect_then_delete"
	// DiscardDeleteNow is an admin's discard without collect of a
	// collect_failed box: delete at once, audited.
	DiscardDeleteNow DiscardAction = "delete_now"
)

// DecideDiscard decides a discard (section 3.6). A member may discard only
// their own held box; a member's discard of a collect_failed box is refused
// (collect_failed_admin_only); only an admin's discard without collect
// deletes a collect_failed box.
func DecideDiscard(f DiscardFacts) (DiscardAction, Reason) {
	b := f.Box
	if !b.Found || (!f.ByAdmin && b.MemberID != f.MemberID) {
		return "", ReasonRunNotYours
	}
	switch b.State {
	case BoxHeld:
		return DiscardCollectThenDelete, ReasonNone
	case BoxCollectFailed:
		if f.ByAdmin && f.WithoutCollect {
			return DiscardDeleteNow, ReasonNone
		}
		return "", ReasonCollectFailedOnly
	}
	return "", ReasonRunNotHeld
}
