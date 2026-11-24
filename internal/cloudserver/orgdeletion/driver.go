package orgdeletion

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/deletionjournal"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/hostapi"
	pc "github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// OrgRequest is one org deletion request as the driver reads it.
type OrgRequest struct {
	RequestID string
	OrgID     string
	State     string
	Step      Step
	Origin    Origin
	// RequestedBy is the opaque account that asked.
	RequestedBy string
	PurgeAfter  time.Time
	// PurgeGen is the lifecycle generation of the transition to purging (0
	// before the fence).
	PurgeGen int64
	// Attempts counts consecutive failures of the current step.
	Attempts int
	// StepEnteredAt is when the request reached its current step (a resume
	// restarts it); await_host's bounded wait is measured from it.
	StepEnteredAt time.Time
}

// Subscription is the org's most relevant subscription.
type Subscription struct {
	ID     string
	Status string
}

// Live reports a subscription that holds a live slot and grants a paid plan
// (the 0090 live-slot rule). It is NOT the test for "Paddle may still bill
// it": a refunded or charged-back subscription is not Live but still renews
// at Paddle (MayBill).
func (s Subscription) Live() bool {
	switch s.Status {
	case "", "canceled", "refunded", "charged_back":
		return false
	}
	return s.ID != ""
}

// MayBill reports a subscription Paddle may still charge, so a deletion that
// drops its row must cancel it first: every stored status but canceled. A
// full refund or chargeback revokes the plan but does not cancel the Paddle
// subscription (FR-7, store/paddle_lifecycle.go; the go-live runbook 5c:
// "a refund does not cancel it"), and Paddle renews it at the next period.
// No subscription id or no status is nothing to cancel.
func (s Subscription) MayBill() bool {
	return s.ID != "" && s.Status != "" && s.Status != "canceled"
}

// OrgFacts is what the steps read about an org.
type OrgFacts struct {
	// Found is false when the org row does not exist.
	Found  bool
	Kind   string
	Status string
	Gen    int64
	// HostID is "" when the org was never placed on a host.
	HostID       string
	Subscription Subscription
}

// HostAck is the state of the host's answer to an intent.
type HostAck struct {
	// Queued: the intent is in the outbox (false: no row with that key).
	Queued bool
	// Acked: the host answered (applied, or already in that state).
	Acked bool
	// Failed: the outbox parked the intent; Class is its error class.
	Failed bool
	Class  string
}

// OrgStore is the org deletion's store seam. Every transition method is one
// transaction that moves the request from its step to the next only if the
// request is still at that step (a compare-and-set), so a step run twice, or
// by two drivers, does its work once. A transition that finds the request
// elsewhere returns nil and does nothing.
type OrgStore interface {
	// DueOrgRequests returns up to limit open requests whose next attempt is
	// due at now, oldest due first.
	DueOrgRequests(ctx context.Context, now time.Time, limit int) ([]OrgRequest, error)
	// OpenOrgRequest returns org's open request, ok=false when none.
	OpenOrgRequest(ctx context.Context, orgID string) (OrgRequest, bool, error)
	// OrgFacts reads the org.
	OrgFacts(ctx context.Context, orgID string) (OrgFacts, error)
	// Announce moves the org to pending_deletion at its generation + 1 with
	// the set_state intent (unless it already is), and the request to
	// cooling_off.
	Announce(ctx context.Context, req OrgRequest, now time.Time) error
	// EndCoolingOff moves the request from cooling_off to cancel_billing and
	// its state to purging, only while its state is still cooling_off (a
	// concurrent cancel wins or loses atomically). It reports whether it
	// moved the request.
	EndCoolingOff(ctx context.Context, req OrgRequest, now time.Time) (bool, error)
	// Fence moves the org to purging at in.PurgeGen and the request to
	// await_host, enqueuing in.Intents in the same transaction, and disables
	// the org's OIDC client and deletes its unused codes.
	Fence(ctx context.Context, req OrgRequest, in FenceInput, now time.Time) error
	// IntentAck reads the outbox state of the intent with this key.
	IntentAck(ctx context.Context, idempotencyKey string) (HostAck, error)
	// Finalize moves the org to purged at in.PurgedGen (unless it already
	// is), removes its memberships, and the request to done.
	Finalize(ctx context.Context, req OrgRequest, purgedGen int64, now time.Time) error
	// Restore moves a canceled request's org back to active at its
	// generation + 1 with the set_state intent (only when it is
	// pending_deletion), and the request to done.
	Restore(ctx context.Context, req OrgRequest, intent func(gen int64) (hostapi.Intent, error), now time.Time) error
	// AdvanceOrg moves the request from step from to step to.
	AdvanceOrg(ctx context.Context, requestID string, from, to Step, now time.Time) error
	// DeferOrg schedules the request's current step at until with the
	// attempt count and error class ("" clears it).
	DeferOrg(ctx context.Context, requestID string, step Step, until time.Time, attempts int, class string) error
	// BlockOrg marks the request blocked at its step with reason and the
	// error class that led to it ("" for none).
	BlockOrg(ctx context.Context, requestID string, step Step, reason, class string, now time.Time) error
}

// FenceInput is what the fence transaction writes.
type FenceInput struct {
	// PurgeGen is the generation of the transition to purging.
	PurgeGen int64
	// Intents are set_state purging, evict and set_state purged, in order.
	Intents []hostapi.Intent
}

// AccountFollowup is one account deletion's org-side half.
type AccountFollowup struct {
	RequestID     string
	AccountID     string
	Subs          []string
	PersonalOrgID string
	Step          Step
	State         string
	Attempts      int
	CreatedAt     time.Time
}

// SubSeen is one org a subject signed in to through the platform rail.
type SubSeen struct {
	OrgID string
	Sub   string
	// Kind is the org's kind.
	Kind string
}

// AccountStore is the account follow-up's store seam, with OrgStore's
// compare-and-set rule.
type AccountStore interface {
	// DueFollowups returns up to limit running follow-ups due at now.
	DueFollowups(ctx context.Context, now time.Time, limit int) ([]AccountFollowup, error)
	// VerifyFollowup checks the row against the account deletion it claims
	// (a finished account deletion of AccountID with RequestID) and its
	// personal org (an org of kind personal that AccountID created). It
	// returns "" when the row checks out, else an enum word naming the
	// mismatch (FR-12: the row's columns are never trusted on their own).
	VerifyFollowup(ctx context.Context, f AccountFollowup) (string, error)
	// OpenPersonalOrgDeletion opens an account-origin deletion of the
	// personal org with purge_after now, or brings an open request forward
	// (purge_after now; a canceled one reopened), and moves the follow-up to
	// memberships. An org already purged or missing only advances.
	OpenPersonalOrgDeletion(ctx context.Context, f AccountFollowup, now time.Time) error
	// RemoveMemberships deletes every membership of the account and moves
	// the follow-up to deactivate.
	RemoveMemberships(ctx context.Context, f AccountFollowup, now time.Time) error
	// SubsSeen lists the orgs the subjects signed in to.
	SubsSeen(ctx context.Context, subs []string) ([]SubSeen, error)
	// Deactivate enqueues intents and writes a notice for each team org in
	// notices, and moves the follow-up to await_deactivate.
	Deactivate(ctx context.Context, f AccountFollowup, intents []hostapi.Intent, notices []string, now time.Time) error
	// IntentAck reads the outbox state of the intent with this key.
	IntentAck(ctx context.Context, idempotencyKey string) (HostAck, error)
	// FinishFollowup forgets the subjects and marks the follow-up done.
	FinishFollowup(ctx context.Context, f AccountFollowup, now time.Time) error
	// AdvanceFollowup moves the follow-up from step from to step to.
	AdvanceFollowup(ctx context.Context, requestID string, from, to Step, now time.Time) error
	// DeferFollowup schedules the follow-up's current step.
	DeferFollowup(ctx context.Context, requestID string, step Step, until time.Time, attempts int, class string) error
	// BlockFollowup marks the follow-up blocked at its step with reason and
	// the error class that led to it ("" for none).
	BlockFollowup(ctx context.Context, requestID string, step Step, reason, class string, now time.Time) error
}

// Billing cancels an org's subscription. The deletion never calls Paddle
// itself: cmd/observer-cloud wires this seam over the Paddle API client.
type Billing interface {
	// CancelOrgSubscription cancels the subscription. It must be idempotent
	// on IdempotencyKey; an already canceled subscription is success. A
	// deployment without a billing client returns ErrSeamUnwired; a refusal
	// a retry cannot fix wraps ErrBillingRefused.
	CancelOrgSubscription(ctx context.Context, req CancelRequest) error
}

// CancelRequest is one subscription cancellation.
type CancelRequest struct {
	OrgID          string
	SubscriptionID string
	IdempotencyKey string
}

// Identity deletes the identity provider's user. Not found is success. A
// deployment without an identity client returns ErrSeamUnwired.
type Identity interface {
	DeleteUser(ctx context.Context, sub string) error
}

// Journal is the restore-surviving deletion journal (deletionjournal).
type Journal interface {
	Append(ctx context.Context, rec deletionjournal.Record) error
}

// Deps are the driver's seams. Billing and Identity may be nil: a step that
// needs one then blocks with the seam's named reason.
type Deps struct {
	Orgs     OrgStore
	Accounts AccountStore
	Journal  Journal
	Billing  Billing
	Identity Identity
	Now      func() time.Time
}

// Driver drives org deletions and account follow-ups. It holds no state
// between calls.
type Driver struct {
	d Deps
}

// New validates the step tables and the required seams.
func New(d Deps) (*Driver, error) {
	if err := validateTables(); err != nil {
		return nil, err
	}
	if d.Orgs == nil || d.Accounts == nil || d.Journal == nil {
		return nil, errors.New("orgdeletion.New: the org store, the account store and the journal are required")
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	return &Driver{d: d}, nil
}

// maxStepsPerPass bounds how many steps one request walks in one pass.
const maxStepsPerPass = 8

// waitPoll is how soon a waiting host step looks again.
const waitPoll = time.Minute

// PassReport counts what one pass did.
type PassReport struct {
	Orgs      int
	Followups int
	Advanced  int
	Waiting   int
	Blocked   int
	Failed    int
	// Blocks are the requests this pass blocked, one per block, so the
	// caller can raise an alert naming each (a blocked request leaves the
	// due queue and is never seen by a later pass).
	Blocks []BlockEvent
}

// BlockEvent is one request a pass blocked: ids and enum words only.
type BlockEvent struct {
	// Kind is "org" or "account".
	Kind      string
	RequestID string
	// OrgID is the org (for an account follow-up, its personal org; "" when
	// none).
	OrgID  string
	Step   Step
	Reason string
	// Class is the error class that led to the block ("" for none).
	Class string
}

// Pass runs every due org request and account follow-up once, up to limit of
// each. A request's failure is recorded on it and never stops the next.
func (dr *Driver) Pass(ctx context.Context, limit int) (PassReport, error) {
	var rep PassReport
	// The follow-ups first: their personal_org step opens an org request
	// with no window, which the org half of the same pass then fences.
	fus, err := dr.d.Accounts.DueFollowups(ctx, dr.d.Now(), limit)
	if err != nil {
		return rep, fmt.Errorf("orgdeletion.Pass: %w", err)
	}
	for _, f := range fus {
		rep.Followups++
		dr.runFollowup(ctx, f, &rep)
	}
	reqs, err := dr.d.Orgs.DueOrgRequests(ctx, dr.d.Now(), limit)
	if err != nil {
		return rep, fmt.Errorf("orgdeletion.Pass: %w", err)
	}
	for _, r := range reqs {
		rep.Orgs++
		dr.runOrg(ctx, r, &rep)
	}
	return rep, nil
}

// Outcome is one step run's result.
type Outcome struct {
	Kind   OutcomeKind
	Until  time.Time
	Reason string
	// Class is a wait's reason or a block's cause, for last_error_class.
	Class string
	Err   error
	// PurgeGen is the purge generation an advancing fence recorded, so the
	// steps after it in the same pass read the purged intent the fence
	// queued (0: the step does not change it).
	PurgeGen int64
}

func advance() Outcome              { return Outcome{Kind: OutcomeAdvance} }
func waitUntil(t time.Time) Outcome { return Outcome{Kind: OutcomeWait, Until: t} }
func waitWhy(t time.Time, class string) Outcome {
	return Outcome{Kind: OutcomeWait, Until: t, Class: class}
}
func block(reason string) Outcome { return Outcome{Kind: OutcomeBlock, Reason: reason} }
func blockWhy(reason, class string) Outcome {
	return Outcome{Kind: OutcomeBlock, Reason: reason, Class: class}
}

func retry(class string, err error) Outcome {
	return Outcome{Kind: OutcomeRetry, Err: Classed(class, err)}
}

// record writes a non-advance outcome through the table's seams and counts
// it; a block is also reported in rep.Blocks as ev with the step, reason and
// class filled in.
func record(ctx context.Context, o Outcome, step Step, attempts int, now time.Time, rep *PassReport, ev BlockEvent,
	deferFn func(ctx context.Context, step Step, until time.Time, attempts int, class string) error,
	blockFn func(ctx context.Context, step Step, reason, class string, now time.Time) error,
) {
	switch o.Kind {
	case OutcomeWait:
		rep.Waiting++
		_ = deferFn(ctx, step, o.Until, 0, o.Class)
	case OutcomeBlock:
		rep.Blocked++
		ev.Step, ev.Reason, ev.Class = step, o.Reason, o.Class
		rep.Blocks = append(rep.Blocks, ev)
		_ = blockFn(ctx, step, o.Reason, o.Class, now)
	case OutcomeRetry:
		rep.Failed++
		n := attempts + 1
		_ = deferFn(ctx, step, now.Add(Backoff(n)), n, ClassOf(o.Err))
	}
}

// runOrg walks one org request until a step does not advance.
func (dr *Driver) runOrg(ctx context.Context, r OrgRequest, rep *PassReport) {
	for i := 0; i < maxStepsPerPass && r.Step != StepDone; i++ {
		now := dr.d.Now()
		o := dr.orgStep(ctx, r, now)
		if o.Kind != OutcomeAdvance {
			record(ctx, o, r.Step, r.Attempts, now, rep, BlockEvent{Kind: "org", RequestID: r.RequestID, OrgID: r.OrgID},
				func(ctx context.Context, s Step, until time.Time, n int, class string) error {
					return dr.d.Orgs.DeferOrg(ctx, r.RequestID, s, until, n, class)
				},
				func(ctx context.Context, s Step, reason, class string, now time.Time) error {
					return dr.d.Orgs.BlockOrg(ctx, r.RequestID, s, reason, class, now)
				})
			return
		}
		rep.Advanced++
		nxt, err := next(OrgSteps(), r.Step)
		if err != nil {
			return
		}
		r.Step, r.Attempts, r.StepEnteredAt = nxt, 0, now
		if o.PurgeGen > 0 {
			r.PurgeGen = o.PurgeGen
		}
		if nxt == StepCancelBilling {
			r.State = StatePurging
		}
	}
}

// orgStep runs request r's current step.
func (dr *Driver) orgStep(ctx context.Context, r OrgRequest, now time.Time) Outcome {
	switch r.Step {
	case StepAnnounce:
		if err := dr.d.Orgs.Announce(ctx, r, now); err != nil {
			return retry("announce", err)
		}
		return advance()
	case StepCoolingOff:
		if now.Before(r.PurgeAfter) {
			return waitUntil(r.PurgeAfter)
		}
		moved, err := dr.d.Orgs.EndCoolingOff(ctx, r, now)
		if err != nil {
			return retry("end_cooling_off", err)
		}
		if !moved {
			// A concurrent cancel won: the next pass reads the restore step.
			return waitUntil(now)
		}
		return advance()
	case StepCancelBilling:
		return dr.cancelBilling(ctx, r, now)
	case StepFence:
		return dr.fence(ctx, r, now)
	case StepAwaitHost:
		return dr.awaitHost(ctx, r, now)
	case StepFinalize:
		if err := dr.d.Orgs.Finalize(ctx, r, r.PurgeGen+1, now); err != nil {
			return retry("finalize", err)
		}
		_ = dr.d.Journal.Append(ctx, deletionjournal.Record{
			Event: deletionjournal.EventDone, Kind: deletionjournal.KindOrg, OrgID: r.OrgID, RequestID: r.RequestID, At: now,
		})
		return advance()
	case StepRestore:
		err := dr.d.Orgs.Restore(ctx, r, func(gen int64) (hostapi.Intent, error) {
			return hostapi.SetStateIntent(r.OrgID, pc.StateActive, gen)
		}, now)
		if err != nil {
			return retry("restore", err)
		}
		return advance()
	}
	return block("unknown_step")
}

// cancelBilling cancels, through the billing seam, a subscription Paddle may
// still bill (Subscription.MayBill: a live one, and a refunded or
// charged-back one, which Paddle still renews).
func (dr *Driver) cancelBilling(ctx context.Context, r OrgRequest, now time.Time) Outcome {
	f, err := dr.d.Orgs.OrgFacts(ctx, r.OrgID)
	if err != nil {
		return retry("org_facts", err)
	}
	if f.Subscription.MayBill() {
		if dr.d.Billing == nil {
			return block(ReasonBillingSeamUnwired)
		}
		err := dr.d.Billing.CancelOrgSubscription(ctx, CancelRequest{
			OrgID: r.OrgID, SubscriptionID: f.Subscription.ID, IdempotencyKey: "orgdel:" + r.RequestID,
		})
		if errors.Is(err, ErrSeamUnwired) {
			return block(ReasonBillingSeamUnwired)
		}
		if errors.Is(err, ErrBillingRefused) {
			return blockWhy(ReasonBillingRefused, ClassOf(err))
		}
		if err != nil {
			return retry("billing", err)
		}
	}
	if err := dr.d.Orgs.AdvanceOrg(ctx, r.RequestID, StepCancelBilling, StepFence, now); err != nil {
		return retry("advance", err)
	}
	return advance()
}

// FenceIntents returns the fence's intents for org at purgeGen: set_state
// purging, evict, and set_state purged at purgeGen + 1 queued behind them.
func FenceIntents(orgID string, purgeGen int64) ([]hostapi.Intent, error) {
	purging, err := hostapi.SetStateIntent(orgID, pc.StatePurging, purgeGen)
	if err != nil {
		return nil, err
	}
	evict, err := hostapi.EvictIntent(orgID, purgeGen)
	if err != nil {
		return nil, err
	}
	purged, err := hostapi.SetStateIntent(orgID, pc.StatePurged, purgeGen+1)
	if err != nil {
		return nil, err
	}
	return []hostapi.Intent{purging, evict, purged}, nil
}

// fence journals the org, then fences it for purging.
func (dr *Driver) fence(ctx context.Context, r OrgRequest, now time.Time) Outcome {
	f, err := dr.d.Orgs.OrgFacts(ctx, r.OrgID)
	if err != nil {
		return retry("org_facts", err)
	}
	if !f.Found {
		return block("org_missing")
	}
	purgeGen := f.Gen + 1
	if f.Status == StatusPurging || f.Status == StatusPurged {
		purgeGen = f.Gen // a fence that committed but whose request did not move
	}
	intents, err := FenceIntents(r.OrgID, purgeGen)
	if err != nil {
		return retry("intent", err)
	}
	// The journal first: a restore to any later point purges the org again.
	if err := dr.d.Journal.Append(ctx, deletionjournal.Record{
		Event: deletionjournal.EventAccepted, Kind: deletionjournal.KindOrg, OrgID: r.OrgID, RequestID: r.RequestID, At: now,
	}); err != nil {
		return retry("journal", err)
	}
	if err := dr.d.Orgs.Fence(ctx, r, FenceInput{PurgeGen: purgeGen, Intents: intents}, now); err != nil {
		return retry("fence", err)
	}
	// The request now carries purgeGen: await_host and finalize later in
	// this pass key the purged intent (purgeGen + 1) from it, not from the
	// zero the request was loaded with before the fence.
	return Outcome{Kind: OutcomeAdvance, PurgeGen: purgeGen}
}

// awaitHost waits for the host's ack of purged, for at most HostPurgeGrace
// from the step's start; each wait records why it is still waiting.
func (dr *Driver) awaitHost(ctx context.Context, r OrgRequest, now time.Time) Outcome {
	f, err := dr.d.Orgs.OrgFacts(ctx, r.OrgID)
	if err != nil {
		return retry("org_facts", err)
	}
	if f.HostID != "" {
		purged, err := hostapi.SetStateIntent(r.OrgID, pc.StatePurged, r.PurgeGen+1)
		if err != nil {
			return retry("intent", err)
		}
		ack, err := dr.d.Orgs.IntentAck(ctx, purged.IdempotencyKey)
		if err != nil {
			return retry("intent_ack", err)
		}
		switch {
		case ack.Failed:
			return blockWhy(ReasonHostRefused, HostWaitClass(ack))
		case !ack.Acked && HostWaitOverdue(r.StepEnteredAt, now):
			return blockWhy(ReasonHostPurgeOverdue, HostWaitClass(ack))
		case !ack.Acked:
			return waitWhy(now.Add(waitPoll), HostWaitClass(ack))
		}
	}
	if err := dr.d.Orgs.AdvanceOrg(ctx, r.RequestID, StepAwaitHost, StepFinalize, now); err != nil {
		return retry("advance", err)
	}
	return advance()
}

// HostWaitOverdue reports an await_host wait that started at entered and has
// lasted HostPurgeGrace by now (a zero start never expires).
func HostWaitOverdue(entered, now time.Time) bool {
	return !entered.IsZero() && now.Sub(entered) >= HostPurgeGrace
}

// runFollowup walks one account follow-up until a step does not advance. The
// row is verified first (FR-12): a row that does not match a finished account
// deletion of its account blocks before any step runs.
func (dr *Driver) runFollowup(ctx context.Context, f AccountFollowup, rep *PassReport) {
	ev := BlockEvent{Kind: "account", RequestID: f.RequestID, OrgID: f.PersonalOrgID}
	deferFn := func(ctx context.Context, s Step, until time.Time, n int, class string) error {
		return dr.d.Accounts.DeferFollowup(ctx, f.RequestID, s, until, n, class)
	}
	blockFn := func(ctx context.Context, s Step, reason, class string, now time.Time) error {
		return dr.d.Accounts.BlockFollowup(ctx, f.RequestID, s, reason, class, now)
	}
	if f.Step != StepDone {
		now := dr.d.Now()
		mismatch, err := dr.d.Accounts.VerifyFollowup(ctx, f)
		switch {
		case err != nil:
			record(ctx, retry("verify", err), f.Step, f.Attempts, now, rep, ev, deferFn, blockFn)
			return
		case mismatch != "":
			class := mismatch
			if !classPattern.MatchString(class) {
				class = "mismatch"
			}
			record(ctx, blockWhy(ReasonFollowupUnverified, class), f.Step, f.Attempts, now, rep, ev, deferFn, blockFn)
			return
		}
	}
	for i := 0; i < maxStepsPerPass && f.Step != StepDone; i++ {
		now := dr.d.Now()
		o := dr.followupStep(ctx, f, now)
		if o.Kind != OutcomeAdvance {
			record(ctx, o, f.Step, f.Attempts, now, rep, ev, deferFn, blockFn)
			return
		}
		rep.Advanced++
		nxt, err := next(AccountSteps(), f.Step)
		if err != nil {
			return
		}
		f.Step, f.Attempts = nxt, 0
	}
}

// followupStep runs follow-up f's current step.
func (dr *Driver) followupStep(ctx context.Context, f AccountFollowup, now time.Time) Outcome {
	switch f.Step {
	case StepPersonalOrg:
		if err := dr.d.Accounts.OpenPersonalOrgDeletion(ctx, f, now); err != nil {
			return retry("personal_org", err)
		}
		return advance()
	case StepMemberships:
		if err := dr.d.Accounts.RemoveMemberships(ctx, f, now); err != nil {
			return retry("memberships", err)
		}
		return advance()
	case StepDeactivate:
		return dr.deactivate(ctx, f, now)
	case StepAwaitDeactivate:
		return dr.awaitDeactivate(ctx, f, now)
	case StepDeleteIdentity:
		return dr.deleteIdentity(ctx, f, now)
	case StepFinish:
		if err := dr.d.Accounts.FinishFollowup(ctx, f, now); err != nil {
			return retry("finish", err)
		}
		return advance()
	}
	return block("unknown_step")
}

// deactivationTargets returns the orgs whose host must deactivate the
// subjects (every org seen but the account's personal org, which is being
// purged) and the team orgs whose admins get a notice, deduplicated.
func deactivationTargets(f AccountFollowup, seen []SubSeen) (targets []SubSeen, notices []string) {
	noticed := map[string]bool{}
	for _, s := range seen {
		if s.OrgID == f.PersonalOrgID || s.Kind == KindPersonal {
			continue
		}
		targets = append(targets, s)
		if s.Kind == KindTeam && !noticed[s.OrgID] {
			noticed[s.OrgID] = true
			notices = append(notices, s.OrgID)
		}
	}
	return targets, notices
}

// deactivate queues members_deactivate per (org, sub) and the notices.
func (dr *Driver) deactivate(ctx context.Context, f AccountFollowup, now time.Time) Outcome {
	seen, err := dr.d.Accounts.SubsSeen(ctx, f.Subs)
	if err != nil {
		return retry("subs_seen", err)
	}
	targets, notices := deactivationTargets(f, seen)
	intents := make([]hostapi.Intent, 0, len(targets))
	for _, t := range targets {
		in, err := hostapi.DeactivateMemberIntent(t.OrgID, t.Sub)
		if err != nil {
			return retry("intent", err)
		}
		intents = append(intents, in)
	}
	if err := dr.d.Accounts.Deactivate(ctx, f, intents, notices, now); err != nil {
		return retry("deactivate", err)
	}
	return advance()
}

// awaitDeactivate waits until every deactivation intent is acked.
func (dr *Driver) awaitDeactivate(ctx context.Context, f AccountFollowup, now time.Time) Outcome {
	seen, err := dr.d.Accounts.SubsSeen(ctx, f.Subs)
	if err != nil {
		return retry("subs_seen", err)
	}
	targets, _ := deactivationTargets(f, seen)
	pending := false
	for _, t := range targets {
		in, err := hostapi.DeactivateMemberIntent(t.OrgID, t.Sub)
		if err != nil {
			return retry("intent", err)
		}
		ack, err := dr.d.Accounts.IntentAck(ctx, in.IdempotencyKey)
		if err != nil {
			return retry("intent_ack", err)
		}
		if ack.Failed {
			return block(ReasonDeactivateRefused)
		}
		if !ack.Acked {
			pending = true
		}
	}
	if pending {
		if !f.CreatedAt.IsZero() && now.Sub(f.CreatedAt) >= DeactivateGrace {
			return block(ReasonDeactivateOverdue)
		}
		return waitUntil(now.Add(waitPoll))
	}
	if err := dr.d.Accounts.AdvanceFollowup(ctx, f.RequestID, StepAwaitDeactivate, StepDeleteIdentity, now); err != nil {
		return retry("advance", err)
	}
	return advance()
}

// deleteIdentity deletes the identity provider's user for every subject.
func (dr *Driver) deleteIdentity(ctx context.Context, f AccountFollowup, now time.Time) Outcome {
	if len(f.Subs) > 0 {
		if dr.d.Identity == nil {
			return block(ReasonIdentitySeamUnwired)
		}
		for _, sub := range f.Subs {
			err := dr.d.Identity.DeleteUser(ctx, sub)
			if errors.Is(err, ErrSeamUnwired) {
				return block(ReasonIdentitySeamUnwired)
			}
			if err != nil {
				return retry("identity", err)
			}
		}
	}
	if err := dr.d.Accounts.AdvanceFollowup(ctx, f.RequestID, StepDeleteIdentity, StepFinish, now); err != nil {
		return retry("advance", err)
	}
	return advance()
}

// Preview is a dry run of an org deletion: what the driver would do now.
type Preview struct {
	OrgID string
	Facts OrgFacts
	// Request is the open request, nil when none.
	Request *OrgRequest
	// Steps are the steps left, in order (the whole path when no request).
	Steps []Step
	// Window is the cooling-off window an owner request opened now gets.
	Window time.Duration
	// WillCancelSubscription reports a subscription the cancel_billing step
	// would cancel (Subscription.MayBill).
	WillCancelSubscription bool
	// BillingWired and IdentityWired report the seams.
	BillingWired bool
}

// PreviewOrg reports what the driver would do with org now. It writes
// nothing. lastSeatDay feeds the window (zero: no seat ever reported).
func (dr *Driver) PreviewOrg(ctx context.Context, orgID string, lastSeatDay time.Time) (Preview, error) {
	p := Preview{OrgID: orgID, BillingWired: dr.d.Billing != nil}
	f, err := dr.d.Orgs.OrgFacts(ctx, orgID)
	if err != nil {
		return p, fmt.Errorf("orgdeletion.PreviewOrg: %w", err)
	}
	p.Facts = f
	p.WillCancelSubscription = f.Subscription.MayBill()
	p.Window = CoolingOff(CoolingFacts{Origin: OriginOwner, LiveSubscription: f.Subscription.Live(), LastSeatDay: lastSeatDay, Now: dr.d.Now()})
	r, ok, err := dr.d.Orgs.OpenOrgRequest(ctx, orgID)
	if err != nil {
		return p, fmt.Errorf("orgdeletion.PreviewOrg: %w", err)
	}
	if ok {
		p.Request = &r
		if r.Step == StepRestore {
			p.Steps = []Step{StepRestore}
		} else {
			p.Steps = remaining(OrgSteps(), r.Step)
		}
	} else {
		p.Steps = remaining(OrgSteps(), "")
	}
	return p, nil
}
