package orgdeletion

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/deletionjournal"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/hostapi"
)

// fakeOrg is one org in the fake store.
type fakeOrg struct {
	kind, status string
	gen          int64
	host         string
	sub          Subscription
	members      []string
	oidcDisabled bool
}

// fake is an in-memory OrgStore and AccountStore with the compare-and-set
// rule of the real store.
type fake struct {
	mu        sync.Mutex
	orgs      map[string]*fakeOrg
	reqs      map[string]*OrgRequest
	blocked   map[string]string
	deferred  map[string]time.Time
	classes   map[string]string
	fus       map[string]*AccountFollowup
	fuBlocked map[string]string
	// blockClass is the class each block recorded (org request id, or
	// "fu:" + follow-up id).
	blockClass map[string]string
	// fuMismatch is VerifyFollowup's answer per follow-up ("" checks out).
	fuMismatch map[string]string
	intents    []hostapi.Intent
	acks       map[string]HostAck
	notices    []string
	seen       []SubSeen
	failFence  error
}

func newFake() *fake {
	return &fake{
		orgs: map[string]*fakeOrg{}, reqs: map[string]*OrgRequest{}, blocked: map[string]string{},
		deferred: map[string]time.Time{}, classes: map[string]string{}, fus: map[string]*AccountFollowup{},
		fuBlocked: map[string]string{}, acks: map[string]HostAck{}, blockClass: map[string]string{},
		fuMismatch: map[string]string{},
	}
}

func (f *fake) DueOrgRequests(_ context.Context, now time.Time, _ int) ([]OrgRequest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []OrgRequest
	for id, r := range f.reqs {
		if r.Step == StepDone || f.blocked[id] != "" || f.deferred[id].After(now) {
			continue
		}
		out = append(out, *r)
	}
	return out, nil
}

func (f *fake) OpenOrgRequest(_ context.Context, org string) (OrgRequest, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.reqs {
		if r.OrgID == org && r.Step != StepDone {
			return *r, true, nil
		}
	}
	return OrgRequest{}, false, nil
}

func (f *fake) OrgFacts(_ context.Context, org string) (OrgFacts, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	o, ok := f.orgs[org]
	if !ok {
		return OrgFacts{}, nil
	}
	return OrgFacts{Found: true, Kind: o.kind, Status: o.status, Gen: o.gen, HostID: o.host, Subscription: o.sub}, nil
}

// cas moves request id from step from to to, reporting whether it did.
func (f *fake) cas(id string, from, to Step) (*OrgRequest, bool) {
	r := f.reqs[id]
	if r == nil || r.Step != from {
		return nil, false
	}
	r.Step = to
	delete(f.deferred, id)
	return r, true
}

func (f *fake) Announce(_ context.Context, req OrgRequest, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.cas(req.RequestID, StepAnnounce, StepCoolingOff); !ok {
		return nil
	}
	o := f.orgs[req.OrgID]
	if o.status != StatusPendingDeletion {
		o.gen++
		o.status = StatusPendingDeletion
		in, _ := hostapi.SetStateIntent(req.OrgID, "pending_deletion", o.gen)
		f.intents = append(f.intents, in)
	}
	return nil
}

func (f *fake) EndCoolingOff(_ context.Context, req OrgRequest, _ time.Time) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.reqs[req.RequestID]
	if r == nil || r.Step != StepCoolingOff || r.State != StateCoolingOff {
		return false, nil
	}
	r.Step, r.State = StepCancelBilling, StatePurging
	return true, nil
}

func (f *fake) Fence(_ context.Context, req OrgRequest, in FenceInput, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failFence != nil {
		return f.failFence
	}
	r, ok := f.cas(req.RequestID, StepFence, StepAwaitHost)
	if !ok {
		return nil
	}
	r.PurgeGen = in.PurgeGen
	o := f.orgs[req.OrgID]
	o.status, o.gen, o.oidcDisabled = StatusPurging, in.PurgeGen, true
	f.intents = append(f.intents, in.Intents...)
	return nil
}

func (f *fake) IntentAck(_ context.Context, key string) (HostAck, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.acks[key], nil
}

func (f *fake) Finalize(_ context.Context, req OrgRequest, gen int64, now time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.cas(req.RequestID, StepFinalize, StepDone)
	if !ok {
		return nil
	}
	r.State = StateDone
	o := f.orgs[req.OrgID]
	o.status, o.gen, o.members = StatusPurged, gen, nil
	return nil
}

func (f *fake) Restore(_ context.Context, req OrgRequest, intent func(int64) (hostapi.Intent, error), _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.cas(req.RequestID, StepRestore, StepDone); !ok {
		return nil
	}
	o := f.orgs[req.OrgID]
	if o.status == StatusPendingDeletion {
		o.gen++
		o.status = "active"
		in, err := intent(o.gen)
		if err != nil {
			return err
		}
		f.intents = append(f.intents, in)
	}
	return nil
}

func (f *fake) AdvanceOrg(_ context.Context, id string, from, to Step, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cas(id, from, to)
	return nil
}

func (f *fake) DeferOrg(_ context.Context, id string, _ Step, until time.Time, n int, class string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deferred[id], f.classes[id] = until, class
	f.reqs[id].Attempts = n
	return nil
}

func (f *fake) BlockOrg(_ context.Context, id string, _ Step, reason, class string, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blocked[id], f.blockClass[id] = reason, class
	return nil
}

func (f *fake) VerifyFollowup(_ context.Context, a AccountFollowup) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fuMismatch[a.RequestID], nil
}

func (f *fake) DueFollowups(_ context.Context, now time.Time, _ int) ([]AccountFollowup, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []AccountFollowup
	for id, a := range f.fus {
		if a.Step == StepDone || f.fuBlocked[id] != "" || f.deferred["fu:"+id].After(now) {
			continue
		}
		out = append(out, *a)
	}
	return out, nil
}

func (f *fake) fuCAS(id string, from, to Step) (*AccountFollowup, bool) {
	a := f.fus[id]
	if a == nil || a.Step != from {
		return nil, false
	}
	a.Step = to
	return a, true
}

func (f *fake) OpenPersonalOrgDeletion(_ context.Context, a AccountFollowup, now time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.fuCAS(a.RequestID, StepPersonalOrg, StepMemberships); !ok || a.PersonalOrgID == "" {
		return nil
	}
	for _, r := range f.reqs {
		if r.OrgID == a.PersonalOrgID && r.Step != StepDone {
			r.PurgeAfter = now
			return nil
		}
	}
	f.reqs["acct-"+a.RequestID] = &OrgRequest{
		RequestID: "acct-" + a.RequestID, OrgID: a.PersonalOrgID, State: StateCoolingOff,
		Step: StepAnnounce, Origin: OriginAccountDeletion, PurgeAfter: now,
	}
	return nil
}

func (f *fake) RemoveMemberships(_ context.Context, a AccountFollowup, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.fuCAS(a.RequestID, StepMemberships, StepDeactivate); !ok {
		return nil
	}
	for _, o := range f.orgs {
		o.members = slices.DeleteFunc(o.members, func(m string) bool { return m == a.AccountID })
	}
	return nil
}

func (f *fake) SubsSeen(_ context.Context, subs []string) ([]SubSeen, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []SubSeen
	for _, s := range f.seen {
		if slices.Contains(subs, s.Sub) {
			out = append(out, s)
		}
	}
	return out, nil
}

func (f *fake) Deactivate(_ context.Context, a AccountFollowup, intents []hostapi.Intent, notices []string, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.fuCAS(a.RequestID, StepDeactivate, StepAwaitDeactivate); !ok {
		return nil
	}
	f.intents = append(f.intents, intents...)
	f.notices = append(f.notices, notices...)
	return nil
}

func (f *fake) FinishFollowup(_ context.Context, a AccountFollowup, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if x, ok := f.fuCAS(a.RequestID, StepFinish, StepDone); ok {
		x.Subs, x.State = nil, "done"
	}
	return nil
}

func (f *fake) AdvanceFollowup(_ context.Context, id string, from, to Step, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fuCAS(id, from, to)
	return nil
}

func (f *fake) DeferFollowup(_ context.Context, id string, _ Step, until time.Time, n int, class string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deferred["fu:"+id], f.classes["fu:"+id] = until, class
	f.fus[id].Attempts = n
	return nil
}

func (f *fake) BlockFollowup(_ context.Context, id string, _ Step, reason, class string, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fuBlocked[id], f.blockClass["fu:"+id] = reason, class
	return nil
}

// memJournal records appends.
type memJournal struct {
	mu   sync.Mutex
	recs []deletionjournal.Record
	fail error
}

func (j *memJournal) Append(_ context.Context, r deletionjournal.Record) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.fail != nil {
		return j.fail
	}
	j.recs = append(j.recs, r)
	return nil
}

// fakeBilling records cancellations.
type fakeBilling struct {
	calls []CancelRequest
	err   error
}

func (b *fakeBilling) CancelOrgSubscription(_ context.Context, r CancelRequest) error {
	b.calls = append(b.calls, r)
	return b.err
}

// fakeIdentity records deletions.
type fakeIdentity struct {
	deleted []string
	err     error
}

func (i *fakeIdentity) DeleteUser(_ context.Context, sub string) error {
	if i.err != nil {
		return i.err
	}
	i.deleted = append(i.deleted, sub)
	return nil
}

// clock is a settable time source.
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func driverFor(t *testing.T, f *fake, j *memJournal, b Billing, id Identity, c *clock) *Driver {
	t.Helper()
	d, err := New(Deps{Orgs: f, Accounts: f, Journal: j, Billing: b, Identity: id, Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func pass(t *testing.T, d *Driver) PassReport {
	t.Helper()
	rep, err := d.Pass(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func intentKeys(f *fake) []string {
	var out []string
	for _, in := range f.intents {
		out = append(out, in.IdempotencyKey)
	}
	return out
}

var t0 = time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)

// TestOrgDeletionEndToEnd walks an owner deletion through every step: the
// org is announced, waits out the window, its subscription is cancelled, it
// is journaled and fenced, the driver waits for the host's purge, and it is
// finalized.
func TestOrgDeletionEndToEnd(t *testing.T) {
	t.Parallel()
	f := newFake()
	f.orgs["org1"] = &fakeOrg{kind: KindTeam, status: "active", gen: 3, host: "h1", sub: Subscription{ID: "sub_1", Status: "active"}, members: []string{"a", "b"}}
	f.reqs["r1"] = &OrgRequest{RequestID: "r1", OrgID: "org1", State: StateCoolingOff, Step: StepAnnounce, Origin: OriginOwner, PurgeAfter: t0.Add(DefaultCoolingOff)}
	j, b, c := &memJournal{}, &fakeBilling{}, &clock{t: t0}
	d := driverFor(t, f, j, b, nil, c)

	pass(t, d)
	if o := f.orgs["org1"]; o.status != StatusPendingDeletion || o.gen != 4 {
		t.Fatalf("after announce: %+v", o)
	}
	if f.reqs["r1"].Step != StepCoolingOff || !f.deferred["r1"].Equal(t0.Add(DefaultCoolingOff)) {
		t.Fatalf("the request should wait out the window: %+v deferred %v", f.reqs["r1"], f.deferred["r1"])
	}
	if len(j.recs) != 0 {
		t.Fatal("nothing is journaled while the deletion can still be canceled")
	}

	c.t = t0.Add(DefaultCoolingOff)
	pass(t, d)
	if len(b.calls) != 1 || b.calls[0] != (CancelRequest{OrgID: "org1", SubscriptionID: "sub_1", IdempotencyKey: "orgdel:r1"}) {
		t.Fatalf("billing calls = %+v", b.calls)
	}
	if r := f.reqs["r1"]; r.Step != StepAwaitHost || r.PurgeGen != 5 || r.State != StatePurging {
		t.Fatalf("after fence: %+v", r)
	}
	if !f.orgs["org1"].oidcDisabled {
		t.Error("the fence disables the org's OIDC client")
	}
	want := []string{"state:org1:4:pending_deletion", "state:org1:5:purging", "evict:org1:5", "state:org1:6:purged"}
	if got := intentKeys(f); !slices.Equal(got, want) {
		t.Fatalf("intents = %v, want %v", got, want)
	}
	if len(j.recs) != 1 || j.recs[0].Kind != deletionjournal.KindOrg || j.recs[0].Event != deletionjournal.EventAccepted || j.recs[0].OrgID != "org1" {
		t.Fatalf("journal = %+v", j.recs)
	}

	// The host has not purged yet: wait.
	c.t = c.t.Add(time.Minute)
	pass(t, d)
	if f.reqs["r1"].Step != StepAwaitHost {
		t.Fatal("finalized before the host acked purged")
	}
	f.acks["state:org1:6:purged"] = HostAck{Acked: true}
	c.t = c.t.Add(2 * time.Minute)
	pass(t, d)
	if r := f.reqs["r1"]; r.Step != StepDone || r.State != StateDone {
		t.Fatalf("not done: %+v", r)
	}
	if o := f.orgs["org1"]; o.status != StatusPurged || o.gen != 6 || len(o.members) != 0 {
		t.Fatalf("after finalize: %+v", o)
	}
	if len(j.recs) != 2 || j.recs[1].Event != deletionjournal.EventDone {
		t.Fatalf("journal = %+v", j.recs)
	}
	// Idempotent: another pass does nothing.
	if rep := pass(t, d); rep.Orgs != 0 {
		t.Errorf("a done request was driven again: %+v", rep)
	}
}

// TestOrgDeletionCancel: a canceled request restores the org at a new
// generation and journals nothing.
func TestOrgDeletionCancel(t *testing.T) {
	t.Parallel()
	f := newFake()
	f.orgs["org1"] = &fakeOrg{kind: KindTeam, status: "active", gen: 1, host: "h1"}
	f.reqs["r1"] = &OrgRequest{RequestID: "r1", OrgID: "org1", State: StateCoolingOff, Step: StepAnnounce, PurgeAfter: t0.Add(DefaultCoolingOff)}
	j, c := &memJournal{}, &clock{t: t0}
	d := driverFor(t, f, j, nil, nil, c)
	pass(t, d)
	// The owner cancels (the definer function's write).
	f.reqs["r1"].State, f.reqs["r1"].Step = StateCanceled, StepRestore
	delete(f.deferred, "r1")
	pass(t, d)
	if o := f.orgs["org1"]; o.status != "active" || o.gen != 3 {
		t.Fatalf("restored org = %+v", o)
	}
	if got := intentKeys(f); !slices.Equal(got, []string{"state:org1:2:pending_deletion", "state:org1:3:active"}) {
		t.Fatalf("intents = %v", got)
	}
	if f.reqs["r1"].Step != StepDone || len(j.recs) != 0 {
		t.Fatalf("request %+v journal %+v", f.reqs["r1"], j.recs)
	}
}

// TestOrgDeletionStepOutcomes covers the blocking and retrying outcomes of
// the steps that call a seam.
func TestOrgDeletionStepOutcomes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		step      Step
		billing   Billing
		sub       Subscription
		ack       HostAck
		host      string
		journal   error
		fence     error
		wantStep  Step
		wantBlock string
		wantClass string
		// polls: the outcome is the host wait's poll (now+waitPoll), not a
		// retry backoff (FR-23 records why it waits).
		polls bool
	}{
		{name: "no live subscription and no billing seam: proceed to the host wait", step: StepCancelBilling, host: "h1", sub: Subscription{ID: "s", Status: "canceled"}, wantStep: StepAwaitHost, wantClass: WaitHostIntentMissing, polls: true},
		{name: "live subscription, no billing seam: blocked", step: StepCancelBilling, sub: Subscription{ID: "s", Status: "active"}, wantStep: StepCancelBilling, wantBlock: ReasonBillingSeamUnwired},
		{name: "refunded subscription Paddle still renews, no billing seam: blocked", step: StepCancelBilling, sub: Subscription{ID: "s", Status: "refunded"}, wantStep: StepCancelBilling, wantBlock: ReasonBillingSeamUnwired},
		{name: "charged-back subscription Paddle still renews, no billing seam: blocked", step: StepCancelBilling, sub: Subscription{ID: "s", Status: "charged_back"}, wantStep: StepCancelBilling, wantBlock: ReasonBillingSeamUnwired},
		{name: "seam answers unwired: blocked", step: StepCancelBilling, sub: Subscription{ID: "s", Status: "active"}, billing: &fakeBilling{err: ErrSeamUnwired}, wantStep: StepCancelBilling, wantBlock: ReasonBillingSeamUnwired},
		{name: "billing fails: retried", step: StepCancelBilling, sub: Subscription{ID: "s", Status: "active"}, billing: &fakeBilling{err: errors.New("503")}, wantStep: StepCancelBilling, wantClass: "billing"},
		{name: "billing refused for good: blocked, not retried (FR-1)", step: StepCancelBilling, sub: Subscription{ID: "s", Status: "active"}, billing: &fakeBilling{err: Classed("billing:http_403", fmt.Errorf("%w: forbidden", ErrBillingRefused))}, wantStep: StepCancelBilling, wantBlock: ReasonBillingRefused},
		{name: "journal fails: nothing fenced", step: StepFence, journal: errors.New("disk"), wantStep: StepFence, wantClass: "journal"},
		{name: "fence fails: retried", step: StepFence, fence: errors.New("db"), wantStep: StepFence, wantClass: "fence"},
		{name: "host parked purged: blocked", step: StepAwaitHost, host: "h1", ack: HostAck{Failed: true, Class: "refused:invalid"}, wantStep: StepAwaitHost, wantBlock: ReasonHostRefused},
		{name: "never placed: no host to wait for", step: StepAwaitHost, wantStep: StepDone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.orgs["o"] = &fakeOrg{kind: KindTeam, status: StatusPendingDeletion, gen: 2, host: tc.host, sub: tc.sub}
			if tc.step == StepAwaitHost {
				f.orgs["o"].status = StatusPurging
			}
			f.reqs["r"] = &OrgRequest{RequestID: "r", OrgID: "o", State: StatePurging, Step: tc.step, PurgeGen: 2}
			f.acks["state:o:3:purged"] = tc.ack
			f.failFence = tc.fence
			d := driverFor(t, f, &memJournal{fail: tc.journal}, tc.billing, nil, &clock{t: t0})
			pass(t, d)
			if got := f.reqs["r"].Step; got != tc.wantStep {
				t.Errorf("step = %s, want %s", got, tc.wantStep)
			}
			if got := f.blocked["r"]; got != tc.wantBlock {
				t.Errorf("blocked = %q, want %q", got, tc.wantBlock)
			}
			if got := f.classes["r"]; got != tc.wantClass {
				t.Errorf("class = %q, want %q", got, tc.wantClass)
			}
			switch {
			case tc.polls && !f.deferred["r"].Equal(t0.Add(waitPoll)):
				t.Errorf("poll at %v, want now+waitPoll", f.deferred["r"])
			case !tc.polls && tc.wantClass != "" && !f.deferred["r"].Equal(t0.Add(Backoff(1))):
				t.Errorf("retry at %v, want the first backoff", f.deferred["r"])
			}
		})
	}
}

// TestCancelBillingCancelsWhatPaddleMayBill: cancel_billing cancels every
// subscription Paddle may still bill before the org is fenced, a refunded or
// charged-back one included (a refund or chargeback revokes the plan but does
// not cancel the Paddle subscription, FR-7), and calls nothing for a canceled
// one or none.
func TestCancelBillingCancelsWhatPaddleMayBill(t *testing.T) {
	t.Parallel()
	cases := []struct {
		sub        Subscription
		wantCancel bool
	}{
		{Subscription{ID: "sub_9", Status: "active"}, true},
		{Subscription{ID: "sub_9", Status: "past_due"}, true},
		{Subscription{ID: "sub_9", Status: "refunded"}, true},
		{Subscription{ID: "sub_9", Status: "charged_back"}, true},
		{Subscription{ID: "sub_9", Status: "canceled"}, false},
		{Subscription{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.sub.Status, func(t *testing.T) {
			t.Parallel()
			f := newFake()
			f.orgs["o"] = &fakeOrg{kind: KindTeam, status: StatusPendingDeletion, gen: 2, host: "h1", sub: tc.sub}
			f.reqs["r"] = &OrgRequest{RequestID: "r", OrgID: "o", State: StatePurging, Step: StepCancelBilling}
			b := &fakeBilling{}
			d := driverFor(t, f, &memJournal{}, b, nil, &clock{t: t0})
			if p, err := d.PreviewOrg(context.Background(), "o", time.Time{}); err != nil || p.WillCancelSubscription != tc.wantCancel {
				t.Errorf("preview will cancel = %v (%v), want %v", p.WillCancelSubscription, err, tc.wantCancel)
			}
			pass(t, d)
			if tc.wantCancel {
				if len(b.calls) != 1 || b.calls[0].SubscriptionID != "sub_9" || b.calls[0].IdempotencyKey != "orgdel:r" {
					t.Fatalf("billing calls = %+v, want one cancel of sub_9", b.calls)
				}
			} else if len(b.calls) != 0 {
				t.Fatalf("billing calls = %+v, want none", b.calls)
			}
			if got := f.reqs["r"].Step; got != StepAwaitHost || f.blocked["r"] != "" {
				t.Errorf("step = %s blocked %q, want on to the host wait", got, f.blocked["r"])
			}
		})
	}
}

// TestFenceCarriesPurgeGenWithinThePass: a request loaded before its fence
// has purge_gen 0; the steps after the fence in the same pass must key the
// purged intent from the generation the fence recorded. Otherwise the host
// wait probes a key nothing queued and records host_intent_missing for a
// queued intent, and a hostless org is finalized at the wrong generation.
func TestFenceCarriesPurgeGenWithinThePass(t *testing.T) {
	t.Parallel()
	t.Run("host wait sees the queued intent", func(t *testing.T) {
		f := newFake()
		f.orgs["o"] = &fakeOrg{kind: KindTeam, status: StatusPendingDeletion, gen: 2, host: "h1"}
		f.reqs["r"] = &OrgRequest{RequestID: "r", OrgID: "o", State: StatePurging, Step: StepFence}
		// The fence purges at gen 3 and queues purged at gen 4.
		f.acks["state:o:4:purged"] = HostAck{Queued: true}
		pass(t, driverFor(t, f, &memJournal{}, nil, nil, &clock{t: t0}))
		if got := f.reqs["r"].Step; got != StepAwaitHost {
			t.Fatalf("step = %s, want %s", got, StepAwaitHost)
		}
		if got := f.classes["r"]; got != WaitHostAckPending {
			t.Fatalf("class = %q, want %q", got, WaitHostAckPending)
		}
	})
	t.Run("a hostless org finalizes at the purged generation", func(t *testing.T) {
		f := newFake()
		f.orgs["o"] = &fakeOrg{kind: KindTeam, status: StatusPendingDeletion, gen: 2}
		f.reqs["r"] = &OrgRequest{RequestID: "r", OrgID: "o", State: StatePurging, Step: StepFence}
		pass(t, driverFor(t, f, &memJournal{}, nil, nil, &clock{t: t0}))
		if got := f.reqs["r"].Step; got != StepDone {
			t.Fatalf("step = %s, want %s", got, StepDone)
		}
		if o := f.orgs["o"]; o.status != StatusPurged || o.gen != 4 {
			t.Fatalf("org = %s gen %d, want %s gen 4", o.status, o.gen, StatusPurged)
		}
	})
}

// TestAccountFollowupEndToEnd walks an account deletion's org side.
func TestAccountFollowupEndToEnd(t *testing.T) {
	t.Parallel()
	f := newFake()
	f.orgs["personal"] = &fakeOrg{kind: KindPersonal, status: "active", gen: 1, host: "h1", members: []string{"acct"}}
	f.orgs["team"] = &fakeOrg{kind: KindTeam, status: "active", gen: 1, host: "h1", members: []string{"acct", "other"}}
	f.seen = []SubSeen{
		{OrgID: "personal", Sub: "user_1", Kind: KindPersonal},
		{OrgID: "team", Sub: "user_1", Kind: KindTeam},
		{OrgID: "team2", Sub: "user_1", Kind: KindTeam},
		{OrgID: "team", Sub: "user_other", Kind: KindTeam},
	}
	f.fus["dr1"] = &AccountFollowup{RequestID: "dr1", AccountID: "acct", Subs: []string{"user_1"}, PersonalOrgID: "personal", Step: StepPersonalOrg, State: "running", CreatedAt: t0}
	id, c := &fakeIdentity{}, &clock{t: t0}
	d := driverFor(t, f, &memJournal{}, nil, id, c)

	pass(t, d)
	if a := f.fus["dr1"]; a.Step != StepAwaitDeactivate {
		t.Fatalf("follow-up at %s, want await_deactivate", a.Step)
	}
	r, ok, _ := f.OpenOrgRequest(context.Background(), "personal")
	if !ok || r.Origin != OriginAccountDeletion {
		t.Fatalf("personal org request = %+v %v", r, ok)
	}
	if slices.Contains(f.orgs["team"].members, "acct") || !slices.Contains(f.orgs["team"].members, "other") {
		t.Errorf("team members = %v", f.orgs["team"].members)
	}
	var deact []string
	for _, k := range intentKeys(f) {
		if strings.HasPrefix(k, "deact:") {
			deact = append(deact, k)
		}
	}
	if !slices.Equal(deact, []string{"deact:team:user_1", "deact:team2:user_1"}) {
		t.Fatalf("deactivations = %v", deact)
	}
	if !slices.Equal(f.notices, []string{"team", "team2"}) {
		t.Errorf("notices = %v", f.notices)
	}
	if len(id.deleted) != 0 {
		t.Fatal("the WorkOS user was deleted before the deactivations were acked")
	}

	f.acks["deact:team:user_1"] = HostAck{Acked: true}
	c.t = c.t.Add(2 * time.Minute)
	pass(t, d)
	if f.fus["dr1"].Step != StepAwaitDeactivate {
		t.Fatal("advanced with one deactivation still open")
	}
	f.acks["deact:team2:user_1"] = HostAck{Acked: true}
	c.t = c.t.Add(2 * time.Minute)
	pass(t, d)
	if a := f.fus["dr1"]; a.Step != StepDone || len(a.Subs) != 0 {
		t.Fatalf("follow-up = %+v", a)
	}
	if !slices.Equal(id.deleted, []string{"user_1"}) {
		t.Errorf("identity deletions = %v", id.deleted)
	}
}

// TestAccountFollowupOutcomes covers the follow-up's blocking outcomes.
func TestAccountFollowupOutcomes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		step      Step
		created   time.Time
		ack       HostAck
		identity  Identity
		wantBlock string
		wantStep  Step
	}{
		{name: "deactivation refused by the host", step: StepAwaitDeactivate, created: t0, ack: HostAck{Failed: true}, wantBlock: ReasonDeactivateRefused, wantStep: StepAwaitDeactivate},
		{name: "deactivation still open within the grace", step: StepAwaitDeactivate, created: t0.Add(-time.Hour), wantStep: StepAwaitDeactivate},
		{name: "deactivation overdue", step: StepAwaitDeactivate, created: t0.Add(-DeactivateGrace), wantBlock: ReasonDeactivateOverdue, wantStep: StepAwaitDeactivate},
		{name: "no identity seam", step: StepDeleteIdentity, wantBlock: ReasonIdentitySeamUnwired, wantStep: StepDeleteIdentity},
		{name: "identity seam unwired", step: StepDeleteIdentity, identity: &fakeIdentity{err: ErrSeamUnwired}, wantBlock: ReasonIdentitySeamUnwired, wantStep: StepDeleteIdentity},
		{name: "identity deleted", step: StepDeleteIdentity, identity: &fakeIdentity{}, wantStep: StepDone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.seen = []SubSeen{{OrgID: "team", Sub: "u", Kind: KindTeam}}
			f.acks["deact:team:u"] = tc.ack
			f.fus["x"] = &AccountFollowup{RequestID: "x", AccountID: "a", Subs: []string{"u"}, Step: tc.step, State: "running", CreatedAt: tc.created}
			d := driverFor(t, f, &memJournal{}, nil, tc.identity, &clock{t: t0})
			pass(t, d)
			if got := f.fuBlocked["x"]; got != tc.wantBlock {
				t.Errorf("blocked = %q, want %q", got, tc.wantBlock)
			}
			if got := f.fus["x"].Step; got != tc.wantStep {
				t.Errorf("step = %s, want %s", got, tc.wantStep)
			}
		})
	}
}

// TestPreviewOrgWritesNothing: the dry run reports the path and the facts.
func TestPreviewOrgWritesNothing(t *testing.T) {
	t.Parallel()
	f := newFake()
	f.orgs["o"] = &fakeOrg{kind: KindTeam, status: "active", gen: 1, sub: Subscription{ID: "s", Status: "active"}}
	d := driverFor(t, f, &memJournal{}, nil, nil, &clock{t: t0})
	p, err := d.PreviewOrg(context.Background(), "o", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if p.Request != nil || !p.WillCancelSubscription || p.BillingWired || p.Window != DefaultCoolingOff {
		t.Errorf("preview = %+v", p)
	}
	if !slices.Equal(p.Steps, []Step{StepAnnounce, StepCoolingOff, StepCancelBilling, StepFence, StepAwaitHost, StepFinalize}) {
		t.Errorf("steps = %v", p.Steps)
	}
	if len(f.intents) != 0 || f.orgs["o"].gen != 1 {
		t.Error("the dry run wrote")
	}
	f.reqs["r"] = &OrgRequest{RequestID: "r", OrgID: "o", Step: StepAwaitHost}
	p, _ = d.PreviewOrg(context.Background(), "o", time.Time{})
	if p.Request == nil || !slices.Equal(p.Steps, []Step{StepAwaitHost, StepFinalize}) {
		t.Errorf("open request preview = %+v", p)
	}
}

// TestNewRequiresSeams refuses a driver without its required seams.
func TestNewRequiresSeams(t *testing.T) {
	t.Parallel()
	if _, err := New(Deps{}); err == nil {
		t.Error("a driver with no seams was built")
	}
}

// TestAwaitHostIsBounded (FR-23): await_host records why it waits, and after
// HostPurgeGrace from the step's start it blocks as host_purge_overdue
// instead of polling for ever. One row per outcome.
func TestAwaitHostIsBounded(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		entered   time.Time
		ack       HostAck
		wantBlock string
		wantClass string // the wait's class, or the block's
		wantUntil time.Time
	}{
		{name: "queued, not answered, within the grace: wait with the reason", entered: t0.Add(-time.Hour), ack: HostAck{Queued: true}, wantClass: WaitHostAckPending, wantUntil: t0.Add(waitPoll)},
		{name: "queued with the outbox's error class: wait naming it", entered: t0.Add(-time.Hour), ack: HostAck{Queued: true, Class: "unavailable"}, wantClass: "host:unavailable", wantUntil: t0.Add(waitPoll)},
		{name: "no intent in the outbox: wait naming that", entered: t0.Add(-time.Hour), wantClass: WaitHostIntentMissing, wantUntil: t0.Add(waitPoll)},
		{name: "past the grace: blocked overdue", entered: t0.Add(-HostPurgeGrace), ack: HostAck{Queued: true}, wantBlock: ReasonHostPurgeOverdue, wantClass: WaitHostAckPending},
		{name: "no start recorded: never overdue", ack: HostAck{Queued: true}, wantClass: WaitHostAckPending, wantUntil: t0.Add(waitPoll)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFake()
			f.orgs["o"] = &fakeOrg{kind: KindTeam, status: StatusPurging, gen: 2, host: "h1"}
			f.reqs["r"] = &OrgRequest{RequestID: "r", OrgID: "o", State: StatePurging, Step: StepAwaitHost, PurgeGen: 2, StepEnteredAt: tc.entered}
			f.acks["state:o:3:purged"] = tc.ack
			d := driverFor(t, f, &memJournal{}, nil, nil, &clock{t: t0})
			rep := pass(t, d)
			if got := f.blocked["r"]; got != tc.wantBlock {
				t.Fatalf("blocked = %q, want %q", got, tc.wantBlock)
			}
			if tc.wantBlock != "" {
				if f.blockClass["r"] != tc.wantClass || len(rep.Blocks) != 1 || rep.Blocks[0].Reason != tc.wantBlock || rep.Blocks[0].Kind != "org" {
					t.Fatalf("block class %q, report %+v", f.blockClass["r"], rep.Blocks)
				}
				return
			}
			if f.classes["r"] != tc.wantClass || !f.deferred["r"].Equal(tc.wantUntil) || len(rep.Blocks) != 0 {
				t.Fatalf("wait class %q until %v, blocks %+v", f.classes["r"], f.deferred["r"], rep.Blocks)
			}
		})
	}
}

// TestHostWaitClass: one row per class rule, including an outbox class that
// does not fit the column.
func TestHostWaitClass(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		ack  HostAck
		want string
	}{
		{HostAck{}, WaitHostIntentMissing},
		{HostAck{Queued: true}, WaitHostAckPending},
		{HostAck{Queued: true, Class: "refused:invalid"}, "host:refused:invalid"},
		{HostAck{Queued: true, Class: "Has Spaces"}, WaitHostAckPending},
	} {
		if got := HostWaitClass(tc.ack); got != tc.want {
			t.Errorf("HostWaitClass(%+v) = %q, want %q", tc.ack, got, tc.want)
		}
	}
}

// TestFollowupIsVerifiedFirst (FR-12): a follow-up row that does not match a
// finished deletion of its account blocks before any step runs: no personal
// org request, no membership removed.
func TestFollowupIsVerifiedFirst(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		mismatch  string
		wantBlock string
		wantClass string
		wantStep  Step
	}{
		{name: "checks out: the steps run", wantStep: StepDone},
		{name: "no finished account deletion: blocked", mismatch: "no_account_deletion", wantBlock: ReasonFollowupUnverified, wantClass: "no_account_deletion", wantStep: StepPersonalOrg},
		{name: "personal org not the account's: blocked", mismatch: "personal_org_mismatch", wantBlock: ReasonFollowupUnverified, wantClass: "personal_org_mismatch", wantStep: StepPersonalOrg},
		{name: "a word that does not fit the column: blocked as mismatch", mismatch: "Bad Word", wantBlock: ReasonFollowupUnverified, wantClass: "mismatch", wantStep: StepPersonalOrg},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFake()
			f.orgs["victim"] = &fakeOrg{kind: KindTeam, status: "active", gen: 1, members: []string{"acct", "other"}}
			f.fus["x"] = &AccountFollowup{RequestID: "x", AccountID: "acct", PersonalOrgID: "victim", Step: StepPersonalOrg, State: "running", CreatedAt: t0}
			f.fuMismatch["x"] = tc.mismatch
			d := driverFor(t, f, &memJournal{}, nil, nil, &clock{t: t0})
			rep := pass(t, d)
			if got := f.fuBlocked["x"]; got != tc.wantBlock {
				t.Fatalf("blocked = %q, want %q", got, tc.wantBlock)
			}
			if got := f.fus["x"].Step; got != tc.wantStep {
				t.Fatalf("step = %s, want %s", got, tc.wantStep)
			}
			if tc.wantBlock == "" {
				return
			}
			if f.blockClass["fu:x"] != tc.wantClass || len(rep.Blocks) != 1 || rep.Blocks[0].Kind != "account" {
				t.Fatalf("class %q blocks %+v", f.blockClass["fu:x"], rep.Blocks)
			}
			if _, ok, _ := f.OpenOrgRequest(context.Background(), "victim"); ok {
				t.Fatal("an org request was opened for an unverified follow-up")
			}
			if !slices.Contains(f.orgs["victim"].members, "acct") {
				t.Fatal("a membership was removed for an unverified follow-up")
			}
		})
	}
}
