package hostclient

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/hostapi"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// Dispatcher defaults.
const (
	// DefaultLeaseTTL is how long a claim holds a row; it must outlast one
	// request (NewDispatcher checks it against the transport's timeout).
	DefaultLeaseTTL = 2 * time.Minute
	// DefaultBatch is the claim size.
	DefaultBatch = 32
	// recordTimeout bounds recording one outcome.
	recordTimeout = 10 * time.Second
)

// OutboxStore is the store seam the dispatcher uses (*store.Store, bound to
// sbci_worker).
type OutboxStore interface {
	// ClaimOrgOutbox leases due rows.
	ClaimOrgOutbox(ctx context.Context, c store.OrgOutboxClaim) ([]store.ClaimedOrgIntent, error)
	// AssignOrgHost places an org on a host once and returns its host.
	AssignOrgHost(ctx context.Context, orgID, hostID string) (string, error)
	// RecordOrgOutboxOutcome records an attempt under its lease.
	RecordOrgOutboxOutcome(ctx context.Context, o store.OrgOutboxOutcome) error
}

// Transport sends one request and reports a verified, unverified or failed
// answer (*Sender).
type Transport interface {
	// Send sends r to h.
	Send(ctx context.Context, h Host, r hostapi.Request) hostapi.Answer
}

// CreateResolver supplies what a create_tenant request needs beyond its
// payload: the owner's WorkOS subject and email and the first signed
// entitlement document. It returns an error, not a partial answer, when any
// of them is not available yet (the row is retried, not parked). An error
// that is (or wraps) a *ResolveError names its reason in the row's error
// class ("not_sent:resolve:<reason>"); any other error is "not_sent:resolve".
type CreateResolver interface {
	// ResolveCreate resolves the extras for orgID.
	ResolveCreate(ctx context.Context, orgID string) (hostapi.CreateExtras, error)
}

// DispatcherConfig configures a Dispatcher. Store, Transport, Hosts and
// Resolver are required.
type DispatcherConfig struct {
	Store     OutboxStore
	Transport Transport
	Hosts     Directory
	Resolver  CreateResolver
	// Now is the clock (nil: time.Now).
	Now func() time.Time
	// Jitter returns a value in [0, 1) for the backoff (nil: math/rand/v2).
	Jitter func() float64
	// LeaseTTL is the claim lease (0: DefaultLeaseTTL).
	LeaseTTL time.Duration
	// Batch is the claim size (0: DefaultBatch).
	Batch int
	// AfterCreate runs once a create_tenant row's ack is recorded, with the
	// org id (nil: nothing runs). The worker issues the org's launch
	// entitlements document there (W14-D1a), so the new tenant does not wait
	// for the issuer's next pass. Its error is reported with the pass's
	// errors; the ack itself stands.
	AfterCreate func(ctx context.Context, orgID string) error
	// WaitlistRetryFloor is the least delay before a waitlisted create is
	// sent again (0: hostapi.WaitlistMinDelay; SBCI_WAITLIST_RETRY_FLOOR,
	// W16-D5). A value outside hostapi.CheckWaitlistFloor's range is refused.
	WaitlistRetryFloor time.Duration
}

// Dispatcher sends the org outbox.
type Dispatcher struct {
	store       OutboxStore
	tr          Transport
	hosts       Directory
	resolver    CreateResolver
	now         func() time.Time
	jitter      func() float64
	leaseTTL    time.Duration
	batch       int
	afterCreate func(ctx context.Context, orgID string) error
	delays      hostapi.DelayOptions
}

// NewDispatcher builds a Dispatcher. When the transport reports its
// per-request timeout, the lease must be at least twice it, so a slow send
// cannot outlive its lease and race a second worker.
func NewDispatcher(cfg DispatcherConfig) (*Dispatcher, error) {
	if cfg.Store == nil || cfg.Transport == nil || cfg.Hosts == nil || cfg.Resolver == nil {
		return nil, errors.New("hostclient.NewDispatcher: Store, Transport, Hosts and Resolver are required")
	}
	d := &Dispatcher{
		store: cfg.Store, tr: cfg.Transport, hosts: cfg.Hosts, resolver: cfg.Resolver,
		now: cfg.Now, jitter: cfg.Jitter, leaseTTL: cfg.LeaseTTL, batch: cfg.Batch,
		afterCreate: cfg.AfterCreate,
		delays:      hostapi.DelayOptions{WaitlistFloor: cfg.WaitlistRetryFloor},
	}
	if cfg.WaitlistRetryFloor != 0 {
		if err := hostapi.CheckWaitlistFloor(cfg.WaitlistRetryFloor); err != nil {
			return nil, fmt.Errorf("hostclient.NewDispatcher: %w", err)
		}
	}
	if d.now == nil {
		d.now = time.Now
	}
	if d.jitter == nil {
		d.jitter = rand.Float64 //nolint:gosec // backoff jitter, not a secret
	}
	if d.leaseTTL <= 0 {
		d.leaseTTL = DefaultLeaseTTL
	}
	if d.batch <= 0 {
		d.batch = DefaultBatch
	}
	if t, ok := cfg.Transport.(interface{ Timeout() time.Duration }); ok && d.leaseTTL < 2*t.Timeout() {
		return nil, fmt.Errorf("hostclient.NewDispatcher: lease %s is shorter than twice the request timeout %s", d.leaseTTL, t.Timeout())
	}
	return d, nil
}

// DispatchStats counts one pass.
type DispatchStats struct {
	Claimed, Acked, Retried, Parked, LeaseLost int
}

// resultFor maps a decision's action to the row's result.
var resultFor = map[hostapi.Action]store.OrgOutboxResult{
	hostapi.ActionAck:             store.OutboxResultAcked,
	hostapi.ActionRetry:           store.OutboxResultRetry,
	hostapi.ActionRetryNewRequest: store.OutboxResultRetry,
	hostapi.ActionWaitlist:        store.OutboxResultRetry,
	hostapi.ActionPark:            store.OutboxResultParked,
}

// DispatchOnce claims one batch of due rows and sends each in order. A
// failure to record one row's outcome does not stop the others; the errors
// are joined. A lost lease is counted, not an error.
func (d *Dispatcher) DispatchOnce(ctx context.Context) (DispatchStats, error) {
	var st DispatchStats
	rows, err := d.store.ClaimOrgOutbox(ctx, store.OrgOutboxClaim{Now: d.now(), LeaseTTL: d.leaseTTL, Limit: d.batch})
	if err != nil {
		return st, fmt.Errorf("hostclient.Dispatcher.DispatchOnce: %w", err)
	}
	st.Claimed = len(rows)
	var errs []error
	for _, row := range rows {
		dec := d.attempt(ctx, row)
		out := d.outcome(row, dec)
		// Record even when ctx ended mid-send (shutdown): the attempt's
		// outcome, usually a retry, is known, and the lease fences it.
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), recordTimeout)
		err := d.store.RecordOrgOutboxOutcome(rctx, out)
		cancel()
		switch {
		case errors.Is(err, store.ErrOrgOutboxLeaseLost):
			st.LeaseLost++
		case err != nil:
			errs = append(errs, fmt.Errorf("record %s: %w", row.OutboxID, err))
		case out.Result == store.OutboxResultAcked:
			st.Acked++
			if out.AdoptCreate && d.afterCreate != nil && ctx.Err() == nil {
				if err := d.afterCreate(ctx, row.OrgID); err != nil {
					errs = append(errs, fmt.Errorf("after create %s: %w", row.OrgID, err))
				}
			}
		case out.Result == store.OutboxResultRetry:
			st.Retried++
		default:
			st.Parked++
		}
	}
	if len(errs) > 0 {
		return st, fmt.Errorf("hostclient.Dispatcher.DispatchOnce: %w", errors.Join(errs...))
	}
	return st, nil
}

// attempt places, builds, sends and judges one claimed row.
func (d *Dispatcher) attempt(ctx context.Context, row store.ClaimedOrgIntent) hostapi.Decision {
	q := hostapi.Queued{
		OrgID: row.OrgID, Verb: hostapi.Verb(row.Verb), IdempotencyKey: row.IdempotencyKey,
		LifecycleGen: row.LifecycleGen, Payload: row.Payload,
	}
	host, answer, ok := d.route(ctx, row)
	if !ok {
		return hostapi.Judge(q, answer)
	}
	var extras hostapi.CreateExtras
	if hostapi.NeedsCreateExtras(q.Verb) {
		x, err := d.resolver.ResolveCreate(ctx, row.OrgID)
		if err != nil {
			return hostapi.Judge(q, hostapi.Answer{Kind: hostapi.AnswerNotSent, Reason: resolveReason(err)})
		}
		extras = x
	}
	req, err := hostapi.Build(q, extras)
	if err != nil {
		return hostapi.Judge(q, hostapi.Answer{Kind: hostapi.AnswerNotSent, Reason: "build", Permanent: true})
	}
	return hostapi.Judge(q, d.tr.Send(ctx, host, req))
}

// route finds the row's host, placing a new tenant first. Only create_tenant
// may place: any other intent for an unplaced org waits (the org's create
// is earlier in its per-org order).
func (d *Dispatcher) route(ctx context.Context, row store.ClaimedOrgIntent) (Host, hostapi.Answer, bool) {
	hostID := row.HostID
	if hostID == "" {
		if row.Verb != store.OutboxCreateTenant {
			return Host{}, hostapi.Answer{Kind: hostapi.AnswerNotSent, Reason: "unplaced"}, false
		}
		placed, err := d.hosts.Place(ctx, row.OrgID)
		if err == nil {
			hostID, err = d.store.AssignOrgHost(ctx, row.OrgID, placed)
		}
		if err != nil || hostID == "" {
			return Host{}, hostapi.Answer{Kind: hostapi.AnswerNotSent, Reason: "place"}, false
		}
	}
	h, ok := d.hosts.Host(hostID)
	if !ok {
		return Host{}, hostapi.Answer{Kind: hostapi.AnswerNotSent, Reason: "unknown_host"}, false
	}
	return h, hostapi.Answer{}, true
}

// outcome turns a decision into the fenced row outcome.
func (d *Dispatcher) outcome(row store.ClaimedOrgIntent, dec hostapi.Decision) store.OrgOutboxOutcome {
	now := d.now()
	res, ok := resultFor[dec.Action]
	if !ok {
		res, dec.Class = store.OutboxResultRetry, "unjudged"
	}
	o := store.OrgOutboxOutcome{OutboxID: row.OutboxID, LeaseToken: row.LeaseToken, Result: res, Now: now, ErrorClass: dec.Class}
	switch res {
	case store.OutboxResultRetry:
		delay := hostapi.RetryDelayWith(dec.Action, row.Attempts, d.jitter(), d.delays)
		if delay <= 0 {
			delay = hostapi.Backoff(row.Attempts, d.jitter())
		}
		o.NextAttemptAt = now.Add(delay)
	case store.OutboxResultAcked:
		if dec.Observed.HasState {
			o.HostState, o.HostGen = string(dec.Observed.State), dec.Observed.LifecycleGen
		}
		o.AdoptCreate = row.Verb == store.OutboxCreateTenant
	}
	return o
}
