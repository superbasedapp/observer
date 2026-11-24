package availwork

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/hostapi"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	pc "github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// Deliverer defaults.
const (
	// DefaultRefusedRetryAfter is how long a host that refused a version
	// waits before the same version is sent to it again (a newer one goes
	// at once).
	DefaultRefusedRetryAfter = time.Hour
	// DefaultConfirmAfter is how long a host's answer that it holds the
	// newest envelope counts as current. After that the newest envelope is
	// sent again: a host restored from a backup or rebuilt under the same id
	// may have fallen back to an older envelope (or the launch floor), which
	// could reopen a staff kill switch. A host that still holds it answers
	// Applied=false, nothing changes on it, and its row's time moves on.
	DefaultConfirmAfter = 6 * time.Hour
)

// DeliveryStore is the deliverer's store seam (*store.Store as sbci_worker).
type DeliveryStore interface {
	LatestAvailabilityDocument(ctx context.Context) (pc.AvailabilityDocument, error)
	AvailabilityDeliveries(ctx context.Context) ([]store.AvailabilityDelivery, error)
	RecordAvailabilityDelivery(ctx context.Context, d store.AvailabilityDelivery) error
}

// Transport sends one host-API request to a host by id (the hosts file's
// id) and reports the answer: the worker's mTLS sender, signing each request
// with the document signer's host-API key and verifying each answer against
// the host's pinned response key.
type Transport interface {
	Send(ctx context.Context, hostID string, r hostapi.Request) hostapi.Answer
}

// TransportFunc adapts a function to Transport.
type TransportFunc func(ctx context.Context, hostID string, r hostapi.Request) hostapi.Answer

// Send implements Transport.
func (f TransportFunc) Send(ctx context.Context, hostID string, r hostapi.Request) hostapi.Answer {
	return f(ctx, hostID, r)
}

// DelivererConfig configures a Deliverer. Store, Transport and Hosts are
// required.
type DelivererConfig struct {
	Store     DeliveryStore
	Transport Transport
	// Hosts lists the host ids to deliver to (the hosts file).
	Hosts func() []string
	// Now is the clock (nil: time.Now).
	Now func() time.Time
	// RefusedRetryAfter is the wait before a refused version is sent again
	// (0: DefaultRefusedRetryAfter).
	RefusedRetryAfter time.Duration
	// ConfirmAfter is how long a host's confirmation that it holds the
	// newest envelope stands before it is sent again (0:
	// DefaultConfirmAfter).
	ConfirmAfter time.Duration
}

// Deliverer pushes the newest envelope to every host.
type Deliverer struct {
	cfg DelivererConfig
}

// NewDeliverer builds a Deliverer.
func NewDeliverer(cfg DelivererConfig) (*Deliverer, error) {
	if cfg.Store == nil || cfg.Transport == nil || cfg.Hosts == nil {
		return nil, errors.New("availwork.NewDeliverer: Store, Transport and Hosts are required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.RefusedRetryAfter <= 0 {
		cfg.RefusedRetryAfter = DefaultRefusedRetryAfter
	}
	if cfg.ConfirmAfter <= 0 {
		cfg.ConfirmAfter = DefaultConfirmAfter
	}
	return &Deliverer{cfg: cfg}, nil
}

// DeliveryStats counts one pass.
type DeliveryStats struct {
	Hosts, Current, Sent, Delivered, Retry, Refused, Held int
}

// sendFacts is what the send table reads for one host.
type sendFacts struct {
	// d is the host's delivery row (nil: never sent).
	d      *store.AvailabilityDelivery
	latest int64
	now    time.Time
	// wait is RefusedRetryAfter; confirm is ConfirmAfter.
	wait    time.Duration
	confirm time.Duration
}

// holdsLatest: the host's last answer was a verified one that it holds the
// newest envelope (or a newer one).
func (f sendFacts) holdsLatest() bool {
	return f.d.State == store.DeliveryDelivered && f.d.Version >= f.latest
}

// sendRule is one row of the send table: whether a host gets the newest
// envelope on this pass. Walked top down, first match wins; the last row
// matches everything.
type sendRule struct {
	name  string
	match func(f sendFacts) bool
	send  bool
}

var sendRules = []sendRule{
	{name: "never-sent", match: func(f sendFacts) bool { return f.d == nil }, send: true},
	// current only while the confirmation is recent: a host restored from
	// a backup does not say so, so its answer is asked for again.
	{name: "current", match: func(f sendFacts) bool {
		return f.holdsLatest() && f.now.Sub(f.d.UpdatedAt) < f.confirm
	}, send: false},
	{name: "reconfirm", match: func(f sendFacts) bool { return f.holdsLatest() }, send: true},
	{name: "refused-recently", match: func(f sendFacts) bool {
		return f.d.State == store.DeliveryRefused && f.d.AttemptedVersion == f.latest && f.now.Sub(f.d.UpdatedAt) < f.wait
	}, send: false},
	{name: "behind", match: func(sendFacts) bool { return true }, send: true},
}

// sendDecision returns the matching send rule.
func sendDecision(f sendFacts) sendRule {
	for _, r := range sendRules {
		if r.match(f) {
			return r
		}
	}
	return sendRules[len(sendRules)-1]
}

// DeliverOnce sends the newest envelope to every host that does not hold it.
// A failure for one host does not stop the others; store errors are joined.
func (d *Deliverer) DeliverOnce(ctx context.Context) (DeliveryStats, error) {
	var st DeliveryStats
	latest, err := d.cfg.Store.LatestAvailabilityDocument(ctx)
	if errors.Is(err, store.ErrNotFound) {
		return st, nil
	}
	if err != nil {
		return st, fmt.Errorf("availwork.DeliverOnce: latest: %w", err)
	}
	rows, err := d.cfg.Store.AvailabilityDeliveries(ctx)
	if err != nil {
		return st, fmt.Errorf("availwork.DeliverOnce: deliveries: %w", err)
	}
	known := make(map[string]store.AvailabilityDelivery, len(rows))
	for _, r := range rows {
		known[r.HostID] = r
	}
	req, err := hostapi.AvailabilityPush(latest)
	if err != nil {
		return st, fmt.Errorf("availwork.DeliverOnce: %w", err)
	}
	var errs []error
	for _, host := range d.cfg.Hosts() {
		st.Hosts++
		prev, seen := known[host]
		var p *store.AvailabilityDelivery
		if seen {
			p = &prev
		}
		if rule := sendDecision(sendFacts{d: p, latest: latest.Version, now: d.cfg.Now(), wait: d.cfg.RefusedRetryAfter, confirm: d.cfg.ConfirmAfter}); !rule.send {
			if rule.name == "current" {
				st.Current++
			} else {
				st.Held++
			}
			continue
		}
		st.Sent++
		v := hostapi.JudgeAvailability(d.cfg.Transport.Send(ctx, host, req))
		rec := store.AvailabilityDelivery{
			HostID: host, AttemptedVersion: latest.Version, State: string(v.Outcome), ErrorClass: v.Class, UpdatedAt: d.cfg.Now(),
		}
		if seen {
			rec.Version = prev.Version
			if prev.AttemptedVersion == latest.Version && prev.State != store.DeliveryDelivered {
				rec.Attempts = prev.Attempts
			}
		}
		rec.Attempts++
		switch v.Outcome {
		case hostapi.DeliveryInForce:
			st.Delivered++
			rec.Version = max(rec.Version, v.InForce)
		case hostapi.DeliveryRefused:
			st.Refused++
		default:
			st.Retry++
		}
		if err := d.cfg.Store.RecordAvailabilityDelivery(ctx, rec); err != nil {
			errs = append(errs, fmt.Errorf("host %s: %w", host, err))
		}
	}
	if len(errs) > 0 {
		return st, fmt.Errorf("availwork.DeliverOnce: %w", errors.Join(errs...))
	}
	return st, nil
}
