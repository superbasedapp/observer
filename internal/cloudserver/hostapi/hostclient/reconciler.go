package hostclient

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/hostapi"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	pc "github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// DefaultReconcilePage is how many orgs one store read returns.
const DefaultReconcilePage = 100

// ReconcileStore is the store seam the reconciler uses (*store.Store, bound
// to sbci_worker).
type ReconcileStore interface {
	// ListOrgsForReconcile pages through every org.
	ListOrgsForReconcile(ctx context.Context, afterOrgID string, limit int) ([]store.OrgReconcileView, error)
	// ApplyOrgReconcile writes one org's findings and correction.
	ApplyOrgReconcile(ctx context.Context, u store.OrgReconcileUpdate) (bool, error)
}

// ReconcilerConfig configures a Reconciler. Store, Transport and Hosts are
// required.
type ReconcilerConfig struct {
	Store     ReconcileStore
	Transport Transport
	Hosts     Directory
	// Now is the clock (nil: time.Now).
	Now func() time.Time
	// Page is the store page size (0: DefaultReconcilePage).
	Page int
	// Usage stores the daily usage reports the pass pulls from each host
	// (nil: no usage pull; design 4.6 "Usage", M6.0 Q11).
	Usage UsageStore
	// UsageDays is how many receipt days each pull asks for (0:
	// hostapi.DefaultUsageDays).
	UsageDays int
}

// Reconciler compares every org with its host and pulls each host's usage.
type Reconciler struct {
	store     ReconcileStore
	tr        Transport
	hosts     Directory
	now       func() time.Time
	page      int
	usage     UsageStore
	usageDays int
}

// NewReconciler builds a Reconciler.
func NewReconciler(cfg ReconcilerConfig) (*Reconciler, error) {
	if cfg.Store == nil || cfg.Transport == nil || cfg.Hosts == nil {
		return nil, errors.New("hostclient.NewReconciler: Store, Transport and Hosts are required")
	}
	r := &Reconciler{
		store: cfg.Store, tr: cfg.Transport, hosts: cfg.Hosts, now: cfg.Now, page: cfg.Page,
		usage: cfg.Usage, usageDays: cfg.UsageDays,
	}
	if r.now == nil {
		r.now = time.Now
	}
	if r.page <= 0 {
		r.page = DefaultReconcilePage
	}
	return r, nil
}

// ReconcileStats counts one pass.
type ReconcileStats struct {
	Orgs, Skipped, WithFindings, Corrections int
	// Usage counts the pass's usage pull (zero when no UsageStore is set).
	Usage UsageStats
}

// ReconcileOnce walks every org once, then pulls the usage of every host
// that serves at least one of them. A failure on one org or one host does
// not stop the pass; the errors are joined.
func (r *Reconciler) ReconcileOnce(ctx context.Context) (ReconcileStats, error) {
	var st ReconcileStats
	var errs []error
	placed := map[string]string{} // org id -> the host the control plane placed it on
	after := ""
	for {
		page, err := r.store.ListOrgsForReconcile(ctx, after, r.page)
		if err != nil {
			errs = append(errs, err)
			break
		}
		for _, v := range page {
			st.Orgs++
			if v.HostID != "" {
				placed[v.OrgID] = v.HostID
			}
			if err := r.one(ctx, v, &st); err != nil {
				errs = append(errs, fmt.Errorf("org %s: %w", v.OrgID, err))
			}
		}
		if len(page) < r.page || ctx.Err() != nil {
			break
		}
		after = page[len(page)-1].OrgID
	}
	if r.usage != nil && ctx.Err() == nil {
		us, err := r.pullUsage(ctx, placed)
		st.Usage = us
		if err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return st, fmt.Errorf("hostclient.Reconciler.ReconcileOnce: %w", errors.Join(errs...))
	}
	return st, nil
}

// one reconciles one org.
func (r *Reconciler) one(ctx context.Context, v store.OrgReconcileView, st *ReconcileStats) error {
	d := hostapi.Desired{
		OrgID: v.OrgID, DisplayName: v.DisplayName, State: pc.TenantState(v.Status),
		LifecycleGen: v.LifecycleGen, HostAssigned: v.HostID != "", OpenIntent: v.OpenIntent,
	}
	var p hostapi.Probe
	if d.NeedsProbe() {
		p = r.probe(ctx, v)
	}
	rec, err := hostapi.Reconcile(d, p)
	if err != nil {
		return err
	}
	if rec.Skip {
		st.Skipped++
		return nil
	}
	u := store.OrgReconcileUpdate{OrgID: v.OrgID, Now: r.now()}
	correctionKey := ""
	if rec.Correction != nil {
		c := rec.Correction
		correctionKey = c.IdempotencyKey
		u.Correction = &store.OrgIntent{
			OrgID: c.OrgID, Verb: store.OrgOutboxVerb(c.Verb), IdempotencyKey: c.IdempotencyKey,
			LifecycleGen: c.LifecycleGen, Payload: c.Payload,
		}
	}
	for i, k := range rec.Findings {
		f := store.OrgReconcileFinding{Kind: string(k), DesiredState: v.Status, DesiredGen: v.LifecycleGen, Health: string(p.Health)}
		if p.Reached {
			served := p.Served
			f.Served = &served
		}
		if p.Served {
			gen := p.LifecycleGen
			f.HostState, f.HostGen = string(p.State), &gen
		}
		if i == 0 {
			f.CorrectionKey = correctionKey // the rule's own finding carries its correction
		}
		u.Findings = append(u.Findings, f)
	}
	enqueued, err := r.store.ApplyOrgReconcile(ctx, u)
	if err != nil {
		return err
	}
	if len(rec.Findings) > 0 {
		st.WithFindings++
	}
	if enqueued {
		st.Corrections++
	}
	return nil
}

// probe asks the org's host route-check and, when served, health. Only
// verified answers fill the probe; anything else leaves Reached false.
func (r *Reconciler) probe(ctx context.Context, v store.OrgReconcileView) hostapi.Probe {
	h, ok := r.hosts.Host(v.HostID)
	if !ok {
		return hostapi.Probe{}
	}
	req, err := hostapi.RouteCheckProbe(v.OrgID)
	if err != nil {
		return hostapi.Probe{}
	}
	rc, ok := hostapi.ReadRouteCheck(r.tr.Send(ctx, h, req))
	if !ok {
		return hostapi.Probe{}
	}
	p := hostapi.Probe{Reached: true, Served: rc.Served, State: rc.State, LifecycleGen: rc.LifecycleGen}
	if !rc.Served {
		return p
	}
	if hreq, err := hostapi.HealthProbe(v.OrgID); err == nil {
		if hr, ok := hostapi.ReadHealth(r.tr.Send(ctx, h, hreq), v.OrgID); ok {
			p.Health = hr.Status
		}
	}
	return p
}
