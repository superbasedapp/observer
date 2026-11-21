package planlimitssvc

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/keystore"
	"github.com/marmutapp/superbased-observer/internal/planlimits"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TickEvery is how often the loop checks for due accounts. With no account
// added a tick reads the local database only.
const TickEvery = 30 * time.Second

// maxRunDetail caps the stored error class of one run.
const maxRunDetail = 160

// RefreshResult is the outcome of one account refresh.
type RefreshResult struct {
	AccountID string               `json:"account_id"`
	Outcome   string               `json:"outcome"`
	Detail    string               `json:"detail,omitempty"`
	Snapshot  *planlimits.Snapshot `json:"snapshot,omitempty"`
	Held      bool                 `json:"held,omitempty"`
}

// Run polls due accounts until ctx is done. It never makes a network call or
// starts a vendor process for a provider the user did not add, and never for
// an experimental source unless that provider's switch is on.
func (s *Service) Run(ctx context.Context) {
	t := time.NewTicker(TickEvery)
	defer t.Stop()
	lastPrune := time.Time{}
	for {
		s.tick(ctx, false)
		if now := s.now(); now.Sub(lastPrune) > 24*time.Hour {
			if n, err := s.st.PrunePlanHistory(ctx, now.Add(-HistoryRetention)); err != nil {
				s.log.Warn("plans: prune failed", "error", err)
			} else if n > 0 {
				s.log.Debug("plans: pruned history", "rows", n)
			}
			lastPrune = now
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// RefreshAll refreshes every enabled account now (a user action), honouring
// the opt-in but not the schedule.
func (s *Service) RefreshAll(ctx context.Context) []RefreshResult {
	return s.tick(ctx, true)
}

// tick refreshes due accounts (or every enabled one when force).
func (s *Service) tick(ctx context.Context, force bool) []RefreshResult {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	rows, err := s.st.PlanAccounts(ctx)
	if err != nil {
		s.log.Warn("plans: list accounts", "error", err)
		return nil
	}
	if len(rows) == 0 {
		return nil
	}
	now := s.now()
	in, _, err := s.viewInput(ctx, now)
	if err != nil {
		s.log.Warn("plans: read state", "error", err)
		return nil
	}
	var out []RefreshResult
	for _, a := range rows {
		if ctx.Err() != nil {
			break
		}
		if !a.Enabled {
			continue
		}
		if !force && (a.State.Stopped || now.Before(a.State.NextDue)) {
			continue
		}
		out = append(out, s.refresh(ctx, a, in, force))
	}
	return out
}

// Refresh refreshes one account now.
func (s *Service) Refresh(ctx context.Context, id string) (RefreshResult, error) {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	a, err := s.st.PlanAccount(ctx, id)
	if err != nil {
		return RefreshResult{}, err
	}
	in, _, err := s.viewInput(ctx, s.now())
	if err != nil {
		return RefreshResult{}, err
	}
	return s.refresh(ctx, a, in, true), nil
}

// refresh runs one account through the ladder, the driver and the backoff
// table, and records the outcome. force skips only the ladder's "rung 1 is
// fresh" rule (the user asked); the opt-in is always honoured.
func (s *Service) refresh(ctx context.Context, a store.PlanAccountRow, in planlimits.ViewInput, force bool) RefreshResult {
	started := s.now()
	res := RefreshResult{AccountID: a.ID}
	src, ok := planlimits.SourceByID(a.Source)
	if !ok {
		res.Outcome = planlimits.StatusEndpointGone
		return res
	}
	poll, reason := planlimits.ShouldPoll(planlimits.LadderInput{
		Source: src, OptedIn: in.OptIns[a.Provider],
		OfficialFreshAt: officialFreshAt(a.Provider, in), Now: started,
	})
	if !poll && !(force && reason == planlimits.StatusSkipped) {
		st := a.State
		st.Status = reason
		st.NextDue = started.Add(planlimits.Cadence(planlimits.CadenceInput{MinInterval: src.MinInterval}))
		_ = s.st.UpdatePlanAccountState(ctx, a.ID, st, started)
		res.Outcome = reason
		return res
	}

	snap, err := s.collect(ctx, a, src, started)
	held := false
	if err == nil {
		if verr := planlimits.Validate(snap); verr != nil {
			err = fmt.Errorf("%w: %s", planlimits.ErrShape, verr.Error())
		}
	}
	if err == nil {
		s.storeUsage(ctx, a, src, snap.Usage, started)
		held = s.holdSuspicious(a.ID, in.Latest[a.ID], snap, started)
		if !held {
			if ierr := s.st.InsertPlanSnapshot(ctx, a.ID, "", snap); ierr != nil {
				err = fmt.Errorf("%w: store: %s", planlimits.ErrTransient, ierr.Error())
			}
		}
	}
	var retry time.Duration
	var re *retryErr
	if errors.As(err, &re) {
		retry = re.after
	}
	cad := planlimits.Cadence(planlimits.CadenceInput{
		MinInterval: src.MinInterval, PageOpen: s.pageOpen(),
		NearLimit: err == nil && planlimits.NearLimit(snap, started),
	})
	st := planlimits.NextRun(a.State, planlimits.Outcome{Err: err, RetryAfter: retry}, started, cad)
	st.NextDue = st.NextDue.Add(jitter(cad))
	_ = s.st.UpdatePlanAccountState(ctx, a.ID, st, started)
	res.Outcome = st.Status
	res.Held = held
	if err != nil {
		res.Detail = s.detail(err)
	} else {
		res.Snapshot = &snap
	}
	_ = s.st.InsertPlanRun(ctx, store.PlanRunRow{AccountID: a.ID, StartedAt: started, EndedAt: s.now(), Outcome: st.Status, Detail: res.Detail})
	return res
}

// jitter spreads polls by up to a tenth of the cadence.
func jitter(cadence time.Duration) time.Duration {
	if cadence <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(int64(cadence / 10))) //nolint:gosec // poll jitter, not a security value
}

// detail reduces an error to a scrubbed, capped line.
func (s *Service) detail(err error) string {
	d := s.scrub.String(err.Error())
	if len(d) > maxRunDetail {
		d = d[:maxRunDetail]
	}
	return d
}

// holdSuspicious holds a reading that looks like a reset that has not
// happened yet, until a second reading agrees with it.
func (s *Service) holdSuspicious(id string, prev, next planlimits.Snapshot, now time.Time) bool {
	s.heldMu.Lock()
	defer s.heldMu.Unlock()
	if prev.Provider == "" || !planlimits.Suspicious(prev, next, now) {
		delete(s.held, id)
		return false
	}
	if h, ok := s.held[id]; ok && planlimits.Agrees(h, next) {
		delete(s.held, id)
		return false
	}
	s.held[id] = next
	return true
}

// retryErr carries a vendor's Retry-After through the error chain.
type retryErr struct {
	err   error
	after time.Duration
}

func (e *retryErr) Error() string { return e.err.Error() }
func (e *retryErr) Unwrap() error { return e.err }

// collect gathers the secrets and local reads a source needs, runs its
// driver through the egress and returns the snapshot.
func (s *Service) collect(ctx context.Context, a store.PlanAccountRow, src planlimits.SourceDef, now time.Time) (planlimits.Snapshot, error) {
	params := map[string]string{"provider": a.Provider}
	for k, v := range a.Params {
		params[k] = v
	}
	secrets := map[string]string{}
	for _, k := range a.SecretKeys {
		if s.keys == nil {
			return planlimits.Snapshot{}, fmt.Errorf("%w: keychain not available", planlimits.ErrAuth)
		}
		v, err := s.keys.Get(secretName(a.ID, k))
		if errors.Is(err, keystore.ErrNotFound) {
			continue
		}
		if err != nil {
			return planlimits.Snapshot{}, fmt.Errorf("%w: keychain: %s", planlimits.ErrTransient, err.Error())
		}
		secrets[k] = v
	}
	if src.Kind == planlimits.KindManual {
		s.observedUsed(ctx, a, params, now)
	}
	return s.run(ctx, src, params, secrets, now)
}

// run executes one source's driver with in-memory inputs. It is the single
// path shared by a scheduled refresh and a live probe.
func (s *Service) run(ctx context.Context, src planlimits.SourceDef, params, secrets map[string]string, now time.Time) (planlimits.Snapshot, error) {
	drv, ok := planlimits.Drivers[src.ID]
	if !ok {
		return planlimits.Snapshot{}, fmt.Errorf("%w: no driver", planlimits.ErrShape)
	}
	in := planlimits.PlanInput{Params: params, Secrets: secrets, Now: now}
	if len(src.Local) > 0 {
		if s.local == nil {
			return planlimits.Snapshot{}, fmt.Errorf("%w: local reads not wired", planlimits.ErrUnavailable)
		}
		local, err := s.local.Read(ctx, src.Local)
		if err != nil {
			return planlimits.Snapshot{}, err
		}
		in.Local = local
	}
	if drv.Converse != nil {
		if s.net == nil {
			return planlimits.Snapshot{}, fmt.Errorf("%w: egress not wired", planlimits.ErrUnavailable)
		}
		return s.net.Converse(ctx, src, drv, in)
	}
	reqs, err := drv.Plan(in)
	if err != nil {
		return planlimits.Snapshot{}, err
	}
	var resp map[string]planlimits.Response
	if len(reqs) > 0 {
		if s.net == nil {
			return planlimits.Snapshot{}, fmt.Errorf("%w: egress not wired", planlimits.ErrUnavailable)
		}
		resp = s.net.Do(ctx, src, reqs)
	}
	snap, err := drv.Parse(planlimits.ParseInput{Params: params, Local: in.Local, Responses: resp, Now: now})
	if err != nil {
		var after time.Duration
		for _, r := range resp {
			if r.RetryAfter > after {
				after = r.RetryAfter
			}
		}
		if after > 0 && errors.Is(err, planlimits.ErrRateLimited) {
			return snap, &retryErr{err: err, after: after}
		}
	}
	return snap, err
}

// observedUsed fills the manual entry's measured spend: Observer's own
// recorded spend for the provider's tools since the window started, in
// micros, when the user left "used" empty and the unit is money.
func (s *Service) observedUsed(ctx context.Context, a store.PlanAccountRow, params map[string]string, now time.Time) {
	if strings.TrimSpace(params["used"]) != "" || params["unit"] != "usd" {
		return
	}
	prov, ok := planlimits.ProviderByID(a.Provider)
	if !ok || len(prov.Tools) == 0 {
		return
	}
	rd, _ := strconv.Atoi(params["renews_day"])
	start, _ := planlimits.ManualWindowStart(params["window"], rd, now)
	usd, err := s.st.ObservedToolSpendSince(ctx, prov.Tools, start)
	if err != nil {
		return
	}
	params[planlimits.ParamObservedUsed] = strconv.FormatFloat(usd*1e6, 'f', 0, 64)
}

// ProbeRequest is a one-off live check of a source with in-memory inputs.
type ProbeRequest struct {
	Provider string
	Source   string
	Params   map[string]string
	Secrets  map[string]string
}

// Probe runs one source once and stores nothing. It honours the
// experimental switch like any refresh.
func (s *Service) Probe(ctx context.Context, req ProbeRequest) (planlimits.Snapshot, error) {
	src, ok := planlimits.SourceByID(req.Source)
	if !ok || src.Passive {
		return planlimits.Snapshot{}, fmt.Errorf("%w: unknown source", ErrInvalid)
	}
	if src.Experimental() {
		opt, err := s.st.PlanOptIns(ctx)
		if err != nil {
			return planlimits.Snapshot{}, err
		}
		if !opt[src.Provider] {
			return planlimits.Snapshot{}, ErrNeedsOptIn
		}
	}
	params := map[string]string{"provider": req.Provider}
	for k, v := range req.Params {
		params[k] = v
	}
	snap, err := s.run(ctx, src, params, req.Secrets, s.now())
	if err == nil {
		err = planlimits.Validate(snap)
	}
	return snap, err
}

// ProbeAccount runs an existing account's source once and stores nothing.
func (s *Service) ProbeAccount(ctx context.Context, id string) (planlimits.Snapshot, error) {
	a, err := s.st.PlanAccount(ctx, id)
	if err != nil {
		return planlimits.Snapshot{}, err
	}
	src, _ := planlimits.SourceByID(a.Source)
	if src.Experimental() {
		opt, err := s.st.PlanOptIns(ctx)
		if err != nil {
			return planlimits.Snapshot{}, err
		}
		if !opt[a.Provider] {
			return planlimits.Snapshot{}, ErrNeedsOptIn
		}
	}
	snap, err := s.collect(ctx, a, src, s.now())
	if err == nil {
		err = planlimits.Validate(snap)
	}
	return snap, err
}

// storeUsage persists the daily usage a reading carried (Snapshot.Usage) for
// a source that declares it (SourceDef.DailyUsage). It is fail-soft: a store
// error is logged and never changes the reading's outcome, the same way the
// driver never fails a reading over its usage call. It is independent of the
// suspicious-reset hold, which concerns the limit windows only.
func (s *Service) storeUsage(ctx context.Context, a store.PlanAccountRow, src planlimits.SourceDef, u *planlimits.UsageReport, at time.Time) {
	if u == nil || !src.DailyUsage || len(u.Days) == 0 {
		return
	}
	if err := s.st.UpsertPlanUsageDaily(ctx, a.ID, a.Provider, u.Days, at); err != nil {
		s.log.Debug("planlimits: daily usage not stored", "account", a.ID, "err", s.detail(err))
	}
}
