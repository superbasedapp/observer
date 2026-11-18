package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/orgintel"
	"github.com/marmutapp/superbased-observer/internal/settingslink"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// orgintel_dashboard.go is the dashboard half of the node's org-plane Cloud
// Intelligence surface: dashapi.OrgIntelManager over the SAME functions
// `observer intel` runs (intel.go), plus the daemon-side resolvers start.go
// binds (the rail gate's live opt-in and the consent report source).

// orgIntelHistoryLimit bounds the consent history and receipts the page shows.
const orgIntelHistoryLimit = 20

// orgIntelConflict marks an intel.go refusal as "not applicable in this
// state" for the dashboard (409), keeping the CLI's message verbatim.
type orgIntelConflict struct{ err error }

func (e orgIntelConflict) Error() string { return e.err.Error() }

// Is maps the conflict onto dashapi.ErrOrgIntelConflict.
func (e orgIntelConflict) Is(target error) bool { return target == dashapi.ErrOrgIntelConflict }

// orgIntelConflictErrs are the intel.go refusals that are a state conflict
// rather than a failure.
var orgIntelConflictErrs = []error{errOrgIntelNotEnrolled, errOrgIntelManaged, errOrgIntelNoTerms, errOrgIntelStale}

func asOrgIntelDashboardErr(err error) error {
	for _, c := range orgIntelConflictErrs {
		if errors.Is(err, c) {
			return orgIntelConflict{err: err}
		}
	}
	return err
}

// orgIntelDashboard implements dashapi.OrgIntelManager.
type orgIntelDashboard struct {
	configPath string
	build      func(ctx context.Context, configPath string) (orgBundle, error)
	now        func() time.Time
	// changed runs after a write (the daemon invalidates its live opt-in
	// cache so the rail gate follows the click at once).
	changed func()
}

var _ dashapi.OrgIntelManager = (*orgIntelDashboard)(nil)

// newOrgIntelDashboard builds the manager for a process.
func newOrgIntelDashboard(configPath string, changed func()) *orgIntelDashboard {
	return &orgIntelDashboard{configPath: configPath, build: buildOrgBundle, now: time.Now, changed: changed}
}

func (d *orgIntelDashboard) status(ctx context.Context, b orgBundle) (dashapi.OrgIntelStatus, error) {
	optIn, err := loadConfigOptIn(d.configPath)
	if err != nil {
		return dashapi.OrgIntelStatus{}, err
	}
	snap, err := loadOrgIntelSnapshot(ctx, b.store, optIn, d.now().UTC())
	if err != nil {
		return dashapi.OrgIntelStatus{}, err
	}
	noteManagedNoticeShown(ctx, b.store, snap)
	v, err := buildOrgIntelStatusView(ctx, b.store, snap)
	setOrgIntelManagedRail(&v, snap, orgIntelGovernance(ctx, b))
	if snap.Enrolment != nil {
		v.DashboardKind = readConnectKind(d.configPath, snap.Enrolment.OrgID)
	}
	return v, err
}

// Status serves GET /api/intel/status.
func (d *orgIntelDashboard) Status(r *http.Request) (dashapi.OrgIntelStatus, error) {
	b, err := d.build(r.Context(), d.configPath)
	if err != nil {
		return dashapi.OrgIntelStatus{}, err
	}
	defer b.cleanup()
	return d.status(r.Context(), b)
}

// Accept serves POST /api/intel/accept.
func (d *orgIntelDashboard) Accept(r *http.Request, shownDigest string) (dashapi.OrgIntelStatus, error) {
	b, err := d.build(r.Context(), d.configPath)
	if err != nil {
		return dashapi.OrgIntelStatus{}, err
	}
	defer b.cleanup()
	res, err := acceptOrgIntel(r.Context(), b, d.configPath, shownDigest, orgIntelModeDashboard)
	if err != nil {
		return dashapi.OrgIntelStatus{}, asOrgIntelDashboardErr(err)
	}
	if d.changed != nil {
		d.changed()
	}
	st, err := d.status(r.Context(), b)
	st.Note = res.ReportNote
	return st, err
}

// Withdraw serves POST /api/intel/withdraw.
func (d *orgIntelDashboard) Withdraw(r *http.Request) (dashapi.OrgIntelStatus, error) {
	b, err := d.build(r.Context(), d.configPath)
	if err != nil {
		return dashapi.OrgIntelStatus{}, err
	}
	defer b.cleanup()
	res, err := withdrawOrgIntel(r.Context(), b, d.configPath, orgIntelModeDashboard)
	if err != nil {
		return dashapi.OrgIntelStatus{}, asOrgIntelDashboardErr(err)
	}
	if d.changed != nil {
		d.changed()
	}
	st, err := d.status(r.Context(), b)
	st.Note = res.ReportNote
	return st, err
}

// noteManagedNoticeShown writes the managed-notice receipt once per org
// document version (design section 3.3: a managed developer is shown a notice,
// not asked; the receipt is the local record that it was shown).
func noteManagedNoticeShown(ctx context.Context, st *store.Store, snap orgIntelSnapshot) {
	if snap.Status.Class != orgintel.ClassManaged || snap.Requirement == nil || !snap.Status.OrgEnabled {
		return
	}
	detail := fmt.Sprintf("version=%d", snap.Requirement.Version)
	recent, err := st.OrgIntelReceipts(ctx, orgIntelHistoryLimit)
	if err != nil {
		return
	}
	for _, r := range recent {
		if r.Kind == store.OrgIntelReceiptNoticeShown && r.OrgID == snap.Requirement.OrgID && r.Detail == detail {
			return
		}
	}
	_ = st.AppendOrgIntelReceipt(ctx, store.OrgIntelReceipt{
		Kind: store.OrgIntelReceiptNoticeShown, OrgID: snap.Requirement.OrgID, Detail: detail,
	})
}

// newOrgIntelStatusView maps a snapshot onto the wire view (the pure part:
// no history, receipts or cache count).
func newOrgIntelStatusView(snap orgIntelSnapshot) dashapi.OrgIntelStatus {
	st := snap.Status
	v := dashapi.OrgIntelStatus{
		Class:          st.Class,
		OrgEnabled:     st.OrgEnabled,
		Required:       st.Required,
		Pending:        st.Pending,
		PendingReason:  st.PendingReason,
		Covered:        st.Covered,
		ConfigOptIn:    snap.ConfigOptIn,
		EffectiveOptIn: st.EffectiveOptIn,
		NoticeOnly:     st.NoticeOnly,
		DeadlinePassed: st.DeadlinePassed,
		History:        []dashapi.OrgIntelConsentView{},
		Receipts:       []dashapi.OrgIntelReceiptView{},
	}
	if !st.DeadlineAt.IsZero() {
		v.DeadlineAt = st.DeadlineAt.Format(time.RFC3339)
	}
	if snap.Enrolment != nil {
		v.OrgName = snap.Enrolment.OrgName
		if v.OrgName == "" {
			v.OrgName = snap.Enrolment.OrgID
		}
		v.OrgDashboard = settingslink.OrgDashboardBase(orgDashboardAddress(snap.Enrolment))
	}
	if snap.Body != nil {
		b := snap.Body
		purposes := append([]string{}, b.Purposes...)
		v.Requirement = &dashapi.OrgIntelRequirementView{
			Enabled: b.Enabled, ProviderLabel: b.ProviderLabel, Model: b.Model,
			EvidenceLevel: b.EvidenceLevel, Purposes: purposes,
			DeveloperActions: b.DeveloperActions, PerDeveloperDailyCap: b.PerDeveloperDailyCap,
			RequireIndividualConsent: b.RequireIndividualConsent, RequirementVersion: b.RequirementVersion,
			RequiredSince: b.RequiredSince, DeadlineDays: b.DeadlineDays,
		}
		sweep := orgintel.SweepFor(b)
		v.Requirement.Background = sweep.On
		v.Requirement.PerDeveloperMonthlyCap = b.PerDeveloperMonthlyCap
		v.Requirement.QuietMinutes = int(sweep.Quiet / time.Minute)
		v.Requirement.MinActions = sweep.MinActions
		v.Requirement.MaxAgeDays = int(sweep.MaxAge / (24 * time.Hour))
		if snap.Requirement != nil {
			v.Requirement.DocVersion = snap.Requirement.Version
			if !snap.Requirement.ReceivedAt.IsZero() {
				v.Requirement.ReceivedAt = snap.Requirement.ReceivedAt.UTC().Format(time.RFC3339)
			}
		}
		// The disclosure is shown on individual nodes (the accept screen);
		// a managed node sees the same terms as a notice.
		plan := orgintel.PlanAccept(*b)
		v.Disclosure, v.DisclosureDigest = plan.Disclosure, plan.DisclosureDigest
	}
	if snap.Active != nil {
		a := consentView(*snap.Active)
		v.Active = &a
	}
	return v
}

func consentView(ev store.OrgIntelConsentEvent) dashapi.OrgIntelConsentView {
	return dashapi.OrgIntelConsentView{
		Event: ev.Event, RequirementVersion: ev.RequirementVersion, EvidenceLevel: ev.EvidenceLevel,
		Purposes: ev.Purposes, DisclosureDigest: ev.DisclosureDigest, ConsentMode: ev.ConsentMode,
		CreatedAt: ev.CreatedAt.UTC().Format(time.RFC3339),
	}
}

// buildOrgIntelStatusView is the full view: the snapshot plus the local
// consent history, receipts and the cached-result count.
func buildOrgIntelStatusView(ctx context.Context, st *store.Store, snap orgIntelSnapshot) (dashapi.OrgIntelStatus, error) {
	v := newOrgIntelStatusView(snap)
	if snap.Enrolment != nil {
		hist, err := st.OrgIntelConsentHistory(ctx, snap.Enrolment.OrgID, orgIntelHistoryLimit)
		if err != nil {
			return v, err
		}
		for _, ev := range hist {
			v.History = append(v.History, consentView(ev))
		}
	}
	recs, err := st.OrgIntelReceipts(ctx, orgIntelHistoryLimit)
	if err != nil {
		return v, err
	}
	for _, r := range recs {
		v.Receipts = append(v.Receipts, dashapi.OrgIntelReceiptView{
			Kind: r.Kind, Count: r.Count, Detail: r.Detail, CreatedAt: r.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
	n, err := st.OrgIntelCacheCount(ctx)
	if err != nil {
		return v, err
	}
	v.CachedResults = n
	return v, nil
}

// --- daemon resolvers ----------------------------------------------------

// liveOrgEnrichment reads the node-authored [intelligence].org_enrichment key
// LIVE (the daemon loaded its config once at start, but an accept or withdraw
// from the CLI or the dashboard rewrites the file afterwards). The value is
// cached by the file's modification time so the push cycle does not re-parse
// an unchanged file; invalidate forces the next read.
type liveOrgEnrichment struct {
	configPath string
	mu         sync.Mutex
	mtime      time.Time
	size       int64
	value      bool
	loaded     bool
}

func newLiveOrgEnrichment(configPath string, initial bool) *liveOrgEnrichment {
	return &liveOrgEnrichment{configPath: configPath, value: initial}
}

// invalidate forces the next Get to re-read the file.
func (l *liveOrgEnrichment) invalidate() {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.loaded = false
	l.mu.Unlock()
}

// Get returns the current key value; a read failure keeps the last value.
func (l *liveOrgEnrichment) Get() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	path, err := config.ResolveGlobalPath(l.configPath)
	if err != nil {
		return l.value
	}
	fi, err := os.Stat(path)
	if err != nil {
		return l.value
	}
	if l.loaded && fi.ModTime().Equal(l.mtime) && fi.Size() == l.size {
		return l.value
	}
	if v, lerr := loadConfigOptIn(l.configPath); lerr == nil {
		l.value, l.mtime, l.size, l.loaded = v, fi.ModTime(), fi.Size(), true
	}
	return l.value
}

// orgIntelLocalOptIn is the node-authored input to the org-plane rail gate
// (intelRailEnabled's `local`). On an INDIVIDUAL-tenancy enrolment it is the
// effective opt-in of INV-13: the config key AND an active consent record, so
// a hand-edited key alone never turns the org plane on. On a managed (or no)
// enrolment it is the config key, which the govern table then merges.
func orgIntelLocalOptIn(ctx context.Context, st *store.Store, configKey bool) bool {
	if !configKey || st == nil {
		return configKey
	}
	snap, err := loadOrgIntelSnapshot(ctx, st, configKey, time.Now().UTC())
	if err != nil {
		return false
	}
	if snap.Status.Class == orgintel.ClassIndividual {
		return snap.Status.EffectiveOptIn
	}
	return configKey
}

// orgIntelConsentSource is the report source the org client polls each cycle
// (orgclient.SetIntelConsentSource): the node's own posture, derived by the
// same pure table every surface uses.
func orgIntelConsentSource(st *store.Store, live *liveOrgEnrichment) func(ctx context.Context) (orgcontract.IntelConsentReport, bool) {
	return func(ctx context.Context) (orgcontract.IntelConsentReport, bool) {
		snap, err := loadOrgIntelSnapshot(ctx, st, live.Get(), time.Now().UTC())
		if err != nil {
			return orgcontract.IntelConsentReport{}, false
		}
		return orgintel.Report(snap.Inputs, snap.Status)
	}
}
