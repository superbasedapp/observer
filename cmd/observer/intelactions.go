package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/dataauthority"
	"github.com/marmutapp/superbased-observer/internal/orgintel"
	"github.com/marmutapp/superbased-observer/internal/settingslink"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// intelactions.go is the org-plane ACTION half of the node's Cloud
// Intelligence parity (phase 3, design section 3.2): one session's state, the
// network-free preview of its exact evidence bytes, a developer-started
// enrichment, and the submission ledger. `observer intel results | preview |
// enrich | ledger` and the dashboard's /api/intel/{session,preview,enrich,
// ledger} routes call these SAME functions.

// orgIntelLedgerLimit bounds the ledger the surfaces list.
const orgIntelLedgerLimit = 200

// orgIntelSession is one session's resolved org-plane context.
type orgIntelSession struct {
	snap      orgIntelSnapshot
	authority dataauthority.Authority
	plan      orgintel.SessionActionPlan
}

// orgIntelRailOn resolves the org-plane rail gate the way the daemon does: the
// node-authored opt-in (with the individual consent rule, INV-13) merged with
// the managed raise of the live governance posture.
func orgIntelRailOn(ctx context.Context, b orgBundle) bool {
	return intelRailEnabled(
		orgIntelLocalOptIn(ctx, b.store, b.cfg.Intelligence.OrgEnrichment),
		enterpriseContentEffective(ctx, b.cfg, b.store, nil),
	)
}

// resolveOrgIntelSession reads the snapshot, the session's authority stamp and
// the pure per-session action table.
func resolveOrgIntelSession(ctx context.Context, b orgBundle, sessionID string) (orgIntelSession, error) {
	snap, err := loadOrgIntelSnapshot(ctx, b.store, b.cfg.Intelligence.OrgEnrichment, time.Now().UTC())
	if err != nil {
		return orgIntelSession{}, err
	}
	// "unknown" is the honest label for a session with no (or an unknown)
	// authority stamp: it is never eligible for either plane.
	auth := dataauthority.Authority("unknown")
	if cls, ok, aerr := b.store.SessionAuthority(ctx, sessionID); aerr != nil {
		return orgIntelSession{}, aerr
	} else if ok {
		auth = cls.Authority
	}
	return orgIntelSession{
		snap: snap, authority: auth,
		plan: orgintel.PlanSessionAction(snap.Inputs, orgIntelRailOn(ctx, b), auth),
	}, nil
}

func (s orgIntelSession) orgName() string {
	if s.snap.Enrolment == nil {
		return ""
	}
	if s.snap.Enrolment.OrgName != "" {
		return s.snap.Enrolment.OrgName
	}
	return s.snap.Enrolment.OrgID
}

// orgIntelSubmissionView maps an outbox row onto the wire view.
func orgIntelSubmissionView(row store.OrgIntelSubmission, withBytes bool) dashapi.OrgIntelSubmissionView {
	v := dashapi.OrgIntelSubmissionView{
		ID: row.ID, SessionID: row.SessionID, Purpose: row.Purpose, EvidenceLevel: row.EvidenceLevel,
		Trigger: row.Trigger, State: row.State, Reason: row.Reason, JobID: row.JobID,
		EvidenceDigest: row.EvidenceDigest, UploadDigest: row.UploadDigest, SizeBytes: row.Bytes,
		Attempts: row.Attempts, CreatedAt: row.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt: row.UpdatedAt.UTC().Format(time.RFC3339), BytesHeld: len(row.Envelope) > 0,
	}
	if !row.NextAt.IsZero() && (row.State == store.OrgIntelOutboxPending || row.State == store.OrgIntelOutboxFailedRetryable) {
		v.NextAt = row.NextAt.UTC().Format(time.RFC3339)
	}
	if withBytes && v.BytesHeld {
		v.Bytes = string(row.Envelope)
	}
	return v
}

// orgIntelActionsView maps the session's action plan onto the wire view,
// with the way forward for a refusal: the local place the developer changes
// and/or the team-dashboard place only the organization's admins change
// (orgintel.ActionReasonFix, paths from internal/settingslink).
//
// kind is the online dashboard kind (readConnectKind): on a personal
// dashboard the sentence and the link speak to its only admin, the person.
func orgIntelActionsView(s orgIntelSession, kind string) dashapi.OrgIntelActionsView {
	v := dashapi.OrgIntelActionsView{
		Preview: s.plan.Preview, Enrich: s.plan.Enrich, NeedsPreview: s.plan.NeedsPreview,
		Reason: s.plan.Reason, ReasonText: orgintel.ActionReasonTextFor(s.plan.Reason, kind == "personal"),
	}
	fix := orgintel.ActionReasonFix(s.plan.Reason)
	if l, ok := settingslink.For(fix.Place); ok {
		v.Fields = l.Fields()
	}
	if l, ok := settingslink.OrgFor(orgDashboardAddress(s.snap.Enrolment), fix.OrgPlace); ok {
		v.OrgFields = l.Fields()
		v.OrgDashboardKind = kind
	}
	return v
}

// orgDashboardAddress is where the organization's own dashboard is: the
// online address `observer connect` recorded, else the org server address.
func orgDashboardAddress(e *store.Enrolment) string {
	if e == nil {
		return ""
	}
	if settingslink.OrgDashboardBase(e.OnlineURL) != "" {
		return e.OnlineURL
	}
	return e.OrgServerURL
}

// orgIntelSessionState is `observer intel results` and GET /api/intel/session.
func orgIntelSessionState(ctx context.Context, b orgBundle, sessionID, configPath string) (dashapi.OrgIntelSessionView, error) {
	s, err := resolveOrgIntelSession(ctx, b, sessionID)
	if err != nil {
		return dashapi.OrgIntelSessionView{}, err
	}
	kind := ""
	if s.snap.Enrolment != nil {
		kind = readConnectKind(configPath, s.snap.Enrolment.OrgID)
	}
	v := dashapi.OrgIntelSessionView{
		SessionID: sessionID, Authority: string(s.authority), OrgName: s.orgName(), Class: s.snap.Status.Class,
		DashboardKind: kind, Actions: orgIntelActionsView(s, kind),
	}
	if s.snap.Enrolment != nil {
		rows, rerr := b.store.OrgIntelSubmissions(ctx, s.snap.Enrolment.OrgID, sessionID, orgIntelLedgerLimit)
		if rerr != nil {
			return v, rerr
		}
		v.Submissions = len(rows)
		if len(rows) > 0 {
			latest := orgIntelSubmissionView(rows[0], false)
			v.Latest = &latest
		}
	}
	return v, nil
}

// previewOrgIntelSession builds the org-plane evidence for one session at the
// planned level. Nothing is queued and nothing is sent.
func previewOrgIntelSession(ctx context.Context, b orgBundle, sessionID string) (orgIntelBuilt, orgIntelSession, error) {
	s, err := resolveOrgIntelSession(ctx, b, sessionID)
	if err != nil {
		return orgIntelBuilt{}, s, err
	}
	if !s.plan.Preview {
		return orgIntelBuilt{}, s, orgIntelConflict{err: fmt.Errorf("%s", orgintel.ActionReasonText(s.plan.Reason))}
	}
	built, err := buildOrgIntelEnvelope(ctx, b.store, s.snap.Enrolment.OrgID, sessionID, s.plan.Submit,
		orgintel.EvidenceSettingsFor(s.snap.Inputs.Requirement, s.plan.Submit.Level),
		acquireProcessCostEngine(ctx, b.cfg, b.db, slog.Default()))
	return built, s, err
}

// orgIntelPreviewView maps a build onto the wire view.
func orgIntelPreviewView(sessionID string, built orgIntelBuilt, s orgIntelSession) dashapi.OrgIntelPreview {
	return dashapi.OrgIntelPreview{
		SessionID: sessionID, OrgName: s.orgName(), EvidenceLevel: string(built.Level), Purpose: string(built.Purpose),
		EvidenceDigest: built.Result.Digests.EvidenceContent, UploadDigest: built.Result.Digests.Upload,
		SizeBytes: len(built.Result.Bytes), Actions: built.Result.Actions, Excerpts: built.Result.Excerpts,
		NoticeOnly: !s.plan.NeedsPreview, Bytes: string(built.Result.Bytes),
	}
}

// orgIntelEnrichMessages is the sentence each outcome reads as (one table for
// the CLI and the dashboard).
var orgIntelEnrichMessages = map[string]string{
	store.OrgIntelOutboxSubmitted:       "Sent. Your organization's server queued the enrichment; the result arrives with a later sync.",
	store.OrgIntelOutboxDuplicate:       "Your organization's server already has these exact bytes; nothing new was queued.",
	store.OrgIntelOutboxAlreadyEnriched: "Your organization already enriched this session.",
	store.OrgIntelOutboxRefused:         "Refused by your organization's server.",
	store.OrgIntelOutboxFailedRetryable: "Queued. It could not be sent yet; the next push cycle tries again.",
	store.OrgIntelOutboxPending:         "Queued. The next push cycle sends it.",
}

// enrichOrgIntelSession builds the session's evidence, checks it is the bytes
// the developer previewed when the plan requires that, queues one
// developer-started submission and sends it now. shownDigest is the upload
// digest of the preview the developer saw ("" when none).
func enrichOrgIntelSession(ctx context.Context, b orgBundle, sessionID, shownDigest string) (dashapi.OrgIntelEnrichResult, error) {
	built, s, err := previewOrgIntelSession(ctx, b, sessionID)
	if err != nil {
		return dashapi.OrgIntelEnrichResult{}, err
	}
	if !s.plan.Enrich {
		return dashapi.OrgIntelEnrichResult{}, orgIntelConflict{err: fmt.Errorf("%s", orgintel.ActionReasonText(s.plan.Reason))}
	}
	current := built.Result.Digests.Upload
	if (s.plan.NeedsPreview || shownDigest != "") && shownDigest != current {
		return dashapi.OrgIntelEnrichResult{}, fmt.Errorf("%w: the session's evidence is not the preview that was shown (preview it again and confirm)",
			dashapi.ErrOrgIntelPreviewRequired)
	}
	row, inserted, err := queueOrgIntelSubmission(ctx, b.store, built, sessionID, store.OrgIntelTriggerDeveloper)
	if err != nil {
		return dashapi.OrgIntelEnrichResult{}, err
	}
	res := dashapi.OrgIntelEnrichResult{Queued: inserted}
	sendable := row.State == store.OrgIntelOutboxPending || row.State == store.OrgIntelOutboxFailedRetryable
	if sendable && b.client != nil {
		sent, serr := b.client.SubmitIntelEvidence(ctx, row)
		if serr != nil {
			return res, serr
		}
		res.Sent = sent.Receipt != nil || sent.Refusal != nil
		if got, ok, gerr := b.store.GetOrgIntelSubmission(ctx, row.OrgID, row.ID); gerr == nil && ok {
			row = got
		}
	}
	res.Submission = orgIntelSubmissionView(row, false)
	res.Message = orgIntelEnrichMessages[row.State]
	if row.State == store.OrgIntelOutboxRefused && row.Reason != "" {
		res.Message = fmt.Sprintf("%s (%s)", res.Message, row.Reason)
	}
	if !inserted && !sendable {
		res.Message = "These exact bytes were already submitted from this machine; an enrichment runs again once the session changes. " + res.Message
	}
	return res, nil
}

// orgIntelLedger is `observer intel ledger` and GET /api/intel/ledger. id > 0
// reads one row, with its exact bytes while it still holds them.
func orgIntelLedger(ctx context.Context, b orgBundle, id int64) (dashapi.OrgIntelLedger, error) {
	l := dashapi.OrgIntelLedger{Rows: []dashapi.OrgIntelSubmissionView{}}
	enr, err := b.store.LoadEnrolment(ctx)
	if err != nil || enr == nil {
		return l, err
	}
	l.OrgName = enr.OrgName
	if id > 0 {
		row, ok, gerr := b.store.GetOrgIntelSubmission(ctx, enr.OrgID, id)
		if gerr != nil {
			return l, gerr
		}
		if !ok {
			return l, fmt.Errorf("%w: no submission %d", dashapi.ErrOrgIntelNotFound, id)
		}
		l.Rows = append(l.Rows, orgIntelSubmissionView(row, true))
		return l, nil
	}
	rows, err := b.store.OrgIntelSubmissions(ctx, enr.OrgID, "", orgIntelLedgerLimit)
	if err != nil {
		return l, err
	}
	for _, r := range rows {
		l.Rows = append(l.Rows, orgIntelSubmissionView(r, false))
	}
	return l, nil
}

// --- dashapi.OrgIntelActionManager ------------------------------------

var _ dashapi.OrgIntelActionManager = (*orgIntelDashboard)(nil)

func (d *orgIntelDashboard) withBundle(r *http.Request, fn func(b orgBundle) error) error {
	b, err := d.build(r.Context(), d.configPath)
	if err != nil {
		return err
	}
	defer b.cleanup()
	return fn(b)
}

// Session serves GET /api/intel/session/{id}.
func (d *orgIntelDashboard) Session(r *http.Request, sessionID string) (v dashapi.OrgIntelSessionView, err error) {
	err = d.withBundle(r, func(b orgBundle) error {
		v, err = orgIntelSessionState(r.Context(), b, sessionID, d.configPath)
		return err
	})
	return v, asOrgIntelDashboardErr(err)
}

// Preview serves GET /api/intel/preview.
func (d *orgIntelDashboard) Preview(r *http.Request, sessionID string) (p dashapi.OrgIntelPreview, err error) {
	err = d.withBundle(r, func(b orgBundle) error {
		built, s, berr := previewOrgIntelSession(r.Context(), b, sessionID)
		if berr != nil {
			return berr
		}
		p = orgIntelPreviewView(sessionID, built, s)
		return nil
	})
	return p, asOrgIntelDashboardErr(err)
}

// Enrich serves POST /api/intel/enrich.
func (d *orgIntelDashboard) Enrich(r *http.Request, sessionID, shownDigest string) (res dashapi.OrgIntelEnrichResult, err error) {
	err = d.withBundle(r, func(b orgBundle) error {
		res, err = enrichOrgIntelSession(r.Context(), b, sessionID, shownDigest)
		return err
	})
	return res, asOrgIntelDashboardErr(err)
}

// Ledger serves GET /api/intel/ledger.
func (d *orgIntelDashboard) Ledger(r *http.Request, id int64) (l dashapi.OrgIntelLedger, err error) {
	err = d.withBundle(r, func(b orgBundle) error {
		l, err = orgIntelLedger(r.Context(), b, id)
		return err
	})
	return l, asOrgIntelDashboardErr(err)
}
