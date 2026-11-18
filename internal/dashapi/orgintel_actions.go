package dashapi

import (
	"errors"
	"net/http"

	"github.com/marmutapp/superbased-observer/internal/settingslink"
)

// OrgIntelActionsView is what the developer may do with one session.
type OrgIntelActionsView struct {
	Preview      bool   `json:"preview"`
	Enrich       bool   `json:"enrich"`
	NeedsPreview bool   `json:"needs_preview"`
	Reason       string `json:"reason,omitempty"`
	ReasonText   string `json:"reason_text,omitempty"`
	// The way forward for Reason (internal/orgintel.ActionReasonFix): a
	// place on this machine (settings, settings_label) and/or the team
	// dashboard place only the organization's admins change (org_settings,
	// org_settings_label). Each field is omitted when it does not apply.
	settingslink.Fields
	settingslink.OrgFields
}

// OrgIntelSubmissionView is one org_intel_outbox row as the surfaces render it.
type OrgIntelSubmissionView struct {
	ID             int64  `json:"id"`
	SessionID      string `json:"session_id"`
	Purpose        string `json:"purpose"`
	EvidenceLevel  string `json:"evidence_level"`
	Trigger        string `json:"trigger"`
	State          string `json:"state"`
	Reason         string `json:"reason,omitempty"`
	JobID          int64  `json:"job_id,omitempty"`
	EvidenceDigest string `json:"evidence_content_digest"`
	UploadDigest   string `json:"upload_digest"`
	SizeBytes      int    `json:"size_bytes"`
	Attempts       int    `json:"attempts"`
	NextAt         string `json:"next_at,omitempty"`
	CreatedAt      string `json:"created_at"`
	UpdatedAt      string `json:"updated_at"`
	// BytesHeld reports the exact bytes are still on this machine (a row
	// not yet finally answered). A sent row keeps only its digests.
	BytesHeld bool `json:"bytes_held"`
	// Bytes is the exact envelope, only on a single-row ledger read.
	Bytes string `json:"bytes,omitempty"`
}

// OrgIntelSessionView is the GET /api/intel/session/{id} body.
type OrgIntelSessionView struct {
	SessionID string `json:"session_id"`
	// Authority is the session's data-authority stamp: org | personal |
	// unknown. Only an org session is part of the org plane.
	Authority string `json:"authority"`
	// DashboardKind is "personal", "team" or omitted (see
	// OrgIntelStatus.DashboardKind).
	DashboardKind string                  `json:"dashboard_kind,omitempty"`
	OrgName       string                  `json:"org_name,omitempty"`
	Class         string                  `json:"class"`
	Actions       OrgIntelActionsView     `json:"actions"`
	Latest        *OrgIntelSubmissionView `json:"latest,omitempty"`
	Submissions   int                     `json:"submissions"`
	// Enriched / Result are the newest cached org result (filled here from
	// the node-local cache, the /api/session/{id}/org-intel read).
	Enriched bool                `json:"enriched"`
	Result   *OrgIntelResultWire `json:"result,omitempty"`
}

// OrgIntelPreview is the GET /api/intel/preview body: the exact bytes a
// submission of this session would send now.
type OrgIntelPreview struct {
	SessionID      string `json:"session_id"`
	OrgName        string `json:"org_name,omitempty"`
	EvidenceLevel  string `json:"evidence_level"`
	Purpose        string `json:"purpose"`
	EvidenceDigest string `json:"evidence_content_digest"`
	UploadDigest   string `json:"upload_digest"`
	SizeBytes      int    `json:"size_bytes"`
	Actions        int    `json:"actions"`
	Excerpts       int    `json:"excerpts"`
	// NoticeOnly: a managed machine previews to see what leaves; it has no
	// veto (design Q7).
	NoticeOnly bool   `json:"notice_only"`
	Bytes      string `json:"bytes"`
}

// OrgIntelEnrichResult is the POST /api/intel/enrich body.
type OrgIntelEnrichResult struct {
	Submission OrgIntelSubmissionView `json:"submission"`
	// Queued is false when these exact bytes were already queued or sent
	// (the earlier row is returned; the org would answer duplicate).
	Queued bool `json:"queued"`
	// Sent reports the submission reached the org server now; false leaves
	// it queued for the next push cycle.
	Sent    bool   `json:"sent"`
	Message string `json:"message"`
}

// OrgIntelLedger is the GET /api/intel/ledger body.
type OrgIntelLedger struct {
	OrgName string                   `json:"org_name,omitempty"`
	Rows    []OrgIntelSubmissionView `json:"rows"`
}

// OrgIntelActionManager is the cmd-wired action seam. The org-plane manager
// implements it beside OrgIntelManager.
type OrgIntelActionManager interface {
	Session(r *http.Request, sessionID string) (OrgIntelSessionView, error)
	Preview(r *http.Request, sessionID string) (OrgIntelPreview, error)
	Enrich(r *http.Request, sessionID, shownUploadDigest string) (OrgIntelEnrichResult, error)
	Ledger(r *http.Request, id int64) (OrgIntelLedger, error)
}

// Typed action refusals a manager returns.
var (
	// ErrOrgIntelPreviewRequired marks an enrich whose shown digest is not the
	// current bytes' (the developer must preview what will be sent).
	ErrOrgIntelPreviewRequired = errors.New("org intelligence: preview the current evidence first")
	// ErrOrgIntelNotFound marks an unknown session or ledger row.
	ErrOrgIntelNotFound = errors.New("org intelligence: not found")
)
