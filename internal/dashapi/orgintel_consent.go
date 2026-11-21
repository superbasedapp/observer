package dashapi

import (
	"errors"
	"net/http"
)

// OrgIntelRequirementView is the org's signed terms as the page renders them.
type OrgIntelRequirementView struct {
	Enabled                  bool     `json:"enabled"`
	ProviderLabel            string   `json:"provider_label"`
	Model                    string   `json:"model"`
	EvidenceLevel            string   `json:"evidence_level"`
	Purposes                 []string `json:"purposes"`
	DeveloperActions         bool     `json:"developer_actions"`
	PerDeveloperDailyCap     int      `json:"per_developer_daily_cap"`
	RequireIndividualConsent bool     `json:"require_individual_consent"`
	RequirementVersion       int64    `json:"requirement_version"`
	RequiredSince            string   `json:"required_since,omitempty"`
	DeadlineDays             int      `json:"deadline_days"`
	DocVersion               int64    `json:"doc_version"`
	ReceivedAt               string   `json:"received_at,omitempty"`
	// Parity phase 4: the sweep the org runs for this member. Background
	// false means on demand only; the bounds are the node's effective ones
	// (its defaults when the org sent none).
	Background             bool `json:"background"`
	PerDeveloperMonthlyCap int  `json:"per_developer_monthly_cap"`
	QuietMinutes           int  `json:"quiet_minutes"`
	MinActions             int  `json:"min_actions"`
	MaxAgeDays             int  `json:"max_age_days"`
}

// OrgIntelRailView is the managed machine's result-rail readout (ruling Q2):
// whether org enrichment runs here and, when it does not, why, in plain words.
// Reason is a stable id (no_policy, policy_not_in_force, no_authority,
// not_raised, on); Message is the sentence the page and the CLI show.
type OrgIntelRailView struct {
	On      bool   `json:"on"`
	Reason  string `json:"reason"`
	Message string `json:"message"`
}

// OrgIntelConsentView is one consent event.
type OrgIntelConsentView struct {
	Event              string   `json:"event"`
	RequirementVersion int64    `json:"requirement_version"`
	EvidenceLevel      string   `json:"evidence_level,omitempty"`
	Purposes           []string `json:"purposes,omitempty"`
	DisclosureDigest   string   `json:"disclosure_digest,omitempty"`
	ConsentMode        string   `json:"consent_mode,omitempty"`
	CreatedAt          string   `json:"created_at"`
}

// OrgIntelReceiptView is one local audit row.
type OrgIntelReceiptView struct {
	Kind      string `json:"kind"`
	Count     int    `json:"count"`
	Detail    string `json:"detail,omitempty"`
	CreatedAt string `json:"created_at"`
}

// OrgIntelStatus is the GET /api/intel/status body (and `observer intel status
// --json`).
type OrgIntelStatus struct {
	// Class is unenrolled | individual | managed.
	Class   string `json:"class"`
	OrgName string `json:"org_name,omitempty"`
	// Requirement is nil when the org server has not sent its terms.
	Requirement *OrgIntelRequirementView `json:"requirement,omitempty"`
	// Disclosure / DisclosureDigest are THE consent text for the current
	// terms (one source of truth with the CLI) and its SHA-256; the accept
	// call echoes the digest back.
	Disclosure       string `json:"disclosure,omitempty"`
	DisclosureDigest string `json:"disclosure_digest,omitempty"`
	OrgEnabled       bool   `json:"org_enabled"`
	Required         bool   `json:"required"`
	Pending          bool   `json:"pending"`
	PendingReason    string `json:"pending_reason,omitempty"`
	Covered          bool   `json:"covered"`
	ConfigOptIn      bool   `json:"config_opt_in"`
	EffectiveOptIn   bool   `json:"effective_opt_in"`
	NoticeOnly       bool   `json:"notice_only"`
	DeadlineAt       string `json:"deadline_at,omitempty"`
	DeadlinePassed   bool   `json:"deadline_passed"`
	// Active is the consent in force (nil when none).
	Active   *OrgIntelConsentView  `json:"active,omitempty"`
	History  []OrgIntelConsentView `json:"history"`
	Receipts []OrgIntelReceiptView `json:"receipts"`
	// CachedResults is how many org results this machine holds.
	CachedResults int `json:"cached_results"`
	// ManagedRail is set on a managed machine only.
	ManagedRail *OrgIntelRailView `json:"managed_rail,omitempty"`
	// Note carries a non-fatal remark (a report that could not be sent).
	Note string `json:"note,omitempty"`
	// OrgDashboard is the team dashboard's origin (settingslink.
	// OrgDashboardBase of the enrolment's server address), so a status that
	// only the organization's admins can change links to the exact place.
	// Omitted when the address is not one a button may open.
	OrgDashboard string `json:"org_dashboard,omitempty"`
	// DashboardKind is the online dashboard this machine is connected to:
	// "personal" (the person is its only admin) or "team"; omitted when the
	// node does not know (an enrolment made by invite reads as a team).
	DashboardKind string `json:"dashboard_kind,omitempty"`
}

// OrgIntelManager is the cmd-wired org-plane seam (intel.go /
// orgintel_dashboard.go in cmd/observer).
type OrgIntelManager interface {
	Status(r *http.Request) (OrgIntelStatus, error)
	Accept(r *http.Request, shownDigest string) (OrgIntelStatus, error)
	Withdraw(r *http.Request) (OrgIntelStatus, error)
}

// Typed org-plane refusals a manager returns; mapped to statuses here.
var (
	// ErrOrgIntelConflict marks a request that cannot apply in the node's
	// current state (not enrolled, managed, no terms yet, stale terms).
	ErrOrgIntelConflict = errors.New("org intelligence: not applicable")
)
