package dashapi

import (
	"context"

	"github.com/marmutapp/superbased-observer/internal/orgenrol"
)

// EnrolmentManager is the dashboard's seam onto organization enrolment. Nil =
// not wired (the routes answer 501, e.g. a standalone `observer dashboard`).
type EnrolmentManager interface {
	// Overview is `observer org status` as data (works enrolled or not).
	Overview(ctx context.Context) (EnrolmentOverview, error)
	// Probe checks a server URL's shape and reachability; nothing is sent
	// but an unauthenticated health read.
	Probe(ctx context.Context, orgURL string) (EnrolProbe, error)
	// Enrol exchanges a one-time code (code or link method) and writes the
	// default [org_client] block. A governance grant that needs consent is
	// parked and returned as PendingGrant for DecideGrant.
	Enrol(ctx context.Context, req EnrolRequest) (EnrolOutcome, error)
	// DecideGrant records (accept) or declines a parked grant offer.
	DecideGrant(ctx context.Context, offerID string, accept bool) (GrantDecision, error)
	// StartIdP begins a sign-in enrolment (`observer enroll --idp`).
	StartIdP(ctx context.Context, orgURL string) (IdPStart, error)
	// PollIdP advances a sign-in enrolment one step; on approval it enrols.
	PollIdP(ctx context.Context, flowID string) (IdPPoll, error)
	// GrantReport is `observer org grant show` as data.
	GrantReport(ctx context.Context) (GrantReport, error)
	// PushNow is `observer org push-now`.
	PushNow(ctx context.Context) (PushNowReport, error)
	// ShareHistory is `observer org backfill --all [--confirm]`: confirm=false
	// only counts, confirm=true rewinds the push cursor so the history that
	// predates enrolment ships over the next push cycles.
	ShareHistory(ctx context.Context, confirm bool) (ShareHistoryReport, error)
	// Resync is `observer org resync [--confirm]` with its default window:
	// confirm=false only counts, confirm=true queues already-pushed rows that
	// changed on this node (and deletion manifests) for a re-send.
	Resync(ctx context.Context, confirm bool) (ResyncReport, error)
	// Leave is `observer unenroll`, including its symmetric cleanup.
	Leave(ctx context.Context) (LeaveReport, error)
}

// EnrolNote is one line of outcome copy with a tone.
type EnrolNote struct {
	// Level is "ok", "info" or "warn".
	Level string `json:"level"`
	Text  string `json:"text"`
}

// EnrolTableCount is one row of the historical-vs-eligible scope table.
type EnrolTableCount struct {
	Table      string `json:"table"`
	Historical int64  `json:"historical"`
	Eligible   int64  `json:"eligible"`
}

// PendingGrant is a governance-grant offer awaiting the developer's decision.
type PendingGrant struct {
	OfferID    string              `json:"offer_id"`
	ExpiresAt  string              `json:"expires_at"`
	Disclosure orgenrol.Disclosure `json:"disclosure"`
}

// EnrolmentOverview is GET /api/enrolment/manage's `overview`.
type EnrolmentOverview struct {
	Enrolled bool   `json:"enrolled"`
	OrgID    string `json:"org_id,omitempty"`
	OrgName  string `json:"org_name,omitempty"`
	// OrgDisplay is the name every surface shows (orgenrol.DisplayName),
	// never the org id.
	OrgDisplay      string `json:"org_display,omitempty"`
	OrgServerURL    string `json:"org_server_url,omitempty"`
	UserEmail       string `json:"user_email,omitempty"`
	EnrolledAt      string `json:"enrolled_at,omitempty"`
	CredentialStore string `json:"credential_store,omitempty"`
	// Tenancy is "managed" or "individual" (empty when not enrolled).
	Tenancy string `json:"tenancy,omitempty"`
	// MachineProofWarning is set on a managed enrolment whose daemon signs
	// no machine proof (WINNODE item 4: "Machine proof unavailable: no
	// Windows logon session ..."). Absent is the normal case.
	MachineProofWarning string `json:"machine_proof_warning,omitempty"`
	// DaemonCredentialWarning is set when a running daemon reported, at its
	// last push cycle, that it cannot read the organization credential, so
	// it does not push (WINNODE2 issue 1b). "" otherwise.
	DaemonCredentialWarning string `json:"daemon_credential_warning,omitempty"`
	// PushingEnabled is [org_client].enabled in config.toml.
	PushingEnabled bool `json:"pushing_enabled"`
	// PushLoopRunning reports whether THIS daemon runs a push loop. False on
	// a daemon that started before the node was enrolled: a restart starts it.
	PushLoopRunning bool `json:"push_loop_running"`
	// PushIntervalSeconds is the configured push ceiling (`observer org
	// push-status`'s "Push interval"): the loop pushes at least this often,
	// sooner when new activity arrives. Zero from a manager that predates it.
	PushIntervalSeconds int `json:"push_interval_seconds,omitempty"`
	// ShareMode is the share-mode rule name (full_content, admin_managed,
	// enterprise_grant, metadata_only); ShareModeLine the CLI's sentence.
	ShareMode         string            `json:"share_mode,omitempty"`
	ShareModeLine     string            `json:"share_mode_line,omitempty"`
	TargetActions     []string          `json:"target_actions,omitempty"`
	GovernanceWarning string            `json:"governance_warning,omitempty"`
	Governed          bool              `json:"governed"`
	Tables            []EnrolTableCount `json:"tables,omitempty"`
	PendingResends    map[string]int64  `json:"pending_resends,omitempty"`
	PendingDeletions  int64             `json:"pending_deletions,omitempty"`
	PendingManifests  int64             `json:"pending_manifests,omitempty"`
	EligibleReason    string            `json:"eligible_reason,omitempty"`
	LastPush          *EnrolLastPush    `json:"last_push,omitempty"`
	PushPaused        *EnrolPushPaused  `json:"push_paused,omitempty"`
	PendingGrant      *PendingGrant     `json:"pending_grant,omitempty"`
	// LeavePlan is what Leave would do with each proxy route right now: the
	// confirm dialog names exactly what will be removed and what is kept.
	LeavePlan []EnrolLeaveRoute `json:"leave_plan,omitempty"`
	// LeaveSteps is the structured unenrol's conferred -> retired table in
	// apply order (T-718): the same rows `observer unenroll --plan` prints.
	LeaveSteps []EnrolLeaveStep `json:"leave_steps,omitempty"`
}

// EnrolLeaveStep is one row of the structured unenrol plan.
type EnrolLeaveStep struct {
	ID string `json:"id"`
	// Phase is "fence", "enforcement", "notify", "identity" or "kept".
	Phase     string `json:"phase"`
	Conferred string `json:"conferred"`
	Retired   string `json:"retired"`
}

// EnrolLastPush is the most recent push attempt (same shape as
// /api/enrolment/status's last_push).
type EnrolLastPush struct {
	PushedAt string `json:"pushed_at"`
	Status   string `json:"status"`
	RowCount int64  `json:"row_count"`
	Bytes    int64  `json:"bytes"`
	Error    string `json:"error,omitempty"`
}

// EnrolPushPaused is the open oversized-batch circuit (same shape as
// /api/enrolment/status's push_paused).
type EnrolPushPaused struct {
	Reason string `json:"reason,omitempty"`
	Until  string `json:"until"`
}

// EnrolProbe is the POST /api/enrolment/probe answer.
type EnrolProbe struct {
	OrgURL  string `json:"org_url"`
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

// EnrolRequest is the POST /api/enrolment/enrol body. The token never leaves
// this request: it is not logged, audited, or echoed back.
type EnrolRequest struct {
	Method string `json:"method"`
	OrgURL string `json:"org_url"`
	Token  string `json:"token"`
	Link   string `json:"link"`
}

// EnrolOutcome is what an enrolment did.
type EnrolOutcome struct {
	OrgID        string `json:"org_id"`
	OrgName      string `json:"org_name"`
	OrgDisplay   string `json:"org_display,omitempty"`
	UserEmail    string `json:"user_email"`
	OrgServerURL string `json:"org_server_url"`
	Tenancy      string `json:"tenancy"`
	Managed      bool   `json:"managed"`
	// ConfigPath / BlockWritten / FullContent / ShareSummary describe the
	// [org_client] block the enrolment wrote (or found already present).
	ConfigPath   string        `json:"config_path,omitempty"`
	BlockWritten bool          `json:"block_written"`
	FullContent  bool          `json:"full_content"`
	ShareSummary string        `json:"share_summary,omitempty"`
	Notes        []EnrolNote   `json:"notes,omitempty"`
	PendingGrant *PendingGrant `json:"pending_grant,omitempty"`
	// Grant is set when the grant was settled without asking (an IdP
	// approval already was the consent, or the node refused the offer).
	Grant *GrantDecision `json:"grant,omitempty"`
	// RestartRequired: this daemon runs no push loop yet (it started before
	// the node was enrolled), so pushes begin after a daemon restart.
	RestartRequired bool `json:"restart_required"`
}

// GrantDecision is what happened to a governance-grant offer.
type GrantDecision struct {
	// Status is accepted, declined, refused, or consented (IdP approval).
	Status  string      `json:"status"`
	Message string      `json:"message"`
	Notes   []EnrolNote `json:"notes,omitempty"`
}

// IdPStart is the POST /api/enrolment/idp/start answer. The device code
// stays server-side; the browser only ever holds the opaque flow id.
type IdPStart struct {
	FlowID          string `json:"flow_id"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

// IdPPoll is one sign-in enrolment step.
type IdPPoll struct {
	// Status is pending, approved, denied, or expired.
	Status   string        `json:"status"`
	Interval int           `json:"interval"`
	Message  string        `json:"message,omitempty"`
	Outcome  *EnrolOutcome `json:"outcome,omitempty"`
}

// FamilyRow is one [org_client.policy] family the grant governs.
type FamilyRow struct {
	Family       string `json:"family"`
	Accepted     bool   `json:"accepted"`
	Preauthorize bool   `json:"preauthorized"`
}

// GrantReport is GET /api/enrolment/grant.
type GrantReport struct {
	// State is not_enrolled, ungoverned, or governed.
	State        string                   `json:"state"`
	OrgName      string                   `json:"org_name,omitempty"`
	OrgDisplay   string                   `json:"org_display,omitempty"`
	OrgID        string                   `json:"org_id,omitempty"`
	ServerURL    string                   `json:"server_url,omitempty"`
	GrantedAt    string                   `json:"granted_at,omitempty"`
	ExpiryLine   string                   `json:"expiry_line,omitempty"`
	Consent      string                   `json:"consent,omitempty"`
	Receipt      string                   `json:"receipt,omitempty"`
	Authority    []orgenrol.AuthorityLine `json:"authority,omitempty"`
	ContentLine  string                   `json:"content_line,omitempty"`
	Families     []FamilyRow              `json:"families,omitempty"`
	Verification []EnrolNote              `json:"verification,omitempty"`
	Pinned       []string                 `json:"pinned,omitempty"`
}

// PushNowReport is POST /api/enrolment/push-now.
type PushNowReport struct {
	Empty    bool        `json:"empty"`
	RowCount int         `json:"row_count"`
	Bytes    int         `json:"bytes"`
	Accepted int64       `json:"accepted"`
	Deduped  int64       `json:"deduped"`
	More     bool        `json:"more"`
	Message  string      `json:"message"`
	Notes    []EnrolNote `json:"notes,omitempty"`
}

// ShareHistoryReport is POST /api/enrolment/share-history: the same counts
// `observer org backfill --all` prints.
type ShareHistoryReport struct {
	// Eligible is how many rows were already waiting to ship.
	Eligible int64 `json:"eligible"`
	// WouldUnlock is how many more rows the rewind makes (or made) eligible.
	WouldUnlock int64 `json:"would_unlock"`
	// Total is the whole local corpus across the pushable tables.
	Total int64 `json:"total"`
	// Rewound is true when the cursor was reset (a confirmed run).
	Rewound bool `json:"rewound"`
}

// ResyncReport is POST /api/enrolment/resync: the counts `observer org
// resync` prints for its default window.
type ResyncReport struct {
	// WindowDays / Limit are the window and the row cap the run used.
	WindowDays int `json:"window_days"`
	Limit      int `json:"limit"`
	// Tables is each pushed table's queued (or would-queue) row count.
	Tables []ResyncTable `json:"tables"`
	// Queued is the rows queued, or that would be, across all tables.
	Queued int64 `json:"queued"`
	// EndedAtChecked is the sessions whose end time was recomputed.
	EndedAtChecked int `json:"ended_at_checked"`
	// Manifests is the sessions queued (or that would be) to reconcile
	// deletions; ManifestsChecked the sessions looked at; ManifestsTooBig
	// those too large to reconcile.
	Manifests        int `json:"manifests"`
	ManifestsChecked int `json:"manifests_checked"`
	ManifestsTooBig  int `json:"manifests_too_big"`
	// NotBefore is the oldest row time a deletion manifest may touch
	// (inside this node's retention horizon), RFC 3339; empty when none.
	NotBefore string `json:"not_before,omitempty"`
	// Confirmed is true for a run that queued (confirm=true).
	Confirmed bool `json:"confirmed"`
}

// ResyncTable is one table's line of a ResyncReport.
type ResyncTable struct {
	Table  string `json:"table"`
	Queued int64  `json:"queued"`
}

// LeaveReport is POST /api/enrolment/leave.
// EnrolLeaveRoute is one proxy route in the Leave plan or report.
type EnrolLeaveRoute struct {
	Tool string `json:"tool"`
	// Action is "remove" or "keep".
	Action string `json:"action"`
	// Message is the sentence shown (the same one `observer unenroll` prints).
	Message string `json:"message"`
}

type LeaveReport struct {
	WasEnrolled bool        `json:"was_enrolled"`
	OrgName     string      `json:"org_name,omitempty"`
	OrgDisplay  string      `json:"org_display,omitempty"`
	Notes       []EnrolNote `json:"notes,omitempty"`
}
