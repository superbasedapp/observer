package cloudcontract

import (
	"encoding/json"
	"time"
)

// export.go is the account data-export contract (divergence-remediation plan §3
// "W6d", closing D11; Doc B §5.2 / Doc A §7.2). An AccountExport is the assembled
// snapshot of everything the plan's W6d per-object matrix marks "in export" — the
// portable copy a signed-in developer can download of their OWN account data.
//
// It is a LIVE-ACCOUNT artifact: the deletion flow offers export as its first
// step ("download your data first"), because once deletion runs, result text is
// tombstoned and every credential revoked in the same pass, so there is no
// post-`done` export. See the store's export.go for assembly and the API's
// export.go for the endpoints.
//
// Contract discipline: this is an external artifact, so it ships `.v1-candidate`
// and is frozen before private beta. It carries ONLY the account's own data
// (its opaque UUID, its enrichment results and corrections, its consent receipts,
// its usage summary, its structural aggregates) — never another tenant's, never
// operator/system state, never raw credentials (device public keys/thumbprints
// are excluded), never identity email/subject, never evidence bytes. The matrix's
// "no"/"excluded" objects are simply absent from this shape.

// AccountExportSchemaVersion is the frozen candidate version stamped into every
// assembled export. Bumping it is a deliberate contract change.
const AccountExportSchemaVersion = "account_export.v1-candidate"

// AccountExport is the top-level export document. Field order is the reading
// order of the matrix; every sub-slice is non-nil (empty, never null) so the
// downloaded JSON is uniform.
type AccountExport struct {
	SchemaVersion string    `json:"schema_version"`
	GeneratedAt   time.Time `json:"generated_at"`
	// AccountID is the developer's own opaque account UUID — their identifier for
	// their own data, never a cross-account key.
	AccountID  string                `json:"account_id"`
	Devices    []ExportDevice        `json:"devices"`
	Consents   ExportConsents        `json:"consents"`
	Usage      ExportUsage           `json:"usage"`
	Projects   []ExportProject       `json:"projects"`
	Sessions   []ExportSession       `json:"sessions"`
	Jobs       []ExportJobSummary    `json:"jobs"`
	Structural []ExportStructuralDay `json:"structural_days"`
}

// ExportDevice is a device SUMMARY (matrix: "devices: name+created summary").
// The public key and thumbprint are credentials and are deliberately excluded.
type ExportDevice struct {
	Label     string     `json:"label"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// ExportConsents is the full consent history (matrix: "yes (full receipts)") —
// the legal proof-of-consent the developer is entitled to a copy of.
type ExportConsents struct {
	Receipts []ExportConsentReceipt `json:"receipts"`
	Events   []ExportConsentEvent   `json:"events"`
}

// ExportConsentReceipt mirrors a consent_receipts row (content-free binding
// metadata; no session content).
type ExportConsentReceipt struct {
	Purposes              []string   `json:"purposes"`
	FieldClasses          []string   `json:"field_classes"`
	EvidenceSchema        string     `json:"evidence_schema"`
	ScrubberVersion       string     `json:"scrubber_version"`
	RetentionPolicy       string     `json:"retention_policy"`
	Endpoint              string     `json:"endpoint"`
	Subprocessors         []string   `json:"subprocessors"`
	UploadDigest          string     `json:"upload_digest"`
	EvidenceContentDigest string     `json:"evidence_content_digest,omitempty"`
	Generation            int64      `json:"generation"`
	CreatedAt             time.Time  `json:"created_at"`
	ExpiresAt             *time.Time `json:"expires_at,omitempty"`
}

// ExportConsentEvent mirrors a consent_events row (grant/revoke history).
type ExportConsentEvent struct {
	EventType  string    `json:"event_type"`
	Purposes   []string  `json:"purposes"`
	Generation int64     `json:"generation"`
	CreatedAt  time.Time `json:"created_at"`
}

// ExportUsage is the usage summary (matrix: entitlements + cycles + ledger).
type ExportUsage struct {
	Entitlements []ExportEntitlement      `json:"entitlements"`
	Cycles       []ExportUsageCycle       `json:"cycles"`
	Ledger       []ExportUsageLedgerEntry `json:"ledger"`
}

// ExportEntitlement mirrors an entitlements row (the account's caps).
type ExportEntitlement struct {
	Feature        string `json:"feature"`
	Source         string `json:"source"`
	DailyCap       int    `json:"daily_cap"`
	MonthlyCap     int    `json:"monthly_cap"`
	ConcurrencyCap int    `json:"concurrency_cap"`
}

// ExportUsageCycle mirrors a usage_cycles row (a window's cap/used counts).
type ExportUsageCycle struct {
	Feature   string `json:"feature"`
	CycleKind string `json:"cycle_kind"`
	WindowKey string `json:"window_key"`
	Cap       int    `json:"cap"`
	Used      int    `json:"used"`
}

// ExportUsageLedgerEntry mirrors an analysis_usage_ledger row — amounts only,
// already content-free (matrix: "yes (summary)").
type ExportUsageLedgerEntry struct {
	Event         string    `json:"event"`
	UserUnits     int       `json:"user_units"`
	InternalUnits int       `json:"internal_units"`
	TokensIn      int64     `json:"tokens_in"`
	TokensOut     int64     `json:"tokens_out"`
	CreatedAt     time.Time `json:"created_at"`
}

// ExportProject is a project pseudonym (matrix: "pseudonym list").
type ExportProject struct {
	CloudProjectID string    `json:"cloud_project_id"`
	CreatedAt      time.Time `json:"created_at"`
}

// ExportSession is a session pseudonym plus its enrichment results and every
// user correction (matrix: cloud_sessions pseudonym + "results + user
// revisions"). Results are newest-first.
type ExportSession struct {
	CloudSessionID string         `json:"cloud_session_id"`
	Tool           string         `json:"tool"`
	ModelFamily    string         `json:"model_family"`
	CreatedAt      time.Time      `json:"created_at"`
	Results        []ExportResult `json:"results"`
}

// ExportResult is one enrichment result: the immutable AI original body plus the
// developer's append-only correction history.
type ExportResult struct {
	ResultID   string    `json:"result_id"`
	CreatedAt  time.Time `json:"created_at"`
	AISource   bool      `json:"ai_source"`
	Superseded bool      `json:"superseded"`
	// Result is the stored (already-normalized) result body. Omitted when the
	// result is tombstoned (defensive — export is a live-account operation, so a
	// tombstoned result should not appear).
	Result    json.RawMessage  `json:"result,omitempty"`
	Revisions []ExportRevision `json:"revisions"`
}

// ExportRevision is one user correction (already-normalized SafeText body).
type ExportRevision struct {
	RevisionSeq int             `json:"revision_seq"`
	Editor      string          `json:"editor"`
	Source      string          `json:"source"`
	Correction  json.RawMessage `json:"correction"`
	CreatedAt   time.Time       `json:"created_at"`
}

// ExportJobSummary is an analysis_jobs metadata summary (matrix: "job metadata
// summary") — feature + terminal state + created time, no route internals.
type ExportJobSummary struct {
	Feature   string    `json:"feature"`
	State     string    `json:"state"`
	CreatedAt time.Time `json:"created_at"`
}

// ExportStructuralDay mirrors a structural_account_days materialization row
// (matrix: "yes (snapshots)") — bounded deterministic aggregates, no content.
type ExportStructuralDay struct {
	Period                   string    `json:"period"`
	DeviceCount              int       `json:"device_count"`
	SessionCount             int       `json:"session_count"`
	ActionCount              int       `json:"action_count"`
	TokensIn                 int64     `json:"tokens_in"`
	TokensOut                int64     `json:"tokens_out"`
	CostUSD                  float64   `json:"cost_usd"`
	VerificationCoverageBand string    `json:"verification_coverage_band"`
	OutcomeEvidenceBand      string    `json:"outcome_evidence_band"`
	ComputedAt               time.Time `json:"computed_at"`
}

// Bytes serializes the export to canonical, human-readable JSON (indented — a
// download the developer reads). The document is fully deterministic given the
// assembled rows, so json.MarshalIndent is the whole serializer; there is no
// digest protocol here (an export is a download, not an idempotency-keyed
// upload).
func (e AccountExport) Bytes() ([]byte, error) {
	return json.MarshalIndent(e, "", "  ")
}
