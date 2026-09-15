package aigateway

import "time"

// AuditEvent is the metadata-ONLY record written for every gateway request
// (design §2.4.7, operator ruling 2026-08-29). The gateway captures NO
// request/response bodies — the node already captures content and ships it
// under the enterprise collection posture via the existing otel_content rail;
// a second content store here would double storage and create a second
// retention/deletion surface for the same bytes. Content-bearing inspection
// (egress scan, admission) runs in-stream and discards; only verdicts persist.
//
// The struct therefore has NO field that could hold a prompt, a completion, a
// tool argument, or a raw header value. TestAuditEventIsMetadataOnly pins that
// property by field name so a future edit cannot quietly add a body column.
type AuditEvent struct {
	RequestID  string
	OrgID      string
	UserID     string // the org member — internal attribution, not the upstream pseudonym
	KeyID      string
	UpstreamID string
	Model      string
	Kind       ProviderKind

	// Owner is the economic-owner category (design §2.6b) so a developer's
	// coding spend never conflates with the org's own intelligence or judge
	// spend in budgets and rollups.
	Owner EconomicOwner

	// Route and ModeGeneration are the per-turn authority stamps (Sol S5): the
	// gateway is authoritative for org-level token usage, and rollups select by
	// this stamp rather than the org's CURRENT mode — which makes a mixed-mode
	// fleet during a staged flip roll up correctly.
	Route          string // always "gateway" for events this component writes
	ModeGeneration int64

	// Tokens are AUTHORITATIVE (observed from the provider response);
	// EstimatedUSD is priced from RateCardVersion and is an ESTIMATE (Sol S12).
	Usage           Usage
	EstimatedUSD    float64
	RateCardVersion string

	// Verdicts — the admission and in-stream decisions, no content.
	Admitted   bool
	DenyReason string // budget/policy/authn reject code when not admitted; on an
	// ADMITTED request it carries the SOFT-budget breach marker
	// ("budget_soft_breach:<level>/<scope_id>", plan §3.2) — still an id and a
	// code, never content, so the metadata-only pin is unaffected.
	GuardFlagged bool   // a non-critical egress-guard hit
	AbortMarker  string // "", "aborted", "reconciled", "stream_error"
	StatusCode   int

	// Timing + size — bytes counts only, never the bytes themselves.
	StartedAt    time.Time
	DurationMS   int64
	RequestBytes int64
}

// RouteGateway is the authority-stamp value for every event this component
// writes.
const RouteGateway = "gateway"
