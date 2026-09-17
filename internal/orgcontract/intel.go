package orgcontract

// Org-served Cloud Intelligence — the agent RESULT rail wire contract
// (docs/plans/org-served-cloud-intelligence-plan-2026-09-10.md §1.3, §2.4,
// W3).
//
// These are the ONLY types that cross the wire on GET /api/agent/intel/results:
// a page of per-session enrichment results the ORG server derived (B2 default —
// the server derives evidence from rows the node already pushed, so this rail
// is a request/response PULL, not a second content wire) and a cursor to page
// them. The rail is authenticated like POST /api/agent/judge (the enrolment
// bearer plus a per-request Ed25519 proof), but the proof MESSAGE is this rail's
// OWN domain-separated IntelRailSigningMessage(ts, method, path, canonical
// query, org id) — NOT PushSigningMessage(ts, body) — so a captured judge-relay
// proof can never be replayed here within the skew window (and vice versa). It
// carries no signed document of its own, so — unlike the pricing/budget document
// rails — there is nothing to verify against a key pin. The transport trust is
// the authenticated org connection the node already egresses to. The `limit`
// query parameter is SERVER-BOUND: the canonical query the node signs pins
// limit=0 and the server owns the page size, so a client-supplied ?limit is not
// honored (see internal/orgserver/api/intelrail.go).
//
// A result is model-generated PROSE about a developer's own session. It is
// NEVER on the node→server push wire (that direction is the org-push envelope);
// this is the org's own derived product coming BACK to the node that owns the
// session. On the node it lands in the node-local org_intel_cache table, whose
// name is in the privacy sentinel's forbidden set so orgpush.go can never
// reference it (INV-3).

// IntelResultRow is one per-session enrichment result. It mirrors the
// cloudcontract Result schema (session_enrichment.v2-candidate) minus the
// evidence-ref plumbing the node has no use for, plus the identity fields
// (SessionID / JobID) and the server-side production time the cursor pages on.
//
// The node persists every field except GeneratedAt (its node-local mirror
// stamps its own fetched_at instead); GeneratedAt is the wire's pagination
// axis, read by the node only to advance its `since` cursor.
type IntelResultRow struct {
	// SessionID is the node-owned session this result describes. The server
	// only ever returns rows whose session belongs to the calling node's
	// enrolment identity (scope enforced server-side; INV-1).
	SessionID string `json:"session_id"`
	// JobID identifies the enrichment job that produced this result. Together
	// with SessionID it is the idempotency key both sides dedup on
	// (UNIQUE(session_id, job_id) on the node table).
	JobID string `json:"job_id"`
	// Title is the AI-suggested session title.
	Title string `json:"title,omitempty"`
	// TaxonomyTags is the controlled-vocabulary tag list.
	TaxonomyTags []string `json:"taxonomy_tags,omitempty"`
	// SuggestedTags is the free-form suggested-tag list.
	SuggestedTags []string `json:"suggested_tags,omitempty"`
	// Description is the short AI-generated description.
	Description string `json:"description,omitempty"`
	// Confidence is the result's self-reported confidence (low/medium/high).
	// A plain string on the wire — the node stores whatever the server sends
	// and never re-derives it.
	Confidence string `json:"confidence,omitempty"`
	// Limitations enumerates what the enrichment did not observe.
	Limitations []string `json:"limitations,omitempty"`
	// WorkDone, PlansImplemented, IssuesFound, Failures and NextSteps are the
	// NARRATIVE half of the result (cloudcontract.NarrativeFields): what the
	// session actually did, whether the stated plans landed, what is broken,
	// what failed or is unresolved, and what to do next. They are the prose a
	// developer actually reads, and they are ADDITIVE in both directions — an
	// older server that has not run server migration 156 simply omits them, and
	// an older node that does not know the keys ignores them. evidence_refs are
	// deliberately NOT on this wire: they are the server's own grounding tokens
	// ("a136", "m5", "activity_mix"), checked server-side and never rendered.
	WorkDone []string `json:"work_done,omitempty"`
	// PlansImplemented says which stated asks landed and which were left.
	PlansImplemented []string `json:"plans_implemented,omitempty"`
	// IssuesFound lists bugs or problems the session identified, as a class of
	// problem rather than a quoted failure message.
	IssuesFound []string `json:"issues_found,omitempty"`
	// Failures lists what failed or is unresolved, including outcomes the
	// evidence could not establish (reported as unknown, never as a pass).
	Failures []string `json:"failures,omitempty"`
	// NextSteps lists concrete actions implied by the unfinished work.
	NextSteps []string `json:"next_steps,omitempty"`
	// SchemaVersion is the result schema tag the server produced this row
	// under (cloudcontract.ResultSchemaVersion at derivation time).
	SchemaVersion string `json:"schema_version,omitempty"`
	// GeneratedAt is the server-side production time (RFC3339). It is the
	// human-readable production time; it is deliberately NOT persisted in the
	// node table — the node's own fetched_at records when it pulled the row.
	GeneratedAt string `json:"generated_at,omitempty"`
	// Cursor is the OPAQUE, STABLE pagination token for this row: the
	// (generated_at, result id) pair encoded by the server (finding 4). Paging
	// on GeneratedAt alone lost rows that shared a production SECOND; this
	// tie-breaker makes the page boundary total-ordered. It is additive on the
	// wire — an older node that ignores it still pages by next_cursor, and an
	// older server that never sets it still works because the handler falls back
	// to GeneratedAt. The node treats it as opaque and persists nothing from it.
	Cursor string `json:"cursor,omitempty"`
}

// IntelResultsResponse is the GET /api/agent/intel/results body: a page of
// results plus an opaque continuation cursor. NextCursor is empty when the
// server has no more rows past this page; a non-empty value is fed back
// verbatim as the next request's `since` parameter.
type IntelResultsResponse struct {
	// Results is this page of rows, ordered oldest-first by GeneratedAt so the
	// cursor advances monotonically.
	Results []IntelResultRow `json:"results"`
	// NextCursor is the opaque token for the next page (the GeneratedAt of the
	// last row when a full page was returned), empty when this is the last
	// page. The node stores nothing durable from it — a restart re-pages from
	// the start and the node table's UNIQUE key dedups the re-fetch.
	NextCursor string `json:"next_cursor,omitempty"`
}
