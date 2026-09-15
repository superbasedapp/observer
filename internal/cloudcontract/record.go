package cloudcontract

import "time"

// ResultProvenance records how one enrichment result was produced — the model
// route, the resolved route/prompt versions, the price snapshot, the prompt
// hash, the token counts, the computed cost, and the retry count that yielded
// the accepted output (plan §6 CI-P4). It carries no evidence content, no
// prompt text, and no model response beyond the validated result itself.
type ResultProvenance struct {
	// ModelRouteID is the route registry id the result was produced under.
	ModelRouteID string `json:"model_route_id"`
	// RouteVersion is the resolved route version.
	RouteVersion int64 `json:"route_version"`
	// PromptVersion is the resolved prompt version.
	PromptVersion int64 `json:"prompt_version"`
	// PriceVersion identifies the price snapshot used for CostUSD.
	PriceVersion string `json:"price_version"`
	// PromptHash is a content-free digest of the exact prompt sent (audit only).
	PromptHash string `json:"prompt_hash"`
	// TokensIn is the provider-reported input token count.
	TokensIn int64 `json:"tokens_in"`
	// TokensOut is the provider-reported output token count.
	TokensOut int64 `json:"tokens_out"`
	// CostUSD is the settled provider cost in USD (from the price snapshot).
	CostUSD float64 `json:"cost_usd"`
	// RetryCount is how many prior provider attempts were made before this one
	// produced the accepted output (0 ⇒ first attempt succeeded).
	RetryCount int `json:"retry_count"`
}

// ResultRecord is the results-endpoint WIRE type (plan §6 CI-P4, closing the
// CI-P3 flagged gap): the node client pulls typed records, each carrying the
// cloud_session_id it must associate the result to locally (the CI-P5b reverse
// pseudonym lookup). The server emits []ResultRecord; the node decodes it
// directly (cloudclient.ResultsPage.Results is []ResultRecord).
//
// It is plane-neutral (no personal-only field names) per the §4(f)
// deliberate-divergence ledger entry, so the harness kernel can absorb it.
type ResultRecord struct {
	// CloudSessionID is the node-minted session pseudonym this result belongs
	// to — the key the node uses to associate the result with a local session.
	CloudSessionID string `json:"cloud_session_id"`
	// ResultID is the server-side result id.
	ResultID string `json:"result_id"`
	// Cursor is the LEGACY global monotonic pull cursor (analysis_results.seq).
	// Kept for the dual-read back-compat window (E1 / W6b): a bare-decimal
	// `after` advances on it. It is a stringifiable int on the wire query but is
	// carried here as its numeric value for the client's monotonicity check.
	// Retired one release after AccountCursor is the sole cursor.
	Cursor int64 `json:"cursor"`
	// AccountCursor is the ADDITIVE per-account pull cursor, emitted as the
	// opaque string "v2:<n>" (E1 / W6b). Unlike Cursor it is dense per account
	// and independent of cross-tenant volume, so it leaks nothing about global
	// result volume. The new-default results path advances on it; a node passes
	// the response's next_cursor ("v2:<n>") straight back as `after`.
	AccountCursor string `json:"account_cursor"`
	// SchemaVersion is the result schema (always ResultSchemaVersion this arc).
	SchemaVersion string `json:"schema_version"`
	// AISource marks the result as AI-produced (always true this arc; the node
	// treats it as an editable suggestion, user edits win).
	AISource bool `json:"ai_source"`
	// Superseded is true once a later regeneration replaces this record (W6c /
	// D21): a newer result for the same session set this result's superseded
	// flag. A superseded record is history, not the current head.
	Superseded bool `json:"superseded"`
	// ETag is the strong entity-tag for this result at its current correction
	// sequence (W6c): ResultETag(ResultID, correction_seq). The node passes it as
	// If-Match on PATCH /v1/results/{id}/correction when it syncs a local
	// override up as a revision (R6). Empty on a tombstoned record.
	ETag string `json:"etag,omitempty"`
	// Tombstoned is true when the stored result has been deleted (account
	// deletion overwrote its body with the tombstone marker). A tombstoned
	// record carries an EMPTY Result and MUST NOT be decoded/persisted as an
	// enrichment (FE6): it is a typed deletion marker, not a title-less result.
	Tombstoned bool `json:"tombstoned,omitempty"`
	// CreatedAt is when the server stored the result.
	CreatedAt time.Time `json:"created_at"`
	// ReceivedAt is when the server accepted the producing job's evidence
	// (equal to CreatedAt this arc; a distinct field for a future ingest split).
	ReceivedAt time.Time `json:"received_at"`
	// Result is the validated, normalized, scrubbed enrichment result.
	Result Result `json:"result"`
	// Provenance is how the result was produced.
	Provenance ResultProvenance `json:"provenance"`

	// Kind classifies this result (W5, migration 0037): ResultKindSessionEnrichment
	// or ResultKindProjectDigest. ADDITIVE and omitempty: an empty Kind means
	// ResultKindSessionEnrichment (every result this arc predates carried no
	// other kind), so an old node decoding a session-enrichment record is
	// unaffected.
	Kind string `json:"kind,omitempty"`
	// CloudProjectID is set only on a ResultKindProjectDigest record — the
	// project pseudonym the digest covers. Empty on a session-enrichment
	// record.
	CloudProjectID string `json:"cloud_project_id,omitempty"`
	// PeriodStart / PeriodEnd bound a project digest's ISO week ("YYYY-MM-DD").
	// Empty on a session-enrichment record.
	PeriodStart string `json:"period_start,omitempty"`
	PeriodEnd   string `json:"period_end,omitempty"`
	// DigestResult carries the project-digest body for a
	// ResultKindProjectDigest record; nil for a session-enrichment record.
	// ADDITIVE beyond Kind/CloudProjectID/PeriodStart/PeriodEnd: a digest's
	// shape (headline/themes/cost_trend/...) does not overlap Result's
	// (title/tags/description/...) beyond schema_version and confidence, so
	// forcing it through the Result field would silently drop every digest
	// field rather than merely being unused. omitempty keeps an old node's
	// decode of a session-enrichment record byte-identical to before.
	DigestResult *DigestResult `json:"digest_result,omitempty"`
}
