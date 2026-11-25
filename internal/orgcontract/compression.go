package orgcontract

// CompressionStatRow is the W3.5 compression-savings/eviction wire row: one
// row per (day, mechanism) bucket, mirroring the node dashboard's Compression
// page (web/src/pages/Compression.tsx) and its /api/compression/* read-side
// (internal/intelligence/dashboard/compression_handlers.go::handleCompressionEvents /
// handleCompressionByModel), which both read the node-local compression_events
// table (migration internal/db/migrations/009_compression_events.sql). This is
// the confirmed durable backing store — compression figures are NOT computed
// purely in-memory; every row aggregated here already exists as a persisted
// SQLite row on the node.
//
// Content-free: mechanism name + byte/event counts only. No message text, no
// file path, no tool-call content, no importance score, no body hash — those
// stay node-local (compression_events carries msg_index/importance_score/
// body_hash for the node's own dashboard drill-down; none of that crosses).
//
// HONESTY RULE (see memory feedback_compression_savings_history: a prior
// compression-savings claim was RETRACTED after being measured at +60% cost —
// never ship a projected/marketed savings number, only a measured delta from
// the node's own store). This row enforces that at aggregation time, not by
// convention:
//
//   - For a genuinely compressing mechanism (json/code/logs/text/diff/html/
//     stash/read_cache/tools/rolling_summary/code_collapse/...), compressed_bytes
//     is a REAL retained size, so SavedBytes = OriginalBytes - CompressedBytes
//     is a real, measured byte saving. SavedTokensEst applies the same
//     chars-per-token heuristic (bytes/4) the node's own handleCompressionEvents
//     uses, and is explicitly an ESTIMATE (the field name says so).
//   - For the lossy "drop" mechanism, the message is EVICTED outright —
//     compressed_bytes is 0 by construction and the content is gone, not
//     retained smaller. Pricing that as "savings" would misrepresent lossy
//     eviction as compression savings, the same misleading class as the
//     retracted claim. This row keeps eviction in a SEPARATE field
//     (EvictedBytes) with SavedBytes/SavedTokensEst forced to 0, and marks
//     Lossy=true so the org UI can never conflate the two even if it tries.
//
// The lossy/non-lossy classification mirrors
// internal/intelligence/dashboard/compression_mechanism.go::mechanismIsLossy
// exactly (currently just {"drop": true}). It is DUPLICATED, not imported: the
// dashboard package is an HTTP-layer package and internal/store (the row
// builder for this type) must not import it (CLAUDE.md module-boundary
// discipline — a domain/store package importing an HTTP handler package is a
// smell, and the dependency would also point the wrong direction). See
// internal/store/compressionorgrows.go for the duplicated copy and its
// pointer back to the canonical source.
type CompressionStatRow struct {
	// OrgID / UserEmail are the agent-stamped attribution (same stamping rule
	// as every other wire row — see ingest.go forcePusherOrgID /
	// forcePusherEmail).
	OrgID     string `json:"org_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`
	// Day is the UTC date (YYYY-MM-DD) the compression events occurred on.
	Day string `json:"day"`
	// Mechanism is the compression_events.mechanism value verbatim: one of
	// the per-type compressors ("json"|"code"|"logs"|"text"|"diff"|"html"),
	// a structural mechanism ("stash"|"read_cache"|"tools"|"rolling_summary"|
	// "code_collapse"|"code_collapse_preview"), or the lossy eviction marker
	// ("drop"). Carried verbatim rather than normalized so a new mechanism
	// the node ships shows up on the org side without a schema change.
	Mechanism string `json:"mechanism"`
	// Events is the row count for the (day, mechanism) bucket.
	Events int64 `json:"events"`
	// OriginalBytes / CompressedBytes are the summed before/after sizes for
	// this bucket, straight from compression_events — the node's own
	// ground truth, not re-derived.
	OriginalBytes   int64 `json:"original_bytes"`
	CompressedBytes int64 `json:"compressed_bytes"`
	// SavedBytes is OriginalBytes - CompressedBytes for a genuinely
	// compressing (non-lossy) mechanism; always 0 for a lossy one (see type
	// doc). This is a MEASURED delta from the node's own stored byte counts,
	// never a projection.
	SavedBytes int64 `json:"saved_bytes"`
	// EvictedBytes is OriginalBytes for a lossy mechanism (content dropped
	// outright, nothing retained); always 0 for a non-lossy one. Kept
	// separate from SavedBytes so eviction can never be summed into a
	// "savings" total.
	EvictedBytes int64 `json:"evicted_bytes"`
	// SavedTokensEst is an ESTIMATE (bytes/4 chars-per-token heuristic,
	// matching the node's own handleCompressionEvents) of SavedBytes in
	// tokens; always 0 for a lossy bucket. The field name says "Est" so no
	// downstream consumer mistakes it for a measured token count.
	SavedTokensEst int64 `json:"saved_tokens_est"`
	// Lossy is true when Mechanism is a lossy-eviction mechanism (currently
	// just "drop") — mirrors mechanismIsLossy() so the org UI never has to
	// re-derive the classification from the mechanism string itself.
	Lossy bool `json:"lossy"`
}
