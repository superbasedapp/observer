// Package enrichbudget holds the pure decisions of the enrichment data budget
// (managed-SaaS ruling R-AI1, approved 2026-11-13): there is no cap on the
// NUMBER of sessions an account enriches; instead every account has a token
// budget per UTC day and per UTC month, every session a CUMULATIVE token
// budget across its re-enrichments, and every tier an evidence budget (how
// much of one session is sent). The concurrency cap and the budget pool's
// USD spend ceiling stay as they were.
//
// The numbers are platform configuration, not code: an enrichment TIER (the
// store's enrichment_tiers table, cloud migration 0078) maps a tier name to
// a route id, an evidence budget and the three token budgets, and a plan
// names its tier. A tier only SELECTS among routes; it never carries an
// endpoint URL or a credential, and CheckRoute refuses any route that is not
// bound, priced and attested (binding a route stays the operator's
// `observer-cloud route bind-*` act).
//
// The package is pure: no database/sql, pgx, net/http or fsnotify
// (imports_test.go pins it). The store reads its rows under its own locks,
// hands the values here, and writes back what the returned decision says;
// the arithmetic of every hold and settle is the shared reserve core's
// (internal/reserve), which already speaks token units.
//
// Formulas (all integers):
//
//	evidence estimate  = ceil(bytes x 323 / 1000)          (cloudcontract, shared with the node)
//	worst-case hold    = ceil(bytes x 500 / 1000) + PromptOverheadTokens + route max_output_tokens
//	settled actual     = provider prompt_tokens + completion_tokens   (a missing meter books the hold)
//
// A hold is admitted only when it fits under every cap in scope: committed +
// hold <= cap for the daily, monthly and per-session token budgets, and one
// more in-flight job under the concurrency cap.
package enrichbudget
