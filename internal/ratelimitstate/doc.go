// Package ratelimitstate is the ONE owner of "did a tool's subscription
// rate-limit state change?" — the pure predicate shared by capture (the
// codex and cowork adapters decide which rate_limit rows to emit) and
// display (internal/sessionmsg decides which folded rate-limit snapshots
// are worth a marker on the Messages table).
//
// Why it exists: Codex 0.130+ repeats its full rate_limits envelope on
// EVERY token_count line, i.e. once per model inference, and the codex
// adapter used to emit one ActionRateLimit row per line. On the live
// corpus (2026-09-30) that was 53,479 rows over 887 sessions, of which
// only ~8,650 carried a different limit reading from the row before (and
// most of the rest differed only by a few seconds of server-side jitter in
// resets_at). Every one of them rendered as a standalone "Rate limit"
// message row between turns.
//
// The package is PURE (no database/sql, net/http, fsnotify — pinned by
// imports_test.go). It dispatches on the JSON SHAPE of a snapshot, never
// on a tool name: Parse recognises the codex token_count envelope
// (limit_id / primary / secondary / plan_type / rate_limit_reached_type)
// and the cowork rate_limit_info envelope (status / resetsAt /
// rateLimitType / overageStatus / isUsingOverage) by their fields.
//
// Decision logic is table-driven (changeRules, emitRules), walked
// top-down, one test case per row.
package ratelimitstate
