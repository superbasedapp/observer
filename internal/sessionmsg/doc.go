// Package sessionmsg is the ONE pure derivation shared by the node's
// per-session Messages tab (internal/intelligence/dashboard's
// handleSessionMessages) and the org's per-session message-metrics rollup
// (internal/orgserver/rollup.SessionMessageMetrics). It exists because a
// 2026-09-22 adversarial review (Codex GPT-5.6, "REVIEW-parity.md")
// established that the two engines had independently reimplemented the same
// message-bucketing algorithm — group-key precedence, proxy/JSONL twin
// folding, the Copilot output-only-shadow-row pairing, and the final
// chronological ordering — and had drifted: the org's copy omitted the twin
// fold entirely, used a narrower group key, keyed user rows differently than
// every other action, and paired Copilot shadow rows by SET membership
// (which could discard a legitimate turn) rather than one-to-one.
//
// This package is PURE per CLAUDE.md's module-boundary discipline: no
// database/sql, no net/http, no fsnotify (pinned by imports_test.go).
// Inputs are plain, already-loaded row slices — the caller's own SQL loads
// api_turns / token_usage / actions (SQLite on the node; SQLite-or-
// PostgreSQL on the org) with an explicit ORDER BY on every query, so
// Derive's output is deterministic across engines regardless of physical
// scan order. Capability dispatch (the Copilot-family output-only-shadow
// behavior) is a caller-supplied bool sourced from
// internal/integration.Capability.TokenTier.OutputOnlyShadow — this package
// never branches on a tool name (CLAUDE.md "branch on capabilities, never on
// source identity").
//
// Both the node and the org are THIN ADAPTERS over Derive: each loads its
// own rows with its own SQL, calls Derive, and decorates the returned Rows
// with its own additional display fields (the node's rich per-tool-call
// excerpts/full-text; the org's content-free MessageToolCall). Neither
// engine's SQL determines row identity, grouping, ordering, or shadow-pair
// suppression anymore — Derive does, identically, on both sides.
package sessionmsg
