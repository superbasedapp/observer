// Package cacheobs is the shared Tier-2 cache-observation builder
// used by every transcript/SQLite adapter that emits
// models.CacheTurnObservation rows for the internal/cachetrack
// engine (spec §14.3).
//
// Before this package existed, each Tier-2 producer (claudecode,
// opencode, kilo-code CLI, cline-cli) hand-rolled an identical
// per-session accumulator (pending-block delta, a cumulative
// block cap, compaction-reset bookkeeping) plus the identical
// "cachetrack:"+messageID idempotency-key convention and the
// identical three-line §15.3 implicit-cache overlay. cacheobs
// owns that logic (Accumulator, SourceEventID,
// ApplyImplicitCacheOverlay, EmitTurn) and the canonical block forms
// more than one adapter shares:
//
//   - message.go: flattened message-level blocks (a text, a tool call
//     with a string input or args, a tool result's text), with the
//     Accumulator.Observe* helpers that stamp kind and role;
//   - content.go: Anthropic-shape content-array blocks (text,
//     thinking, tool_use, tool_result, image) and ContentBlocks, the
//     ordered array walk.
//
// A canonical form specific to one adapter (claudecode's full content
// block, junie's terminal and file-change blocks, kiro-cli's tool
// blocks, cline-cli's tool_result with the tool name) stays in that
// adapter's own cachetrack.go, because which JSON fields belong in the
// chain is tool-specific. opencode and kilo-code CLI still carry two
// copies of the OpenCode part canonicalizer: the bodies match, but each
// decodes into its own part types and kilo-code's tool part type has an
// extra metadata field, so a malformed part can be dropped by one and
// kept by the other. The canonical bytes feed the engine's chain hash, so
// TestTier2CanonicalBytesGolden pins every adapter's output end to end.
//
// Module boundary (CLAUDE.md "Module Boundaries & Anti-Spaghetti
// Discipline" + spec §24.1): cacheobs is pure logic. It may import
// internal/models (the wire-shape data type) and internal/cachetrack
// (also pure logic — the §15.3 provider-shape table), but never
// database/sql, net/http, or fsnotify. I/O and per-tool parsing
// stay in the adapter package; cacheobs only assembles the
// resulting observation.
package cacheobs
