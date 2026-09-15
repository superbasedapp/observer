// Package codexpatch decodes the JavaScript wrapper Codex's unified-exec
// tool call uses to pass an apply_patch envelope.
//
// Current Codex builds — and the Open Interpreter rebadge, which reuses
// the same parser — collapse the whole tool surface into a SINGLE
// custom_tool_call named "exec" whose `input` is a small JavaScript
// program that calls the real tool. Patch envelopes are hoisted into a
// string binding and passed by identifier:
//
//	const patch = "*** Begin Patch\n*** Update File: a.go\n@@\n-x\n+y\n*** End Patch";
//	const result = await tools.apply_patch(patch); text(result);
//
// Getting from that program text to the envelope needs a small
// string- and comment-aware JavaScript lexer: a raw regexp over the
// program is not enough, because an apply_patch envelope routinely
// embeds whole source files (including text that looks like another
// binding or another tool call) inside one literal.
//
// # Why this is its own package
//
// The lexer has TWO owners. The Codex adapter
// (internal/adapter/codex/unifiedexec.go) needs it to resolve an action
// row's Target — which file the program actually edited. The
// lines-of-code shape ladder (internal/loc) needs the same decode to
// count added and removed lines out of the 643+ live rows carrying this
// wrapper shape. Copying it would give the decode two owners and let
// them drift, so the generic JS-lexing layer lives here and both
// callers reach it through this one seam. Everything Codex-specific —
// the `tools.` dispatcher namespace, the per-inner-call argument-key
// ladder, the bookkeeping-call precedence rule, the no-tool-call proof —
// stays in the adapter.
//
// This package is PURE (CLAUDE.md §1 / spec §24.1): no database/sql, no
// net/http, no fsnotify, and no dependency on any adapter. It is pinned
// by imports_test.go.
//
// # Honest approximation
//
// Binding resolution is TEXTUAL NEAREST-DOMINATING resolution, not
// scope- or control-flow-aware evaluation. A binding inside a branch, a
// loop or a nested function that does not execute (or executes with a
// different value) is resolved as if it did. A real JavaScript parser is
// out of scope, and the failure mode is bounded: the Codex adapter's
// ACTION TYPE comes from the call itself and is unaffected, only the
// patch-derived Target can be wrong, and the whole program is preserved
// in raw_tool_input as the evidence trail. Zero live programs (819
// apply_patch calls, measured 2026-07-31) contain a conditional or
// repeated binding of the patch identifier.
//
// Nothing here panics: a truncated, unbalanced or hostile program yields
// an honest partial or empty result rather than a guess.
package codexpatch
