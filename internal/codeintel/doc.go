// Package codeintel is Observer's self-contained, CGO-free code-
// intelligence module: Observer owns the parser, schema, store, and
// embedder in-process, so there is no third-party binary download and
// no foreign database read.
//
// # What & why
//
// codeintel extracts symbols (with accurate spans), imports, and a
// name-matched call graph from a project's source tree at index time,
// persists them to node-local SQLite tables, and answers structural +
// semantic queries from the prebuilt index. The proxy hot path never
// parses — it performs store lookups only (ADR-0002). The aggressive
// code compressor consumes the index to collapse function bodies to
// signatures, but only when an exact-span backend produced the span
// (ADR-0005); otherwise it degrades to content-preserving mode.
//
// # Layout
//
// The root package is the facade: it exposes the [Provider] interface
// (the single seam every consumer depends on) plus the plain-data
// types ([Symbol], [SymbolMatch], [Ref]) that cross that seam. The
// pure-logic subpackages — parse, resolve, semantic, analyze, query —
// import no database/sql, net/http, or fsnotify (pinned by
// imports_test.go). I/O lives in index (the orchestrator) and in the
// store seam internal/store/codeintel.go.
//
// # Provider seam
//
// [Provider] is the single seam every consumer depends on; the native
// engine ([NewEngine]) is its sole implementation, answering from
// codeintel's own store. See docs/codeintel/architecture.md and
// docs/codeintel/decisions.md.
package codeintel
