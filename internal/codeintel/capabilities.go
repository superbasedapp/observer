package codeintel

// Language is a source language identifier (lowercase, stable across
// the module — e.g. "go", "python", "typescript", "tsx"). It is the
// key the parser registry and capability table are indexed by. Defined
// here at the facade so every layer shares one spelling; branching in
// logic is on [LanguageCapability] flags, never on the Language value
// itself (CLAUDE.md anti-spaghetti rule 3).
type Language string

// LanguageCapability declares, per language, which extraction passes a
// backend can perform and how trustworthy its spans are. It is the
// "capabilities not source identity" boundary: downstream code (the
// compressor's collapse gate, the resolver's call extraction) branches
// on these flags, not on the language name or the backend identity.
type LanguageCapability struct {
	// Symbols is true when the backend extracts symbol definitions
	// (names + kinds) for this language.
	Symbols bool
	// ExactSpans is true when the backend produces byte/line-accurate
	// symbol spans (start AND end). ADR-0005: only an ExactSpans
	// backend may feed aggressive body-collapse. A heuristic backend
	// reports false and is non-destructive (symbol lists, enrichment,
	// search) only.
	ExactSpans bool
	// Imports is true when the backend extracts import/dependency
	// specifiers for this language.
	Imports bool
	// Calls is true when the backend extracts call sites for
	// name-matched CALLS edges. "Best-effort" languages set this true
	// but may produce a noisier graph (documented in
	// docs/codeintel/languages).
	Calls bool
}

// CanCollapse reports whether a file in this language may be subject to
// aggressive body-collapse: it requires both symbol extraction and an
// exact-span backend (ADR-0005). The compressor consults this at the
// boundary; a false result forces content-preserving mode.
func (c LanguageCapability) CanCollapse() bool {
	return c.Symbols && c.ExactSpans
}

// ExactParser reports whether a parser-backend identity (as stored on
// codeintel_files.parser) produces exact spans. go/ast and any
// tree-sitter backend are exact; the heuristic fallback is not. This is
// the per-file exactness signal the store stamps onto each [Symbol] so
// the aggressive compressor can honour ADR-0005 without re-deriving the
// backend.
func ExactParser(parser string) bool {
	return parser == "goast" || (len(parser) >= 11 && parser[:11] == "treesitter:") || parser == "treesitter"
}

// ParserReplayable reports whether a cold-storage copy produced by the named
// parser backend can still be replayed into the hot index verbatim, or whether
// the project must be re-indexed instead (corpus archival P2.2,
// docs/plans/observer-corpus-archival-lazyload-design-2026-08-26.md §4.2).
//
// A codeintel row encodes the parser that produced it
// (memory:feedback_db_rows_encode_parser_version), so this is the one place
// that knows which of those identities THIS build still produces. It lives
// here, beside ExactParser, rather than in the archival packages: the archive
// mover must not carry a second copy of the code-intelligence backend
// vocabulary that goes stale silently — it takes this as an injected predicate.
//
// The current answer is "every backend we have ever written": goast,
// treesitter:*, and the heuristic fallback are all still produced, so no
// archived copy is stale today. The seam exists so that when a backend IS
// retired, retiring it is one line here rather than an archaeology exercise —
// and a false answer is not a failure, it routes the rehydrate to
// `observer index`, which always works because the source is the repository.
//
// An EMPTY parser is treated as replayable: rows written before the column was
// populated are not evidence of a retired backend.
func ParserReplayable(parser string) bool {
	switch {
	case parser == "":
		return true
	case ExactParser(parser):
		return true
	case parser == "heuristic":
		return true
	default:
		return false
	}
}
