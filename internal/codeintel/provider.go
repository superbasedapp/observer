package codeintel

import (
	"context"

	"github.com/marmutapp/superbased-observer/internal/archive"
)

// Provider is the single seam every codeintel consumer depends on. The
// MCP retrieval tools, the compression pipeline, and the CLI/dashboard
// surfaces all hold a Provider; none import a concrete engine.
//
// The native engine ([NewEngine]) is the sole implementation: it answers
// from codeintel's own store (codeintel_files / codeintel_nodes / …).
// [Unavailable] returns an empty engine for tests and pre-index wiring.
// (Historically a strangler-fig wrapper over the external codegraph
// client was the first implementation; it was deleted in Phase 4 once
// the native engine became the default — see
// docs/codeintel/migration-from-codegraph.md.)
//
// The interface starts at exactly the surface today's consumers use and
// grows additively (Search / Architecture / Query land in their
// phases). Every method MUST fail open: an unavailable provider,
// missing schema, or query error returns an empty result and a nil
// error so callers degrade gracefully rather than aborting. All methods
// MUST be safe for concurrent use.
type Provider interface {
	// Available reports whether the backing index is open and
	// reachable. Callers gate enrichment on this to avoid wasted work.
	Available() bool
	// Path returns the configured backing-store path, even when
	// Available is false — useful for "we looked here" diagnostics.
	Path() string
	// Stale reports whether absPath's mtime is meaningfully newer than
	// the index's last pass. Callers SKIP enrichment when true: stale
	// spans mislead the agent (and must never feed body-collapse).
	Stale(absPath string) bool

	// SymbolsInFile returns the user-facing symbols defined in absPath
	// (functions, methods, classes, interfaces, types), sorted by
	// start line for byte-stable output.
	SymbolsInFile(ctx context.Context, absPath string) ([]Symbol, error)
	// FunctionsInFile returns the function names defined in absPath.
	FunctionsInFile(ctx context.Context, absPath string) ([]string, error)
	// ImportsInFile returns the import/dependency specifiers referenced
	// from absPath.
	ImportsInFile(ctx context.Context, absPath string) ([]string, error)

	// FindSymbols returns matches in absFile filtered by the optional
	// (name, fqn, kind) selectors. Empty selectors widen the query;
	// all three empty is discovery mode (every user-facing symbol).
	FindSymbols(ctx context.Context, absFile, name, fqn, kind string) ([]SymbolMatch, error)

	// CallersOf returns the names of symbols that call functionName
	// (legacy names-only traversal).
	CallersOf(ctx context.Context, functionName string) ([]string, error)
	// CallersOfSymbol returns symbols that call symbolID via CALLS
	// edges, with metadata, capped at limit.
	CallersOfSymbol(ctx context.Context, symbolID int64, limit int) ([]Ref, error)
	// CalleesOfSymbol returns symbols that symbolID calls, capped at
	// limit.
	CalleesOfSymbol(ctx context.Context, symbolID int64, limit int) ([]Ref, error)
	// CountCallers returns the unlimited count of symbols calling
	// symbolID.
	CountCallers(ctx context.Context, symbolID int64) (int, error)
	// CountCallees returns the unlimited count of symbols called by
	// symbolID.
	CountCallees(ctx context.Context, symbolID int64) (int, error)
	// CountEdgesByKind returns the total number of edges of the given
	// kind across the graph — used to distinguish "genuinely zero
	// relations" from "this edge kind isn't populated".
	CountEdgesByKind(ctx context.Context, kind string) (int, error)

	// Reachable returns symbols reachable from anchorID via the chosen
	// relation, up to maxDepth hops, capped at maxResults. The bool
	// reports whether the cap truncated the result.
	Reachable(ctx context.Context, anchorID int64, dir RelationDirection, maxDepth, maxResults int) ([]Ref, bool, error)

	// Search runs a full-text symbol search (Tier C), scoped to project
	// (empty = all projects), ranked by relevance, capped at limit.
	Search(ctx context.Context, project, query string, limit int) ([]SymbolMatch, error)
	// SemanticNeighbors returns symbols most semantically related to
	// nodeID (embedding cosine), capped at limit.
	SemanticNeighbors(ctx context.Context, nodeID int64, limit int) ([]SymbolMatch, error)
	// SimilarTo returns near-clone candidates for nodeID (MinHash/LSH),
	// capped at limit.
	SimilarTo(ctx context.Context, nodeID int64, limit int) ([]SymbolMatch, error)
	// ListProjects returns the distinct indexed projects.
	ListProjects(ctx context.Context) ([]string, error)
	// LoadGraph returns a project's node+resolved-edge snapshot — the
	// in-memory input the pure analyze/ and query/ engines run over. The
	// engine itself stays free of those packages (no import cycle); the
	// surface layer orchestrates them over this.
	LoadGraph(ctx context.Context, project string) (Graph, error)

	// ArchivedProject reports whether a project's index has been moved to
	// cold storage, and the marker describing it
	// (docs/plans/observer-corpus-archival-lazyload-design-2026-08-26.md
	// §4.2). Every other method on this interface answers an archived
	// project exactly like a never-indexed one — empty — and the two need
	// completely different responses from a caller. This is the ONE cheap
	// hot-database lookup that tells them apart; the archive file is never
	// opened. Fails open: an error or an unavailable provider reports
	// "not archived", so an archival fault degrades to today's behaviour
	// rather than to a wrong claim.
	ArchivedProject(ctx context.Context, project string) (archive.Marker, bool, error)

	// Close releases the backing handle. Safe to call on an
	// unavailable provider.
	Close() error
}
