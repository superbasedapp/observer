package codeintel

import (
	"context"

	"github.com/marmutapp/superbased-observer/internal/archive"
)

// FileResult is what the indexer hands the store to persist for one
// fully-parsed file: the file's identity + index metadata plus the
// symbols extracted from it. The store replaces the file's prior nodes
// atomically. (Phase 1 carries nodes only; imports/calls join in
// Phase 3 via additional fields + tables.)
type FileResult struct {
	Project     string
	Path        string
	Lang        Language
	Parser      string
	ContentHash string
	MTime       int64 // file mtime, unix seconds
	Nodes       []Node
	// Imports + Calls are the file's relationship inputs (Phase 3).
	// Imports persist directly as IMPORTS edges; Calls persist as CALLS
	// edges whose dst is resolved by name (in-file at save, cross-file by
	// the project resolution sweep). A CallSite's Enclosing indexes into
	// Nodes — the store maps it to the inserted src node id.
	Imports []Import
	Calls   []CallSite
	// BodyBuckets carries the per-node body-shingle MinHash LSH band hashes
	// (W3 near-clone) computed by the indexer from the file content + each
	// node's byte span — BodyBuckets[i] aligns with Nodes[i] (nil when a
	// node has no usable body span). Only these hashes are persisted (into
	// codeintel_minhash); the body bytes never reach the store (privacy).
	BodyBuckets [][]uint64
}

// FileState is the index bookkeeping stored for one already-seen file.
// The indexer uses it to decide whether a file needs re-parsing without
// reading its bytes: MTime + IndexedAt drive the stat-only fast path,
// ContentHash the authoritative comparison when the stat check is
// inconclusive.
type FileState struct {
	ContentHash string
	Status      string
	// MTime is the file mtime (unix seconds) recorded at the last
	// successful index of this file.
	MTime int64
	// IndexedAt is when that index pass ran (unix seconds). It exists so
	// the mtime fast path can reject a "racily clean" row — one indexed in
	// the same wall-clock second it was written, where a later write in
	// that same second would be invisible to a seconds-granularity mtime
	// comparison (git's racily-clean rule).
	IndexedAt int64
}

// EngineStore is the narrow READ surface the native engine depends on —
// dependency inversion so internal/codeintel never imports
// internal/store. *store.Store satisfies it (internal/store/codeintel.go).
// Every method must fail open (empty + nil) so the engine degrades
// gracefully.
type EngineStore interface {
	CodeIntelHasIndex(ctx context.Context) (bool, error)
	CodeIntelFileMeta(ctx context.Context, absPath string) (indexed bool, indexedAt int64, contentHash string, err error)
	CodeIntelSymbolsInFile(ctx context.Context, absPath string) ([]Symbol, error)
	CodeIntelFunctionsInFile(ctx context.Context, absPath string) ([]string, error)
	CodeIntelFindSymbols(ctx context.Context, absFile, name, fqn, kind string) ([]SymbolMatch, error)
	// Edge-traversal surface (Phase 3).
	CodeIntelImportsInFile(ctx context.Context, absPath string) ([]string, error)
	CodeIntelCallersOf(ctx context.Context, functionName string) ([]string, error)
	CodeIntelCallersOfSymbol(ctx context.Context, symbolID int64, limit int) ([]Ref, error)
	CodeIntelCalleesOfSymbol(ctx context.Context, symbolID int64, limit int) ([]Ref, error)
	CodeIntelCountCallers(ctx context.Context, symbolID int64) (int, error)
	CodeIntelCountCallees(ctx context.Context, symbolID int64) (int, error)
	CodeIntelCountEdgesByKind(ctx context.Context, kind string) (int, error)
	CodeIntelReachable(ctx context.Context, anchorID int64, dir RelationDirection, maxDepth, maxResults int) ([]Ref, bool, error)
	// Tier C search/semantic surface (Phase 6).
	CodeIntelSearch(ctx context.Context, project, query string, limit int) ([]SymbolMatch, error)
	CodeIntelSemanticNeighbors(ctx context.Context, nodeID int64, limit int) ([]SymbolMatch, error)
	CodeIntelSimilarTo(ctx context.Context, nodeID int64, limit int) ([]SymbolMatch, error)
	// Graph load surface for analyze/ + query/ (Phase 6) — whole-project
	// node/edge dumps the pure analysis + Cypher engines run over.
	CodeIntelListProjects(ctx context.Context) ([]string, error)
	CodeIntelLoadGraph(ctx context.Context, project string) (Graph, error)
	// Corpus-archival marker read (P2). Adding it here rather than behind a
	// second interface keeps the Provider one seam wide: a consumer asking
	// "is this project archived?" is asking the code-intelligence layer a
	// question about its own index, not reaching into a storage subsystem.
	CodeIntelArchivedProject(ctx context.Context, project string) (archive.Marker, bool, error)
}

// IndexStore is the narrow WRITE/status surface the index orchestrator
// depends on. *store.Store satisfies it.
type IndexStore interface {
	CodeIntelListProjects(ctx context.Context) ([]string, error)
	CodeIntelFileState(ctx context.Context, project, path string) (state FileState, found bool, err error)
	CodeIntelRegisterFile(ctx context.Context, project, path, lang string) error
	CodeIntelSetFileStatus(ctx context.Context, project, path, status string) error
	CodeIntelSaveFile(ctx context.Context, res FileResult) error
	// CodeIntelBuildDerived rebuilds the FTS / embedding / MinHash rows
	// for a project from its current nodes (Phase 6). Idempotent.
	CodeIntelBuildDerived(ctx context.Context, project string) error
	// CodeIntelHasDerived reports whether the project's nodes already have
	// their derived (FTS) rows. It is the cheap guard that lets an index
	// pass which changed nothing skip the full DELETE-then-reinsert
	// rebuild, while still self-healing a project whose derived rows were
	// never built. A project with no nodes has nothing to derive and
	// reports true.
	CodeIntelHasDerived(ctx context.Context, project string) (bool, error)
	CodeIntelDeleteProject(ctx context.Context, project string) error
	CodeIntelProjectStatus(ctx context.Context, project string) (map[string]int, error)
	// CodeIntelResolveCalls is the project-level name-matched CALLS
	// resolution sweep: it fills in dst_id for CALLS edges left
	// unresolved at file-save time (cross-file forward references).
	// Returns the number of edges newly resolved.
	CodeIntelResolveCalls(ctx context.Context, project string) (int, error)
	// CodeIntelResolveScoped is the scoped (import/package-bound) CALLS
	// upgrade pass run after CodeIntelResolveCalls (W2): it upgrades
	// unambiguous bare/qualified edges in place to resolver_backend
	// 'scoped' with higher confidence, fixing cross-package over-link.
	// Returns the number of edges upgraded.
	CodeIntelResolveScoped(ctx context.Context, project string) (int, error)
}
