package codeintel

import (
	"context"
	"os"
	"sync/atomic"
	"time"

	"github.com/marmutapp/superbased-observer/internal/archive"
)

// engine is the NATIVE [Provider] implementation: it answers from
// codeintel's own store (codeintel_files / codeintel_nodes / …) instead
// of the external codegraph DB. It is the strangler-fig target — the
// codegraph wrapper is validated against it and then deleted.
//
// Phase 1 surfaces symbols, spans, find, and staleness from
// files+nodes. Edge-traversal methods (callers/callees/reachable),
// imports, and edge counts return empty until the edge tables land
// (Phase 3); every method fails open per the [Provider] contract.
type engine struct {
	store EngineStore
	// availCached latches true once the index has any indexed file —
	// Available() is polled per compression block, so once it's true we
	// skip the COUNT query. It only ever goes false→true during a
	// daemon's life (the index grows), so caching the positive is safe.
	availCached atomic.Bool
}

// NewEngine builds the native provider over a store read surface.
func NewEngine(store EngineStore) Provider {
	return &engine{store: store}
}

// Unavailable returns a [Provider] that reports Available()==false and
// answers every query empty. It is the empty native engine (nil store):
// useful for tests and for wiring before an index exists. Every method
// fails open per the [Provider] contract.
func Unavailable() Provider {
	return &engine{}
}

// engineStaleSlack mirrors the codegraph wrapper's tolerance: file-
// system mtime jitter + index latency shouldn't flap Stale().
const engineStaleSlack = 5 * time.Second

func (e *engine) Available() bool {
	if e == nil || e.store == nil {
		return false
	}
	if e.availCached.Load() {
		return true
	}
	ok, err := e.store.CodeIntelHasIndex(context.Background())
	if err == nil && ok {
		e.availCached.Store(true)
	}
	return err == nil && ok
}

// Path has no single value for the native engine (the index spans many
// files); return a stable sentinel for diagnostics.
func (e *engine) Path() string { return "codeintel:native" }

func (e *engine) Stale(absPath string) bool {
	if e == nil || e.store == nil || absPath == "" {
		return false
	}
	indexed, indexedAt, _, err := e.store.CodeIntelFileMeta(context.Background(), absPath)
	if err != nil || !indexed || indexedAt == 0 {
		// Unknown / unindexed: not "stale" (fail open) — callers gate
		// enrichment on Available()/empty results, not on Stale().
		return false
	}
	fi, err := os.Stat(absPath)
	if err != nil {
		return false
	}
	return fi.ModTime().After(time.Unix(indexedAt, 0).Add(engineStaleSlack))
}

func (e *engine) SymbolsInFile(ctx context.Context, absPath string) ([]Symbol, error) {
	if e == nil || e.store == nil {
		return nil, nil
	}
	return e.store.CodeIntelSymbolsInFile(ctx, absPath)
}

func (e *engine) FunctionsInFile(ctx context.Context, absPath string) ([]string, error) {
	if e == nil || e.store == nil {
		return nil, nil
	}
	return e.store.CodeIntelFunctionsInFile(ctx, absPath)
}

func (e *engine) FindSymbols(ctx context.Context, absFile, name, fqn, kind string) ([]SymbolMatch, error) {
	if e == nil || e.store == nil {
		return nil, nil
	}
	return e.store.CodeIntelFindSymbols(ctx, absFile, name, fqn, kind)
}

// --- edge-traversal surfaces (Phase 3) --------------------------------

func (e *engine) ImportsInFile(ctx context.Context, absPath string) ([]string, error) {
	if e == nil || e.store == nil {
		return nil, nil
	}
	return e.store.CodeIntelImportsInFile(ctx, absPath)
}

func (e *engine) CallersOf(ctx context.Context, functionName string) ([]string, error) {
	if e == nil || e.store == nil {
		return nil, nil
	}
	return e.store.CodeIntelCallersOf(ctx, functionName)
}

func (e *engine) CallersOfSymbol(ctx context.Context, symbolID int64, limit int) ([]Ref, error) {
	if e == nil || e.store == nil {
		return nil, nil
	}
	return e.store.CodeIntelCallersOfSymbol(ctx, symbolID, limit)
}

func (e *engine) CalleesOfSymbol(ctx context.Context, symbolID int64, limit int) ([]Ref, error) {
	if e == nil || e.store == nil {
		return nil, nil
	}
	return e.store.CodeIntelCalleesOfSymbol(ctx, symbolID, limit)
}

func (e *engine) CountCallers(ctx context.Context, symbolID int64) (int, error) {
	if e == nil || e.store == nil {
		return 0, nil
	}
	return e.store.CodeIntelCountCallers(ctx, symbolID)
}

func (e *engine) CountCallees(ctx context.Context, symbolID int64) (int, error) {
	if e == nil || e.store == nil {
		return 0, nil
	}
	return e.store.CodeIntelCountCallees(ctx, symbolID)
}

func (e *engine) CountEdgesByKind(ctx context.Context, kind string) (int, error) {
	if e == nil || e.store == nil {
		return 0, nil
	}
	return e.store.CodeIntelCountEdgesByKind(ctx, kind)
}

func (e *engine) Reachable(ctx context.Context, anchorID int64, dir RelationDirection, maxDepth, maxResults int) ([]Ref, bool, error) {
	if e == nil || e.store == nil {
		return nil, false, nil
	}
	return e.store.CodeIntelReachable(ctx, anchorID, dir, maxDepth, maxResults)
}

// --- Tier C surfaces (Phase 6) ---------------------------------------

func (e *engine) Search(ctx context.Context, project, query string, limit int) ([]SymbolMatch, error) {
	if e == nil || e.store == nil {
		return nil, nil
	}
	return e.store.CodeIntelSearch(ctx, project, query, limit)
}

func (e *engine) SemanticNeighbors(ctx context.Context, nodeID int64, limit int) ([]SymbolMatch, error) {
	if e == nil || e.store == nil {
		return nil, nil
	}
	return e.store.CodeIntelSemanticNeighbors(ctx, nodeID, limit)
}

func (e *engine) SimilarTo(ctx context.Context, nodeID int64, limit int) ([]SymbolMatch, error) {
	if e == nil || e.store == nil {
		return nil, nil
	}
	return e.store.CodeIntelSimilarTo(ctx, nodeID, limit)
}

func (e *engine) ListProjects(ctx context.Context) ([]string, error) {
	if e == nil || e.store == nil {
		return nil, nil
	}
	return e.store.CodeIntelListProjects(ctx)
}

func (e *engine) LoadGraph(ctx context.Context, project string) (Graph, error) {
	if e == nil || e.store == nil {
		return Graph{}, nil
	}
	return e.store.CodeIntelLoadGraph(ctx, project)
}

// Close is a no-op: the native engine borrows the store's DB handle and
// does not own it.
// ArchivedProject passes the marker lookup through to the store. Nil-store
// (the [Unavailable] provider) reports "not archived": a provider with no
// index cannot honestly claim a project was archived, and guessing would put
// a false "archived, last indexed <date>" in front of an operator whose
// project was simply never indexed.
func (e *engine) ArchivedProject(ctx context.Context, project string) (archive.Marker, bool, error) {
	if e == nil || e.store == nil || project == "" {
		return archive.Marker{}, false, nil
	}
	return e.store.CodeIntelArchivedProject(ctx, project)
}

func (e *engine) Close() error { return nil }
