package watcher

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/adapter"
)

// discardLogger silences watcher logs for tests that assert on
// bookkeeping rather than output.
func discardLogger() Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// countingRootsAdapter records how many times WatchPaths was asked for
// its roots and lets a test swap the slice mid-flight (an adapter whose
// sessions directory only appears after the tool is first used).
type countingRootsAdapter struct {
	mu    sync.Mutex
	roots []string
	calls int
}

func (a *countingRootsAdapter) Name() string { return "counting-roots" }

func (a *countingRootsAdapter) WatchPaths() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls++
	return append([]string(nil), a.roots...)
}

func (a *countingRootsAdapter) setRoots(roots ...string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.roots = roots
}

func (a *countingRootsAdapter) watchPathsCalls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls
}

func (a *countingRootsAdapter) IsSessionFile(path string) bool {
	a.mu.Lock()
	roots := append([]string(nil), a.roots...)
	a.mu.Unlock()
	return filepath.Ext(path) == ".jsonl" && adapter.UnderAnyWatchRoot(path, roots)
}

func (a *countingRootsAdapter) ParseSessionFile(context.Context, string, int64) (adapter.ParseResult, error) {
	return adapter.ParseResult{}, nil
}

// TestWatchRootsMemoizesIdentityDedup pins that the identity fold
// (adapter.DedupRootsByIdentity — Stat + EvalSymlinks + SameFile per
// root) runs ONCE per distinct raw WatchPaths slice, no matter how many
// times the watcher asks for an adapter's roots.
//
// This is the poller hot path: pollCursors calls adapterFor for every
// grown cursor row, and adapterFor rebuilds the whole root→adapter map,
// so an unmemoized fold turned steady-state polling into
// O(rows × adapters × roots) filesystem syscalls.
func TestWatchRootsMemoizesIdentityDedup(t *testing.T) {
	t.Parallel()
	rootA := t.TempDir()
	a := &countingRootsAdapter{roots: []string{rootA, rootA + string(filepath.Separator)}}

	reg := adapter.NewRegistry()
	reg.Register(a)
	w := New(nil, reg, Options{Logger: discardLogger()})

	var folds int
	w.dedupRoots = func(roots []string) []string {
		folds++
		return adapter.DedupRootsByIdentity(roots)
	}

	for i := 0; i < 25; i++ {
		got := w.watchRoots(a)
		if len(got) != 1 || got[0] != rootA {
			t.Fatalf("iteration %d: watchRoots = %v, want [%q]", i, got, rootA)
		}
	}
	if folds != 1 {
		t.Errorf("DedupRootsByIdentity ran %d times over 25 calls, want 1 (memoized)", folds)
	}
	// WatchPaths itself is still consulted every call — it is the only
	// honest way to notice a root set that has changed.
	if got := a.watchPathsCalls(); got != 25 {
		t.Errorf("WatchPaths called %d times, want 25", got)
	}

	// Invalidation: an adapter whose raw roots change (a tool installed
	// mid-daemon) must re-fold rather than serve the stale set.
	rootB := t.TempDir()
	a.setRoots(rootA, rootB)
	for i := 0; i < 5; i++ {
		got := w.watchRoots(a)
		if len(got) != 2 || got[0] != rootA || got[1] != rootB {
			t.Fatalf("after root change, iteration %d: watchRoots = %v, want [%q %q]", i, got, rootA, rootB)
		}
	}
	if folds != 2 {
		t.Errorf("folds = %d after a changed root slice, want 2 (one re-fold, then memoized again)", folds)
	}

	// Reverting to the original slice re-folds once more (the cache
	// holds one entry per adapter, keyed on the CURRENT fingerprint —
	// it is a memo, not a history).
	a.setRoots(rootA, rootA+string(filepath.Separator))
	_ = w.watchRoots(a)
	_ = w.watchRoots(a)
	if folds != 3 {
		t.Errorf("folds = %d after reverting the root slice, want 3", folds)
	}
}

// TestAdapterForReusesMemoizedRoots pins the consequence at the call
// site the finding named: repeated adapterFor dispatch (one per grown
// cursor row) folds roots exactly once.
func TestAdapterForReusesMemoizedRoots(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	a := &countingRootsAdapter{roots: []string{root, root + string(filepath.Separator)}}
	reg := adapter.NewRegistry()
	reg.Register(a)
	w := New(nil, reg, Options{Logger: discardLogger()})

	var folds int
	w.dedupRoots = func(roots []string) []string {
		folds++
		return adapter.DedupRootsByIdentity(roots)
	}

	probe := filepath.Join(root, "session.jsonl")
	for i := 0; i < 10; i++ {
		if got := w.adapterFor(probe); got == nil || got.Name() != "counting-roots" {
			t.Fatalf("iteration %d: adapterFor = %v, want the counting adapter", i, got)
		}
	}
	if folds != 1 {
		t.Errorf("adapterFor folded roots %d times over 10 dispatches, want 1", folds)
	}
}
