package watcher

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/adapter/claudecode"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// aliasRootAdapter is a test-only adapter that returns SEVERAL watch
// roots which may all name the same directory — the shape a Windows
// MSIX Claude Desktop install produces for cowork (`%APPDATA%\Claude`
// is a reparse point onto `Packages\Claude_*\LocalCache\Roaming\
// Claude`). Parsing is delegated to the real claude-code adapter so
// the ingest path (actions + cursors) is exercised end to end.
type aliasRootAdapter struct {
	inner *claudecode.Adapter
	roots []string
}

func newAliasRootAdapter(roots ...string) *aliasRootAdapter {
	return &aliasRootAdapter{
		inner: claudecode.NewWithOptions(nil, roots[0]),
		roots: roots,
	}
}

func (a *aliasRootAdapter) Name() string { return a.inner.Name() }

// WatchPaths returns a defensive copy so a caller that dedups in place
// could not silently mutate the adapter's own root list.
func (a *aliasRootAdapter) WatchPaths() []string {
	return append([]string(nil), a.roots...)
}

func (a *aliasRootAdapter) IsSessionFile(path string) bool {
	if filepath.Ext(path) != ".jsonl" {
		return false
	}
	return adapter.UnderAnyWatchRoot(path, a.roots)
}

func (a *aliasRootAdapter) ParseSessionFile(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	return a.inner.ParseSessionFile(ctx, path, fromOffset)
}

// rootDedupSetup builds a watcher over an adapter whose WatchPaths
// returns the supplied roots, seeds ONE claude-code session file into
// seedRoot, and returns the watcher + store.
func rootDedupSetup(t *testing.T, seedRoot string, roots ...string) (*Watcher, *store.Store) {
	t.Helper()
	ctx := context.Background()

	dbPath := filepath.Join(t.TempDir(), "w.db")
	database, err := db.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	s := store.New(database)

	body, err := os.ReadFile(filepath.Join("..", "..", "testdata", "claudecode", "simple-session.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(seedRoot, "session.jsonl"), body, 0o600); err != nil {
		t.Fatal(err)
	}

	reg := adapter.NewRegistry()
	reg.Register(newAliasRootAdapter(roots...))

	w := New(s, reg, Options{
		Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
		NativePredicate: map[string]func(string) bool{
			"claude-code": claudecode.IsNativeTool,
		},
		Debounce: 50 * time.Millisecond,
	})
	return w, s
}

// assertIngestedOnce pins the observable consequence of root-identity
// dedup: the seeded session file is walked exactly once, produces the
// fixture's 4 action rows (not 8), and leaves exactly one
// parse_cursors row (not one per root spelling).
func assertIngestedOnce(t *testing.T, w *Watcher, s *store.Store) {
	t.Helper()
	ctx := context.Background()

	res, err := w.Scan(ctx)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.FilesProcessed != 1 {
		t.Errorf("FilesProcessed=%d want 1 (aliased roots must not walk the tree twice)", res.FilesProcessed)
	}
	if res.Errors != 0 {
		t.Errorf("Scan errors=%d want 0", res.Errors)
	}

	n, err := s.CountActions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Same 4 rows TestScanIngestsFixtureFile pins for a single root.
	if n != 4 {
		t.Errorf("actions=%d want 4 (a doubled root would ingest each row twice under two source_file values)", n)
	}

	cursors, err := s.ListCursors(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(cursors) != 1 {
		paths := make([]string, 0, len(cursors))
		for _, c := range cursors {
			paths = append(paths, c.SourceFile)
		}
		t.Errorf("parse_cursors rows=%d want 1; got %v", len(cursors), paths)
	}
}

// TestScanDedupsAliasedRootSpelling covers the always-runnable half:
// the SAME directory handed to the watcher under three spellings
// (plain, trailing separator, `sub/..` round-trip). Without
// adapter.DedupRootsByIdentity the walk fires three times.
func TestScanDedupsAliasedRootSpelling(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	sep := string(filepath.Separator)
	w, s := rootDedupSetup(t, root,
		root,
		root+sep,
		root+sep+"sub"+sep+"..",
	)
	assertIngestedOnce(t, w, s)
}

// TestScanDedupsSymlinkedRootAlias covers the identity half: two
// spellings that are only equal after EvalSymlinks / os.SameFile —
// the portable stand-in for the Windows MSIX reparse point. Skips
// when the host refuses os.Symlink (Windows without
// SeCreateSymbolicLinkPrivilege).
func TestScanDedupsSymlinkedRootAlias(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	target := filepath.Join(base, "LocalCache", "Roaming", "Claude", "local-agent-mode-sessions")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	alias := filepath.Join(base, "Roaming-Claude")
	if err := os.Symlink(target, alias); err != nil {
		t.Skipf("os.Symlink unsupported on this host (privilege?): %v", err)
	}
	w, s := rootDedupSetup(t, target, target, alias)
	assertIngestedOnce(t, w, s)
}

// TestScanToleratesNonExistentSecondRoot pins that a root which does
// not exist (the common Invariant #48 case — an adapter returns its
// canonical path on a box where the tool is not installed) is retained
// by the dedup, skipped by the walk, and breaks nothing.
func TestScanToleratesNonExistentSecondRoot(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	missing := filepath.Join(t.TempDir(), "not-installed", "sessions")
	w, s := rootDedupSetup(t, root, root, missing)
	assertIngestedOnce(t, w, s)
}

// TestApplyDetectedRootsDedupsAliasedRoots pins the fsnotify
// registration site: three spellings of one directory add exactly ONE
// entry to byRoot. fsw/byRoot are seeded directly (Watch's job) so the
// assertion is deterministic without racing the event loop.
//
// Only aliased spellings here: addRecursive deliberately returns nil
// for a path that does not exist, so a missing canonical root still
// gets a byRoot entry (pre-existing, unrelated behaviour) — the
// missing-root case is covered by TestScanToleratesNonExistentSecondRoot.
func TestApplyDetectedRootsDedupsAliasedRoots(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	sep := string(filepath.Separator)
	w, _ := rootDedupSetup(t, root,
		root,
		root+sep,
		root+sep+"sub"+sep+"..",
	)

	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatalf("fsnotify.NewWatcher: %v", err)
	}
	t.Cleanup(func() { fsw.Close() })

	w.liveMu.Lock()
	w.fsw = fsw
	w.byRoot = map[string]adapter.Adapter{}
	w.liveMu.Unlock()

	added := w.applyDetectedRoots()
	if len(added) != 1 {
		t.Errorf("applyDetectedRoots added %d roots, want 1", len(added))
	}
	live := w.snapshotByRoot()
	if len(live) != 1 {
		t.Errorf("byRoot=%v want exactly 1 entry", live)
	}
	if _, ok := live[root]; !ok {
		t.Errorf("byRoot missing the canonical spelling %q; got %v", root, live)
	}

	// Idempotent: a second apply adds nothing.
	if again := w.applyDetectedRoots(); len(again) != 0 {
		t.Errorf("second applyDetectedRoots added %d roots, want 0", len(again))
	}
}

// TestAdapterForUsesDedupedRoots pins that root→adapter dispatch is
// built off the deduped set — the aliased spellings collapse onto the
// canonical one and a file under it still resolves to the adapter.
func TestAdapterForUsesDedupedRoots(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	sep := string(filepath.Separator)
	w, _ := rootDedupSetup(t, root, root, root+sep)

	got := w.adapterFor(filepath.Join(root, "session.jsonl"))
	if got == nil {
		t.Fatal("adapterFor returned nil for a file under the watch root")
	}
	if got.Name() != "claude-code" {
		t.Fatalf("adapterFor name=%q want claude-code", got.Name())
	}
}
