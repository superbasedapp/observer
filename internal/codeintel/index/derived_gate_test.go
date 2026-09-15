package index_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/codeintel"
	"github.com/marmutapp/superbased-observer/internal/codeintel/index"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// countingStore wraps the real store seam and counts the two calls the
// change gate is about, so the tests below assert on WORK ACTUALLY DONE
// rather than on a report flag the gate could set while still doing the
// work. It also lets a test force the "derived rows are missing" state
// without reaching into fts5 internals.
type countingStore struct {
	codeintel.IndexStore
	buildDerived int
	saveFile     int
	// hasDerivedOverride, when non-nil, replaces the real probe.
	hasDerivedOverride func() (bool, error)
}

func (c *countingStore) CodeIntelBuildDerived(ctx context.Context, project string) error {
	c.buildDerived++
	return c.IndexStore.CodeIntelBuildDerived(ctx, project)
}

func (c *countingStore) CodeIntelSaveFile(ctx context.Context, res codeintel.FileResult) error {
	c.saveFile++
	return c.IndexStore.CodeIntelSaveFile(ctx, res)
}

func (c *countingStore) CodeIntelHasDerived(ctx context.Context, project string) (bool, error) {
	if c.hasDerivedOverride != nil {
		return c.hasDerivedOverride()
	}
	return c.IndexStore.CodeIntelHasDerived(ctx, project)
}

func newGateFixture(t *testing.T) (*countingStore, string) {
	t.Helper()
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "obs.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	cs := &countingStore{IndexStore: store.New(database)}

	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a.go"), "package a\n\nfunc Alpha() {}\n")
	writeFile(t, filepath.Join(root, "b.go"), "package a\n\nfunc Beta() { Alpha() }\n")
	return cs, root
}

// rewrite writes new content AND advances the file's mtime past the whole
// second the previous index pass ran in. Tests must not sleep for a
// seconds-granularity timestamp to tick over; stamping it is deterministic
// and instant, and it keeps the change visible to BOTH the stat fast path
// and the content-hash comparison behind it.
func rewrite(t *testing.T, path, content string) {
	t.Helper()
	writeFile(t, path, content)
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatalf("chtimes %s: %v", path, err)
	}
}

// TestDerivedRebuildGate pins the rule that keeps `observer start` from
// re-running the whole-project FTS/embedding rebuild on every boot for
// every known project: the rebuild runs when a file changed, or when the
// derived rows are missing, and ONLY then.
//
// Mutation proof: delete the gate in IndexProject/maybeBuildDerived and
// the "second pass, nothing changed" row fails on buildDerived == 1.
func TestDerivedRebuildGate(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name string
		// mutate runs between the first and second index pass.
		mutate func(t *testing.T, cs *countingStore, root string)
		// wantSecondPassBuilds is the number of CodeIntelBuildDerived
		// calls the SECOND pass may make.
		wantSecondPassBuilds int
		wantSkipped          bool
		wantIndexed          int
	}{
		{
			name:                 "nothing changed skips the rebuild",
			mutate:               func(*testing.T, *countingStore, string) {},
			wantSecondPassBuilds: 0,
			wantSkipped:          true,
			wantIndexed:          0,
		},
		{
			name: "a changed file rebuilds",
			mutate: func(t *testing.T, _ *countingStore, root string) {
				rewrite(t, filepath.Join(root, "a.go"), "package a\n\nfunc Alpha() {}\n\nfunc Gamma() {}\n")
			},
			wantSecondPassBuilds: 1,
			wantSkipped:          false,
			wantIndexed:          1,
		},
		{
			name: "a new file rebuilds",
			mutate: func(t *testing.T, _ *countingStore, root string) {
				rewrite(t, filepath.Join(root, "c.go"), "package a\n\nfunc Delta() {}\n")
			},
			wantSecondPassBuilds: 1,
			wantSkipped:          false,
			wantIndexed:          1,
		},
		{
			name: "interrupted build (nodes present, derived missing) rebuilds despite zero changes",
			mutate: func(_ *testing.T, cs *countingStore, _ string) {
				cs.hasDerivedOverride = func() (bool, error) { return false, nil }
			},
			wantSecondPassBuilds: 1,
			wantSkipped:          false,
			wantIndexed:          0,
		},
		{
			name: "a failing probe rebuilds rather than skipping",
			mutate: func(_ *testing.T, cs *countingStore, _ string) {
				cs.hasDerivedOverride = func() (bool, error) { return false, context.DeadlineExceeded }
			},
			wantSecondPassBuilds: 1,
			wantSkipped:          false,
			wantIndexed:          0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cs, root := newGateFixture(t)
			ix := index.New(index.Options{Store: cs, Registry: index.DefaultRegistry()})

			// First-ever index: always builds.
			first, err := ix.IndexProject(ctx, root, true)
			if err != nil {
				t.Fatalf("first IndexProject: %v", err)
			}
			if first.Indexed != 2 {
				t.Fatalf("first pass indexed = %d, want 2", first.Indexed)
			}
			if !first.DerivedBuilt || first.DerivedSkipped {
				t.Fatalf("first pass must build derived rows: built=%v skipped=%v",
					first.DerivedBuilt, first.DerivedSkipped)
			}
			if cs.buildDerived != 1 {
				t.Fatalf("first pass BuildDerived calls = %d, want 1", cs.buildDerived)
			}

			tc.mutate(t, cs, root)

			before := cs.buildDerived
			second, err := ix.IndexProject(ctx, root, true)
			if err != nil {
				t.Fatalf("second IndexProject: %v", err)
			}
			if got := cs.buildDerived - before; got != tc.wantSecondPassBuilds {
				t.Errorf("second pass BuildDerived calls = %d, want %d", got, tc.wantSecondPassBuilds)
			}
			if second.DerivedSkipped != tc.wantSkipped {
				t.Errorf("second pass DerivedSkipped = %v, want %v", second.DerivedSkipped, tc.wantSkipped)
			}
			if second.DerivedBuilt == tc.wantSkipped {
				t.Errorf("DerivedBuilt (%v) and DerivedSkipped (%v) must be opposites",
					second.DerivedBuilt, second.DerivedSkipped)
			}
			if second.Indexed != tc.wantIndexed {
				t.Errorf("second pass indexed = %d, want %d", second.Indexed, tc.wantIndexed)
			}
		})
	}
}

// TestDerivedGateKeepsSearchCorrect proves the skip is not a correctness
// regression: after a no-change pass that skipped the rebuild, search
// still answers, and after a change it reflects the new symbol.
func TestDerivedGateKeepsSearchCorrect(t *testing.T) {
	ctx := context.Background()
	cs, root := newGateFixture(t)
	ix := index.New(index.Options{Store: cs, Registry: index.DefaultRegistry()})

	if _, err := ix.IndexProject(ctx, root, true); err != nil {
		t.Fatalf("first IndexProject: %v", err)
	}
	eng := codeintel.NewEngine(cs.IndexStore.(*store.Store))

	if _, err := ix.IndexProject(ctx, root, true); err != nil {
		t.Fatalf("second IndexProject: %v", err)
	}
	ms, err := eng.Search(ctx, root, "Alpha", 10)
	if err != nil || len(ms) == 0 {
		t.Fatalf("search after a skipped rebuild found nothing: %v, %v", ms, err)
	}

	rewrite(t, filepath.Join(root, "a.go"), "package a\n\nfunc Alpha() {}\n\nfunc Epsilon() {}\n")
	if _, err := ix.IndexProject(ctx, root, true); err != nil {
		t.Fatalf("third IndexProject: %v", err)
	}
	ms, err = eng.Search(ctx, root, "Epsilon", 10)
	if err != nil || len(ms) == 0 {
		t.Fatalf("search after a rebuild missed the new symbol: %v, %v", ms, err)
	}
}

// TestStatFastPathSkipsReads pins the second half of the fix: an
// unchanged file is resolved from its stored mtime, without opening or
// hashing it. Without the fast path every boot SHA-256s the whole estate.
func TestStatFastPathSkipsReads(t *testing.T) {
	ctx := context.Background()
	cs, root := newGateFixture(t)
	ix := index.New(index.Options{Store: cs, Registry: index.DefaultRegistry()})

	// Age the files so the racily-clean guard (mtime < indexed_at) can pass.
	old := time.Now().Add(-1 * time.Hour)
	for _, name := range []string{"a.go", "b.go"} {
		if err := os.Chtimes(filepath.Join(root, name), old, old); err != nil {
			t.Fatalf("chtimes: %v", err)
		}
	}
	if _, err := ix.IndexProject(ctx, root, true); err != nil {
		t.Fatalf("first IndexProject: %v", err)
	}

	rep, err := ix.IndexProject(ctx, root, true)
	if err != nil {
		t.Fatalf("second IndexProject: %v", err)
	}
	if rep.Unchanged != 2 {
		t.Fatalf("second pass unchanged = %d, want 2", rep.Unchanged)
	}
	if rep.StatFresh != 2 {
		t.Errorf("second pass stat-fresh = %d, want 2 (files were re-read and re-hashed)", rep.StatFresh)
	}
	if cs.saveFile != 2 {
		t.Errorf("SaveFile calls = %d, want 2 (only the first pass may write)", cs.saveFile)
	}

	// A rewrite with a NEW mtime must still be seen.
	rewrite(t, filepath.Join(root, "a.go"), "package a\n\nfunc Alpha() {}\n\nfunc Zeta() {}\n")
	rep, err = ix.IndexProject(ctx, root, true)
	if err != nil {
		t.Fatalf("third IndexProject: %v", err)
	}
	if rep.Indexed != 1 {
		t.Errorf("third pass indexed = %d, want 1 (the rewritten file)", rep.Indexed)
	}
}

// TestStatFastPathRejectsRaciallyCleanRow pins the git racily-clean rule:
// a row whose recorded mtime is NOT strictly older than the index pass
// must fall through to the content hash, because a second write inside
// that same whole second would otherwise be invisible.
func TestStatFastPathRejectsRaciallyCleanRow(t *testing.T) {
	ctx := context.Background()
	cs, root := newGateFixture(t)
	ix := index.New(index.Options{Store: cs, Registry: index.DefaultRegistry()})

	// Files written moments ago: mtime == indexed_at (same second), so the
	// fast path must refuse them.
	if _, err := ix.IndexProject(ctx, root, true); err != nil {
		t.Fatalf("first IndexProject: %v", err)
	}
	now := time.Now()
	for _, name := range []string{"a.go", "b.go"} {
		if err := os.Chtimes(filepath.Join(root, name), now, now); err != nil {
			t.Fatalf("chtimes: %v", err)
		}
	}
	rep, err := ix.IndexProject(ctx, root, true)
	if err != nil {
		t.Fatalf("second IndexProject: %v", err)
	}
	if rep.StatFresh != 0 {
		t.Errorf("stat-fresh = %d, want 0 — a same-second row must be re-hashed, not trusted", rep.StatFresh)
	}
	if rep.Unchanged != 2 {
		t.Errorf("unchanged = %d, want 2 (hash comparison still resolves them)", rep.Unchanged)
	}
}
