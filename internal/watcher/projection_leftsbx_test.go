package watcher

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/adapter/claudecode"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// projection_leftsbx_test.go: lane LEFT-SBX milestone 3, the projection's
// poll safety net and the one-shot ingest of an unwatched run.

func projectionFixture(t *testing.T) (context.Context, *store.Store, *Watcher, string, string, []byte) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "w.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	s := store.New(database)
	boxProjects := filepath.Join(t.TempDir(), ".claude", "projects")
	reg := adapter.NewRegistry()
	reg.Register(claudecode.NewWithOptions(nil, boxProjects))
	w := New(s, reg, Options{
		Logger:          slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
		NativePredicate: map[string]func(string) bool{"claude-code": claudecode.IsNativeTool},
		Debounce:        20 * time.Millisecond,
	})
	body, err := os.ReadFile(filepath.Join("..", "..", "testdata", "claudecode", "simple-session.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	return ctx, s, w, boxProjects, filepath.Join(t.TempDir(), "run1.state", "0", "projects"), body
}

// TestProjectionRootGetsThePollSafetyNet: the poll pass (adapterFor, the
// resolver every grown cursor row goes through) resolves a file under a
// live projection root to the projection adapter (the SBX-P3C merge's seam),
// and no longer once the root is gone from the live map. The live map is
// filled the way AddProjectionRoot fills it.
func TestProjectionRootGetsThePollSafetyNet(t *testing.T) {
	_, _, w, box, host, _ := projectionFixture(t)
	pa := &projectionAdapter{Adapter: w.registry.Get("claude-code"), hostRoot: host, boxRoot: box}
	w.liveMu.Lock()
	w.byRoot = map[string]adapter.Adapter{host: pa}
	w.liveMu.Unlock()
	f := filepath.Join(host, "-ws", "s.jsonl")
	if got, ok := w.adapterFor(f).(*projectionAdapter); !ok || got != pa {
		t.Fatalf("the poll pass does not resolve %s to the projection adapter", f)
	}
	w.removeProjectionRoot(host, pa)
	if a := w.adapterFor(f); a != nil {
		t.Fatalf("a removed projection root still resolves: %T", a)
	}
}

// TestIngestProjectionOnce (lane LEFT-SBX, CLI runsc transcripts): with no
// running watcher, the one-shot ingest reads the transcripts a box left in
// its projection through the tool's own adapter, bound to the run, before
// the projection is removed.
func TestIngestProjectionOnce(t *testing.T) {
	ctx, s, w, box, host, body := projectionFixture(t)
	if err := os.MkdirAll(filepath.Join(host, "-ws"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(host, "-ws", "session.jsonl"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	ws := t.TempDir()
	res, err := w.IngestProjectionOnce(ctx, "claude-code", host, box, ProjectionBinding{RunID: "run1", Workspace: ws})
	if err != nil || res.FilesProcessed != 1 {
		t.Fatalf("ingest: %+v %v", res, err)
	}
	if n, _ := s.CountActions(ctx); n != 4 {
		t.Fatalf("actions %d, want 4", n)
	}
	for _, bad := range [][2]string{{"no-such-tool", host}, {"claude-code", "relative"}} {
		if _, err := w.IngestProjectionOnce(ctx, bad[0], bad[1], box, ProjectionBinding{}); err == nil {
			t.Fatalf("%v accepted", bad)
		}
	}
}
