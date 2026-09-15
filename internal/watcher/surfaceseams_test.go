package watcher

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestSurfaceSeams pins the contract the surface enricher relies on:
// load reports found=false (no error) for a session that does not exist
// yet, found=true with the stored columns once it does, and stamp is the
// store's SetSessionSurface (hosted semantics included).
func TestSurfaceSeams(t *testing.T) {
	w, s, _ := setup(t)
	ctx := context.Background()
	load, stamp := w.SurfaceSeams()

	if sf, found, err := load(ctx, "missing"); err != nil || found || sf.SessionID != "" {
		t.Fatalf("missing session: sf=%+v found=%v err=%v", sf, found, err)
	}

	pid, _ := s.UpsertProject(ctx, "/tmp/seams", "")
	if err := s.UpsertSession(ctx, models.Session{
		ID: "sess-1", ProjectID: pid, Tool: models.ToolClaudeCode,
		StartedAt: time.Date(2026, 9, 3, 10, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatal(err)
	}
	if sf, found, err := load(ctx, "sess-1"); err != nil || !found || sf.Surface != "" {
		t.Fatalf("fresh session: sf=%+v found=%v err=%v", sf, found, err)
	}
	if _, err := stamp(ctx, models.SessionSurface{SessionID: "sess-1", Surface: models.SurfaceSDK, SurfaceHost: "ts"}); err != nil {
		t.Fatal(err)
	}
	changed, err := stamp(ctx, models.SessionSurface{SessionID: "sess-1", Surface: models.SurfaceIDE, SurfaceHost: "jetbrains-idea", Hosted: true})
	if err != nil || !changed {
		t.Fatalf("hosted stamp: changed=%v err=%v", changed, err)
	}
	if sf, found, err := load(ctx, "sess-1"); err != nil || !found || sf.Surface != models.SurfaceIDE || sf.SurfaceHost != "jetbrains-idea" {
		t.Fatalf("after hosted stamp: sf=%+v found=%v err=%v", sf, found, err)
	}
}
