package cowork

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestParseSessionFile_SurfaceAttribution pins Part E (IDE-15 provenance
// half): every parsed cowork audit.jsonl is unconditionally stamped
// desktop/claude-desktop — Cowork's audit.jsonl format is written by no
// other host. See docs/claude-cowork.md "Surface attribution".
func TestParseSessionFile_SurfaceAttribution(t *testing.T) {
	t.Parallel()
	root := fixturePath(t, "")
	auditPath := fixturePath(t, "cowork-aaaa/dev-bbbb/local_cccc-dddd-eeee/audit.jsonl")
	a := NewWithOptions(nil, root)

	res, err := a.ParseSessionFile(context.Background(), auditPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.SessionSurfaces) != 1 {
		t.Fatalf("session surfaces: got %d want 1", len(res.SessionSurfaces))
	}
	got := res.SessionSurfaces[0]
	const wantSessionID = "local_cccc-dddd-eeee"
	if got.SessionID != wantSessionID || got.Surface != models.SurfaceDesktop || got.SurfaceHost != "claude-desktop" {
		t.Errorf("surface = %+v; want {%s %s claude-desktop}", got, wantSessionID, models.SurfaceDesktop)
	}
}

// TestParseSessionFile_SurfaceAttributionEveryChunk pins that a
// resumed (fromOffset > 0) parse re-stamps the same surface value —
// harmless per the SessionSurface first-wins-unless-empty store write,
// and simpler than gating on a "first chunk only" flag Cowork has no
// other use for.
func TestParseSessionFile_SurfaceAttributionEveryChunk(t *testing.T) {
	t.Parallel()
	root := fixturePath(t, "")
	auditPath := fixturePath(t, "cowork-aaaa/dev-bbbb/local_cccc-dddd-eeee/audit.jsonl")
	a := NewWithOptions(nil, root)

	first, err := a.ParseSessionFile(context.Background(), auditPath, 0)
	if err != nil {
		t.Fatalf("first ParseSessionFile: %v", err)
	}
	if len(first.SessionSurfaces) != 1 {
		t.Fatalf("first chunk session surfaces: got %d want 1", len(first.SessionSurfaces))
	}

	second, err := a.ParseSessionFile(context.Background(), auditPath, first.NewOffset)
	if err != nil {
		t.Fatalf("resumed ParseSessionFile: %v", err)
	}
	if len(second.SessionSurfaces) != 1 {
		t.Fatalf("resumed chunk session surfaces: got %d want 1 (re-stamp is harmless)", len(second.SessionSurfaces))
	}
	if second.SessionSurfaces[0] != first.SessionSurfaces[0] {
		t.Errorf("resumed surface = %+v differs from first-chunk surface = %+v", second.SessionSurfaces[0], first.SessionSurfaces[0])
	}
}

// TestParseSessionFile_SurfaceAttributionSkippedForUnrecognizedPath
// pins the honesty rule: a path that doesn't follow the
// local_<uuid>/audit.jsonl layout yields no session id
// (instanceSessionID returns "") and ParseSessionFile must not stamp
// a surface it can't attribute to a session.
func TestParseSessionFile_SurfaceAttributionSkippedForUnrecognizedPath(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// No local_<uuid> parent directory, and loadSidecar will find
	// nothing — ParseSessionFile still runs (missing sidecar is
	// best-effort), but instanceSessionID("") means no attribution.
	path := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	a := NewWithOptions(nil, dir)
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.SessionSurfaces) != 0 {
		t.Errorf("session surfaces = %+v; want none for an unrecognized path with no session id", res.SessionSurfaces)
	}
}
