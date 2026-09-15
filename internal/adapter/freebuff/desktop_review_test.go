package freebuff

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestDesktopMainDBPath pins the sidecar → main-store mapping.
func TestDesktopMainDBPath(t *testing.T) {
	t.Parallel()
	base := filepath.Join("x", "projects", "p", desktopDBName)
	for _, tc := range []struct{ in, want string }{
		{base, base},
		{base + "-wal", base},
		{base + "-shm", base},
		{filepath.Join("x", "other.db-wal"), filepath.Join("x", "other.db")},
	} {
		if got := desktopMainDBPath(tc.in); got != tc.want {
			t.Errorf("desktopMainDBPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestDesktopSidecarEventParsesMainStore pins the review fix: a `-wal`
// sibling is a session file (fsnotify on it is what keeps a WAL-resident
// capture live) and parsing it yields the SAME rows, keyed on the main
// db's path, as parsing the main store — plus the never-blank-target
// rule for suggest_prompts.
func TestDesktopSidecarEventParsesMainStore(t *testing.T) {
	root, dbPath := desktopFixture(t)
	a := NewWithOptions(nil, root)
	wal := dbPath + "-wal"
	if !a.IsSessionFile(wal) {
		t.Fatalf("IsSessionFile(%q) = false, want true", wal)
	}
	viaMain, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	viaWAL, err := a.ParseSessionFile(context.Background(), wal, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(viaWAL.ToolEvents) != len(viaMain.ToolEvents) || len(viaWAL.TokenEvents) != len(viaMain.TokenEvents) {
		t.Fatalf("wal parse: %d/%d rows, main parse: %d/%d", len(viaWAL.ToolEvents), len(viaWAL.TokenEvents), len(viaMain.ToolEvents), len(viaMain.TokenEvents))
	}
	if viaWAL.NewOffset != viaMain.NewOffset {
		t.Errorf("watermark via wal %d != via main %d", viaWAL.NewOffset, viaMain.NewOffset)
	}
	for i := range viaWAL.ToolEvents {
		if viaWAL.ToolEvents[i].SourceFile != dbPath {
			t.Fatalf("row %d SourceFile = %q, want the main store %q", i, viaWAL.ToolEvents[i].SourceFile, dbPath)
		}
		if viaWAL.ToolEvents[i].SourceEventID != viaMain.ToolEvents[i].SourceEventID {
			t.Fatalf("row %d id %q != %q", i, viaWAL.ToolEvents[i].SourceEventID, viaMain.ToolEvents[i].SourceEventID)
		}
	}
	var sawUnknown bool
	for _, e := range viaMain.ToolEvents {
		if e.ActionType == models.ActionUnknown {
			sawUnknown = true
			if e.Target != e.RawToolName || e.Target == "" {
				t.Errorf("unknown tool %q Target = %q, want the raw tool name", e.RawToolName, e.Target)
			}
		}
	}
	if !sawUnknown {
		t.Error("fixture has no unknown (suggest_prompts) row to check")
	}
}

// TestDesktopStreamingThreadIsDeferred pins the turn_state gate: a thread
// whose turn is still streaming (turn_state != idle) emits nothing this
// parse — its assistant row is rewritten in place until the turn ends,
// which bumps threads.updated_at past the watermark and re-covers it.
func TestDesktopStreamingThreadIsDeferred(t *testing.T) {
	root, dbPath := desktopFixture(t)
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(dbPath))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE threads SET turn_state = 'running'`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	a := NewWithOptions(nil, root)
	res, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.ToolEvents) != 0 || len(res.TokenEvents) != 0 || len(res.SessionSurfaces) != 0 {
		t.Fatalf("streaming thread emitted %d/%d/%d rows, want none", len(res.ToolEvents), len(res.TokenEvents), len(res.SessionSurfaces))
	}

	db, err = sql.Open("sqlite", "file:"+filepath.ToSlash(dbPath))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE threads SET turn_state = 'idle', updated_at = updated_at + 1000`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	again, err := a.ParseSessionFile(context.Background(), dbPath, res.NewOffset)
	if err != nil {
		t.Fatal(err)
	}
	if len(again.ToolEvents) == 0 || len(again.TokenEvents) == 0 {
		t.Fatalf("turn end must re-cover the thread: %d/%d rows", len(again.ToolEvents), len(again.TokenEvents))
	}
}
