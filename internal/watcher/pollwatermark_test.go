package watcher

import (
	"bytes"
	"context"
	"database/sql"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/adapter/goose"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// pollLogBuffer collects the watcher log (the poll pass is synchronous here).
type pollLogBuffer struct{ bytes.Buffer }

func (b *pollLogBuffer) count(msg string) int { return strings.Count(b.String(), msg) }

// TestPollCursorsWatermarkStoreLogsOnlyOnProgress reproduces live finding
// D7 (2026-09-28, node-3) with the REAL goose adapter: goose's sessions.db
// is scanned by a messages.id watermark, so its parse_cursors row holds a
// row id (41 there) while the file is thousands of bytes. `size != cursor`
// therefore held on every 2 s poll tick, the re-parse found nothing new, and
// the watcher logged "caught up dropped writes" with a constant behind_bytes
// forever (7,344 lines in about an hour). The poll must log only when the
// cursor actually advanced - and must still catch a real out-of-band write.
func TestPollCursorsWatermarkStoreLogsOnlyOnProgress(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "sessions")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	storePath := filepath.Join(root, "sessions.db")
	src, err := sql.Open("sqlite", storePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { src.Close() })
	if _, err := src.Exec(`CREATE TABLE messages (id INTEGER PRIMARY KEY, session_id TEXT, message_id TEXT,
		role TEXT, content_json TEXT, created_timestamp INTEGER)`); err != nil {
		t.Fatal(err)
	}
	insert := func(n int) {
		t.Helper()
		for i := 0; i < n; i++ {
			if _, err := src.Exec(`INSERT INTO messages (session_id, role, content_json, created_timestamp) VALUES ('s1', 'user', '[]', 0)`); err != nil {
				t.Fatal(err)
			}
		}
	}
	insert(41) // node-3's watermark

	obsDB, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "w.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { obsDB.Close() })
	s := store.New(obsDB)
	reg := adapter.NewRegistry()
	reg.Register(goose.NewWithOptions(nil, []string{root}))
	var logs pollLogBuffer
	w := New(s, reg, Options{Logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo}))})

	if _, err := w.Scan(ctx); err != nil {
		t.Fatal(err)
	}
	off, err := s.GetCursor(ctx, storePath)
	if err != nil || off != 41 {
		t.Fatalf("cursor after scan = %d (err %v), want the messages.id watermark 41", off, err)
	}
	fi, err := os.Stat(storePath)
	if err != nil || fi.Size() == off {
		t.Fatalf("fixture must reproduce size != cursor (size %d, cursor %d)", fi.Size(), off)
	}

	const msg = "watcher.poll: caught up dropped writes"
	logs.Reset()
	for i := 0; i < 5; i++ {
		if err := w.pollCursors(ctx); err != nil {
			t.Fatalf("pollCursors: %v", err)
		}
	}
	if n := logs.count(msg); n != 0 {
		t.Fatalf("5 polls with no new rows logged %d catch-up lines, want 0:\n%s", n, logs.String())
	}

	// A real out-of-band write (no fsnotify event) is still caught, once.
	insert(1)
	if err := w.pollCursors(ctx); err != nil {
		t.Fatalf("pollCursors: %v", err)
	}
	if off, _ := s.GetCursor(ctx, storePath); off != 42 {
		t.Fatalf("cursor after a real write = %d, want 42 (catch-up lost)", off)
	}
	if n := logs.count(msg); n != 1 {
		t.Fatalf("real catch-up logged %d lines, want exactly 1:\n%s", n, logs.String())
	}
	line := logs.String()
	if !strings.Contains(line, "cursor_from=41") || !strings.Contains(line, "cursor_to=42") {
		t.Errorf("catch-up line must name the cursor move:\n%s", line)
	}
	if strings.Contains(line, "behind_bytes") {
		t.Errorf("behind_bytes is not a lag for a watermark cursor:\n%s", line)
	}
	if err := w.pollCursors(ctx); err != nil {
		t.Fatalf("pollCursors: %v", err)
	}
	if n := logs.count(msg); n != 1 {
		t.Errorf("idle poll after the catch-up logged again (%d lines):\n%s", n, logs.String())
	}
}
