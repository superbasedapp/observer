package watcher

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/adapter/cursor"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// stubNoActionsStreamer declares the Cursor hooks-log shape for its
// `.stub` files: a no-actions byte-offset cursor that seeks and streams.
type stubNoActionsStreamer struct {
	stubFlagAdapter
}

func (s *stubNoActionsStreamer) CursorSemanticsFor(path string) adapter.FileCursorSemantics {
	if !s.IsSessionFile(path) {
		return adapter.FileCursorSemantics{}
	}
	return adapter.FileCursorSemantics{Kind: adapter.CursorNoActions, StreamsFromCursor: true}
}

// TestProcessFileOversizeGateStreamsNoActionsTail pins S10-CURSOR P1: a
// no-actions log that seeks and streams (Cursor's hooks output log) is
// gated on its UNREAD TAIL, not its total size. Before the fix the
// delta gate required CursorByteOffset, so the first hooks log past the
// 2 MB default was never parsed again.
func TestProcessFileOversizeGateStreamsNoActionsTail(t *testing.T) {
	body := bytes.Repeat([]byte("x"), 3<<10) // 3 KB against a 1 KB cap
	cases := []struct {
		name       string
		cursor     int64
		wantParsed bool
	}{
		{"cursor 512 B from EOF: tail under the cap, parsed", int64(len(body)) - 512, true},
		{"cursor 0: whole file unread, gated", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			a := &stubNoActionsStreamer{stubFlagAdapter{name: "stub", root: root}}
			w, s := quietWatcher(t, Options{MaxFileBytes: 1 << 10})
			path := filepath.Join(root, "big.stub")
			if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatal(err)
			}
			if tc.cursor > 0 {
				if err := s.SetCursor(context.Background(), path, tc.cursor); err != nil {
					t.Fatal(err)
				}
			}
			if err := w.processFile(context.Background(), a, path, false); err != nil {
				t.Fatalf("processFile: %v", err)
			}
			if a.called != tc.wantParsed {
				t.Errorf("adapter called = %v, want %v", a.called, tc.wantParsed)
			}
		})
	}
}

// offsetRecorder wraps the real cursor adapter and records every
// fromOffset the watcher hands it. Embedding keeps CursorSemanticsFor.
type offsetRecorder struct {
	*cursor.Adapter
	offsets []int64
}

func (r *offsetRecorder) ParseSessionFile(ctx context.Context, path string, from int64) (adapter.ParseResult, error) {
	r.offsets = append(r.offsets, from)
	return r.Adapter.ParseSessionFile(ctx, path, from)
}

// TestPollerRewindsRotatedCursorHooksLog drives Cursor's in-place log
// rotation through the REAL watcher (pollCursors -> processFile ->
// persistProcessCursor): the persisted cursor sits past the end of the
// new, smaller file. The poller must re-process it (size < cursor), the
// cursor must REWIND to the parse's offset instead of staying pinned by
// SetCursor's MAX rule, and the next pass must read only the appended
// tail — from that rewound offset, never 0 and never the stale cursor.
func TestPollerRewindsRotatedCursorHooksLog(t *testing.T) {
	ctx := context.Background()
	full, err := os.ReadFile(filepath.Join("..", "..", "testdata", "cursor", "hooks-log", "cursor.hooks.workspaceId-fixture.log"))
	if err != nil {
		t.Fatal(err)
	}
	marker := bytes.Index(full, []byte(`"hook_event_name": "afterAgentResponse"`))
	if marker < 0 {
		t.Fatal("fixture has no afterAgentResponse block")
	}
	cut := bytes.LastIndex(full[:marker], []byte("\nINPUT:\n"))
	cut = bytes.LastIndex(full[:cut], []byte("\n[")) + 1 // start of that block's ts line

	logs := filepath.Join(t.TempDir(), "Cursor", "logs")
	dir := filepath.Join(logs, "20260919T130539", "window1_wb4", "output_20260919T193726")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "cursor.hooks.workspaceId-fixture.log")
	if err := os.WriteFile(path, full[:cut], 0o600); err != nil {
		t.Fatal(err)
	}

	rec := &offsetRecorder{Adapter: cursor.NewWithOptions(nil, logs)}
	reg := adapter.NewRegistry()
	reg.Register(rec)
	database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "w.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	s := store.New(database)
	w := New(s, reg, Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})

	const stale = int64(50 << 20) // the pre-rotation cursor
	if err := s.SetCursor(ctx, path, stale); err != nil {
		t.Fatal(err)
	}
	if err := w.pollCursors(ctx); err != nil {
		t.Fatal(err)
	}
	if len(rec.offsets) != 1 || rec.offsets[0] != stale {
		t.Fatalf("first poll offsets = %v, want one parse handed the stale %d", rec.offsets, stale)
	}
	rewound, err := s.GetCursor(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if rewound <= 0 || rewound > int64(cut) {
		t.Fatalf("cursor after rotation = %d, want rewound into (0, %d]", rewound, cut)
	}
	var n int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM token_usage WHERE message_id = 'ed2e9caf-ed8d-4485-9865-8af0b65d037d'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("usage row present before its block was written (%d)", n)
	}

	// Cursor appends the rest; a second poll reads only the tail.
	if err := os.WriteFile(path, full, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := w.pollCursors(ctx); err != nil {
		t.Fatal(err)
	}
	if len(rec.offsets) != 2 || rec.offsets[1] != rewound {
		t.Fatalf("second poll offsets = %v, want the tail read from the rewound %d", rec.offsets, rewound)
	}
	var in, out, cr int64
	if err := database.QueryRowContext(ctx, `SELECT input_tokens, output_tokens, cache_read_tokens FROM token_usage WHERE message_id = 'ed2e9caf-ed8d-4485-9865-8af0b65d037d'`).Scan(&in, &out, &cr); err != nil {
		t.Fatalf("appended usage block not ingested: %v", err)
	}
	if in != 253719 || out != 21724 || cr != 2529792 {
		t.Fatalf("usage = %d/%d/%d, want 253719/21724/2529792", in, out, cr)
	}
	if got, _ := s.GetCursor(ctx, path); got != int64(len(full)) {
		t.Fatalf("cursor = %d, want EOF %d", got, len(full))
	}
	// Idle: nothing new, no further parse.
	if err := w.pollCursors(ctx); err != nil {
		t.Fatal(err)
	}
	if len(rec.offsets) != 2 {
		t.Fatalf("idle poll re-parsed the file: offsets %v", rec.offsets)
	}
}
