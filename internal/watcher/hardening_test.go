package watcher

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// stubFlagAdapter records whether ParseSessionFile was called and can be told
// to panic, so the size-cap and panic-recovery guards can be exercised.
type stubFlagAdapter struct {
	name        string
	root        string
	called      bool
	shouldPanic bool
}

func (s *stubFlagAdapter) Name() string                { return s.name }
func (s *stubFlagAdapter) WatchPaths() []string        { return []string{s.root} }
func (s *stubFlagAdapter) IsSessionFile(p string) bool { return strings.HasSuffix(p, ".stub") }

func (s *stubFlagAdapter) ParseSessionFile(_ context.Context, _ string, _ int64) (adapter.ParseResult, error) {
	s.called = true
	if s.shouldPanic {
		panic("adapter blew up on a malformed file")
	}
	return adapter.ParseResult{}, nil
}

func quietWatcher(t *testing.T, opts Options) (*Watcher, *store.Store) {
	t.Helper()
	database, err := db.Open(context.Background(), db.Options{Path: filepath.Join(t.TempDir(), "w.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	s := store.New(database)
	return New(s, adapter.NewRegistry(), opts), s
}

func TestProcessFileSkipsOversizeFile(t *testing.T) {
	root := t.TempDir()
	stub := &stubFlagAdapter{name: "stub", root: root}
	w, _ := quietWatcher(t, Options{MaxFileBytes: 8})

	path := filepath.Join(root, "big.stub")
	if err := os.WriteFile(path, []byte("this file is well over eight bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := w.processFile(context.Background(), stub, path, false); err != nil {
		t.Fatalf("processFile: %v", err)
	}
	if stub.called {
		t.Error("adapter was called on an oversize file; the size cap did not skip it")
	}
}

func TestProcessFileParsesWhenUnderCap(t *testing.T) {
	root := t.TempDir()
	stub := &stubFlagAdapter{name: "stub", root: root}
	w, _ := quietWatcher(t, Options{MaxFileBytes: 1024})

	path := filepath.Join(root, "small.stub")
	if err := os.WriteFile(path, []byte("tiny"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := w.processFile(context.Background(), stub, path, false); err != nil {
		t.Fatalf("processFile: %v", err)
	}
	if !stub.called {
		t.Error("adapter was not called on an under-cap file")
	}
}

// stubWatermarkAdapter is a stubFlagAdapter that declares watermark cursor
// semantics for its `.db` files only — the mixed-shape reality (opencode:
// SQLite store + JSONL siblings; cline-cli: sessions.db + hooks.jsonl).
type stubWatermarkAdapter struct {
	stubFlagAdapter
}

func (s *stubWatermarkAdapter) IsSessionFile(p string) bool {
	return strings.HasSuffix(p, ".db") || strings.HasSuffix(p, ".stub")
}

func (s *stubWatermarkAdapter) CursorSemanticsFor(path string) adapter.FileCursorSemantics {
	if strings.HasSuffix(path, ".db") {
		return adapter.FileCursorSemantics{Kind: adapter.CursorWatermark, Detail: "test store"}
	}
	return adapter.FileCursorSemantics{}
}

// TestProcessFileOversizeGateExemptsWatermarkStores pins the 2026-08-27
// finding: a watermark SQLite store is queried incrementally, so the
// MaxFileBytes DoS guard must not gate it — a healthy store grows past any
// fixed cap eventually, and gating it is permanent silent capture loss
// (the 53 MB Windows opencode.db). Byte-offset files from the SAME adapter
// stay gated — here because neither file has a persisted cursor, so the
// unread delta IS the whole file (see TestProcessFileOversizeGateUsesUnreadDelta
// for the tracked-tail case).
func TestProcessFileOversizeGateExemptsWatermarkStores(t *testing.T) {
	cases := []struct {
		name       string
		file       string
		wantParsed bool
	}{
		{"oversize watermark store is parsed", "big.db", true},
		{"oversize byte-offset sibling stays gated", "big.stub", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			stub := &stubWatermarkAdapter{stubFlagAdapter{name: "stub", root: root}}
			w, _ := quietWatcher(t, Options{MaxFileBytes: 8})

			path := filepath.Join(root, tc.file)
			if err := os.WriteFile(path, []byte("this file is well over eight bytes"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := w.processFile(context.Background(), stub, path, false); err != nil {
				t.Fatalf("processFile: %v", err)
			}
			if stub.called != tc.wantParsed {
				t.Errorf("adapter called = %v, want %v", stub.called, tc.wantParsed)
			}
		})
	}
}

func TestProcessFileRecoversFromAdapterPanic(t *testing.T) {
	root := t.TempDir()
	stub := &stubFlagAdapter{name: "stub", root: root, shouldPanic: true}
	w, _ := quietWatcher(t, Options{})

	path := filepath.Join(root, "boom.stub")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Must not propagate the panic; a recovered parse returns nil so the
	// watcher keeps running.
	if err := w.processFile(context.Background(), stub, path, false); err != nil {
		t.Fatalf("processFile returned an error instead of recovering: %v", err)
	}
}

// TestOversizeUnreadDelta pins the pure predicate both the watcher gate
// and `observer doctor` read. The `streams` column is the adapter's
// FileCursorSemantics.DeltaGateMeaningful() answer: false (the default)
// must keep comparing the file's TOTAL size, because a whole-file
// os.ReadFile allocates the whole file no matter where the cursor sits.
func TestOversizeUnreadDelta(t *testing.T) {
	cases := []struct {
		name      string
		size      int64
		off       int64
		max       int64
		streams   bool
		wantDelta int64
		wantSkip  bool
	}{
		{"untracked oversize file is gated", 100, 0, 8, true, 100, true},
		{"tracked tail under the cap streams", 100, 95, 8, true, 5, false},
		{"tracked tail over the cap is gated", 100, 10, 8, true, 90, true},
		{"delta exactly at the cap streams", 100, 92, 8, true, 8, false},
		{"truncated file re-reads whole", 100, 400, 8, true, 100, true},
		{"negative cursor re-reads whole", 100, -1, 8, true, 100, true},
		{"disabled cap never gates", 1 << 40, 0, 0, true, 1 << 40, false},
		{"under-cap file never gates", 4, 0, 8, true, 4, false},
		// The whole-file-reader half: a near-EOF cursor must NOT unlock
		// the gate, or the guard is a no-op for the adapters it exists
		// for (kirocrew/cline/copilot/deepseek/cursor/gemini/antigravity
		// all ReadFile the whole file and persist NewOffset = size).
		{"whole-file reader with a near-EOF cursor stays gated", 100, 95, 8, false, 5, true},
		{"whole-file reader under the cap is not gated", 4, 0, 8, false, 4, false},
		{"whole-file reader with no cursor stays gated", 100, 0, 8, false, 100, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := OversizeUnreadDelta(tc.size, tc.off); got != tc.wantDelta {
				t.Errorf("OversizeUnreadDelta(%d, %d) = %d, want %d", tc.size, tc.off, got, tc.wantDelta)
			}
			if got := OversizeSkipped(tc.size, tc.off, tc.max, tc.streams); got != tc.wantSkip {
				t.Errorf("OversizeSkipped(%d, %d, %d, streams=%v) = %v, want %v",
					tc.size, tc.off, tc.max, tc.streams, got, tc.wantSkip)
			}
		})
	}
}

// stubStreamingAdapter declares StreamsFromCursor for its `.stub`
// files: the seek-and-stream shape (claudecode/codex).
type stubStreamingAdapter struct {
	stubFlagAdapter
}

func (s *stubStreamingAdapter) CursorSemanticsFor(path string) adapter.FileCursorSemantics {
	if !s.IsSessionFile(path) {
		return adapter.FileCursorSemantics{}
	}
	return adapter.FileCursorSemantics{StreamsFromCursor: true, Detail: "test streamer"}
}

// TestProcessFileOversizeGateUsesUnreadDelta pins P1-3 AND its
// adversarial correction: the unread-delta relaxation applies ONLY to an
// adapter that declared StreamsFromCursor. A whole-file reader with a
// near-EOF cursor must stay gated, or the DoS guard becomes a no-op for
// exactly the adapters it was written for.
//
// Before the fix a streaming transcript past the cap was skipped on every
// tick forever (six Codex transcripts frozen at ~52 MB while the files
// grew to 85 MB).
func TestProcessFileOversizeGateUsesUnreadDelta(t *testing.T) {
	body := []byte("this file is well over eight bytes")
	nearEOF := int64(len(body)) - 4

	cases := []struct {
		name       string
		streams    bool
		cursor     int64
		wantParsed bool
	}{
		{"streamer, no cursor: whole file would be read, stays gated", true, 0, false},
		{"streamer, cursor near EOF: only the tail is read, parses", true, nearEOF, true},
		{"streamer, cursor far behind: tail still over the cap, stays gated", true, 4, false},
		{"whole-file reader, cursor near EOF: STILL gated", false, nearEOF, false},
		{"whole-file reader, no cursor: gated", false, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			base := stubFlagAdapter{name: "stub", root: root}
			var a adapter.Adapter = &base
			if tc.streams {
				a = &stubStreamingAdapter{base}
			}
			w, s := quietWatcher(t, Options{MaxFileBytes: 8})

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
			called := base.called
			if st, ok := a.(*stubStreamingAdapter); ok {
				called = st.called
			}
			if called != tc.wantParsed {
				t.Errorf("adapter called = %v, want %v", called, tc.wantParsed)
			}
		})
	}
}

// TestProcessFileOversizeWarnIsDeduped pins the WARN-spam half of P1-3:
// a file that stays past the cap logged "skipping oversize file" on
// every poll tick (1,146 lines across 6 paths in one audit log sample).
func TestProcessFileOversizeWarnIsDeduped(t *testing.T) {
	root := t.TempDir()
	stub := &stubFlagAdapter{name: "stub", root: root}
	var buf bytes.Buffer
	w, _ := quietWatcher(t, Options{
		MaxFileBytes: 8,
		Logger:       slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})),
	})

	path := filepath.Join(root, "big.stub")
	if err := os.WriteFile(path, []byte("this file is well over eight bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := w.processFile(context.Background(), stub, path, false); err != nil {
			t.Fatalf("processFile: %v", err)
		}
	}
	if got := strings.Count(buf.String(), "skipping oversize file"); got != 1 {
		t.Errorf("oversize WARN emitted %d times across 5 passes, want 1", got)
	}
}

// fakeWatchAdder fails Add for paths whose base name is in fail.
type fakeWatchAdder struct {
	fail  map[string]error
	added []string
}

func (f *fakeWatchAdder) Add(name string) error {
	if err, ok := f.fail[filepath.Base(name)]; ok {
		return err
	}
	f.added = append(f.added, name)
	return nil
}

// TestAddRecursiveContinuesPastAFailingDirectory pins ADAPT-LZ-1: one
// inotify ENOSPC/EACCES on a nested directory must not abort the whole
// root's walk (which left every sibling unwatched and leaked the
// watches already added).
func TestAddRecursiveContinuesPastAFailingDirectory(t *testing.T) {
	root := t.TempDir()
	for _, sub := range []string{"a", "bad", "c"} {
		if err := os.MkdirAll(filepath.Join(root, sub, "nested"), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	cases := []struct {
		name        string
		fail        map[string]error
		wantFailed  int
		wantRootErr bool
		wantWatched []string // base names that MUST have been added
	}{
		{
			name:        "all watches succeed",
			fail:        nil,
			wantFailed:  0,
			wantWatched: []string{"a", "bad", "c"},
		},
		{
			name:        "one failing subdirectory does not abort the walk",
			fail:        map[string]error{"bad": errors.New("no space left on device")},
			wantFailed:  1,
			wantWatched: []string{"a", "c"},
		},
		{
			name:        "an unwatchable root is reported separately",
			fail:        map[string]error{filepath.Base(root): errors.New("permission denied")},
			wantFailed:  0,
			wantRootErr: true,
			wantWatched: []string{"a", "bad", "c"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeWatchAdder{fail: tc.fail}
			res := addRecursive(fake, root)
			if res.Failed != tc.wantFailed {
				t.Errorf("Failed = %d, want %d", res.Failed, tc.wantFailed)
			}
			if (res.RootErr != nil) != tc.wantRootErr {
				t.Errorf("RootErr = %v, want error: %v", res.RootErr, tc.wantRootErr)
			}
			if tc.wantFailed > 0 && res.FirstErr == nil {
				t.Error("FirstErr is nil despite a failed Add")
			}
			for _, want := range tc.wantWatched {
				found := false
				for _, got := range fake.added {
					if filepath.Base(got) == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("directory %q was never watched (added: %v)", want, fake.added)
				}
			}
			// Every "nested" dir is still watched, including the one
			// under the directory whose own Add failed: the walk
			// descends past a failure instead of stopping at it.
			nested := 0
			for _, got := range fake.added {
				if filepath.Base(got) == "nested" {
					nested++
				}
			}
			if nested != 3 {
				t.Errorf("nested directories watched = %d, want 3 (the walk stopped early)", nested)
			}
		})
	}
}
