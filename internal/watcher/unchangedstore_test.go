package watcher

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
)

// countingWatermark is a watermark-cursor stub whose parses are counted; its
// files declare SelfContained per the selfContained flag.
type countingWatermark struct {
	stubFlagAdapter
	selfContained bool
	parses        int
	retry         bool
}

func (c *countingWatermark) CursorSemanticsFor(path string) adapter.FileCursorSemantics {
	if !c.IsSessionFile(path) {
		return adapter.FileCursorSemantics{}
	}
	return adapter.FileCursorSemantics{Kind: adapter.CursorWatermark, SelfContained: c.selfContained}
}

func (c *countingWatermark) ParseSessionFile(_ context.Context, _ string, from int64) (adapter.ParseResult, error) {
	c.parses++
	return adapter.ParseResult{NewOffset: from + 1, RetrySuggested: c.retry}, nil
}

// TestUnchangedSelfContainedStoreSkipsReparse pins the 2026-10-18 fix: a
// self-contained watermark store (freebuff's whole-file chat JSON) is parsed
// once and then skipped while its size and modification time are unchanged,
// instead of being re-read on every poll tick; a change, a forced rescan or a
// retry request parses again; a store that does not declare SelfContained is
// still parsed every pass.
func TestUnchangedSelfContainedStoreSkipsReparse(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	path := filepath.Join(root, "chat.stub")
	if err := os.WriteFile(path, []byte(`[{"m":1}]`), 0o600); err != nil {
		t.Fatal(err)
	}

	a := &countingWatermark{stubFlagAdapter: stubFlagAdapter{name: "wm", root: root}, selfContained: true}
	w, _ := quietWatcher(t, Options{})
	for i := 0; i < 3; i++ {
		if err := w.processFile(ctx, a, path, false); err != nil {
			t.Fatal(err)
		}
	}
	if a.parses != 1 {
		t.Fatalf("unchanged self-contained store parsed %d times over 3 passes; want 1", a.parses)
	}

	// A rewrite (new size and mtime) parses again, once.
	later := time.Now().Add(2 * time.Second)
	if err := os.WriteFile(path, []byte(`[{"m":1},{"m":2}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Chtimes(path, later, later)
	for i := 0; i < 2; i++ {
		if err := w.processFile(ctx, a, path, false); err != nil {
			t.Fatal(err)
		}
	}
	if a.parses != 2 {
		t.Fatalf("after a rewrite: %d parses; want 2", a.parses)
	}

	// A forced from-zero rescan always parses.
	if err := w.processFile(ctx, a, path, true); err != nil {
		t.Fatal(err)
	}
	if a.parses != 3 {
		t.Fatalf("forced rescan did not parse (parses %d)", a.parses)
	}

	// A parse that asks for a retry is not remembered.
	r := &countingWatermark{stubFlagAdapter: stubFlagAdapter{name: "wm-retry", root: root}, selfContained: true, retry: true}
	w2, _ := quietWatcher(t, Options{})
	for i := 0; i < 2; i++ {
		if err := w2.processFile(ctx, r, path, false); err != nil {
			t.Fatal(err)
		}
	}
	if r.parses != 2 {
		t.Fatalf("retry-suggested parses = %d; want 2 (never memoized)", r.parses)
	}

	// Not declared self-contained: unchanged behaviour, parsed every pass.
	b := &countingWatermark{stubFlagAdapter: stubFlagAdapter{name: "wm-open", root: root}}
	w3, _ := quietWatcher(t, Options{})
	for i := 0; i < 3; i++ {
		if err := w3.processFile(ctx, b, path, false); err != nil {
			t.Fatal(err)
		}
	}
	if b.parses != 3 {
		t.Fatalf("non-self-contained store parsed %d times; want 3", b.parses)
	}
}
