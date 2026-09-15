package watcher

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestScanFileScopedRecovery(t *testing.T) {
	w, s, root := setup(t)
	ctx := context.Background()
	body := []byte(`{"sessionId":"selected","uuid":"u1","cwd":"/project","timestamp":"2026-09-10T01:00:00Z","message":{"role":"user","content":"Selected transcript"}}` + "\n")
	selected := writeJSONL(t, root, "selected.jsonl", body)
	unselected := writeJSONL(t, root, "unselected.jsonl", body)
	for _, force := range []bool{false, true} {
		r, err := w.ScanFile(ctx, selected, force)
		if err != nil || r.FilesProcessed != 1 || r.Errors != 0 {
			t.Fatalf("scan: %+v %v", r, err)
		}
	}
	if off, err := s.GetCursor(ctx, selected); err != nil || off != int64(len(body)) {
		t.Fatalf("selected cursor: %d %v", off, err)
	}
	if off, err := s.GetCursor(ctx, unselected); err != nil || off != 0 {
		t.Fatalf("unselected cursor changed: %d %v", off, err)
	}
	outside := filepath.Join(t.TempDir(), "outside.jsonl")
	if err := os.WriteFile(outside, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := w.ScanFile(ctx, outside, true); err == nil {
		t.Fatal("unrecognized path accepted")
	}
}
