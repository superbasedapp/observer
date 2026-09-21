package qwencode

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestToolVersionEmitted pins Issue 2 (migration 125): the CC-envelope
// `version` on qwen records becomes exactly one SessionToolVersion per
// session (the simple-session fixture carries "0.19.8").
func TestToolVersionEmitted(t *testing.T) {
	src := filepath.Join("..", "..", "..", "testdata", "qwencode", "simple-session.jsonl")
	body, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	root := t.TempDir()
	dst := filepath.Join(root, ".qwen", "projects", "-home-dev-proj", "chats", "session.jsonl")
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, body, 0o644); err != nil {
		t.Fatal(err)
	}
	a := newTestAdapter(filepath.Join(root, ".qwen", "projects"))
	res, err := a.ParseSessionFile(context.Background(), dst, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.SessionToolVersions) != 1 {
		t.Fatalf("SessionToolVersions = %+v, want exactly one", res.SessionToolVersions)
	}
	if res.SessionToolVersions[0].Version != "0.19.8" {
		t.Errorf("version = %q, want 0.19.8", res.SessionToolVersions[0].Version)
	}
}
