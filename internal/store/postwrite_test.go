package store

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestPostWriteSink: the seam reports each inserted, successful write once
// with a project-relative path, and nothing for reads, failures, paths
// outside the project or a re-ingest of the same rows.
func TestPostWriteSink(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	var got []PostWrite
	s.SetPostWriteSink(func(p PostWrite) { got = append(got, p) })
	ev := func(id, action, target string, ok bool) models.ToolEvent {
		return models.ToolEvent{
			SourceFile: "/t/pw.jsonl", SourceEventID: id, SessionID: "s_pw", ProjectRoot: "/tmp/p_pw",
			Timestamp: now, Tool: models.ToolClaudeCode, ActionType: action, Target: target, Success: ok,
		}
	}
	events := []models.ToolEvent{
		ev("w1", models.ActionWriteFile, "/tmp/p_pw/cfg/prod.py", true),
		ev("w2", models.ActionEditFile, "src/a.go", true),
		ev("w3", models.ActionWriteFile, "/etc/passwd", true),
		ev("w4", models.ActionWriteFile, "/tmp/p_pw/failed.py", false),
		ev("r1", models.ActionReadFile, "/tmp/p_pw/cfg/prod.py", true),
		ev("w5", models.ActionWriteFile, "../escape.py", true),
	}
	if _, err := s.Ingest(ctx, events, nil, IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, p := range got {
		if p.SessionID != "s_pw" || p.ProjectRoot != "/tmp/p_pw" || p.ActionID == 0 {
			t.Fatalf("post-write = %+v", p)
		}
		paths = append(paths, p.Path)
	}
	if want := []string{"cfg/prod.py", "src/a.go"}; !reflect.DeepEqual(paths, want) {
		t.Fatalf("paths = %v, want %v", paths, want)
	}
	got = nil
	if _, err := s.Ingest(ctx, events, nil, IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("re-ingest reported %d writes again", len(got))
	}
}

// TestPostWritesAfter (SEC-C2): the action-id feed reports each stored,
// successful write once, from any writer (no sink involved, as for a row
// the hook process inserted), and advances its watermark past skipped rows.
func TestPostWritesAfter(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	start, err := s.MaxActionID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ev := func(id, action, target string, ok bool) models.ToolEvent {
		return models.ToolEvent{
			SourceFile: "/t/pwa.jsonl", SourceEventID: id, SessionID: "s_pwa", ProjectRoot: "/tmp/p_pwa",
			Timestamp: now, Tool: models.ToolClaudeCode, ActionType: action, Target: target, Success: ok,
		}
	}
	if _, err := s.Ingest(ctx, []models.ToolEvent{
		ev("w1", models.ActionWriteFile, "/tmp/p_pwa/cfg/prod.py", true),
		ev("r1", models.ActionReadFile, "/tmp/p_pwa/cfg/prod.py", true),
		ev("w2", models.ActionEditFile, "/etc/passwd", true),
		ev("w3", models.ActionEditFile, "src/a.go", true),
	}, nil, IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	got, last, err := s.PostWritesAfter(ctx, start, 10)
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, p := range got {
		paths = append(paths, p.Path)
	}
	if want := []string{"cfg/prod.py", "src/a.go"}; !reflect.DeepEqual(paths, want) || last <= start {
		t.Fatalf("paths = %v (last %d, start %d), want %v", paths, last, start, want)
	}
	again, last2, err := s.PostWritesAfter(ctx, last, 10)
	if err != nil || len(again) != 0 || last2 != last {
		t.Fatalf("second read = %v, %d, %v", again, last2, err)
	}
}
