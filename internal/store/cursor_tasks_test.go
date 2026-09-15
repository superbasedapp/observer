package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter/cursor"
	"github.com/marmutapp/superbased-observer/internal/taskflow"
)

func TestCursorNativeTasksIngestAndReplay(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	s.SetTasksEnabled(true)
	dir := t.TempDir()
	nativePath := filepath.Join(dir, ".cursor", "chats", "workspace", "cursor-native-probe", "store.db")
	if err := os.MkdirAll(filepath.Dir(nativePath), 0o755); err != nil {
		t.Fatal(err)
	}
	native, err := sql.Open("sqlite", nativePath)
	if err != nil {
		t.Fatal(err)
	}
	defer native.Close()
	if _, err := native.ExecContext(ctx, "CREATE TABLE blobs(id TEXT PRIMARY KEY, data BLOB)"); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 4; i++ {
		blob, err := os.ReadFile(filepath.Join("..", "..", "testdata", "cursor", "native-todos", fmt.Sprintf("step-%d.bin", i)))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := native.ExecContext(ctx, "INSERT INTO blobs VALUES (?,?)", fmt.Sprint(i), blob); err != nil {
			t.Fatal(err)
		}
	}
	a := cursor.NewWithOptions(nil, filepath.Join(dir, ".cursor"))
	parsed, err := a.ParseSessionFile(ctx, nativePath, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := range parsed.ToolEvents {
		parsed.ToolEvents[i].ProjectRoot = dir
	}
	// Re-ingesting the same native events must not duplicate actions or
	// transitions, nor reopen a completed task.
	for replay := 0; replay < 2; replay++ {
		if _, err := s.Ingest(ctx, parsed.ToolEvents, nil, IngestOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	items, err := s.LoadTaskItems(ctx, "cursor-native-probe")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("got %d items, want two", len(items))
	}
	for _, item := range items {
		if item.Status != taskflow.StatusCompleted || item.KeyKind != taskflow.KeyNative {
			t.Fatalf("bad item: %+v", item)
		}
	}
	transitions, err := s.LoadTaskTransitions(ctx, "cursor-native-probe")
	if err != nil {
		t.Fatal(err)
	}
	if len(transitions) != 6 {
		t.Fatalf("got %d transitions, want six", len(transitions))
	}
	summaries := taskflow.Summarize(transitions, time.UnixMilli(1788942100000))
	if len(summaries) != 2 {
		t.Fatalf("summaries=%+v", summaries)
	}
	for _, summary := range summaries {
		if summary.NeverActivated || summary.StillOpen || summary.Elapsed <= 0 {
			t.Fatalf("lost lifecycle: %+v", summary)
		}
	}
}
