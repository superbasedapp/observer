package discover

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

func openDB(t *testing.T) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "disc.db")
	database, err := db.Open(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	return database
}

// ingest is a tiny seed helper — inserts events via store.Ingest under a
// stable project root, then lets the caller patch rows as needed.
func ingest(t *testing.T, database *sql.DB, root string, events []models.ToolEvent) {
	t.Helper()
	if _, err := store.New(database).Ingest(context.Background(), events, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
}

func evt(id, session, tool, action, target string, ts time.Time, success bool) models.ToolEvent {
	return models.ToolEvent{
		SourceFile: "f-" + session, SourceEventID: id,
		SessionID: session, Tool: tool,
		Timestamp: ts, ActionType: action, Target: target, Success: success,
	}
}

func TestRun_StaleReadsAndWasteEstimate(t *testing.T) {
	database := openDB(t)
	root := t.TempDir()
	base := time.Date(2026, 4, 16, 10, 0, 0, 0, time.UTC)
	// Three reads of a.go: two stale, one fresh.
	events := []models.ToolEvent{
		{
			SourceFile: "f", SourceEventID: "1", SessionID: "s", ProjectRoot: root,
			Timestamp: base, Tool: models.ToolClaudeCode,
			ActionType: models.ActionReadFile, Target: "a.go", Success: true,
		},
		{
			SourceFile: "f", SourceEventID: "2", SessionID: "s", ProjectRoot: root,
			Timestamp: base.Add(time.Second), Tool: models.ToolClaudeCode,
			ActionType: models.ActionReadFile, Target: "a.go", Success: true,
		},
		{
			SourceFile: "f", SourceEventID: "3", SessionID: "s", ProjectRoot: root,
			Timestamp: base.Add(2 * time.Second), Tool: models.ToolClaudeCode,
			ActionType: models.ActionReadFile, Target: "a.go", Success: true,
		},
	}
	ingest(t, database, root, events)
	// Force the two re-reads to stale (events 2 & 3, NOT 1 — the first
	// read of a file in a session can never be a stale reread, since
	// there's nothing to compare against in-session). Gives a stable
	// stale_count = 2 under the same-session-scoping rule.
	if _, err := database.ExecContext(context.Background(),
		`UPDATE actions SET freshness = 'stale' WHERE source_event_id IN ('2', '3')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(context.Background(),
		`INSERT INTO file_state (project_id, file_path, content_hash, file_mtime,
			file_size_bytes, last_action_type, last_seen_at)
		 VALUES ((SELECT id FROM projects WHERE root_path = ?), 'a.go', 'h',
			 ?, 4096, 'read_file', ?)`,
		root, base.Format(time.RFC3339Nano), base.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}

	got, err := New(database).Run(context.Background(), Options{ProjectRoot: root})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(got.StaleReads) != 1 {
		t.Fatalf("StaleReads: %d", len(got.StaleReads))
	}
	s := got.StaleReads[0]
	if s.FilePath != "a.go" || s.StaleCount != 2 || s.TotalReads != 3 {
		t.Errorf("row wrong: %+v", s)
	}
	// 4096 bytes → 1024 tokens × 2 stale reads = 2048.
	if s.EstWastedTokens != 2048 {
		t.Errorf("waste: got %d want 2048", s.EstWastedTokens)
	}
	if got.Summary.StaleReadCount != 2 || got.Summary.EstWastedTokens != 2048 {
		t.Errorf("summary: %+v", got.Summary)
	}
}

// TestRun_StaleReads_CrossSessionExcluded pins the cross-session scoping
// rule: when freshness=stale rows belong to different sessions and have
// no prior read of the same file *within their own session*, they must
// not surface as stale rereads. Two sessions, two reads of a.go (one
// each), both stamped stale at write time — expectation: zero stale
// rereads in the report.
func TestRun_StaleReads_CrossSessionExcluded(t *testing.T) {
	database := openDB(t)
	root := t.TempDir()
	base := time.Date(2026, 4, 27, 10, 0, 0, 0, time.UTC)
	// Each session has exactly one read of a.go. Without same-session
	// scoping the freshness=stale tag would count both as stale; with
	// scoping neither qualifies because there's no prior in-session read.
	events := []models.ToolEvent{
		{
			SourceFile: "f-A", SourceEventID: "A1", SessionID: "sessA", ProjectRoot: root,
			Timestamp: base, Tool: models.ToolClaudeCode,
			ActionType: models.ActionReadFile, Target: "a.go", Success: true,
		},
		{
			SourceFile: "f-B", SourceEventID: "B1", SessionID: "sessB", ProjectRoot: root,
			Timestamp: base.Add(10 * time.Minute), Tool: models.ToolClaudeCode,
			ActionType: models.ActionReadFile, Target: "a.go", Success: true,
		},
	}
	ingest(t, database, root, events)
	if _, err := database.ExecContext(context.Background(),
		`UPDATE actions SET freshness = 'stale' WHERE source_event_id IN ('A1', 'B1')`); err != nil {
		t.Fatal(err)
	}
	got, err := New(database).Run(context.Background(), Options{ProjectRoot: root})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(got.StaleReads) != 0 {
		t.Fatalf("StaleReads should be empty (cross-session reads don't count): got %+v", got.StaleReads)
	}
	if got.Summary.StaleReadCount != 0 {
		t.Errorf("Summary.StaleReadCount: got %d want 0", got.Summary.StaleReadCount)
	}

	// Now add a second read of a.go *inside* sessA — that one DOES have
	// a prior in-session read, so it's a legitimate stale.
	more := []models.ToolEvent{
		{
			SourceFile: "f-A", SourceEventID: "A2", SessionID: "sessA", ProjectRoot: root,
			Timestamp: base.Add(time.Minute), Tool: models.ToolClaudeCode,
			ActionType: models.ActionReadFile, Target: "a.go", Success: true,
		},
	}
	ingest(t, database, root, more)
	if _, err := database.ExecContext(context.Background(),
		`UPDATE actions SET freshness = 'stale' WHERE source_event_id = 'A2'`); err != nil {
		t.Fatal(err)
	}
	got, err = New(database).Run(context.Background(), Options{ProjectRoot: root})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(got.StaleReads) != 1 {
		t.Fatalf("StaleReads after in-session reread: %+v", got.StaleReads)
	}
	if got.StaleReads[0].StaleCount != 1 {
		t.Errorf("StaleCount: got %d want 1 (only the A2 in-session reread counts)", got.StaleReads[0].StaleCount)
	}
}

func TestRun_RepeatedCommands_NoChangeReruns(t *testing.T) {
	database := openDB(t)
	root := t.TempDir()
	base := time.Date(2026, 4, 16, 10, 0, 0, 0, time.UTC)
	// go test runs three times; one edit between first and second; no edit
	// between second and third → one no-change rerun.
	events := []models.ToolEvent{
		evt("1", "s", models.ToolClaudeCode, models.ActionRunCommand, "go test", base, true),
		evt("2", "s", models.ToolClaudeCode, models.ActionEditFile, "a.go", base.Add(time.Second), true),
		evt("3", "s", models.ToolClaudeCode, models.ActionRunCommand, "go test", base.Add(2*time.Second), true),
		evt("4", "s", models.ToolClaudeCode, models.ActionRunCommand, "go test", base.Add(3*time.Second), true),
	}
	for i := range events {
		events[i].ProjectRoot = root
	}
	ingest(t, database, root, events)

	got, err := New(database).Run(context.Background(), Options{ProjectRoot: root})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(got.RepeatedCommands) != 1 {
		t.Fatalf("RepeatedCommands: %d", len(got.RepeatedCommands))
	}
	r := got.RepeatedCommands[0]
	if r.TotalRuns != 3 {
		t.Errorf("TotalRuns: %d", r.TotalRuns)
	}
	if r.NoChangeReruns != 1 {
		t.Errorf("NoChangeReruns: got %d want 1 (run 3 followed run 2 without edits)", r.NoChangeReruns)
	}
}

func TestRun_CrossToolFiles(t *testing.T) {
	database := openDB(t)
	root := t.TempDir()
	base := time.Date(2026, 4, 16, 10, 0, 0, 0, time.UTC)
	events := []models.ToolEvent{
		evt("1", "sA", models.ToolClaudeCode, models.ActionReadFile, "shared.go", base, true),
		evt("2", "sB", models.ToolCodex, models.ActionReadFile, "shared.go", base.Add(time.Second), true),
		evt("3", "sC", models.ToolCursor, models.ActionEditFile, "shared.go", base.Add(2*time.Second), true),
		evt("4", "sA", models.ToolClaudeCode, models.ActionReadFile, "solo.go", base.Add(3*time.Second), true),
	}
	for i := range events {
		events[i].ProjectRoot = root
	}
	ingest(t, database, root, events)

	got, err := New(database).Run(context.Background(), Options{ProjectRoot: root})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(got.CrossToolFiles) != 1 {
		t.Fatalf("CrossToolFiles: %d", len(got.CrossToolFiles))
	}
	c := got.CrossToolFiles[0]
	if c.FilePath != "shared.go" {
		t.Errorf("file: %s", c.FilePath)
	}
	if len(c.Tools) != 3 {
		t.Errorf("tools: %v", c.Tools)
	}
}

func TestRun_NativeVsBashBuckets(t *testing.T) {
	database := openDB(t)
	root := t.TempDir()
	base := time.Date(2026, 4, 16, 10, 0, 0, 0, time.UTC)
	// 2 reads via Claude Code (native), 1 run_command via Bash (non-native).
	events := []models.ToolEvent{
		evt("1", "s", models.ToolClaudeCode, models.ActionReadFile, "a.go", base, true),
		evt("2", "s", models.ToolClaudeCode, models.ActionReadFile, "b.go", base.Add(time.Second), true),
		evt("3", "s", models.ToolClaudeCode, models.ActionRunCommand, "ls", base.Add(2*time.Second), true),
	}
	for i := range events {
		events[i].ProjectRoot = root
		events[i].RawToolName = "Read"
	}
	events[2].RawToolName = "Bash"
	if _, err := store.New(database).Ingest(context.Background(), events, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	// Mark reads as native directly (the adapter's NativePredicate does
	// this in production; tests bypass the watcher).
	if _, err := database.ExecContext(context.Background(),
		`UPDATE actions SET is_native_tool = 1 WHERE raw_tool_name = 'Read'`); err != nil {
		t.Fatal(err)
	}
	got, err := New(database).Run(context.Background(), Options{ProjectRoot: root})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got.Summary.NativeActionCount != 2 {
		t.Errorf("NativeActionCount: %d", got.Summary.NativeActionCount)
	}
	if got.Summary.BashActionCount != 1 {
		t.Errorf("BashActionCount: %d", got.Summary.BashActionCount)
	}
}

func TestRun_ProjectAndDateFilters(t *testing.T) {
	database := openDB(t)
	rootA := t.TempDir()
	rootB := t.TempDir()
	base := time.Date(2026, 4, 16, 10, 0, 0, 0, time.UTC)
	events := []models.ToolEvent{
		{
			SourceFile: "f1", SourceEventID: "1", SessionID: "sA", ProjectRoot: rootA,
			Timestamp: base.Add(-10 * 24 * time.Hour), Tool: models.ToolClaudeCode,
			ActionType: models.ActionReadFile, Target: "old.go", Success: true,
		},
		{
			SourceFile: "f1", SourceEventID: "2", SessionID: "sA", ProjectRoot: rootA,
			Timestamp: base, Tool: models.ToolClaudeCode,
			ActionType: models.ActionReadFile, Target: "new.go", Success: true,
		},
		{
			SourceFile: "f2", SourceEventID: "3", SessionID: "sB", ProjectRoot: rootB,
			Timestamp: base, Tool: models.ToolClaudeCode,
			ActionType: models.ActionReadFile, Target: "other.go", Success: true,
		},
	}
	ingest(t, database, rootA, events)

	d := New(database)
	// Project filter.
	got, err := d.Run(context.Background(), Options{
		ProjectRoot: rootA,
		Now:         func() time.Time { return base.Add(time.Minute) },
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got.Summary.TotalActions != 2 {
		t.Errorf("project filter: TotalActions=%d", got.Summary.TotalActions)
	}
	// Days filter.
	got, err = d.Run(context.Background(), Options{
		ProjectRoot: rootA, Days: 3,
		Now: func() time.Time { return base.Add(time.Minute) },
	})
	if err != nil {
		t.Fatalf("Run days: %v", err)
	}
	if got.Summary.TotalActions != 1 {
		t.Errorf("days filter: TotalActions=%d", got.Summary.TotalActions)
	}
}

// TestRun_StaleOnlyMatchesFullRunStaleFields pins Options.StaleOnly: the
// stale-read rows and every stale / total field of the summary equal a full
// Run's, and the other sections are left empty.
func TestRun_StaleOnlyMatchesFullRunStaleFields(t *testing.T) {
	database := openDB(t)
	root := t.TempDir()
	base := time.Date(2026, 4, 16, 10, 0, 0, 0, time.UTC)
	var events []models.ToolEvent
	for i, target := range []string{"a.go", "a.go", "a.go", "b.go", "b.go"} {
		e := evt(string(rune('1'+i)), "s", models.ToolClaudeCode, models.ActionReadFile, target, base.Add(time.Duration(i)*time.Second), true)
		e.ProjectRoot = root
		events = append(events, e)
	}
	for i := 0; i < 3; i++ {
		e := evt("c"+string(rune('0'+i)), "s", models.ToolClaudeCode, models.ActionRunCommand, "go test ./...", base.Add(time.Duration(10+i)*time.Second), true)
		e.ProjectRoot = root
		events = append(events, e)
	}
	ingest(t, database, root, events)
	if _, err := database.ExecContext(context.Background(),
		`UPDATE actions SET freshness = 'stale' WHERE source_event_id IN ('2', '3', '5')`); err != nil {
		t.Fatal(err)
	}

	full, err := New(database).Run(context.Background(), Options{ProjectRoot: root})
	if err != nil {
		t.Fatalf("full Run: %v", err)
	}
	only, err := New(database).Run(context.Background(), Options{ProjectRoot: root, StaleOnly: true})
	if err != nil {
		t.Fatalf("StaleOnly Run: %v", err)
	}
	if len(full.StaleReads) == 0 || len(full.RepeatedCommands) == 0 {
		t.Fatalf("fixture must exercise both sections: stale=%d repeated=%d", len(full.StaleReads), len(full.RepeatedCommands))
	}
	if len(only.StaleReads) != len(full.StaleReads) {
		t.Fatalf("stale rows: %d vs %d", len(only.StaleReads), len(full.StaleReads))
	}
	for i := range full.StaleReads {
		if only.StaleReads[i] != full.StaleReads[i] {
			t.Errorf("stale row %d: %+v vs %+v", i, only.StaleReads[i], full.StaleReads[i])
		}
	}
	fs, os := full.Summary, only.Summary
	if os.TotalActions != fs.TotalActions || os.StaleReadCount != fs.StaleReadCount ||
		os.CrossThreadStaleCount != fs.CrossThreadStaleCount || os.EstWastedTokens != fs.EstWastedTokens {
		t.Errorf("stale summary differs: %+v vs %+v", os, fs)
	}
	if len(only.RepeatedCommands) != 0 || len(only.CrossToolFiles) != 0 || len(only.NativeVsBash) != 0 ||
		os.RepeatedCmdGroups != 0 || os.CrossToolFileCount != 0 || os.NativeActionCount != 0 || os.BashActionCount != 0 {
		t.Errorf("StaleOnly must leave the other sections empty: %+v", only)
	}
}
