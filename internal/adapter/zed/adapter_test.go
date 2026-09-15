package zed

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	_ "modernc.org/sqlite"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// buildTestDB creates a fresh threads.db at dir/threads.db containing one
// row: id, the fixture JSON at fixturePath zstd-compressed into `data`,
// data_type="zstd", and the given created_at/updated_at TEXT values. It
// returns the db path.
func buildTestDB(t *testing.T, dir, id, fixturePath, createdAt, updatedAt string) string {
	t.Helper()
	plain, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	enc, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatalf("new zstd writer: %v", err)
	}
	defer enc.Close()
	compressed := enc.EncodeAll(plain, nil)

	dbPath := filepath.Join(dir, dbName)
	db, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	if _, err := db.Exec(`CREATE TABLE threads (
		id TEXT PRIMARY KEY, summary TEXT, updated_at TEXT NOT NULL,
		data_type TEXT NOT NULL, data BLOB NOT NULL, parent_id TEXT,
		folder_paths TEXT, folder_paths_order TEXT, created_at TEXT
	)`); err != nil {
		t.Fatalf("create table: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO threads (id, summary, updated_at, data_type, data, parent_id, created_at)
		 VALUES (?, ?, ?, 'zstd', ?, NULL, ?)`,
		id, "", updatedAt, compressed, createdAt,
	); err != nil {
		t.Fatalf("insert: %v", err)
	}
	return dbPath
}

// upsertThread replaces (or inserts) one row directly, for tests that
// simulate a turn advancing updated_at.
func upsertThread(t *testing.T, dbPath, id, fixturePath, createdAt, updatedAt string) {
	t.Helper()
	plain, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	enc, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatalf("new zstd writer: %v", err)
	}
	defer enc.Close()
	compressed := enc.EncodeAll(plain, nil)

	db, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(
		`INSERT INTO threads (id, summary, updated_at, data_type, data, parent_id, created_at)
		 VALUES (?, ?, ?, 'zstd', ?, NULL, ?)
		 ON CONFLICT(id) DO UPDATE SET updated_at=excluded.updated_at, data=excluded.data`,
		id, "", updatedAt, compressed, createdAt,
	); err != nil {
		t.Fatalf("upsert: %v", err)
	}
}

const fixturePath = "../../../testdata/zed/thread.json"

func countByAction(events []models.ToolEvent, action string) int {
	n := 0
	for _, e := range events {
		if e.ActionType == action {
			n++
		}
	}
	return n
}

func findEvent(events []models.ToolEvent, rawToolName string) (models.ToolEvent, bool) {
	for _, e := range events {
		if e.RawToolName == rawToolName {
			return e, true
		}
	}
	return models.ToolEvent{}, false
}

func TestParseSessionFile_FullThread(t *testing.T) {
	dir := t.TempDir()
	dbPath := buildTestDB(t, dir, "thread-1", fixturePath,
		"2026-09-06T08:18:35.820504Z", "2026-09-06T08:23:26.777724900Z")

	a := New()
	res, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.Warnings) != 0 {
		t.Errorf("unexpected warnings: %v", res.Warnings)
	}
	if res.NewOffset <= 0 {
		t.Fatalf("NewOffset = %d, want > 0", res.NewOffset)
	}
	wantOffset, _ := parseRFC3339("2026-09-06T08:23:26.777724900Z")
	if res.NewOffset != wantOffset.UnixNano() {
		t.Errorf("NewOffset = %d, want %d", res.NewOffset, wantOffset.UnixNano())
	}

	// 2 user prompts + 3 assistant text rows (1 in the first Agent
	// message, 2 in the second) + 7 tool calls = 12.
	if got := len(res.ToolEvents); got != 12 {
		t.Fatalf("len(ToolEvents) = %d, want 12: %+v", got, res.ToolEvents)
	}
	if got := countByAction(res.ToolEvents, models.ActionUserPrompt); got != 2 {
		t.Errorf("user prompts = %d, want 2", got)
	}
	if got := countByAction(res.ToolEvents, models.ActionAssistantMessage); got != 3 {
		t.Errorf("assistant messages = %d, want 3", got)
	}

	// Tool taxonomy mapping.
	wantActions := map[string]string{
		"list_directory": models.ActionSearchFiles,
		"find_path":      models.ActionSearchFiles,
		"write_file":     models.ActionWriteFile,
		"terminal":       models.ActionRunCommand,
		"edit_file":      models.ActionEditFile,
		"delete_path":    models.ActionEditFile,
	}
	for raw, wantAction := range wantActions {
		ev, ok := findEvent(res.ToolEvents, raw)
		if !ok {
			t.Errorf("no event found for raw tool %q", raw)
			continue
		}
		if ev.ActionType != wantAction {
			t.Errorf("tool %q: ActionType = %q, want %q", raw, ev.ActionType, wantAction)
		}
		if ev.Model != "gpt-5.6-luna" {
			t.Errorf("tool %q: Model = %q, want gpt-5.6-luna", raw, ev.Model)
		}
	}

	// The canceled terminal call: is_error true, outcome carried through.
	term, ok := findEvent(res.ToolEvents, "terminal")
	if !ok {
		t.Fatal("terminal event not found")
	}
	if term.Success {
		t.Error("terminal call-004 should be Success=false (is_error:true)")
	}
	if term.ErrorMessage != "Tool canceled by user" {
		t.Errorf("terminal ErrorMessage = %q, want %q", term.ErrorMessage, "Tool canceled by user")
	}
	if term.OutcomePending {
		t.Error("terminal call has a tool_results entry; OutcomePending should be false")
	}

	// delete_path succeeded.
	del, ok := findEvent(res.ToolEvents, "delete_path")
	if !ok {
		t.Fatal("delete_path event not found")
	}
	if !del.Success {
		t.Error("delete_path should be Success=true")
	}
	if del.ToolOutput == "" {
		t.Error("delete_path ToolOutput should carry the tool_results content text")
	}

	// Token events: net input carried straight through, no subtraction.
	if got := len(res.TokenEvents); got != 2 {
		t.Fatalf("len(TokenEvents) = %d, want 2", got)
	}
	byMsg := map[string]models.TokenEvent{}
	for _, te := range res.TokenEvents {
		byMsg[te.MessageID] = te
	}
	first, ok := byMsg["msg-user-1"]
	if !ok {
		t.Fatal("no token event for msg-user-1")
	}
	if first.InputTokens != 500 {
		t.Errorf("InputTokens = %d, want 500 (already net — no subtraction)", first.InputTokens)
	}
	if first.CacheReadTokens != 9000 {
		t.Errorf("CacheReadTokens = %d, want 9000", first.CacheReadTokens)
	}
	if first.OutputTokens != 120 {
		t.Errorf("OutputTokens = %d, want 120", first.OutputTokens)
	}
	if first.Source != models.TokenSourceJSONL || first.Reliability != models.ReliabilityAccurate {
		t.Errorf("Source/Reliability = %s/%s, want jsonl/accurate", first.Source, first.Reliability)
	}

	// Surface stamp.
	if len(res.SessionSurfaces) != 1 {
		t.Fatalf("len(SessionSurfaces) = %d, want 1", len(res.SessionSurfaces))
	}
	surf := res.SessionSurfaces[0]
	if surf.SessionID != "thread-1" || surf.Surface != models.SurfaceIDE || surf.SurfaceHost != "zed" {
		t.Errorf("surface = %+v, want {thread-1 ide zed}", surf)
	}

	// Project root: /w/project doesn't exist on the test host, so
	// git.Resolve's stat-gate fails and the raw worktree path (after
	// crossmount translation) is used verbatim, with the JSON's own
	// git_state as the branch/remote fallback.
	for _, e := range res.ToolEvents {
		if e.GitBranch != "main" {
			t.Errorf("event %s: GitBranch = %q, want main", e.SourceEventID, e.GitBranch)
		}
		if e.GitRemote != "" {
			t.Errorf("event %s: GitRemote = %q, want empty (remote_url was null)", e.SourceEventID, e.GitRemote)
		}
	}
}

func TestParseSessionFile_NoAdvanceNoReEmit(t *testing.T) {
	dir := t.TempDir()
	dbPath := buildTestDB(t, dir, "thread-1", fixturePath,
		"2026-09-06T08:18:35.820504Z", "2026-09-06T08:23:26.777724900Z")

	a := New()
	first, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("first parse: %v", err)
	}

	second, err := a.ParseSessionFile(context.Background(), dbPath, first.NewOffset)
	if err != nil {
		t.Fatalf("second parse: %v", err)
	}
	if len(second.ToolEvents) != 0 || len(second.TokenEvents) != 0 || len(second.SessionSurfaces) != 0 {
		t.Errorf("unchanged updated_at should re-emit nothing: %+v", second)
	}
	if second.NewOffset != first.NewOffset {
		t.Errorf("NewOffset drifted on a no-op poll: got %d, want %d", second.NewOffset, first.NewOffset)
	}
}

func TestParseSessionFile_AdvanceReReads(t *testing.T) {
	dir := t.TempDir()
	dbPath := buildTestDB(t, dir, "thread-1", fixturePath,
		"2026-09-06T08:18:35.820504Z", "2026-09-06T08:23:26.777724900Z")

	a := New()
	first, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("first parse: %v", err)
	}

	// Simulate a new turn: the row is rewritten with a LATER updated_at
	// (the same JSON body is fine — the point is the watermark moved).
	advanced := time.Unix(0, first.NewOffset).UTC().Add(1 * time.Hour).Format(time.RFC3339Nano)
	upsertThread(t, dbPath, "thread-1", fixturePath, "2026-09-06T08:18:35.820504Z", advanced)

	second, err := a.ParseSessionFile(context.Background(), dbPath, first.NewOffset)
	if err != nil {
		t.Fatalf("second parse: %v", err)
	}
	if len(second.ToolEvents) == 0 {
		t.Error("advanced updated_at should re-cover the whole thread, got zero ToolEvents")
	}
	if second.NewOffset <= first.NewOffset {
		t.Errorf("NewOffset should advance past the first watermark: got %d, want > %d", second.NewOffset, first.NewOffset)
	}
}

// TestParseSessionFile_RescanFromZeroIsIdempotent exercises the
// `observer backfill --zed-rescan` shape: the watcher resets the
// stored cursor to offset 0 (see internal/watcher/watcher.go's
// forceFromZero) and re-parses threads.db from scratch, potentially
// more than once (a re-run of the flag, or --all combined with
// --zed-rescan on a daemon that already ran it). Two independent
// fromOffset=0 parses of an UNCHANGED threads.db must emit the exact
// same rows with the exact same deterministic SourceEventIDs — that's
// what makes re-ingesting them through the store's
// (source_file, source_event_id) UNIQUE index a no-op instead of a
// duplicate.
func TestParseSessionFile_RescanFromZeroIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	dbPath := buildTestDB(t, dir, "thread-1", fixturePath,
		"2026-09-06T08:18:35.820504Z", "2026-09-06T08:23:26.777724900Z")

	a := New()
	first, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("first fromOffset=0 parse: %v", err)
	}
	if len(first.ToolEvents) == 0 {
		t.Fatal("first rescan-from-zero parse emitted zero ToolEvents")
	}

	second, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("second fromOffset=0 parse: %v", err)
	}

	if second.NewOffset != first.NewOffset {
		t.Errorf("NewOffset drifted across two identical rescans: got %d, want %d", second.NewOffset, first.NewOffset)
	}
	if len(second.ToolEvents) != len(first.ToolEvents) {
		t.Fatalf("len(ToolEvents) = %d on second rescan, want %d (same as first)", len(second.ToolEvents), len(first.ToolEvents))
	}
	if len(second.TokenEvents) != len(first.TokenEvents) {
		t.Fatalf("len(TokenEvents) = %d on second rescan, want %d (same as first)", len(second.TokenEvents), len(first.TokenEvents))
	}

	// The set of SourceEventIDs must match exactly — this is the
	// property the store's UNIQUE(source_file, source_event_id) index
	// relies on to make a repeated --zed-rescan a no-op rather than a
	// duplicate-row generator.
	firstIDs := map[string]int{}
	for _, e := range first.ToolEvents {
		firstIDs[e.SourceEventID]++
	}
	secondIDs := map[string]int{}
	for _, e := range second.ToolEvents {
		secondIDs[e.SourceEventID]++
	}
	if len(firstIDs) != len(first.ToolEvents) {
		t.Fatalf("first rescan produced duplicate SourceEventIDs within itself: %d unique of %d rows", len(firstIDs), len(first.ToolEvents))
	}
	for id, n := range firstIDs {
		if secondIDs[id] != n {
			t.Errorf("SourceEventID %q: first rescan count=%d, second rescan count=%d, want equal", id, n, secondIDs[id])
		}
	}
	for id, n := range secondIDs {
		if firstIDs[id] != n {
			t.Errorf("SourceEventID %q: appeared only on the second rescan (count=%d) — not idempotent", id, n)
		}
	}
}

func TestParseSessionFile_UnsupportedDataTypeSkipped(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, dbName)
	db, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE threads (
		id TEXT PRIMARY KEY, summary TEXT, updated_at TEXT NOT NULL,
		data_type TEXT NOT NULL, data BLOB NOT NULL, parent_id TEXT,
		folder_paths TEXT, folder_paths_order TEXT, created_at TEXT
	)`); err != nil {
		t.Fatalf("create table: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO threads (id, summary, updated_at, data_type, data, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		"thread-x", "", "2026-09-06T08:23:26.777724900Z", "future-encoding", []byte("whatever"),
		"2026-09-06T08:18:35.820504Z",
	); err != nil {
		t.Fatalf("insert: %v", err)
	}
	db.Close()

	a := New()
	res, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.ToolEvents) != 0 || len(res.TokenEvents) != 0 {
		t.Errorf("unsupported data_type should emit nothing: %+v", res)
	}
	if len(res.Warnings) == 0 {
		t.Error("expected a warning for the unsupported data_type")
	}
	if res.NewOffset <= 0 {
		t.Error("cursor should still advance past a permanently-unrecoverable row")
	}
}

func TestDecodeTaggedBlock(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		wantOK  bool
		wantKnd blockKind
	}{
		{"text", `{"Text":"hello"}`, true, blockText},
		{"thinking", `{"Thinking":{"text":"reasoning here","signature":null}}`, true, blockThinking},
		{"tooluse", `{"ToolUse":{"id":"c1","name":"read_file","raw_input":"{}"}}`, true, blockToolUse},
		{"unknown-kind", `{"FutureBlockKind":{"foo":"bar"}}`, true, blockUnknown},
		{"malformed", `not-json`, false, blockUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, ok := decodeTaggedBlock(json.RawMessage(tc.raw))
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && b.kind != tc.wantKnd {
				t.Errorf("kind = %v, want %v", b.kind, tc.wantKnd)
			}
		})
	}
}

// TestUnknownBlockKindIsSkippedNotFatal exercises a full Agent message
// whose content carries a block kind this adapter doesn't recognize —
// it must be silently skipped, not fatal, and not fabricated into a row.
func TestUnknownBlockKindIsSkippedNotFatal(t *testing.T) {
	a := New()
	am := zedAgentMessage{
		Content: []json.RawMessage{
			json.RawMessage(`{"Text":"hello"}`),
			json.RawMessage(`{"SomeNewBlockKind":{"whatever":true}}`),
		},
	}
	pr := &adapter.ParseResult{}
	// Route through the real emission path so a future block-kind
	// addition to the switch is exercised the same way production data
	// would hit it.
	a.emitAgentMessage(pr, "path", "sess", "root", "branch", "remote", time.Time{}, 0, am, "model", false)
	if len(pr.ToolEvents) != 1 {
		t.Fatalf("expected exactly 1 emitted row (the Text block), got %d: %+v", len(pr.ToolEvents), pr.ToolEvents)
	}
	if pr.ToolEvents[0].ActionType != models.ActionAssistantMessage {
		t.Errorf("ActionType = %q, want assistant_message", pr.ToolEvents[0].ActionType)
	}
}

func TestMapZedTool(t *testing.T) {
	cases := map[string]string{
		"read_file":        models.ActionReadFile,
		"write_file":       models.ActionWriteFile,
		"edit_file":        models.ActionEditFile,
		"delete_path":      models.ActionEditFile,
		"list_directory":   models.ActionSearchFiles,
		"find_path":        models.ActionSearchFiles,
		"terminal":         models.ActionRunCommand,
		"some_future_tool": models.ActionUnknown,
	}
	for name, want := range cases {
		if got := mapZedTool(name); got != want {
			t.Errorf("mapZedTool(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestIsSessionFile(t *testing.T) {
	root := filepath.Join("C:", "Users", "u", "AppData", "Local", "Zed", "threads")
	a := NewWithOptions(nil, root)
	cases := []struct {
		path string
		want bool
	}{
		{filepath.Join(root, "threads.db"), true},
		{filepath.Join(root, "threads.db-wal"), true},
		{filepath.Join(root, "threads.db-shm"), true},
		{filepath.Join(root, "settings.json"), false},
		{filepath.Join("D:", "foreign", "Zed", "threads", "threads.db"), false},
	}
	for _, tc := range cases {
		if got := a.IsSessionFile(tc.path); got != tc.want {
			t.Errorf("IsSessionFile(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}
