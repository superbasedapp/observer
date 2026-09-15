package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/taskflow"
)

// seedTaskflowSession creates a minimal project+session pair so
// InsertActions' foreign-key constraints against sessions AND projects
// are satisfied, and returns the project id every test action row must
// carry as ProjectID.
func seedTaskflowSession(t *testing.T, s *Store, ctx context.Context, sessionID string) int64 {
	t.Helper()
	pid, err := s.UpsertProject(ctx, "/tmp/taskflow-"+sessionID, "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	if err := s.UpsertSession(ctx, models.Session{
		ID: sessionID, ProjectID: pid, Tool: models.ToolClaudeCode, StartedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("UpsertSession: %v", err)
	}
	return pid
}

func TestIngest_TaskTracking_Disabled_IsNoop(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	pid := seedTaskflowSession(t, s, ctx, "s1")
	// SetTasksEnabled never called — zero value is false.

	batch := []models.Action{{
		SessionID: "s1", ProjectID: pid, Timestamp: time.Now().UTC(), ActionType: models.ActionTodoUpdate,
		Tool: models.ToolClaudeCode, RawToolName: "TaskUpdate",
		RawToolInput: `{"status":"in_progress","taskId":"1"}`,
		SourceFile:   "f.jsonl", SourceEventID: "e1",
	}}
	if _, err := s.InsertActions(ctx, batch); err != nil {
		t.Fatal(err)
	}
	if _, err := s.applyTaskEvents(ctx, batch); err != nil {
		t.Fatal(err)
	}
	items, err := s.LoadTaskItems(ctx, "s1")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Errorf("want no task_items rows while [tasks].enabled is false, got %+v", items)
	}
}

func TestIngest_TaskTracking_ClaudeCodeTaskLifecycle(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	s.SetTasksEnabled(true)
	ctx := context.Background()
	pid := seedTaskflowSession(t, s, ctx, "s1")

	base := time.Date(2026, 9, 7, 10, 0, 0, 0, time.UTC)
	batch := []models.Action{
		{
			SessionID: "s1", ProjectID: pid, Timestamp: base, ActionType: models.ActionTodoUpdate,
			Tool: models.ToolClaudeCode, RawToolName: "TaskCreate",
			RawToolInput:  `{"subject":"Ship the feature","activeForm":"Shipping"}`,
			RawToolOutput: `Task #1 created successfully: Ship the feature`,
			SourceFile:    "f.jsonl", SourceEventID: "toolu_create",
		},
		{
			SessionID: "s1", ProjectID: pid, Timestamp: base.Add(time.Minute), ActionType: models.ActionTodoUpdate,
			Tool: models.ToolClaudeCode, RawToolName: "TaskUpdate",
			RawToolInput: `{"status":"in_progress","taskId":"1"}`,
			SourceFile:   "f.jsonl", SourceEventID: "toolu_update1",
		},
		{
			SessionID: "s1", ProjectID: pid, Timestamp: base.Add(5 * time.Minute), ActionType: models.ActionTodoUpdate,
			Tool: models.ToolClaudeCode, RawToolName: "TaskUpdate",
			RawToolInput: `{"status":"completed","taskId":"1"}`,
			SourceFile:   "f.jsonl", SourceEventID: "toolu_update2",
		},
	}
	if _, err := s.InsertActions(ctx, batch); err != nil {
		t.Fatal(err)
	}
	if _, err := s.applyTaskEvents(ctx, batch); err != nil {
		t.Fatal(err)
	}

	items, err := s.LoadTaskItems(ctx, "s1")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("want 1 task item, got %+v", items)
	}
	if items[0].Key != "1" || items[0].Status != taskflow.StatusCompleted || items[0].Content != "Ship the feature" {
		t.Errorf("item = %+v", items[0])
	}

	transitions, err := s.LoadTaskTransitions(ctx, "s1")
	if err != nil {
		t.Fatal(err)
	}
	if len(transitions) != 3 {
		t.Fatalf("want 3 transitions (create/pending, ->in_progress, ->completed), got %+v", transitions)
	}

	summaries := taskflow.Summarize(transitions, base.Add(10*time.Minute))
	if len(summaries) != 1 || summaries[0].Elapsed != 4*time.Minute {
		t.Errorf("summaries = %+v, want 4m elapsed", summaries)
	}
}

func TestIngest_TaskTracking_FailedUpdateSkipped(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	s.SetTasksEnabled(true)
	ctx := context.Background()
	pid := seedTaskflowSession(t, s, ctx, "s1")

	batch := []models.Action{{
		SessionID: "s1", ProjectID: pid, Timestamp: time.Now().UTC(), ActionType: models.ActionTodoUpdate,
		Tool: models.ToolClaudeCode, RawToolName: "TaskUpdate",
		RawToolInput:  `{"status":"deleted","taskId":"3"}`,
		RawToolOutput: `<tool_use_error>Task not found</tool_use_error>`,
		SourceFile:    "f.jsonl", SourceEventID: "e1",
	}}
	if _, err := s.InsertActions(ctx, batch); err != nil {
		t.Fatal(err)
	}
	if _, err := s.applyTaskEvents(ctx, batch); err != nil {
		t.Fatal(err)
	}
	items, err := s.LoadTaskItems(ctx, "s1")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Errorf("a rejected update must not create a task_items row, got %+v", items)
	}
}

func TestIngest_TaskTracking_SnapshotVanishBookkeeping(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	s.SetTasksEnabled(true)
	ctx := context.Background()
	pid := seedTaskflowSession(t, s, ctx, "s1")

	base := time.Date(2026, 9, 7, 10, 0, 0, 0, time.UTC)
	first := []models.Action{{
		SessionID: "s1", ProjectID: pid, Timestamp: base, ActionType: models.ActionTodoUpdate,
		Tool: models.ToolClaudeCode, RawToolName: "TodoWrite",
		RawToolInput: `{"todos":[{"content":"keep me","status":"pending"},{"content":"drop me","status":"pending"}]}`,
		SourceFile:   "f.jsonl", SourceEventID: "e1",
	}}
	if _, err := s.InsertActions(ctx, first); err != nil {
		t.Fatal(err)
	}
	if _, err := s.applyTaskEvents(ctx, first); err != nil {
		t.Fatal(err)
	}
	second := []models.Action{{
		SessionID: "s1", ProjectID: pid, Timestamp: base.Add(time.Minute), ActionType: models.ActionTodoUpdate,
		Tool: models.ToolClaudeCode, RawToolName: "TodoWrite",
		RawToolInput: `{"todos":[{"content":"keep me","status":"completed"}]}`,
		SourceFile:   "f.jsonl", SourceEventID: "e2",
	}}
	if _, err := s.InsertActions(ctx, second); err != nil {
		t.Fatal(err)
	}
	if _, err := s.applyTaskEvents(ctx, second); err != nil {
		t.Fatal(err)
	}

	items, err := s.LoadTaskItems(ctx, "s1")
	if err != nil {
		t.Fatal(err)
	}
	byContent := map[string]TaskItemRow{}
	for _, it := range items {
		byContent[it.Content] = it
	}
	if got := byContent["keep me"]; got.Unmatched || got.Status != taskflow.StatusCompleted {
		t.Errorf("keep me = %+v, want matched+completed", got)
	}
	if got := byContent["drop me"]; !got.Unmatched {
		t.Errorf("drop me = %+v, want unmatched=true (vanished from the second snapshot)", got)
	}

	n, err := s.LoadTaskUnmatchedCount(ctx, "s1")
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("unmatched count = %d, want 1", n)
	}
}

// TestIngest_TaskTracking_VanishWhileInProgressClosesWindow is FIX-2: a
// Snapshot rewrite that drops an item last-known in_progress must not
// leave that item's open interval open forever. The store seam should
// synthesize an in_progress -> vanished transition at the second
// snapshot's own ts, AND flip task_items.status/raw_status to
// 'vanished' so the two tables agree.
func TestIngest_TaskTracking_VanishWhileInProgressClosesWindow(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	s.SetTasksEnabled(true)
	ctx := context.Background()
	pid := seedTaskflowSession(t, s, ctx, "s1")

	base := time.Date(2026, 9, 7, 10, 0, 0, 0, time.UTC)
	first := []models.Action{{
		SessionID: "s1", ProjectID: pid, Timestamp: base, ActionType: models.ActionTodoUpdate,
		Tool: models.ToolClaudeCode, RawToolName: "TodoWrite",
		RawToolInput: `{"todos":[{"content":"vanishes mid-flight","status":"in_progress"}]}`,
		SourceFile:   "f.jsonl", SourceEventID: "e1",
	}}
	if _, err := s.InsertActions(ctx, first); err != nil {
		t.Fatal(err)
	}
	if _, err := s.applyTaskEvents(ctx, first); err != nil {
		t.Fatal(err)
	}

	// Second snapshot no longer lists the item at all.
	second := []models.Action{{
		SessionID: "s1", ProjectID: pid, Timestamp: base.Add(3 * time.Minute), ActionType: models.ActionTodoUpdate,
		Tool: models.ToolClaudeCode, RawToolName: "TodoWrite",
		RawToolInput: `{"todos":[]}`,
		SourceFile:   "f.jsonl", SourceEventID: "e2",
	}}
	if _, err := s.InsertActions(ctx, second); err != nil {
		t.Fatal(err)
	}
	if _, err := s.applyTaskEvents(ctx, second); err != nil {
		t.Fatal(err)
	}

	items, err := s.LoadTaskItems(ctx, "s1")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("items = %+v", items)
	}
	it := items[0]
	if !it.Unmatched || it.Status != taskflow.StatusVanished || it.RawStatus != taskflow.StatusVanished {
		t.Errorf("item = %+v, want unmatched + status/raw_status=vanished", it)
	}

	transitions, err := s.LoadTaskTransitions(ctx, "s1")
	if err != nil {
		t.Fatal(err)
	}
	var sawVanish bool
	for _, tr := range transitions {
		if tr.ToStatus == taskflow.StatusVanished {
			sawVanish = true
			if tr.FromStatus != taskflow.StatusInProgress {
				t.Errorf("vanish transition from_status = %q, want in_progress", tr.FromStatus)
			}
			if !tr.Ts.Equal(base.Add(3 * time.Minute)) {
				t.Errorf("vanish transition ts = %v, want the closing snapshot's ts", tr.Ts)
			}
		}
	}
	if !sawVanish {
		t.Fatalf("no in_progress -> vanished transition recorded, got %+v", transitions)
	}

	// The open interval must be CLOSED, not left running forever.
	intervals := taskflow.BuildOpenIntervals(transitions)
	for _, iv := range intervals {
		if !iv.HasEnd {
			t.Errorf("interval %+v is still open after the item vanished", iv)
		}
	}
}

func TestIngest_TaskTracking_PostToolBatchDedupedAgainstDirectAction(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	s.SetTasksEnabled(true)
	ctx := context.Background()
	pid := seedTaskflowSession(t, s, ctx, "s1")

	ts := time.Now().UTC()
	// The SAME TaskUpdate call, captured both as its own actions row and
	// echoed inside a post_tool_batch envelope sharing the same
	// tool_use_id — must apply exactly one transition (§R2.6 item 3).
	batch := []models.Action{
		{
			SessionID: "s1", ProjectID: pid, Timestamp: ts, ActionType: models.ActionTodoUpdate,
			Tool: models.ToolClaudeCode, RawToolName: "TaskUpdate",
			RawToolInput: `{"status":"completed","taskId":"9"}`,
			SourceFile:   "f.jsonl", SourceEventID: "toolu_dup",
		},
		{
			SessionID: "s1", ProjectID: pid, Timestamp: ts.Add(time.Millisecond), ActionType: "post_tool_batch",
			Tool:         models.ToolClaudeCode,
			RawToolInput: `[{"tool_name":"TaskUpdate","tool_use_id":"toolu_dup","tool_input":{"status":"completed","taskId":"9"},"tool_response":"Updated task #9 status"}]`,
			SourceFile:   "f.jsonl", SourceEventID: "batch1",
		},
	}
	if _, err := s.InsertActions(ctx, batch); err != nil {
		t.Fatal(err)
	}
	if _, err := s.applyTaskEvents(ctx, batch); err != nil {
		t.Fatal(err)
	}
	transitions, err := s.LoadTaskTransitions(ctx, "s1")
	if err != nil {
		t.Fatal(err)
	}
	if len(transitions) != 1 {
		t.Errorf("want exactly 1 deduped transition, got %+v", transitions)
	}
}

// TestIngest_TaskTracking_EmptySourceEventIDSynthesizesPerAction is
// FIX-6: task_transitions.source_event_id is NOT NULL DEFAULT ” under
// UNIQUE(session_id, key, source_event_id) (migration 109). A tool
// shape with no vendor id for the CALL itself (poolside's flat
// todo_action, content-keyed) leaves ev.SourceEventID empty on every
// call — two REAL, distinct transitions on the same key would collide
// on the identical (session_id, key, ”) triple and the second would
// be silently dropped by INSERT OR IGNORE without the aid:<action id>
// synthesis.
func TestIngest_TaskTracking_EmptySourceEventIDSynthesizesPerAction(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	s.SetTasksEnabled(true)
	ctx := context.Background()
	pid := seedTaskflowSession(t, s, ctx, "s1")

	// Distinct SourceFile per row: InsertActions dedupes on the actions
	// table's own (source_file, source_event_id) UNIQUE index, so three
	// rows sharing BOTH an empty source_event_id AND one source_file
	// would collapse into a single upserted row before ever reaching
	// task-tracking — a store-layer concern this test must route around
	// to actually exercise three DISTINCT actions rows, each still
	// carrying taskflow's own empty source_event_id.
	base := time.Date(2026, 9, 7, 10, 0, 0, 0, time.UTC)
	batch := []models.Action{
		{
			SessionID: "s1", ProjectID: pid, Timestamp: base, ActionType: models.ActionTodoUpdate,
			Tool: models.ToolPoolside, RawToolName: "todo_action",
			RawToolInput: `{"action":"add","content":"write the plan"}`,
			SourceFile:   "f1.jsonl", SourceEventID: "",
		},
		{
			SessionID: "s1", ProjectID: pid, Timestamp: base.Add(time.Minute), ActionType: models.ActionTodoUpdate,
			Tool: models.ToolPoolside, RawToolName: "todo_action",
			RawToolInput: `{"action":"set_in_progress","content":"write the plan"}`,
			SourceFile:   "f2.jsonl", SourceEventID: "",
		},
		{
			SessionID: "s1", ProjectID: pid, Timestamp: base.Add(2 * time.Minute), ActionType: models.ActionTodoUpdate,
			Tool: models.ToolPoolside, RawToolName: "todo_action",
			RawToolInput: `{"action":"complete","content":"write the plan"}`,
			SourceFile:   "f3.jsonl", SourceEventID: "",
		},
	}
	if _, err := s.InsertActions(ctx, batch); err != nil {
		t.Fatal(err)
	}
	if _, err := s.applyTaskEvents(ctx, batch); err != nil {
		t.Fatal(err)
	}

	transitions, err := s.LoadTaskTransitions(ctx, "s1")
	if err != nil {
		t.Fatal(err)
	}
	// pending -> in_progress -> completed: 3 transitions total (the
	// first-observed pending counts as one), none dropped despite every
	// call carrying an empty source_event_id.
	if len(transitions) != 3 {
		t.Fatalf("want 3 transitions (none dropped by the empty source_event_id collision), got %+v", transitions)
	}
}

func TestBackfillTaskItems_ReDerivesFromExistingRows(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	// tasksEnabled deliberately left false — backfill must run regardless.
	ctx := context.Background()
	pid := seedTaskflowSession(t, s, ctx, "s1")

	batch := []models.Action{{
		SessionID: "s1", ProjectID: pid, Timestamp: time.Now().UTC(), ActionType: models.ActionTodoUpdate,
		Tool: models.ToolClaudeCode, RawToolName: "TaskUpdate",
		RawToolInput: `{"status":"in_progress","taskId":"5"}`,
		SourceFile:   "f.jsonl", SourceEventID: "e1",
	}}
	if _, err := s.InsertActions(ctx, batch); err != nil {
		t.Fatal(err)
	}
	// Confirm the ingest-time seam really did nothing (feature off).
	if items, _ := s.LoadTaskItems(ctx, "s1"); len(items) != 0 {
		t.Fatalf("expected no rows pre-backfill, got %+v", items)
	}

	res, err := s.BackfillTaskItems(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.ActionsScanned != 1 || res.TransitionsWritten != 1 {
		t.Errorf("backfill result = %+v", res)
	}
	items, err := s.LoadTaskItems(ctx, "s1")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Key != "5" {
		t.Fatalf("items = %+v", items)
	}

	// Idempotent re-run: no new transitions.
	res2, err := s.BackfillTaskItems(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if res2.TransitionsWritten != 0 {
		t.Errorf("re-run wrote %d new transitions, want 0 (idempotent)", res2.TransitionsWritten)
	}
}

// TestBackfillTaskItems_PagesLargeCorpusAndSkipsIneligibleRows is
// FIX-3: BackfillTaskItems must page a large eligible set (rather than
// materialize it all in one slice — the unbounded version measured
// ~119MB for 26,995 post_tool_batch rows on the grounding corpus) AND
// must exclude task_complete rows plus post_tool_batch rows that carry
// no registered decoder tool name at all, without needing
// json.Unmarshal to find that out.
func TestBackfillTaskItems_PagesLargeCorpusAndSkipsIneligibleRows(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	pid := seedTaskflowSession(t, s, ctx, "s1")

	const eligible = 1050 // > 2*taskBackfillPageSize, forces 3 pages
	base := time.Now().UTC()
	var batch []models.Action
	for i := 0; i < eligible; i++ {
		batch = append(batch, models.Action{
			SessionID: "s1", ProjectID: pid, Timestamp: base.Add(time.Duration(i) * time.Millisecond),
			ActionType: models.ActionTodoUpdate, Tool: models.ToolClaudeCode, RawToolName: "TaskUpdate",
			RawToolInput: `{"status":"in_progress","taskId":"` + itoaTest(i) + `"}`,
			SourceFile:   "f.jsonl", SourceEventID: "e" + itoaTest(i),
		})
	}
	// Ineligible noise: a task_complete row (no decoder ever matches
	// it) and a post_tool_batch row whose envelope names a tool nobody
	// registered — both must be excluded from ActionsScanned by the SQL
	// filter itself, not merely produce zero transitions after a scan.
	batch = append(batch,
		models.Action{
			SessionID: "s1", ProjectID: pid, Timestamp: base.Add(time.Hour), ActionType: models.ActionTaskComplete,
			Tool: models.ToolClaudeCode, RawToolName: "TaskComplete", RawToolInput: `{}`,
			SourceFile: "f.jsonl", SourceEventID: "complete1",
		},
		models.Action{
			SessionID: "s1", ProjectID: pid, Timestamp: base.Add(2 * time.Hour), ActionType: "post_tool_batch",
			Tool:         models.ToolClaudeCode,
			RawToolInput: `[{"tool_name":"SomeUnrelatedTool","tool_use_id":"x1","tool_input":{},"tool_response":""}]`,
			SourceFile:   "f.jsonl", SourceEventID: "batch_noise",
		},
	)
	if _, err := s.InsertActions(ctx, batch); err != nil {
		t.Fatal(err)
	}

	res, err := s.BackfillTaskItems(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.ActionsScanned != eligible {
		t.Errorf("ActionsScanned = %d, want exactly %d (task_complete + unregistered post_tool_batch excluded)", res.ActionsScanned, eligible)
	}
	if res.TransitionsWritten != eligible {
		t.Errorf("TransitionsWritten = %d, want %d", res.TransitionsWritten, eligible)
	}

	items, err := s.LoadTaskItems(ctx, "s1")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != eligible {
		t.Fatalf("want %d distinct task_items rows across all pages, got %d", eligible, len(items))
	}
}

func itoaTest(i int) string { return fmt.Sprintf("%d", i) }

func TestLoadTaskTokenRows_ExcludesSidechainsByDefault(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	seedTaskflowSession(t, s, ctx, "s1")

	events := []models.TokenEvent{
		{
			SourceFile: "f.jsonl", SourceEventID: "tok1",
			SessionID: "s1", Timestamp: time.Now().UTC(), Tool: models.ToolClaudeCode,
			Model: "claude-x", InputTokens: 100, OutputTokens: 50, IsSidechain: false,
		},
		{
			SourceFile: "f.jsonl", SourceEventID: "tok2",
			SessionID: "s1", Timestamp: time.Now().UTC(), Tool: models.ToolClaudeCode,
			Model: "claude-x", InputTokens: 10, OutputTokens: 5, IsSidechain: true,
		},
	}
	if _, err := s.InsertTokenEvents(ctx, events); err != nil {
		t.Fatal(err)
	}

	rows, err := s.LoadTaskTokenRows(ctx, "s1", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].InputTokens != 100 {
		t.Errorf("rows = %+v, want only the non-sidechain row", rows)
	}

	all, err := s.LoadTaskTokenRows(ctx, "s1", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Errorf("includeSidechains=true rows = %+v, want 2", all)
	}

	sideOnly, err := s.LoadSidechainOnlyTaskTokenRows(ctx, "s1")
	if err != nil {
		t.Fatal(err)
	}
	if len(sideOnly) != 1 || sideOnly[0].InputTokens != 10 {
		t.Errorf("LoadSidechainOnlyTaskTokenRows = %+v, want just the sidechain row", sideOnly)
	}
}

func TestLoadTaskActionTimestamps(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	pid := seedTaskflowSession(t, s, ctx, "s1")

	base := time.Date(2026, 9, 7, 10, 0, 0, 0, time.UTC)
	batch := []models.Action{
		{SessionID: "s1", ProjectID: pid, Timestamp: base, ActionType: "user_prompt", Tool: models.ToolClaudeCode, SourceFile: "f.jsonl", SourceEventID: "a1"},
		{SessionID: "s1", ProjectID: pid, Timestamp: base.Add(time.Minute), ActionType: "user_prompt", Tool: models.ToolClaudeCode, SourceFile: "f.jsonl", SourceEventID: "a2", IsSidechain: true},
	}
	if _, err := s.InsertActions(ctx, batch); err != nil {
		t.Fatal(err)
	}

	nonSide, err := s.LoadTaskActionTimestamps(ctx, "s1", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(nonSide) != 1 || !nonSide[0].Equal(base) {
		t.Errorf("LoadTaskActionTimestamps(false) = %+v", nonSide)
	}

	all, err := s.LoadTaskActionTimestamps(ctx, "s1", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Errorf("LoadTaskActionTimestamps(true) = %+v, want 2", all)
	}
}

func TestSessionsWithTasksInWindow(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	s.SetTasksEnabled(true)
	ctx := context.Background()
	pid1 := seedTaskflowSession(t, s, ctx, "sIn")
	pid2 := seedTaskflowSession(t, s, ctx, "sOutOfWindow")
	pid3 := seedTaskflowSession(t, s, ctx, "sOtherProject")

	// sIn: started (per seedTaskflowSession) at time.Now() — inside any
	// reasonable window. Give it a task.
	inBatch := []models.Action{{
		SessionID: "sIn", ProjectID: pid1, Timestamp: time.Now().UTC(), ActionType: models.ActionTodoUpdate,
		Tool: models.ToolClaudeCode, RawToolName: "TaskUpdate", RawToolInput: `{"status":"pending","taskId":"1"}`,
		SourceFile: "f.jsonl", SourceEventID: "e1",
	}}
	if _, err := s.InsertActions(ctx, inBatch); err != nil {
		t.Fatal(err)
	}
	if _, err := s.applyTaskEvents(ctx, inBatch); err != nil {
		t.Fatal(err)
	}

	// sOutOfWindow: backdate started_at far in the past, add a task —
	// must be excluded by a `since` bound.
	if _, err := s.db.ExecContext(ctx, `UPDATE sessions SET started_at = '2000-01-01T00:00:00Z' WHERE id = 'sOutOfWindow'`); err != nil {
		t.Fatal(err)
	}
	outBatch := []models.Action{{
		SessionID: "sOutOfWindow", ProjectID: pid2, Timestamp: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), ActionType: models.ActionTodoUpdate,
		Tool: models.ToolClaudeCode, RawToolName: "TaskUpdate", RawToolInput: `{"status":"pending","taskId":"1"}`,
		SourceFile: "f2.jsonl", SourceEventID: "e1",
	}}
	if _, err := s.InsertActions(ctx, outBatch); err != nil {
		t.Fatal(err)
	}
	if _, err := s.applyTaskEvents(ctx, outBatch); err != nil {
		t.Fatal(err)
	}

	// sOtherProject: in-window, but a different project — excluded by a
	// projectID filter.
	otherBatch := []models.Action{{
		SessionID: "sOtherProject", ProjectID: pid3, Timestamp: time.Now().UTC(), ActionType: models.ActionTodoUpdate,
		Tool: models.ToolClaudeCode, RawToolName: "TaskUpdate", RawToolInput: `{"status":"pending","taskId":"1"}`,
		SourceFile: "f3.jsonl", SourceEventID: "e1",
	}}
	if _, err := s.InsertActions(ctx, otherBatch); err != nil {
		t.Fatal(err)
	}
	if _, err := s.applyTaskEvents(ctx, otherBatch); err != nil {
		t.Fatal(err)
	}

	all, err := s.SessionsWithTasksInWindow(ctx, time.Time{}, time.Time{}, 0, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Fatalf("unbounded window = %+v, want all 3 sessions", all)
	}

	sinceRecent := time.Now().UTC().Add(-time.Hour)
	windowed, err := s.SessionsWithTasksInWindow(ctx, sinceRecent, time.Time{}, 0, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(windowed) != 2 {
		t.Fatalf("windowed (since=1h ago) = %+v, want 2 (sIn + sOtherProject)", windowed)
	}

	scoped, err := s.SessionsWithTasksInWindow(ctx, time.Time{}, time.Time{}, pid1, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(scoped) != 1 || scoped[0].SessionID != "sIn" {
		t.Fatalf("project-scoped = %+v, want just sIn", scoped)
	}

	// FIX-B: the string-keyed project-root/tool filters (the dashboard's
	// global Analysis-page filters, which key on root_path/tool strings,
	// never a numeric project id) compose the same way projectID does.
	var pid1Root string
	if err := s.db.QueryRowContext(ctx, `SELECT root_path FROM projects WHERE id = ?`, pid1).Scan(&pid1Root); err != nil {
		t.Fatal(err)
	}
	byRoot, err := s.SessionsWithTasksInWindow(ctx, time.Time{}, time.Time{}, 0, pid1Root, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(byRoot) != 1 || byRoot[0].SessionID != "sIn" {
		t.Fatalf("project-root-scoped = %+v, want just sIn", byRoot)
	}

	byTool, err := s.SessionsWithTasksInWindow(ctx, time.Time{}, time.Time{}, 0, "", "claude-code")
	if err != nil {
		t.Fatal(err)
	}
	if len(byTool) != 3 {
		t.Fatalf("tool-scoped (claude-code, all 3 seeded as claude-code) = %+v, want all 3", byTool)
	}

	byOtherTool, err := s.SessionsWithTasksInWindow(ctx, time.Time{}, time.Time{}, 0, "", "codex")
	if err != nil {
		t.Fatal(err)
	}
	if len(byOtherTool) != 0 {
		t.Fatalf("tool-scoped (codex, none seeded) = %+v, want none", byOtherTool)
	}
}
