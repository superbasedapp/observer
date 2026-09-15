package store

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/loc"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// locEvent builds an edit/write ToolEvent for the LOC ingest tests.
func locEvent(sessionID, root, target, actionType, raw, eventID string, sidechain bool) models.ToolEvent {
	return models.ToolEvent{
		SessionID:     sessionID,
		ProjectRoot:   root,
		Target:        target,
		ActionType:    actionType,
		RawToolInput:  raw,
		RawToolName:   "Edit",
		Tool:          models.ToolClaudeCode,
		SourceFile:    "/tmp/session.jsonl",
		SourceEventID: eventID,
		IsSidechain:   sidechain,
		Timestamp:     time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC),
		Success:       true,
	}
}

// TestRecordFileChangesCountsAnEdit pins the live-ingest seam end to end:
// Ingest inserts the action, the LOC seam resolves it back by
// (source_file, source_event_id) and writes the counts.
func TestRecordFileChangesCountsAnEdit(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	events := []models.ToolEvent{
		locEvent("s1", "/repo", "/repo/a.go", models.ActionEditFile,
			`{"file_path":"/repo/a.go","old_string":"a := 1","new_string":"a := 2"}`,
			"ev1", false),
	}
	if _, err := s.Ingest(ctx, events, nil, IngestOptions{}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	got, err := s.LoadSessionLOC(ctx, "s1")
	if err != nil {
		t.Fatalf("LoadSessionLOC: %v", err)
	}
	if got.Files != 1 {
		t.Fatalf("files = %d, want 1 (buckets %+v)", got.Files, got.Buckets)
	}
	if len(got.Buckets) != 1 {
		t.Fatalf("buckets = %d, want 1: %+v", len(got.Buckets), got.Buckets)
	}
	b := got.Buckets[0]
	if b.Actor != LOCActorAI || b.Sidechain || b.Category != string(loc.CategoryCode) {
		t.Errorf("bucket = %+v, want ai/main/code", b)
	}
	if b.Stats.ModifiedCode != 1 {
		t.Errorf("modified_code = %d, want 1 (stats %+v)", b.Stats.ModifiedCode, b.Stats)
	}
	// With no editor reporting saves there is no human denominator, so
	// the payload must say so rather than implying 100% AI.
	if got.HumanCapture != "none" {
		t.Errorf("human_capture = %q, want %q", got.HumanCapture, "none")
	}
}

// TestRecordFileChangesIsIdempotent pins that re-ingesting the same
// transcript (the routine case — a watcher re-parse, a backfill rescan)
// does not double a single line.
func TestRecordFileChangesIsIdempotent(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	events := []models.ToolEvent{
		locEvent("s1", "/repo", "/repo/a.go", models.ActionEditFile,
			`{"file_path":"/repo/a.go","old_string":"a := 1\nb := 1","new_string":"a := 2\nb := 2"}`,
			"ev1", false),
	}
	for i := 0; i < 3; i++ {
		if _, err := s.Ingest(ctx, events, nil, IngestOptions{}); err != nil {
			t.Fatalf("Ingest %d: %v", i, err)
		}
	}
	got, err := s.LoadSessionLOC(ctx, "s1")
	if err != nil {
		t.Fatal(err)
	}
	var total loc.Stats
	for _, b := range got.Buckets {
		total.Add(b.Stats)
	}
	if total.ModifiedCode != 2 {
		t.Errorf("modified_code = %d after 3 ingests, want 2", total.ModifiedCode)
	}
	if got.Files != 1 {
		t.Errorf("files = %d, want 1", got.Files)
	}
}

// TestSidechainSplit pins acceptance criterion 8: a subagent's edits are
// AI work, but they must be separable from the developer's own agent
// turn — 47% of edit rows on the reference node are sidechain.
func TestSidechainSplit(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	events := []models.ToolEvent{
		locEvent("s1", "/repo", "/repo/main.go", models.ActionEditFile,
			`{"file_path":"/repo/main.go","old_string":"a := 1","new_string":"a := 2"}`,
			"ev-main", false),
		locEvent("s1", "/repo", "/repo/sub.go", models.ActionEditFile,
			`{"file_path":"/repo/sub.go","old_string":"b := 1","new_string":"b := 2\nc := 3"}`,
			"ev-sub", true),
	}
	if _, err := s.Ingest(ctx, events, nil, IngestOptions{}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	got, err := s.LoadSessionLOC(ctx, "s1")
	if err != nil {
		t.Fatal(err)
	}
	var main, side loc.Stats
	for _, b := range got.Buckets {
		if b.Sidechain {
			side.Add(b.Stats)
		} else {
			main.Add(b.Stats)
		}
	}
	if main.ModifiedCode != 1 || main.AddedCode != 0 {
		t.Errorf("main = %+v, want 1 modified", main)
	}
	if side.ModifiedCode != 1 || side.AddedCode != 1 {
		t.Errorf("sidechain = %+v, want 1 modified + 1 added", side)
	}
}

// TestBackfillLOCIsIdempotentAndVersionGated pins acceptance criterion 6:
// the backfill can be re-run at will, and a classifier-version bump is
// what replaces rows.
func TestBackfillLOCIsIdempotentAndVersionGated(t *testing.T) {
	t.Parallel()
	s, database := newTestStore(t)
	ctx := context.Background()

	events := []models.ToolEvent{
		locEvent("s1", "/repo", "/repo/a.go", models.ActionEditFile,
			`{"file_path":"/repo/a.go","old_string":"a := 1","new_string":"a := 2"}`,
			"ev1", false),
	}
	if _, err := s.Ingest(ctx, events, nil, IngestOptions{}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	countRows := func() int {
		var n int
		if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM file_changes`).Scan(&n); err != nil {
			t.Fatalf("count: %v", err)
		}
		return n
	}
	before := countRows()
	if before != 1 {
		t.Fatalf("rows after ingest = %d, want 1", before)
	}

	// A plain re-run must not even READ the already-counted action.
	res, err := s.BackfillLOC(ctx, BackfillLOCOptions{})
	if err != nil {
		t.Fatalf("BackfillLOC: %v", err)
	}
	if res.ActionsScanned != 0 {
		t.Errorf("re-run scanned %d actions, want 0 — the version guard should skip them",
			res.ActionsScanned)
	}
	if countRows() != before {
		t.Errorf("rows = %d after a no-op re-run, want %d", countRows(), before)
	}

	// --loc-rescan re-reads them; the row count still must not grow.
	res, err = s.BackfillLOC(ctx, BackfillLOCOptions{Rescan: true})
	if err != nil {
		t.Fatalf("BackfillLOC rescan: %v", err)
	}
	if res.ActionsScanned != 1 {
		t.Errorf("rescan scanned %d actions, want 1", res.ActionsScanned)
	}
	if countRows() != before {
		t.Errorf("rows = %d after a rescan, want %d — the upsert must replace, not append",
			countRows(), before)
	}

	// A dry run writes nothing.
	res, err = s.BackfillLOC(ctx, BackfillLOCOptions{Rescan: true, DryRun: true})
	if err != nil {
		t.Fatalf("BackfillLOC dry run: %v", err)
	}
	if res.RowsWritten != 0 {
		t.Errorf("dry run wrote %d rows, want 0", res.RowsWritten)
	}
	if got := res.PerSession["s1"]; got.ModifiedCode != 1 {
		t.Errorf("dry run per-session s1 = %+v, want 1 modified", got)
	}
}

// TestBackfillLOCLimitAndSince pin the two bounds the operator uses on a
// multi-gigabyte database.
func TestBackfillLOCLimitAndSince(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	var events []models.ToolEvent
	for i := 0; i < 5; i++ {
		e := locEvent("s1", "/repo", "/repo/a.go", models.ActionEditFile,
			`{"file_path":"/repo/a.go","old_string":"a := 1","new_string":"a := 2"}`,
			"ev"+string(rune('a'+i)), false)
		e.Timestamp = time.Date(2026, 9, i+1, 12, 0, 0, 0, time.UTC)
		events = append(events, e)
	}
	if _, err := s.Ingest(ctx, events, nil, IngestOptions{}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	res, err := s.BackfillLOC(ctx, BackfillLOCOptions{Rescan: true, Limit: 2, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.ActionsScanned != 2 {
		t.Errorf("--loc-limit 2 scanned %d, want 2", res.ActionsScanned)
	}

	res, err = s.BackfillLOC(ctx, BackfillLOCOptions{
		Rescan: true, DryRun: true,
		Since: time.Date(2026, 9, 4, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.ActionsScanned != 2 {
		t.Errorf("--loc-since 2026-09-04 scanned %d, want 2 (the 4th and 5th)", res.ActionsScanned)
	}
}

// TestRelativeProjectPath pins the hashing normalization (plan §2). The
// AI side and the editor side MUST agree on it, or a human save and the
// agent edit it echoes could never join.
func TestRelativeProjectPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		root string
		path string
		want string
	}{
		{"absolute under root", "/repo", "/repo/src/a.go", "src/a.go"},
		{"trailing slash on root", "/repo/", "/repo/src/a.go", "src/a.go"},
		{"already relative", "/repo", "src/a.go", "src/a.go"},
		{"dot-slash relative", "/repo", "./src/a.go", "src/a.go"},
		{"windows separators", `C:\proj`, `C:\proj\src\a.go`, "src/a.go"},
		{"windows drive-letter case", `c:\proj`, `C:\proj\src\a.go`, "src/a.go"},
		{"not under root stays distinct", "/repo", "/other/x.go", "other/x.go"},
		{"external pseudo path", "/repo", "[external]/x.go", "[external]/x.go"},
		{"empty path", "/repo", "", ""},
		{"empty root", "", "/abs/a.go", "abs/a.go"},
		// A prefix that only LOOKS like the root must not be stripped:
		// /repo-two is not inside /repo.
		{"prefix is not a path boundary", "/repo", "/repo-two/a.go", "repo-two/a.go"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RelativeProjectPath(tt.root, tt.path); got != tt.want {
				t.Errorf("RelativeProjectPath(%q, %q) = %q, want %q",
					tt.root, tt.path, got, tt.want)
			}
		})
	}
}

// TestCodexInvocationAndExecutorCollapseToOne pins acceptance criterion
// 2's last clause: codex emits the same patch twice, and the READ must
// count it once.
//
// THE FIXTURE IS THE TEST. It is the pair from the codex adapter's own
// fixture, testdata/codex/rollout-patch-pairing.jsonl lines 3 and 4
// (turn-A) — the model's JS-wrapped envelope with a bare `@@` and NO
// context, and the executor's unified_diff with the standard leading
// context line. The version this test shipped with gave BOTH sides an
// identical three-line body, a shape the real corpus never produces, so
// it passed while every codex patch in the live database was counted
// twice (review finding H2).
func TestCodexInvocationAndExecutorCollapseToOne(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	// rollout-patch-pairing.jsonl line 3: response_item / custom_tool_call.
	invocation := locEvent("s1", "/tmp/fx", "/tmp/fx/a.go", models.ActionEditFile,
		"const patch = \"*** Begin Patch\\n*** Update File: /tmp/fx/a.go\\n"+
			"@@\\n+var one = 1\\n*** End Patch\";\ntext(await tools.apply_patch(patch));\n",
		"call_HashOne", false)
	invocation.Tool = models.ToolCodex
	// rollout-patch-pairing.jsonl line 4: event_msg / patch_apply_end.
	executor := locEvent("s1", "/tmp/fx", "/tmp/fx/a.go", models.ActionEditFile,
		`{"/tmp/fx/a.go":{"type":"update","move_path":null,`+
			`"unified_diff":"@@ -1,1 +1,2 @@\n package main\n+var one = 1\n"}}`,
		"exec-aaaaaaaa-0000-0000-0000-000000000001", false)
	executor.Tool = models.ToolCodex

	if _, err := s.Ingest(ctx, []models.ToolEvent{invocation, executor}, nil, IngestOptions{}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	got, err := s.LoadSessionLOC(ctx, "s1")
	if err != nil {
		t.Fatal(err)
	}
	var total loc.Stats
	for _, b := range got.Buckets {
		total.Add(b.Stats)
	}
	if total.AddedCode != 1 || total.ModifiedCode != 0 {
		t.Errorf("added/modified = %d/%d, want 1/0 — the codex invocation/executor pair "+
			"double-counted (stats %+v, buckets %+v)",
			total.AddedCode, total.ModifiedCode, total, got.Buckets)
	}
	if got.Files != 1 {
		t.Errorf("files = %d, want 1", got.Files)
	}

	// The pair also has to collapse for a MODIFICATION, which is the
	// dominant real shape (an update hunk with both a - and a + line).
	mod := locEvent("s2", "/tmp/fx", "/tmp/fx/calc.py", models.ActionEditFile,
		"*** Begin Patch\n*** Update File: /tmp/fx/calc.py\n@@\n"+
			"-    return a - b\n+    return a + b\n*** End Patch",
		"call-mod", false)
	mod.Tool = models.ToolCodex
	modExec := locEvent("s2", "/tmp/fx", "/tmp/fx/calc.py", models.ActionEditFile,
		`{"/tmp/fx/calc.py":{"type":"update","move_path":null,`+
			`"unified_diff":"@@ -1,4 +1,4 @@\n def add(a, b):\n-    return a - b\n`+
			`+    return a + b\n\n\n"}}`,
		"call-mod-executor", false)
	modExec.Tool = models.ToolCodex
	if _, err := s.Ingest(ctx, []models.ToolEvent{mod, modExec}, nil, IngestOptions{}); err != nil {
		t.Fatalf("Ingest mod: %v", err)
	}
	gotMod, err := s.LoadSessionLOC(ctx, "s2")
	if err != nil {
		t.Fatal(err)
	}
	var modTotal loc.Stats
	for _, b := range gotMod.Buckets {
		modTotal.Add(b.Stats)
	}
	if modTotal.ModifiedCode != 1 {
		t.Errorf("modified_code = %d, want 1 — the modification pair double-counted "+
			"(stats %+v)", modTotal.ModifiedCode, modTotal)
	}
}

// TestLoadLOCByDayBucketsOnEventTime pins that a backfilled August action
// lands in August, not on the day the operator ran the backfill.
func TestLoadLOCByDayBucketsOnEventTime(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	e := locEvent("s1", "/repo", "/repo/a.go", models.ActionEditFile,
		`{"file_path":"/repo/a.go","old_string":"a := 1","new_string":"a := 2"}`,
		"ev1", false)
	e.Timestamp = time.Now().UTC().AddDate(0, 0, -10)
	if _, err := s.Ingest(ctx, []models.ToolEvent{e}, nil, IngestOptions{}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	days, err := s.LoadLOCByDay(ctx, 30, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(days) != 1 {
		t.Fatalf("days = %d, want 1: %+v", len(days), days)
	}
	want := e.Timestamp.Format("2006-01-02")
	if days[0].Day != want {
		t.Errorf("day = %q, want %q — the bucket must use the EVENT time, not ingest time",
			days[0].Day, want)
	}

	// A window that ends before the event excludes it.
	narrow, err := s.LoadLOCByDay(ctx, 3, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(narrow) != 0 {
		t.Errorf("3-day window returned %d rows, want 0", len(narrow))
	}
}

// TestGeneratedFileIsRecordedButNotCounted pins acceptance criterion 5 at
// the store level: a lockfile produces a ROW (so the UI can say how many
// files were skipped) with zero lines.
func TestGeneratedFileIsRecordedButNotCounted(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	e := locEvent("s1", "/repo", "/repo/package-lock.json", models.ActionWriteFile,
		`{"file_path":"/repo/package-lock.json","content":"{\n\"a\": 1\n}\n"}`,
		"ev1", false)
	if _, err := s.Ingest(ctx, []models.ToolEvent{e}, nil, IngestOptions{}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	got, err := s.LoadSessionLOC(ctx, "s1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Files != 1 {
		t.Fatalf("files = %d, want 1 (the row exists so the skip is visible)", got.Files)
	}
	for _, b := range got.Buckets {
		if b.Category != string(loc.CategoryGenerated) {
			t.Errorf("category = %q, want generated", b.Category)
		}
		if b.Stats.Total() != 0 {
			t.Errorf("a generated file contributed %+v, want nothing", b.Stats)
		}
	}
}

// TestMarkEditorEchoRelabelsWithoutDeleting pins the deferred
// reconciliation's write: an editor row that turns out to be the echo of
// an AI write is KEPT as evidence and stops counting as human authorship.
func TestMarkEditorEchoRelabelsWithoutDeleting(t *testing.T) {
	t.Parallel()
	s, database := newTestStore(t)
	ctx := context.Background()

	pid, err := s.UpsertProject(ctx, "/repo", "")
	if err != nil {
		t.Fatal(err)
	}
	saved := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	if _, err := s.InsertFileChanges(ctx, []FileChangeRow{{
		SessionID:    "s1",
		ProjectID:    pid,
		FilePathHash: sha256Hex("src/a.go"),
		Language:     string(loc.LangGo),
		Category:     string(loc.CategoryCode),
		Actor:        LOCActorHuman,
		Confidence:   string(loc.ConfidenceHigh),
		Source:       LOCSourceEditor,
		Stats:        loc.Stats{AddedCode: 3},
		Version:      loc.Version,
		SavedAt:      saved,
	}}); err != nil {
		t.Fatalf("InsertFileChanges: %v", err)
	}

	pending, err := s.LoadEditorRowsPending(ctx, saved.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("pending = %d, want 1", len(pending))
	}
	if err := s.MarkEditorEcho(ctx, pending[0].ID); err != nil {
		t.Fatal(err)
	}

	var source, actor string
	if err := database.QueryRowContext(ctx,
		`SELECT source, actor FROM file_changes WHERE id = ?`, pending[0].ID).
		Scan(&source, &actor); err != nil {
		t.Fatal(err)
	}
	if source != LOCSourceEditorEcho {
		t.Errorf("source = %q, want %q", source, LOCSourceEditorEcho)
	}
	if actor == LOCActorHuman {
		t.Error("an echoed editor row still counts as human authorship")
	}

	// It is relabelled, not deleted — the evidence survives.
	var n int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM file_changes`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("rows = %d, want 1 — the echo must be relabelled, never deleted", n)
	}
}

// ---------------------------------------------------------------------
// Review fixes (2026-09-07): M1, M8, L4, L5 + the editor-echo read rule
// ---------------------------------------------------------------------

// insertEditorSave writes one editor-reported human save directly, the
// way the loopback POST handler does.
func insertEditorSave(
	t *testing.T, s *Store, sessionID string, projectID int64, rel string,
	st loc.Stats, savedAt time.Time,
) {
	t.Helper()
	if _, err := s.InsertFileChanges(context.Background(), []FileChangeRow{{
		SessionID:    sessionID,
		ProjectID:    projectID,
		FilePathHash: sha256Hex(rel),
		Language:     string(loc.LangGo),
		Category:     string(loc.CategoryCode),
		Actor:        LOCActorHuman,
		Confidence:   string(loc.ConfidenceHigh),
		Source:       LOCSourceEditor,
		Stats:        st,
		Version:      loc.Version,
		SavedAt:      savedAt,
	}}); err != nil {
		t.Fatalf("InsertFileChanges: %v", err)
	}
}

// TestEchoWindowLeansBackwardNotForward is review finding M1.
//
// The window shipped as [save-5s, save+60s], which made the everyday
// collaboration — hand-edit a file, save, then ask the agent to carry on
// in it — read as an "echo" and drove the human count to zero in exactly
// the sessions the feature exists to measure. The causal order is
// agent-writes → editor-reloads → developer-saves, so the AI action
// PRECEDES the save and the window must lean backward.
func TestEchoWindowLeansBackwardNotForward(t *testing.T) {
	t.Parallel()

	t.Run("a human save the agent EDITS 30s LATER stays human", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestStore(t)
		ctx := context.Background()
		pid, err := s.UpsertProject(ctx, "/repo", "")
		if err != nil {
			t.Fatal(err)
		}
		at := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)

		// The developer hand-edits src/a.go (+20 lines) and saves at T.
		insertEditorSave(t, s, "s1", pid, "src/a.go", loc.Stats{AddedCode: 20}, at)

		// The running agent edits the SAME file 30 seconds later.
		e := locEvent("s1", "/repo", "/repo/src/a.go", models.ActionEditFile,
			`{"file_path":"/repo/src/a.go","old_string":"x := 1","new_string":"x := 2"}`,
			"ev-late", false)
		e.Timestamp = at.Add(30 * time.Second)
		if _, err := s.Ingest(ctx, []models.ToolEvent{e}, nil, IngestOptions{}); err != nil {
			t.Fatalf("Ingest: %v", err)
		}

		got, err := s.LoadSessionLOC(ctx, "s1")
		if err != nil {
			t.Fatal(err)
		}
		var human loc.Stats
		var humanFiles int
		for _, b := range got.Buckets {
			if b.Actor == LOCActorHuman {
				human.Add(b.Stats)
				humanFiles += b.Files
			}
		}
		if humanFiles == 0 {
			t.Fatalf("the developer's save was relabelled an echo by an agent edit 30s AFTER it "+
				"— human authorship erased (buckets %+v)", got.Buckets)
		}
		if human.AddedCode != 20 {
			t.Errorf("human added_code = %d, want 20 (buckets %+v)", human.AddedCode, got.Buckets)
		}
	})

	t.Run("an AI edit 1s BEFORE the save still collapses", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestStore(t)
		ctx := context.Background()
		pid, err := s.UpsertProject(ctx, "/repo", "")
		if err != nil {
			t.Fatal(err)
		}
		at := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)

		// The save lands first (the extension reports it immediately),
		// then the transcript flushes and the agent's action arrives.
		insertEditorSave(t, s, "s1", pid, "src/a.go", loc.Stats{AddedCode: 3}, at)
		e := locEvent("s1", "/repo", "/repo/src/a.go", models.ActionEditFile,
			`{"file_path":"/repo/src/a.go","old_string":"x := 1","new_string":"x := 2\ny := 3\nz := 4"}`,
			"ev-echo", false)
		e.Timestamp = at.Add(-time.Second)
		if _, err := s.Ingest(ctx, []models.ToolEvent{e}, nil, IngestOptions{}); err != nil {
			t.Fatalf("Ingest: %v", err)
		}

		got, err := s.LoadSessionLOC(ctx, "s1")
		if err != nil {
			t.Fatal(err)
		}
		for _, b := range got.Buckets {
			if b.Actor == LOCActorHuman {
				t.Errorf("the AI-then-save echo was still counted as human authorship: %+v", b)
			}
		}
		// The echo row is KEPT as evidence, and human capture still says
		// an editor is reporting — it just contributes no lines.
		if got.HumanCapture != "vscode" {
			t.Errorf("human_capture = %q, want vscode — the echo row is still editor evidence",
				got.HumanCapture)
		}
	})

	t.Run("the window constants themselves", func(t *testing.T) {
		t.Parallel()
		if LOCEchoBefore <= LOCEchoAfter {
			t.Errorf("LOCEchoBefore=%v LOCEchoAfter=%v — the window must lean BACKWARD: "+
				"the AI action precedes the save it is echoed by", LOCEchoBefore, LOCEchoAfter)
		}
	})
}

// TestEditorEchoRowsAreNeverCounted pins the read rule migration 103
// already states in words: an `editor-echo` row is kept as evidence and
// counted nowhere. It surfaced inside the Unattributed bucket on the node
// card while the org composer dropped it, so the two disagreed about the
// same session.
func TestEditorEchoRowsAreNeverCounted(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	pid, err := s.UpsertProject(ctx, "/repo", "")
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Add(-time.Hour)

	e := locEvent("s1", "/repo", "/repo/src/a.go", models.ActionEditFile,
		`{"file_path":"/repo/src/a.go","old_string":"x := 1","new_string":"x := 2"}`,
		"ev1", false)
	e.Timestamp = at
	if _, err := s.Ingest(ctx, []models.ToolEvent{e}, nil, IngestOptions{}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	before, err := s.LoadSessionLOC(ctx, "s1")
	if err != nil {
		t.Fatal(err)
	}
	beforeDay, err := s.LoadLOCByDay(ctx, 30, 0)
	if err != nil {
		t.Fatal(err)
	}
	beforeSummary, err := s.LoadLOCSummary(ctx, 30, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Seed one echo row on a DIFFERENT file, so it cannot be masked by an
	// AI row for the same path.
	insertEditorSave(t, s, "s1", pid, "src/echoed.go", loc.Stats{AddedCode: 999}, at)
	pending, err := s.LoadEditorRowsPending(ctx, at.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("pending = %d, want 1", len(pending))
	}
	if err := s.MarkEditorEcho(ctx, pending[0].ID); err != nil {
		t.Fatal(err)
	}

	after, err := s.LoadSessionLOC(ctx, "s1")
	if err != nil {
		t.Fatal(err)
	}
	if after.Files != before.Files {
		t.Errorf("files = %d after the echo, want %d — an echo row must change nothing",
			after.Files, before.Files)
	}
	if len(after.Buckets) != len(before.Buckets) {
		t.Errorf("buckets = %d after the echo, want %d: %+v",
			len(after.Buckets), len(before.Buckets), after.Buckets)
	}
	var afterTotal, beforeTotal loc.Stats
	for _, b := range after.Buckets {
		afterTotal.Add(b.Stats)
	}
	for _, b := range before.Buckets {
		beforeTotal.Add(b.Stats)
	}
	if afterTotal != beforeTotal {
		t.Errorf("totals moved: %+v → %+v — the echo's 999 lines leaked into a bucket",
			beforeTotal, afterTotal)
	}
	// It IS still evidence that an editor is reporting saves.
	if after.HumanCapture != "vscode" {
		t.Errorf("human_capture = %q, want vscode", after.HumanCapture)
	}

	afterDay, err := s.LoadLOCByDay(ctx, 30, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(afterDay) != len(beforeDay) {
		t.Errorf("by-day rows = %d, want %d — the echo reached the trend series: %+v",
			len(afterDay), len(beforeDay), afterDay)
	}
	afterSummary, err := s.LoadLOCSummary(ctx, 30, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(afterSummary.Buckets) != len(beforeSummary.Buckets) {
		t.Errorf("summary buckets = %d, want %d: %+v",
			len(afterSummary.Buckets), len(beforeSummary.Buckets), afterSummary.Buckets)
	}
}

// TestBackfillLOCRescanReplacesRowsAtTheSameVersion pins review finding
// M8. `--loc-rescan`'s help text promises "use after changing a language
// table or lexer rule without bumping the version", but the flag only
// widened the page SELECT — the upsert still rejected the row at an equal
// version, so a rescan re-read the whole corpus and wrote nothing.
func TestBackfillLOCRescanReplacesRowsAtTheSameVersion(t *testing.T) {
	t.Parallel()
	s, database := newTestStore(t)
	ctx := context.Background()

	if _, err := s.Ingest(ctx, []models.ToolEvent{
		locEvent("s1", "/repo", "/repo/a.go", models.ActionEditFile,
			`{"file_path":"/repo/a.go","old_string":"a := 1","new_string":"a := 2"}`,
			"ev1", false),
	}, nil, IngestOptions{}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	// Simulate "the lexer rule changed": corrupt the stored count at the
	// CURRENT classifier version. A rescan must put it back.
	if _, err := database.ExecContext(ctx,
		`UPDATE file_changes SET modified_code = 4242`); err != nil {
		t.Fatal(err)
	}

	res, err := s.BackfillLOC(ctx, BackfillLOCOptions{Rescan: true})
	if err != nil {
		t.Fatalf("BackfillLOC rescan: %v", err)
	}
	if res.ActionsScanned != 1 {
		t.Fatalf("rescan scanned %d actions, want 1", res.ActionsScanned)
	}
	if res.RowsWritten != 1 {
		t.Errorf("rescan wrote %d rows, want 1 — --loc-rescan re-read the corpus and wrote "+
			"nothing, which is exactly what its help text promises it does NOT do",
			res.RowsWritten)
	}
	var got int
	if err := database.QueryRowContext(ctx,
		`SELECT modified_code FROM file_changes`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != 1 {
		t.Errorf("modified_code = %d after a rescan, want 1 — the recomputed value was rejected "+
			"by the strict version guard", got)
	}

	// The row count must still not grow, and a PLAIN backfill must stay
	// idempotent — the relaxed guard is for --loc-rescan only.
	var n int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM file_changes`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("rows = %d after a rescan, want 1 — the upsert must replace, not append", n)
	}
	if _, err := database.ExecContext(ctx, `UPDATE file_changes SET modified_code = 7`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.BackfillLOC(ctx, BackfillLOCOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx,
		`SELECT modified_code FROM file_changes`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != 7 {
		t.Errorf("a PLAIN backfill rewrote a row at the same version (modified_code = %d, "+
			"want the untouched 7) — idempotence is gone", got)
	}
}

// TestTruncatedReadWindowDegradesTheBeforeImage pins review finding L4.
//
// The before-image of a whole-content write is reconstructed from the
// preceding READ's raw_tool_output — but claude-code's Read is
// line-numbered, honours offset/limit (2,000 lines by default) and is
// capped by internal/scrub. A WINDOW is not a smaller file, so counting
// its lines books the difference as lines the agent "added". The row must
// degrade to unknown (overwrite + low confidence) instead.
func TestTruncatedReadWindowDegradesTheBeforeImage(t *testing.T) {
	t.Parallel()

	numbered := func(from, n int) string {
		var b strings.Builder
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, "%6d\tline %d\n", from+i, from+i)
		}
		return strings.TrimSuffix(b.String(), "\n")
	}

	tests := []struct {
		name       string
		readOutput string
		wantFound  bool
		wantLines  int
	}{
		{
			name:       "a whole small file is a measurement",
			readOutput: numbered(1, 12),
			wantFound:  true, wantLines: 12,
		},
		{
			name:       "a read at the default 2000-line limit is a window",
			readOutput: numbered(1, readWindowLimit),
			wantFound:  false,
		},
		{
			name:       "a read with an offset is a window",
			readOutput: numbered(1500, 40),
			wantFound:  false,
		},
		{
			name:       "the scrub cap marker is a window",
			readOutput: numbered(1, 12) + "\n…[truncated]",
			wantFound:  false,
		},
		{
			name:       "a tool's own truncation note is a window",
			readOutput: numbered(1, 12) + "\n(Results are truncated. Consider a more specific path.)",
			wantFound:  false,
		},
		{
			name:       "an unnumbered read is trusted as-is",
			readOutput: "package main\n\nfunc main() {}\n",
			wantFound:  true, wantLines: 3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := readOutputIsPartial(tt.readOutput); got == tt.wantFound {
				t.Errorf("readOutputIsPartial = %v, want %v", got, !tt.wantFound)
			}
		})
	}

	// End to end: a 6,000-line file read at the default limit and then
	// rewritten must NOT book 2,000 unknown lines.
	s, _ := newTestStore(t)
	ctx := context.Background()
	at := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)

	read := locEvent("s1", "/repo", "/repo/big.go", models.ActionReadFile, "", "ev-read", false)
	read.ToolOutput = numbered(1, readWindowLimit)
	read.Timestamp = at
	write := locEvent("s1", "/repo", "/repo/big.go", models.ActionWriteFile,
		`{"file_path":"/repo/big.go","content":"package main\n\nfunc main() {}\n"}`,
		"ev-write", false)
	write.Timestamp = at.Add(time.Second)
	if _, err := s.Ingest(ctx, []models.ToolEvent{read, write}, nil, IngestOptions{}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	got, err := s.LoadSessionLOC(ctx, "s1")
	if err != nil {
		t.Fatal(err)
	}
	var total loc.Stats
	var lowConfidence int
	for _, b := range got.Buckets {
		total.Add(b.Stats)
		lowConfidence += b.LowConfidence
	}
	if total.Unknown != 0 {
		t.Errorf("unknown = %d, want 0 — a truncated read window was counted as %d "+
			"un-measured before-image lines (stats %+v)", total.Unknown, total.Unknown, total)
	}
	if lowConfidence == 0 {
		t.Error("the row is not graded low-confidence — an overwrite with no before-image " +
			"must say so")
	}
}

// TestSessionLessEditorSaveDoesNotDuplicateOnRePost pins review finding
// L5. idx_file_changes_editor is UNIQUE(session_id, file_path_hash,
// saved_at), and SQLite treats two NULL session_ids as DISTINCT — so a
// re-POSTed save outside any session inserted a second row and doubled
// the developer's own lines.
func TestSessionLessEditorSaveDoesNotDuplicateOnRePost(t *testing.T) {
	t.Parallel()
	s, database := newTestStore(t)
	ctx := context.Background()
	pid, err := s.UpsertProject(ctx, "/repo", "")
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)

	row := FileChangeRow{
		// No SessionID: a save with no agent session running, which the
		// plan books to the project-day bucket.
		ProjectID:    pid,
		FilePathHash: sha256Hex("src/a.go"),
		Language:     string(loc.LangGo),
		Category:     string(loc.CategoryCode),
		Actor:        LOCActorHuman,
		Confidence:   string(loc.ConfidenceHigh),
		Source:       LOCSourceEditor,
		Stats:        loc.Stats{AddedCode: 5},
		Version:      loc.Version,
		SavedAt:      at,
	}
	for i := 0; i < 3; i++ {
		if _, err := s.InsertFileChanges(ctx, []FileChangeRow{row}); err != nil {
			t.Fatalf("InsertFileChanges %d: %v", i, err)
		}
	}

	var n, added int
	if err := database.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(SUM(added_code),0) FROM file_changes
		 WHERE session_id IS NULL`).Scan(&n, &added); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("rows = %d after 3 identical POSTs, want 1 — NULL session_ids are DISTINCT "+
			"to the unique index, so the re-POST duplicated the save", n)
	}
	if added != 5 {
		t.Errorf("added_code = %d, want 5 — the developer's lines were counted %dx",
			added, added/5)
	}

	// A re-POST with corrected counts must UPDATE, not append.
	row.Stats = loc.Stats{AddedCode: 9}
	if _, err := s.InsertFileChanges(ctx, []FileChangeRow{row}); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(SUM(added_code),0) FROM file_changes
		 WHERE session_id IS NULL`).Scan(&n, &added); err != nil {
		t.Fatal(err)
	}
	if n != 1 || added != 9 {
		t.Errorf("rows/added = %d/%d after a corrected re-POST, want 1/9", n, added)
	}

	// A DIFFERENT save time is a different save and must still land.
	row.SavedAt = at.Add(time.Minute)
	if _, err := s.InsertFileChanges(ctx, []FileChangeRow{row}); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM file_changes WHERE session_id IS NULL`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("rows = %d after a save one minute later, want 2 — the dedup collapsed two "+
			"genuinely different saves", n)
	}
}

// TestLoadLOCSummaryHumanCaptureIsEditorPresence pins that the window
// headline and the session card answer "is an editor reporting saves?"
// the SAME way. It matters for the two row kinds the review added: an
// `editor-echo` (counted nowhere) and a `possible_agent` save (recorded
// as `unknown`) are both still an editor reporting, and a node whose
// saves happen to be all of one kind must not read as "no editor
// installed" — the state in which the API is required to omit AIShare.
func TestLoadLOCSummaryHumanCaptureIsEditorPresence(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	pid, err := s.UpsertProject(ctx, "/repo", "")
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Add(-time.Hour)

	sum, err := s.LoadLOCSummary(ctx, 30, 0)
	if err != nil {
		t.Fatal(err)
	}
	if sum.HumanCapture != "none" {
		t.Fatalf("human_capture = %q with no editor rows at all, want none", sum.HumanCapture)
	}

	// One editor save whose actor is `unknown` — what a possible_agent
	// save and a reconciled echo both land as.
	if _, err := s.InsertFileChanges(ctx, []FileChangeRow{{
		SessionID:    "s1",
		ProjectID:    pid,
		FilePathHash: sha256Hex("src/a.go"),
		Language:     string(loc.LangGo),
		Category:     string(loc.CategoryCode),
		Actor:        LOCActorUnknown,
		Confidence:   string(loc.ConfidenceMedium),
		Source:       LOCSourceEditor,
		Stats:        loc.Stats{AddedCode: 120},
		Version:      loc.Version,
		SavedAt:      at,
	}}); err != nil {
		t.Fatal(err)
	}

	sum, err = s.LoadLOCSummary(ctx, 30, 0)
	if err != nil {
		t.Fatal(err)
	}
	if sum.HumanCapture != "vscode" {
		t.Errorf("summary human_capture = %q, want vscode — an editor IS reporting, its save "+
			"just could not be credited to the developer", sum.HumanCapture)
	}
	card, err := s.LoadSessionLOC(ctx, "s1")
	if err != nil {
		t.Fatal(err)
	}
	if card.HumanCapture != sum.HumanCapture {
		t.Errorf("card says %q, summary says %q — the two surfaces disagree about whether the "+
			"node is measuring the human side", card.HumanCapture, sum.HumanCapture)
	}
}

// TestLocDedupCTEMatchesSQL pins locDedupCTE (the const default-narrowing
// CTE, assembled from the locDedupCTEPrefix/-Middle/-Suffix fragments so it
// stays gosec-const-safe for concatenation with locStatsColumns) against
// locDedupCTESQL(locDedupSessionFilter) — the general renderer used for
// per-read narrowing. The two must never drift apart.
func TestLocDedupCTEMatchesSQL(t *testing.T) {
	if got, want := locDedupCTE, locDedupCTESQL(locDedupSessionFilter); got != want {
		t.Errorf("locDedupCTE diverged from locDedupCTESQL(locDedupSessionFilter):\ngot:  %q\nwant: %q", got, want)
	}
}
