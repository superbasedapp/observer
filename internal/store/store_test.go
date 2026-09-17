package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/compression/indexing"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/freshness"
	"github.com/marmutapp/superbased-observer/internal/models"
)

func newTestStore(t *testing.T) (*Store, *sql.DB) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "store.db")
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	return New(database), database
}

func TestUpsertProjectIdempotent(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	id1, err := s.UpsertProject(ctx, "/tmp/p1", "git@example.com:x.git")
	if err != nil {
		t.Fatal(err)
	}
	id2, err := s.UpsertProject(ctx, "/tmp/p1", "")
	if err != nil {
		t.Fatal(err)
	}
	if id1 != id2 {
		t.Errorf("project id changed: %d -> %d", id1, id2)
	}
}

// TestUpsertProject_NormalizesGitInternalPaths guards Round 3 issue #12:
// the live DB had accumulated a project row at
// <repo>/.git/worktrees because a session's cwd resolved
// into the worktree manager directory. Fold any "/.git/<...>" or
// "/.git" suffix back to the working-tree root so the table doesn't get
// polluted with admin paths that aren't actually projects.
func TestUpsertProject_NormalizesGitInternalPaths(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	cases := []struct {
		input string
		want  string
	}{
		{"/home/me/repo/.git/worktrees", "/home/me/repo"},
		{"/home/me/repo/.git/worktrees/feature-x", "/home/me/repo"},
		{"/home/me/repo/.git", "/home/me/repo"},
		{"/home/me/repo", "/home/me/repo"},                 // no-op
		{"/home/me/.git-stash/x", "/home/me/.git-stash/x"}, // not a real .git path
	}
	seen := map[string]int64{}
	for _, c := range cases {
		id, err := s.UpsertProject(ctx, c.input, "")
		if err != nil {
			t.Fatalf("UpsertProject(%q): %v", c.input, err)
		}
		if prev, ok := seen[c.want]; ok && prev != id {
			t.Errorf("input %q normalized to %q but got id %d, expected matching prior id %d",
				c.input, c.want, id, prev)
		}
		seen[c.want] = id
	}
}

func TestUpsertSessionMergesFields(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	pid, _ := s.UpsertProject(ctx, "/tmp/p2", "")
	start := time.Date(2026, 4, 16, 10, 0, 0, 0, time.UTC)
	if err := s.UpsertSession(ctx, models.Session{
		ID: "s1", ProjectID: pid, Tool: models.ToolClaudeCode, StartedAt: start,
	}); err != nil {
		t.Fatal(err)
	}
	// Second call provides model + ended_at.
	end := start.Add(10 * time.Minute)
	if err := s.UpsertSession(ctx, models.Session{
		ID: "s1", ProjectID: pid, Tool: models.ToolClaudeCode,
		Model: "claude-sonnet-4", StartedAt: start, EndedAt: end,
	}); err != nil {
		t.Fatal(err)
	}
}

// TestSetSessionLineage pins the codex fork/subagent lineage columns
// (migration 069): SetSessionLineage stamps them onto an existing
// session, empty fields are preserve-on-empty (a re-parse never
// clobbers), and a missing session id is a silent no-op.
func TestSetSessionLineage(t *testing.T) {
	t.Parallel()
	s, database := newTestStore(t)
	ctx := context.Background()

	pid, _ := s.UpsertProject(ctx, "/tmp/lineage", "")
	if err := s.UpsertSession(ctx, models.Session{
		ID: "child-sess", ProjectID: pid, Tool: models.ToolCodex,
		StartedAt: time.Date(2026, 7, 16, 20, 32, 4, 0, time.UTC),
	}); err != nil {
		t.Fatal(err)
	}

	if changed, err := s.SetSessionLineage(ctx, models.SessionLineage{
		SessionID: "child-sess", ForkedFromID: "parent-sess",
		ParentThreadID: "parent-sess", ThreadSource: "subagent",
	}); err != nil {
		t.Fatalf("SetSessionLineage: %v", err)
	} else if !changed {
		t.Error("SetSessionLineage: changed=false on first stamp; want true")
	}

	// Re-stamping the SAME values changes nothing → changed=false
	// (honest counter contract).
	if changed, err := s.SetSessionLineage(ctx, models.SessionLineage{
		SessionID: "child-sess", ForkedFromID: "parent-sess",
		ParentThreadID: "parent-sess", ThreadSource: "subagent",
	}); err != nil {
		t.Fatalf("SetSessionLineage (re-stamp): %v", err)
	} else if changed {
		t.Error("SetSessionLineage: changed=true on identical re-stamp; want false")
	}

	var forked, parent, source string
	if err := database.QueryRowContext(
		ctx,
		`SELECT COALESCE(forked_from_id,''), COALESCE(parent_thread_id,''), COALESCE(thread_source,'') FROM sessions WHERE id='child-sess'`,
	).Scan(&forked, &parent, &source); err != nil {
		t.Fatal(err)
	}
	if forked != "parent-sess" || parent != "parent-sess" || source != "subagent" {
		t.Fatalf("lineage = %q/%q/%q; want parent-sess/parent-sess/subagent", forked, parent, source)
	}

	// Preserve-on-empty: a re-stamp with empty fields keeps the values
	// and reports no change.
	if changed, err := s.SetSessionLineage(ctx, models.SessionLineage{SessionID: "child-sess"}); err != nil {
		t.Fatalf("SetSessionLineage (empty): %v", err)
	} else if changed {
		t.Error("SetSessionLineage (empty): changed=true; want false")
	}
	if err := database.QueryRowContext(
		ctx,
		`SELECT COALESCE(forked_from_id,'') FROM sessions WHERE id='child-sess'`,
	).Scan(&forked); err != nil {
		t.Fatal(err)
	}
	if forked != "parent-sess" {
		t.Errorf("forked_from_id clobbered by empty re-stamp: %q", forked)
	}

	// Missing session id is a no-op (matches zero rows, no error, no
	// change).
	if changed, err := s.SetSessionLineage(ctx, models.SessionLineage{
		SessionID: "ghost", ThreadSource: "user",
	}); err != nil {
		t.Errorf("SetSessionLineage(ghost) errored: %v", err)
	} else if changed {
		t.Error("SetSessionLineage(ghost): changed=true on missing session; want false")
	}

	// Empty SessionID is rejected.
	if _, err := s.SetSessionLineage(ctx, models.SessionLineage{}); err == nil {
		t.Error("SetSessionLineage with empty SessionID: want error, got nil")
	}
}

// TestLoadSessionLineage pins the read seam that backs the session-detail
// lineage surface: a subagent child resolves its parent (present →
// ParentInDB true), a fork whose parent is absent reports ParentInDB false,
// and a parent lists the sessions spawned from it ordered by start time.
func TestLoadSessionLineage(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	pid, _ := s.UpsertProject(ctx, "/tmp/lineage-load", "")
	mk := func(id string, at time.Time) {
		if err := s.UpsertSession(ctx, models.Session{
			ID: id, ProjectID: pid, Tool: models.ToolCodex, StartedAt: at,
		}); err != nil {
			t.Fatalf("UpsertSession(%s): %v", id, err)
		}
	}
	base := time.Date(2026, 7, 16, 20, 0, 0, 0, time.UTC)
	mk("parent", base)
	mk("sub-b", base.Add(2*time.Minute))
	mk("sub-a", base.Add(1*time.Minute))
	mk("fork-orphan", base.Add(3*time.Minute))

	// Two subagents spawned from parent.
	for _, id := range []string{"sub-a", "sub-b"} {
		if _, err := s.SetSessionLineage(ctx, models.SessionLineage{
			SessionID: id, ForkedFromID: "parent",
			ParentThreadID: "parent", ThreadSource: "subagent",
		}); err != nil {
			t.Fatal(err)
		}
	}
	// A fork whose parent is NOT in this DB.
	if _, err := s.SetSessionLineage(ctx, models.SessionLineage{
		SessionID: "fork-orphan", ForkedFromID: "missing-parent", ThreadSource: "user",
	}); err != nil {
		t.Fatal(err)
	}

	// Child with an in-DB parent.
	subView, err := s.LoadSessionLineage(ctx, "sub-a")
	if err != nil {
		t.Fatalf("LoadSessionLineage(sub-a): %v", err)
	}
	if subView.ForkedFromID != "parent" || subView.ThreadSource != "subagent" {
		t.Errorf("sub-a lineage = %q/%q; want parent/subagent", subView.ForkedFromID, subView.ThreadSource)
	}
	if !subView.ParentInDB {
		t.Error("sub-a ParentInDB = false; parent row exists, want true")
	}
	if len(subView.Children) != 0 {
		t.Errorf("sub-a Children = %d; want 0", len(subView.Children))
	}

	// Fork whose parent is absent.
	orphan, err := s.LoadSessionLineage(ctx, "fork-orphan")
	if err != nil {
		t.Fatalf("LoadSessionLineage(fork-orphan): %v", err)
	}
	if orphan.ForkedFromID != "missing-parent" || orphan.ParentInDB {
		t.Errorf("fork-orphan = %q/ParentInDB=%v; want missing-parent/false", orphan.ForkedFromID, orphan.ParentInDB)
	}

	// Parent lists both children, ordered by started_at (sub-a before sub-b).
	parent, err := s.LoadSessionLineage(ctx, "parent")
	if err != nil {
		t.Fatalf("LoadSessionLineage(parent): %v", err)
	}
	if parent.ForkedFromID != "" || parent.ParentInDB {
		t.Errorf("parent lineage markers non-empty: %q/%v", parent.ForkedFromID, parent.ParentInDB)
	}
	if len(parent.Children) != 2 {
		t.Fatalf("parent Children = %d; want 2", len(parent.Children))
	}
	if parent.Children[0].ID != "sub-a" || parent.Children[1].ID != "sub-b" {
		t.Errorf("children order = %q,%q; want sub-a,sub-b", parent.Children[0].ID, parent.Children[1].ID)
	}
	if parent.Children[0].ThreadSource != "subagent" {
		t.Errorf("child ThreadSource = %q; want subagent", parent.Children[0].ThreadSource)
	}

	// Missing session → sql.ErrNoRows.
	if _, err := s.LoadSessionLineage(ctx, "does-not-exist"); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("LoadSessionLineage(missing) err = %v; want sql.ErrNoRows", err)
	}
}

// TestLoadSessionLineage_OpencodeChildren pins the 2026-08-21 extension:
// children linked ONLY via parent_thread_id (the opencode sub-agent model —
// no forked_from_id) are listed by the parent's view, and each child row
// carries its non-sidechain token/cost/action rollups so the LineageBanner
// can show what the sub-agent cost without navigating into it.
func TestLoadSessionLineage_OpencodeChildren(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	pid, _ := s.UpsertProject(ctx, "/tmp/lineage-oc", "")
	mk := func(id string, at time.Time) {
		if err := s.UpsertSession(ctx, models.Session{
			ID: id, ProjectID: pid, Tool: models.ToolOpenCode, StartedAt: at,
		}); err != nil {
			t.Fatalf("UpsertSession(%s): %v", id, err)
		}
	}
	base := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	mk("oc-parent", base)
	mk("oc-child", base.Add(time.Minute))

	// opencode-style lineage: parent_thread_id only.
	if _, err := s.SetSessionLineage(ctx, models.SessionLineage{
		SessionID: "oc-child", ParentThreadID: "oc-parent", ThreadSource: "subagent",
	}); err != nil {
		t.Fatal(err)
	}

	// Child usage: two non-sidechain rows + one sidechain row that must be
	// excluded from the rollup; plus recorded cost on one row.
	for _, tok := range []models.TokenEvent{
		{
			SessionID: "oc-child", Timestamp: base.Add(time.Second), Model: "m",
			InputTokens: 100, OutputTokens: 10, EstimatedCostUSD: 0.25,
		},
		{
			SessionID: "oc-child", Timestamp: base.Add(2 * time.Second), Model: "m",
			InputTokens: 30, OutputTokens: 5, EstimatedCostUSD: 0.05,
		},
		{
			SessionID: "oc-child", Timestamp: base.Add(3 * time.Second), Model: "m",
			InputTokens: 999, IsSidechain: true,
		},
	} {
		if _, err := s.InsertTokenEvents(ctx, []models.TokenEvent{tok}); err != nil {
			t.Fatalf("InsertTokenEvents: %v", err)
		}
	}

	view, err := s.LoadSessionLineage(ctx, "oc-parent")
	if err != nil {
		t.Fatalf("LoadSessionLineage(oc-parent): %v", err)
	}
	if len(view.Children) != 1 {
		t.Fatalf("children = %d; want 1 (parent_thread_id-only link must list)", len(view.Children))
	}
	c := view.Children[0]
	if c.ID != "oc-child" || c.ThreadSource != "subagent" {
		t.Errorf("child = %s/%s; want oc-child/subagent", c.ID, c.ThreadSource)
	}
	if c.InputTokens != 130 || c.OutputTokens != 15 {
		t.Errorf("child tokens = %d/%d; want 130/15 (sidechain row excluded)", c.InputTokens, c.OutputTokens)
	}
	if c.CostUSD < 0.2999 || c.CostUSD > 0.3001 {
		t.Errorf("child CostUSD = %v; want ~0.30", c.CostUSD)
	}
	if c.ActionCount != 0 {
		t.Errorf("child ActionCount = %d; want 0 (no actions ingested)", c.ActionCount)
	}

	// Empty id → error.
	if _, err := s.LoadSessionLineage(ctx, ""); err == nil {
		t.Error("LoadSessionLineage(\"\"): want error, got nil")
	}
}

// TestUpsertSession_ProjectIDChangesOnReingest pins the v1.6.11
// project-attribution fix: when an adapter re-parses a session and
// the project_root resolves to a different project (e.g. an earlier
// buggy ingest pinned the wrong project; a now-fixed adapter routes
// correctly), the session row's project_id must update to match.
//
// Pre-fix the ON CONFLICT clause omitted project_id from the SET
// list, so once a session was created with a wrong project_id it
// stayed stuck. The maintainer's e371fdb1 session surfaced this
// 2026-05-19: the wrong-workspace-stub bug pinned it to project 109
// (/home/marmutapp/superbased); even after the routing fix
// correctly re-ingested under project 307
// (/home/marmutapp/superbased-observer), the session row's
// project_id stayed at 109.
func TestUpsertSession_ProjectIDChangesOnReingest(t *testing.T) {
	t.Parallel()
	s, db := newTestStore(t)
	ctx := context.Background()

	wrongPID, _ := s.UpsertProject(ctx, "/home/marmutapp/superbased", "")
	rightPID, _ := s.UpsertProject(ctx, "/home/marmutapp/superbased-observer", "")
	if wrongPID == rightPID {
		t.Fatalf("test setup error: project ids should differ")
	}
	start := time.Date(2026, 5, 18, 18, 51, 30, 0, time.UTC)

	// First ingest pins the WRONG project.
	if err := s.UpsertSession(ctx, models.Session{
		ID: "e371fdb1", ProjectID: wrongPID, Tool: models.ToolAntigravity, StartedAt: start,
	}); err != nil {
		t.Fatal(err)
	}
	var got int64
	if err := db.QueryRowContext(ctx, `SELECT project_id FROM sessions WHERE id='e371fdb1'`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != wrongPID {
		t.Fatalf("first upsert: got %d, want %d", got, wrongPID)
	}

	// Second ingest (post-fix routing) supplies the RIGHT project.
	// Must overwrite. Also tests that other fields STILL preserve
	// their COALESCE semantics — we pass a model in this round and
	// the next pass with empty model should keep this value.
	if err := s.UpsertSession(ctx, models.Session{
		ID: "e371fdb1", ProjectID: rightPID, Tool: models.ToolAntigravity,
		Model: "claude-sonnet-4-6", StartedAt: start,
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT project_id FROM sessions WHERE id='e371fdb1'`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != rightPID {
		t.Errorf("after re-ingest: project_id stayed %d (want %d) — fix not applied", got, rightPID)
	}

	// Third pass with empty model — confirms COALESCE for model
	// still preserves the prior value (other field's semantics
	// weren't accidentally broken when adding project_id to SET).
	if err := s.UpsertSession(ctx, models.Session{
		ID: "e371fdb1", ProjectID: rightPID, Tool: models.ToolAntigravity, StartedAt: start,
	}); err != nil {
		t.Fatal(err)
	}
	var model string
	if err := db.QueryRowContext(ctx, `SELECT model FROM sessions WHERE id='e371fdb1'`).Scan(&model); err != nil {
		t.Fatal(err)
	}
	if model != "claude-sonnet-4-6" {
		t.Errorf("model after empty-model re-ingest: got %q, want claude-sonnet-4-6 (COALESCE broken)", model)
	}
}

func TestParseCursors(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	off, err := s.GetCursor(ctx, "/x.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if off != 0 {
		t.Errorf("fresh cursor: %d", off)
	}
	if err := s.SetCursor(ctx, "/x.jsonl", 1234); err != nil {
		t.Fatal(err)
	}
	off, err = s.GetCursor(ctx, "/x.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if off != 1234 {
		t.Errorf("cursor: got %d want 1234", off)
	}
	// A lower value must not rewind.
	if err := s.SetCursor(ctx, "/x.jsonl", 500); err != nil {
		t.Fatal(err)
	}
	off, _ = s.GetCursor(ctx, "/x.jsonl")
	if off != 1234 {
		t.Errorf("cursor rewound: got %d want 1234", off)
	}
}

func TestListCursors(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	got, err := s.ListCursors(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("empty DB: got %d cursors", len(got))
	}

	if err := s.SetCursor(ctx, "/a.jsonl", 100); err != nil {
		t.Fatal(err)
	}
	if err := s.SetCursor(ctx, "/b.jsonl", 250); err != nil {
		t.Fatal(err)
	}
	got, err = s.ListCursors(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("after two inserts: got %d cursors", len(got))
	}
	byPath := map[string]int64{}
	for _, c := range got {
		byPath[c.SourceFile] = c.ByteOffset
	}
	if byPath["/a.jsonl"] != 100 || byPath["/b.jsonl"] != 250 {
		t.Errorf("offsets mismatch: %v", byPath)
	}
}

func TestInsertActionsIdempotent(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	pid, _ := s.UpsertProject(ctx, "/tmp/p3", "")
	if err := s.UpsertSession(ctx, models.Session{
		ID: "s1", ProjectID: pid, Tool: models.ToolClaudeCode,
		StartedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	batch := []models.Action{
		{
			SessionID: "s1", ProjectID: pid, Timestamp: time.Now().UTC(),
			ActionType: models.ActionReadFile, Target: "a.go", Success: true,
			Tool: models.ToolClaudeCode, SourceFile: "f.jsonl", SourceEventID: "e1",
		},
		{
			SessionID: "s1", ProjectID: pid, Timestamp: time.Now().UTC(),
			ActionType: models.ActionRunCommand, Target: "go test", Success: false,
			Tool: models.ToolClaudeCode, SourceFile: "f.jsonl", SourceEventID: "e2",
		},
	}
	n, err := s.InsertActions(ctx, batch)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("inserted %d want 2", n)
	}
	// Same batch again → idempotent at the table level (no new rows
	// land), but the v1.4.28 ON CONFLICT DO UPDATE for duration_ms
	// touches every conflict row, so SQLite's RowsAffected counts
	// each as 1. Assert against COUNT(*) instead — the contract that
	// matters is "no row duplication", not the specific counter.
	if _, err := s.InsertActions(ctx, batch); err != nil {
		t.Fatal(err)
	}
	total, _ := s.CountActions(ctx)
	if total != 2 {
		t.Errorf("total rows %d want 2", total)
	}
}

// TestInsertActions_DupLeavesIDZero pins the FK-violation root-cause
// fix (v1.4.46): when a row is a duplicate (UPSERT-update path
// fires), Action.ID must stay 0 so caller's `if a.ID == 0` skip for
// failure_context / file_state side-effects keeps working. Pre-fix,
// the UPSERT's UPDATE branch returned a stale LastInsertId from a
// prior connection insert; combined with retention pruning old
// rows, this caused failure_context FK insert to point at a non-
// existent action_id and 787 errors.
func TestInsertActions_DupLeavesIDZero(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	pid, _ := s.UpsertProject(ctx, "/tmp/p_dup", "")
	if err := s.UpsertSession(ctx, models.Session{
		ID: "s_dup", ProjectID: pid, Tool: models.ToolClaudeCode,
		StartedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	first := []models.Action{
		{
			SessionID: "s_dup", ProjectID: pid, Timestamp: time.Now().UTC(),
			ActionType: models.ActionRunCommand, Target: "go build", Success: false,
			Tool: models.ToolClaudeCode, SourceFile: "fdup.jsonl", SourceEventID: "ev-1",
		},
	}
	if _, err := s.InsertActions(ctx, first); err != nil {
		t.Fatal(err)
	}
	if first[0].ID == 0 {
		t.Fatalf("first insert: expected non-zero ID, got 0")
	}
	originalID := first[0].ID

	// Re-insert the same (source_file, source_event_id) — must hit the
	// UPSERT-update path. Action.ID must stay zero so the caller's
	// duplicate-skip logic remains correct.
	dup := []models.Action{
		{
			SessionID: "s_dup", ProjectID: pid, Timestamp: time.Now().UTC(),
			ActionType: models.ActionRunCommand, Target: "go build", Success: false,
			Tool: models.ToolClaudeCode, SourceFile: "fdup.jsonl", SourceEventID: "ev-1",
		},
	}
	if _, err := s.InsertActions(ctx, dup); err != nil {
		t.Fatal(err)
	}
	if dup[0].ID != 0 {
		t.Errorf("duplicate insert: Action.ID = %d, want 0 (so caller skips side effects)", dup[0].ID)
	}
	// Sanity: original row still exists.
	total, _ := s.CountActions(ctx)
	if total != 1 {
		t.Errorf("expected 1 row, got %d (originalID was %d)", total, originalID)
	}
}

// TestInsertActions_DurationRefreshOnConflict pins the v1.4.28 fix:
// an action row first ingested with duration_ms=0 (pre-fix adapter)
// gets refreshed when re-ingested with a non-zero duration (post-fix
// adapter that derives DurationMs from the tool_use→tool_result or
// function_call→output timestamp gap). A non-zero existing value is
// NEVER clobbered, even by a smaller positive value.
// TestInsertActions_ActionTypeReclassifyOnConflict pins the rescan
// self-heal clause: an adapter mapping fix (grok search_replace ->
// edit_file, 2026-07-09) lets a re-scan upgrade an 'unknown' row to a
// real type, while a known type is frozen — never rewritten to another
// known type, never downgraded to unknown/empty.
func TestInsertActions_ActionTypeReclassifyOnConflict(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	pid, _ := s.UpsertProject(ctx, "/tmp/reclass", "")
	if err := s.UpsertSession(ctx, models.Session{
		ID: "s-reclass", ProjectID: pid, Tool: models.ToolClaudeCode,
		StartedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	mk := func(eid, at string) models.Action {
		return models.Action{
			SessionID: "s-reclass", ProjectID: pid, Timestamp: time.Now().UTC(),
			ActionType: at, Target: eid + ".go", Success: true,
			Tool: models.ToolClaudeCode, SourceFile: "f", SourceEventID: eid,
		}
	}

	cases := []struct {
		name    string
		initial string
		reemit  string
		want    string
	}{
		{"unknown_upgrades_to_known", models.ActionUnknown, models.ActionEditFile, models.ActionEditFile},
		{"known_frozen_against_other_known", models.ActionReadFile, models.ActionEditFile, models.ActionReadFile},
		{"known_never_downgrades_to_unknown", models.ActionEditFile, models.ActionUnknown, models.ActionEditFile},
		{"known_never_downgrades_to_empty", models.ActionEditFile, "", models.ActionEditFile},
		{"unknown_stays_unknown_on_empty_reemit", models.ActionUnknown, "", models.ActionUnknown},
	}

	// Seed initial rows.
	pre := make([]models.Action, 0, len(cases))
	for _, c := range cases {
		pre = append(pre, mk(c.name, c.initial))
	}
	if _, err := s.InsertActions(ctx, pre); err != nil {
		t.Fatal(err)
	}

	// Re-scan with the (possibly corrected) mappings.
	post := make([]models.Action, 0, len(cases))
	for _, c := range cases {
		post = append(post, mk(c.name, c.reemit))
	}
	if _, err := s.InsertActions(ctx, post); err != nil {
		t.Fatal(err)
	}

	for _, c := range cases {
		var got string
		if err := s.db.QueryRowContext(
			ctx,
			`SELECT action_type FROM actions WHERE source_event_id = ?`, c.name,
		).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Errorf("%s: action_type = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestInsertActions_DurationRefreshOnConflict(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	pid, _ := s.UpsertProject(ctx, "/tmp/dur", "")
	if err := s.UpsertSession(ctx, models.Session{
		ID: "s-dur", ProjectID: pid, Tool: models.ToolClaudeCode,
		StartedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	pre := []models.Action{
		{
			SessionID: "s-dur", ProjectID: pid, Timestamp: time.Now().UTC(),
			ActionType: models.ActionReadFile, Target: "a.go", Success: true,
			Tool: models.ToolClaudeCode, SourceFile: "f", SourceEventID: "e-zero",
			DurationMs: 0,
		},
		{
			SessionID: "s-dur", ProjectID: pid, Timestamp: time.Now().UTC(),
			ActionType: models.ActionReadFile, Target: "b.go", Success: true,
			Tool: models.ToolClaudeCode, SourceFile: "f", SourceEventID: "e-set",
			DurationMs: 500,
		},
	}
	if _, err := s.InsertActions(ctx, pre); err != nil {
		t.Fatal(err)
	}

	// Re-ingest: the zero-duration row gets a real value; the
	// already-set row must NOT be lowered.
	post := []models.Action{
		{
			SessionID: "s-dur", ProjectID: pid, Timestamp: time.Now().UTC(),
			ActionType: models.ActionReadFile, Target: "a.go", Success: true,
			Tool: models.ToolClaudeCode, SourceFile: "f", SourceEventID: "e-zero",
			DurationMs: 1234,
		},
		{
			SessionID: "s-dur", ProjectID: pid, Timestamp: time.Now().UTC(),
			ActionType: models.ActionReadFile, Target: "b.go", Success: true,
			Tool: models.ToolClaudeCode, SourceFile: "f", SourceEventID: "e-set",
			DurationMs: 100,
		}, // smaller than existing 500
	}
	if _, err := s.InsertActions(ctx, post); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		eid  string
		want int64
	}{
		{"e-zero", 1234}, // refreshed from 0 → 1234
		{"e-set", 500},   // protected; would have become 100 if we clobbered
	} {
		var got int64
		if err := s.db.QueryRowContext(
			ctx,
			`SELECT COALESCE(duration_ms, 0) FROM actions WHERE source_event_id = ?`, c.eid,
		).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Errorf("%s: duration_ms = %d, want %d", c.eid, got, c.want)
		}
	}
}

// TestInsertActions_RawToolOutputLengthMerge pins migration 027's
// length-merge ON CONFLICT behavior for raw_tool_output: a re-ingest
// that carries a strictly longer body upgrades the column; a shorter
// re-ingest is silently ignored so a regressing adapter can't lower a
// row's captured output. Mirrors the raw_tool_input length-merge that
// has shipped since v1.4.53.
func TestInsertActions_RawToolOutputLengthMerge(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	pid, _ := s.UpsertProject(ctx, "/tmp/rto", "")
	if err := s.UpsertSession(ctx, models.Session{
		ID: "s-rto", ProjectID: pid, Tool: models.ToolClaudeCode,
		StartedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	pre := []models.Action{
		{
			SessionID: "s-rto", ProjectID: pid, Timestamp: time.Now().UTC(),
			ActionType: models.ActionReadFile, Target: "a.go", Success: true,
			Tool: models.ToolClaudeCode, SourceFile: "f", SourceEventID: "e-empty",
		},
		{
			SessionID: "s-rto", ProjectID: pid, Timestamp: time.Now().UTC(),
			ActionType: models.ActionReadFile, Target: "b.go", Success: true,
			Tool: models.ToolClaudeCode, SourceFile: "f", SourceEventID: "e-rich",
			RawToolOutput: "a quite long captured tool_result body",
		},
	}
	if _, err := s.InsertActions(ctx, pre); err != nil {
		t.Fatal(err)
	}

	// Re-ingest:
	//   - the empty-output row gets a real body
	//   - the already-rich row sees a strictly SHORTER value and must keep its longer one
	post := []models.Action{
		{
			SessionID: "s-rto", ProjectID: pid, Timestamp: time.Now().UTC(),
			ActionType: models.ActionReadFile, Target: "a.go", Success: true,
			Tool: models.ToolClaudeCode, SourceFile: "f", SourceEventID: "e-empty",
			RawToolOutput: "filled-in body from the re-ingest",
		},
		{
			SessionID: "s-rto", ProjectID: pid, Timestamp: time.Now().UTC(),
			ActionType: models.ActionReadFile, Target: "b.go", Success: true,
			Tool: models.ToolClaudeCode, SourceFile: "f", SourceEventID: "e-rich",
			RawToolOutput: "shorter",
		},
	}
	if _, err := s.InsertActions(ctx, post); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		eid  string
		want string
	}{
		{"e-empty", "filled-in body from the re-ingest"},
		{"e-rich", "a quite long captured tool_result body"},
	} {
		var got string
		if err := s.db.QueryRowContext(
			ctx,
			`SELECT COALESCE(raw_tool_output, '') FROM actions WHERE source_event_id = ?`, c.eid,
		).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Errorf("%s: raw_tool_output = %q, want %q", c.eid, got, c.want)
		}
	}
}

// TestInsertActions_PersistsMetadata pins migration 017: a non-nil
// ActionMetadata on insert round-trips through actions.metadata as
// a JSON-marshaled blob with all set fields preserved.
func TestInsertActions_PersistsMetadata(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	pid, _ := s.UpsertProject(ctx, "/tmp/p_meta", "")
	if err := s.UpsertSession(ctx, models.Session{
		ID: "s_meta", ProjectID: pid, Tool: models.ToolClaudeCode,
		StartedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	batch := []models.Action{
		{
			SessionID: "s_meta", ProjectID: pid, Timestamp: time.Now().UTC(),
			ActionType: models.ActionToolFailure, Target: "Bash", Success: false,
			Tool: models.ToolClaudeCode, SourceFile: "fmeta.jsonl", SourceEventID: "ev-meta",
			Metadata: &models.ActionMetadata{
				PermissionMode: "default",
				EffortLevel:    "high",
				IsInterrupt:    true,
			},
		},
		// No metadata: should land as NULL.
		{
			SessionID: "s_meta", ProjectID: pid, Timestamp: time.Now().UTC(),
			ActionType: models.ActionReadFile, Target: "x.go", Success: true,
			Tool: models.ToolClaudeCode, SourceFile: "fmeta.jsonl", SourceEventID: "ev-bare",
		},
	}
	if _, err := s.InsertActions(ctx, batch); err != nil {
		t.Fatal(err)
	}

	var blob sql.NullString
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT metadata FROM actions WHERE source_event_id = 'ev-meta'`,
	).Scan(&blob); err != nil {
		t.Fatal(err)
	}
	if !blob.Valid {
		t.Fatalf("metadata column NULL; want JSON blob")
	}
	if !strings.Contains(blob.String, `"permission_mode":"default"`) {
		t.Errorf("metadata missing permission_mode: %q", blob.String)
	}
	if !strings.Contains(blob.String, `"effort_level":"high"`) {
		t.Errorf("metadata missing effort_level: %q", blob.String)
	}
	if !strings.Contains(blob.String, `"is_interrupt":true`) {
		t.Errorf("metadata missing is_interrupt: %q", blob.String)
	}

	// Bare row (no metadata): column should be NULL, not "{}".
	var bare sql.NullString
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT metadata FROM actions WHERE source_event_id = 'ev-bare'`,
	).Scan(&bare); err != nil {
		t.Fatal(err)
	}
	if bare.Valid {
		t.Errorf("bare row metadata = %q; want NULL", bare.String)
	}
}

// TestInsertActions_BackfillsMetadataOnConflict pins the migration
// 017 backfill rule: a row first inserted without metadata gets a
// later non-nil metadata value applied via UPSERT-update, but a
// pre-populated metadata blob is NEVER clobbered. Mirrors the
// duration_ms backfill semantics.
func TestInsertActions_BackfillsMetadataOnConflict(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	pid, _ := s.UpsertProject(ctx, "/tmp/meta_bf", "")
	if err := s.UpsertSession(ctx, models.Session{
		ID: "s-bf", ProjectID: pid, Tool: models.ToolClaudeCode,
		StartedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	pre := []models.Action{
		// Row first ingested without metadata.
		{
			SessionID: "s-bf", ProjectID: pid, Timestamp: time.Now().UTC(),
			ActionType: models.ActionReadFile, Target: "a.go", Success: true,
			Tool: models.ToolClaudeCode, SourceFile: "fmbf", SourceEventID: "e-empty",
		},
		// Row first ingested WITH metadata; must not be overwritten.
		{
			SessionID: "s-bf", ProjectID: pid, Timestamp: time.Now().UTC(),
			ActionType: models.ActionReadFile, Target: "b.go", Success: true,
			Tool: models.ToolClaudeCode, SourceFile: "fmbf", SourceEventID: "e-set",
			Metadata: &models.ActionMetadata{PermissionMode: "plan"},
		},
	}
	if _, err := s.InsertActions(ctx, pre); err != nil {
		t.Fatal(err)
	}

	// Re-ingest: e-empty acquires metadata; e-set gets a different
	// value that should NOT clobber the existing one.
	post := []models.Action{
		{
			SessionID: "s-bf", ProjectID: pid, Timestamp: time.Now().UTC(),
			ActionType: models.ActionReadFile, Target: "a.go", Success: true,
			Tool: models.ToolClaudeCode, SourceFile: "fmbf", SourceEventID: "e-empty",
			Metadata: &models.ActionMetadata{PermissionMode: "default"},
		},
		{
			SessionID: "s-bf", ProjectID: pid, Timestamp: time.Now().UTC(),
			ActionType: models.ActionReadFile, Target: "b.go", Success: true,
			Tool: models.ToolClaudeCode, SourceFile: "fmbf", SourceEventID: "e-set",
			Metadata: &models.ActionMetadata{PermissionMode: "bypass_permissions"},
		},
	}
	if _, err := s.InsertActions(ctx, post); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		eid  string
		want string
	}{
		{"e-empty", `"permission_mode":"default"`}, // backfilled from NULL
		{"e-set", `"permission_mode":"plan"`},      // protected; bypass_permissions would have appeared if clobbered
	} {
		var blob sql.NullString
		if err := s.db.QueryRowContext(
			ctx,
			`SELECT metadata FROM actions WHERE source_event_id = ?`, c.eid,
		).Scan(&blob); err != nil {
			t.Fatal(err)
		}
		if !blob.Valid {
			t.Errorf("%s: metadata is NULL; want %q", c.eid, c.want)
			continue
		}
		if !strings.Contains(blob.String, c.want) {
			t.Errorf("%s: metadata = %q; want substring %q", c.eid, blob.String, c.want)
		}
	}
}

// TestInsertActions_MetadataRefreshesWithEnrichedContent pins the browser
// full-detail coherence fix: a turn first stored at usage_only (metadata
// carries the granularity label + token estimates, but NO content) then
// re-fired at full (content arrives) must advance BOTH the content AND the
// metadata together — the granularity label can't stay frozen at "usage_only"
// while the row now holds full content. The refresh is gated on content
// actually growing (a capability), so it's coherent for every adapter, and an
// idempotent re-fire (same content) never churns metadata.
func TestInsertActions_MetadataRefreshesWithEnrichedContent(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	pid, _ := s.UpsertProject(ctx, "browser://chatgpt.com", "")
	if err := s.UpsertSession(ctx, models.Session{
		ID: "s-brz", ProjectID: pid, Tool: "chatgpt-web",
		StartedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	// First fire: usage_only — metadata present, NO content.
	first := []models.Action{{
		SessionID: "s-brz", ProjectID: pid, Timestamp: time.Now().UTC(),
		ActionType: models.ActionAssistantMessage, Target: "gpt-4o", Success: true,
		Tool: "chatgpt-web", SourceFile: "chatgpt-web:extension", SourceEventID: "conv-brz:msg-brz",
		Metadata: &models.ActionMetadata{
			Granularity: "usage_only", ResponseTokensEst: 3, RequestURL: "https://chatgpt.com/x",
		},
	}}
	if _, err := s.InsertActions(ctx, first); err != nil {
		t.Fatal(err)
	}

	// Re-fire: full — content arrives, metadata carries the upgraded label +
	// a refined token estimate.
	second := []models.Action{{
		SessionID: "s-brz", ProjectID: pid, Timestamp: time.Now().UTC(),
		ActionType: models.ActionAssistantMessage, Target: "gpt-4o", Success: true,
		Tool: "chatgpt-web", SourceFile: "chatgpt-web:extension", SourceEventID: "conv-brz:msg-brz",
		RawToolOutput: "the full assistant response body that only arrives at full granularity",
		Metadata: &models.ActionMetadata{
			Granularity: "full", ResponseTokensEst: 14, RequestURL: "https://chatgpt.com/x",
		},
	}}
	if _, err := s.InsertActions(ctx, second); err != nil {
		t.Fatal(err)
	}

	var (
		out  string
		blob sql.NullString
	)
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT COALESCE(raw_tool_output, ''), metadata FROM actions WHERE source_event_id = 'conv-brz:msg-brz'`,
	).Scan(&out, &blob); err != nil {
		t.Fatal(err)
	}
	// Content advanced.
	if out != "the full assistant response body that only arrives at full granularity" {
		t.Errorf("raw_tool_output not enriched: %q", out)
	}
	// AND metadata advanced coherently with it — no stale usage_only label.
	if !blob.Valid {
		t.Fatalf("metadata NULL after enrichment")
	}
	if !strings.Contains(blob.String, `"granularity":"full"`) {
		t.Errorf("metadata granularity not upgraded: %q", blob.String)
	}
	if strings.Contains(blob.String, `"granularity":"usage_only"`) {
		t.Errorf("stale usage_only granularity survived enrichment: %q", blob.String)
	}
	if !strings.Contains(blob.String, `"response_tokens_est":14`) {
		t.Errorf("metadata token estimate not refreshed: %q", blob.String)
	}

	// Idempotent re-fire (identical content) must NOT churn metadata: send the
	// SAME content with a (hypothetically) different label and confirm the
	// stored metadata is untouched because content did not grow.
	third := []models.Action{{
		SessionID: "s-brz", ProjectID: pid, Timestamp: time.Now().UTC(),
		ActionType: models.ActionAssistantMessage, Target: "gpt-4o", Success: true,
		Tool: "chatgpt-web", SourceFile: "chatgpt-web:extension", SourceEventID: "conv-brz:msg-brz",
		RawToolOutput: "the full assistant response body that only arrives at full granularity",
		Metadata: &models.ActionMetadata{
			Granularity: "redacted", ResponseTokensEst: 99, RequestURL: "https://chatgpt.com/x",
		},
	}}
	if _, err := s.InsertActions(ctx, third); err != nil {
		t.Fatal(err)
	}
	var blob2 sql.NullString
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT metadata FROM actions WHERE source_event_id = 'conv-brz:msg-brz'`,
	).Scan(&blob2); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(blob2.String, `"granularity":"full"`) || strings.Contains(blob2.String, `"granularity":"redacted"`) {
		t.Errorf("metadata churned on idempotent re-fire (content unchanged): %q", blob2.String)
	}
}

// TestUpdateActionOutcome_Roundtrip pins the migration's after-event
// enrichment path: an UPDATE on (source_file, source_event_id)
// applies success / error_message / duration_ms onto an existing row.
// Mirrors the cursor afterShellExecution → beforeShellExecution
// pairing the dispatcher routes through.
func TestUpdateActionOutcome_Roundtrip(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	pid, _ := s.UpsertProject(ctx, "/tmp/p_uo", "")
	if err := s.UpsertSession(ctx, models.Session{
		ID: "s_uo", ProjectID: pid, Tool: models.ToolCursor,
		StartedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	// Seed a beforeShellExecution-style row with placeholder Success=true.
	pre := []models.Action{
		{
			SessionID: "s_uo", ProjectID: pid, Timestamp: time.Now().UTC(),
			ActionType: models.ActionRunCommand, Target: "go test", Success: true,
			Tool: models.ToolCursor, SourceFile: "cursor:hook", SourceEventID: "g1:beforeShellExecution:abc",
		},
	}
	if _, err := s.InsertActions(ctx, pre); err != nil {
		t.Fatal(err)
	}

	// Apply the after-event outcome: failure with an error and 750ms duration.
	n, err := s.UpdateActionOutcome(ctx, "cursor:hook", "g1:beforeShellExecution:abc",
		false, "exit 1: TestFoo failed", 750, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("rows updated = %d, want 1", n)
	}

	var success int
	var errMsg string
	var dur int64
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT success, error_message, COALESCE(duration_ms, 0) FROM actions WHERE source_event_id = 'g1:beforeShellExecution:abc'`,
	).Scan(&success, &errMsg, &dur); err != nil {
		t.Fatal(err)
	}
	if success != 0 {
		t.Errorf("success = %d, want 0", success)
	}
	if errMsg != "exit 1: TestFoo failed" {
		t.Errorf("error_message = %q", errMsg)
	}
	if dur != 750 {
		t.Errorf("duration_ms = %d, want 750", dur)
	}
}

// TestUpdateActionOutcome_NoMatchReturnsZero pins the race-tolerant
// behavior: an after-event whose pairing key doesn't match any row
// (because the before-row hasn't landed yet, or carried different
// payload that produced a different source_event_id) returns 0
// updated rows without an error. The dispatcher logs this case but
// doesn't treat it as a fatal hook failure.
func TestUpdateActionOutcome_NoMatchReturnsZero(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	n, err := s.UpdateActionOutcome(ctx, "cursor:hook", "nonexistent", false, "x", 100, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("rows updated for missing row = %d, want 0", n)
	}
}

// TestUpdateActionOutcome_PreservesPriorErrorAndDuration pins the
// conservative backfill rules: an after-event with empty
// error_message must NOT wipe a populated one (a postToolUseFailure
// row may have already stored a structured error); a duration_ms
// of zero (or any value when existing is non-zero) must NOT lower
// a populated duration. Mirrors the InsertActions backfill rule.
func TestUpdateActionOutcome_PreservesPriorErrorAndDuration(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	pid, _ := s.UpsertProject(ctx, "/tmp/p_uo2", "")
	if err := s.UpsertSession(ctx, models.Session{
		ID: "s_uo2", ProjectID: pid, Tool: models.ToolCursor,
		StartedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	pre := []models.Action{
		{
			SessionID: "s_uo2", ProjectID: pid, Timestamp: time.Now().UTC(),
			ActionType: models.ActionRunCommand, Target: "go test", Success: false,
			ErrorMessage: "structured failure: timeout", DurationMs: 1500,
			Tool: models.ToolCursor, SourceFile: "cursor:hook", SourceEventID: "g2:beforeShellExecution:xyz",
		},
	}
	if _, err := s.InsertActions(ctx, pre); err != nil {
		t.Fatal(err)
	}

	// After-event reports success but with NO error_message and a
	// SMALLER duration. The error must stay; the larger duration must
	// stay; success may be overwritten.
	if _, err := s.UpdateActionOutcome(ctx, "cursor:hook", "g2:beforeShellExecution:xyz",
		true, "", 250, "", "", ""); err != nil {
		t.Fatal(err)
	}

	var success int
	var errMsg string
	var dur int64
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT success, error_message, duration_ms FROM actions WHERE source_event_id = 'g2:beforeShellExecution:xyz'`,
	).Scan(&success, &errMsg, &dur); err != nil {
		t.Fatal(err)
	}
	if success != 1 {
		t.Errorf("success = %d, want 1 (after-event is authoritative)", success)
	}
	if errMsg != "structured failure: timeout" {
		t.Errorf("error_message = %q (want preserved)", errMsg)
	}
	if dur != 1500 {
		t.Errorf("duration_ms = %d (want 1500 preserved; 250 would be a regression)", dur)
	}
}

// TestIngestAppliesOutcomeUpdates pins the cross-tick seam: a
// tool_result parsed in a LATER watcher tick than its tool_use arrives
// as IngestOptions.OutcomeUpdates and flips the already-persisted row.
// The action upsert cannot express this — ON CONFLICT never touches
// success / error_message — so without the seam the outcome is lost.
func TestIngestAppliesOutcomeUpdates(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// Tick 1: the tool_use lands, optimistically successful.
	events := []models.ToolEvent{{
		SourceFile: "/t/ou.jsonl", SourceEventID: "toolu_ou1",
		SessionID: "s_ou", ProjectRoot: "/tmp/p_ou", Timestamp: now,
		Tool: models.ToolClaudeCode, ActionType: models.ActionRunCommand,
		Target: "go test ./...", RawToolName: "Bash", Success: true,
	}}
	if _, err := s.Ingest(ctx, events, nil, IngestOptions{}); err != nil {
		t.Fatal(err)
	}

	// Tick 2: no events at all, only the late outcome.
	if _, err := s.Ingest(ctx, nil, nil, IngestOptions{
		OutcomeUpdates: []models.ActionOutcomeUpdate{{
			SourceFile: "/t/ou.jsonl", SourceEventID: "toolu_ou1",
			SuccessKnown: true, Success: false, ErrorMessage: "exit 1: FAIL ./internal/store",
			ToolOutput: "--- FAIL: TestFoo\nexit status 1",
		}},
	}); err != nil {
		t.Fatal(err)
	}

	var success int
	var errMsg, out string
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT success, error_message, COALESCE(raw_tool_output, '')
		   FROM actions WHERE source_event_id = 'toolu_ou1'`,
	).Scan(&success, &errMsg, &out); err != nil {
		t.Fatal(err)
	}
	if success != 0 {
		t.Errorf("success = %d, want 0 (late tool_result is authoritative)", success)
	}
	if errMsg != "exit 1: FAIL ./internal/store" {
		t.Errorf("error_message = %q", errMsg)
	}
	if !strings.Contains(out, "--- FAIL: TestFoo") {
		t.Errorf("raw_tool_output = %q, want the late result body", out)
	}
}

// TestIngestOutcomeUpdateNoMatchTolerated pins the tolerance rule: an
// update whose key matches no row (unknown id, or a row pruned by
// retention) is neither an error nor allowed to disturb the other
// updates in the same Ingest call.
func TestIngestOutcomeUpdateNoMatchTolerated(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	events := []models.ToolEvent{{
		SourceFile: "/t/ou2.jsonl", SourceEventID: "toolu_ou2",
		SessionID: "s_ou2", ProjectRoot: "/tmp/p_ou2", Timestamp: now,
		Tool: models.ToolClaudeCode, ActionType: models.ActionRunCommand,
		Target: "ls", RawToolName: "Bash", Success: true,
	}}
	if _, err := s.Ingest(ctx, events, nil, IngestOptions{}); err != nil {
		t.Fatal(err)
	}

	if _, err := s.Ingest(ctx, nil, nil, IngestOptions{
		OutcomeUpdates: []models.ActionOutcomeUpdate{
			{SourceFile: "/t/ou2.jsonl", SourceEventID: "toolu_missing", SuccessKnown: true, Success: false, ErrorMessage: "ghost"},
			{SourceFile: "", SourceEventID: "", SuccessKnown: true, Success: false, ErrorMessage: "empty key"},
			{SourceFile: "/t/ou2.jsonl", SourceEventID: "toolu_ou2", SuccessKnown: true, Success: false, ErrorMessage: "real failure"},
		},
	}); err != nil {
		t.Fatalf("no-match update must not fail Ingest: %v", err)
	}

	var rows int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM actions`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Errorf("actions rows = %d, want 1 (a no-match update must not insert)", rows)
	}
	var success int
	var errMsg string
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT success, error_message FROM actions WHERE source_event_id = 'toolu_ou2'`,
	).Scan(&success, &errMsg); err != nil {
		t.Fatal(err)
	}
	if success != 0 || errMsg != "real failure" {
		t.Errorf("sibling update dropped: success=%d error_message=%q", success, errMsg)
	}
}

// TestIngestOutcomeUpdateIndexesViaOptsIndexer pins the reason
// updateActionOutcome takes the indexer as a PARAMETER: the watcher's
// Store has no WithIndexer binding — its indexer arrives per-call in
// IngestOptions. Reading s.indexer here instead would silently skip
// FTS for every cross-tick tool output on the watcher path.
func TestIngestOutcomeUpdateIndexesViaOptsIndexer(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// No WithIndexer binding on the Store — exactly the watcher shape.
	idx := indexing.New(s.db, 0)

	events := []models.ToolEvent{{
		SourceFile: "/t/ou3.jsonl", SourceEventID: "toolu_ou3",
		SessionID: "s_ou3", ProjectRoot: "/tmp/p_ou3", Timestamp: now,
		Tool: models.ToolClaudeCode, ActionType: models.ActionRunCommand,
		Target: "rg zathras", RawToolName: "Bash", Success: true,
	}}
	if _, err := s.Ingest(ctx, events, nil, IngestOptions{Indexer: idx}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Ingest(ctx, nil, nil, IngestOptions{
		Indexer: idx,
		OutcomeUpdates: []models.ActionOutcomeUpdate{{
			SourceFile: "/t/ou3.jsonl", SourceEventID: "toolu_ou3",
			SuccessKnown: true, Success: true, ToolOutput: "matched zathras in cmd/observer/main.go",
		}},
	}); err != nil {
		t.Fatal(err)
	}

	hits, err := idx.Search(ctx, "zathras", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 {
		t.Fatalf("FTS hits = %d, want 1 (cross-tick output must reach action_excerpts): %+v", len(hits), hits)
	}
}

// TestActionMetadata_OmitsZeroFields confirms json.Marshal of a
// zero-valued struct yields "{}", and the IsZero predicate flags
// such structs so the store layer persists NULL instead. Pins the
// "dense column" property of migration 017.
func TestActionMetadata_OmitsZeroFields(t *testing.T) {
	t.Parallel()
	zero := models.ActionMetadata{}
	if !zero.IsZero() {
		t.Errorf("IsZero() = false on zero struct")
	}
	full := models.ActionMetadata{PermissionMode: "default"}
	if full.IsZero() {
		t.Errorf("IsZero() = true on non-zero struct")
	}
}

func TestIngestWithFreshness(t *testing.T) {
	t.Parallel()
	s, d := newTestStore(t)
	ctx := context.Background()

	// Materialize a real file so the classifier can hash it.
	root := t.TempDir()
	p := filepath.Join(root, "a.go")
	if err := os.WriteFile(p, []byte("package a\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	classifier := freshness.New(d, freshness.Options{MaxHashSizeMB: 10, FastPathStatOnly: true})

	now := time.Date(2026, 4, 17, 10, 0, 0, 0, time.UTC)
	events := []models.ToolEvent{
		{
			SourceFile: "f.jsonl", SourceEventID: "fe1",
			SessionID: "sess-f1", ProjectRoot: root,
			Timestamp: now, Tool: models.ToolClaudeCode,
			ActionType: models.ActionReadFile, Target: "a.go",
			Success: true, RawToolName: "Read",
		},
		{
			SourceFile: "f.jsonl", SourceEventID: "fe2",
			SessionID: "sess-f1", ProjectRoot: root,
			Timestamp: now.Add(time.Second), Tool: models.ToolClaudeCode,
			ActionType: models.ActionReadFile, Target: "a.go",
			Success: true, RawToolName: "Read",
		},
	}

	native := func(n string) bool { return n == "Read" }
	if _, err := s.Ingest(ctx, events, nil, IngestOptions{
		IsNativeTool: native,
		Classifier:   classifier,
	}); err != nil {
		t.Fatal(err)
	}

	// First Read should be fresh, second should be stale (same session).
	var fresh1, fresh2 string
	err := d.QueryRowContext(ctx,
		`SELECT freshness FROM actions WHERE source_event_id = 'fe1'`).Scan(&fresh1)
	if err != nil {
		t.Fatal(err)
	}
	err = d.QueryRowContext(ctx,
		`SELECT freshness FROM actions WHERE source_event_id = 'fe2'`).Scan(&fresh2)
	if err != nil {
		t.Fatal(err)
	}
	if fresh1 != models.FreshnessFresh {
		t.Errorf("fe1 freshness: %q want fresh", fresh1)
	}
	if fresh2 != models.FreshnessStale {
		t.Errorf("fe2 freshness: %q want stale", fresh2)
	}

	// file_state should have exactly one row for this file.
	var n int
	_ = d.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM file_state WHERE file_path = ?`, p).Scan(&n)
	if n != 1 {
		t.Errorf("file_state rows: %d want 1", n)
	}

	// content_hash should be set.
	var hash string
	_ = d.QueryRowContext(ctx,
		`SELECT content_hash FROM actions WHERE source_event_id = 'fe1'`).Scan(&hash)
	if hash == "" {
		t.Error("content_hash not populated for file action")
	}
}

// TestIngestFileAction_RescanAfterRetentionDoesNotFKFail pins the
// 2026-05-19 fix for the copilot-cli FK 787 report. The bug: a
// long-running daemon's connection caches LastInsertId() across an
// `INSERT ... ON CONFLICT DO UPDATE` UPSERT-UPDATE path. Per SQLite,
// UPSERTs that take the UPDATE branch do NOT change last_insert_rowid,
// so the stale value (from the connection's last true INSERT, possibly
// pruned by retention) gets bound to the action and then handed to
// freshness.UpsertFileState as last_action_id — which FK-fails against
// actions(id) for a deleted row. Symptom on a Windows-native daemon:
//
//	watcher.Scan: process failed adapter=copilot-cli
//	err="freshness.UpsertFileState: constraint failed: FOREIGN KEY constraint failed (787)"
//
// Repro: insert action B, manually delete it (simulating retention),
// then re-ingest action A (already exists from a prior ingest) so the
// UPSERT takes the UPDATE branch — the buggy LastInsertId would point
// at deleted B, the fix's pre-check binds a.ID to A's actual rowid.
func TestIngestFileAction_RescanAfterRetentionDoesNotFKFail(t *testing.T) {
	t.Parallel()
	s, d := newTestStore(t)
	ctx := context.Background()

	// Pin the connection pool to one so LastInsertId state carries
	// deterministically across operations — same regime as a
	// long-running daemon doing serial work on a single Windows-side
	// connection. Without this, the test would pass on the buggy code
	// by coincidence whenever the pool hands out a fresh connection
	// for the rescan (LastInsertId = 0 → NULL last_action_id → FK
	// passes vacuously). The bug only manifests when staleness
	// actually carries forward.
	d.SetMaxOpenConns(1)

	root := t.TempDir()
	p := filepath.Join(root, "a.go")
	if err := os.WriteFile(p, []byte("package a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	classifier := freshness.New(d, freshness.Options{MaxHashSizeMB: 10, FastPathStatOnly: true})
	now := time.Date(2026, 5, 19, 23, 19, 0, 0, time.UTC)

	// Step 1: first ingest creates two actions (A + B). Action A is the
	// file-action that takes the single-row insertSingleAction path;
	// action B exists so its rowid stays in the connection's
	// last_insert_rowid cache.
	eventsA := []models.ToolEvent{
		{
			SourceFile: "f.jsonl", SourceEventID: "evA",
			SessionID: "sess-1", ProjectRoot: root,
			Timestamp: now, Tool: models.ToolCopilotCLI,
			ActionType: models.ActionReadFile, Target: "a.go",
			Success: true, RawToolName: "Read",
		},
		{
			SourceFile: "f.jsonl", SourceEventID: "evB",
			SessionID: "sess-1", ProjectRoot: root,
			Timestamp: now.Add(time.Second), Tool: models.ToolCopilotCLI,
			ActionType: models.ActionRunCommand, Target: "ls",
			Success: true, RawToolName: "Bash",
		},
	}
	if _, err := s.Ingest(ctx, eventsA, nil, IngestOptions{
		IsNativeTool: func(string) bool { return true },
		Classifier:   classifier,
	}); err != nil {
		t.Fatalf("initial ingest: %v", err)
	}

	// Step 2: simulate retention pruning action B. retention.go also
	// NULLs file_state.last_action_id references; the file-action
	// row (evA) is unaffected.
	var evBID int64
	if err := d.QueryRowContext(ctx,
		`SELECT id FROM actions WHERE source_event_id = 'evB'`).Scan(&evBID); err != nil {
		t.Fatalf("locate evB rowid: %v", err)
	}
	if _, err := d.ExecContext(ctx,
		`UPDATE file_state SET last_action_id = NULL WHERE last_action_id = ?`, evBID); err != nil {
		t.Fatalf("simulate retention NULL: %v", err)
	}
	if _, err := d.ExecContext(ctx, `DELETE FROM actions WHERE id = ?`, evBID); err != nil {
		t.Fatalf("simulate retention DELETE: %v", err)
	}

	// Step 3: re-ingest event A (rescan). Pre-fix, the UPSERT-UPDATE
	// branch would leave a.ID = (stale LastInsertId, possibly evB's
	// deleted rowid), then UpsertFileState's FK on last_action_id
	// would fail with SQLITE_CONSTRAINT_FOREIGNKEY (787).
	if _, err := s.Ingest(ctx, eventsA[:1], nil, IngestOptions{
		IsNativeTool: func(string) bool { return true },
		Classifier:   classifier,
	}); err != nil {
		t.Fatalf("rescan ingest after retention: %v", err)
	}

	// file_state should remain consistent: one row, last_action_id
	// pointing at evA's actual rowid (not stale, not NULL).
	var fsActionID sql.NullInt64
	if err := d.QueryRowContext(ctx,
		`SELECT last_action_id FROM file_state WHERE file_path = ?`, p).Scan(&fsActionID); err != nil {
		t.Fatalf("query file_state after rescan: %v", err)
	}
	if !fsActionID.Valid {
		t.Errorf("file_state.last_action_id is NULL after rescan; want bound to evA")
	} else {
		var evACurrentID int64
		_ = d.QueryRowContext(ctx,
			`SELECT id FROM actions WHERE source_event_id = 'evA'`).Scan(&evACurrentID)
		if fsActionID.Int64 != evACurrentID {
			t.Errorf("file_state.last_action_id = %d, want evA's rowid %d (not stale)", fsActionID.Int64, evACurrentID)
		}
	}
}

func TestIngestRecordsFailureContextAndRetries(t *testing.T) {
	t.Parallel()
	s, d := newTestStore(t)
	ctx := context.Background()

	now := time.Date(2026, 4, 17, 10, 0, 0, 0, time.UTC)
	mk := func(id, cmd string, ok bool, errMsg string, ts time.Time) models.ToolEvent {
		return models.ToolEvent{
			SourceFile: "cmds.jsonl", SourceEventID: id,
			SessionID: "sess-fc", ProjectRoot: "/tmp/pfc",
			Timestamp: ts, Tool: models.ToolClaudeCode,
			ActionType: models.ActionRunCommand, Target: cmd,
			Success: ok, ErrorMessage: errMsg, RawToolName: "Bash",
		}
	}
	events := []models.ToolEvent{
		mk("c1", "go test ./...", false, "--- FAIL: TestFoo", now),
		mk("c2", "go  test   ./...", false, "--- FAIL: TestFoo", now.Add(time.Second)), // same hash, whitespace collapsed
		mk("c3", "go test ./...", true, "", now.Add(2*time.Second)),
		mk("c4", "ls /no-such", false, "ls: cannot access '/no-such': No such file or directory", now.Add(3*time.Second)),
	}

	if _, err := s.Ingest(ctx, events, nil, IngestOptions{RecordFailures: true}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	// 3 failure rows total: c1, c2, c4.
	var total int
	_ = d.QueryRowContext(ctx, `SELECT COUNT(*) FROM failure_context`).Scan(&total)
	if total != 3 {
		t.Errorf("failure_context rows: %d want 3", total)
	}

	// c1 retry_count = 0, c2 retry_count = 1 (both for go test).
	var r1, r2 int
	_ = d.QueryRowContext(ctx,
		`SELECT retry_count FROM failure_context WHERE action_id =
		 (SELECT id FROM actions WHERE source_event_id = 'c1')`).Scan(&r1)
	_ = d.QueryRowContext(ctx,
		`SELECT retry_count FROM failure_context WHERE action_id =
		 (SELECT id FROM actions WHERE source_event_id = 'c2')`).Scan(&r2)
	if r1 != 0 || r2 != 1 {
		t.Errorf("retry_count: c1=%d c2=%d want 0, 1", r1, r2)
	}

	// After c3 succeeded, both go test failure rows should flip.
	var es1, es2 int
	_ = d.QueryRowContext(ctx,
		`SELECT eventually_succeeded FROM failure_context WHERE action_id =
		 (SELECT id FROM actions WHERE source_event_id = 'c1')`).Scan(&es1)
	_ = d.QueryRowContext(ctx,
		`SELECT eventually_succeeded FROM failure_context WHERE action_id =
		 (SELECT id FROM actions WHERE source_event_id = 'c2')`).Scan(&es2)
	if es1 != 1 || es2 != 1 {
		t.Errorf("eventually_succeeded: c1=%d c2=%d want 1, 1", es1, es2)
	}

	// c4 (unrelated command) should NOT be flipped by c3's success.
	var es4 int
	_ = d.QueryRowContext(ctx,
		`SELECT eventually_succeeded FROM failure_context WHERE action_id =
		 (SELECT id FROM actions WHERE source_event_id = 'c4')`).Scan(&es4)
	if es4 != 0 {
		t.Errorf("eventually_succeeded for unrelated failure: %d want 0", es4)
	}

	// Error categories.
	var cat1, cat4 string
	_ = d.QueryRowContext(ctx,
		`SELECT error_category FROM failure_context WHERE action_id =
		 (SELECT id FROM actions WHERE source_event_id = 'c1')`).Scan(&cat1)
	_ = d.QueryRowContext(ctx,
		`SELECT error_category FROM failure_context WHERE action_id =
		 (SELECT id FROM actions WHERE source_event_id = 'c4')`).Scan(&cat4)
	if cat1 != "test_failure" {
		t.Errorf("c1 category: %q want test_failure", cat1)
	}
	if cat4 != "runtime" {
		t.Errorf("c4 category: %q want runtime", cat4)
	}
}

func TestIngestEndToEnd(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	now := time.Date(2026, 4, 16, 10, 0, 0, 0, time.UTC)
	events := []models.ToolEvent{
		{
			SourceFile: "f.jsonl", SourceEventID: "e1",
			SessionID: "sess-1", ProjectRoot: "/tmp/proj",
			Timestamp: now, Tool: models.ToolClaudeCode,
			ActionType: models.ActionReadFile, Target: "README.md",
			Success: true, RawToolName: "Read",
		},
		{
			SourceFile: "f.jsonl", SourceEventID: "e2",
			SessionID: "sess-1", ProjectRoot: "/tmp/proj",
			Timestamp: now.Add(time.Second), Tool: models.ToolClaudeCode,
			ActionType: models.ActionRunCommand, Target: "ls",
			Success: true, RawToolName: "Bash",
		},
		// Skippable: missing SessionID.
		{
			SourceFile: "f.jsonl", SourceEventID: "e3",
			ProjectRoot: "/tmp/proj", Tool: models.ToolClaudeCode,
			Timestamp: now, ActionType: models.ActionReadFile,
		},
	}
	tokens := []models.TokenEvent{
		{
			SourceFile: "f.jsonl", SourceEventID: "t1",
			SessionID: "sess-1", Timestamp: now,
			Tool: models.ToolClaudeCode, InputTokens: 10, OutputTokens: 20,
			Source: models.TokenSourceJSONL, Reliability: models.ReliabilityUnreliable,
		},
	}

	native := map[string]bool{"Read": true, "Edit": true, "Write": true, "Grep": true, "Glob": true}
	res, err := s.Ingest(ctx, events, tokens, IngestOptions{
		IsNativeTool: func(n string) bool { return native[n] },
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.ActionsInserted != 2 {
		t.Errorf("actions inserted: %d", res.ActionsInserted)
	}
	if res.TokensInserted != 1 {
		t.Errorf("tokens inserted: %d", res.TokensInserted)
	}
	if res.ProjectsTouched != 1 {
		t.Errorf("projects touched: %d", res.ProjectsTouched)
	}
	if res.SessionsTouched != 1 {
		t.Errorf("sessions touched: %d", res.SessionsTouched)
	}

	// is_native_tool was set correctly.
	var readNative, bashNative int
	_ = s.db.QueryRowContext(ctx,
		`SELECT is_native_tool FROM actions WHERE source_event_id = 'e1'`).Scan(&readNative)
	_ = s.db.QueryRowContext(ctx,
		`SELECT is_native_tool FROM actions WHERE source_event_id = 'e2'`).Scan(&bashNative)
	if readNative != 1 || bashNative != 0 {
		t.Errorf("is_native_tool: Read=%d Bash=%d want 1, 0", readNative, bashNative)
	}

	// Re-ingesting produces no duplicates. Both actions and
	// token_usage now use ON CONFLICT DO UPDATE for select fields
	// (actions.duration_ms, token_usage.model — both descriptive,
	// adapter-improvement-driven), so RowsAffected counts shifted to
	// "rows touched" rather than "actually new rows" in v1.4.27 +
	// v1.4.28. The real "no duplicates" property is the
	// post-condition row count, not the metric.
	if _, err := s.Ingest(ctx, events, tokens, IngestOptions{
		IsNativeTool: func(n string) bool { return native[n] },
	}); err != nil {
		t.Fatal(err)
	}
	var actionRows, tokenRows int
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM actions`).Scan(&actionRows)
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM token_usage`).Scan(&tokenRows)
	if actionRows != 2 {
		t.Errorf("post re-ingest action rows: %d want 2", actionRows)
	}
	if tokenRows != 1 {
		t.Errorf("post re-ingest token rows: %d want 1", tokenRows)
	}
}

// TestIngest_SessionEndDoesNotBootstrapPhantom pins the fix for phantom
// dashboard sessions: a lone session_end (the Windows-CC empty-session
// hook case) must not conjure a session that has no other record, but a
// session_end for a session that already exists — or one created by an
// earlier event in the same batch — still attaches normally.
func TestIngest_SessionEndDoesNotBootstrapPhantom(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 6, 7, 10, 0, 0, 0, time.UTC)

	sessionEnd := func(id, eid string, ts time.Time) models.ToolEvent {
		return models.ToolEvent{
			SourceFile: "claude-code:hook", SourceEventID: eid,
			SessionID: id, ProjectRoot: "/tmp/proj",
			Timestamp: ts, Tool: models.ToolClaudeCode,
			ActionType: models.ActionSessionEnd, Target: "session_ended", Success: true,
		}
	}
	userPrompt := func(id, eid string, ts time.Time) models.ToolEvent {
		return models.ToolEvent{
			SourceFile: "f.jsonl", SourceEventID: eid,
			SessionID: id, ProjectRoot: "/tmp/proj",
			Timestamp: ts, Tool: models.ToolClaudeCode,
			ActionType: models.ActionUserPrompt, Target: "hi", Success: true,
		}
	}

	// 1. Lone session_end for a never-seen session → dropped entirely.
	res, err := s.Ingest(ctx, []models.ToolEvent{sessionEnd("sess-x", "sess-x:end", now)}, nil, IngestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.ActionsInserted != 0 || res.SessionsTouched != 0 {
		t.Errorf("lone session_end: actions=%d sessions=%d, want 0/0", res.ActionsInserted, res.SessionsTouched)
	}
	if exists, _ := s.sessionExists(ctx, "sess-x"); exists {
		t.Error("lone session_end conjured a phantom session row")
	}

	// 2. session_end for a session that already exists → attaches.
	if _, err := s.Ingest(ctx, []models.ToolEvent{userPrompt("sess-y", "sess-y:up", now)}, nil, IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	res2, err := s.Ingest(ctx, []models.ToolEvent{sessionEnd("sess-y", "sess-y:end", now.Add(time.Minute))}, nil, IngestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res2.ActionsInserted != 1 {
		t.Errorf("session_end on existing session: actions=%d, want 1", res2.ActionsInserted)
	}

	// 3. Real event + session_end in the same batch → both land (the real
	//    event creates the session before session_end is processed).
	res3, err := s.Ingest(ctx, []models.ToolEvent{
		userPrompt("sess-z", "sess-z:up", now),
		sessionEnd("sess-z", "sess-z:end", now.Add(time.Second)),
	}, nil, IngestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res3.ActionsInserted != 2 {
		t.Errorf("same-batch real+session_end: actions=%d, want 2", res3.ActionsInserted)
	}
}

// TestInsertTokenEvents_ModelRefreshOnConflict pins the audit-fix v1.4.27
// behavior where re-ingesting a token row with a more specific model
// (e.g. an adapter improving from "copilot/auto" → "claude-haiku-4-5...")
// upgrades the existing row in place. reliability remains frozen
// (quality-sensitive). Token counts since v1.6.23 upgrade via MAX so
// snapshot-based adapters (Copilot modern) that re-emit refined counts
// finalize correctly — covered by the LARGER/SMALLER cases below.
func TestInsertTokenEvents_ModelRefreshOnConflict(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 5, 2, 11, 8, 10, 0, time.UTC)

	if _, err := s.UpsertProject(ctx, "/tmp/proj", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSession(ctx, models.Session{
		ID: "sess-mr", ProjectID: 1, Tool: models.ToolCopilot,
		StartedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	// First insert: placeholder model with partial counts (the typical
	// snapshot mid-flight state from Copilot modern).
	first := []models.TokenEvent{{
		SourceFile: "f.jsonl", SourceEventID: "request_x:usage",
		SessionID: "sess-mr", Timestamp: now,
		Tool: models.ToolCopilot, Model: "copilot/auto",
		InputTokens: 100, OutputTokens: 50,
		Source: models.TokenSourceJSONL, Reliability: models.ReliabilityApproximate,
	}}
	if _, err := s.InsertTokenEvents(ctx, first); err != nil {
		t.Fatal(err)
	}

	// Re-insert with the resolved model AND refined (larger) counts.
	// Reliability is intentionally a different value to confirm it is
	// NOT clobbered (quality-sensitive; pinned at first insert).
	second := []models.TokenEvent{{
		SourceFile: "f.jsonl", SourceEventID: "request_x:usage",
		SessionID: "sess-mr", Timestamp: now,
		Tool: models.ToolCopilot, Model: "claude-haiku-4-5-20251001",
		InputTokens: 999999, OutputTokens: 999999,
		Source: models.TokenSourceJSONL, Reliability: models.ReliabilityUnreliable,
	}}
	if _, err := s.InsertTokenEvents(ctx, second); err != nil {
		t.Fatal(err)
	}

	var rows int
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM token_usage`).Scan(&rows)
	if rows != 1 {
		t.Fatalf("post re-ingest rows: got %d want 1", rows)
	}

	var model, reliability string
	var inTok, outTok int64
	if err := s.db.QueryRowContext(ctx, `
		SELECT model, reliability, input_tokens, output_tokens
		FROM token_usage WHERE source_event_id = 'request_x:usage'`).Scan(
		&model, &reliability, &inTok, &outTok,
	); err != nil {
		t.Fatal(err)
	}
	if model != "claude-haiku-4-5-20251001" {
		t.Errorf("model: got %q want claude-haiku-4-5-20251001", model)
	}
	// v1.6.23: counts MAX-upgrade — newer larger values win.
	if inTok != 999999 || outTok != 999999 {
		t.Errorf("counts not upgraded to MAX: in=%d out=%d want 999999/999999", inTok, outTok)
	}
	if reliability != models.ReliabilityApproximate {
		t.Errorf("reliability overwritten: got %q want %q", reliability, models.ReliabilityApproximate)
	}

	// Empty-model re-insert must NOT erase a previously-resolved model.
	third := []models.TokenEvent{{
		SourceFile: "f.jsonl", SourceEventID: "request_x:usage",
		SessionID: "sess-mr", Timestamp: now,
		Tool: models.ToolCopilot, Model: "",
		InputTokens: 100, OutputTokens: 50,
		Source: models.TokenSourceJSONL, Reliability: models.ReliabilityApproximate,
	}}
	if _, err := s.InsertTokenEvents(ctx, third); err != nil {
		t.Fatal(err)
	}
	_ = s.db.QueryRowContext(ctx, `
		SELECT model FROM token_usage WHERE source_event_id = 'request_x:usage'`).Scan(&model)
	if model != "claude-haiku-4-5-20251001" {
		t.Errorf("empty-model re-insert clobbered resolved value: got %q", model)
	}
}

// TestInsertTokenEvents_TurnIDPersistsAndBackfills pins the v1.7.24
// migration-032 contract: TurnID lands in the new turn_id column, an
// empty TurnID on re-emit doesn't clobber an existing non-empty value,
// and a NULL existing column upgrades from a re-parse that now carries
// TurnID (older codex JSONL re-parsed by a v1.7.24+ adapter).
func TestInsertTokenEvents_TurnIDPersistsAndBackfills(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 6, 2, 0, 0, 0, 0, time.UTC)

	if _, err := s.UpsertProject(ctx, "/tmp/proj-turn", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSession(ctx, models.Session{
		ID: "sess-turn", ProjectID: 1, Tool: models.ToolCodex, StartedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	// Phase 1: legacy-style insert — TurnID empty (simulates a pre-
	// v1.7.24 emit that landed before migration 032's adapter rewrite).
	legacy := []models.TokenEvent{{
		SourceFile: "rollout.jsonl", SourceEventID: "tk:rollout.jsonl:L7",
		SessionID: "sess-turn", Timestamp: now,
		Tool: models.ToolCodex, Model: "gpt-5.4",
		InputTokens: 100, OutputTokens: 50,
		Source: models.TokenSourceJSONL, Reliability: models.ReliabilityApproximate,
		MessageID: "tk:rollout.jsonl:L7",
		// TurnID intentionally empty.
	}}
	if _, err := s.InsertTokenEvents(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	var turnID sql.NullString
	if err := s.db.QueryRowContext(ctx, `
		SELECT turn_id FROM token_usage WHERE source_event_id = 'tk:rollout.jsonl:L7'`).
		Scan(&turnID); err != nil {
		t.Fatal(err)
	}
	if turnID.Valid && turnID.String != "" {
		t.Errorf("phase 1 turn_id: got %q want NULL", turnID.String)
	}

	// Phase 2: re-parse with v1.7.24+ adapter — TurnID now populated.
	// COALESCE rule upgrades NULL → "turn-2".
	upgraded := []models.TokenEvent{{
		SourceFile: "rollout.jsonl", SourceEventID: "tk:rollout.jsonl:L7",
		SessionID: "sess-turn", Timestamp: now,
		Tool: models.ToolCodex, Model: "gpt-5.4",
		InputTokens: 100, OutputTokens: 50,
		Source: models.TokenSourceJSONL, Reliability: models.ReliabilityApproximate,
		MessageID: "tk:rollout.jsonl:L7",
		TurnID:    "turn-2",
	}}
	if _, err := s.InsertTokenEvents(ctx, upgraded); err != nil {
		t.Fatal(err)
	}
	_ = s.db.QueryRowContext(ctx, `
		SELECT turn_id FROM token_usage WHERE source_event_id = 'tk:rollout.jsonl:L7'`).
		Scan(&turnID)
	if !turnID.Valid || turnID.String != "turn-2" {
		t.Errorf("phase 2 turn_id: got %v want turn-2", turnID)
	}

	// Phase 3: re-emit with empty TurnID — existing "turn-2" must NOT
	// be clobbered. Mirrors the model-preservation contract above.
	cleared := []models.TokenEvent{{
		SourceFile: "rollout.jsonl", SourceEventID: "tk:rollout.jsonl:L7",
		SessionID: "sess-turn", Timestamp: now,
		Tool: models.ToolCodex, Model: "gpt-5.4",
		InputTokens: 100, OutputTokens: 50,
		Source: models.TokenSourceJSONL, Reliability: models.ReliabilityApproximate,
		MessageID: "tk:rollout.jsonl:L7",
		// TurnID intentionally empty again.
	}}
	if _, err := s.InsertTokenEvents(ctx, cleared); err != nil {
		t.Fatal(err)
	}
	_ = s.db.QueryRowContext(ctx, `
		SELECT turn_id FROM token_usage WHERE source_event_id = 'tk:rollout.jsonl:L7'`).
		Scan(&turnID)
	if !turnID.Valid || turnID.String != "turn-2" {
		t.Errorf("phase 3 empty-TurnID re-insert clobbered existing value: got %v want turn-2", turnID)
	}
}

// TestInsertTokenEvents_CountsMaxUpgradeOnConflict pins the v1.6.23
// fix where token count columns MAX-upgrade on conflict so
// snapshot-based adapters (Copilot's modern adapter) that re-emit the
// same source_event_id with refined token counts as an in-flight
// request finalizes don't permanently persist a partial state.
//
// Three progression states exercised:
//  1. partial state lands first (low in, no out, no reasoning)
//  2. mid-progress state arrives (same in, output appears)
//  3. complete state arrives (in upgrades, output upgrades, reasoning appears)
//  4. accidental regression (smaller new values) — existing larger values preserved
func TestInsertTokenEvents_CountsMaxUpgradeOnConflict(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)

	if _, err := s.UpsertProject(ctx, "/tmp/proj-max", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSession(ctx, models.Session{
		ID: "sess-max", ProjectID: 1, Tool: models.ToolCopilot,
		StartedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	mk := func(in, out, cR, cW, c1h, reason int64) []models.TokenEvent {
		return []models.TokenEvent{{
			SourceFile: "snap.jsonl", SourceEventID: "request_y:usage",
			SessionID: "sess-max", Timestamp: now,
			Tool: models.ToolCopilot, Model: "copilot/auto",
			InputTokens: in, OutputTokens: out,
			CacheReadTokens: cR, CacheCreationTokens: cW,
			CacheCreation1hTokens: c1h, ReasoningTokens: reason,
			Source: models.TokenSourceJSONL, Reliability: models.ReliabilityApproximate,
		}}
	}
	get := func() (in, out, cR, cW, reason int64) {
		_ = s.db.QueryRowContext(ctx, `
			SELECT input_tokens, output_tokens, cache_read_tokens,
			       cache_creation_tokens, reasoning_tokens
			FROM token_usage WHERE source_event_id = 'request_y:usage'`).Scan(
			&in, &out, &cR, &cW, &reason,
		)
		return
	}

	// 1. partial state
	if _, err := s.InsertTokenEvents(ctx, mk(100, 0, 0, 0, 0, 0)); err != nil {
		t.Fatal(err)
	}
	in, out, _, _, reason := get()
	if in != 100 || out != 0 || reason != 0 {
		t.Errorf("after partial: in=%d out=%d reason=%d", in, out, reason)
	}

	// 2. mid-progress — output appears
	if _, err := s.InsertTokenEvents(ctx, mk(100, 50, 0, 0, 0, 0)); err != nil {
		t.Fatal(err)
	}
	in, out, _, _, _ = get()
	if in != 100 || out != 50 {
		t.Errorf("after mid: in=%d out=%d want 100/50", in, out)
	}

	// 3. complete — input refines upward, reasoning appears, cache lands
	if _, err := s.InsertTokenEvents(ctx, mk(150, 200, 80, 0, 0, 25)); err != nil {
		t.Fatal(err)
	}
	in, out, cR, _, reason := get()
	if in != 150 || out != 200 || cR != 80 || reason != 25 {
		t.Errorf("after complete: in=%d out=%d cR=%d reason=%d", in, out, cR, reason)
	}

	// 4. accidental regression — smaller new values must NOT clobber
	if _, err := s.InsertTokenEvents(ctx, mk(50, 100, 40, 0, 0, 10)); err != nil {
		t.Fatal(err)
	}
	in, out, cR, _, reason = get()
	if in != 150 || out != 200 || cR != 80 || reason != 25 {
		t.Errorf("regression clobbered values: in=%d out=%d cR=%d reason=%d", in, out, cR, reason)
	}
}

// TestInsertTokenEvents_CopilotCLITierDedup pins the v1.6.3 dedup
// behavior: when a copilot-cli session emits both a Tier-3 (events.jsonl,
// OutputTokens only) row and a Tier-1 (debug-log, full usage) row for
// the same Request-ID, the Tier-3 row is dropped so output_tokens
// doesn't double-count. The dedup must be arrival-order independent
// and idempotent across re-parses. Scoped to copilot-cli only —
// other adapters with similar overlap patterns are left alone.
func TestInsertTokenEvents_CopilotCLITierDedup(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)

	// Helper to construct the two tiers for a given Request-ID. Tier 1
	// (debug log) carries full usage; Tier 3 (events.jsonl) carries only
	// OutputTokens. MessageID == Request-ID is the join key.
	tier3 := func(sessionID, reqID string) models.TokenEvent {
		return models.TokenEvent{
			SourceFile: "/x/events.jsonl", SourceEventID: reqID + ":token",
			SessionID: sessionID, Timestamp: now,
			Tool: models.ToolCopilotCLI, Model: "gpt-5-mini",
			OutputTokens: 565,
			Source:       models.TokenSourceJSONL,
			Reliability:  models.ReliabilityUnreliable,
			MessageID:    reqID,
		}
	}
	tier1 := func(sessionID, reqID string) models.TokenEvent {
		return models.TokenEvent{
			SourceFile: "/x/process.log", SourceEventID: "log:" + reqID + ":1",
			SessionID: sessionID, Timestamp: now,
			Tool: models.ToolCopilotCLI, Model: "gpt-5-mini",
			InputTokens: 15474, OutputTokens: 565,
			CacheReadTokens: 2560, ReasoningTokens: 448,
			Source:      models.TokenSourceOTel,
			Reliability: models.ReliabilityApproximate,
			MessageID:   reqID,
		}
	}
	mustSeedProjectAndSession := func(t *testing.T, s *Store, sessionID string) {
		t.Helper()
		if _, err := s.UpsertProject(ctx, "/tmp/proj", ""); err != nil {
			t.Fatal(err)
		}
		if err := s.UpsertSession(ctx, models.Session{
			ID: sessionID, ProjectID: 1, Tool: models.ToolCopilotCLI, StartedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	countRows := func(t *testing.T, s *Store, sessionID, messageID string) (n int, source string, inTok, outTok int64) {
		t.Helper()
		rows, err := s.db.QueryContext(ctx,
			`SELECT source, input_tokens, output_tokens FROM token_usage
			 WHERE session_id = ? AND message_id = ?`,
			sessionID, messageID)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		for rows.Next() {
			var src string
			var in, out int64
			if err := rows.Scan(&src, &in, &out); err != nil {
				t.Fatal(err)
			}
			n++
			source, inTok, outTok = src, in, out
		}
		return
	}

	cases := []struct {
		name      string
		insertFn  func(t *testing.T, s *Store)
		wantRows  int
		wantSrc   string
		wantInTok int64
		wantOut   int64
	}{
		{
			name: "tier3 then tier1 — tier3 dropped",
			insertFn: func(t *testing.T, s *Store) {
				if _, err := s.InsertTokenEvents(ctx, []models.TokenEvent{tier3("sess-A", "req-1")}); err != nil {
					t.Fatal(err)
				}
				if _, err := s.InsertTokenEvents(ctx, []models.TokenEvent{tier1("sess-A", "req-1")}); err != nil {
					t.Fatal(err)
				}
			},
			wantRows: 1, wantSrc: models.TokenSourceOTel, wantInTok: 15474, wantOut: 565,
		},
		{
			name: "tier1 then tier3 — tier3 dropped immediately",
			insertFn: func(t *testing.T, s *Store) {
				if _, err := s.InsertTokenEvents(ctx, []models.TokenEvent{tier1("sess-A", "req-1")}); err != nil {
					t.Fatal(err)
				}
				if _, err := s.InsertTokenEvents(ctx, []models.TokenEvent{tier3("sess-A", "req-1")}); err != nil {
					t.Fatal(err)
				}
			},
			wantRows: 1, wantSrc: models.TokenSourceOTel, wantInTok: 15474, wantOut: 565,
		},
		{
			name: "both in same batch — tier3 dropped",
			insertFn: func(t *testing.T, s *Store) {
				if _, err := s.InsertTokenEvents(ctx, []models.TokenEvent{
					tier3("sess-A", "req-1"), tier1("sess-A", "req-1"),
				}); err != nil {
					t.Fatal(err)
				}
			},
			wantRows: 1, wantSrc: models.TokenSourceOTel, wantInTok: 15474, wantOut: 565,
		},
		{
			name: "tier1 only — no dedup",
			insertFn: func(t *testing.T, s *Store) {
				if _, err := s.InsertTokenEvents(ctx, []models.TokenEvent{tier1("sess-A", "req-1")}); err != nil {
					t.Fatal(err)
				}
			},
			wantRows: 1, wantSrc: models.TokenSourceOTel, wantInTok: 15474, wantOut: 565,
		},
		{
			name: "tier3 only — kept (no upgrade available)",
			insertFn: func(t *testing.T, s *Store) {
				if _, err := s.InsertTokenEvents(ctx, []models.TokenEvent{tier3("sess-A", "req-1")}); err != nil {
					t.Fatal(err)
				}
			},
			wantRows: 1, wantSrc: models.TokenSourceJSONL, wantInTok: 0, wantOut: 565,
		},
		{
			name: "re-parse tier1 — idempotent via source_file+source_event_id upsert",
			insertFn: func(t *testing.T, s *Store) {
				if _, err := s.InsertTokenEvents(ctx, []models.TokenEvent{tier1("sess-A", "req-1")}); err != nil {
					t.Fatal(err)
				}
				if _, err := s.InsertTokenEvents(ctx, []models.TokenEvent{tier1("sess-A", "req-1")}); err != nil {
					t.Fatal(err)
				}
			},
			wantRows: 1, wantSrc: models.TokenSourceOTel, wantInTok: 15474, wantOut: 565,
		},
		{
			name: "re-parse tier3 — idempotent (no tier1 ever arrives)",
			insertFn: func(t *testing.T, s *Store) {
				if _, err := s.InsertTokenEvents(ctx, []models.TokenEvent{tier3("sess-A", "req-1")}); err != nil {
					t.Fatal(err)
				}
				if _, err := s.InsertTokenEvents(ctx, []models.TokenEvent{tier3("sess-A", "req-1")}); err != nil {
					t.Fatal(err)
				}
			},
			wantRows: 1, wantSrc: models.TokenSourceJSONL, wantInTok: 0, wantOut: 565,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newTestStore(t)
			mustSeedProjectAndSession(t, s, "sess-A")
			tc.insertFn(t, s)
			n, src, in, out := countRows(t, s, "sess-A", "req-1")
			if n != tc.wantRows {
				t.Fatalf("rows: got %d want %d", n, tc.wantRows)
			}
			if tc.wantRows == 1 && src != tc.wantSrc {
				t.Errorf("source: got %q want %q", src, tc.wantSrc)
			}
			if tc.wantRows == 1 && in != tc.wantInTok {
				t.Errorf("input_tokens: got %d want %d", in, tc.wantInTok)
			}
			if tc.wantRows == 1 && out != tc.wantOut {
				t.Errorf("output_tokens: got %d want %d", out, tc.wantOut)
			}
		})
	}
}

// TestInsertTokenEvents_HealsNullMessageIDAndDedups pins the modern Copilot
// CLI (1.0.60+) Request-ID heal. The process log emits a "Request-ID null"
// header, so the Tier-1 (otel) row first lands with message_id="null" while
// the Tier-3 (events.jsonl) row carries the real hex:colon requestId — the
// (session_id, message_id) sweep can't fire (ids differ), so both rows persist
// and output double-counts. After the parser recovers the real id
// (copilotcli.recoverNullRequestIDs), a rescan re-emits the Tier-1 row with
// the SAME source_event_id but the recovered message_id; the UPSERT heals the
// "null" placeholder and the sweep then drops the Tier-3 shadow.
func TestInsertTokenEvents_HealsNullMessageIDAndDedups(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 6, 8, 12, 24, 28, 0, time.UTC)
	const sessionID = "sess-heal"
	const realID = "DD86:3DBC98:11337CF:121E92C:6A26B477"

	s, _ := newTestStore(t)
	if _, err := s.UpsertProject(ctx, "/tmp/proj", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSession(ctx, models.Session{
		ID: sessionID, ProjectID: 1, Tool: models.ToolCopilotCLI, StartedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	countRows := func() int {
		t.Helper()
		var n int
		if err := s.db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM token_usage WHERE session_id = ?`, sessionID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// Tier-1 (otel) — the pre-recovery shape: message_id is the literal "null".
	tier1Null := models.TokenEvent{
		SourceFile: "/x/process.log", SourceEventID: "log:null:1",
		SessionID: sessionID, Timestamp: now,
		Tool: models.ToolCopilotCLI, Model: "claude-haiku-4-5-20251001",
		InputTokens: 16267, OutputTokens: 152, ReasoningTokens: 93,
		Source: models.TokenSourceOTel, Reliability: models.ReliabilityApproximate,
		MessageID: "null",
	}
	// Tier-3 (events.jsonl) — already carries the real hex:colon requestId.
	tier3 := models.TokenEvent{
		SourceFile: "/x/events.jsonl", SourceEventID: "a1:token",
		SessionID: sessionID, Timestamp: now,
		Tool: models.ToolCopilotCLI, Model: "claude-haiku-4.5",
		OutputTokens: 152,
		Source:       models.TokenSourceJSONL,
		Reliability:  models.ReliabilityUnreliable,
		MessageID:    realID,
	}

	// First ingest (pre-recovery): message_ids differ, so the sweep can't
	// fire — both rows persist.
	if _, err := s.InsertTokenEvents(ctx, []models.TokenEvent{tier1Null, tier3}); err != nil {
		t.Fatal(err)
	}
	if got := countRows(); got != 2 {
		t.Fatalf("pre-recovery: rows = %d, want 2 (sweep can't fire on mismatched message_id)", got)
	}

	// Rescan re-emits the Tier-1 row with the SAME source_event_id but the
	// recovered message_id. The UPSERT heals "null" -> realID and the sweep
	// then drops the Tier-3 shadow.
	tier1Healed := tier1Null
	tier1Healed.MessageID = realID
	if _, err := s.InsertTokenEvents(ctx, []models.TokenEvent{tier1Healed}); err != nil {
		t.Fatal(err)
	}
	if got := countRows(); got != 1 {
		t.Fatalf("post-recovery: rows = %d, want 1 (otel survivor; jsonl shadow swept)", got)
	}
	var gotSrc, gotMID string
	var gotIn, gotOut int64
	if err := s.db.QueryRowContext(ctx,
		`SELECT source, message_id, input_tokens, output_tokens FROM token_usage WHERE session_id = ?`,
		sessionID).Scan(&gotSrc, &gotMID, &gotIn, &gotOut); err != nil {
		t.Fatal(err)
	}
	if gotSrc != models.TokenSourceOTel {
		t.Errorf("source = %q, want otel (the full-usage survivor)", gotSrc)
	}
	if gotMID != realID {
		t.Errorf("message_id = %q, want the healed %q (no longer \"null\")", gotMID, realID)
	}
	if gotIn != 16267 || gotOut != 152 {
		t.Errorf("tokens: in=%d out=%d, want 16267/152", gotIn, gotOut)
	}
}

// TestInsertTokenEvents_CopilotCacheCreationCorrectsInputOnRescan pins the
// scoped input-correction upsert. Modern Copilot CLI lumps the cache-write
// portion into the gross prompt, so a pre-fix row stored it as net input (too
// high). A rescan re-parses the authoritative log with the corrected
// decomposition (lower input + a now-populated cache_creation); the UPSERT
// must trust the re-parse's input when it newly discovers cache_creation —
// but ONLY for the copilot tools. Every other adapter keeps the monotonic MAX
// so a partial re-parse can't lower a complete count.
func TestInsertTokenEvents_CopilotCacheCreationCorrectsInputOnRescan(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 6, 8, 12, 24, 28, 0, time.UTC)

	read := func(t *testing.T, s *Store, sessionID string) (in, cc, out int64) {
		t.Helper()
		if err := s.db.QueryRowContext(ctx,
			`SELECT input_tokens, cache_creation_tokens, output_tokens FROM token_usage WHERE session_id = ?`,
			sessionID).Scan(&in, &cc, &out); err != nil {
			t.Fatal(err)
		}
		return
	}
	seed := func(t *testing.T, s *Store, sessionID, tool string) {
		t.Helper()
		if _, err := s.UpsertProject(ctx, "/tmp/proj", ""); err != nil {
			t.Fatal(err)
		}
		if err := s.UpsertSession(ctx, models.Session{
			ID: sessionID, ProjectID: 1, Tool: tool, StartedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("copilot-cli — input corrected down, cache_creation populated", func(t *testing.T) {
		s, _ := newTestStore(t)
		seed(t, s, "sess-cc", models.ToolCopilotCLI)
		// Pre-fix row: the whole gross prompt landed as net input.
		pre := models.TokenEvent{
			SourceFile: "/x/process.log", SourceEventID: "log:r1:1",
			SessionID: "sess-cc", Timestamp: now,
			Tool: models.ToolCopilotCLI, Model: "claude-haiku-4-5-20251001",
			InputTokens: 16267, OutputTokens: 152,
			Source: models.TokenSourceOTel, Reliability: models.ReliabilityApproximate,
			MessageID: "r1",
		}
		if _, err := s.InsertTokenEvents(ctx, []models.TokenEvent{pre}); err != nil {
			t.Fatal(err)
		}
		if in, cc, _ := read(t, s, "sess-cc"); in != 16267 || cc != 0 {
			t.Fatalf("pre-rescan: in=%d cc=%d, want 16267/0", in, cc)
		}
		// Rescan re-emits with the corrected decomposition.
		fixed := pre
		fixed.InputTokens = 10
		fixed.CacheCreationTokens = 16257
		if _, err := s.InsertTokenEvents(ctx, []models.TokenEvent{fixed}); err != nil {
			t.Fatal(err)
		}
		if in, cc, out := read(t, s, "sess-cc"); in != 10 || cc != 16257 || out != 152 {
			t.Errorf("post-rescan: in=%d cc=%d out=%d, want 10/16257/152 (input corrected down)", in, cc, out)
		}
	})

	t.Run("claude-code — input keeps MAX (correction is copilot-scoped)", func(t *testing.T) {
		s, _ := newTestStore(t)
		seed(t, s, "sess-cc-guard", models.ToolClaudeCode)
		pre := models.TokenEvent{
			SourceFile: "/y/transcript.jsonl", SourceEventID: "cc:1",
			SessionID: "sess-cc-guard", Timestamp: now,
			Tool: models.ToolClaudeCode, Model: "claude-opus-4-8",
			InputTokens: 16267, OutputTokens: 152,
			Source: models.TokenSourceJSONL, Reliability: models.ReliabilityApproximate,
			MessageID: "cc-1",
		}
		if _, err := s.InsertTokenEvents(ctx, []models.TokenEvent{pre}); err != nil {
			t.Fatal(err)
		}
		// Same shape of re-emit, but a non-copilot tool: MAX must keep 16267.
		fixed := pre
		fixed.InputTokens = 10
		fixed.CacheCreationTokens = 16257
		if _, err := s.InsertTokenEvents(ctx, []models.TokenEvent{fixed}); err != nil {
			t.Fatal(err)
		}
		if in, cc, _ := read(t, s, "sess-cc-guard"); in != 16267 || cc != 16257 {
			t.Errorf("guard: in=%d cc=%d, want 16267/16257 (MAX kept input; cc still MAX-heals)", in, cc)
		}
	})
}

// TestInsertTokenEvents_DedupScopedToCopilotCLI ensures the v1.6.3
// dedup logic does NOT touch rows from other adapters even when they
// share (session_id, message_id, source). Anthropic proxy + claudecode
// JSONL overlap is a real future possibility; the dedup is intentionally
// narrow until that's handled separately.
func TestInsertTokenEvents_DedupScopedToCopilotCLI(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)

	if _, err := s.UpsertProject(ctx, "/tmp/proj", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSession(ctx, models.Session{
		ID: "sess-cc", ProjectID: 1, Tool: models.ToolClaudeCode, StartedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	// Two rows for claude-code sharing (session_id, message_id) but
	// from different sources. The dedup must NOT touch these.
	events := []models.TokenEvent{
		{
			SourceFile: "/x/events.jsonl", SourceEventID: "req-1:token",
			SessionID: "sess-cc", Timestamp: now,
			Tool: models.ToolClaudeCode, Model: "claude-sonnet-4-6",
			OutputTokens: 200, Source: models.TokenSourceJSONL,
			Reliability: models.ReliabilityUnreliable, MessageID: "req-1",
		},
		{
			SourceFile: "/x/proxy.log", SourceEventID: "proxy:req-1",
			SessionID: "sess-cc", Timestamp: now,
			Tool: models.ToolClaudeCode, Model: "claude-sonnet-4-6",
			InputTokens: 1000, OutputTokens: 200,
			Source: models.TokenSourceProxy, Reliability: models.ReliabilityAccurate,
			MessageID: "req-1",
		},
	}
	if _, err := s.InsertTokenEvents(ctx, events); err != nil {
		t.Fatal(err)
	}

	var rows int
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM token_usage WHERE session_id = 'sess-cc' AND message_id = 'req-1'`,
	).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 2 {
		t.Errorf("claude-code rows: got %d want 2 (dedup must NOT scope across tools)", rows)
	}
}

// TestInsertTokenEvents_SessionSummaryDroppedWhenOtelPresent pins
// the v1.6.6 Tier 0 ≺ Tier 1 precedence rule. When a copilot-cli
// session has any source='otel' row (Tier 1, full per-request
// breakdown captured via debug log), the session-summary row from
// session.shutdown.modelMetrics must be dropped — otherwise the
// session-level aggregate input/cache would double-count what
// Tier 1 already covers per-request.
func TestInsertTokenEvents_SessionSummaryDroppedWhenOtelPresent(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)

	if _, err := s.UpsertProject(ctx, "/tmp/proj", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSession(ctx, models.Session{
		ID: "sess-cli", ProjectID: 1, Tool: models.ToolCopilotCLI, StartedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	events := []models.TokenEvent{
		// Tier 1: per-request otel row from debug log.
		{
			SourceFile: "/x/process.log", SourceEventID: "log:req-1",
			SessionID: "sess-cli", Timestamp: now,
			Tool: models.ToolCopilotCLI, Model: "claude-opus-4.7",
			InputTokens: 1000, OutputTokens: 50, CacheReadTokens: 500,
			Source: models.TokenSourceOTel, Reliability: models.ReliabilityApproximate,
			MessageID: "req-1",
		},
		// Tier 0: session-shutdown row.
		{
			SourceFile: "/x/events.jsonl", SourceEventID: "shut-1:claude-opus-4.7",
			SessionID: "sess-cli", Timestamp: now,
			Tool: models.ToolCopilotCLI, Model: "claude-opus-4.7",
			InputTokens: 5000, CacheReadTokens: 4000,
			Source: models.TokenSourceSessionSummary, Reliability: models.ReliabilityApproximate,
			MessageID: "session-shutdown:shut-1",
		},
	}
	if _, err := s.InsertTokenEvents(ctx, events); err != nil {
		t.Fatal(err)
	}

	var rows int
	var srcs string
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT COUNT(*), COALESCE(GROUP_CONCAT(source, ','), '') FROM token_usage
		 WHERE session_id = 'sess-cli'`,
	).Scan(&rows, &srcs); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Errorf("rows: got %d want 1 (Tier 0 must be dropped when Tier 1 exists)", rows)
	}
	if srcs != models.TokenSourceOTel {
		t.Errorf("surviving source: got %q want %q", srcs, models.TokenSourceOTel)
	}
}

// TestInsertTokenEvents_SessionSummaryPreservedAloneNoOtel pins that
// when no Tier 1 (otel) row exists for the session, the Tier 0
// (session_summary) row is kept. This is the common case for users
// not running `copilot --log-level debug` — Tier 0 is the only source
// of input/cache/reasoning data and must survive.
func TestInsertTokenEvents_SessionSummaryPreservedAloneNoOtel(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)

	if _, err := s.UpsertProject(ctx, "/tmp/proj", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSession(ctx, models.Session{
		ID: "sess-cli-no-debug", ProjectID: 1, Tool: models.ToolCopilotCLI, StartedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	events := []models.TokenEvent{
		{
			SourceFile: "/x/events.jsonl", SourceEventID: "shut-1:claude-opus-4.7",
			SessionID: "sess-cli-no-debug", Timestamp: now,
			Tool: models.ToolCopilotCLI, Model: "claude-opus-4.7",
			InputTokens: 5000, CacheReadTokens: 4000,
			Source: models.TokenSourceSessionSummary, Reliability: models.ReliabilityApproximate,
			MessageID: "session-shutdown:shut-1",
		},
	}
	if _, err := s.InsertTokenEvents(ctx, events); err != nil {
		t.Fatal(err)
	}

	var rows int
	var in int64
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT COUNT(*), COALESCE(MAX(input_tokens), 0) FROM token_usage
		 WHERE session_id = 'sess-cli-no-debug'`,
	).Scan(&rows, &in); err != nil {
		t.Fatal(err)
	}
	if rows != 1 || in != 5000 {
		t.Errorf("rows=%d in=%d want rows=1 in=5000 (Tier 0 must survive when no Tier 1 exists)", rows, in)
	}
}

// TestInsertTokenEvents_SessionSummaryAndTier3Coexist pins that the
// Tier 0 (session_summary, session-level aggregate input/cache) and
// Tier 3 (jsonl, per-message outputTokens) rows coexist with no
// interference. The cost engine SUMs them: Tier 3 contributes
// per-message OutputTokens, Tier 0 contributes session-aggregate
// InputTokens / CacheReadTokens / etc. → complete capture.
func TestInsertTokenEvents_SessionSummaryAndTier3Coexist(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)

	if _, err := s.UpsertProject(ctx, "/tmp/proj", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSession(ctx, models.Session{
		ID: "sess-cli-coex", ProjectID: 1, Tool: models.ToolCopilotCLI, StartedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	events := []models.TokenEvent{
		// Tier 3 per-message: only OutputTokens populated.
		{
			SourceFile: "/x/events.jsonl", SourceEventID: "msg-1:token",
			SessionID: "sess-cli-coex", Timestamp: now,
			Tool: models.ToolCopilotCLI, Model: "claude-opus-4.7",
			OutputTokens: 100,
			Source:       models.TokenSourceJSONL, Reliability: models.ReliabilityUnreliable,
			MessageID: "req-1",
		},
		{
			SourceFile: "/x/events.jsonl", SourceEventID: "msg-2:token",
			SessionID: "sess-cli-coex", Timestamp: now.Add(time.Second),
			Tool: models.ToolCopilotCLI, Model: "claude-opus-4.7",
			OutputTokens: 200,
			Source:       models.TokenSourceJSONL, Reliability: models.ReliabilityUnreliable,
			MessageID: "req-2",
		},
		// Tier 0 session-level aggregate: InputTokens + CacheReadTokens.
		{
			SourceFile: "/x/events.jsonl", SourceEventID: "shut-1:claude-opus-4.7",
			SessionID: "sess-cli-coex", Timestamp: now.Add(2 * time.Second),
			Tool: models.ToolCopilotCLI, Model: "claude-opus-4.7",
			InputTokens: 50000, CacheReadTokens: 40000,
			Source: models.TokenSourceSessionSummary, Reliability: models.ReliabilityApproximate,
			MessageID: "session-shutdown:shut-1",
		},
	}
	if _, err := s.InsertTokenEvents(ctx, events); err != nil {
		t.Fatal(err)
	}

	var rows int
	var inSum, outSum, crSum int64
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT COUNT(*),
		        COALESCE(SUM(input_tokens), 0),
		        COALESCE(SUM(output_tokens), 0),
		        COALESCE(SUM(cache_read_tokens), 0)
		 FROM token_usage WHERE session_id = 'sess-cli-coex'`,
	).Scan(&rows, &inSum, &outSum, &crSum); err != nil {
		t.Fatal(err)
	}
	if rows != 3 {
		t.Errorf("rows: got %d want 3 (no Tier 1, all three rows must survive)", rows)
	}
	if inSum != 50000 || outSum != 300 || crSum != 40000 {
		t.Errorf("token sums: in=%d out=%d cr=%d want 50000/300/40000", inSum, outSum, crSum)
	}
}

// TestInsertTokenEvents_SessionSummaryIdempotentReparse pins that
// re-ingesting the same session.shutdown event produces no new rows.
// The UNIQUE (source_file, source_event_id) constraint catches the
// upsert; the post-batch dedup pass is a no-op when nothing changed.
func TestInsertTokenEvents_SessionSummaryIdempotentReparse(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)

	if _, err := s.UpsertProject(ctx, "/tmp/proj", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSession(ctx, models.Session{
		ID: "sess-cli-idem", ProjectID: 1, Tool: models.ToolCopilotCLI, StartedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	mk := func() []models.TokenEvent {
		return []models.TokenEvent{
			{
				SourceFile: "/x/events.jsonl", SourceEventID: "shut-1:claude-opus-4.7",
				SessionID: "sess-cli-idem", Timestamp: now,
				Tool: models.ToolCopilotCLI, Model: "claude-opus-4.7",
				InputTokens: 1000, CacheReadTokens: 800,
				Source: models.TokenSourceSessionSummary, Reliability: models.ReliabilityApproximate,
				MessageID: "session-shutdown:shut-1",
			},
		}
	}
	for i := 0; i < 3; i++ {
		if _, err := s.InsertTokenEvents(ctx, mk()); err != nil {
			t.Fatalf("ingest %d: %v", i, err)
		}
	}

	var rows int
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM token_usage WHERE session_id = 'sess-cli-idem'`,
	).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Errorf("rows after 3 ingests: got %d want 1 (UNIQUE constraint must dedup)", rows)
	}
}

// TestInsertTokenEvents_SessionSummaryMultiModelsAllSurvive pins that
// multiple per-model rows from one session.shutdown event survive
// independently — they share the same MessageID but their token
// tuples differ, so the v1.6.5 tuple dedup must not collapse them.
func TestInsertTokenEvents_SessionSummaryMultiModelsAllSurvive(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)

	if _, err := s.UpsertProject(ctx, "/tmp/proj", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSession(ctx, models.Session{
		ID: "sess-cli-multi", ProjectID: 1, Tool: models.ToolCopilotCLI, StartedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	events := []models.TokenEvent{
		{
			SourceFile: "/x/events.jsonl", SourceEventID: "shut-1:claude-opus-4.7",
			SessionID: "sess-cli-multi", Timestamp: now,
			Tool: models.ToolCopilotCLI, Model: "claude-opus-4.7",
			InputTokens: 5000, CacheReadTokens: 4000,
			Source: models.TokenSourceSessionSummary, Reliability: models.ReliabilityApproximate,
			MessageID: "session-shutdown:shut-1",
		},
		{
			SourceFile: "/x/events.jsonl", SourceEventID: "shut-1:gpt-5.4",
			SessionID: "sess-cli-multi", Timestamp: now,
			Tool: models.ToolCopilotCLI, Model: "gpt-5.4",
			InputTokens: 8000, CacheReadTokens: 6000, ReasoningTokens: 200,
			Source: models.TokenSourceSessionSummary, Reliability: models.ReliabilityApproximate,
			MessageID: "session-shutdown:shut-1",
		},
		{
			SourceFile: "/x/events.jsonl", SourceEventID: "shut-1:claude-haiku-4.5",
			SessionID: "sess-cli-multi", Timestamp: now,
			Tool: models.ToolCopilotCLI, Model: "claude-haiku-4.5",
			InputTokens: 512, CacheReadTokens: 256,
			Source: models.TokenSourceSessionSummary, Reliability: models.ReliabilityApproximate,
			MessageID: "session-shutdown:shut-1",
		},
	}
	if _, err := s.InsertTokenEvents(ctx, events); err != nil {
		t.Fatal(err)
	}

	var rows int
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM token_usage
		 WHERE session_id = 'sess-cli-multi' AND message_id = 'session-shutdown:shut-1'`,
	).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 3 {
		t.Errorf("rows: got %d want 3 (each model has a distinct token tuple — tuple dedup must not collapse)", rows)
	}
}

// TestInsertTokenEvents_TupleDedupIdenticalRows pins the v1.6.5
// tuple-level dedup: claudecode JSONL writes one content-block line
// per text/tool_use block, and every line carries the same
// cumulative usage snapshot of the parent API call. Pre-cb16006 the
// adapter keyed source_event_id off per-line UUIDs, escaping the
// UNIQUE constraint and leaving N rows per logical assistant
// message. The tuple dedup collapses byte-identical re-emissions per
// (tool, session_id, message_id), keeping the highest-id row.
func TestInsertTokenEvents_TupleDedupIdenticalRows(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)

	if _, err := s.UpsertProject(ctx, "/tmp/proj", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSession(ctx, models.Session{
		ID: "sess-cc", ProjectID: 1, Tool: models.ToolClaudeCode, StartedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	// Five rows for the same (session_id, message_id) with identical
	// token tuples but different source_event_ids — exactly the
	// pre-cb16006 claudecode shape.
	const msgID = "msg_01ABCDEFG"
	events := make([]models.TokenEvent, 5)
	for i := range events {
		events[i] = models.TokenEvent{
			SourceFile: "/x/2626c1f6.jsonl", SourceEventID: "uuid-" + string(rune('a'+i)),
			SessionID: "sess-cc", Timestamp: now.Add(time.Duration(i) * time.Second),
			Tool: models.ToolClaudeCode, Model: "claude-opus-4-7",
			InputTokens: 1, OutputTokens: 3283,
			CacheReadTokens: 258985, CacheCreationTokens: 2097,
			Source: models.TokenSourceJSONL, Reliability: models.ReliabilityUnreliable,
			MessageID: msgID,
		}
	}
	if _, err := s.InsertTokenEvents(ctx, events); err != nil {
		t.Fatal(err)
	}

	var rows int
	var maxID int64
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT COUNT(*), COALESCE(MAX(id), 0) FROM token_usage
		 WHERE session_id = 'sess-cc' AND message_id = ?`, msgID,
	).Scan(&rows, &maxID); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Errorf("rows: got %d want 1 (5 identical tuples should collapse)", rows)
	}
	// The surviving row should be the highest-id one (last inserted).
	if maxID == 0 {
		t.Errorf("surviving row id should be > 0")
	}
}

// TestInsertTokenEvents_TupleDedupPreservesDistinctRows pins that
// rows in the same (tool, session_id, message_id) group with DISTINCT
// token tuples are NOT collapsed. Codex emits multiple per-turn
// delta token_count events that legitimately share TurnID; each row
// represents real separate billable cost and must be preserved.
func TestInsertTokenEvents_TupleDedupPreservesDistinctRows(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)

	if _, err := s.UpsertProject(ctx, "/tmp/proj", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSession(ctx, models.Session{
		ID: "sess-cx", ProjectID: 1, Tool: models.ToolCodex, StartedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	const turnID = "turn-1"
	// Three codex token_count emissions sharing TurnID but with
	// progressing token values — the L77/L83/L95 pattern but with
	// all three distinct.
	events := []models.TokenEvent{
		{
			SourceFile: "/x/rollout.jsonl", SourceEventID: "tk:rollout.jsonl:L14",
			SessionID: "sess-cx", Timestamp: now,
			Tool: models.ToolCodex, Model: "gpt-5-codex",
			InputTokens: 22286, OutputTokens: 342, CacheReadTokens: 4480,
			Source: models.TokenSourceJSONL, Reliability: models.ReliabilityApproximate,
			MessageID: turnID,
		},
		{
			SourceFile: "/x/rollout.jsonl", SourceEventID: "tk:rollout.jsonl:L38",
			SessionID: "sess-cx", Timestamp: now.Add(30 * time.Second),
			Tool: models.ToolCodex, Model: "gpt-5-codex",
			InputTokens: 39679, OutputTokens: 1529, CacheReadTokens: 21376,
			Source: models.TokenSourceJSONL, Reliability: models.ReliabilityApproximate,
			MessageID: turnID,
		},
		{
			SourceFile: "/x/rollout.jsonl", SourceEventID: "tk:rollout.jsonl:L95",
			SessionID: "sess-cx", Timestamp: now.Add(60 * time.Second),
			Tool: models.ToolCodex, Model: "gpt-5-codex",
			InputTokens: 39755, OutputTokens: 1097, CacheReadTokens: 24960,
			Source: models.TokenSourceJSONL, Reliability: models.ReliabilityApproximate,
			MessageID: turnID,
		},
	}
	if _, err := s.InsertTokenEvents(ctx, events); err != nil {
		t.Fatal(err)
	}

	var rows int
	var sumIn int64
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT COUNT(*), COALESCE(SUM(input_tokens), 0) FROM token_usage
		 WHERE session_id = 'sess-cx' AND message_id = ?`, turnID,
	).Scan(&rows, &sumIn); err != nil {
		t.Fatal(err)
	}
	if rows != 3 {
		t.Errorf("rows: got %d want 3 (distinct tuples must all survive)", rows)
	}
	if got, want := sumIn, int64(22286+39679+39755); got != want {
		t.Errorf("sum(input_tokens): got %d want %d (delta semantics preserved)", got, want)
	}
}

// TestInsertTokenEvents_ClaudecodeSnapshotDriftDedup pins the v1.6.10
// audit B2 fix: when the same (claude-code, session_id, message_id)
// appears in TWO JSONL source_files with DIFFERENT cumulative output
// snapshots (parent file's early cumulative value + acompact subagent
// file's later snapshot of the same in-flight API turn), the cross-
// file dedup keeps only the row with the highest output_tokens (the
// canonical latest snapshot) and drops siblings. Without this fix the
// cost engine would sum both rows and double-count the API call —
// 96 msgids / +2,401 output tokens on the maintainer corpus.
func TestInsertTokenEvents_ClaudecodeSnapshotDriftDedup(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)

	if _, err := s.UpsertProject(ctx, "/tmp/proj", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSession(ctx, models.Session{
		ID: "sess-cc-drift", ProjectID: 1, Tool: models.ToolClaudeCode, StartedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	const msgID = "msg_01XYZ"
	// Parent file's row — early cumulative-stream snapshot of msgID
	// with output=8 (one of many cumulative emissions; per-file dedup
	// at claudecode/adapter.go:279 already collapsed the parent's N
	// content-block lines to this one row).
	// Acompact subagent file's row — later cumulative snapshot of the
	// same API turn, captured when auto-compaction stitched the
	// in-flight state. output=336.
	// Both Source=jsonl. Bug: byte-identical dedup doesn't catch them
	// (token tuples differ), so both survive into the cost engine.
	events := []models.TokenEvent{
		{
			SourceFile: "/x/sess-cc-drift.jsonl", SourceEventID: "ev-parent",
			SessionID: "sess-cc-drift", Timestamp: now,
			Tool: models.ToolClaudeCode, Model: "claude-opus-4-6",
			InputTokens: 1, OutputTokens: 8,
			Source: models.TokenSourceJSONL, Reliability: models.ReliabilityUnreliable,
			MessageID: msgID,
		},
		{
			SourceFile: "/x/sess-cc-drift/subagents/agent-acompact-X.jsonl", SourceEventID: "ev-acompact",
			SessionID: "sess-cc-drift", Timestamp: now.Add(time.Second),
			Tool: models.ToolClaudeCode, Model: "claude-opus-4-6",
			InputTokens: 1, OutputTokens: 336,
			Source: models.TokenSourceJSONL, Reliability: models.ReliabilityUnreliable,
			MessageID: msgID,
		},
	}
	if _, err := s.InsertTokenEvents(ctx, events); err != nil {
		t.Fatal(err)
	}

	var rows int
	var sumOut int64
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT COUNT(*), COALESCE(SUM(output_tokens), 0) FROM token_usage
		 WHERE session_id = 'sess-cc-drift' AND message_id = ?`, msgID,
	).Scan(&rows, &sumOut); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Errorf("rows: got %d want 1 (snapshot-drift dedup must collapse parent+acompact)", rows)
	}
	if sumOut != 336 {
		t.Errorf("sum(output_tokens): got %d want 336 (must keep higher cumulative snapshot, not sum)", sumOut)
	}
}

// TestInsertTokenEvents_ClaudecodeCrossSourceProxyJsonlSurvive pins
// that the v1.6.10 snapshot-drift dedup does NOT collapse the
// claude-code-jsonl ⊕ anthropic-proxy pair (different `source` values)
// even when they share (session_id, message_id). Anthropic proxy
// capture carries full input/cache breakdown that JSONL omits — both
// rows must survive so the cost engine sees the proxy's complete
// picture alongside the JSONL row.
func TestInsertTokenEvents_ClaudecodeCrossSourceProxyJsonlSurvive(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)

	if _, err := s.UpsertProject(ctx, "/tmp/proj", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSession(ctx, models.Session{
		ID: "sess-cc-cross", ProjectID: 1, Tool: models.ToolClaudeCode, StartedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	const msgID = "msg_proxy_cross"
	events := []models.TokenEvent{
		{
			SourceFile: "/x/sess.jsonl", SourceEventID: "ev-jsonl",
			SessionID: "sess-cc-cross", Timestamp: now,
			Tool: models.ToolClaudeCode, Model: "claude-opus-4-7",
			OutputTokens: 100,
			Source:       models.TokenSourceJSONL, Reliability: models.ReliabilityUnreliable,
			MessageID: msgID,
		},
		{
			SourceFile: "/x/proxy.log", SourceEventID: "ev-proxy",
			SessionID: "sess-cc-cross", Timestamp: now,
			Tool: models.ToolClaudeCode, Model: "claude-opus-4-7",
			InputTokens: 5000, OutputTokens: 100, CacheReadTokens: 12000,
			Source: models.TokenSourceProxy, Reliability: models.ReliabilityAccurate,
			MessageID: msgID,
		},
	}
	if _, err := s.InsertTokenEvents(ctx, events); err != nil {
		t.Fatal(err)
	}
	var rows int
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM token_usage WHERE session_id = 'sess-cc-cross' AND message_id = ?`, msgID,
	).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 2 {
		t.Errorf("rows: got %d want 2 (cross-source proxy+jsonl pair must NOT be collapsed)", rows)
	}
}

// TestInsertTokenEvents_TupleDedupPreservesEmptyMessageID pins that
// rows with empty MessageID are never touched by the tuple dedup,
// even if their token tuples match. The dedup contract requires a
// non-empty message_id; rows without it are pre-msg.id-era data that
// must not be retroactively merged.
func TestInsertTokenEvents_TupleDedupPreservesEmptyMessageID(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)

	if _, err := s.UpsertProject(ctx, "/tmp/proj", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSession(ctx, models.Session{
		ID: "sess-no-msg", ProjectID: 1, Tool: models.ToolClaudeCode, StartedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	// Three rows with identical tuples but EMPTY MessageID, plus one
	// trigger row with non-empty MessageID so the dedup pass actually
	// runs (hasMsgIDBearing gate).
	events := []models.TokenEvent{
		{
			SourceFile: "/x/file.jsonl", SourceEventID: "uuid-1",
			SessionID: "sess-no-msg", Timestamp: now,
			Tool: models.ToolClaudeCode, Model: "claude-opus-4-7",
			InputTokens: 100, OutputTokens: 50,
			Source: models.TokenSourceJSONL, Reliability: models.ReliabilityUnreliable,
			MessageID: "",
		},
		{
			SourceFile: "/x/file.jsonl", SourceEventID: "uuid-2",
			SessionID: "sess-no-msg", Timestamp: now.Add(time.Second),
			Tool: models.ToolClaudeCode, Model: "claude-opus-4-7",
			InputTokens: 100, OutputTokens: 50,
			Source: models.TokenSourceJSONL, Reliability: models.ReliabilityUnreliable,
			MessageID: "",
		},
		{
			SourceFile: "/x/file.jsonl", SourceEventID: "uuid-3",
			SessionID: "sess-no-msg", Timestamp: now.Add(2 * time.Second),
			Tool: models.ToolClaudeCode, Model: "claude-opus-4-7",
			InputTokens: 100, OutputTokens: 50,
			Source: models.TokenSourceJSONL, Reliability: models.ReliabilityUnreliable,
			MessageID: "",
		},
		{
			SourceFile: "/x/file.jsonl", SourceEventID: "trigger",
			SessionID: "sess-no-msg", Timestamp: now,
			Tool: models.ToolClaudeCode, Model: "claude-opus-4-7",
			InputTokens: 999, OutputTokens: 999,
			Source: models.TokenSourceJSONL, Reliability: models.ReliabilityUnreliable,
			MessageID: "msg_trigger",
		},
	}
	if _, err := s.InsertTokenEvents(ctx, events); err != nil {
		t.Fatal(err)
	}

	var emptyRows int
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM token_usage
		 WHERE session_id = 'sess-no-msg' AND COALESCE(message_id, '') = ''`,
	).Scan(&emptyRows); err != nil {
		t.Fatal(err)
	}
	if emptyRows != 3 {
		t.Errorf("empty-message-id rows: got %d want 3 (must be untouched by dedup)", emptyRows)
	}
}

// TestInsertTokenEvents_TupleDedupAcrossTools pins that the tuple
// dedup is scoped per-tool: two rows with identical
// (session_id, message_id, token-tuple) but DIFFERENT tools survive
// independently. Different tools are different cost contexts even
// when their captured snapshot happens to match.
func TestInsertTokenEvents_TupleDedupAcrossTools(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)

	if _, err := s.UpsertProject(ctx, "/tmp/proj", ""); err != nil {
		t.Fatal(err)
	}
	for _, sid := range []string{"sess-shared"} {
		if err := s.UpsertSession(ctx, models.Session{
			ID: sid, ProjectID: 1, Tool: models.ToolClaudeCode, StartedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}

	const msgID = "msg_xtool"
	events := []models.TokenEvent{
		{
			SourceFile: "/x/cc.jsonl", SourceEventID: "cc:uuid",
			SessionID: "sess-shared", Timestamp: now,
			Tool: models.ToolClaudeCode, Model: "claude-opus-4-7",
			InputTokens: 100, OutputTokens: 50, CacheReadTokens: 1000,
			Source: models.TokenSourceJSONL, Reliability: models.ReliabilityUnreliable,
			MessageID: msgID,
		},
		{
			SourceFile: "/x/codex.jsonl", SourceEventID: "cx:uuid",
			SessionID: "sess-shared", Timestamp: now,
			Tool: models.ToolCodex, Model: "gpt-5-codex",
			InputTokens: 100, OutputTokens: 50, CacheReadTokens: 1000,
			Source: models.TokenSourceJSONL, Reliability: models.ReliabilityApproximate,
			MessageID: msgID,
		},
	}
	if _, err := s.InsertTokenEvents(ctx, events); err != nil {
		t.Fatal(err)
	}

	var rows int
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM token_usage
		 WHERE session_id = 'sess-shared' AND message_id = ?`, msgID,
	).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 2 {
		t.Errorf("cross-tool rows: got %d want 2 (dedup must be tool-scoped)", rows)
	}
}

// TestInsertTokenEvents_TupleDedupArrivalOrder pins that the final
// state is identical regardless of insertion order: 5 identical
// rows produce 1 surviving row whether inserted as one batch,
// sequentially in single-event batches, or in reverse temporal
// order.
func TestInsertTokenEvents_TupleDedupArrivalOrder(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)

	mkEvents := func(sessionID string) []models.TokenEvent {
		events := make([]models.TokenEvent, 5)
		for i := range events {
			events[i] = models.TokenEvent{
				SourceFile: "/x/file.jsonl", SourceEventID: "uuid-" + string(rune('a'+i)),
				SessionID: sessionID, Timestamp: now.Add(time.Duration(i) * time.Second),
				Tool: models.ToolClaudeCode, Model: "claude-opus-4-7",
				InputTokens: 1, OutputTokens: 3283,
				CacheReadTokens: 258985, CacheCreationTokens: 2097,
				Source: models.TokenSourceJSONL, Reliability: models.ReliabilityUnreliable,
				MessageID: "msg_arrival",
			}
		}
		return events
	}

	cases := []struct {
		name   string
		insert func(t *testing.T, s *Store, sid string)
	}{
		{
			name: "single batch",
			insert: func(t *testing.T, s *Store, sid string) {
				if _, err := s.InsertTokenEvents(ctx, mkEvents(sid)); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "sequential single-event batches",
			insert: func(t *testing.T, s *Store, sid string) {
				for _, e := range mkEvents(sid) {
					if _, err := s.InsertTokenEvents(ctx, []models.TokenEvent{e}); err != nil {
						t.Fatal(err)
					}
				}
			},
		},
		{
			name: "reversed batch",
			insert: func(t *testing.T, s *Store, sid string) {
				evs := mkEvents(sid)
				for i, j := 0, len(evs)-1; i < j; i, j = i+1, j-1 {
					evs[i], evs[j] = evs[j], evs[i]
				}
				if _, err := s.InsertTokenEvents(ctx, evs); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newTestStore(t)
			if _, err := s.UpsertProject(ctx, "/tmp/proj", ""); err != nil {
				t.Fatal(err)
			}
			sid := "sess-arrival"
			if err := s.UpsertSession(ctx, models.Session{
				ID: sid, ProjectID: 1, Tool: models.ToolClaudeCode, StartedAt: now,
			}); err != nil {
				t.Fatal(err)
			}
			tc.insert(t, s, sid)

			var rows int
			if err := s.db.QueryRowContext(
				ctx,
				`SELECT COUNT(*) FROM token_usage
				 WHERE session_id = ? AND message_id = 'msg_arrival'`, sid,
			).Scan(&rows); err != nil {
				t.Fatal(err)
			}
			if rows != 1 {
				t.Errorf("rows after %s: got %d want 1", tc.name, rows)
			}
		})
	}
}

// TestInsertTokenEvents_TupleDedupCoexistsWithCopilotCLI pins that
// the v1.6.5 tuple dedup runs alongside the v1.6.3 T1 mixed-source
// dedup without interference. A single batch containing copilot-cli
// tier1+tier3 (mixed-source, distinct tuples — handled by T1) AND a
// separate claude-code identical-tuple dup group (handled by tuple
// dedup) resolves to 1 copilot-cli row (tier1 wins) + 1 claude-code
// row (highest id wins).
func TestInsertTokenEvents_TupleDedupCoexistsWithCopilotCLI(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)

	if _, err := s.UpsertProject(ctx, "/tmp/proj", ""); err != nil {
		t.Fatal(err)
	}
	for _, sess := range []models.Session{
		{ID: "sess-cli", ProjectID: 1, Tool: models.ToolCopilotCLI, StartedAt: now},
		{ID: "sess-cc", ProjectID: 1, Tool: models.ToolClaudeCode, StartedAt: now},
	} {
		if err := s.UpsertSession(ctx, sess); err != nil {
			t.Fatal(err)
		}
	}

	events := []models.TokenEvent{
		// copilot-cli mixed-source: tier3 (jsonl) + tier1 (otel).
		// v1.6.3 T1 drops tier3.
		{
			SourceFile: "/x/events.jsonl", SourceEventID: "req-1:token",
			SessionID: "sess-cli", Timestamp: now,
			Tool: models.ToolCopilotCLI, Model: "gpt-5-mini",
			OutputTokens: 565, Source: models.TokenSourceJSONL,
			Reliability: models.ReliabilityUnreliable, MessageID: "req-1",
		},
		{
			SourceFile: "/x/process.log", SourceEventID: "log:req-1",
			SessionID: "sess-cli", Timestamp: now,
			Tool: models.ToolCopilotCLI, Model: "gpt-5-mini",
			InputTokens: 15474, OutputTokens: 565, CacheReadTokens: 2560, ReasoningTokens: 448,
			Source: models.TokenSourceOTel, Reliability: models.ReliabilityApproximate,
			MessageID: "req-1",
		},
		// claudecode identical-tuple dups for the same msg.id.
		// Tuple dedup collapses these 3 to 1.
		{
			SourceFile: "/x/cc.jsonl", SourceEventID: "uuid-a",
			SessionID: "sess-cc", Timestamp: now,
			Tool: models.ToolClaudeCode, Model: "claude-opus-4-7",
			InputTokens: 1, OutputTokens: 100, CacheReadTokens: 50000, CacheCreationTokens: 1024,
			Source: models.TokenSourceJSONL, Reliability: models.ReliabilityUnreliable,
			MessageID: "msg_cc",
		},
		{
			SourceFile: "/x/cc.jsonl", SourceEventID: "uuid-b",
			SessionID: "sess-cc", Timestamp: now.Add(time.Second),
			Tool: models.ToolClaudeCode, Model: "claude-opus-4-7",
			InputTokens: 1, OutputTokens: 100, CacheReadTokens: 50000, CacheCreationTokens: 1024,
			Source: models.TokenSourceJSONL, Reliability: models.ReliabilityUnreliable,
			MessageID: "msg_cc",
		},
		{
			SourceFile: "/x/cc.jsonl", SourceEventID: "uuid-c",
			SessionID: "sess-cc", Timestamp: now.Add(2 * time.Second),
			Tool: models.ToolClaudeCode, Model: "claude-opus-4-7",
			InputTokens: 1, OutputTokens: 100, CacheReadTokens: 50000, CacheCreationTokens: 1024,
			Source: models.TokenSourceJSONL, Reliability: models.ReliabilityUnreliable,
			MessageID: "msg_cc",
		},
	}
	if _, err := s.InsertTokenEvents(ctx, events); err != nil {
		t.Fatal(err)
	}

	var cliRows, cliIn int64
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT COUNT(*), COALESCE(MAX(input_tokens), 0) FROM token_usage
		 WHERE session_id = 'sess-cli' AND message_id = 'req-1'`,
	).Scan(&cliRows, &cliIn); err != nil {
		t.Fatal(err)
	}
	if cliRows != 1 || cliIn != 15474 {
		t.Errorf("copilot-cli row: got rows=%d in=%d want rows=1 in=15474 (tier1 should win)", cliRows, cliIn)
	}

	var ccRows int
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM token_usage
		 WHERE session_id = 'sess-cc' AND message_id = 'msg_cc'`,
	).Scan(&ccRows); err != nil {
		t.Fatal(err)
	}
	if ccRows != 1 {
		t.Errorf("claude-code dup group: got %d rows want 1 (3 identical tuples should collapse)", ccRows)
	}
}

// TestInsertTokenEvents_SessionSummaryMidDebugToggle pins the
// v1.6.8 B2 fix: when --log-level debug is enabled MID-SESSION,
// pre-debug shutdowns emit modelMetrics with NO otel coverage in
// their window; post-debug shutdowns emit modelMetrics AND otel
// rows. The pre-v1.6.8 sweep dropped ALL session_summary rows the
// moment any otel row existed for the session — silently losing
// the pre-debug Tier-0 input/cache that no other Tier covers.
// The fix scopes the drop to the per-shutdown timestamp window
// (prior_session_summary_ts, this_ts]: pre-debug session_summary
// survives (no otel in its window), post-debug drops.
func TestInsertTokenEvents_SessionSummaryMidDebugToggle(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	t0 := time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC)

	if _, err := s.UpsertProject(ctx, "/tmp/proj", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSession(ctx, models.Session{
		ID: "sess-cli-toggle", ProjectID: 1, Tool: models.ToolCopilotCLI, StartedAt: t0,
	}); err != nil {
		t.Fatal(err)
	}

	// Two shutdowns. Shutdown 1 at t0+1h covers pre-debug period
	// (no otel rows). Shutdown 2 at t0+2h covers post-debug period
	// (debug enabled at t0+1h30m, otel rows fire between t0+1h30m
	// and t0+2h).
	shutdown1Ts := t0.Add(1 * time.Hour)
	shutdown2Ts := t0.Add(2 * time.Hour)
	otelTs := t0.Add(1*time.Hour + 30*time.Minute)

	events := []models.TokenEvent{
		// Pre-debug shutdown's session_summary — no otel in
		// (-∞, shutdown1Ts] window for this session.
		{
			SourceFile: "/x/events.jsonl", SourceEventID: "shut-1:claude-opus-4.7",
			SessionID: "sess-cli-toggle", Timestamp: shutdown1Ts,
			Tool: models.ToolCopilotCLI, Model: "claude-opus-4.7",
			InputTokens: 10_000_000, CacheReadTokens: 9_000_000,
			Source: models.TokenSourceSessionSummary, Reliability: models.ReliabilityApproximate,
			MessageID: "session-shutdown:shut-1",
		},
		// Otel row from a debug-mode API call between the two
		// shutdowns.
		{
			SourceFile: "/x/process.log", SourceEventID: "log:req-post-debug",
			SessionID: "sess-cli-toggle", Timestamp: otelTs,
			Tool: models.ToolCopilotCLI, Model: "claude-opus-4.7",
			InputTokens: 50_000, OutputTokens: 800, CacheReadTokens: 45_000,
			Source: models.TokenSourceOTel, Reliability: models.ReliabilityApproximate,
			MessageID: "req-post-debug",
		},
		// Post-debug shutdown's session_summary — otel row falls
		// in (shutdown1Ts, shutdown2Ts] window → DROP.
		{
			SourceFile: "/x/events.jsonl", SourceEventID: "shut-2:claude-opus-4.7",
			SessionID: "sess-cli-toggle", Timestamp: shutdown2Ts,
			Tool: models.ToolCopilotCLI, Model: "claude-opus-4.7",
			InputTokens: 100_000, CacheReadTokens: 90_000,
			Source: models.TokenSourceSessionSummary, Reliability: models.ReliabilityApproximate,
			MessageID: "session-shutdown:shut-2",
		},
	}
	if _, err := s.InsertTokenEvents(ctx, events); err != nil {
		t.Fatal(err)
	}

	var rows1, rows2, rowsOtel int
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM token_usage
		 WHERE session_id = 'sess-cli-toggle' AND message_id = 'session-shutdown:shut-1'`,
	).Scan(&rows1); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM token_usage
		 WHERE session_id = 'sess-cli-toggle' AND message_id = 'session-shutdown:shut-2'`,
	).Scan(&rows2); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM token_usage
		 WHERE session_id = 'sess-cli-toggle' AND source = 'otel'`,
	).Scan(&rowsOtel); err != nil {
		t.Fatal(err)
	}
	if rows1 != 1 {
		t.Errorf("shutdown-1 session_summary: got %d want 1 (pre-debug window has no otel; must NOT be dropped)", rows1)
	}
	if rows2 != 0 {
		t.Errorf("shutdown-2 session_summary: got %d want 0 (post-debug window has otel; MUST be dropped)", rows2)
	}
	if rowsOtel != 1 {
		t.Errorf("otel row: got %d want 1 (Tier 1 always survives)", rowsOtel)
	}
}

// TestInsertTokenEvents_SessionSummaryMultiShutdownAllDebug pins
// the "always-debug" path: every shutdown's window contains otel
// rows → all session_summary rows drop. This is the original
// v1.6.6 behaviour preserved unchanged by the v1.6.8 per-window
// scoping.
func TestInsertTokenEvents_SessionSummaryMultiShutdownAllDebug(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	t0 := time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC)

	if _, err := s.UpsertProject(ctx, "/tmp/proj", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSession(ctx, models.Session{
		ID: "sess-cli-always", ProjectID: 1, Tool: models.ToolCopilotCLI, StartedAt: t0,
	}); err != nil {
		t.Fatal(err)
	}

	events := []models.TokenEvent{
		// Otel pre-shutdown-1.
		{
			SourceFile: "/x/process.log", SourceEventID: "log:req-1",
			SessionID: "sess-cli-always", Timestamp: t0.Add(30 * time.Minute),
			Tool: models.ToolCopilotCLI, Model: "gpt-5-mini",
			InputTokens: 5000, OutputTokens: 100,
			Source: models.TokenSourceOTel, Reliability: models.ReliabilityApproximate,
			MessageID: "req-1",
		},
		// Shutdown 1.
		{
			SourceFile: "/x/events.jsonl", SourceEventID: "shut-1:gpt-5-mini",
			SessionID: "sess-cli-always", Timestamp: t0.Add(1 * time.Hour),
			Tool: models.ToolCopilotCLI, Model: "gpt-5-mini",
			InputTokens: 5000, CacheReadTokens: 1000,
			Source: models.TokenSourceSessionSummary, Reliability: models.ReliabilityApproximate,
			MessageID: "session-shutdown:shut-1",
		},
		// Otel between shutdowns.
		{
			SourceFile: "/x/process.log", SourceEventID: "log:req-2",
			SessionID: "sess-cli-always", Timestamp: t0.Add(90 * time.Minute),
			Tool: models.ToolCopilotCLI, Model: "gpt-5-mini",
			InputTokens: 7000, OutputTokens: 200,
			Source: models.TokenSourceOTel, Reliability: models.ReliabilityApproximate,
			MessageID: "req-2",
		},
		// Shutdown 2.
		{
			SourceFile: "/x/events.jsonl", SourceEventID: "shut-2:gpt-5-mini",
			SessionID: "sess-cli-always", Timestamp: t0.Add(2 * time.Hour),
			Tool: models.ToolCopilotCLI, Model: "gpt-5-mini",
			InputTokens: 7000, CacheReadTokens: 1500,
			Source: models.TokenSourceSessionSummary, Reliability: models.ReliabilityApproximate,
			MessageID: "session-shutdown:shut-2",
		},
	}
	if _, err := s.InsertTokenEvents(ctx, events); err != nil {
		t.Fatal(err)
	}

	var summaries, otels int
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM token_usage
		 WHERE session_id = 'sess-cli-always' AND source = 'session_summary'`,
	).Scan(&summaries); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM token_usage
		 WHERE session_id = 'sess-cli-always' AND source = 'otel'`,
	).Scan(&otels); err != nil {
		t.Fatal(err)
	}
	if summaries != 0 {
		t.Errorf("session_summary rows: got %d want 0 (all shutdowns have otel coverage)", summaries)
	}
	if otels != 2 {
		t.Errorf("otel rows: got %d want 2", otels)
	}
}

// TestInsertTokenEvents_TupleDedupSkipsCopilotCLIMultiBlock pins the
// v1.6.8 B1 fix: Copilot CLI emits one assistant.message event per
// content block (text / tool_use / reasoning), each carrying its own
// per-block outputTokens delta. All blocks under one API call share
// MessageID = requestId. Two distinct blocks can legitimately have
// byte-identical small outputTokens — the tool-agnostic v1.6.5 dedup
// wrongly collapsed them. The fix scopes the dedup to claude-code +
// codex only; copilot-cli rows survive their per-block legitimate
// duplicates.
//
// Fixture mirrors a real collision observed on the operator sample
// (tmp/session-files-examples/events.jsonl) — requestId
// 00000-abd359f9-... emitted 32 blocks including two with
// outputTokens=278 and two with outputTokens=264 (4 byte-identical
// pairs across 5 multi-block requestIds in total).
func TestInsertTokenEvents_TupleDedupSkipsCopilotCLIMultiBlock(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)

	if _, err := s.UpsertProject(ctx, "/tmp/proj", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSession(ctx, models.Session{
		ID: "sess-cli-mb", ProjectID: 1, Tool: models.ToolCopilotCLI, StartedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	// Six blocks under one requestId, two pairs byte-identical
	// (output=278 twice, output=264 twice). Mimics
	// 00000-abd359f9-af07-... from the audit sample.
	const requestID = "00000-abd359f9-af07-4cd2-a8eb-b8efb5ebc15b"
	outs := []int64{275, 295, 278, 278, 264, 264}
	events := make([]models.TokenEvent, len(outs))
	for i, ot := range outs {
		events[i] = models.TokenEvent{
			SourceFile:    "/x/events.jsonl",
			SourceEventID: "block-" + string(rune('a'+i)) + ":token",
			SessionID:     "sess-cli-mb",
			Timestamp:     now.Add(time.Duration(i) * time.Millisecond),
			Tool:          models.ToolCopilotCLI,
			Model:         "claude-opus-4.7",
			OutputTokens:  ot,
			Source:        models.TokenSourceJSONL,
			Reliability:   models.ReliabilityUnreliable,
			MessageID:     requestID,
		}
	}
	if _, err := s.InsertTokenEvents(ctx, events); err != nil {
		t.Fatal(err)
	}

	var rows int
	var sumOut int64
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT COUNT(*), COALESCE(SUM(output_tokens), 0) FROM token_usage
		 WHERE session_id = 'sess-cli-mb' AND message_id = ?`, requestID,
	).Scan(&rows, &sumOut); err != nil {
		t.Fatal(err)
	}
	if rows != 6 {
		t.Errorf("copilot-cli multi-block rows: got %d want 6 (per-block deltas are not re-emissions; dedup must not fire on copilot-cli)", rows)
	}
	var wantSum int64
	for _, ot := range outs {
		wantSum += ot
	}
	if sumOut != wantSum {
		t.Errorf("copilot-cli output sum: got %d want %d (all per-block deltas must contribute)", sumOut, wantSum)
	}
}

// TestInsertTokenEvents_TupleDedupAllowlistRejectsUnknownTool pins
// that the v1.6.8 allowlist scope keeps the dedup conservative: only
// claude-code + codex are scrubbed. New adapters that follow the
// Copilot CLI per-block pattern (or any other multi-row-per-MessageID
// shape) survive automatically without explicit opt-out — they just
// have to NOT be added to the allowlist.
//
// Uses cline as a representative "future tool we haven't audited
// emission patterns for"; its rows must survive byte-identical
// duplication.
func TestInsertTokenEvents_TupleDedupAllowlistRejectsUnknownTool(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)

	if _, err := s.UpsertProject(ctx, "/tmp/proj", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSession(ctx, models.Session{
		ID: "sess-cline", ProjectID: 1, Tool: models.ToolCline, StartedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	const msgID = "msg-cline"
	events := make([]models.TokenEvent, 3)
	for i := range events {
		events[i] = models.TokenEvent{
			SourceFile:    "/x/cline.jsonl",
			SourceEventID: "cline-uuid-" + string(rune('a'+i)),
			SessionID:     "sess-cline",
			Timestamp:     now.Add(time.Duration(i) * time.Second),
			Tool:          models.ToolCline,
			Model:         "claude-opus-4-7",
			InputTokens:   100, OutputTokens: 50,
			Source: models.TokenSourceJSONL, Reliability: models.ReliabilityUnreliable,
			MessageID: msgID,
		}
	}
	if _, err := s.InsertTokenEvents(ctx, events); err != nil {
		t.Fatal(err)
	}

	var rows int
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM token_usage
		 WHERE session_id = 'sess-cline' AND message_id = ?`, msgID,
	).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 3 {
		t.Errorf("cline rows: got %d want 3 (cline is not on the allowlist; dedup must not fire)", rows)
	}
}

// TestInsertTokenEvents_DedupSweepsSkippedForBrowserOnlyBatch pins the
// batch-gate perf fix: the tuple/snapshot-drift dedup sweeps only delete
// claude-code/codex rows, so a batch containing neither tool must NOT run
// them (they full-scan token_usage, and the always-msgid-bearing
// browser-hook lane was timing out on the scan under its 500ms deadline).
// Correctness proxy: seed two claude-code rows that ARE tuple-dedup
// candidates, insert a browser-web-only (claude-web) batch, and assert both
// claude-code rows survive (sweep skipped). Then insert a claude-code batch
// and assert the duplicate collapses (gate still fires when the tool is
// present).
func TestInsertTokenEvents_DedupSweepsSkippedForBrowserOnlyBatch(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)

	if _, err := s.UpsertProject(ctx, "/tmp/proj", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSession(ctx, models.Session{
		ID: "sess-cc-gate", ProjectID: 1, Tool: models.ToolClaudeCode, StartedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSession(ctx, models.Session{
		ID: "sess-web-gate", ProjectID: 1, Tool: models.ToolClaudeWeb, StartedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	const msgID = "msg_gate"
	// Seed two claude-code rows via raw SQL so they land WITHOUT the
	// dedup sweep collapsing them at insert time — this is the state the
	// sweep WOULD act on if it ran. Same (session,message) + identical
	// token dims, different source_event_id → tuple-dedup candidates.
	for i, ev := range []string{"seed-a", "seed-b"} {
		if _, err := s.db.ExecContext(
			ctx,
			`INSERT INTO token_usage
			   (session_id, timestamp, tool, model, input_tokens, output_tokens,
			    source, reliability, source_file, source_event_id, message_id)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			"sess-cc-gate", timestamp(now.Add(time.Duration(i)*time.Second)),
			models.ToolClaudeCode, "claude-opus-4-7", 10, 20,
			models.TokenSourceJSONL, models.ReliabilityUnreliable,
			"/x/seed.jsonl", ev, msgID,
		); err != nil {
			t.Fatal(err)
		}
	}

	ccCount := func() int {
		t.Helper()
		var n int
		if err := s.db.QueryRowContext(
			ctx,
			`SELECT COUNT(*) FROM token_usage
			 WHERE session_id = 'sess-cc-gate' AND message_id = ?`, msgID,
		).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if got := ccCount(); got != 2 {
		t.Fatalf("seed: got %d claude-code rows want 2", got)
	}

	// Insert a browser-web-only batch (claude-web, msgid-bearing, 500ms
	// browser-hook shape). hasMsgIDBearing is true but hasClaudeCode /
	// hasCodex are false → both sweeps must be skipped → the two seeded
	// claude-code duplicates survive untouched.
	webBatch := []models.TokenEvent{{
		SourceFile: "/x/claude-web.jsonl", SourceEventID: "web-1",
		SessionID: "sess-web-gate", Timestamp: now,
		Tool: models.ToolClaudeWeb, Model: "claude-opus-4-7",
		InputTokens: 500, OutputTokens: 250,
		Source: models.TokenSourceEstimated, Reliability: models.ReliabilityUnreliable,
		MessageID: "web-msg-1",
	}}
	if _, err := s.InsertTokenEvents(ctx, webBatch); err != nil {
		t.Fatal(err)
	}
	if got := ccCount(); got != 2 {
		t.Errorf("after claude-web batch: got %d claude-code rows want 2 (sweep must be skipped)", got)
	}

	// Now insert a claude-code batch. hasClaudeCode is true → the tuple
	// sweep fires and collapses the two seeded duplicates (the lower-id
	// row has a byte-identical higher-id sibling).
	ccBatch := []models.TokenEvent{{
		SourceFile: "/x/cc.jsonl", SourceEventID: "cc-trigger",
		SessionID: "sess-cc-gate", Timestamp: now.Add(5 * time.Second),
		Tool: models.ToolClaudeCode, Model: "claude-opus-4-7",
		InputTokens: 999, OutputTokens: 999,
		Source: models.TokenSourceJSONL, Reliability: models.ReliabilityUnreliable,
		MessageID: "cc-trigger-msg",
	}}
	if _, err := s.InsertTokenEvents(ctx, ccBatch); err != nil {
		t.Fatal(err)
	}
	if got := ccCount(); got != 1 {
		t.Errorf("after claude-code batch: got %d duplicate rows want 1 (gate must fire when claude-code present)", got)
	}
}

// TestInsertTokenEvents_CrossToolConflictNoMutation pins the upsert's
// `WHERE token_usage.tool = excluded.tool` guard: a batch from a DIFFERENT
// tool that collides on an existing claude-code row's
// (source_file, source_event_id) key must NOT mutate that row's token dims
// (which could otherwise manufacture tuple/snapshot-drift duplicates the
// now-batch-gated sweeps would skip). Cross-tool key collisions are
// impossible by construction today (disjoint per-adapter source namespaces),
// but the store must not rely on that.
func TestInsertTokenEvents_CrossToolConflictNoMutation(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)

	if _, err := s.UpsertProject(ctx, "/tmp/proj", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSession(ctx, models.Session{
		ID: "sess-xtool", ProjectID: 1, Tool: models.ToolClaudeCode, StartedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSession(ctx, models.Session{
		ID: "sess-xtool-web", ProjectID: 1, Tool: models.ToolClaudeWeb, StartedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	const msgID = "msg_xtool"
	// Seed two claude-code rows via raw SQL (bypassing the sweeps). Row A
	// key (file-a, event-a) tokens 10/20; row B a different source key,
	// same (session, message), tokens 30/40.
	seed := []struct {
		file, event string
		in, out     int
	}{
		{"/x/file-a.jsonl", "event-a", 10, 20},
		{"/x/file-b.jsonl", "event-b", 30, 40},
	}
	for i, r := range seed {
		if _, err := s.db.ExecContext(
			ctx,
			`INSERT INTO token_usage
			   (session_id, timestamp, tool, model, input_tokens, output_tokens,
			    source, reliability, source_file, source_event_id, message_id)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			"sess-xtool", timestamp(now.Add(time.Duration(i)*time.Second)),
			models.ToolClaudeCode, "claude-opus-4-7", r.in, r.out,
			models.TokenSourceJSONL, models.ReliabilityUnreliable,
			r.file, r.event, msgID,
		); err != nil {
			t.Fatal(err)
		}
	}

	var beforeTotal int
	if err := s.db.QueryRowContext(
		ctx, `SELECT COUNT(*) FROM token_usage`,
	).Scan(&beforeTotal); err != nil {
		t.Fatal(err)
	}

	// A claude-web emit reusing row A's EXACT (source_file, source_event_id)
	// key with tokens 30/40. The conflict target excludes tool, so this
	// collides with row A — but the WHERE token_usage.tool = excluded.tool
	// predicate is false ('claude-code' != 'claude-web'), so resolution
	// no-ops: neither inserted nor updated.
	inserted, err := s.InsertTokenEvents(ctx, []models.TokenEvent{{
		SourceFile: "/x/file-a.jsonl", SourceEventID: "event-a",
		SessionID: "sess-xtool-web", Timestamp: now,
		Tool: models.ToolClaudeWeb, Model: "claude-opus-4-7",
		InputTokens: 30, OutputTokens: 40,
		Source: models.TokenSourceEstimated, Reliability: models.ReliabilityUnreliable,
		MessageID: msgID,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if inserted != 0 {
		t.Errorf("inserted: got %d want 0 (cross-tool conflict must no-op)", inserted)
	}

	// Row A unchanged: still claude-code, still 10/20.
	var tool string
	var in, out int
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT tool, input_tokens, output_tokens FROM token_usage
		 WHERE source_file = '/x/file-a.jsonl' AND source_event_id = 'event-a'`,
	).Scan(&tool, &in, &out); err != nil {
		t.Fatal(err)
	}
	if tool != models.ToolClaudeCode || in != 10 || out != 20 {
		t.Errorf("row A: got (tool=%s in=%d out=%d) want (claude-code 10 20) — cross-tool upsert mutated another tool's row", tool, in, out)
	}

	// Row B unchanged: still 30/40.
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT input_tokens, output_tokens FROM token_usage
		 WHERE source_file = '/x/file-b.jsonl' AND source_event_id = 'event-b'`,
	).Scan(&in, &out); err != nil {
		t.Fatal(err)
	}
	if in != 30 || out != 40 {
		t.Errorf("row B: got (in=%d out=%d) want (30 40)", in, out)
	}

	// Total row count unchanged: the claude-web emit neither inserted nor
	// updated a row.
	var afterTotal int
	if err := s.db.QueryRowContext(
		ctx, `SELECT COUNT(*) FROM token_usage`,
	).Scan(&afterTotal); err != nil {
		t.Fatal(err)
	}
	if afterTotal != beforeTotal {
		t.Errorf("total rows: got %d want %d (cross-tool emit must not add a row)", afterTotal, beforeTotal)
	}
}

// TestInsertTokenEvents_AntigravityCLIRescanMaxUpgrade proves the upsert's
// same-tool guard does NOT block a legitimate same-tool rescan-merge: after
// migration 071 retags the historical agy-CLI rows to tool='antigravity-cli',
// `observer backfill --antigravity-cli-rescan` re-emits the same
// (source_file, source_event_id) key under antigravity-cli and its refined
// (higher) token counts must MAX-upgrade the stored row.
func TestInsertTokenEvents_AntigravityCLIRescanMaxUpgrade(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)

	if _, err := s.UpsertProject(ctx, "/tmp/proj", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSession(ctx, models.Session{
		ID: "sess-agy", ProjectID: 1, Tool: models.ToolAntigravityCLI, StartedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	key := struct{ file, event string }{"/x/conv.db", "antigravity-cli-db:conv1:gen:0"}
	// Initial parse: partial output.
	if _, err := s.InsertTokenEvents(ctx, []models.TokenEvent{{
		SourceFile: key.file, SourceEventID: key.event,
		SessionID: "sess-agy", Timestamp: now,
		Tool: models.ToolAntigravityCLI, Model: "gemini",
		InputTokens: 100, OutputTokens: 20,
		Source: models.TokenSourceEstimated, Reliability: models.ReliabilityUnreliable,
		MessageID: "conv1:gen:0",
	}}); err != nil {
		t.Fatal(err)
	}

	// Rescan re-emits the SAME key (same tool) with a refined, higher
	// output count. The WHERE token_usage.tool = excluded.tool predicate
	// is true (both antigravity-cli), so the MAX-upgrade applies.
	if _, err := s.InsertTokenEvents(ctx, []models.TokenEvent{{
		SourceFile: key.file, SourceEventID: key.event,
		SessionID: "sess-agy", Timestamp: now,
		Tool: models.ToolAntigravityCLI, Model: "gemini",
		InputTokens: 100, OutputTokens: 350,
		Source: models.TokenSourceEstimated, Reliability: models.ReliabilityUnreliable,
		MessageID: "conv1:gen:0",
	}}); err != nil {
		t.Fatal(err)
	}

	var rows int
	var out int64
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT COUNT(*), COALESCE(MAX(output_tokens), 0) FROM token_usage
		 WHERE session_id = 'sess-agy' AND source_event_id = ?`, key.event,
	).Scan(&rows, &out); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Errorf("rows: got %d want 1 (rescan must upgrade in place, not insert)", rows)
	}
	if out != 350 {
		t.Errorf("output_tokens: got %d want 350 (same-tool rescan MAX-upgrade must apply)", out)
	}
}

func TestInsertAPITurn(t *testing.T) {
	t.Parallel()
	s, raw := newTestStore(t)
	ctx := context.Background()

	ts := time.Date(2026, 4, 16, 14, 0, 0, 0, time.UTC)
	id, err := s.InsertAPITurn(ctx, models.APITurn{
		SessionID:           "sess-1",
		Timestamp:           ts,
		Provider:            models.ProviderAnthropic,
		Model:               "claude-sonnet-4",
		RequestID:           "req_1",
		InputTokens:         100,
		OutputTokens:        50,
		CacheReadTokens:     200,
		CacheCreationTokens: 0,
		MessageCount:        3,
		ToolUseCount:        1,
		SystemPromptHash:    "hash",
		TotalResponseMS:     1234,
		StopReason:          "end_turn",
	})
	if err != nil {
		t.Fatalf("InsertAPITurn: %v", err)
	}
	if id == 0 {
		t.Error("expected non-zero row id")
	}

	// Nullable round-trip: empty session + zero project + zero cache_creation + zero cost should land as NULL.
	var sess sql.NullString
	var proj sql.NullInt64
	var cacheCreation sql.NullInt64
	var cost sql.NullFloat64
	if err := raw.QueryRowContext(
		ctx,
		`SELECT session_id, project_id, cache_creation_tokens, cost_usd FROM api_turns WHERE id = ?`, id,
	).Scan(&sess, &proj, &cacheCreation, &cost); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if !sess.Valid || sess.String != "sess-1" {
		t.Errorf("session_id: %+v", sess)
	}
	if proj.Valid {
		t.Errorf("project_id should be NULL: %+v", proj)
	}
	if cacheCreation.Valid {
		t.Errorf("cache_creation_tokens should be NULL: %+v", cacheCreation)
	}
	if cost.Valid {
		t.Errorf("cost_usd should be NULL: %+v", cost)
	}

	// Second insert with empty session leaves session_id NULL.
	id2, err := s.InsertAPITurn(ctx, models.APITurn{
		Timestamp: ts,
		Provider:  models.ProviderOpenAI,
		Model:     "gpt-5",
	})
	if err != nil {
		t.Fatalf("InsertAPITurn 2: %v", err)
	}
	var sess2 sql.NullString
	if err := raw.QueryRowContext(ctx, `SELECT session_id FROM api_turns WHERE id = ?`, id2).Scan(&sess2); err != nil {
		t.Fatalf("scan 2: %v", err)
	}
	if sess2.Valid {
		t.Errorf("session_id should be NULL: %+v", sess2)
	}

	n, err := s.CountAPITurns(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("count: got %d want 2", n)
	}

	// Validation: missing Provider/Model must error.
	if _, err := s.InsertAPITurn(ctx, models.APITurn{Timestamp: ts}); err == nil {
		t.Error("expected error for missing provider/model")
	}
}

// TestIngest_SkipsMCPToolOutputsFromFTSIndex pins the recursive-
// search-pollution fix surfaced 2026-05-08 dogfood: tool outputs
// from MCP tools (`mcp__*`) are derived query data — indexing them
// makes future searches surface prior search results as hits,
// degrading FTS5 quality session-over-session. The fix skips
// indexing for any event whose RawToolName starts with `mcp__`.
func TestIngest_SkipsMCPToolOutputsFromFTSIndex(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	now := time.Date(2026, 5, 8, 10, 0, 0, 0, time.UTC)
	events := []models.ToolEvent{
		// Bash output — should be indexed.
		{
			SourceFile: "f.jsonl", SourceEventID: "e-bash",
			SessionID: "sess-mcp", ProjectRoot: "/tmp/proj",
			Timestamp: now, Tool: models.ToolClaudeCode,
			ActionType: models.ActionRunCommand, Target: "grep app.set",
			Success: true, RawToolName: "Bash",
			ToolOutput: "matched: app.set('foo', 'bar') in test/config.js",
		},
		// MCP search_past_outputs — must NOT be indexed (its body
		// contains app.set keywords because that was the query, but
		// it's derived data, not source content).
		{
			SourceFile: "f.jsonl", SourceEventID: "e-mcp",
			SessionID: "sess-mcp", ProjectRoot: "/tmp/proj",
			Timestamp: now.Add(time.Second), Tool: models.ToolClaudeCode,
			ActionType: models.ActionRunCommand, Target: "search_past_outputs(app.set)",
			Success: true, RawToolName: "mcp__observer__search_past_outputs",
			ToolOutput: `{"query":"app.set","hits":[{"action_id":1,"excerpt":"app.set found"}]}`,
		},
	}

	idx := indexing.New(s.db, 0)
	if _, err := s.Ingest(ctx, events, nil, IngestOptions{Indexer: idx}); err != nil {
		t.Fatal(err)
	}

	// Search for "app.set" — should hit ONLY the Bash row, not the
	// MCP row. Pre-fix, both would surface.
	res, err := idx.Search(ctx, "app.set", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 {
		t.Fatalf("expected exactly 1 hit (Bash only); got %d: %+v", len(res), res)
	}
	if res[0].ToolName != "Bash" {
		t.Errorf("hit should be the Bash event, got tool_name=%q", res[0].ToolName)
	}
}

// TestUnrecoverable_MarkLookupClear pins the contract for migration
// 025's adapter_unrecoverable_files table. Mark records a failure;
// Lookup returns it only when (size, mtime) still match; Clear
// removes it. Tested end-to-end via *Store rather than raw SQL so
// the JSON/timestamp encoding paths are exercised. (Issue #4
// follow-up.)
func TestUnrecoverable_MarkLookupClear(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	path := "/some/host/path/conv-abc.pb"
	const adapter = "antigravity"

	// Miss when nothing is recorded.
	got, err := s.LookupUnrecoverable(ctx, adapter, path, 1024, 1700000000)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Errorf("pre-mark lookup: got %+v, want nil", got)
	}

	// Mark + look up with matching size/mtime.
	if err := s.MarkUnrecoverable(ctx, adapter, path, 1024, 1700000000, "decrypt+grpc: test"); err != nil {
		t.Fatal(err)
	}
	got, err = s.LookupUnrecoverable(ctx, adapter, path, 1024, 1700000000)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("post-mark lookup: got nil, want entry")
	}
	if got.Reason != "decrypt+grpc: test" {
		t.Errorf("reason: got %q want %q", got.Reason, "decrypt+grpc: test")
	}
	if got.FileSize != 1024 || got.FileMtimeUnix != 1700000000 {
		t.Errorf("identity: size=%d mtime=%d", got.FileSize, got.FileMtimeUnix)
	}

	// Drift: size differs → miss (caller should retry).
	got, err = s.LookupUnrecoverable(ctx, adapter, path, 2048, 1700000000)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Errorf("size-drift lookup: got %+v, want nil (caller retries)", got)
	}

	// Drift: mtime differs → also a miss.
	got, err = s.LookupUnrecoverable(ctx, adapter, path, 1024, 1700000099)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Errorf("mtime-drift lookup: got %+v, want nil", got)
	}

	// Re-mark upserts (new size/mtime replaces old).
	if err := s.MarkUnrecoverable(ctx, adapter, path, 2048, 1700000099, "decrypt+grpc: retry-failed"); err != nil {
		t.Fatal(err)
	}
	got, err = s.LookupUnrecoverable(ctx, adapter, path, 2048, 1700000099)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Reason != "decrypt+grpc: retry-failed" {
		t.Errorf("post-upsert: %+v", got)
	}

	// Clear → subsequent lookup misses.
	if err := s.ClearUnrecoverable(ctx, adapter, path); err != nil {
		t.Fatal(err)
	}
	got, err = s.LookupUnrecoverable(ctx, adapter, path, 2048, 1700000099)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Errorf("post-clear lookup: got %+v, want nil", got)
	}

	// Idempotent clear (deleting nonexistent row is a no-op).
	if err := s.ClearUnrecoverable(ctx, adapter, path); err != nil {
		t.Errorf("idempotent clear: %v", err)
	}
}

// TestUnrecoverable_AdapterScoped pins the (adapter, source_file)
// composite primary key — two adapters can independently track the
// same path without colliding. Defensive guard for a future adapter
// that happens to scan the same .pb file.
func TestUnrecoverable_AdapterScoped(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	const path = "/shared/file.pb"
	if err := s.MarkUnrecoverable(ctx, "antigravity", path, 100, 1, "ag-fail"); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkUnrecoverable(ctx, "future-adapter", path, 100, 1, "future-fail"); err != nil {
		t.Fatal(err)
	}

	ag, err := s.LookupUnrecoverable(ctx, "antigravity", path, 100, 1)
	if err != nil || ag == nil || ag.Reason != "ag-fail" {
		t.Errorf("antigravity entry: %+v err=%v", ag, err)
	}
	fa, err := s.LookupUnrecoverable(ctx, "future-adapter", path, 100, 1)
	if err != nil || fa == nil || fa.Reason != "future-fail" {
		t.Errorf("future-adapter entry: %+v err=%v", fa, err)
	}

	// Clearing one adapter's row leaves the other intact.
	if err := s.ClearUnrecoverable(ctx, "antigravity", path); err != nil {
		t.Fatal(err)
	}
	ag, _ = s.LookupUnrecoverable(ctx, "antigravity", path, 100, 1)
	if ag != nil {
		t.Errorf("antigravity not cleared: %+v", ag)
	}
	fa, _ = s.LookupUnrecoverable(ctx, "future-adapter", path, 100, 1)
	if fa == nil {
		t.Errorf("future-adapter entry got swept too")
	}
}

func TestUpsertClaudecodeEffort_Sidecar(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	const sessID = "sess-1"
	if err := s.UpsertClaudecodeEffort(ctx, sessID, "toolu_A", "max", "PreToolUse"); err != nil {
		t.Fatalf("upsert A: %v", err)
	}
	if err := s.UpsertClaudecodeEffort(ctx, sessID, "toolu_B", "low", "PreToolUse"); err != nil {
		t.Fatalf("upsert B: %v", err)
	}
	// Second upsert on same key with new value — last-write-wins.
	if err := s.UpsertClaudecodeEffort(ctx, sessID, "toolu_A", "xhigh", "PostToolUse"); err != nil {
		t.Fatalf("upsert A retry: %v", err)
	}

	m, err := s.LoadClaudecodeEffortMap(ctx, sessID)
	if err != nil {
		t.Fatalf("load map: %v", err)
	}
	if got := m["toolu_A"]; got != "xhigh" {
		t.Errorf("toolu_A: got %q want xhigh (last-write-wins)", got)
	}
	if got := m["toolu_B"]; got != "low" {
		t.Errorf("toolu_B: got %q want low", got)
	}

	// Empty inputs are no-ops.
	if err := s.UpsertClaudecodeEffort(ctx, "", "x", "y", "z"); err != nil {
		t.Errorf("empty session_id: got err %v, want nil", err)
	}
	if err := s.UpsertClaudecodeEffort(ctx, "s", "", "y", "z"); err != nil {
		t.Errorf("empty tool_use_id: got err %v, want nil", err)
	}

	// Other session is isolated.
	m2, _ := s.LoadClaudecodeEffortMap(ctx, "sess-other")
	if len(m2) != 0 {
		t.Errorf("other session: got %d rows, want 0", len(m2))
	}
}

func TestUpsertClaudecodeEffort_StampsExistingAction(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	pid, err := s.UpsertProject(ctx, "/tmp/eff", "")
	if err != nil {
		t.Fatalf("upsert project: %v", err)
	}
	const sessID = "stamp-sess-1"
	if err := s.UpsertSession(ctx, models.Session{
		ID:        sessID,
		ProjectID: pid,
		Tool:      "claude-code",
		StartedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("upsert session: %v", err)
	}

	// Insert a tool_use row whose source_event_id matches the
	// tool_use_id the hook will emit. Metadata starts nil — the
	// UpsertClaudecodeEffort UPDATE should populate effort_level.
	res, err := s.InsertActions(ctx, []models.Action{{
		SessionID:     sessID,
		ProjectID:     pid,
		Timestamp:     time.Now().UTC(),
		ActionType:    "search_files",
		Target:        "**/*.go",
		Tool:          "claude-code",
		SourceFile:    "claudecode:test",
		SourceEventID: "toolu_stamp_me",
		Success:       true,
	}})
	if err != nil {
		t.Fatalf("insert action: %v", err)
	}
	if res != 1 {
		t.Fatalf("insert action: got %d rows, want 1", res)
	}

	if err := s.UpsertClaudecodeEffort(ctx, sessID, "toolu_stamp_me", "max", "PreToolUse"); err != nil {
		t.Fatalf("upsert effort: %v", err)
	}

	// Read back the metadata column directly — the cleanest way to
	// verify the json_set landed.
	var meta string
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT COALESCE(metadata, '') FROM actions WHERE session_id = ? AND source_event_id = ?`,
		sessID, "toolu_stamp_me",
	).Scan(&meta); err != nil {
		t.Fatalf("scan metadata: %v", err)
	}
	if !strings.Contains(meta, `"effort_level":"max"`) {
		t.Errorf("metadata missing effort_level: %q", meta)
	}

	// A second action without a matching sidecar row stays empty.
	if _, err := s.InsertActions(ctx, []models.Action{{
		SessionID:     sessID,
		ProjectID:     pid,
		Timestamp:     time.Now().UTC().Add(time.Second),
		ActionType:    "read_file",
		Target:        "main.go",
		Tool:          "claude-code",
		SourceFile:    "claudecode:test",
		SourceEventID: "toolu_no_hook",
		Success:       true,
	}}); err != nil {
		t.Fatalf("insert second action: %v", err)
	}
	var meta2 string
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT COALESCE(metadata, '') FROM actions WHERE session_id = ? AND source_event_id = ?`,
		sessID, "toolu_no_hook",
	).Scan(&meta2); err != nil {
		t.Fatalf("scan second: %v", err)
	}
	if strings.Contains(meta2, "effort_level") {
		t.Errorf("second action metadata leaked effort: %q", meta2)
	}
}

// TestCountUniqueCompressions_DedupesBySessionAndHash pins V7-9: the
// same body_hash across N turns counts once per session.
func TestCountUniqueCompressions_DedupesBySessionAndHash(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	ts := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)

	// 3 turns, each with the SAME body hash → 1 unique compression.
	for i := 0; i < 3; i++ {
		turnID, err := s.InsertAPITurn(ctx, models.APITurn{
			SessionID: "sess-A",
			Timestamp: ts.Add(time.Duration(i) * time.Second),
			Provider:  models.ProviderAnthropic,
			Model:     "claude-sonnet-4",
			RequestID: fmt.Sprintf("req_%d", i),
			CompressionEvents: []models.CompressionEvent{{
				Mechanism:       "json",
				OriginalBytes:   1024,
				CompressedBytes: 256,
				BodyHash:        "abc123",
			}},
		})
		if err != nil {
			t.Fatalf("InsertAPITurn %d: %v", i, err)
		}
		if turnID == 0 {
			t.Fatalf("turn %d: zero id", i)
		}
	}

	got, err := s.CountUniqueCompressions(ctx, "sess-A")
	if err != nil {
		t.Fatalf("CountUniqueCompressions: %v", err)
	}
	if got != 1 {
		t.Errorf("3 turns × same body_hash: got %d, want 1", got)
	}

	// Add 2 more turns with DISTINCT body hashes → total 3 unique.
	for i, h := range []string{"def456", "ghi789"} {
		if _, err := s.InsertAPITurn(ctx, models.APITurn{
			SessionID: "sess-A",
			Timestamp: ts.Add(time.Duration(10+i) * time.Second),
			Provider:  models.ProviderAnthropic,
			Model:     "claude-sonnet-4",
			RequestID: fmt.Sprintf("req_extra_%d", i),
			CompressionEvents: []models.CompressionEvent{{
				Mechanism:       "json",
				OriginalBytes:   1024,
				CompressedBytes: 256,
				BodyHash:        h,
			}},
		}); err != nil {
			t.Fatalf("InsertAPITurn extra %d: %v", i, err)
		}
	}
	got, err = s.CountUniqueCompressions(ctx, "sess-A")
	if err != nil {
		t.Fatalf("CountUniqueCompressions: %v", err)
	}
	if got != 3 {
		t.Errorf("3 same + 2 distinct: got %d unique, want 3", got)
	}
}

// TestCountUniqueCompressions_IgnoresNullHashRows pins that pre-
// v1.7.12 rows (which have NULL body_hash) don't count. Critical for
// migration semantics: legacy data ingested before this PR doesn't
// drift the dedup metric.
func TestCountUniqueCompressions_IgnoresNullHashRows(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	ts := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)

	// One turn with body_hash; one without.
	if _, err := s.InsertAPITurn(ctx, models.APITurn{
		SessionID: "sess-B",
		Timestamp: ts,
		Provider:  models.ProviderAnthropic,
		Model:     "claude-sonnet-4",
		RequestID: "req_with_hash",
		CompressionEvents: []models.CompressionEvent{{
			Mechanism:       "json",
			OriginalBytes:   1024,
			CompressedBytes: 256,
			BodyHash:        "xyz",
		}},
	}); err != nil {
		t.Fatalf("InsertAPITurn: %v", err)
	}
	if _, err := s.InsertAPITurn(ctx, models.APITurn{
		SessionID: "sess-B",
		Timestamp: ts.Add(time.Second),
		Provider:  models.ProviderAnthropic,
		Model:     "claude-sonnet-4",
		RequestID: "req_no_hash",
		CompressionEvents: []models.CompressionEvent{{
			Mechanism:       "logs",
			OriginalBytes:   1024,
			CompressedBytes: 256,
			// BodyHash empty — represents pre-v1.7.12 / 'drop' /
			// rolling-summary mechanisms that don't populate.
		}},
	}); err != nil {
		t.Fatalf("InsertAPITurn no-hash: %v", err)
	}

	got, err := s.CountUniqueCompressions(ctx, "sess-B")
	if err != nil {
		t.Fatalf("CountUniqueCompressions: %v", err)
	}
	if got != 1 {
		t.Errorf("1 hashed + 1 NULL: got %d unique, want 1", got)
	}
}

// TestCountUniqueCompressions_ScopesToSessionID pins that two distinct
// sessions don't bleed into each other — same hash in two sessions
// counts as 1 per session.
func TestCountUniqueCompressions_ScopesToSessionID(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	ts := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)

	for _, sess := range []string{"sess-C", "sess-D"} {
		if _, err := s.InsertAPITurn(ctx, models.APITurn{
			SessionID: sess,
			Timestamp: ts,
			Provider:  models.ProviderAnthropic,
			Model:     "claude-sonnet-4",
			RequestID: "req_" + sess,
			CompressionEvents: []models.CompressionEvent{{
				Mechanism: "json", OriginalBytes: 100, CompressedBytes: 50,
				BodyHash: "shared",
			}},
		}); err != nil {
			t.Fatalf("Insert %s: %v", sess, err)
		}
	}

	for _, sess := range []string{"sess-C", "sess-D"} {
		got, err := s.CountUniqueCompressions(ctx, sess)
		if err != nil {
			t.Fatalf("CountUniqueCompressions(%s): %v", sess, err)
		}
		if got != 1 {
			t.Errorf("%s: got %d, want 1", sess, got)
		}
	}
}

// TestCountUniqueCompressions_RequiresSessionID rejects empty session.
func TestCountUniqueCompressions_RequiresSessionID(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	if _, err := s.CountUniqueCompressions(context.Background(), ""); err == nil {
		t.Errorf("expected error for empty sessionID")
	}
}

// TestIngestOutcomeUpdateErrorFailsTick pins the retry contract (F1).
// The tool_result record is the ONLY carrier of the outcome, and the
// watcher advances its parse cursor past it the moment Ingest returns
// nil — so an update that errored must fail the whole tick, exactly as
// an InsertActions error would, and let the watcher re-run the window.
// (Re-processing is idempotent: upserts plus idempotent updates.)
func TestIngestOutcomeUpdateErrorFailsTick(t *testing.T) {
	t.Parallel()
	s, database := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	if _, err := s.Ingest(ctx, []models.ToolEvent{{
		SourceFile: "/t/ou_err.jsonl", SourceEventID: "toolu_err",
		SessionID: "s_err", ProjectRoot: "/tmp/p_err", Timestamp: now,
		Tool: models.ToolClaudeCode, ActionType: models.ActionRunCommand,
		Target: "go build ./...", RawToolName: "Bash", Success: true,
	}}, nil, IngestOptions{}); err != nil {
		t.Fatal(err)
	}

	// Simulate the transient DB fault class the retry exists for
	// (SQLITE_BUSY against a concurrent hook process) with the bluntest
	// reproducible stand-in: a closed handle. The events/tokens slices
	// are empty so the update is the ONLY DB work this call attempts.
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	_, err := s.Ingest(ctx, nil, nil, IngestOptions{
		OutcomeUpdates: []models.ActionOutcomeUpdate{{
			SourceFile: "/t/ou_err.jsonl", SourceEventID: "toolu_err",
			SuccessKnown: true, Success: false, ErrorMessage: "boom",
		}},
	})
	if err == nil {
		t.Fatal("Ingest returned nil after a failed outcome update — the watcher would advance the cursor past the only record carrying this outcome")
	}
	if !strings.Contains(err.Error(), "toolu_err") {
		t.Errorf("error does not identify the failed update: %v", err)
	}
}

// TestIngestOutcomeUpdateRecordsFailureContext pins F2(b): a command
// whose failure is only known cross-tick still lands in failure_context.
// Pre-fix, recordCommandOutcome ran exclusively at insert time — on an
// outcome that had not been observed — so a cross-tick failure was
// invisible to the "this command kept failing" surface.
func TestIngestOutcomeUpdateRecordsFailureContext(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// Tick 1: the call lands, outcome not yet observed.
	if _, err := s.Ingest(ctx, []models.ToolEvent{{
		SourceFile: "/t/fc1.jsonl", SourceEventID: "toolu_fc1",
		SessionID: "s_fc1", ProjectRoot: "/tmp/p_fc1", Timestamp: now,
		Tool: models.ToolClaudeCode, ActionType: models.ActionRunCommand,
		Target: "go test ./internal/store", RawToolName: "Bash",
		Success: true, OutcomePending: true,
	}}, nil, IngestOptions{RecordFailures: true}); err != nil {
		t.Fatal(err)
	}
	var rows int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM failure_context`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("failure_context rows after the optimistic tick = %d, want 0", rows)
	}

	// Tick 2: the real (failed) outcome arrives.
	if _, err := s.Ingest(ctx, nil, nil, IngestOptions{
		RecordFailures: true,
		OutcomeUpdates: []models.ActionOutcomeUpdate{{
			SourceFile: "/t/fc1.jsonl", SourceEventID: "toolu_fc1",
			SuccessKnown: true, Success: false,
			ErrorMessage: "exit status 1: FAIL github.com/x/store",
		}},
	}); err != nil {
		t.Fatal(err)
	}

	var errMsg string
	var retry int
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT error_message, retry_count FROM failure_context`,
	).Scan(&errMsg, &retry); err != nil {
		t.Fatalf("cross-tick failure never reached failure_context: %v", err)
	}
	if !strings.Contains(errMsg, "FAIL github.com/x/store") {
		t.Errorf("failure_context.error_message = %q", errMsg)
	}
	if retry != 0 {
		t.Errorf("retry_count = %d, want 0 (first failure of this command)", retry)
	}
}

// TestOutcomePendingDefersFailureContextBookkeeping pins F2(a) and the
// second half of F2(b) together. An optimistic tick-1 insert must NOT
// mark a prior failure of the same command eventually_succeeded — that
// success was never observed — and the real success arriving at tick 2
// must.
func TestOutcomePendingDefersFailureContextBookkeeping(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	const cmd = "go test ./internal/watcher"

	// Tick 0: an observed failure of the command.
	if _, err := s.Ingest(ctx, []models.ToolEvent{{
		SourceFile: "/t/fc2.jsonl", SourceEventID: "toolu_fc2a",
		SessionID: "s_fc2", ProjectRoot: "/tmp/p_fc2", Timestamp: now,
		Tool: models.ToolClaudeCode, ActionType: models.ActionRunCommand,
		Target: cmd, RawToolName: "Bash",
		Success: false, ErrorMessage: "exit status 1",
	}}, nil, IngestOptions{RecordFailures: true}); err != nil {
		t.Fatal(err)
	}

	succeeded := func() int {
		t.Helper()
		var v int
		if err := s.db.QueryRowContext(
			ctx, `SELECT eventually_succeeded FROM failure_context`,
		).Scan(&v); err != nil {
			t.Fatalf("prior failure row missing: %v", err)
		}
		return v
	}
	if got := succeeded(); got != 0 {
		t.Fatalf("eventually_succeeded = %d right after the failure, want 0", got)
	}

	// Tick 1: the retry's tool_use lands, outcome NOT yet observed.
	if _, err := s.Ingest(ctx, []models.ToolEvent{{
		SourceFile: "/t/fc2.jsonl", SourceEventID: "toolu_fc2b",
		SessionID: "s_fc2", ProjectRoot: "/tmp/p_fc2", Timestamp: now.Add(time.Second),
		Tool: models.ToolClaudeCode, ActionType: models.ActionRunCommand,
		Target: cmd, RawToolName: "Bash",
		Success: true, OutcomePending: true,
	}}, nil, IngestOptions{RecordFailures: true}); err != nil {
		t.Fatal(err)
	}
	if got := succeeded(); got != 0 {
		t.Errorf("eventually_succeeded = %d after an UNOBSERVED optimistic insert, want 0", got)
	}

	// Tick 2: the retry really did succeed.
	if _, err := s.Ingest(ctx, nil, nil, IngestOptions{
		RecordFailures: true,
		OutcomeUpdates: []models.ActionOutcomeUpdate{{
			SourceFile: "/t/fc2.jsonl", SourceEventID: "toolu_fc2b",
			SuccessKnown: true, Success: true, ToolOutput: "ok",
		}},
	}); err != nil {
		t.Fatal(err)
	}
	if got := succeeded(); got != 1 {
		t.Errorf("eventually_succeeded = %d after the observed success, want 1", got)
	}
}

// TestIngestOutcomeUpdateWithoutVerdictLeavesSuccess pins F3 through the
// SQL. qwen-code's functionResponse records carry no status: in-window
// that leaves Success untouched, and cross-tick it must do the same. A
// row an earlier ui_telemetry tool_call event marked failed must not be
// silently repaired by a status-less result — output still merges.
func TestIngestOutcomeUpdateWithoutVerdictLeavesSuccess(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	if _, err := s.Ingest(ctx, []models.ToolEvent{{
		SourceFile: "/t/nv.jsonl", SourceEventID: "tool:call_nv",
		SessionID: "s_nv", ProjectRoot: "/tmp/p_nv", Timestamp: now,
		Tool: models.ToolQwenCode, ActionType: models.ActionRunCommand,
		Target: "go test ./...", RawToolName: "run_shell_command",
		Success: false, ErrorMessage: "telemetry: status=error",
	}}, nil, IngestOptions{}); err != nil {
		t.Fatal(err)
	}

	if _, err := s.Ingest(ctx, nil, nil, IngestOptions{
		OutcomeUpdates: []models.ActionOutcomeUpdate{{
			SourceFile: "/t/nv.jsonl", SourceEventID: "tool:call_nv",
			SuccessKnown: false, Success: true, // Success must be ignored
			ToolOutput: "--- FAIL: TestFoo",
		}},
	}); err != nil {
		t.Fatal(err)
	}

	var success int
	var errMsg, out string
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT success, error_message, COALESCE(raw_tool_output, '')
		   FROM actions WHERE source_event_id = 'tool:call_nv'`,
	).Scan(&success, &errMsg, &out); err != nil {
		t.Fatal(err)
	}
	if success != 0 {
		t.Errorf("success = %d, want 0 (a verdict-less result must not flip it)", success)
	}
	if errMsg != "telemetry: status=error" {
		t.Errorf("error_message = %q, want the earlier verdict preserved", errMsg)
	}
	if out != "--- FAIL: TestFoo" {
		t.Errorf("raw_tool_output = %q, want the result body merged anyway", out)
	}
}

// TestInsertActionsSuccessSelfHealsOneWay pins F4's asymmetric conflict
// rule. A force rescan (offset 0) pairs a tool_use with its tool_result
// in ONE window and re-emits the CORRECTED event; with success frozen on
// conflict, a row left optimistically successful by an interrupted
// cross-tick parse could never be repaired. The reverse must stay
// frozen — every tool_use re-emits success=1 by construction, so 0 → 1
// would let an ordinary re-scan un-fix a corrected failure.
func TestInsertActionsSuccessSelfHealsOneWay(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	optimistic := models.ToolEvent{
		SourceFile: "/t/heal.jsonl", SourceEventID: "toolu_heal",
		SessionID: "s_heal", ProjectRoot: "/tmp/p_heal", Timestamp: now,
		Tool: models.ToolClaudeCode, ActionType: models.ActionRunCommand,
		Target: "go test ./...", RawToolName: "Bash", Success: true,
	}
	corrected := optimistic
	corrected.Success = false
	corrected.ErrorMessage = "exit status 1: FAIL"

	read := func() (int, string) {
		t.Helper()
		var success int
		var errMsg string
		if err := s.db.QueryRowContext(
			ctx,
			`SELECT success, COALESCE(error_message, '') FROM actions
			  WHERE source_event_id = 'toolu_heal'`,
		).Scan(&success, &errMsg); err != nil {
			t.Fatal(err)
		}
		return success, errMsg
	}

	// The damaged state a cross-tick parse could leave behind.
	if _, err := s.Ingest(ctx, []models.ToolEvent{optimistic}, nil, IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	if got, _ := read(); got != 1 {
		t.Fatalf("seeded success = %d, want 1", got)
	}

	// Force rescan re-emits the corrected event: 1 → 0 must heal.
	if _, err := s.Ingest(ctx, []models.ToolEvent{corrected}, nil, IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	success, errMsg := read()
	if success != 0 {
		t.Errorf("success = %d after re-emitting the corrected event, want 0 (row cannot self-heal)", success)
	}
	if errMsg != "exit status 1: FAIL" {
		t.Errorf("error_message = %q, want it to ride along on the heal", errMsg)
	}

	// Another ordinary re-scan re-emits the optimistic event: 0 → 1
	// must NOT happen.
	if _, err := s.Ingest(ctx, []models.ToolEvent{optimistic}, nil, IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	success, errMsg = read()
	if success != 0 {
		t.Errorf("success = %d — an optimistic re-emit un-fixed a corrected failure", success)
	}
	if errMsg != "exit status 1: FAIL" {
		t.Errorf("error_message = %q, want it preserved", errMsg)
	}
}

// TestIngestOutcomeUpdateSkipsFTSWhenOutputRejected pins F5: the FTS
// excerpt must follow the SAME acceptance rule as the column's SQL
// length-merge. A shorter duplicate payload is rejected by the UPDATE,
// so indexing it would leave action_excerpts describing a body
// raw_tool_output does not hold.
func TestIngestOutcomeUpdateSkipsFTSWhenOutputRejected(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	idx := indexing.New(s.db, 0)

	if _, err := s.Ingest(ctx, []models.ToolEvent{{
		SourceFile: "/t/fts.jsonl", SourceEventID: "toolu_fts",
		SessionID: "s_fts", ProjectRoot: "/tmp/p_fts", Timestamp: now,
		Tool: models.ToolClaudeCode, ActionType: models.ActionRunCommand,
		Target: "rg needle", RawToolName: "Bash", Success: true,
	}}, nil, IngestOptions{Indexer: idx}); err != nil {
		t.Fatal(err)
	}

	const long = "zathras found the long buffer with all of the detail"
	const short = "zathras narnia"
	if _, err := s.Ingest(ctx, nil, nil, IngestOptions{
		Indexer: idx,
		OutcomeUpdates: []models.ActionOutcomeUpdate{{
			SourceFile: "/t/fts.jsonl", SourceEventID: "toolu_fts",
			SuccessKnown: true, Success: true, ToolOutput: long,
		}},
	}); err != nil {
		t.Fatal(err)
	}
	// A second, SHORTER payload for the same row: the column rule
	// rejects it, so the index must ignore it too.
	if _, err := s.Ingest(ctx, nil, nil, IngestOptions{
		Indexer: idx,
		OutcomeUpdates: []models.ActionOutcomeUpdate{{
			SourceFile: "/t/fts.jsonl", SourceEventID: "toolu_fts",
			SuccessKnown: true, Success: true, ToolOutput: short,
		}},
	}); err != nil {
		t.Fatal(err)
	}

	var stored string
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT COALESCE(raw_tool_output, '') FROM actions WHERE source_event_id = 'toolu_fts'`,
	).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != long {
		t.Fatalf("raw_tool_output = %q, want the longer body preserved", stored)
	}
	// "narnia" appears only in the rejected payload.
	hits, err := idx.Search(ctx, "narnia", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Errorf("rejected payload was indexed: %d hits — excerpt now disagrees with raw_tool_output", len(hits))
	}
	hits, err = idx.Search(ctx, "zathras", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 {
		t.Fatalf("accepted payload hits = %d, want 1", len(hits))
	}
	if !strings.Contains(hits[0].Excerpt, "long buffer") {
		t.Errorf("excerpt = %q, want the accepted (longer) body", hits[0].Excerpt)
	}
}

// TestIngestOutcomeUpdateErrorStillCompletesBatch pins WHERE the
// outcome-update failure is reported (R2-1). By the time the updates
// run, the batch's actions are already inserted; returning before the
// later stages would cost them their guard evaluation and cache
// observations, and the retry can't make that up — re-inserted
// duplicates keep ID == 0 and the guard stage skips them. So every
// stage must still run, and the error surfaces last.
//
// session lineage is the observable stage here: it sits after the old
// return point and needs no fake collaborator.
func TestIngestOutcomeUpdateErrorStillCompletesBatch(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	if _, err := s.Ingest(ctx, []models.ToolEvent{{
		SourceFile: "/t/late.jsonl", SourceEventID: "toolu_late",
		SessionID: "s_late", ProjectRoot: "/tmp/p_late", Timestamp: now,
		Tool: models.ToolClaudeCode, ActionType: models.ActionRunCommand,
		Target: "go build ./...", RawToolName: "Bash", Success: true,
	}}, nil, IngestOptions{}); err != nil {
		t.Fatal(err)
	}

	// Fail ONLY the outcome update — everything else in the batch must
	// keep working, which a closed handle could not express.
	if _, err := s.db.ExecContext(
		ctx,
		`CREATE TRIGGER fail_outcome_update BEFORE UPDATE ON actions
		 WHEN NEW.error_message = 'BOOM'
		 BEGIN SELECT RAISE(ABORT, 'synthetic outcome-update fault'); END`,
	); err != nil {
		t.Fatal(err)
	}

	_, err := s.Ingest(ctx, nil, nil, IngestOptions{
		OutcomeUpdates: []models.ActionOutcomeUpdate{{
			SourceFile: "/t/late.jsonl", SourceEventID: "toolu_late",
			SuccessKnown: true, Success: false, ErrorMessage: "BOOM",
		}},
		SessionLineages: []models.SessionLineage{{
			SessionID: "s_late", ThreadSource: "subagent",
		}},
	})
	if err == nil {
		t.Fatal("Ingest returned nil despite a failed outcome update")
	}

	var threadSource sql.NullString
	if qerr := s.db.QueryRowContext(
		ctx, `SELECT thread_source FROM sessions WHERE id = 's_late'`,
	).Scan(&threadSource); qerr != nil {
		t.Fatal(qerr)
	}
	if threadSource.String != "subagent" {
		t.Errorf("thread_source = %q — a failed outcome update short-circuited the rest of the batch; the retry cannot make those stages up",
			threadSource.String)
	}
}

// TestIngestOutcomeUpdateFailureContextIdempotentOnReplay pins R2-2.
// The update MATCHES on every replay (RowsAffected counts matched, not
// changed), failure_context has no uniqueness on action_id, and the
// failure branch is a plain INSERT — so a retried window (which an
// outcome-update error now deliberately causes) or a duplicate result
// record would file the same failure twice with an inflated
// retry_count.
func TestIngestOutcomeUpdateFailureContextIdempotentOnReplay(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	if _, err := s.Ingest(ctx, []models.ToolEvent{{
		SourceFile: "/t/idem.jsonl", SourceEventID: "toolu_idem",
		SessionID: "s_idem", ProjectRoot: "/tmp/p_idem", Timestamp: now,
		Tool: models.ToolClaudeCode, ActionType: models.ActionRunCommand,
		Target: "go test ./...", RawToolName: "Bash",
		Success: true, OutcomePending: true,
	}}, nil, IngestOptions{RecordFailures: true}); err != nil {
		t.Fatal(err)
	}

	update := IngestOptions{
		RecordFailures: true,
		OutcomeUpdates: []models.ActionOutcomeUpdate{{
			SourceFile: "/t/idem.jsonl", SourceEventID: "toolu_idem",
			SuccessKnown: true, Success: false, ErrorMessage: "exit status 1: FAIL",
		}},
	}
	for i := 0; i < 2; i++ {
		if _, err := s.Ingest(ctx, nil, nil, update); err != nil {
			t.Fatalf("ingest %d: %v", i, err)
		}
	}

	var rows, maxRetry int
	if err := s.db.QueryRowContext(
		ctx, `SELECT COUNT(*), COALESCE(MAX(retry_count), 0) FROM failure_context`,
	).Scan(&rows, &maxRetry); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Errorf("failure_context rows = %d, want 1 (a replayed window must not re-file)", rows)
	}
	if maxRetry != 0 {
		t.Errorf("retry_count = %d, want 0 (replay inflated the retry count)", maxRetry)
	}
}

// TestInsertActionsProvisionalFalseDoesNotDowngrade pins R2-3. The
// self-heal arm flips 1 → 0 on EVIDENCE, never on a bare success=0:
// snapshot adapters re-emit stable ids carrying provisional falses
// (antigravity's "no exit code yet", copilot's isComplete=false
// task_complete row), and those never carry an error body. A measured
// failure does — that is the discriminator, not the tool name.
func TestInsertActionsProvisionalFalseDoesNotDowngrade(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	complete := models.ToolEvent{
		SourceFile: "/t/prov.jsonl", SourceEventID: "ev_prov",
		SessionID: "s_prov", ProjectRoot: "/tmp/p_prov", Timestamp: now,
		Tool: models.ToolAntigravity, ActionType: models.ActionRunCommand,
		Target: "npm run build", RawToolName: "run_command", Success: true,
	}
	// A stale/truncated snapshot re-parse: not-finished-yet, no error body.
	provisional := complete
	provisional.Success = false

	if _, err := s.Ingest(ctx, []models.ToolEvent{complete}, nil, IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Ingest(ctx, []models.ToolEvent{provisional}, nil, IngestOptions{}); err != nil {
		t.Fatal(err)
	}

	var success int
	var errMsg string
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT success, COALESCE(error_message, '') FROM actions WHERE source_event_id = 'ev_prov'`,
	).Scan(&success, &errMsg); err != nil {
		t.Fatal(err)
	}
	if success != 1 {
		t.Errorf("success = %d — a provisional false with no error body downgraded a completed success", success)
	}
	if errMsg != "" {
		t.Errorf("error_message = %q, want empty", errMsg)
	}
}

// TestIngestOutcomeUpdateFTSFollowsStoredBody pins R2-4: the FTS
// excerpt tracks what the column ACTUALLY ended up holding, not a
// predicted length comparison. The payload here carries an early
// U+0000 — SQLite's LENGTH() stops there and rejects the merge, while
// a Go-side rune count sees a long string and would have indexed it,
// leaving action_excerpts describing a body raw_tool_output never took.
func TestIngestOutcomeUpdateFTSFollowsStoredBody(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	idx := indexing.New(s.db, 0)

	if _, err := s.Ingest(ctx, []models.ToolEvent{{
		SourceFile: "/t/nul.jsonl", SourceEventID: "toolu_nul",
		SessionID: "s_nul", ProjectRoot: "/tmp/p_nul", Timestamp: now,
		Tool: models.ToolClaudeCode, ActionType: models.ActionRunCommand,
		Target: "rg needle", RawToolName: "Bash", Success: true,
	}}, nil, IngestOptions{Indexer: idx}); err != nil {
		t.Fatal(err)
	}

	const stored = "zathras long detailed buffer of output"
	// LENGTH() of this is 6 (it stops at the NUL) so the SQL merge
	// rejects it, but it is 167 runes long to a Go-side counter.
	rejected := "narnia\x00" + strings.Repeat("padding ", 20)

	for _, out := range []string{stored, rejected} {
		if _, err := s.Ingest(ctx, nil, nil, IngestOptions{
			Indexer: idx,
			OutcomeUpdates: []models.ActionOutcomeUpdate{{
				SourceFile: "/t/nul.jsonl", SourceEventID: "toolu_nul",
				SuccessKnown: true, Success: true, ToolOutput: out,
			}},
		}); err != nil {
			t.Fatal(err)
		}
	}

	var got string
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT COALESCE(raw_tool_output, '') FROM actions WHERE source_event_id = 'toolu_nul'`,
	).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != stored {
		t.Fatalf("raw_tool_output = %q, want the first body (the NUL payload must be rejected by the length-merge)", got)
	}
	hits, err := idx.Search(ctx, "narnia", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Errorf("rejected NUL payload was indexed: %d hits — excerpt now disagrees with raw_tool_output", len(hits))
	}
	hits, err = idx.Search(ctx, "zathras", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 {
		t.Fatalf("stored body hits = %d, want 1", len(hits))
	}
}

// TestLoadActionTargets_MatchesBothAssistantTypes pins the WP-T6/B2
// hard-break consumer. LoadActionTargets feeds the antigravity
// plaintext-transcript augmentation's coverage set (see
// antigravity.TargetCoverageReader); the B2a sweep re-typed the
// assistant-text emit sites from task_complete to assistant_message,
// so a query that matched task_complete only would return an EMPTY
// assistant bucket for post-sweep rows and re-open the duplicate-
// assistant-row bug this reader exists to close.
//
// The table covers the three real database states: pre-sweep history
// (task_complete only), post-sweep (assistant_message only), and the
// mid-upgrade mix — the state every existing install passes through
// between the code sweep and migration 078.
func TestLoadActionTargets_MatchesBothAssistantTypes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	base := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)

	ev := func(eid, actionType, target string, n int) models.ToolEvent {
		return models.ToolEvent{
			SourceFile: "/tmp/conv.pb", SourceEventID: eid,
			SessionID: "ag-1", ProjectRoot: "/tmp/proj",
			Timestamp:  base.Add(time.Duration(n) * time.Second),
			Tool:       models.ToolAntigravity,
			ActionType: actionType, Target: target, Success: true,
			RawToolName: "structured.assistant_text",
		}
	}

	cases := []struct {
		name     string
		events   []models.ToolEvent
		wantUser []string
		wantAsst []string
	}{
		{
			name: "pre_sweep_task_complete_only",
			events: []models.ToolEvent{
				ev("e0", models.ActionUserPrompt, "Just say ok", 0),
				ev("e1", models.ActionTaskComplete, "ok", 1),
			},
			wantUser: []string{"Just say ok"},
			wantAsst: []string{"ok"},
		},
		{
			name: "post_sweep_assistant_message_only",
			events: []models.ToolEvent{
				ev("e0", models.ActionUserPrompt, "Just say ok", 0),
				ev("e1", models.ActionAssistantMessage, "ok", 1),
			},
			wantUser: []string{"Just say ok"},
			wantAsst: []string{"ok"},
		},
		{
			name: "mid_upgrade_mixed_history",
			events: []models.ToolEvent{
				ev("e0", models.ActionUserPrompt, "Just say ok", 0),
				ev("e1", models.ActionTaskComplete, "ok", 1),
				ev("e2", models.ActionAssistantMessage, "and then some", 2),
				// Controls: neither type, and an empty target.
				ev("e3", models.ActionReadFile, "/tmp/proj/main.go", 3),
				ev("e4", models.ActionAssistantMessage, "", 4),
			},
			wantUser: []string{"Just say ok"},
			wantAsst: []string{"and then some", "ok"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, _ := newTestStore(t)
			if _, err := s.Ingest(ctx, tc.events, nil, IngestOptions{}); err != nil {
				t.Fatalf("Ingest: %v", err)
			}
			gotUser, gotAsst, err := s.LoadActionTargets(ctx, "/tmp/conv.pb")
			if err != nil {
				t.Fatalf("LoadActionTargets: %v", err)
			}
			sort.Strings(gotUser)
			sort.Strings(gotAsst)
			if !reflect.DeepEqual(gotUser, tc.wantUser) {
				t.Errorf("userTargets = %q, want %q", gotUser, tc.wantUser)
			}
			if !reflect.DeepEqual(gotAsst, tc.wantAsst) {
				t.Errorf("asstTargets = %q, want %q", gotAsst, tc.wantAsst)
			}
		})
	}
}
