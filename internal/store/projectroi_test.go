package store

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/commitlog"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/loc"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// promptEvent builds a user_prompt ToolEvent for the Projects-page
// loader tests — the RawToolInput carries the full (unscrubbed at this
// layer — scrubbing already happened at real-adapter ingest time)
// prompt text, mirroring internal/adapter/claudecode's own shape.
func promptEvent(sessionID, root, text, eventID string, ts time.Time) models.ToolEvent {
	return models.ToolEvent{
		SessionID:     sessionID,
		ProjectRoot:   root,
		Target:        text,
		ActionType:    models.ActionUserPrompt,
		RawToolInput:  text,
		RawToolName:   "user_message",
		Tool:          models.ToolClaudeCode,
		SourceFile:    "/tmp/session.jsonl",
		SourceEventID: eventID,
		Timestamp:     ts,
		Success:       true,
	}
}

// editEvent builds an AI edit_file ToolEvent that produces one
// file_changes row (actor=ai) via the real LOC ingest seam, so its
// PathHash is computed exactly the way a live edit's is.
func editEvent(sessionID, root, path, eventID, oldStr, newStr string, ts time.Time) models.ToolEvent {
	return models.ToolEvent{
		SessionID:     sessionID,
		ProjectRoot:   root,
		Target:        path,
		ActionType:    models.ActionEditFile,
		RawToolInput:  `{"file_path":"` + path + `","old_string":"` + oldStr + `","new_string":"` + newStr + `"}`,
		RawToolName:   "Edit",
		Tool:          models.ToolClaudeCode,
		SourceFile:    "/tmp/session.jsonl",
		SourceEventID: eventID,
		Timestamp:     ts,
		Success:       true,
	}
}

// TestLoadProjectPromptsAndEdits pins the R4.1 structural filter (only
// actor='ai' AND action_id IS NOT NULL edits are ever loaded) and the
// R11 truncation contract for both loaders.
func TestLoadProjectPromptsAndEdits(t *testing.T) {
	t.Parallel()
	s, db := newTestStore(t)
	ctx := context.Background()
	root := "/repo/promptsedits"
	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

	events := []models.ToolEvent{
		promptEvent("s1", root, "add a login button", "p1", base),
		editEvent("s1", root, root+"/a.go", "e1", "a := 1", "a := 2", base.Add(time.Minute)),
		promptEvent("s1", root, "now fix the tests", "p2", base.Add(2*time.Minute)),
		editEvent("s1", root, root+"/b.go", "e2", "b := 1", "b := 2", base.Add(3*time.Minute)),
	}
	if _, err := s.Ingest(ctx, events, nil, IngestOptions{}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	projectID, err := s.ProjectIDForRoot(ctx, root)
	if err != nil {
		t.Fatalf("ProjectIDForRoot: %v", err)
	}

	// A HUMAN edit and a system edit must never surface (R4.1).
	if _, err := db.ExecContext(ctx, `
		INSERT INTO file_changes (session_id, project_id, action_id, file_path_hash, actor, source, saved_at, added_code)
		VALUES ('s1', ?, NULL, 'deadbeef', 'human', 'editor', ?, 5)`,
		projectID, base.Add(4*time.Minute).Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("seed human row: %v", err)
	}

	since, until := base.Add(-time.Hour), base.Add(time.Hour)
	prompts, truncated, err := s.LoadProjectPrompts(ctx, projectID, since, until, 500)
	if err != nil {
		t.Fatalf("LoadProjectPrompts: %v", err)
	}
	if truncated {
		t.Errorf("truncated = true, want false")
	}
	if len(prompts) != 2 {
		t.Fatalf("prompts = %d, want 2: %+v", len(prompts), prompts)
	}

	edits, truncated, err := s.LoadProjectAIEdits(ctx, projectID, since, until, 500)
	if err != nil {
		t.Fatalf("LoadProjectAIEdits: %v", err)
	}
	if truncated {
		t.Errorf("truncated = true, want false")
	}
	if len(edits) != 2 {
		t.Fatalf("edits = %d, want 2 (human/system rows must be excluded structurally): %+v", len(edits), edits)
	}
	for _, e := range edits {
		if e.ActionID == 0 {
			t.Errorf("edit %+v has zero ActionID", e)
		}
		if e.SessionID != "s1" {
			t.Errorf("edit SessionID = %q, want s1", e.SessionID)
		}
	}

	// R11 truncation: cap at 1 must report truncated and keep the
	// most-recent row.
	limited, truncated, err := s.LoadProjectPrompts(ctx, projectID, since, until, 1)
	if err != nil {
		t.Fatalf("LoadProjectPrompts (limit 1): %v", err)
	}
	if !truncated || len(limited) != 1 {
		t.Fatalf("LoadProjectPrompts(limit=1) = (%d rows, truncated=%v), want (1, true)", len(limited), truncated)
	}
}

// TestLoadProjectCommitsForLink pins the LoadProjectCommits +
// LoadCommitFiles composition into internal/projectroi.Commit, plus its
// own truncation contract.
func TestLoadProjectCommitsForLink(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	projectID, err := s.UpsertProject(ctx, "/repo/commitlink", "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	commits := []commitlog.Commit{
		{
			SHA: "sha1", AuthorHash: "abc", AuthoredAt: base, CommittedAt: base, Subject: "fix",
			Files: []commitlog.CommitFile{{RelPath: "a.go", PathHash: "hasha", Added: 3, Deleted: 1}},
		},
		{
			SHA: "sha2", AuthorHash: "abc", AuthoredAt: base.Add(time.Hour), CommittedAt: base.Add(time.Hour), Subject: "feat",
			Files: []commitlog.CommitFile{{RelPath: "b.go", PathHash: "hashb", Added: 10}},
		},
	}
	if _, err := s.UpsertCommits(ctx, projectID, commits, base.Add(2*time.Hour)); err != nil {
		t.Fatalf("UpsertCommits: %v", err)
	}

	got, truncated, err := s.LoadProjectCommitsForLink(ctx, projectID, base.Add(-time.Hour), base.Add(24*time.Hour), 500)
	if err != nil {
		t.Fatalf("LoadProjectCommitsForLink: %v", err)
	}
	if truncated {
		t.Errorf("truncated = true, want false")
	}
	if len(got) != 2 {
		t.Fatalf("commits = %d, want 2", len(got))
	}
	bySHA := map[string]int{got[0].SHA: 0, got[1].SHA: 1}
	c1 := got[bySHA["sha1"]]
	if len(c1.Files) != 1 || c1.Files[0].PathHash != "hasha" || c1.Files[0].Added != 3 {
		t.Errorf("sha1 files = %+v, want one hasha/added=3", c1.Files)
	}

	// Truncation.
	_, truncated, err = s.LoadProjectCommitsForLink(ctx, projectID, base.Add(-time.Hour), base.Add(24*time.Hour), 1)
	if err != nil {
		t.Fatalf("LoadProjectCommitsForLink (limit 1): %v", err)
	}
	if !truncated {
		t.Errorf("truncated = false, want true at limit=1 with 2 commits")
	}
}

// TestLoadProjectTurnsPrefersProxyPerSession pins the dual-source rule:
// a session with ANY api_turns row in the window uses ONLY api_turns
// for that session; a session with none falls back to token_usage.
// TestLoadProjectSpendTurnsDedupsAndPrices pins LoadProjectSpendTurns'
// engine-backed contract (2026-09-22 rework, F1-F7 of the arc review): a
// turn captured by BOTH the proxy and the watcher survives once, as the
// proxy row with its RECORDED cost (never the JSONL shadow's inflated
// estimate), while a watcher-only turn survives untouched.
// De-duplication and pricing are the cost engine's own — this loader is
// a thin projectroi.Turn conversion over cost.Engine.TurnRows, not a
// parallel implementation.
func TestLoadProjectSpendTurnsDedupsAndPrices(t *testing.T) {
	t.Parallel()
	s, db := newTestStore(t)
	ctx := context.Background()
	projectID, err := s.UpsertProject(ctx, "/repo/turns", "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

	if _, err := db.ExecContext(ctx, `INSERT INTO sessions (id, project_id, tool, started_at) VALUES (?, ?, 'claude-code', ?)`,
		"proxied", projectID, base.Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("seed session proxied: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO sessions (id, project_id, tool, started_at) VALUES (?, ?, 'claude-code', ?)`,
		"watcheronly", projectID, base.Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("seed session watcheronly: %v", err)
	}

	// "proxied" has BOTH an api_turns row and a token_usage row for the
	// same conceptual turn (same session, minute, model and token
	// shape) — the cost engine's per-turn dedup collapses them to one,
	// keeping the proxy row's recorded cost.
	if _, err := db.ExecContext(ctx, `
		INSERT INTO api_turns (session_id, project_id, timestamp, provider, model, input_tokens, output_tokens, cost_usd)
		VALUES ('proxied', ?, ?, 'anthropic', 'claude-opus-4', 100, 50, 2.00)`,
		projectID, base.Add(time.Minute).Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("seed api_turns: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO token_usage (session_id, timestamp, tool, model, input_tokens, output_tokens, estimated_cost_usd, source)
		VALUES ('proxied', ?, 'claude-code', 'claude-opus-4', 100, 50, 999.00, 'jsonl')`,
		base.Add(time.Minute).Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("seed shadow token_usage: %v", err)
	}
	// "watcheronly" has ONLY a token_usage row.
	if _, err := db.ExecContext(ctx, `
		INSERT INTO token_usage (session_id, timestamp, tool, model, input_tokens, output_tokens, estimated_cost_usd, source)
		VALUES ('watcheronly', ?, 'claude-code', 'claude-sonnet-4', 10, 5, 0.05, 'jsonl')`,
		base.Add(time.Minute).Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("seed watcheronly token_usage: %v", err)
	}

	since, until := base.Add(-time.Hour), base.Add(time.Hour)
	engine := cost.NewEngine(config.IntelligenceConfig{})
	turns, unpriced, err := s.LoadProjectSpendTurns(ctx, engine, projectID, since, until)
	if err != nil {
		t.Fatalf("LoadProjectSpendTurns: %v", err)
	}
	if unpriced != 0 {
		t.Errorf("unpriced = %d, want 0 (both rows carry a recorded cost)", unpriced)
	}
	if len(turns) != 2 {
		t.Fatalf("turns = %d, want 2 (the proxy/JSONL pair deduped to one + watcher-only): %+v", len(turns), turns)
	}
	var proxyRows, jsonlRows int
	for _, tr := range turns {
		switch {
		case tr.Source == "proxy" && tr.SessionID == "proxied" && tr.CostUSD == 2.00:
			proxyRows++
		case tr.Source == "jsonl" && tr.SessionID == "watcheronly" && tr.CostUSD == 0.05:
			jsonlRows++
		default:
			t.Errorf("unexpected turn %+v", tr)
		}
	}
	if proxyRows != 1 || jsonlRows != 1 {
		t.Errorf("proxy=%d jsonl=%d, want 1/1 (JSONL shadow of the proxied turn must be dropped, never its inflated 999.00)", proxyRows, jsonlRows)
	}

	sessions, err := s.LoadProjectSessions(ctx, projectID, since, until)
	if err != nil {
		t.Fatalf("LoadProjectSessions: %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("sessions = %d, want 2", len(sessions))
	}
	for _, sess := range sessions {
		// Session cost is owned by the dashboard composition's pricing
		// pass (loadProjectSpend), never by the store: the loader leaves
		// it 0 so a recorded-column sum can never disagree with the
		// priced turns.
		if sess.CostUSD != 0 {
			t.Errorf("%s session.CostUSD = %v, want 0 (priced one layer up)", sess.ID, sess.CostUSD)
		}
	}
}

// TestLoadProjectSessionsIncludesActivityStartedOutsideWindow pins F8 of
// the 2026-09-22 arc review: a session started BEFORE [since,until) but
// with a turn/prompt/edit inside it must still appear — a plain
// started_at filter silently dropped it, and with it its spend/prompt/
// edit counts from the by-session table even though the same activity
// fed the window's headline totals.
func TestLoadProjectSessionsIncludesActivityStartedOutsideWindow(t *testing.T) {
	t.Parallel()
	s, db := newTestStore(t)
	ctx := context.Background()
	projectID, err := s.UpsertProject(ctx, "/repo/oldsession", "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	windowStart := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	oldStart := windowStart.Add(-31 * 24 * time.Hour)
	activityAt := windowStart.Add(2 * time.Hour)

	if _, err := db.ExecContext(ctx, `INSERT INTO sessions (id, project_id, tool, started_at) VALUES (?, ?, 'claude-code', ?)`,
		"old-but-active", projectID, oldStart.Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO api_turns (session_id, project_id, timestamp, provider, model, input_tokens, output_tokens, cost_usd)
		VALUES ('old-but-active', ?, ?, 'anthropic', 'claude-opus-4', 10, 5, 0.01)`,
		projectID, activityAt.Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("seed api_turns: %v", err)
	}

	sessions, err := s.LoadProjectSessions(ctx, projectID, windowStart, windowStart.Add(24*time.Hour))
	if err != nil {
		t.Fatalf("LoadProjectSessions: %v", err)
	}
	if len(sessions) != 1 || sessions[0].ID != "old-but-active" {
		t.Fatalf("sessions = %+v, want the old session included because it has in-window activity", sessions)
	}
}

// TestLoadProjectTasksStatusMapping pins the taskflow "completed" ->
// projectroi "done" boundary translation (CLAUDE.md module-boundary
// rule #3).
func TestLoadProjectTasksStatusMapping(t *testing.T) {
	t.Parallel()
	s, db := newTestStore(t)
	ctx := context.Background()
	projectID, err := s.UpsertProject(ctx, "/repo/tasks", "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	if _, err := db.ExecContext(ctx, `INSERT INTO sessions (id, project_id, tool, started_at) VALUES ('ts1', ?, 'claude-code', ?)`,
		projectID, base.Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	seed := func(key, status string) {
		t.Helper()
		if _, err := db.ExecContext(ctx, `
			INSERT INTO task_items (session_id, tool, key, key_kind, status, first_seen_at, last_seen_at)
			VALUES ('ts1', 'claude-code', ?, 'native_id', ?, ?, ?)`,
			key, status, base.Format(time.RFC3339Nano), base.Format(time.RFC3339Nano)); err != nil {
			t.Fatalf("seed task %s: %v", key, err)
		}
	}
	seed("t1", "completed")
	seed("t2", "in_progress")

	tasks, err := s.LoadProjectTasks(ctx, projectID, base.Add(-time.Hour), base.Add(time.Hour))
	if err != nil {
		t.Fatalf("LoadProjectTasks: %v", err)
	}
	if len(tasks) != 2 {
		t.Fatalf("tasks = %d, want 2", len(tasks))
	}
	var done, other int
	for _, tk := range tasks {
		switch tk.Status {
		case "done":
			done++
		case "in_progress":
			other++
		default:
			t.Errorf("unexpected task status %q", tk.Status)
		}
	}
	if done != 1 || other != 1 {
		t.Errorf("done=%d other=%d, want 1/1", done, other)
	}
}

// TestLoadProjectLOCTotalsAndMeta pins LOC totals (reusing
// LoadLOCSummary) and the project header facts.
func TestLoadProjectLOCTotalsAndMeta(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	root := "/repo/locmeta"
	base := time.Now().UTC().Add(-time.Hour)

	events := []models.ToolEvent{
		editEvent("s1", root, root+"/a.go", "e1", "a := 1", "a := 2", base),
	}
	if _, err := s.Ingest(ctx, events, nil, IngestOptions{}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	projectID, err := s.ProjectIDForRoot(ctx, root)
	if err != nil {
		t.Fatalf("ProjectIDForRoot: %v", err)
	}

	aiAdded, aiModified, humanCapture, err := s.LoadProjectLOCTotals(ctx, projectID, base.Add(-time.Hour), base.Add(time.Hour))
	if err != nil {
		t.Fatalf("LoadProjectLOCTotals: %v", err)
	}
	if aiAdded+aiModified == 0 {
		t.Errorf("aiAdded=%d aiModified=%d, want at least one line counted", aiAdded, aiModified)
	}
	if humanCapture != "none" {
		t.Errorf("humanCapture = %q, want none (no editor rows seeded)", humanCapture)
	}

	meta, ok, err := s.LoadProjectMeta(ctx, projectID)
	if err != nil {
		t.Fatalf("LoadProjectMeta: %v", err)
	}
	if !ok {
		t.Fatal("LoadProjectMeta: ok=false, want true")
	}
	if meta.RootPath != root {
		t.Errorf("RootPath = %q, want %q", meta.RootPath, root)
	}
	if len(meta.Tools) != 1 || meta.Tools[0] != "claude-code" {
		t.Errorf("Tools = %v, want [claude-code]", meta.Tools)
	}
	if meta.FirstSeen.IsZero() || meta.LastSeen.IsZero() {
		t.Errorf("FirstSeen/LastSeen unexpectedly zero: %+v", meta)
	}

	if _, ok, err := s.LoadProjectMeta(ctx, projectID+9999); err != nil || ok {
		t.Errorf("LoadProjectMeta(unknown) = (ok=%v, err=%v), want (false, nil)", ok, err)
	}
}

// TestLoadProjectListExtras pins the /api/projects additive-fields
// aggregate: spend/AI-lines/commits in the window, all-time last
// commit, and the capture struct gated on "has been scanned at least
// once".
func TestLoadProjectListExtras(t *testing.T) {
	t.Parallel()
	s, db := newTestStore(t)
	ctx := context.Background()
	root := "/repo/listextras"
	base := time.Now().UTC().Add(-time.Hour)

	events := []models.ToolEvent{
		editEvent("s1", root, root+"/a.go", "e1", "a := 1", "a := 2", base),
	}
	if _, err := s.Ingest(ctx, events, nil, IngestOptions{}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	projectID, err := s.ProjectIDForRoot(ctx, root)
	if err != nil {
		t.Fatalf("ProjectIDForRoot: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO api_turns (session_id, project_id, timestamp, provider, model, input_tokens, output_tokens, cost_usd)
		VALUES ('s1', ?, ?, 'anthropic', 'claude-opus-4', 100, 50, 1.25)`,
		projectID, base.Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("seed api_turns: %v", err)
	}
	commits := []commitlog.Commit{
		{
			SHA: "sha1", AuthorHash: "abc", AuthoredAt: base, CommittedAt: base, Subject: "fix",
			Files: []commitlog.CommitFile{{RelPath: "a.go", PathHash: loc.PathHash(root, root+"/a.go"), Added: 1}},
		},
	}
	if _, err := s.UpsertCommits(ctx, projectID, commits, base); err != nil {
		t.Fatalf("UpsertCommits: %v", err)
	}
	if err := s.SetCommitScanState(ctx, ScanState{ProjectID: projectID, LastSHA: "sha1", LastCommittedAt: base, LastScanAt: base}); err != nil {
		t.Fatalf("SetCommitScanState: %v", err)
	}

	// A second, never-scanned project must be entirely absent from the
	// returned map (R7: "never touched" -> omit, not a fabricated zero).
	unscannedID, err := s.UpsertProject(ctx, "/repo/neverscanned", "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}

	extras, err := s.LoadProjectListExtras(ctx, base.Add(-24*time.Hour), base.Add(24*time.Hour))
	if err != nil {
		t.Fatalf("LoadProjectListExtras: %v", err)
	}
	e, ok := extras[projectID]
	if !ok {
		t.Fatalf("project %d absent from LoadProjectListExtras", projectID)
	}
	// Spend is priced through cost.Engine.Summary(GroupByProject) in the
	// dashboard handler now (see TestHandleProjectsSpendMatchesCostEngine
	// in internal/intelligence/dashboard), not a store-level bucket
	// loader — LoadProjectListExtras itself only ever fed AI lines /
	// commits / capture posture.
	if e.AILines30d == 0 {
		t.Errorf("AILines30d = 0, want > 0")
	}
	if e.Commits30d != 1 {
		t.Errorf("Commits30d = %d, want 1", e.Commits30d)
	}
	if e.LastCommitAt.IsZero() {
		t.Errorf("LastCommitAt is zero")
	}
	if !e.CommitsScanned || e.CommitCapture != "ok" {
		t.Errorf("CommitsScanned/CommitCapture = %v/%q, want true/ok", e.CommitsScanned, e.CommitCapture)
	}
	if e.HumanLOC != "none" {
		t.Errorf("HumanLOC = %q, want none", e.HumanLOC)
	}
	if _, ok := extras[unscannedID]; ok {
		t.Errorf("never-scanned project %d unexpectedly present in LoadProjectListExtras", unscannedID)
	}
}

// TestLoadProjectListExtrasCommits30dCountsReachableMergesOnly pins the
// F17 fix of the 2026-09-22 arc review: Commits30d must use the SAME
// predicate as projectroi.CountsAsCommit (reachable-only; a merge
// counts toward the total, an unreachable non-merge does not). Pre-fix
// this query also excluded merges (`is_merge = 0`), disagreeing with
// both the ROI proxies (projectroi.CountCommits) and, once fixed, the
// detail panel's Commits.Count.
func TestLoadProjectListExtrasCommits30dCountsReachableMergesOnly(t *testing.T) {
	t.Parallel()
	s, db := newTestStore(t)
	ctx := context.Background()
	projectID, err := s.UpsertProject(ctx, "/repo/mergecommits", "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	base := time.Now().UTC().Add(-time.Hour)
	commits := []commitlog.Commit{
		{SHA: "sha-normal", AuthorHash: "abc", AuthoredAt: base, CommittedAt: base, Subject: "fix"},
		{SHA: "sha-merge", AuthorHash: "abc", AuthoredAt: base, CommittedAt: base, Subject: "Merge branch 'x'", IsMerge: true},
		{SHA: "sha-unreachable", AuthorHash: "abc", AuthoredAt: base, CommittedAt: base, Subject: "rebased away"},
	}
	if _, err := s.UpsertCommits(ctx, projectID, commits, base); err != nil {
		t.Fatalf("UpsertCommits: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE project_commits SET reachable = 0 WHERE project_id = ? AND sha = ?`, projectID, "sha-unreachable"); err != nil {
		t.Fatalf("mark unreachable: %v", err)
	}

	extras, err := s.LoadProjectListExtras(ctx, base.Add(-24*time.Hour), base.Add(24*time.Hour))
	if err != nil {
		t.Fatalf("LoadProjectListExtras: %v", err)
	}
	e, ok := extras[projectID]
	if !ok {
		t.Fatalf("project %d absent from LoadProjectListExtras", projectID)
	}
	if e.Commits30d != 2 {
		t.Errorf("Commits30d = %d, want 2 (the reachable merge counts, the unreachable non-merge does not)", e.Commits30d)
	}
}

// TestLoadPromptChainInput covers a prompt whose AI edit reached a
// commit (facts.CommitID set, one hunk, one file) and a prompt whose
// edit reached no commit (facts.CommitID zero, no hunks) — the two
// shapes both the judge tier and the cloud-evidence loader must handle.
func TestLoadPromptChainInput(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	root := "/repo/chaininput"
	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

	events := []models.ToolEvent{
		promptEvent("s1", root, "add a login button", "p1", base),
		editEvent("s1", root, root+"/a.go", "e1", "a := 1", "a := 2", base.Add(time.Minute)),
		promptEvent("s1", root, "unrelated ask, never committed", "p2", base.Add(time.Hour)),
		editEvent("s1", root, root+"/c.go", "e2", "c := 1", "c := 2", base.Add(time.Hour+time.Minute)),
	}
	if _, err := s.Ingest(ctx, events, nil, IngestOptions{}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	projectID, err := s.ProjectIDForRoot(ctx, root)
	if err != nil {
		t.Fatalf("ProjectIDForRoot: %v", err)
	}

	var p1ID, p2ID int64
	prompts, _, err := s.LoadProjectPrompts(ctx, projectID, base.Add(-time.Hour), base.Add(24*time.Hour), 500)
	if err != nil {
		t.Fatalf("LoadProjectPrompts: %v", err)
	}
	for _, p := range prompts {
		switch p.Preview {
		case "add a login button":
			p1ID = p.ActionID
		case "unrelated ask, never committed":
			p2ID = p.ActionID
		}
	}
	if p1ID == 0 || p2ID == 0 {
		t.Fatalf("could not resolve seeded prompt action ids: %+v", prompts)
	}

	commits := []commitlog.Commit{
		{
			SHA: "sha1", AuthorHash: "abc", AuthoredAt: base.Add(10 * time.Minute), CommittedAt: base.Add(10 * time.Minute), Subject: "feat: login button",
			Files: []commitlog.CommitFile{{RelPath: "a.go", PathHash: loc.PathHash(root, root+"/a.go"), Added: 1}},
		},
	}
	if _, err := s.UpsertCommits(ctx, projectID, commits, base.Add(20*time.Minute)); err != nil {
		t.Fatalf("UpsertCommits: %v", err)
	}

	in, facts, err := s.LoadPromptChainInput(ctx, projectID, p1ID)
	if err != nil {
		t.Fatalf("LoadPromptChainInput(p1): %v", err)
	}
	if facts.LinkStatus != "committed" {
		t.Errorf("p1 LinkStatus = %q, want committed", facts.LinkStatus)
	}
	if facts.CommitID == 0 || facts.CommitSHA != "sha1" {
		t.Errorf("p1 facts commit = %+v, want sha1 linked", facts)
	}
	if len(facts.CommitFiles) != 1 || facts.CommitFiles[0].RelPath != "a.go" {
		t.Errorf("p1 CommitFiles = %+v, want one a.go", facts.CommitFiles)
	}
	if len(facts.Hunks) != 1 {
		t.Errorf("p1 Hunks = %d, want 1", len(facts.Hunks))
	}
	if in.PromptText == "" || in.CommitSubject == "" || len(in.Files) != 1 || len(in.Hunks) != 1 {
		t.Errorf("p1 alignment.Input incomplete: %+v", in)
	}

	_, facts2, err := s.LoadPromptChainInput(ctx, projectID, p2ID)
	if err != nil {
		t.Fatalf("LoadPromptChainInput(p2): %v", err)
	}
	if facts2.LinkStatus != "uncommitted" {
		t.Errorf("p2 LinkStatus = %q, want uncommitted", facts2.LinkStatus)
	}
	if facts2.CommitID != 0 || len(facts2.Hunks) != 0 || len(facts2.CommitFiles) != 0 {
		t.Errorf("p2 facts unexpectedly carries a commit: %+v", facts2)
	}

	if _, _, err := s.LoadPromptChainInput(ctx, projectID, 999999); err == nil {
		t.Errorf("LoadPromptChainInput(unknown action) = nil error, want an error")
	}
}

// TestProjectIDForAction pins the tiny lookup cmd/observer's grade-
// commit CLI loader uses (keyed by action id alone).
func TestProjectIDForAction(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	root := "/repo/actionlookup"
	base := time.Now().UTC()

	events := []models.ToolEvent{promptEvent("s1", root, "hello", "p1", base)}
	if _, err := s.Ingest(ctx, events, nil, IngestOptions{}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	projectID, err := s.ProjectIDForRoot(ctx, root)
	if err != nil {
		t.Fatalf("ProjectIDForRoot: %v", err)
	}
	prompts, _, err := s.LoadProjectPrompts(ctx, projectID, base.Add(-time.Hour), base.Add(time.Hour), 10)
	if err != nil || len(prompts) != 1 {
		t.Fatalf("LoadProjectPrompts: %v (%d rows)", err, len(prompts))
	}

	got, err := s.ProjectIDForAction(ctx, prompts[0].ActionID)
	if err != nil {
		t.Fatalf("ProjectIDForAction: %v", err)
	}
	if got != projectID {
		t.Errorf("ProjectIDForAction = %d, want %d", got, projectID)
	}

	if _, err := s.ProjectIDForAction(ctx, 999999); err == nil {
		t.Errorf("ProjectIDForAction(unknown) = nil error, want an error")
	}
}

// TestLoadProjectSpendTurnsCountsCacheReadMissAsUnpriced pins review finding
// F2 (session 3, 2026-09-26): a table-priced turn whose model's CACHE-READ
// rate the vendor never quoted (cost.CacheReadUnpricedAt - swe-1-7-medium is
// the grounded case) bills its cached tokens at an intentional unpriced $0.
// The aggregate Summary already reports that as a miss; the Projects path
// must too, so its unpriced/coverage counts never call such a turn exact. A
// turn with no cached tokens, and a recorded-cost turn (the table was never
// consulted), stay fully priced.
func TestLoadProjectSpendTurnsCountsCacheReadMissAsUnpriced(t *testing.T) {
	t.Parallel()
	s, db := newTestStore(t)
	ctx := context.Background()
	projectID, err := s.UpsertProject(ctx, "/repo/cachemiss", "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	for _, sid := range []string{"cached", "uncached", "recorded"} {
		if _, err := db.ExecContext(ctx, `INSERT INTO sessions (id, project_id, tool, started_at) VALUES (?, ?, 'devin', ?)`,
			sid, projectID, base.Format(time.RFC3339Nano)); err != nil {
			t.Fatalf("seed session %s: %v", sid, err)
		}
	}
	for i, row := range []struct {
		sid       string
		cacheRead int64
		recorded  float64
	}{
		{"cached", 5000, 0},
		{"uncached", 0, 0},
		{"recorded", 5000, 0.25},
	} {
		if _, err := db.ExecContext(ctx, `
			INSERT INTO token_usage (session_id, timestamp, tool, model, input_tokens, output_tokens, cache_read_tokens, estimated_cost_usd, source)
			VALUES (?, ?, 'devin', 'swe-1-7-medium', 100, 50, ?, ?, 'jsonl')`,
			row.sid, base.Add(time.Duration(i+1)*time.Minute).Format(time.RFC3339Nano), row.cacheRead, row.recorded); err != nil {
			t.Fatalf("seed token_usage %s: %v", row.sid, err)
		}
	}

	engine := cost.NewEngine(config.IntelligenceConfig{})
	if !engine.CacheReadUnpricedAt("swe-1-7-medium", base) {
		t.Fatal("precondition: swe-1-7-medium no longer has an unquoted cache-read rate; pick another cacheReadNotQuoted model")
	}
	turns, unpriced, err := s.LoadProjectSpendTurns(ctx, engine, projectID, base.Add(-time.Hour), base.Add(time.Hour))
	if err != nil {
		t.Fatalf("LoadProjectSpendTurns: %v", err)
	}
	if len(turns) != 3 {
		t.Fatalf("turns = %d, want 3", len(turns))
	}
	priced := map[string]bool{}
	for _, tr := range turns {
		priced[tr.SessionID] = tr.Priced
	}
	if priced["cached"] {
		t.Error("a turn whose cached tokens billed at an UNQUOTED cache-read rate reads as fully priced")
	}
	if !priced["uncached"] || !priced["recorded"] {
		t.Errorf("priced = %+v, want the no-cache and recorded-cost turns fully priced", priced)
	}
	if unpriced != 1 {
		t.Errorf("unpriced = %d, want 1 (the cache-read miss)", unpriced)
	}
}

// TestProjectUnpricedCountMatchesSummaryProjectBucket pins review round 2
// finding 2: for the SAME fixture, Summary's GroupByProject bucket (what the
// /api/projects list reads) and the Projects detail path (LoadProjectSpendTurns)
// must agree on how many of the project's turns are not fully priced -
// including a turn whose cached tokens billed against an unquoted cache-read
// rate (a partial price).
func TestProjectUnpricedCountMatchesSummaryProjectBucket(t *testing.T) {
	t.Parallel()
	s, db := newTestStore(t)
	ctx := context.Background()
	const root = "/repo/cachemiss-parity"
	projectID, err := s.UpsertProject(ctx, root, "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	base := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	for _, sid := range []string{"cached", "uncached", "unknown"} {
		if _, err := db.ExecContext(ctx, `INSERT INTO sessions (id, project_id, tool, started_at) VALUES (?, ?, 'devin', ?)`,
			sid, projectID, base.Format(time.RFC3339Nano)); err != nil {
			t.Fatalf("seed session %s: %v", sid, err)
		}
	}
	for i, row := range []struct {
		sid, model string
		cacheRead  int64
	}{
		{"cached", "swe-1-7-medium", 5000},       // partial: cache-read rate never quoted
		{"uncached", "swe-1-7-medium", 0},        // fully priced
		{"unknown", "no-such-model-anywhere", 0}, // whole-row miss
	} {
		if _, err := db.ExecContext(ctx, `
			INSERT INTO token_usage (session_id, timestamp, tool, model, input_tokens, output_tokens, cache_read_tokens, estimated_cost_usd, source)
			VALUES (?, ?, 'devin', ?, 100, 50, ?, 0, 'jsonl')`,
			row.sid, base.Add(time.Duration(i+1)*time.Minute).Format(time.RFC3339Nano), row.model, row.cacheRead); err != nil {
			t.Fatalf("seed token_usage %s: %v", row.sid, err)
		}
	}

	engine := cost.NewEngine(config.IntelligenceConfig{})
	_, projectsUnpriced, err := s.LoadProjectSpendTurns(ctx, engine, projectID, base.Add(-time.Hour), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatalf("LoadProjectSpendTurns: %v", err)
	}
	summary, err := engine.Summary(ctx, db, cost.Options{GroupBy: cost.GroupByProject, Days: 1, Limit: 1000})
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	var bucket *cost.Row
	for i := range summary.Rows {
		if summary.Rows[i].Key == root {
			bucket = &summary.Rows[i]
		}
	}
	if bucket == nil {
		t.Fatalf("Summary(GroupByProject) has no row for %s: %+v", root, summary.Rows)
	}
	if projectsUnpriced != 2 {
		t.Fatalf("Projects unpriced = %d, want 2 (the cache-read miss and the unknown model)", projectsUnpriced)
	}
	if bucket.UnpricedTurnCount != projectsUnpriced {
		t.Errorf("Summary project bucket UnpricedTurnCount = %d, Projects = %d; the two surfaces disagree", bucket.UnpricedTurnCount, projectsUnpriced)
	}
	if bucket.PricedTurnCount != bucket.TurnCount-projectsUnpriced {
		t.Errorf("Summary project bucket PricedTurnCount = %d, want %d", bucket.PricedTurnCount, bucket.TurnCount-projectsUnpriced)
	}
}
