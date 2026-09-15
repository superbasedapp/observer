package store

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/loc"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// locSeedSession creates a project + a session so the org composers (which
// window on sessions.started_at) have something to join to.
func locSeedSession(ctx context.Context, t *testing.T, s *Store, root, sessionID string) int64 {
	t.Helper()
	pid, err := s.UpsertProject(ctx, root, "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	now := time.Now().UTC().Add(-time.Hour)
	if _, err := s.Ingest(ctx, []models.ToolEvent{{
		SourceFile: "t.jsonl", SourceEventID: sessionID + "-e1", SessionID: sessionID,
		ProjectRoot: root, Timestamp: now, Tool: models.ToolClaudeCode,
		ActionType: models.ActionReadFile, Target: "main.go", Success: true,
	}}, nil, IngestOptions{}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	return pid
}

func locRow(sessionID string, pid int64, hash, digest, actor, source string, side bool, st loc.Stats) FileChangeRow {
	return FileChangeRow{
		SessionID: sessionID, ProjectID: pid,
		FilePathHash: hash, InputDigest: digest,
		Language: string(loc.LangGo), Category: string(loc.CategoryCode),
		Actor: actor, Confidence: string(loc.ConfidenceHigh), Source: source,
		Sidechain: side, Stats: st, Version: loc.Version,
		SavedAt: time.Now().UTC().Add(-30 * time.Minute),
	}
}

// TestSelectSessionLOCSummariesSplitsByProjectRoot pins the natural key: a
// session whose rows span two project roots produces two wire rows, so one
// repository's code is never attributed to another.
func TestSelectSessionLOCSummariesSplitsByProjectRoot(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	pidA := locSeedSession(ctx, t, s, "/repo-a", "sess-multi")
	pidB, err := s.UpsertProject(ctx, "/repo-b", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.InsertFileChanges(ctx, []FileChangeRow{
		locRow("sess-multi", pidA, "fa", "da", LOCActorAI, LOCSourceEdit, false, loc.Stats{AddedCode: 10}),
		locRow("sess-multi", pidB, "fb", "db", LOCActorAI, LOCSourceEdit, false, loc.Stats{AddedCode: 3}),
	}); err != nil {
		t.Fatalf("InsertFileChanges: %v", err)
	}

	rows, err := s.SelectSessionLOCSummaries(ctx, ScopeOptions{}, false)
	if err != nil {
		t.Fatalf("SelectSessionLOCSummaries: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2 (one per project root)", len(rows))
	}
	byHash := map[string]int64{}
	for _, r := range rows {
		if r.SessionID != "sess-multi" {
			t.Errorf("unexpected session %q", r.SessionID)
		}
		byHash[r.ProjectRootHash] = r.AIAddedCode
	}
	var seen10, seen3 bool
	for _, v := range byHash {
		if v == 10 {
			seen10 = true
		}
		if v == 3 {
			seen3 = true
		}
	}
	if !seen10 || !seen3 {
		t.Errorf("per-root AI lines = %v, want one root with 10 and one with 3", byHash)
	}
}

// TestSelectSessionLOCSummariesCollapsesCodexDuplicatePair pins the dedup the
// org wire inherits from the node read: codex emits every patch twice under
// two action ids, and the wire must report the lines ONCE.
func TestSelectSessionLOCSummariesCollapsesCodexDuplicatePair(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	pid := locSeedSession(ctx, t, s, "/repo", "sess-codex")

	// Same (session, file, digest, actor, source) twice — the invocation and
	// the executor rendering of one patch.
	a := locRow("sess-codex", pid, "f1", "same-digest", LOCActorAI, LOCSourcePatch, false, loc.Stats{AddedCode: 25})
	a.ActionID = 0
	b := a
	if _, err := s.InsertFileChanges(ctx, []FileChangeRow{a}); err != nil {
		t.Fatalf("insert a: %v", err)
	}
	// A second row with a different saved_at so the editor-unique index does
	// not collapse them at insert time — the dedup must happen at READ time.
	b.SavedAt = a.SavedAt.Add(time.Second)
	if _, err := s.InsertFileChanges(ctx, []FileChangeRow{b}); err != nil {
		t.Fatalf("insert b: %v", err)
	}

	// Non-vacuity: both physical rows must actually exist, or the collapse
	// below would pass simply because only one was ever stored.
	var stored int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM file_changes WHERE session_id = 'sess-codex'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != 2 {
		t.Fatalf("stored %d file_changes rows, want 2 — the duplicate-pair assertion is vacuous", stored)
	}

	rows, err := s.SelectSessionLOCSummaries(ctx, ScopeOptions{}, false)
	if err != nil {
		t.Fatalf("SelectSessionLOCSummaries: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	if rows[0].AIAddedCode != 25 {
		t.Errorf("ai_added_code = %d, want 25 — the codex invocation/executor pair was double counted", rows[0].AIAddedCode)
	}
}

// TestSelectSessionLOCSummariesExcludesEditorEcho pins migration 103's stated
// contract: an editor row later found to be the echo of an AI write is kept
// as evidence and NEVER counted.
func TestSelectSessionLOCSummariesExcludesEditorEcho(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	pid := locSeedSession(ctx, t, s, "/repo", "sess-echo")

	if _, err := s.InsertFileChanges(ctx, []FileChangeRow{
		locRow("sess-echo", pid, "f1", "d1", LOCActorAI, LOCSourceEdit, false, loc.Stats{AddedCode: 12}),
		locRow("sess-echo", pid, "f1", "", LOCActorHuman, LOCSourceEditor, false, loc.Stats{AddedCode: 12}),
	}); err != nil {
		t.Fatalf("InsertFileChanges: %v", err)
	}
	pending, err := s.LoadEditorRowsPending(ctx, time.Now().UTC().Add(-2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("pending editor rows = %d, want 1", len(pending))
	}
	if err := s.MarkEditorEcho(ctx, pending[0].ID); err != nil {
		t.Fatal(err)
	}

	rows, err := s.SelectSessionLOCSummaries(ctx, ScopeOptions{}, false)
	if err != nil {
		t.Fatalf("SelectSessionLOCSummaries: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	if rows[0].UnknownLines != 0 {
		t.Errorf("unknown_lines = %d, want 0 — a reconciled echo must not be recounted as unattributed authorship", rows[0].UnknownLines)
	}
	if rows[0].HumanCapture != "none" {
		t.Errorf("human_capture = %q, want \"none\" — an echo is not evidence that human work was measured", rows[0].HumanCapture)
	}
	if rows[0].AIAddedCode != 12 {
		t.Errorf("ai_added_code = %d, want 12", rows[0].AIAddedCode)
	}
}

// TestSelectSessionLOCSummariesLanguageMixIsGated pins the one gated field:
// withLanguageMix=false leaves it empty, true fills it with the canonical
// language ids and line counts.
func TestSelectSessionLOCSummariesLanguageMixIsGated(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	pid := locSeedSession(ctx, t, s, "/repo", "sess-mix")
	if _, err := s.InsertFileChanges(ctx, []FileChangeRow{
		locRow("sess-mix", pid, "f1", "d1", LOCActorAI, LOCSourceEdit, false, loc.Stats{AddedCode: 9}),
	}); err != nil {
		t.Fatalf("InsertFileChanges: %v", err)
	}

	off, err := s.SelectSessionLOCSummaries(ctx, ScopeOptions{}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(off) != 1 || off[0].LanguageMixJSON != "" {
		t.Fatalf("language mix leaked without the gate: %+v", off)
	}

	on, err := s.SelectSessionLOCSummaries(ctx, ScopeOptions{}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(on) != 1 || on[0].LanguageMixJSON == "" {
		t.Fatalf("language mix missing under the gate: %+v", on)
	}
	var mix []orgcontract.LOCLanguageLines
	if err := json.Unmarshal([]byte(on[0].LanguageMixJSON), &mix); err != nil {
		t.Fatalf("language_mix_json: %v", err)
	}
	if len(mix) != 1 || mix[0].Language != string(loc.LangGo) || mix[0].Lines != 9 {
		t.Errorf("language mix = %+v, want one go entry with 9 lines", mix)
	}
}

// TestSelectSessionLOCSummariesSkipsNonCodeCategories pins plan §1's
// exclusion: a session whose only changes were to generated or vendored files
// ships nothing, and docs/config land in their own buckets rather than in the
// code totals.
func TestSelectSessionLOCSummariesSkipsNonCodeCategories(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	pid := locSeedSession(ctx, t, s, "/repo", "sess-gen")

	gen := locRow("sess-gen", pid, "fgen", "dgen", LOCActorAI, LOCSourceEdit, false, loc.Stats{AddedCode: 5000})
	gen.Category = string(loc.CategoryGenerated)
	docs := locRow("sess-gen", pid, "fdoc", "ddoc", LOCActorAI, LOCSourceEdit, false, loc.Stats{AddedCode: 40})
	docs.Category = string(loc.CategoryDocs)
	code := locRow("sess-gen", pid, "fgo", "dgo", LOCActorAI, LOCSourceEdit, false, loc.Stats{AddedCode: 7})
	if _, err := s.InsertFileChanges(ctx, []FileChangeRow{gen, docs, code}); err != nil {
		t.Fatalf("InsertFileChanges: %v", err)
	}

	rows, err := s.SelectSessionLOCSummaries(ctx, ScopeOptions{}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	if rows[0].AIAddedCode != 7 {
		t.Errorf("ai_added_code = %d, want 7 — a generated file must contribute no code lines", rows[0].AIAddedCode)
	}
	if rows[0].DocsLines != 40 {
		t.Errorf("docs_lines = %d, want 40", rows[0].DocsLines)
	}
}

// TestSelectLOCDaySummariesCarriesSessionlessEditorWork is the reason the day
// bucket exists (plan §2): an editor save with NO session must still appear,
// or a developer whose agent runs in a terminal reads as 100% AI.
func TestSelectLOCDaySummariesCarriesSessionlessEditorWork(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	pid, err := s.UpsertProject(ctx, "/repo", "")
	if err != nil {
		t.Fatal(err)
	}
	saved := time.Now().UTC().Add(-2 * time.Hour)
	row := locRow("", pid, "fhuman", "", LOCActorHuman, LOCSourceEditor, false, loc.Stats{AddedCode: 31, ModifiedCode: 4})
	row.SavedAt = saved
	if _, err := s.InsertFileChanges(ctx, []FileChangeRow{row}); err != nil {
		t.Fatalf("InsertFileChanges: %v", err)
	}

	// The per-session wire carries nothing (there is no session).
	sessions, err := s.SelectSessionLOCSummaries(ctx, ScopeOptions{}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 0 {
		t.Fatalf("session wire carried %d rows for session-less work, want 0", len(sessions))
	}

	days, err := s.SelectLOCDaySummaries(ctx, ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectLOCDaySummaries: %v", err)
	}
	if len(days) != 1 {
		t.Fatalf("day wire carried %d rows, want 1 — session-less editor work is exactly what this wire is for", len(days))
	}
	if days[0].HumanCodeLines != 35 {
		t.Errorf("human_code_lines = %d, want 35 (31 added + 4 modified)", days[0].HumanCodeLines)
	}
	if days[0].Day != saved.Format("2006-01-02") {
		t.Errorf("day = %q, want the EVENT date %q — bucketing on ingest time would pile a backfill onto today",
			days[0].Day, saved.Format("2006-01-02"))
	}
	if days[0].HumanCapture != "vscode" {
		t.Errorf("human_capture = %q, want \"vscode\"", days[0].HumanCapture)
	}
}

// TestLOCOrgComposersRespectProjectScope pins that an operator's project
// allowlist narrows the LOC wire the same way it narrows sessions/actions.
func TestLOCOrgComposersRespectProjectScope(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	pidA := locSeedSession(ctx, t, s, "/repo-a", "sess-a")
	pidB := locSeedSession(ctx, t, s, "/repo-b", "sess-b")
	if _, err := s.InsertFileChanges(ctx, []FileChangeRow{
		locRow("sess-a", pidA, "fa", "da", LOCActorAI, LOCSourceEdit, false, loc.Stats{AddedCode: 10}),
		locRow("sess-b", pidB, "fb", "db", LOCActorAI, LOCSourceEdit, false, loc.Stats{AddedCode: 20}),
	}); err != nil {
		t.Fatalf("InsertFileChanges: %v", err)
	}

	scope := ScopeOptions{ProjectRootAllowlist: []string{"/repo-a"}}
	rows, err := s.SelectSessionLOCSummaries(ctx, scope, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].SessionID != "sess-a" {
		t.Fatalf("scoped session wire = %+v, want only sess-a", rows)
	}
	days, err := s.SelectLOCDaySummaries(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	if len(days) != 1 || days[0].AICodeLines != 10 {
		t.Fatalf("scoped day wire = %+v, want only /repo-a's 10 lines", days)
	}

	// A scope that resolves to nothing ships nothing — never everything.
	none, err := s.SelectSessionLOCSummaries(ctx, ScopeOptions{ProjectRootAllowlist: []string{"/no-such-repo"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(none) != 0 {
		t.Fatalf("a scope matching no project shipped %d rows, want 0", len(none))
	}
}

// TestSessionLessDigestRowIsCountedOnceByNodeAndOrg pins that the node and
// org collapse rules PARTITION the table identically.
//
// A row with a NULL session_id AND a non-empty input_digest matched neither
// arm of the node CTE — arm 1 required a session, arm 2 required an empty
// digest — so it was invisible to every node read while the org window CTE
// (whose arm 1 did not require a session) happily counted it. The shape is
// unreachable today: an AI row always carries its session and an editor save
// never carries a digest. That is exactly why it must be pinned rather than
// argued about — the two sides have to answer the same way for a shape
// neither of them should be inventing an answer for.
//
// Two rows are used, sharing a digest and a file, because the collapse group
// is SESSION-scoped: session-less rows can never share a group, so both must
// count on both sides.
func TestSessionLessDigestRowIsCountedOnceByNodeAndOrg(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	pid, err := s.UpsertProject(ctx, "/repo", "")
	if err != nil {
		t.Fatal(err)
	}

	// Midday anchor: two rows minutes apart must land in ONE day bucket even
	// when the suite runs either side of UTC midnight.
	day := time.Now().UTC().Truncate(24 * time.Hour).Add(12 * time.Hour)
	rows := []FileChangeRow{}
	for i, added := range []int{5, 7} {
		r := locRow("", pid, "fsessionless", "shared-digest",
			LOCActorHuman, LOCSourceEditor, false, loc.Stats{AddedCode: added})
		r.SavedAt = day.Add(time.Duration(i) * time.Minute)
		rows = append(rows, r)
	}
	if _, err := s.InsertFileChanges(ctx, rows); err != nil {
		t.Fatalf("InsertFileChanges: %v", err)
	}

	byDay, err := s.LoadLOCByDay(ctx, 30, 0)
	if err != nil {
		t.Fatalf("LoadLOCByDay: %v", err)
	}
	var nodeDayLines int
	for _, d := range byDay {
		nodeDayLines += d.Stats.AddedCode
	}
	if nodeDayLines != 12 {
		t.Errorf("LoadLOCByDay counted %d added_code, want 12 — a session-less row carrying a "+
			"digest matched neither arm of the node collapse and vanished from every node read",
			nodeDayLines)
	}

	summary, err := s.LoadLOCSummary(ctx, 30, 0)
	if err != nil {
		t.Fatalf("LoadLOCSummary: %v", err)
	}
	var nodeSummaryLines int
	for _, b := range summary.Buckets {
		nodeSummaryLines += b.Stats.AddedCode
	}
	if nodeSummaryLines != 12 {
		t.Errorf("LoadLOCSummary counted %d added_code, want 12", nodeSummaryLines)
	}

	orgDays, err := s.SelectLOCDaySummaries(ctx, ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectLOCDaySummaries: %v", err)
	}
	var orgLines int64
	for _, d := range orgDays {
		orgLines += d.HumanCodeLines
	}
	if orgLines != 12 {
		t.Errorf("SelectLOCDaySummaries counted %d human code lines, want 12 — the org arm 1 "+
			"grouped the two session-less rows together and kept only one", orgLines)
	}
	if int64(nodeDayLines) != orgLines {
		t.Errorf("node counted %d, org counted %d — one collapse rule, or the node card and the "+
			"org panel describe the same work differently", nodeDayLines, orgLines)
	}
}

// TestSelectLOCDaySummariesDropsRowsOlderThanTheWireWindow pins the org
// wire's trailing-7-day bound against the node-local read of the same rows
// (2026-09-07 review finding L1: the composer's comment read as a promise
// that a backfill of an old action ships to the org — it does not; only its
// BUCKET KEY is the action's own day). An `observer backfill --loc
// --loc-since <old date>` populates file_changes the node card renders,
// while session_loc / loc_days carry nothing older than the window.
func TestSelectLOCDaySummariesDropsRowsOlderThanTheWireWindow(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	pid, err := s.UpsertProject(ctx, "/repo", "")
	if err != nil {
		t.Fatal(err)
	}
	old := locRow("", pid, "fold", "", LOCActorHuman, LOCSourceEditor, false, loc.Stats{AddedCode: 100})
	old.SavedAt = time.Now().UTC().AddDate(0, 0, -40)
	recent := locRow("", pid, "fnew", "", LOCActorHuman, LOCSourceEditor, false, loc.Stats{AddedCode: 7})
	recent.SavedAt = time.Now().UTC().Add(-2 * time.Hour)
	if _, err := s.InsertFileChanges(ctx, []FileChangeRow{old, recent}); err != nil {
		t.Fatalf("InsertFileChanges: %v", err)
	}

	// Node-local: both days are readable, each bucketed on its own event day.
	local, err := s.LoadLOCByDay(ctx, 90, 0)
	if err != nil {
		t.Fatalf("LoadLOCByDay: %v", err)
	}
	if len(local) != 2 {
		t.Fatalf("node-local days = %d, want 2 (the backfilled day is visible on the node)", len(local))
	}

	// Org wire: only the in-window day ships.
	days, err := s.SelectLOCDaySummaries(ctx, ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectLOCDaySummaries: %v", err)
	}
	if len(days) != 1 {
		t.Fatalf("wire days = %d, want 1 — rows older than the %d-day window stay node-local", len(days), locOrgWindowDays)
	}
	if want := recent.SavedAt.Format("2006-01-02"); days[0].Day != want {
		t.Errorf("wire day = %q, want %q", days[0].Day, want)
	}
	if days[0].HumanCodeLines != 7 {
		t.Errorf("human_code_lines = %d, want 7 (the 40-day-old backfill must not be folded in)", days[0].HumanCodeLines)
	}
}
