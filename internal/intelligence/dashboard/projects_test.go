package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/commitlog"
	"github.com/marmutapp/superbased-observer/internal/intelligence/alignment"
	"github.com/marmutapp/superbased-observer/internal/loc"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestAPIProjectsEmptyCorpusByteIdentical pins R7: a project with
// sessions but no cost/loc/commit rows renders on /api/projects with
// EXACTLY the pre-arc legacy fields (root_path/session_count/
// action_count/last_seen) plus the one genuinely new always-present
// field (id, needed to open the detail panel at all) — every other
// additive field (spend_usd_30d/ai_code_lines_30d/commits_30d/
// last_commit_at/capture) is entirely ABSENT, never a fabricated zero.
func TestAPIProjectsEmptyCorpusByteIdentical(t *testing.T) {
	s, root := newTestServer(t)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/projects", nil))
	if rr.Code != 200 {
		t.Fatalf("status %d body=%s", rr.Code, rr.Body.String())
	}

	var got map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	rows, _ := got["rows"].([]any)
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1: %s", len(rows), rr.Body.String())
	}
	row, _ := rows[0].(map[string]any)

	if row["root_path"] != root {
		t.Errorf("root_path = %v, want %q", row["root_path"], root)
	}
	if row["session_count"] != float64(1) {
		t.Errorf("session_count = %v, want 1", row["session_count"])
	}
	if row["action_count"] != float64(1) {
		t.Errorf("action_count = %v, want 1", row["action_count"])
	}
	lastSeen, ok := row["last_seen"].(string)
	if !ok || lastSeen == "" {
		t.Errorf("last_seen missing/empty: %v", row["last_seen"])
	}
	id, ok := row["id"].(float64)
	if !ok || id <= 0 {
		t.Errorf("id missing/invalid: %v", row["id"])
	}

	wantRow := map[string]any{
		"root_path": root, "session_count": float64(1), "action_count": float64(1),
		"last_seen": lastSeen, "id": id,
	}
	if len(row) != len(wantRow) {
		t.Fatalf("row has %d fields %v, want exactly %v", len(row), row, wantRow)
	}
	for k, v := range wantRow {
		if row[k] != v {
			t.Errorf("field %q = %v, want %v", k, row[k], v)
		}
	}
	for _, leaked := range []string{"spend_usd_30d", "ai_code_lines_30d", "commits_30d", "last_commit_at", "capture"} {
		if _, present := row[leaked]; present {
			t.Errorf("untouched project unexpectedly carries %q: %v", leaked, row[leaked])
		}
	}
}

// seedProjectsFixture builds one project with: two prompts in one
// session (p1 "add login button" whose AI edit to a.go a later commit
// carries -> status committed; p2 "unrelated ask" whose AI edit to
// b.go NO commit ever carries -> status uncommitted), one proxied turn
// ($3.50, inside p1's turn window), one completed task, and a scanned
// commit-capture state so capture.commits reports "ok".
func seedProjectsFixture(t *testing.T) (s *Server, root string, projectID, p1ID, p2ID int64) {
	t.Helper()
	s, _ = newTestServer(t)
	root = t.TempDir()
	ctx := context.Background()
	st := store.New(s.opts.DB)
	base := time.Now().UTC().Add(-2 * time.Hour)

	mkEvent := func(actionType, target, rawInput, eventID string, ts time.Time) models.ToolEvent {
		return models.ToolEvent{
			SessionID: "sess1", ProjectRoot: root, Target: target, ActionType: actionType,
			RawToolInput: rawInput, RawToolName: "Edit", Tool: models.ToolClaudeCode,
			SourceFile: "/tmp/s.jsonl", SourceEventID: eventID, Timestamp: ts, Success: true,
		}
	}
	events := []models.ToolEvent{
		mkEvent(models.ActionUserPrompt, "add login button", "add login button", "p1", base),
		mkEvent(models.ActionEditFile, root+"/a.go",
			`{"file_path":"`+root+`/a.go","old_string":"a := 1","new_string":"a := 2"}`, "e1", base.Add(time.Minute)),
		mkEvent(models.ActionUserPrompt, "unrelated ask", "unrelated ask", "p2", base.Add(30*time.Minute)),
		mkEvent(models.ActionEditFile, root+"/b.go",
			`{"file_path":"`+root+`/b.go","old_string":"b := 1","new_string":"b := 2"}`, "e2", base.Add(31*time.Minute)),
	}
	if _, err := st.Ingest(ctx, events, nil, store.IngestOptions{}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	projectID, err := st.ProjectIDForRoot(ctx, root)
	if err != nil {
		t.Fatalf("ProjectIDForRoot: %v", err)
	}

	prompts, _, err := st.LoadProjectPrompts(ctx, projectID, base.Add(-time.Hour), base.Add(24*time.Hour), 500)
	if err != nil {
		t.Fatalf("LoadProjectPrompts: %v", err)
	}
	for _, p := range prompts {
		switch p.Preview {
		case "add login button":
			p1ID = p.ActionID
		case "unrelated ask":
			p2ID = p.ActionID
		}
	}
	if p1ID == 0 || p2ID == 0 {
		t.Fatalf("could not resolve seeded prompt ids: %+v", prompts)
	}

	if _, err := s.opts.DB.ExecContext(ctx, `
		INSERT INTO api_turns (session_id, project_id, timestamp, provider, model, input_tokens, output_tokens, cost_usd)
		VALUES ('sess1', ?, ?, 'anthropic', 'claude-opus-4', 1000, 200, 3.50)`,
		projectID, base.Add(2*time.Minute).Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("seed api_turns: %v", err)
	}
	if _, err := s.opts.DB.ExecContext(ctx, `
		INSERT INTO task_items (session_id, tool, key, key_kind, status, first_seen_at, last_seen_at)
		VALUES ('sess1', 'claude-code', 't1', 'native_id', 'completed', ?, ?)`,
		base.Format(time.RFC3339Nano), base.Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("seed task_items: %v", err)
	}

	commits := []commitlog.Commit{
		{
			SHA: "sha1", AuthorHash: "author1", AuthoredAt: base.Add(10 * time.Minute), CommittedAt: base.Add(10 * time.Minute),
			Subject: "feat: login button",
			Files:   []commitlog.CommitFile{{RelPath: "a.go", PathHash: loc.PathHash(root, root+"/a.go"), Added: 5}},
		},
	}
	if _, err := st.UpsertCommits(ctx, projectID, commits, base.Add(15*time.Minute)); err != nil {
		t.Fatalf("UpsertCommits: %v", err)
	}
	if err := st.SetCommitScanState(ctx, store.ScanState{
		ProjectID: projectID, LastSHA: "sha1", LastCommittedAt: base.Add(10 * time.Minute), LastScanAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("SetCommitScanState: %v", err)
	}

	return s, root, projectID, p1ID, p2ID
}

func TestAPIProjectDetail(t *testing.T) {
	s, root, projectID, _, _ := seedProjectsFixture(t)

	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/project/2000000000", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("unknown project id: status %d, want 404", rr.Code)
	}

	rr = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/project/"+itoa64(projectID), nil)
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status %d body=%s", rr.Code, rr.Body.String())
	}

	var got apiProjectDetail
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v; body=%s", err, rr.Body.String())
	}
	if got.Project.RootPath != root {
		t.Errorf("project.root_path = %q, want %q", got.Project.RootPath, root)
	}
	if got.Project.ID != projectID {
		t.Errorf("project.id = %d, want %d", got.Project.ID, projectID)
	}
	if got.Spend.TotalUSD != 3.50 {
		t.Errorf("spend.total_usd = %v, want 3.50", got.Spend.TotalUSD)
	}
	if len(got.Spend.BySession) != 1 || got.Spend.BySession[0].CostUSD != 3.50 {
		t.Errorf("spend.by_session = %+v, want one row at 3.50", got.Spend.BySession)
	}
	if got.Commits.Count != 1 {
		t.Errorf("commits.count = %d, want 1", got.Commits.Count)
	}
	if got.Commits.AITouched != 1 {
		t.Errorf("commits.ai_touched = %d, want 1", got.Commits.AITouched)
	}
	if got.Commits.WithSpendUSD != 3.50 {
		t.Errorf("commits.with_spend_usd = %v, want 3.50 (p1's whole turn window reached sha1)", got.Commits.WithSpendUSD)
	}
	// Task counts follow the taskflow lifecycle rollup the Tasks tab renders:
	// the fixture's task carries status "completed" but never transitioned
	// through in_progress, which the rollup classifies as NEVER ACTIVATED,
	// not completed — so done is 0, exactly what the Tasks tab says.
	if got.Tasks.Total != 1 || got.Tasks.Done != 0 {
		t.Errorf("tasks = %+v, want total=1 done=0 (rollup lifecycle: never activated)", got.Tasks)
	}
	if got.Capture.Commits != "ok" {
		t.Errorf("capture.commits = %q, want ok", got.Capture.Commits)
	}
	if got.WindowDays != 30 {
		t.Errorf("window_days = %d, want 30 (default)", got.WindowDays)
	}
	if len(got.ROI) != 8 {
		t.Fatalf("roi tiles = %d, want 8", len(got.ROI))
	}
	for _, tile := range got.ROI {
		if tile.Formula == "" {
			t.Errorf("roi tile %q has no formula (R5: every metric must carry one)", tile.Key)
		}
		if tile.Unit == "ratio" {
			t.Errorf("roi tile %q unit = ratio, want pct (the web tile only formats usd|pct|...)", tile.Key)
		}
	}
}

func TestAPIProjectCommits(t *testing.T) {
	s, _, projectID, p1ID, _ := seedProjectsFixture(t)

	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/project/"+itoa64(projectID)+"/commits", nil))
	if rr.Code != 200 {
		t.Fatalf("status %d body=%s", rr.Code, rr.Body.String())
	}
	var got struct {
		Rows []apiProjectCommitRow `json:"rows"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Rows) != 1 {
		t.Fatalf("commits rows = %d, want 1: %+v", len(got.Rows), got.Rows)
	}
	c := got.Rows[0]
	if c.SHA != "sha1" || c.Subject != "feat: login button" {
		t.Errorf("commit = %+v, want sha1/feat: login button", c)
	}
	if c.AIFiles != 1 || c.AILines == 0 {
		t.Errorf("commit AI aggregation = %+v, want ai_files=1 ai_lines>0", c)
	}
	if c.SpendUSD != 3.50 {
		t.Errorf("commit spend_usd = %v, want 3.50", c.SpendUSD)
	}
	if len(c.Prompts) != 1 || c.Prompts[0].ActionID != p1ID {
		t.Errorf("commit prompts = %+v, want exactly p1 (%d)", c.Prompts, p1ID)
	}
}

func TestAPIProjectPrompts(t *testing.T) {
	s, _, projectID, p1ID, p2ID := seedProjectsFixture(t)

	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/project/"+itoa64(projectID)+"/prompts", nil))
	if rr.Code != 200 {
		t.Fatalf("status %d body=%s", rr.Code, rr.Body.String())
	}
	var got struct {
		Rows []apiProjectPromptRow `json:"rows"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Rows) != 2 {
		t.Fatalf("prompt rows = %d, want 2: %+v", len(got.Rows), got.Rows)
	}
	byID := map[int64]apiProjectPromptRow{}
	for _, r := range got.Rows {
		byID[r.ActionID] = r
	}
	p1 := byID[p1ID]
	if p1.Status != "committed" {
		t.Errorf("p1 status = %q, want committed", p1.Status)
	}
	if len(p1.Commits) != 1 || p1.Commits[0].SHA != "sha1" {
		t.Errorf("p1 commits = %+v, want [sha1]", p1.Commits)
	}
	if p1.Alignment != nil {
		t.Errorf("p1 alignment = %+v, want nil (never graded)", p1.Alignment)
	}
	if p1.GradeAvailable == nil || p1.GradeAvailable.Judge || p1.GradeAvailable.Cloud {
		t.Errorf("p1 grade_available = %+v, want judge=false cloud=false (neither wired in this test server)", p1.GradeAvailable)
	}

	p2 := byID[p2ID]
	if p2.Status != "uncommitted" {
		t.Errorf("p2 status = %q, want uncommitted", p2.Status)
	}
	if len(p2.Commits) != 0 {
		t.Errorf("p2 commits = %+v, want none", p2.Commits)
	}
}

func TestAPIProjectCost(t *testing.T) {
	s, _, projectID, _, _ := seedProjectsFixture(t)

	get := func(by string) []apiProjectCostBucketRow {
		t.Helper()
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/project/"+itoa64(projectID)+"/cost?by="+by, nil))
		if rr.Code != 200 {
			t.Fatalf("by=%s: status %d body=%s", by, rr.Code, rr.Body.String())
		}
		var got struct {
			Rows []apiProjectCostBucketRow `json:"rows"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
			t.Fatalf("by=%s: decode: %v", by, err)
		}
		return got.Rows
	}

	if rows := get("session"); len(rows) != 1 || rows[0].CostUSD != 3.50 {
		t.Errorf("by=session = %+v, want one row at 3.50", rows)
	}
	if rows := get("tool"); len(rows) != 1 || rows[0].Key != "claude-code" || rows[0].CostUSD != 3.50 {
		t.Errorf("by=tool = %+v, want claude-code/3.50", rows)
	}
	if rows := get("model"); len(rows) != 1 || rows[0].Key != "claude-opus-4" {
		t.Errorf("by=model = %+v, want claude-opus-4", rows)
	}
	if rows := get("day"); len(rows) != 1 || rows[0].CostUSD != 3.50 {
		t.Errorf("by=day = %+v, want one day at 3.50", rows)
	}
	if rows := get("commit"); len(rows) != 1 || rows[0].Key != "sha1" || rows[0].CostUSD != 3.50 {
		t.Errorf("by=commit = %+v, want sha1/3.50", rows)
	}
	if rows := get("task"); len(rows) != 1 || rows[0].Key != "t1" {
		t.Errorf("by=task = %+v, want one row keyed t1", rows)
	}

	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/project/"+itoa64(projectID)+"/cost?by=bogus", nil))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("by=bogus: status %d, want 400", rr.Code)
	}
}

// TestAPIProjectCostUnpricedCoverage pins 2026-09-22 rework finding S5:
// the day/session/task cost buckets must carry the SAME unpriced-turn
// coverage signal apiProjectCostBucketRow already exposed for tool/model
// (UnpricedTurns), instead of silently discarding it — a bucket total
// that mixes a real $3.50 priced turn with an unpriced turn (no
// recorded cost, no pricing-table entry for its model) must still read
// $3.50 (never invent a price) AND say so via unpriced_turns, never a
// bare total indistinguishable from "fully priced".
func TestAPIProjectCostUnpricedCoverage(t *testing.T) {
	s, _, projectID, _, _ := seedProjectsFixture(t)
	ctx := context.Background()
	base := time.Now().UTC().Add(-2 * time.Hour)

	// A second turn in the SAME session, SAME task window, with an
	// unknown model and no recorded cost — priceRow resolves this as
	// unpriced (no recorded cost_usd, no pricing-table entry).
	if _, err := s.opts.DB.ExecContext(ctx, `
		INSERT INTO api_turns (session_id, project_id, timestamp, provider, model, input_tokens, output_tokens)
		VALUES ('sess1', ?, ?, 'anthropic', 'totally-unknown-model-2026', 500, 100)`,
		projectID, base.Add(3*time.Minute).Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("seed unpriced api_turns: %v", err)
	}

	get := func(by string) []apiProjectCostBucketRow {
		t.Helper()
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/project/"+itoa64(projectID)+"/cost?by="+by, nil))
		if rr.Code != 200 {
			t.Fatalf("by=%s: status %d body=%s", by, rr.Code, rr.Body.String())
		}
		var got struct {
			Rows []apiProjectCostBucketRow `json:"rows"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
			t.Fatalf("by=%s: decode: %v", by, err)
		}
		return got.Rows
	}

	if rows := get("day"); len(rows) != 1 || rows[0].CostUSD != 3.50 || rows[0].UnpricedTurns != 1 {
		t.Errorf("by=day = %+v, want one day at 3.50 with unpriced_turns=1", rows)
	}
	if rows := get("session"); len(rows) != 1 || rows[0].CostUSD != 3.50 || rows[0].UnpricedTurns != 1 {
		t.Errorf("by=session = %+v, want one session at 3.50 with unpriced_turns=1", rows)
	}
	// 2026-09-22 review round 4 finding #9: commit buckets used to omit
	// unpriced-turn coverage entirely (no field on apiProjectCostBucketRow
	// was ever set for by=commit). The seeded unpriced turn at base+3min
	// falls in p1's [base, base+30min) window, the SAME window
	// TestAPIProjectDetail already established reaches commit sha1
	// wholesale — so sha1's bucket must now say so.
	if rows := get("commit"); len(rows) != 1 || rows[0].Key != "sha1" || rows[0].CostUSD != 3.50 || rows[0].UnpricedTurns != 1 {
		t.Errorf("by=commit = %+v, want sha1/3.50 with unpriced_turns=1", rows)
	}
}

// TestHandleProjectsSpendNilWhenAllUnpriced pins 2026-09-22 rework
// finding S5's list-level half: a project whose ONLY window activity is
// entirely unpriced (no recorded cost, no pricing-table entry for its
// model) must render spend_usd_30d ABSENT — the same honesty contract
// TestAPIProjectsEmptyCorpusByteIdentical already pins for a project
// with NO activity at all. Pre-fix, `PricedTurnCount == 0` was never
// checked, so this case serialized a misleading exact "$0.00" instead of
// "-".
func TestHandleProjectsSpendNilWhenAllUnpriced(t *testing.T) {
	s, root := newTestServer(t)
	ctx := context.Background()
	st := store.New(s.opts.DB)

	projectID, err := st.ProjectIDForRoot(ctx, root)
	if err != nil {
		t.Fatalf("ProjectIDForRoot: %v", err)
	}
	base := time.Now().UTC().Add(-2 * time.Hour)
	if _, err := s.opts.DB.ExecContext(ctx, `INSERT INTO sessions (id, project_id, tool, started_at) VALUES ('sess-unpriced', ?, 'claude-code', ?)`,
		projectID, base.Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("seed session row: %v", err)
	}
	if _, err := s.opts.DB.ExecContext(ctx, `
		INSERT INTO api_turns (session_id, project_id, timestamp, provider, model, input_tokens, output_tokens)
		VALUES ('sess-unpriced', ?, ?, 'anthropic', 'totally-unknown-model-2026', 500, 100)`,
		projectID, base.Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("seed unpriced api_turns: %v", err)
	}

	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/projects", nil))
	if rr.Code != 200 {
		t.Fatalf("status %d body=%s", rr.Code, rr.Body.String())
	}
	var got struct {
		Rows []map[string]any `json:"rows"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	var row map[string]any
	for _, r := range got.Rows {
		if id, ok := r["id"].(float64); ok && int64(id) == projectID {
			row = r
		}
	}
	if row == nil {
		t.Fatalf("project %d absent from /api/projects rows: %+v", projectID, got.Rows)
	}
	if _, present := row["spend_usd_30d"]; present {
		t.Errorf("spend_usd_30d = %v, want ABSENT (PricedTurnCount==0, never a fabricated $0.00)", row["spend_usd_30d"])
	}
	if unpriced, _ := row["spend_unpriced_turns_30d"].(float64); unpriced != 1 {
		t.Errorf("spend_unpriced_turns_30d = %v, want 1", row["spend_unpriced_turns_30d"])
	}
}

// TestAPIProjectGrade covers the not_available cloud path (honest
// reason, no network) and a fake judge path (success -> persisted ->
// visible on a follow-up /prompts read).
func TestAPIProjectGrade(t *testing.T) {
	s, _, projectID, p1ID, _ := seedProjectsFixture(t)

	// Judge disabled by default (Options.JudgeGrade nil in a test server).
	body := strings.NewReader(`{"tier":"judge"}`)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/project/"+itoa64(projectID)+"/prompts/"+itoa64(p1ID)+"/grade", body)
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("judge (disabled): status %d body=%s", rr.Code, rr.Body.String())
	}
	var disabled struct {
		Status string `json:"status"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &disabled); err != nil {
		t.Fatal(err)
	}
	if disabled.Status != "not_available" || disabled.Reason == "" {
		t.Errorf("judge (disabled) = %+v, want not_available with a reason", disabled)
	}

	// Cloud: honest not_available, no hosted kind.
	s.opts.CloudGradeAvailability = func() (bool, string) { return false, "hosted kind not deployed" }
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/project/"+itoa64(projectID)+"/prompts/"+itoa64(p1ID)+"/grade", strings.NewReader(`{"tier":"cloud"}`))
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("cloud: status %d body=%s", rr.Code, rr.Body.String())
	}
	var cloudResp struct {
		Status string `json:"status"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &cloudResp); err != nil {
		t.Fatal(err)
	}
	if cloudResp.Status != "not_available" || cloudResp.Reason != "hosted kind not deployed" {
		t.Errorf("cloud = %+v, want not_available/\"hosted kind not deployed\"", cloudResp)
	}

	// Judge enabled via a fake JudgeGrade closure.
	s.opts.JudgeGrade = func(ctx context.Context, in alignment.Input) (alignment.Result, string, error) {
		if in.PromptText == "" {
			t.Errorf("JudgeGrade called with empty PromptText")
		}
		return alignment.Result{Delivered: []string{"login button"}, Confidence: 0.9, Notes: "looks right"}, "fake-judge-model", nil
	}
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/project/"+itoa64(projectID)+"/prompts/"+itoa64(p1ID)+"/grade", strings.NewReader(`{"tier":"judge"}`))
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("judge (enabled): status %d body=%s", rr.Code, rr.Body.String())
	}
	var okResp struct {
		Status    string                    `json:"status"`
		Alignment apiProjectPromptAlignment `json:"alignment"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &okResp); err != nil {
		t.Fatal(err)
	}
	if okResp.Status != "ok" || okResp.Alignment.Tier != "judge" || okResp.Alignment.Model != "fake-judge-model" {
		t.Fatalf("judge (enabled) = %+v, want ok/judge/fake-judge-model", okResp)
	}
	if len(okResp.Alignment.Delivered) != 1 || okResp.Alignment.Delivered[0] != "login button" {
		t.Errorf("alignment.delivered = %v, want [login button]", okResp.Alignment.Delivered)
	}

	// The grade must now be visible on GET /prompts.
	rr = httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/project/"+itoa64(projectID)+"/prompts", nil))
	var promptsResp struct {
		Rows []apiProjectPromptRow `json:"rows"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &promptsResp); err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, r := range promptsResp.Rows {
		if r.ActionID == p1ID {
			found = true
			if r.Alignment == nil || r.Alignment.Tier != "judge" {
				t.Errorf("p1 alignment after grading = %+v, want tier=judge", r.Alignment)
			}
		}
	}
	if !found {
		t.Fatalf("p1 missing from /prompts after grading")
	}

	// Unknown tier -> 400.
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/project/"+itoa64(projectID)+"/prompts/"+itoa64(p1ID)+"/grade", strings.NewReader(`{"tier":"bogus"}`))
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("bogus tier: status %d, want 400", rr.Code)
	}

	// GET instead of POST -> 405.
	rr = httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/project/"+itoa64(projectID)+"/prompts/"+itoa64(p1ID)+"/grade", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET grade: status %d, want 405", rr.Code)
	}
}

func itoa64(id int64) string {
	return strconv.FormatInt(id, 10)
}

// --- SOL-F10 regression coverage (2026-09-22 rework) ---
//
// Before this fix, /commits, /prompts and /cost?by=commit discarded the
// `truncated` bool internal/store/projectroi.go's capped loaders
// (LoadProjectPrompts/LoadProjectAIEdits/LoadProjectCommitsForLink)
// already returned, so a tab could present partial prompt-to-commit
// linkage as complete with no signal at all — OverviewTab's own
// `truncated` banner only ever covered GET /api/project/{id} itself.

// withCap temporarily overrides one of the package-level request-time
// caps (promptLinkCap/editLinkCap/commitLinkCap), restoring the original
// value via t.Cleanup. These are `var`, not `const`, specifically so a
// test can force a cap hit deterministically without seeding thousands
// of rows — see their doc comment in projects.go. None of these tests
// run t.Parallel(), so mutating a package-level var for the duration of
// one test is safe.
func withCap(t *testing.T, cap *int, value int) {
	t.Helper()
	orig := *cap
	*cap = value
	t.Cleanup(func() { *cap = orig })
}

// TestAPIProjectCommitsTruncationMeta forces promptLinkCap below the
// fixture's 2 seeded prompts and checks /commits carries the resulting
// apiTruncationMeta — and that the response still returns real rows
// rather than going blank.
func TestAPIProjectCommitsTruncationMeta(t *testing.T) {
	s, _, projectID, _, _ := seedProjectsFixture(t)
	withCap(t, &promptLinkCap, 1) // fixture seeds 2 prompts -> forces truncation

	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/project/"+itoa64(projectID)+"/commits", nil))
	if rr.Code != 200 {
		t.Fatalf("status %d body=%s", rr.Code, rr.Body.String())
	}
	var got struct {
		Rows            []apiProjectCommitRow `json:"rows"`
		Truncated       bool                  `json:"truncated"`
		TruncatedInputs []string              `json:"truncated_inputs"`
		Affects         []string              `json:"affects"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Truncated {
		t.Fatalf("truncated = false, want true (promptLinkCap forced to 1 against 2 seeded prompts): %s", rr.Body.String())
	}
	if len(got.TruncatedInputs) != 1 || got.TruncatedInputs[0] != "prompts" {
		t.Errorf("truncated_inputs = %v, want [prompts]", got.TruncatedInputs)
	}
	if len(got.Affects) == 0 {
		t.Errorf("affects is empty, want the fields this truncation puts in doubt")
	}
	if len(got.Rows) != 1 {
		t.Fatalf("commits rows = %d, want 1 (truncation must not blank the response)", len(got.Rows))
	}
}

// TestAPIProjectPromptsTruncationMetaAndStatusUncertain forces
// editLinkCap below the fixture's 2 seeded AI edits and checks /prompts
// carries the resulting apiTruncationMeta AND that every returned row
// carries status_uncertain=true — a capped edits/commits input can make
// ANY row's status wrong, not just the row whose own edit got cut, so
// every row must carry the caveat. The status enum itself must stay one
// of the five known values (never a fabricated "unknown").
func TestAPIProjectPromptsTruncationMetaAndStatusUncertain(t *testing.T) {
	s, _, projectID, p1ID, p2ID := seedProjectsFixture(t)
	withCap(t, &editLinkCap, 1) // fixture seeds 2 AI edits -> forces truncation

	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/project/"+itoa64(projectID)+"/prompts", nil))
	if rr.Code != 200 {
		t.Fatalf("status %d body=%s", rr.Code, rr.Body.String())
	}
	var got struct {
		Rows            []apiProjectPromptRow `json:"rows"`
		Truncated       bool                  `json:"truncated"`
		TruncatedInputs []string              `json:"truncated_inputs"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Truncated {
		t.Fatalf("truncated = false, want true (editLinkCap forced to 1 against 2 seeded edits): %s", rr.Body.String())
	}
	if len(got.TruncatedInputs) != 1 || got.TruncatedInputs[0] != "edits" {
		t.Errorf("truncated_inputs = %v, want [edits]", got.TruncatedInputs)
	}
	if len(got.Rows) != 2 {
		t.Fatalf("prompt rows = %d, want 2 (truncation must not blank the response)", len(got.Rows))
	}
	for _, r := range got.Rows {
		if !r.StatusUncertain {
			t.Errorf("action %d (session %s): status_uncertain = false, want true — a capped edits input can make ANY row's status wrong, every row must carry the caveat (p1=%d p2=%d)",
				r.ActionID, r.SessionID, p1ID, p2ID)
		}
		switch r.Status {
		case "committed", "partial", "uncommitted", "superseded", "no_edits":
		default:
			t.Errorf("action %d: status = %q, not one of the closed enum values", r.ActionID, r.Status)
		}
	}
}

// TestAPIProjectCostByCommitTruncationMeta checks GET /cost?by=commit
// carries apiTruncationMeta when its own capped loaders truncate, and
// that a DIFFERENT `by` value (which never touches the linkage pipeline)
// never carries truncation meta even with the caps still overridden.
func TestAPIProjectCostByCommitTruncationMeta(t *testing.T) {
	s, _, projectID, _, _ := seedProjectsFixture(t)
	withCap(t, &promptLinkCap, 1)

	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/project/"+itoa64(projectID)+"/cost?by=commit", nil))
	if rr.Code != 200 {
		t.Fatalf("status %d body=%s", rr.Code, rr.Body.String())
	}
	var got struct {
		Rows      []apiProjectCostBucketRow `json:"rows"`
		Truncated bool                      `json:"truncated"`
		Affects   []string                  `json:"affects"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Truncated {
		t.Fatalf("by=commit: truncated = false, want true: %s", rr.Body.String())
	}
	if len(got.Affects) != 1 || got.Affects[0] != "cost_usd" {
		t.Errorf("by=commit: affects = %v, want [cost_usd]", got.Affects)
	}

	rr = httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/project/"+itoa64(projectID)+"/cost?by=session", nil))
	if rr.Code != 200 {
		t.Fatalf("by=session: status %d body=%s", rr.Code, rr.Body.String())
	}
	var raw map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if _, present := raw["truncated"]; present {
		t.Errorf("by=session unexpectedly carries a truncated field: %v", raw["truncated"])
	}
}

// TestAPIProjectSecondaryEndpointsOmitTruncationMetaWhenUntruncated pins
// that apiTruncationMeta's zero value serializes to NOTHING: with the
// fixture's 2 prompts / 2 edits / 1 commit all well under the default
// caps, none of the three secondary endpoints may carry `truncated`,
// `truncated_inputs` or `affects` at all — not even a fabricated
// false/[].
func TestAPIProjectSecondaryEndpointsOmitTruncationMetaWhenUntruncated(t *testing.T) {
	s, _, projectID, _, _ := seedProjectsFixture(t)

	for _, path := range []string{"/commits", "/prompts", "/cost?by=commit"} {
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/project/"+itoa64(projectID)+path, nil))
		if rr.Code != 200 {
			t.Fatalf("%s: status %d body=%s", path, rr.Code, rr.Body.String())
		}
		var raw map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		for _, key := range []string{"truncated", "truncated_inputs", "affects"} {
			if _, present := raw[key]; present {
				t.Errorf("%s: response unexpectedly carries %q = %v (should be entirely absent)", path, key, raw[key])
			}
		}
	}
}

// --- SOL-P2 regression coverage (2026-09-22 rework, round 2) ---
//
// The round-1 SOL-F10 fix above wired the LINK caps (promptLinkCap/
// editLinkCap/commitLinkCap, feeding projectroi.Link) into
// apiTruncationMeta but left the OUTPUT row caps (commitRowsCap on
// /commits, promptRowsCap on /prompts) still silently discarded:
// handleProjectCommits detected `len(rawCommits) > limit` only to slice
// it away, and handleProjectPrompts threw away LoadProjectPrompts' own
// truncated bool via `_`. A 501-row window returned exactly 500 rows
// with no signal at all that more existed. These two tests force each
// OUTPUT cap independently (with the LINK caps left at their generous
// defaults) and check the response carries a distinctly-named
// "commit_rows"/"prompt_rows" signal — never the LINK cap's own
// "commits"/"edits" names, which the web side's describeTruncation
// (web/src/components/projectdetail/TruncationBanner.tsx) renders with
// different copy (rows missing entirely vs. a shown row's figures may
// be an undercount).

// TestAPIProjectCommitsRowCapTruncation forces commitRowsCap below the
// window's actual commit count (2, after seeding one past the fixture's
// lone "sha1") and checks /commits' apiTruncationMeta names the OUTPUT
// cap distinctly from the LINK cap.
func TestAPIProjectCommitsRowCapTruncation(t *testing.T) {
	s, root, projectID, _, _ := seedProjectsFixture(t)
	ctx := context.Background()
	st := store.New(s.opts.DB)
	base := time.Now().UTC().Add(-2 * time.Hour)

	commits := []commitlog.Commit{
		{
			SHA: "sha2", AuthorHash: "author2", AuthoredAt: base.Add(20 * time.Minute), CommittedAt: base.Add(20 * time.Minute),
			Subject: "fix: second commit",
			Files:   []commitlog.CommitFile{{RelPath: "b.go", PathHash: loc.PathHash(root, root+"/b.go"), Added: 3}},
		},
	}
	if _, err := st.UpsertCommits(ctx, projectID, commits, base.Add(25*time.Minute)); err != nil {
		t.Fatalf("UpsertCommits: %v", err)
	}

	withCap(t, &commitRowsCap, 1) // window now holds 2 commits -> forces the OUTPUT cap

	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/project/"+itoa64(projectID)+"/commits", nil))
	if rr.Code != 200 {
		t.Fatalf("status %d body=%s", rr.Code, rr.Body.String())
	}
	var got struct {
		Rows            []apiProjectCommitRow `json:"rows"`
		Truncated       bool                  `json:"truncated"`
		TruncatedInputs []string              `json:"truncated_inputs"`
		Affects         []string              `json:"affects"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Truncated {
		t.Fatalf("truncated = false, want true (commitRowsCap forced to 1 against 2 seeded commits): %s", rr.Body.String())
	}
	if len(got.Rows) != 1 {
		t.Fatalf("commits rows = %d, want 1 (the forced cap)", len(got.Rows))
	}
	foundRowCap := false
	for _, in := range got.TruncatedInputs {
		if in == "commit_rows" {
			foundRowCap = true
		}
		if in == "commits" {
			t.Errorf("truncated_inputs unexpectedly names the LINK cap %q — the LINK caps were left at their defaults, only the OUTPUT cap fired here", in)
		}
	}
	if !foundRowCap {
		t.Errorf("truncated_inputs = %v, want to include \"commit_rows\"", got.TruncatedInputs)
	}
	foundAffects := false
	for _, a := range got.Affects {
		if a == "commit_rows" {
			foundAffects = true
		}
	}
	if !foundAffects {
		t.Errorf("affects = %v, want to include \"commit_rows\"", got.Affects)
	}
}

// TestAPIProjectPromptsRowCapTruncation forces promptRowsCap below the
// fixture's 2 seeded prompts and checks /prompts' apiTruncationMeta
// names the OUTPUT cap distinctly from the LINK caps.
func TestAPIProjectPromptsRowCapTruncation(t *testing.T) {
	s, _, projectID, _, _ := seedProjectsFixture(t)
	withCap(t, &promptRowsCap, 1) // fixture seeds 2 prompts -> forces the OUTPUT cap

	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/project/"+itoa64(projectID)+"/prompts", nil))
	if rr.Code != 200 {
		t.Fatalf("status %d body=%s", rr.Code, rr.Body.String())
	}
	var got struct {
		Rows            []apiProjectPromptRow `json:"rows"`
		Truncated       bool                  `json:"truncated"`
		TruncatedInputs []string              `json:"truncated_inputs"`
		Affects         []string              `json:"affects"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Truncated {
		t.Fatalf("truncated = false, want true (promptRowsCap forced to 1 against 2 seeded prompts): %s", rr.Body.String())
	}
	if len(got.Rows) != 1 {
		t.Fatalf("prompt rows = %d, want 1 (the forced cap)", len(got.Rows))
	}
	foundRowCap := false
	for _, in := range got.TruncatedInputs {
		if in == "prompt_rows" {
			foundRowCap = true
		}
		if in == "edits" || in == "commits" {
			t.Errorf("truncated_inputs unexpectedly names a LINK cap %q — the LINK caps were left at their defaults, only the OUTPUT cap fired here", in)
		}
	}
	if !foundRowCap {
		t.Errorf("truncated_inputs = %v, want to include \"prompt_rows\"", got.TruncatedInputs)
	}
	foundAffects := false
	for _, a := range got.Affects {
		if a == "prompt_rows" {
			foundAffects = true
		}
	}
	if !foundAffects {
		t.Errorf("affects = %v, want to include \"prompt_rows\"", got.Affects)
	}
}

// TestAPIProjectSurfacesCarryCodeCommentSplit pins the code-vs-comment
// split (internal/loc.SplitAuthored) on every Projects-page surface that
// shows AI lines: the list row, the detail LOC block, the by-session spend
// rows and the prompt chains - each split built from that surface's own
// code/comment counts, never a second derivation.
func TestAPIProjectSurfacesCarryCodeCommentSplit(t *testing.T) {
	s, projectID := seedCoOwnedFixture(t)

	get := func(path string, v any) {
		t.Helper()
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: status %d body=%s", path, rr.Code, rr.Body.String())
		}
		if err := json.Unmarshal(rr.Body.Bytes(), v); err != nil {
			t.Fatalf("%s: decode: %v", path, err)
		}
	}
	want := func(what string, got loc.AuthoredSplit, code, comment int) {
		t.Helper()
		if exp := loc.SplitAuthored(int64(code), int64(comment)); got.CodeLines != exp.CodeLines || got.CommentLines != exp.CommentLines ||
			(got.CommentShare == nil) != (exp.CommentShare == nil) {
			t.Errorf("%s split = %+v, want SplitAuthored(%d, %d)", what, got, code, comment)
		}
	}

	var detail apiProjectDetail
	get("/api/project/"+itoa64(projectID), &detail)
	if detail.LOC.AIComment == 0 {
		t.Errorf("detail loc.ai_comment = 0, want the fixture's comment line")
	}
	want("detail loc", detail.LOC.AISplit, detail.LOC.AIAdded+detail.LOC.AIModified, detail.LOC.AIComment)
	var sawComment bool
	for _, r := range detail.Spend.BySession {
		if r.AISplit.CodeLines != int64(r.AILines) {
			t.Errorf("by_session %s ai_split.code_lines = %d, want ai_lines %d", r.ID, r.AISplit.CodeLines, r.AILines)
		}
		if r.ID == "sBig" && r.AISplit.CommentLines > 0 {
			sawComment = true
		}
	}
	if !sawComment {
		t.Errorf("by_session rows = %+v, want sBig to carry its comment line", detail.Spend.BySession)
	}

	var prompts apiProjectPromptsResponse
	get("/api/project/"+itoa64(projectID)+"/prompts", &prompts)
	for _, p := range prompts.Rows {
		want("prompt "+p.Preview, p.Edits.Split, p.Edits.Added+p.Edits.Modified, p.Edits.Comment)
	}

	var list struct {
		Rows []struct {
			ID             int64              `json:"id"`
			AICodeLines30d int                `json:"ai_code_lines_30d"`
			AISplit30d     *loc.AuthoredSplit `json:"ai_split_30d"`
		} `json:"rows"`
	}
	get("/api/projects", &list)
	found := false
	for _, r := range list.Rows {
		if r.ID != projectID {
			continue
		}
		found = true
		if r.AISplit30d == nil {
			t.Fatalf("list ai_split_30d missing for a project with AI lines")
		}
		if r.AISplit30d.CodeLines != int64(r.AICodeLines30d) || r.AISplit30d.CommentLines == 0 {
			t.Errorf("list split = %+v, code must equal ai_code_lines_30d %d and comments > 0", r.AISplit30d, r.AICodeLines30d)
		}
	}
	if !found {
		t.Errorf("project %d absent from /api/projects", projectID)
	}
}
