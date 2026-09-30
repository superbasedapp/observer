package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/commitlog"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestComposeProjectDetailEmptyProject pins the composition seam
// ComposeProjectDetail is (projectdetail.go) — the same seam both
// handleProjectDetail and `observer project` (cmd/observer/project.go,
// wave W6) call — for a project with no cost/commit/task activity in the
// window: Project.ID must be set from the loaded meta, every list field
// must be a non-nil (possibly empty) slice so a JSON encoding of the
// result never emits `null` for a list, and WindowDays must echo the
// input Days untouched.
func TestComposeProjectDetailEmptyProject(t *testing.T) {
	s, root := newTestServer(t)
	ctx := context.Background()
	st := store.New(s.opts.DB)

	projectID, err := st.ProjectIDForRoot(ctx, root)
	if err != nil {
		t.Fatalf("ProjectIDForRoot: %v", err)
	}
	if projectID == 0 {
		t.Fatalf("newTestServer's seeded project root %q did not resolve to a project id", root)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/project/x", nil)
	since, until, days := projectDetailWindow(req)
	detail, err := ComposeProjectDetail(ctx, st, ProjectDetailInput{
		ProjectID: projectID, Days: days, Since: since, Until: until,
		LinkWindow: s.commitLinkWindow(), CostEngine: s.opts.CostEngine, Taskflow: s.taskflowOptions(),
	})
	if err != nil {
		t.Fatalf("ComposeProjectDetail: %v", err)
	}

	if detail.Project.ID != projectID {
		t.Errorf("Project.ID = %d, want %d", detail.Project.ID, projectID)
	}
	if detail.Project.RootPath != root {
		t.Errorf("Project.RootPath = %q, want %q", detail.Project.RootPath, root)
	}
	if detail.WindowDays != days {
		t.Errorf("WindowDays = %d, want %d (the input Days)", detail.WindowDays, days)
	}

	if detail.Project.Tools == nil {
		t.Error("Project.Tools is nil, want a non-nil (possibly empty) slice")
	}
	if detail.Spend.ByTool == nil {
		t.Error("Spend.ByTool is nil, want a non-nil slice")
	}
	if detail.Spend.ByModel == nil {
		t.Error("Spend.ByModel is nil, want a non-nil slice")
	}
	if detail.Spend.ByDay == nil {
		t.Error("Spend.ByDay is nil, want a non-nil slice")
	}
	if detail.Spend.BySession == nil {
		t.Error("Spend.BySession is nil, want a non-nil slice")
	}
	if detail.ROI == nil {
		t.Error("ROI is nil, want a non-nil slice")
	}
	if len(detail.ROI) == 0 {
		t.Error("ROI is empty, want the fixed set of proxy tiles (every tile is emitted even when Available=false)")
	}
}

// TestComposeProjectDetailUnknownProject pins the not-found contract: a
// project id with no projects row returns an error rather than a
// zero-valued ProjectDetail, so a caller (the CLI) can surface a clear
// message instead of silently printing an empty report.
func TestComposeProjectDetailUnknownProject(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	st := store.New(s.opts.DB)

	_, err := ComposeProjectDetail(ctx, st, ProjectDetailInput{ProjectID: 999999999})
	if err == nil {
		t.Fatal("ComposeProjectDetail with an unknown project id: want an error, got nil")
	}
}

// TestComposeProjectDetailPricesUnrecordedTurns pins the read-time
// pricing rule loadProjectSpend applies: a token_usage row whose
// estimated_cost_usd is 0 (this box's corpus stores 0 on every row and
// prices on read) is priced through the cost engine at its own
// timestamp; a row for a model the engine cannot price is counted in
// unpriced_turns and contributes nothing; a recorded cost > 0 wins over
// the engine. Session cost follows the priced turns.
func TestComposeProjectDetailPricesUnrecordedTurns(t *testing.T) {
	s, _ := newTestServer(t)
	root := t.TempDir()
	ctx := context.Background()
	st := store.New(s.opts.DB)
	base := time.Now().UTC().Add(-2 * time.Hour)
	if _, err := st.Ingest(ctx, []models.ToolEvent{{
		SessionID: "sessP", ProjectRoot: root, Target: "hello", ActionType: models.ActionUserPrompt,
		RawToolInput: "hello", Tool: models.ToolClaudeCode, SourceFile: "/tmp/p.jsonl", SourceEventID: "p1",
		Timestamp: base, Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	projectID, err := st.ProjectIDForRoot(ctx, root)
	if err != nil {
		t.Fatalf("ProjectIDForRoot: %v", err)
	}
	ts := base.Add(time.Minute).Format(time.RFC3339Nano)
	for _, row := range []struct {
		model string
		in    int64
		cost  float64
	}{
		{"claude-opus-4", 1000, 0},        // priced by the engine
		{"no-such-model-xyz", 1000, 0},    // unpriced
		{"no-such-model-xyz", 1000, 0.25}, // recorded cost wins
	} {
		if _, err := s.opts.DB.ExecContext(ctx, `
			INSERT INTO token_usage (session_id, timestamp, tool, model, input_tokens, output_tokens, estimated_cost_usd, source)
			VALUES ('sessP', ?, 'claude-code', ?, ?, 200, ?, 'jsonl')`, ts, row.model, row.in, row.cost); err != nil {
			t.Fatalf("seed token_usage: %v", err)
		}
	}
	engine := cost.NewEngine(config.IntelligenceConfig{})
	p, ok := engine.LookupAt("claude-opus-4", base.Add(time.Minute))
	if !ok {
		t.Fatal("test premise: claude-opus-4 must have a builtin pricing entry")
	}
	want := cost.Compute(p, cost.TokenBundle{Input: 1000, Output: 200}) + 0.25

	got, err := ComposeProjectDetail(ctx, st, ProjectDetailInput{
		ProjectID: projectID, Days: 30, Since: base.Add(-time.Hour), Until: base.Add(time.Hour), CostEngine: engine,
	})
	if err != nil {
		t.Fatalf("ComposeProjectDetail: %v", err)
	}
	if got.Spend.TotalUSD <= 0.25 || got.Spend.TotalUSD != want {
		t.Errorf("spend.total_usd = %v, want %v (engine-priced + recorded)", got.Spend.TotalUSD, want)
	}
	if got.Spend.UnpricedTurns != 1 {
		t.Errorf("spend.unpriced_turns = %d, want 1", got.Spend.UnpricedTurns)
	}
	if len(got.Spend.BySession) != 1 || got.Spend.BySession[0].CostUSD != want {
		t.Errorf("spend.by_session = %+v, want one row at %v", got.Spend.BySession, want)
	}
	if len(got.Spend.ByModel) != 2 {
		t.Errorf("spend.by_model = %+v, want 2 models", got.Spend.ByModel)
	}
}

// TestHandleProjectsSpendMatchesCostEngine pins SOL-F6 of the
// 2026-09-22 arc review end to end: the `/api/projects` LIST spend
// column (handleProjects, priced via cost.Engine.Summary's
// GroupByProject) and the `/api/project/{id}` DETAIL panel's
// Spend.TotalUSD (ComposeProjectDetail -> loadProjectSpend ->
// store.LoadProjectSpendTurns -> cost.Engine.TurnRows) must agree for
// the SAME project and the SAME window — both are now thin exports of
// the identical cost-engine loadRows+priceRow pipeline, not two
// independently-normalized copies (the pre-fix day-bucket loader could
// cross a long-context pricing tier a per-turn price never would, and
// used a different per-session dedup grain than the detail panel).
func TestHandleProjectsSpendMatchesCostEngine(t *testing.T) {
	s, root := newTestServer(t)
	ctx := context.Background()
	st := store.New(s.opts.DB)

	projectID, err := st.ProjectIDForRoot(ctx, root)
	if err != nil {
		t.Fatalf("ProjectIDForRoot: %v", err)
	}
	base := time.Now().UTC().Add(-2 * time.Hour)
	if _, err := s.opts.DB.ExecContext(ctx, `
		INSERT INTO api_turns (session_id, project_id, timestamp, provider, model, input_tokens, output_tokens, cost_usd)
		VALUES ('sess-parity', ?, ?, 'anthropic', 'claude-opus-4', 1000, 200, 1.50)`,
		projectID, base.Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("seed sessions/api_turns: %v", err)
	}
	if _, err := s.opts.DB.ExecContext(ctx, `INSERT INTO sessions (id, project_id, tool, started_at) VALUES ('sess-parity', ?, 'claude-code', ?)`,
		projectID, base.Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("seed session row: %v", err)
	}

	// Detail panel, default (last 30 days) window.
	req := httptest.NewRequest(http.MethodGet, "/api/project/x", nil)
	since, until, days := projectDetailWindow(req)
	detail, err := ComposeProjectDetail(ctx, st, ProjectDetailInput{
		ProjectID: projectID, Days: days, Since: since, Until: until,
		LinkWindow: s.commitLinkWindow(), CostEngine: s.opts.CostEngine, Taskflow: s.taskflowOptions(),
	})
	if err != nil {
		t.Fatalf("ComposeProjectDetail: %v", err)
	}
	if detail.Spend.TotalUSD != 1.50 {
		t.Fatalf("detail Spend.TotalUSD = %v, want 1.50 (test premise)", detail.Spend.TotalUSD)
	}

	// List, the SAME 30-day window handleProjects itself uses.
	listReq := httptest.NewRequest(http.MethodGet, "/api/projects", nil)
	rec := httptest.NewRecorder()
	s.handleProjects(rec, listReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("handleProjects status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Rows []struct {
			ID          int64   `json:"id"`
			SpendUSD30d float64 `json:"spend_usd_30d"`
		} `json:"rows"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode /api/projects: %v (body %s)", err, rec.Body.String())
	}
	var listUSD float64
	var found bool
	for _, row := range resp.Rows {
		if row.ID == projectID {
			listUSD, found = row.SpendUSD30d, true
		}
	}
	if !found {
		t.Fatalf("project %d absent from /api/projects rows: %+v", projectID, resp.Rows)
	}
	if listUSD != detail.Spend.TotalUSD {
		t.Errorf("list spend_usd_30d = %v, detail Spend.TotalUSD = %v — list and detail must agree", listUSD, detail.Spend.TotalUSD)
	}
}

// TestComposeProjectDetailCommitsCountReachableOnly pins SOL-F17 at the
// composition boundary: detail.Commits.Count must apply the SAME
// predicate as projectroi.CountsAsCommit (reachable-only — a merge
// counts, an unreachable commit does not), not the pre-fix
// len(rawCommits) which counted everything project_commits kept
// on-disk for display, including unreachable and merge rows.
func TestComposeProjectDetailCommitsCountReachableOnly(t *testing.T) {
	s, root := newTestServer(t)
	ctx := context.Background()
	st := store.New(s.opts.DB)

	projectID, err := st.ProjectIDForRoot(ctx, root)
	if err != nil {
		t.Fatalf("ProjectIDForRoot: %v", err)
	}
	base := time.Now().UTC().Add(-time.Hour)
	commits := []commitlog.Commit{
		{SHA: "sha-normal", AuthorHash: "abc", AuthoredAt: base, CommittedAt: base, Subject: "fix"},
		{SHA: "sha-merge", AuthorHash: "abc", AuthoredAt: base, CommittedAt: base, Subject: "Merge branch 'x'", IsMerge: true},
		{SHA: "sha-unreachable", AuthorHash: "abc", AuthoredAt: base, CommittedAt: base, Subject: "rebased away"},
	}
	if _, err := st.UpsertCommits(ctx, projectID, commits, base); err != nil {
		t.Fatalf("UpsertCommits: %v", err)
	}
	if _, err := s.opts.DB.ExecContext(ctx, `UPDATE project_commits SET reachable = 0 WHERE project_id = ? AND sha = ?`, projectID, "sha-unreachable"); err != nil {
		t.Fatalf("mark unreachable: %v", err)
	}

	detail, err := ComposeProjectDetail(ctx, st, ProjectDetailInput{
		ProjectID: projectID, Days: 30, Since: base.Add(-time.Hour), Until: base.Add(time.Hour),
		LinkWindow: s.commitLinkWindow(), CostEngine: s.opts.CostEngine, Taskflow: s.taskflowOptions(),
	})
	if err != nil {
		t.Fatalf("ComposeProjectDetail: %v", err)
	}
	if detail.Commits.Count != 2 {
		t.Errorf("Commits.Count = %d, want 2 (the reachable merge counts, the unreachable non-merge does not)", detail.Commits.Count)
	}
}
