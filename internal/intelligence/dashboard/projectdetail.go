package dashboard

import (
	"context"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/loc"
	"github.com/marmutapp/superbased-observer/internal/projectroi"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/taskflow"
	"github.com/marmutapp/superbased-observer/internal/taskreport"
)

// projectdetail.go holds the ONE composition seam for the Projects-page
// detail summary (plan §3.4) — the nine store loads, the
// projectroi.Link/AttributeSpend/Proxies pipeline and the apiProjectDetail
// assembly that GET /api/project/{id} (handleProjectDetail) and
// `observer project` (cmd/observer/project.go, wave W6) both call, so the
// CLI and the dashboard page can never disagree about what a project's
// spend/ROI/commit picture is. Extracted from handleProjectDetail without
// behavior change — see internal/intelligence/dashboard/projects_test.go's
// -run Project tests, which must still pass byte-identically.

// ProjectDetail is the exported alias for the wire shape every
// /api/project/{id} caller already decodes (apiProjectDetail, declared in
// projects.go) — Go permits an exported alias to an unexported type, and
// every field already carries a json tag, so a caller (the CLI) can range
// over it and json.Marshal it without this package renaming anything W3
// shipped.
type ProjectDetail = apiProjectDetail

// ProjectDetailInput is everything ComposeProjectDetail needs beyond the
// store: the project id, the resolved [since, until) window (days is
// carried through only for WindowDays on the response — Since/Until are
// what actually bound every load), the commit-link window
// ([projects].commit_link_window_days, 0 → projectroi.DefaultLinkWindow,
// same fallback Server.commitLinkWindow applies), the cost engine token
// summaries are priced with, and the [tasks] tunables LoadTaskRollup
// needs. A caller that never sets CostEngine gets baked-in pricing (the
// same degrade cost.Engine itself documents); a caller that never sets
// Taskflow gets taskflow's unconfigured zero-value behavior.
type ProjectDetailInput struct {
	ProjectID  int64
	Days       int
	Since      time.Time
	Until      time.Time
	LinkWindow time.Duration
	CostEngine *cost.Engine
	Taskflow   taskflow.Options
}

// ComposeProjectDetail loads every row the Projects-page detail summary
// needs (prompts, AI edits, commits — both the link-shaped and raw
// projections, turns, sessions, tasks, LOC totals, commit-capture state)
// and runs them through internal/projectroi's pure Link → AttributeSpend →
// Proxies pipeline, returning the exact ProjectDetail shape GET
// /api/project/{id} serves. It is the one seam both the dashboard handler
// and the `observer project` CLI command call, per CLAUDE.md's "one seam
// per integration point" — extending or fixing the composition here
// reaches both surfaces at once.
//
// It does NOT check that in.ProjectID names a real project; the caller is
// expected to have resolved that first (the dashboard's requireProject
// 404s before calling this; the CLI's own resolveProjectArg errors out
// first). A project id with a real projects row but zero activity is not
// an error — it renders as the "empty corpus" shape.
func ComposeProjectDetail(ctx context.Context, st *store.Store, in ProjectDetailInput) (ProjectDetail, error) {
	meta, ok, err := st.LoadProjectMeta(ctx, in.ProjectID)
	if err != nil {
		return ProjectDetail{}, fmt.Errorf("dashboard.ComposeProjectDetail: load project meta: %w", err)
	}
	if !ok {
		return ProjectDetail{}, fmt.Errorf("dashboard.ComposeProjectDetail: project %d not found", in.ProjectID)
	}

	since, until, projectID := in.Since, in.Until, in.ProjectID

	prompts, promptsTrunc, err := st.LoadProjectPrompts(ctx, projectID, since, until, promptLinkCap)
	if err != nil {
		return ProjectDetail{}, fmt.Errorf("dashboard.ComposeProjectDetail: load prompts: %w", err)
	}
	edits, editsTrunc, err := st.LoadProjectAIEdits(ctx, projectID, since, until, editLinkCap)
	if err != nil {
		return ProjectDetail{}, fmt.Errorf("dashboard.ComposeProjectDetail: load AI edits: %w", err)
	}
	commits, commitsTrunc, err := st.LoadProjectCommitsForLink(ctx, projectID, since, until, commitLinkCap)
	if err != nil {
		return ProjectDetail{}, fmt.Errorf("dashboard.ComposeProjectDetail: load link commits: %w", err)
	}
	rawCommits, err := st.LoadProjectCommits(ctx, projectID, since, until, commitLinkCap)
	if err != nil {
		return ProjectDetail{}, fmt.Errorf("dashboard.ComposeProjectDetail: load commits: %w", err)
	}
	priced, err := loadProjectSpend(ctx, st, in.CostEngine, projectID, since, until)
	if err != nil {
		return ProjectDetail{}, fmt.Errorf("dashboard.ComposeProjectDetail: load spend: %w", err)
	}
	turns, sessions := priced.Turns, priced.Sessions
	promptCounts, err := st.LoadProjectPromptCounts(ctx, projectID, since, until)
	if err != nil {
		return ProjectDetail{}, fmt.Errorf("dashboard.ComposeProjectDetail: load prompt counts: %w", err)
	}
	tasks, err := st.LoadProjectTasks(ctx, projectID, since, until)
	if err != nil {
		return ProjectDetail{}, fmt.Errorf("dashboard.ComposeProjectDetail: load tasks: %w", err)
	}
	locTotals, err := st.LoadProjectLOCBreakdown(ctx, projectID, since, until)
	aiAdded, aiModified, humanCapture := locTotals.AIAdded, locTotals.AIModified, locTotals.HumanCapture
	if err != nil {
		return ProjectDetail{}, fmt.Errorf("dashboard.ComposeProjectDetail: load LOC totals: %w", err)
	}
	commitCapture, err := st.CommitCaptureState(ctx, projectID)
	if err != nil {
		return ProjectDetail{}, fmt.Errorf("dashboard.ComposeProjectDetail: load commit-capture state: %w", err)
	}

	linkage := projectroi.Link(prompts, edits, commits, projectroi.Options{LinkWindow: in.LinkWindow})
	spend := projectroi.AttributeSpend(linkage, turns, prompts)
	// Task counts come from the SAME taskflow lifecycle rollup the Tasks tab
	// renders (Created / Completed), never from a raw task_items status
	// count, so the Overview KPI, the "spend per completed task" tile and
	// the Tasks tab can never disagree (the 2026-09-22 visual pass showed
	// 21/26 on the KPI against 16 completed on the tab). The rollup's
	// counts are translated into the pure package's Task shape at this
	// boundary; the raw rows are the fallback only when the rollup fails.
	//
	// SOL-F11 (2026-09-22 arc review): when LoadTaskRollup errors the
	// figures fall back to the raw task_items rows with cost 0, and the
	// response says so through Tasks.Available=false - the page renders
	// "unavailable", never "0 tasks".
	var tasksCostUSD float64
	tasksAvailable := false
	if rollup, rerr := taskreport.LoadTaskRollup(ctx, st, in.CostEngine, since, until, projectID, "", "", in.Taskflow); rerr == nil {
		tasksCostUSD = rollup.AttributedSingle.CostUSD
		tasks = tasksFromLifecycleCounts(rollup.Counts.Created, rollup.Counts.Completed)
		tasksAvailable = true
	}
	roi := projectroi.Proxies(projectroi.ProxyInput{
		WindowDays: in.Days, Turns: turns, Sessions: sessions, Linkage: linkage, Spend: spend, Tasks: tasks,
		AIAdded: aiAdded, AIModified: aiModified, HumanCapture: humanCapture,
		CommitCapture: commitCapture, Commits: commits,
		// finding #11: gate proxyUSDPerTaskDone on the SAME rollup-success
		// flag the KPI and the CLI now both honor — never a real-looking
		// figure computed over the raw task_items fallback.
		TasksAvailable: tasksAvailable,
	})

	var totalUSD float64
	for _, t := range turns {
		totalUSD += t.CostUSD
	}

	agg := aggregateByCommit(linkage)
	var aiTouchedCommits, commitCount int
	var withSpendUSD float64
	for _, c := range rawCommits {
		// F17 of the 2026-09-22 arc review: this used to be
		// unconditionally len(rawCommits) — counting unreachable AND
		// merge commits — while the list (store.LoadProjectListExtras)
		// excluded merges too and the ROI proxies (projectroi.CountCommits)
		// excluded neither. projectroi.CountsAsCommit is now the ONE
		// predicate (reachable-only; a merge counts when reachable) all
		// three consult, so this panel, the list and the proxies can
		// never report three different commit counts for the same window.
		if projectroi.CountsAsCommit(projectroi.Commit{Reachable: c.Reachable, IsMerge: c.IsMerge}) {
			commitCount++
		}
		if agg[c.ID] != nil {
			aiTouchedCommits++
		}
		withSpendUSD += spend.ByCommit[c.ID]
	}

	tasksDone := 0
	for _, tk := range tasks {
		if tk.Status == "done" {
			tasksDone++
		}
	}

	detail := apiProjectDetail{
		Project: apiProjectMeta{
			ID: meta.ID, RootPath: meta.RootPath, GitRemote: meta.GitRemote, Name: meta.Name,
			Tools: meta.Tools, FirstSeen: fmtProjectTime(meta.FirstSeen), LastSeen: fmtProjectTime(meta.LastSeen),
		},
		Spend: apiProjectDetailSpend{
			TotalUSD:      totalUSD,
			UnpricedTurns: priced.UnpricedTurns,
			ByTool:        bucketCost(turns, func(t projectroi.Turn) string { return t.Tool }),
			ByModel:       bucketCost(turns, func(t projectroi.Turn) string { return t.Model }),
			ByDay:         bucketCostByDay(turns),
			BySession:     buildBySession(sessions, turns, promptCounts, edits, linkage),
		},
		ROI:        toRoiTiles(roi),
		WindowDays: in.Days,
		Truncated:  promptsTrunc || editsTrunc || commitsTrunc,
	}
	if detail.Truncated {
		stampTruncationCaveat(detail.ROI)
	}
	if detail.Project.Tools == nil {
		detail.Project.Tools = []string{}
	}
	detail.LOC.AIAdded = aiAdded
	detail.LOC.AIModified = aiModified
	detail.LOC.AIComment = locTotals.AIComment
	detail.LOC.AISplit = loc.SplitAuthored(int64(aiAdded+aiModified), int64(locTotals.AIComment))
	detail.LOC.HumanCapture = humanCapture
	detail.Commits.Count = commitCount
	detail.Commits.AITouched = aiTouchedCommits
	detail.Commits.WithSpendUSD = withSpendUSD
	detail.Tasks.Total = len(tasks)
	detail.Tasks.Done = tasksDone
	detail.Tasks.CostUSD = tasksCostUSD
	detail.Tasks.Available = tasksAvailable
	detail.Capture = apiProjectCaptureInfo{Commits: commitCapture, HumanLOC: humanCapture}

	return detail, nil
}

// projectSpend is the priced spend substrate every /api/project/{id}*
// handler and ComposeProjectDetail consume: the window's turns with
// CostUSD RESOLVED (recorded column when > 0, otherwise priced through
// the cost engine at the turn's own timestamp), the window's sessions
// with CostUSD = the sum of their priced turns, and the count of turns
// that could not be priced at all (no recorded cost AND no pricing
// entry for the model) so the page can say so instead of implying
// $0.00 is a real figure.
//
// This box's corpus is the motivating case: token_usage.estimated_cost_usd
// is 0 on every row (cost is stamped at read time by the cost engine),
// so a recorded-column sum shows $0.00 where /api/cost shows thousands.
type projectSpend struct {
	Turns         []projectroi.Turn
	Sessions      []projectroi.Session
	UnpricedTurns int
}

// loadProjectSpend loads one project's turns and sessions in [since,
// until). It is the ONE place a project's dollar figures are resolved
// — every Projects-page surface (detail summary, commits ledger, prompt
// chains, the cost buckets and the CLI) goes through it — and it is
// itself a thin projectroi.Turn/Session conversion over
// store.LoadProjectSpendTurns, which in turn runs the process cost
// engine's OWN per-turn pipeline (cost.Engine.TurnRows: the same
// loadRows union + dedup + pricing /api/cost and `observer cost` use).
//
// Pre-2026-09-22 this function ran a SECOND, parallel implementation of
// the engine's dedup (dedupProjectTurns) and pricing (priceProjectTurn)
// rules, which drifted from the engine's own fixes — no reasoning-aware
// shape key, no session-aggregate reconciliation (droid/goose/crush/
// mistralcode double-counted against their proxy rows), no fast-tier
// lift, no Copilot shadow collapse (SOL-F1..F5 of the 2026-09-22 arc
// review). There is now exactly one owner of "what does this turn
// cost," and the Projects page can never disagree with the Cost page
// about the same turn's price.
func loadProjectSpend(ctx context.Context, st *store.Store, engine *cost.Engine, projectID int64, since, until time.Time) (projectSpend, error) {
	if engine == nil {
		// Degrade to baked-in pricing rather than panic — see
		// ProjectDetailInput's doc comment ("a caller that never sets
		// CostEngine gets baked-in pricing").
		engine = cost.NewEngine(config.IntelligenceConfig{})
	}
	turns, unpriced, err := st.LoadProjectSpendTurns(ctx, engine, projectID, since, until)
	if err != nil {
		return projectSpend{}, err
	}
	sessions, err := st.LoadProjectSessions(ctx, projectID, since, until)
	if err != nil {
		return projectSpend{}, err
	}
	out := projectSpend{Turns: turns, Sessions: sessions, UnpricedTurns: unpriced}
	costBySession := make(map[string]float64, len(sessions))
	for _, t := range out.Turns {
		if t.SessionID != "" {
			costBySession[t.SessionID] += t.CostUSD
		}
	}
	for i := range out.Sessions {
		out.Sessions[i].CostUSD = costBySession[out.Sessions[i].ID]
	}
	return out, nil
}

// truncationCaveat is appended to every linkage-dependent ROI tile when a
// request-time cap was hit, so a tile computed over a partial window
// never reads as a complete one (the 2026-09-22 live corpus: with the
// old 500-prompt cap, "sessions with no linked commit" swallowed 95% of
// spend purely because 28 of the 30 days' prompts were outside the cap).
const truncationCaveat = " Row caps were hit for this window (newest 10,000 prompts / 100,000 AI edits / 5,000 commits), so this figure covers only those rows."

// linkageDependentTiles are the projectroi proxies whose value depends on
// the prompt -> edit -> commit linkage; spend-only tiles (cache-read share)
// are complete regardless of the caps.
var linkageDependentTiles = map[string]bool{
	"usd_per_reached_ai_line": true, "ai_files_reached_share": true, "sessions_no_commit_usd": true,
	"usd_per_commit": true, "usd_per_task_done": false, "prompts_per_commit": true, "turns_per_commit": true,
}

func stampTruncationCaveat(tiles []apiProjectRoiTile) {
	for i := range tiles {
		if linkageDependentTiles[tiles[i].Key] {
			tiles[i].Caveat += truncationCaveat
		}
	}
}

// tasksFromLifecycleCounts translates the taskflow rollup's lifecycle
// counts into the plain Task rows internal/projectroi.Proxies counts
// (Status "done" per completed task, "" otherwise) — the boundary where
// the taskflow vocabulary becomes the pure package's.
func tasksFromLifecycleCounts(created, completed int) []projectroi.Task {
	if created < completed {
		created = completed
	}
	out := make([]projectroi.Task, 0, created)
	for i := 0; i < completed; i++ {
		out = append(out, projectroi.Task{Status: "done"})
	}
	for i := completed; i < created; i++ {
		out = append(out, projectroi.Task{Status: "open"})
	}
	return out
}
