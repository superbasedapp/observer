package dashboard

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cursorusage"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/requestclass"
	"github.com/marmutapp/superbased-observer/internal/sessiongauge"
	"github.com/marmutapp/superbased-observer/internal/sessionmsg"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// handleSessionDetail handles /api/session/<id>. Returns session metadata
// plus aggregate roll-ups (action counts, tool breakdown, token totals,
// per-model usage). Action list is NOT inlined — the frontend should
// follow-up with /api/actions?session_id=<id>&page=… for the paginated
// stream.
//
//nolint:gocyclo // moved unchanged out of dashboard.go, which .golangci.yml exempts from gocyclo; splitting this handler is INTEL-02.
func (s *Server) handleSessionDetail(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/session/")
	// Sub-route: /api/session/<id>/messages → per-message timeline
	// (one row per upstream Anthropic message). Returns the deduped
	// per-turn breakdown with grouped tool calls. Used by the
	// session modal's Messages panel.
	if strings.HasSuffix(id, "/messages") {
		id = strings.TrimSuffix(id, "/messages")
		s.handleSessionMessages(w, r, id)
		return
	}
	// Sub-route: /api/session/<id>/cache/forecast → model-switch
	// cost forecaster (spec §14.2). Pure read-side math over the
	// existing tables — P from cache_entries, S/gaps from
	// cache_events, O/T/fast from api_turns, rates from cost.Table.
	// Returns the headline switch_cost + break_even_turns + per-
	// turn delta + closed-set warning list. Must precede the
	// /cache match below since "/cache/forecast" suffixes
	// "/cache" too.
	if strings.HasSuffix(id, "/cache/forecast") {
		id = strings.TrimSuffix(id, "/cache/forecast")
		s.handleSessionCacheForecast(w, r, id)
		return
	}
	// Sub-route: /api/session/<id>/cache → cachetrack panel
	// payload (spec §13 / C13). Tier + entries + events +
	// efficiency rollup + timeline (baseline rolled to a single
	// count entry; anomalies itemized). Drives SessionDetailPanel's
	// Cache tab.
	if strings.HasSuffix(id, "/cache") {
		id = strings.TrimSuffix(id, "/cache")
		s.handleSessionCache(w, r, id)
		return
	}
	// Sub-route: /api/session/<id>/loc → lines-of-code authorship for the
	// session (AI main vs sidechain vs editor-reported human, code vs
	// docs vs config, with the confidence and overwrite caveats attached
	// to the numbers). A read over node-local file_changes.
	if strings.HasSuffix(id, "/loc") {
		id = strings.TrimSuffix(id, "/loc")
		s.handleSessionLOC(w, r, id)
		return
	}
	// Sub-route: /api/session/<id>/commits → the git commits this session's
	// prompts reached, and whether this session OWNS each one
	// (docs/projects-page.md "Commit ownership", sessioncommits.go). A read
	// over node-local actions/file_changes/project_commit* rows, classed
	// exactly like /loc above.
	if strings.HasSuffix(id, "/commits") {
		id = strings.TrimSuffix(id, "/commits")
		s.handleSessionCommits(w, r, id)
		return
	}
	// Sub-route: /api/session/<id>/delivery -> where each of those commits
	// went (pushed, in a PR, landed on the default branch; delivery.go). A
	// read over node-local delivery rows, classed exactly like /commits.
	if strings.HasSuffix(id, "/delivery") {
		id = strings.TrimSuffix(id, "/delivery")
		s.handleSessionDelivery(w, r, id)
		return
	}
	// Sub-route: /api/session/<id>/processes → the Process Observability
	// session tree (docs/process-observability.md §13.1). Attributed
	// fork/exec/exit lineage with the spawning command per subtree. Empty
	// unless [observer.process] is enabled; drives the Processes drawer.
	// Sub-route: /api/session/<id>/processes/summary → the process capture
	// summary (capture counters, budget, service roots, top rollups, findings
	// count) with an ETag: what the System tab polls (processcapture.go, plan
	// §9.3). Must precede the /processes match below.
	if strings.HasSuffix(id, "/processes/summary") {
		id = strings.TrimSuffix(id, "/processes/summary")
		s.handleSessionProcessSummary(w, r, id)
		return
	}
	// /processes takes the window parameters from, to, limit and since and
	// returns the newest `limit` rows by default, never the whole history.
	if strings.HasSuffix(id, "/processes") {
		id = strings.TrimSuffix(id, "/processes")
		s.handleSessionProcesses(w, r, id)
		return
	}
	// Sub-route: /api/session/<id>/metrics?bucket=<duration> → the plottable
	// sibling of /processes: the same per-process metric_samples_json rings,
	// but bucketed onto a common time grid, DIFFERENTIATED (the cpu/disk
	// counters are cumulative) and aggregated across the whole attributed
	// subtree. Drives the Session Cockpit's live CPU / RSS / Disk charts.
	// Read-only — the correlation write passes stay on /processes.
	if strings.HasSuffix(id, "/metrics") {
		id = strings.TrimSuffix(id, "/metrics")
		s.handleSessionMetrics(w, r, id)
		return
	}
	// Sub-route: /api/session/<id>/network → lightweight network egress event
	// list for the session. Body excerpts are fetched explicitly through
	// /api/process/network/<event_id>.
	if strings.HasSuffix(id, "/network") {
		id = strings.TrimSuffix(id, "/network")
		s.handleSessionNetwork(w, r, id)
		return
	}
	// Sub-route: /api/session/<id>/subagents → per-sub-agent summaries for
	// sessions whose sub-agent activity rides the parent's session row
	// flagged is_sidechain (claude-code model, migration 010). Codex child
	// sessions surface through lineage instead (children[] below).
	if strings.HasSuffix(id, "/subagents") {
		id = strings.TrimSuffix(id, "/subagents")
		s.handleSessionSubagents(w, r, id)
		return
	}
	// Sub-route: /api/session/<id>/guard → the session-scoped guard
	// verdict feed (hook R-1xx deny/ask/flag events) the Messages tab
	// interleaves into its timeline (sessionguard.go). Read-only, no new
	// SQL — reuses store.LoadGuardEventsForSession.
	if strings.HasSuffix(id, "/guard") {
		id = strings.TrimSuffix(id, "/guard")
		s.handleSessionGuardEvents(w, r, id)
		return
	}
	// Sub-route: /api/session/<id>/mcp-calls → the session's MCP calls the
	// node relay recorded, each correlated to its action / turn / prompt
	// with an honest confidence (Agent Access P11(a), sessionmcp.go).
	if strings.HasSuffix(id, "/mcp-calls") {
		id = strings.TrimSuffix(id, "/mcp-calls")
		s.handleSessionMCPCalls(w, r, id)
		return
	}
	// Sub-route: /api/session/<id>/raw-events → on-demand source JSONL row
	// browser. Re-reads local source files; nothing is persisted.
	if strings.HasSuffix(id, "/raw-events") {
		id = strings.TrimSuffix(id, "/raw-events")
		s.handleSessionRawEvents(w, r, id)
		return
	}
	// Sub-route: /api/session/<id>/handoff/estimate → session-handoff
	// carry-mode price table + fork-picker boundaries (dry run, nothing
	// written). Must precede the /handoff match below.
	if strings.HasSuffix(id, "/handoff/estimate") {
		id = strings.TrimSuffix(id, "/handoff/estimate")
		s.handleSessionHandoffEstimate(w, r, id)
		return
	}
	// Sub-route: /api/session/<id>/handoff → perform the handoff (POST):
	// writes HANDOFF-<shortid>.md + one node-local handoffs row.
	if strings.HasSuffix(id, "/handoff") {
		id = strings.TrimSuffix(id, "/handoff")
		s.handleSessionHandoffCreate(w, r, id)
		return
	}
	// Sub-route: /api/session/<id>/launch → start the tool in the embedded
	// web terminal (POST). Mints an opaque session handle; the browser then
	// opens GET /ws/launch/<handle> to drive the PTY. Gated by the
	// LaunchManager seam (503 when the launcher is disabled).
	if strings.HasSuffix(id, "/launch") {
		id = strings.TrimSuffix(id, "/launch")
		s.handleSessionLaunch(w, r, id)
		return
	}
	// Sub-route: /api/session/<id>/resume → NATIVE resume (POST): spawn the
	// tool's own resume mechanism (claude `--resume <id>`, codex `resume <id>`)
	// in a fresh embedded terminal so the real prior transcript reopens
	// (session-attach design Phase 3). 409 when the tool has no grounded native
	// resume (the Continue-in… handoff-fork is the fallback). Classified Execute
	// via sessionSubRouteCapabilities, like /launch.
	if strings.HasSuffix(id, "/resume") {
		id = strings.TrimSuffix(id, "/resume")
		s.handleSessionResume(w, r, id)
		return
	}
	// Sub-route: /api/session/<id>/predict → the Next-Message Cost &
	// Limit Predictor (docs/plans/next-message-cost-predictor-plan-...).
	// Cost estimate is pure read-side math over token_usage; the limit
	// gauge is proxy-gated (Phase C capture) and renders "needs proxy"
	// until snapshots exist.
	if strings.HasSuffix(id, "/predict") {
		id = strings.TrimSuffix(id, "/predict")
		s.handleSessionPredict(w, r, id)
		return
	}
	// Sub-route: /api/session/<id>/tasks → the Phase-2 session-level
	// task/todo/plan tracking report (docs/task-tracking.md "Phase 2").
	// Per-task tokens/cost/elapsed/actions attributed via
	// taskflow.Attributor, priced through the same cost-ladder pattern
	// as live.go. Read-only; the calm empty state (has_tasks=false) is
	// the majority case.
	if strings.HasSuffix(id, "/tasks") {
		id = strings.TrimSuffix(id, "/tasks")
		s.handleSessionTasks(w, r, id)
		return
	}
	// Sub-route: /api/session/<id>/org-intel → the org-served Cloud
	// Intelligence result the node last pulled back for this session
	// (org-served-cloud-intelligence plan §3.5, W8b). A read over the
	// NODE-LOCAL org_intel_cache; the honest empty (enriched=false) is the
	// ordinary state for a node whose org has not enabled enrichment.
	if strings.HasSuffix(id, "/org-intel") {
		id = strings.TrimSuffix(id, "/org-intel")
		s.handleSessionOrgIntel(w, r, id)
		return
	}
	// Sub-route: /api/session/<id>/verbosity → the Output Composition
	// (Verbosity) card. Read-side: visible narrative/artifact bytes
	// segmented from assistant text + authored code (writes + shell
	// commands) from actions.content_bytes (migration 054).
	// Sub-route: /api/session/<id>/tags → session classification mutation
	// (POST): add/remove tags, toggle the favorite star, set the note. Execute
	// via sessionSubRouteCapabilities, like /launch and /resume.
	if strings.HasSuffix(id, "/tags") {
		id = strings.TrimSuffix(id, "/tags")
		s.handleSessionTags(w, r, id)
		return
	}
	// Sub-route: /api/session/<id>/quality → the persisted spec §15.2
	// quality score (GET) or score-now (POST) for the Quality card
	// (sessionquality.go).
	if strings.HasSuffix(id, "/quality") {
		id = strings.TrimSuffix(id, "/quality")
		s.handleSessionQuality(w, r, id)
		return
	}
	if strings.HasSuffix(id, "/verbosity") {
		id = strings.TrimSuffix(id, "/verbosity")
		s.handleSessionVerbosity(w, r, id)
		return
	}
	if id == "" {
		http.Error(w, "missing session id", http.StatusBadRequest)
		return
	}
	type modelBucket struct {
		Model             string  `json:"model"`
		Input             int64   `json:"input"`
		Output            int64   `json:"output"`
		CacheRead         int64   `json:"cache_read"`
		CacheCreation     int64   `json:"cache_creation"`
		Reasoning         int64   `json:"reasoning,omitempty"`
		WebSearchRequests int64   `json:"web_search_requests,omitempty"`
		TurnCount         int64   `json:"turn_count"`
		CostUSD           float64 `json:"cost_usd"`
		AICostUSD         float64 `json:"ai_cost_usd"`
		ToolCostUSD       float64 `json:"tool_cost_usd"`
		// Per-bucket AICost components (v1.6.13) — sums equal AICostUSD.
		// Feed the session-detail Models Used panel's cost-by-bucket
		// stacked bar. Zero values stay in the response so the frontend
		// can render a 4-segment bar uniformly even for cache-only models.
		InputCostUSD         float64 `json:"input_cost_usd"`
		OutputCostUSD        float64 `json:"output_cost_usd"`
		CacheReadCostUSD     float64 `json:"cache_read_cost_usd"`
		CacheCreationCostUSD float64 `json:"cache_creation_cost_usd"`
	}
	// lineageChild is one spawned (forked/subagent) session in the
	// lineage children list (migration 069; opencode included since the
	// 2026-08-21 parent_id linkage). Token/cost/action rollups let the
	// LineageBanner show what each sub-agent session cost without
	// navigating into it. Emitted as [] not null.
	type lineageChild struct {
		ID           string `json:"id"`
		ThreadSource string `json:"thread_source,omitempty"`
		StartedAt    string `json:"started_at"`
		// Rollups over the child's own rows (omitempty so a fork with no
		// usage yet renders exactly as before).
		InputTokens  int64   `json:"input_tokens,omitempty"`
		OutputTokens int64   `json:"output_tokens,omitempty"`
		CostUSD      float64 `json:"cost_usd,omitempty"`
		ActionCount  int64   `json:"action_count,omitempty"`
	}
	type sessionDetail struct {
		ID        string  `json:"id"`
		Tool      string  `json:"tool"`
		Project   string  `json:"project"`
		Model     string  `json:"model,omitempty"`
		StartedAt string  `json:"started_at"`
		EndedAt   *string `json:"ended_at,omitempty"`
		// LastActivityAt is COALESCE(ended_at, MAX(actions.timestamp)) — the
		// real end of activity for both closed and open/never-closed
		// sessions. The frontend uses it for the Elapsed figure so a session
		// that stopped without a clean ended_at (rollup never finalized)
		// shows start→last-activity instead of start→now (the 583h bug).
		// Mirrors the sessions-list endpoint's COALESCE (see the list query).
		// Empty only when the session has neither ended_at nor any action.
		LastActivityAt string `json:"last_activity_at,omitempty"`
		TotalActions   int    `json:"total_actions"`
		SuccessActions int    `json:"success_actions"`
		FailureActions int    `json:"failure_actions"`
		// SidechainActionCount is the inline sub-agent activity volume
		// (migration 010 model: sub-agents share the parent's session row,
		// flagged is_sidechain). Drives the LineageBanner's sidechain note
		// and the System tab's Sub-agents section.
		SidechainActionCount int      `json:"sidechain_action_count"`
		QualityScore         *float64 `json:"quality_score,omitempty"`
		ErrorRate            *float64 `json:"error_rate,omitempty"`
		RedundancyRatio      *float64 `json:"redundancy_ratio,omitempty"`
		// Spec §14.1 freshness/stale-read split — populated only
		// when the session has cache_events (Tier 3 / pre-backfill
		// sessions leave these nil, no fake zeros).
		StaleReadsWasteful      *int             `json:"stale_reads_wasteful,omitempty"`
		StaleReadsNecessary     *int             `json:"stale_reads_necessary,omitempty"`
		RedundancyRatioWasteful *float64         `json:"redundancy_ratio_wasteful,omitempty"`
		Tokens                  map[string]int64 `json:"tokens"`
		// TokenUsageAvailable distinguishes captured zero usage from no usage rows.
		TokenUsageAvailable bool `json:"token_usage_available"`
		// TurnCount / ProxyTurnCount are sessionmsg.SumContributions' turn
		// counts behind the tokens map: every usage row that survived the
		// proxy/transcript twin fold, and the proxy-observed subset. The
		// org drawer reports the same two numbers from the same rule, so the
		// Tokens tile on both dashboards can name its sources identically
		// (MCP audit #4b, 2026-09-27).
		TurnCount      int64 `json:"turn_count"`
		ProxyTurnCount int64 `json:"proxy_turn_count"`
		// ContextBudgetTokens + TokensNote are the honest fallback for a
		// session with NO captured token usage. Hooks and native files can
		// omit usage even when an agent did real work. ContextBudgetTokens is the carried context
		// budget (the prompt_context section counts — part of a turn's input
		// but never billed on their own), surfaced as an ESTIMATE separate
		// from cost_usd; TokensNote explains why the billed figure is empty.
		// Both omitted when the session has real billed usage.
		ContextBudgetTokens int64  `json:"context_budget_tokens,omitempty"`
		TokensNote          string `json:"tokens_note,omitempty"`
		// ContextGauge is the context-window gauge (used = the running cache
		// prefix over the counted turns; ceiling = the session's reported
		// budget, else the model's catalog context window), derived by the
		// shared pure internal/sessiongauge.Context so the org session drawer
		// reports the same numbers (lane F-WIRE). A nil ratio is unknown.
		ContextGauge sessiongauge.ContextGauge `json:"context_gauge"`
		// RequestClassSplit splits the session's counted proxy turns by the
		// client-declared request class (api_turns.request_class, agent
		// migration 144: main | subagent | workflow | compaction |
		// auxiliary) through the shared pure internal/requestclass.Summarize,
		// so the org session drawer reports the same split (lane G-WIRE2).
		// Omitted when the session has no counted proxy turn; Classified
		// false when none of them carried a class.
		RequestClassSplit *requestclass.Split `json:"request_class_split,omitempty"`
		// PerModel breaks the deduped tokens + cost out by model so the
		// session detail modal shows haiku and opus separately when a
		// session uses both (Claude Code's main vs sub-agent split, etc.).
		PerModel []modelBucket `json:"per_model"`
		// CostUSD is the legacy total; AICostUSD + ToolCostUSD split
		// the same number so callers can render API spend vs tool
		// fees separately. Total == AI + Tool always.
		CostUSD       float64        `json:"cost_usd"`
		AICostUSD     float64        `json:"ai_cost_usd"`
		ToolCostUSD   float64        `json:"tool_cost_usd"`
		ToolBreakdown []actionBucket `json:"tool_breakdown"`
		// CacheSummary is the C15 cost-view cache annotation —
		// a compact glance-view of cache health for this session
		// (tier, event/hit/write/rewrite counts, token rollup,
		// ratio). Sits next to PerModel + ToolBreakdown so the
		// session detail modal shows API spend, tool spend, and
		// cache efficiency side by side. The full Cache tab
		// continues to load /api/session/<id>/cache for the
		// timeline + entries detail.
		CacheSummary *SessionCacheAnnotation `json:"cache_summary,omitempty"`
		// Codex fork/subagent lineage (migration 069). ThreadSource is
		// "subagent" for a spawned subagent, "user" for a normal/user-fork
		// session (empty/nil for non-codex tools). ForkedFromID non-empty =
		// forked/continued from that codex thread id; ParentInDB reports
		// whether a session row exists for it. Children are the sessions
		// spawned from THIS session (always [] not null so the UI can map
		// unconditionally).
		ForkedFromID   string         `json:"forked_from_id,omitempty"`
		ParentThreadID string         `json:"parent_thread_id,omitempty"`
		ThreadSource   string         `json:"thread_source,omitempty"`
		ParentInDB     bool           `json:"parent_in_db"`
		Children       []lineageChild `json:"children"`
		// Surface / SurfaceHost are the capture-surface attribution
		// (migration 107): the normalized kind (cli | ide | desktop |
		// sdk | web) + the concrete host token ("vscode", "cursor",
		// "claude-desktop", ...). Both omitted when no adapter stamped
		// one — the frontend treats absence as "unknown", never as
		// "cli". Additive; frontend rendering is a follow-up.
		Surface     string `json:"surface,omitempty"`
		SurfaceHost string `json:"surface_host,omitempty"`
		// ToolVersion is the captured tool/CLI version (migration 125,
		// NODE-LOCAL): the free-form semver an adapter read from disk.
		// Omitted when unstamped — the frontend treats absence as
		// "unknown", never fabricates a version.
		ToolVersion string `json:"tool_version,omitempty"`
		// ToolVersionLast is the latest build seen in the session
		// (migration 162), equal to ToolVersion when no upgrade was seen.
		// When the two differ the session was upgraded mid-session.
		ToolVersionLast string `json:"tool_version_last,omitempty"`
		// ExecutionLocation / VendorSessionRef: where the session's agent
		// ran and the vendor's second native session id (migration 240,
		// cloud-agents arc). Omitted when unstamped (= unknown, never
		// "local"); the list rows carry the same two fields.
		ExecutionLocation string `json:"execution_location,omitempty"`
		VendorSessionRef  string `json:"vendor_session_ref,omitempty"`
		// Resume declares how a CLOSED session on this tool can be reopened
		// (session-attach design Phase 3): kind "native" (grounded
		// ResumeNative → the Resume button POSTs /resume), "handoff" (no native
		// resume but launchable → the Continue-in… fork), or "none". Derived
		// from the integration registry by capability SHAPE. Always present.
		Resume sessionResumeInfo `json:"resume"`
		// Session classification (plan §4): the tags this session carries, the
		// favorite star, and the full note text (the list endpoint ships only a
		// has_note flag). Tags is always [] not null so the frontend can map
		// unconditionally, like Children above.
		Tags     []string `json:"tags"`
		Favorite bool     `json:"favorite"`
		Note     string   `json:"note,omitempty"`
		Rating   int      `json:"rating,omitempty"`
	}

	var d sessionDetail
	d.ID = id
	var endedAt sql.NullString
	var q, er, rr sql.NullFloat64
	var rrWasteful sql.NullFloat64
	var stWasteful, stNecessary sql.NullInt64
	var model sql.NullString
	if err := s.db().QueryRowContext(
		r.Context(),
		`SELECT s.tool, COALESCE(p.root_path, ''), s.model, s.started_at,
		        s.ended_at, s.quality_score, s.error_rate, s.redundancy_ratio,
		        s.stale_reads_wasteful, s.stale_reads_necessary, s.redundancy_ratio_wasteful
		 FROM sessions s LEFT JOIN projects p ON p.id = s.project_id
		 WHERE s.id = ?`, id,
	).Scan(&d.Tool, &d.Project, &model, &d.StartedAt, &endedAt, &q, &er, &rr,
		&stWasteful, &stNecessary, &rrWasteful); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.NotFound(w, r)
			return
		}
		writeErr(w, err)
		return
	}
	if model.Valid {
		d.Model = model.String
	}
	if endedAt.Valid {
		v := endedAt.String
		d.EndedAt = &v
	}
	if q.Valid {
		v := q.Float64
		d.QualityScore = &v
	}
	if er.Valid {
		v := er.Float64
		d.ErrorRate = &v
	}
	if rr.Valid {
		v := rr.Float64
		d.RedundancyRatio = &v
	}
	if stWasteful.Valid {
		v := int(stWasteful.Int64)
		d.StaleReadsWasteful = &v
	}
	if stNecessary.Valid {
		v := int(stNecessary.Int64)
		d.StaleReadsNecessary = &v
	}
	if rrWasteful.Valid {
		v := rrWasteful.Float64
		d.RedundancyRatioWasteful = &v
	}

	// Action aggregates and tool breakdown. COALESCE the SUMs: a session
	// whose actions were all pruned by retention but whose token_usage rows
	// survive (token_usage isn't pruned) has zero matching rows here, and
	// SUM over an empty set is NULL — scanning that into int fails ("NULL to
	// int is unsupported") and 500s the whole endpoint. This became routine
	// once the FK-787 retention fix let actions actually prune; the detail
	// view must still render (tokens/model/cost) for such sessions. COUNT(*)
	// is never NULL.
	var maxActionTs sql.NullString
	if err := s.db().QueryRowContext(
		r.Context(),
		`SELECT COUNT(*),
		        COALESCE(SUM(CASE WHEN success = 0 THEN 0 ELSE 1 END), 0),
		        COALESCE(SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END), 0),
		        MAX(timestamp),
		        COALESCE(SUM(CASE WHEN is_sidechain = 1 THEN 1 ELSE 0 END), 0)
		 FROM actions WHERE session_id = ?`, id,
	).Scan(&d.TotalActions, &d.SuccessActions, &d.FailureActions, &maxActionTs,
		&d.SidechainActionCount); err != nil {
		writeErr(w, err)
		return
	}
	// last_activity_at = ended_at when the session was cleanly closed, else
	// the last action's timestamp. Drives the frontend Elapsed figure so a
	// never-closed session doesn't measure start→now.
	switch {
	case endedAt.Valid && endedAt.String != "":
		d.LastActivityAt = endedAt.String
	case maxActionTs.Valid:
		d.LastActivityAt = maxActionTs.String
	}
	brRows, err := s.db().QueryContext(r.Context(),
		`SELECT action_type, COUNT(*),
		        SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END)
		 FROM actions WHERE session_id = ?
		 GROUP BY action_type
		 ORDER BY COUNT(*) DESC`, id)
	if err != nil {
		writeErr(w, err)
		return
	}
	defer brRows.Close()
	for brRows.Next() {
		var ab actionBucket
		if err := brRows.Scan(&ab.ActionType, &ab.Count, &ab.Failures); err != nil {
			writeErr(w, err)
			return
		}
		d.ToolBreakdown = append(d.ToolBreakdown, ab)
	}
	if d.ToolBreakdown == nil {
		d.ToolBreakdown = []actionBucket{}
	}

	// C15 cache annotation. Best-effort: a query failure leaves
	// CacheSummary nil and the modal hides the cache pill row.
	// Nil-summary also when the session has no cache_events
	// (pre-cachetrack history, non-Anthropic provider).
	if summary, err := loadSessionCacheAnnotation(r.Context(), s.db(), id); err == nil && summary != nil {
		d.CacheSummary = summary
	}

	// Token totals + per-model breakdown come from the SAME shared
	// pipeline the Messages tab and the org's per-session rollup use:
	// the three thin ordered loaders (loadMessageProxyRows /
	// loadMessageTokenRows) feeding sessionmsg.Derive's one claim-once
	// twin-fold + Copilot-family shadow-row pairing (finding #1, 2026-09-22
	// review round 4). This endpoint used to run its OWN second SQL-side
	// dedup engine here (a blanket "drop every JSONL row matching ANY
	// proxy shape" NOT EXISTS, vs. Derive's one-to-one closest-match
	// claim-once assignment) — one proxy row plus two equal-shape JSONL
	// rows collapsed to one row here but stayed two in Messages/org, and
	// this endpoint's Copilot shadow-row exclusion ignored ids/distance/
	// 1h-cache/reasoning/web-search entirely (PairShadowRows applies all
	// of them). Reusing the SAME loaders + Derive here — rather than a
	// fourth ad hoc query — makes Detail's totals structurally unable to
	// diverge from what Messages/org show for the identical session.
	//
	// Per-contribution pricing (no SQL GROUP BY): a Row's Contributions
	// are the individual raw proxy/token rows Derive folded into it,
	// still separately priceable — pricing the merged Bundle once would
	// falsely apply the cost engine's long-context threshold to a message
	// whose individual underlying turns never crossed it. See
	// sessionmsg.Row.Contributions' doc comment and
	// TestAPISessionMessages_LongContextPerTurn (the Messages handler's
	// existing regression test for this exact rule).
	sessionModel := d.Model
	d.ContextGauge = s.sessionContextGauge(r.Context(), id, sessionModel)
	// A load error degrades to no split (omitted), never a failed detail
	// page - the split is a breakdown of figures the page already carries.
	if split, err := store.New(s.db()).LoadSessionRequestClassSplit(r.Context(), id); err == nil {
		d.RequestClassSplit = split
	}
	proxyRows, err := loadMessageProxyRows(r.Context(), s.db(), id, sessionModel)
	if err != nil {
		writeErr(w, err)
		return
	}
	tokenRows, err := loadMessageTokenRows(r.Context(), s.db(), id, sessionModel, d.Tool)
	if err != nil {
		writeErr(w, err)
		return
	}
	// A legacy pre-fallback row carrying none of request_id/message_id/
	// source_event_id/turn_id is no longer this endpoint's own problem to
	// solve: sessionmsg.Derive itself now synthesizes a collision-safe
	// internal key for such a row (Row.Keyless=true) instead of dropping
	// it, so it contributes to the totals below exactly like every other
	// row — and, critically, the SAME way in the Messages tab and the
	// org's SessionMessageMetrics, which call the identical Derive
	// function. Review round 5 finding #7: this endpoint used to patch
	// proxyRows/tokenRows with a LOCAL "legacy-…-turn:N" id right here
	// before calling Derive — invisible to every other caller, so Detail
	// alone counted the row while Messages/org silently dropped it. See
	// sessionmsg.Derive's doc comment for the shared fix.
	detailCaps := store.NodeSessionCaps(d.Tool)
	detailRows := sessionmsg.Derive(sessionmsg.DeriveInput{
		ProxyRows:         proxyRows,
		TokenRows:         tokenRows,
		Mode:              sessionmsg.RollupTurn,
		ShadowCapable:     detailCaps.ShadowCapable,
		ReasoningDisjoint: detailCaps.ReasoningDisjoint,
		SessionCumulative: detailCaps.SessionCumulative,
		DefaultModel:      sessionModel,
	})

	bucketByModel := map[string]*modelBucket{}
	bucketOrder := []string{}
	for _, drow := range detailRows {
		for _, c := range drow.Contributions {
			modelKey := c.Model
			if modelKey == "" {
				modelKey = sessionModel
			}
			bundle := sessionMsgCostBundle(c.Bundle)
			// Contribution timestamp feeds date-effective pricing (see
			// proxyAwareCost); fall back to the row's own timestamp, then
			// leave zero (→ current rates) exactly like the prior CTE's
			// unparseable-timestamp handling.
			cAt, perr := time.Parse(time.RFC3339Nano, c.Timestamp)
			if perr != nil {
				cAt, _ = time.Parse(time.RFC3339Nano, drow.Timestamp)
			}
			var rowCost, rowAICost, rowToolCost float64
			var rowInputCost, rowOutputCost, rowCacheReadCost, rowCacheCreationCost float64
			if cb, ok := proxyAwareCost(s.opts.CostEngine, modelKey, bundle, c.RecordedCostUSD, c.OwnFast, c.InheritedFast, cAt); ok {
				rowCost = cb.Total
				rowAICost = cb.AICost
				rowToolCost = cb.ToolCost
				rowInputCost = cb.InputCost
				rowOutputCost = cb.OutputCost
				rowCacheReadCost = cb.CacheReadCost
				rowCacheCreationCost = cb.CacheCreationCost
			}

			mb, ok := bucketByModel[modelKey]
			if !ok {
				mb = &modelBucket{Model: modelKey}
				bucketByModel[modelKey] = mb
				bucketOrder = append(bucketOrder, modelKey)
			}
			mb.Input += bundle.Input
			mb.Output += bundle.Output
			mb.CacheRead += bundle.CacheRead
			mb.CacheCreation += bundle.CacheCreation
			mb.Reasoning += bundle.Reasoning
			mb.WebSearchRequests += bundle.WebSearchRequests
			mb.TurnCount++
			mb.CostUSD += rowCost
			mb.AICostUSD += rowAICost
			mb.ToolCostUSD += rowToolCost
			mb.InputCostUSD += rowInputCost
			mb.OutputCostUSD += rowOutputCost
			mb.CacheReadCostUSD += rowCacheReadCost
			mb.CacheCreationCostUSD += rowCacheCreationCost

			d.CostUSD += rowCost
			d.AICostUSD += rowAICost
			d.ToolCostUSD += rowToolCost
		}
	}
	// Headline token totals: sessionmsg.SumContributions, the ONE owner of
	// "what does this session add up to" that the org drawer
	// (rollup.SessionDetail) also calls over the same Derive output — so the
	// node header and the org header can only differ when the rows they were
	// handed differ (MCP audit #4b, 2026-09-27). Only the PRICING above stays
	// per-contribution here: the org has no pricing engine.
	totals := sessionmsg.SumContributions(detailRows, sessionModel)
	// Order buckets by token volume DESC (matches the prior SQL ORDER BY).
	sort.SliceStable(bucketOrder, func(i, j int) bool {
		bi, bj := bucketByModel[bucketOrder[i]], bucketByModel[bucketOrder[j]]
		ti := bi.Input + bi.Output + bi.CacheRead + bi.CacheCreation
		tj := bj.Input + bj.Output + bj.CacheRead + bj.CacheCreation
		return ti > tj
	})
	perModel := make([]modelBucket, 0, len(bucketOrder))
	for _, key := range bucketOrder {
		perModel = append(perModel, *bucketByModel[key])
	}
	d.Tokens = map[string]int64{
		"input": totals.Bundle.Input, "output": totals.Bundle.Output,
		"cache_read": totals.Bundle.CacheRead, "cache_creation": totals.Bundle.CacheCreation,
		// cache_creation_1h is the 1h-ephemeral-tier subset of cache_creation
		// (the rest is 5m-tier). Surfaced separately so the session-detail
		// Token Buckets panel can split "Cache Write" into "Cache Write (5m)"
		// and "Cache Write (1h)" — different bill rates.
		"cache_creation_1h": totals.Bundle.CacheCreation1h,
		"reasoning":         totals.Bundle.Reasoning,
	}
	d.PerModel = perModel
	d.TokenUsageAvailable = len(perModel) > 0
	d.TurnCount = totals.Turns
	d.ProxyTurnCount = totals.ProxyTurns

	// Context occupancy cannot replace missing usage. A captured row with
	// zero counts is distinct from an absent row. Never infer cost from budget.
	if !d.TokenUsageAvailable {
		d.ContextBudgetTokens = s.sessionContextBudget(r.Context(), id)
		var ev *cursorusage.Evidence
		if cursorusage.AppliesTo(d.Tool) {
			if e, err := store.New(s.db()).CursorUsageEvidence(r.Context(), id); err == nil {
				if e.Prompts > 0 {
					// Registration state of the finish hooks, from the
					// same hooks.json walk `observer doctor cursor`
					// reports, so the note never tells the user to
					// re-register hooks that are wired (D4).
					e.FinishHooks = cursorFinishHooksWiring()
				}
				ev = &e
			}
		}
		d.TokensNote = tokensUnbilledNote(d.Tool, d.ContextBudgetTokens, ev)
	} else if cursorusage.AppliesTo(d.Tool) {
		d.TokensNote, _ = store.New(s.db()).CursorUsageNote(r.Context(), id)
	}

	// Headline model fallback. sessions.model is populated only when an
	// ingested event carried a model, which is unreliable across adapters:
	// it's empty for nearly all claude-code sessions and every cursor session
	// (cursor's hooks don't deliver a model, and current cursor-agent emits
	// no stop-token row — see project_cursor_model_capture_gap). When it's
	// empty, surface the dominant model from the per-turn token_usage
	// breakdown, which IS the authoritative per-turn model source. perModel
	// is already sorted by token volume DESC, so the first non-empty bucket
	// is the model the session predominantly ran on.
	if d.Model == "" {
		for _, mb := range perModel {
			if mb.Model != "" {
				d.Model = mb.Model
				break
			}
		}
	}

	// Fork/subagent lineage (migration 069; codex + opencode). Best-effort:
	// a query failure leaves the lineage fields at their zero value and the
	// modal simply hides the badge + spawned-sessions list. Children is
	// normalized to [] below so the frontend can map unconditionally.
	// Capture-surface attribution (migration 107) — best-effort read;
	// a failure leaves both fields empty (= unknown) and omitted.
	if sv, serr := store.New(s.db()).LoadSessionSurface(r.Context(), id); serr == nil {
		d.Surface = sv.Surface
		d.SurfaceHost = sv.SurfaceHost
	}
	// Captured tool/CLI version (migration 125) — same best-effort read;
	// a failure leaves it empty (= unknown) and omitted.
	if first, last, terr := store.New(s.db()).LoadSessionToolVersions(r.Context(), id); terr == nil {
		d.ToolVersion, d.ToolVersionLast = first, last
	}
	// Where it ran (migration 240) - same best-effort read; a failure
	// leaves both empty (= unknown) and omitted.
	if ex, xerr := store.New(s.db()).LoadSessionExecution(r.Context(), id); xerr == nil {
		d.ExecutionLocation, d.VendorSessionRef = ex.ExecutionLocation, ex.VendorSessionRef
	}
	if lin, lerr := store.New(s.db()).LoadSessionLineage(r.Context(), id); lerr == nil {
		d.ForkedFromID = lin.ForkedFromID
		d.ParentThreadID = lin.ParentThreadID
		d.ThreadSource = lin.ThreadSource
		d.ParentInDB = lin.ParentInDB
		for _, c := range lin.Children {
			// A child's cost is priced the way its own header prices it
			// (priceSpendTurns over the same one-rule rows), so the spawned
			// sessions list and the child's detail view show one number.
			d.Children = append(d.Children, lineageChild{
				ID:           c.ID,
				ThreadSource: c.ThreadSource,
				StartedAt:    c.StartedAt,
				InputTokens:  c.InputTokens,
				OutputTokens: c.OutputTokens,
				CostUSD:      s.priceSpendTurns(c.Turns),
				ActionCount:  c.ActionCount,
			})
		}
	}
	if d.Children == nil {
		d.Children = []lineageChild{}
	}

	// Additive resume-capability block (session-attach design Phase 3):
	// native / handoff / none, derived from the integration registry by
	// capability shape so the frontend never branches on tool name.
	d.Resume = resumeInfoForSession(d.Tool, id)

	// Session classification (plan §4). Degrades to the unclassified state on
	// error — an annotation-layer failure must not 500 the whole detail view.
	{
		st := store.New(s.db())
		if tags, tErr := st.SessionTags(r.Context(), id); tErr == nil {
			d.Tags = tags
		} else {
			s.opts.Logger.Warn("session detail: tag load failed", "err", tErr)
		}
		if annot, aErr := st.GetSessionAnnotation(r.Context(), id); aErr == nil {
			d.Favorite = annot.Favorite
			d.Note = annot.Note
			d.Rating = annot.Rating
		} else {
			s.opts.Logger.Warn("session detail: annotation load failed", "err", aErr)
		}
	}
	if d.Tags == nil {
		d.Tags = []string{}
	}

	writeJSON(w, d)
}

// sessionContextBudget sums the carried context budget from a session's
// prompt_context actions (cursor's per-section prompt-token counts) through
// the shared sessiongauge.ReportedBudget parser. These
// tokens are part of a turn's input but never billed on their own, so this is
// only ever surfaced as an estimate for a session with no billed usage — it
// must NOT feed cost. Returns 0 on any error or when no sections exist.
func (s *Server) sessionContextBudget(ctx context.Context, sessionID string) int64 {
	rows, err := s.db().QueryContext(ctx,
		`SELECT COALESCE(target, '') FROM actions
		  WHERE session_id = ? AND action_type = 'prompt_context'`, sessionID)
	if err != nil {
		return 0
	}
	defer rows.Close()
	var targets []string
	for rows.Next() {
		var target string
		if err := rows.Scan(&target); err != nil {
			break
		}
		targets = append(targets, target)
	}
	return sessiongauge.ReportedBudget(targets)
}

// cursorFinishHooksWiring resolves whether this node's Cursor finish hooks
// (stop, afterAgentResponse) are registered. A var so tests can pin it
// without a real $HOME; production reads the doctor's own hooks.json walk.
var cursorFinishHooksWiring = func() cursorusage.HookWiring {
	return diag.CursorFinishHooksWiring(setupWizardHome)
}

// tokensUnbilledNote describes missing capture without attributing it to an
// unobserved failure. The budget clause never implies billed token counts.
// For a Cursor session, ev is the store's evidence of which Cursor events
// fired (nil when it could not be loaded); internal/cursorusage turns it
// into the one reason that applies.
func tokensUnbilledNote(tool string, budget int64, ev *cursorusage.Evidence) string {
	if cursorusage.AppliesTo(tool) {
		var e cursorusage.Evidence
		if ev != nil {
			e = *ev
		}
		return cursorusage.Explain(e, budget)
	}
	return "Token usage was not captured for this session. Token counts and cost are unknown, not zero."
}

type actionBucket struct {
	ActionType string `json:"action_type"`
	Count      int    `json:"count"`
	Failures   int    `json:"failures"`
}

// proxyAwareCost computes a deduped row's cost under the audit-F1 "keep
// proxy, OR-in fast" rule (docs/audits/audit-2026-06-08.md). The effective
// fast tier is the row's own fast OR a fast JSONL twin that was deduped
// against it (inheritedFast). A recorded proxy cost_usd is authoritative
// EXCEPT when the row inherited a fast flag it didn't carry itself — codex's
// proxy wire reports the standard tier, so its insert-time cost_usd was
// priced WITHOUT the FastMultiplier premium; in that one case we re-price
// from the table so the premium lands. Returns ok=false only when the model
// is unknown AND there's no recorded cost (caller leaves the row at $0,
// matching prior behavior).
//
// `at` is the row's own timestamp, used for DATE-EFFECTIVE pricing: a
// re-priced historical row bills at the rate in force when it ran, not
// today's. Pass the zero time when no stamp is available — LookupAt then
// falls back to current rates (never to the oldest tier). Recorded costs
// are unaffected either way: they were priced at insert time, which is
// already the historically correct rate.
func proxyAwareCost(engine *cost.Engine, model string, bundle cost.TokenBundle, recorded float64, ownFast, inheritedFast bool, at time.Time) (cost.Breakdown, bool) {
	bundle.Fast = ownFast || inheritedFast
	if recorded > 0 && !(inheritedFast && !ownFast) {
		// Recorded cost already reflects this row's own tier — use as-is.
		// Recorded-cost adapters (OpenCode, Pi) don't split AI vs tool, so
		// the whole amount lands on AICost, matching the prior code path.
		return cost.Breakdown{AICost: recorded, Total: recorded}, true
	}
	if engine == nil {
		return cost.Breakdown{}, false
	}
	return engine.ComputeBreakdownAt(model, bundle, at)
}

// priceSpendTurns prices a session's one-rule spend rows (store.SpendTurn)
// exactly as the session header prices its Derive contributions - recorded
// cost when positive, else the pricing table at the row's own timestamp and
// served tier (proxyAwareCost; a proxy row lifted to its twin's fast tier
// arrives with its recorded cost already cleared and Fast set) - so a
// drill-down row and the header of the session it summarizes agree on cost
// as well as tokens. An unpriced row adds $0, as in the header.
func (s *Server) priceSpendTurns(turns []store.SpendTurn) float64 {
	var total float64
	for _, t := range turns {
		b := cost.TokenBundle{
			Input: t.InputTokens, Output: t.OutputTokens, CacheRead: t.CacheReadTokens,
			CacheCreation: t.CacheWriteTokens, CacheCreation1h: t.CacheWrite1hTokens,
			Reasoning: t.ReasoningTokens, WebSearchRequests: t.WebSearchRequests,
		}
		if cb, ok := proxyAwareCost(s.opts.CostEngine, t.Model, b, t.RecordedCostUSD, t.Fast, false, t.Ts); ok {
			total += cb.Total
		}
	}
	return total
}
