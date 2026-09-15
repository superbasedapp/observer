// TypeScript shapes for the Go dashboard's /api/* responses.
// Field names mirror the Go JSON tags exactly so renaming on the
// backend doesn't silently break the frontend.

// ---------- /api/status ----------

export type ToolActivity = {
  tool: string;
  last_seen_at: string;
  action_count: number;
};

export type SnapshotCounts = {
  projects: number;
  sessions: number;
  actions: number;
  api_turns: number;
  file_state: number;
  failure_context: number;
  action_excerpts: number;
  token_usage: number;
  // Migration-036 cachetrack surface — drives the sidebar Cache badge.
  // Zero on installs that pre-date 036 or have [cachetrack].enabled
  // = false; the backend reads the count tolerantly.
  cache_events: number;
  suggestions: number;
  // Migration-040/041 surfaces — drive the sidebar Security and
  // Routing badges. Optional: absent entirely when the web build is
  // newer than the daemon serving /api/status.
  guard_events?: number;
  router_decisions?: number;
  // Sessions with activity in the last 15 minutes (the /api/live
  // definition, uncapped) — drives the sidebar Live badge.
  live_sessions?: number;
};

export type StatusSnapshot = {
  // version is the build-stamped binary version (e.g. "1.8.2"). Empty
  // string in dev builds — never compare for update available when
  // version is missing or === "dev".
  version?: string;
  db_path: string;
  db_size_bytes: number;
  schema_version: number;
  counts: SnapshotCounts;
  last_action_at?: string;
  last_action_tool?: string;
  per_tool_last_seen: ToolActivity[];
  recent_failures_24h: number;
  // Serving-process identity (stamped by the dashboard handler). The
  // restart-pending banner compares started_at against config-save
  // timestamps to auto-clear after a real restart.
  started_at?: string;
  uptime_seconds?: number;
  // host_os is the DAEMON's runtime.GOOS ("darwin" / "linux" /
  // "windows") — the machine whose PTYs the terminals attach to, which
  // is NOT necessarily the machine running this browser. The terminal
  // key bar labels its modifier keys from it (lib/keyPlatform).
  // Optional on the wire: an older daemon omits it entirely.
  host_os?: string;
};

// ---------- /api/health/watcher ----------

// WatcherHealth mirrors internal/intelligence/dashboard/health.go.
// The sidebar consumes only the rollup counts; the per-file rows are
// typed for the future health panel.
export type WatcherHealthFile = {
  path: string;
  byte_offset: number;
  file_size: number;
  behind_bytes: number;
  last_parsed?: string;
  behind_seconds?: number;
  missing?: boolean;
  orphan_unmatched?: boolean;
  suspected_misrouted?: boolean;
  misroute_reason?: string;
  action_count?: number;
};

export type WatcherHealth = {
  files: WatcherHealthFile[];
  behind_count: number;
  behind_total_bytes: number;
  orphan_count: number;
  suspected_misrouted_count: number;
  checked_at: string;
};

// ---------- /api/status/scoped ----------

// StatusScoped is the window/tool/project-scoped equivalent of
// SnapshotCounts. Used by the Overview + Analysis headline tiles
// (Sessions / API turns / Token rows / Total sessions) so they honor
// the global filters instead of showing all-time numbers under a
// "window 30d" chip.
export type StatusScoped = {
  days: number;
  sessions: number;
  api_turns: number;
  token_usage: number;
  actions: number;
};

// ---------- /api/timeseries/cost ----------

export type CostPoint = {
  bucket: string;
  input: number;
  output: number;
  cache_read: number;
  cache_creation: number;
  cost_usd: number;
  turn_count: number;
  compression_bytes_saved: number;
  compression_tokens_saved_est: number;
  compression_cost_saved_usd_est: number;
  compression_turns: number;
};

export type CostTimeseries = {
  metric: "cost";
  bucket: "day" | "hour";
  days: number;
  series: CostPoint[];
};

// ---------- /api/timeseries/actions ----------

export type ActionsPoint = {
  bucket: string;
  total: number;
  failures: number;
  by_tool: Record<string, number>;
};

export type ActionsTimeseries = {
  metric: "actions";
  bucket: "day" | "hour";
  days: number;
  series: ActionsPoint[];
};

// ---------- /api/tools ----------

export type ToolRow = {
  tool: string;
  action_count: number;
  failure_count: number;
  success_rate: number;
  session_count: number;
  first_seen: string;
  last_seen: string;
};

export type ToolsResponse = {
  days: number;
  since: string;
  tools: ToolRow[];
};

// ---------- /api/projects ----------

export type ProjectRow = {
  root_path: string;
  session_count: number;
  action_count: number;
  last_seen?: string;
};

export type ProjectsResponse = { rows: ProjectRow[] };

// ---------- /api/models (cost.Summary) ----------

export type TokenBundle = {
  input: number;
  output: number;
  cache_read: number;
  cache_creation: number;
  cache_creation_1h: number;
  reasoning: number;
  web_search_requests: number;
};

export type CompressionStats = {
  original_bytes: number;
  compressed_bytes: number;
  compressed_count: number;
  dropped_count: number;
  marker_count: number;
  turns: number;
  tokens_saved_est: number;
  cost_saved_usd_est: number;
};

export type Reliability =
  | "accurate"
  | "approximate"
  | "unreliable"
  | "unknown"
  | "";

export type CostRow = {
  key: string;
  tokens: TokenBundle;
  cost_usd: number;
  ai_cost_usd: number;
  tool_cost_usd: number;
  turn_count: number;
  source: "proxy" | "jsonl" | "mixed" | "";
  reliability: Reliability;
  unknown_models?: string[];
  pricing_source?: string;
  compression: CompressionStats;
  // Fast-tier (Opus 4.8 speed:"fast") subset of this group's turns.
  // fast_cost_usd already carries the 2x FastMultiplier premium.
  fast_turn_count?: number;
  fast_cost_usd?: number;
};

export type CostSummary = {
  group_by: string;
  source: string;
  days?: number;
  since?: string;
  rows: CostRow[];
  total_tokens: TokenBundle;
  total_cost_usd: number;
  turn_count: number;
  reliability: Reliability;
  unknown_model_count?: number;
  total_compression: CompressionStats;
  // Window-wide fast-tier totals (Opus 4.8 speed:"fast"). Rendered as a
  // small stat line when fast_turn_count > 0.
  fast_turn_count?: number;
  total_fast_cost_usd?: number;
  // Per-row cache annotations (spec §13 cost-view-annotation). Keyed by
  // row.key (model name or session_id depending on group_by). Absent when
  // the grouping isn't indexable by cache_events (project / tool) or when
  // no rows have cache events. The frontend looks up cache_by_key[row.key]
  // and renders a small cache pill when the entry exists.
  cache_by_key?: Record<string, SessionCacheAnnotation>;
};

// ---------- /api/sessions ----------

export type SessionRow = {
  id: string;
  tool: string;
  project: string;
  started_at: string;
  last_seen_at?: string;
  duration_seconds: number;
  total_actions: number;
  sidechain_action_count: number;
  // Lines-of-code authorship
  // (docs/plans/lines-of-code-tracking-plan-2026-09-07.md). ai_code_lines is
  // agent-authored CODE lines: added + modified, with comments, blank lines
  // and whitespace-only reflows excluded and deleted lines deliberately NOT
  // included. human_code_lines is its editor-reported counterpart.
  //
  // BOTH are omitempty on the wire, so ABSENT MEANS "NOT COUNTED", NEVER
  // ZERO — a corpus that has never run `observer backfill --loc`, or a
  // daemon predating the feature, simply omits the keys. Render absent as a
  // dash plus the backfill hint; rendering it as 0 would present an absence
  // of measurement as a measurement.
  //
  // Never derive an "AI share" from these two alone: with no editor capture
  // the human side is unmeasured, not zero, so the share would read 100% AI.
  // /api/loc/summary is the only surface that carries the human_capture flag
  // that makes a share legitimate.
  ai_code_lines?: number;
  human_code_lines?: number;
  quality_score?: number;
  error_rate?: number;
  redundancy_ratio?: number;
  // Spec §14.1 wasteful-subset of redundancy_ratio. Populated only
  // when the session has cache_events (Tier 3 / pre-backfill stay
  // null). Frontend renders as "0.30 (0.20 wasteful)" on the
  // Sessions table when present.
  redundancy_ratio_wasteful?: number;
  stale_reads_wasteful?: number;
  stale_reads_necessary?: number;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_creation_tokens: number;
  // 1h-ephemeral-tier subset of cache_creation_tokens; the rest is 5m
  // tier. Anthropic-only (non-Anthropic providers always 0).
  cache_creation_1h_tokens: number;
  reasoning_tokens?: number;
  web_search_requests?: number;
  total_tokens: number;
  cost_usd: number;
  ai_cost_usd: number;
  tool_cost_usd: number;
  cost_reliability?: Reliability;
  // Distinct model identifiers seen in this session's api_turns +
  // token_usage rows, ordered by turn count desc (heaviest first).
  // Empty when no proxy/JSONL capture preserved model info.
  models?: string[];
  // Session classification (docs/plans/session-classification-tags-plan-2026-07-31.md).
  // All three are `omitempty` on the wire — an untagged session, or an
  // older daemon that predates the feature, simply omits them. Never
  // assume presence; treat absent as "no tags / not favorited / no note".
  tags?: string[];
  favorite?: boolean;
  has_note?: boolean;
  // Overall session rating, 1-10 (absent/0 = unrated). omitempty on the wire.
  rating?: number;
  // title is the developer's OWN session title (migration 116) — distinct
  // from cloud_title below (the AI-generated one) and always wins over it
  // wherever the UI renders an "effective title". omitempty — absent means
  // no developer title has been set (fall back to cloud_title, then the
  // ordinary tool/project fallback text).
  title?: string;
  // Cloud-enrichment presence (personal plane). cloud_enriched=true when a
  // non-superseded cloud_results row exists for the session; cloud_title is the
  // AI-suggested title. Both omitempty — absent on non-enriched sessions.
  cloud_enriched?: boolean;
  cloud_enrichment?: CloudEnrichmentProgress;
  cloud_title?: string;
};

export type SessionsResponse = {
  rows: SessionRow[];
  page: number;
  limit: number;
  total: number;
  scored_count: number;
  days: number;
  // Server-side sort echo + page footer totals (server sorts the full
  // filtered set, so the page footer reconciles with the visible rows even
  // when a global cost/token sort surfaced a different slice).
  sort_by?: string;
  sort_dir?: string;
  page_cost_usd?: number;
  page_ai_cost_usd?: number;
  page_tool_cost_usd?: number;
};

// ---------- /api/live ----------

export type LiveAction = {
  id: number;
  timestamp: string;
  action_type: string;
  target?: string;
  success: boolean;
};

export type LiveSession = {
  session_id: string;
  tool: string;
  project_root?: string;
  started_at: string;
  last_activity: string;
  actions_total: number;
  turns: number;
  models?: string[];
  tokens: {
    input: number;
    output: number;
    cache_read: number;
    cache_write: number;
  };
  cost_usd: number;
  recent_actions: LiveAction[];
};

export type LiveResponse = {
  generated_at: string;
  window_minutes: number;
  active: LiveSession[];
};

// ---------- /api/report/monthly ----------

export type MonthlyReportRow = {
  key: string;
  cost_usd: number;
  turns: number;
  sessions?: number;
};

export type MonthlyReport = {
  month: string;
  project?: string;
  generated_at: string;
  totals?: {
    cost_usd: number;
    sessions: number;
    turns: number;
    tokens?: { input: number; output: number; cache_read: number; cache_write: number };
  };
  by_model?: MonthlyReportRow[];
  by_tool?: MonthlyReportRow[];
  by_project?: MonthlyReportRow[];
  savings?: {
    compression_bytes: number;
    compression_tokens: number;
    /** Bytes removed by lossy eviction (drops). Already excluded from
     * compression_bytes; recoverable via search_past_outputs markers. */
    compression_evicted_bytes?: number;
    cache_read_tokens: number;
  };
  top_sessions?: {
    id: string;
    tool: string;
    project?: string;
    started_at: string;
    cost_usd: number;
    turns: number;
  }[];
};

// ---------- /api/experiments ----------

export type ExperimentDef = {
  name: string;
  class: string;
  control: string;
  candidate: string;
  started_at: string;
  stopped_at?: string;
  note?: string;
};

export type ExperimentArmReport = {
  arm: string;
  profile: string;
  sessions: number;
  total_cost_usd: number;
  mean_cost_usd: number;
  sd_cost_usd: number;
  cv_pct: number;
  turns: number;
  mean_turns: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
  compression_saved_bytes: number;
  /** Bytes removed by lossy eviction (drops). Already excluded from
   * compression_saved_bytes; recoverable via search_past_outputs markers. */
  compression_evicted_bytes?: number;
  cache_events_by_cause: Record<string, number>;
};

export type ExperimentReportResponse = {
  experiment: ExperimentDef;
  running: boolean;
  window_from: string;
  window_to: string;
  control: ExperimentArmReport;
  candidate: ExperimentArmReport;
  delta_cost_pct: number;
  delta_turns_pct: number;
};

// ---------- /api/budget ----------

export type BudgetScope = {
  root?: string;
  budget_usd: number;
  mtd_usd: number;
  pct: number;
  forecast_usd: number;
  threshold?: "warn80" | "over100" | "";
};

export type BudgetResponse = {
  configured: boolean;
  month: string;
  days_elapsed: number;
  days_in_month: number;
  global?: BudgetScope;
  projects?: BudgetScope[];
};

// ---------- /api/search ----------

export type SearchHit = {
  action_id: number;
  session_id?: string;
  timestamp?: string;
  tool?: string;
  action_type?: string;
  tool_name?: string;
  target?: string;
  snippet?: string;
  error_message?: string;
  rank: number;
};

export type SearchResponse = {
  query: string;
  count: number;
  hits: SearchHit[];
};

// ---------- /api/sessions/calendar ----------

export type SessionsCalendarCell = {
  day: string; // YYYY-MM-DD
  session_count: number;
  cost_usd: number;
};

export type SessionsCalendarResponse = {
  days: number;
  cells: SessionsCalendarCell[];
};

// ---------- /api/actions/day-counts ----------

export type ActionsDayCell = {
  day: string; // YYYY-MM-DD
  count: number;
};

export type ActionsDayCountsResponse = {
  days: number;
  cells: ActionsDayCell[];
};

// ---------- /api/timeseries/tokens-by-model ----------

export type TokensByModelPoint = {
  bucket: string;
  model: string;
  input: number;
  output: number;
  cache_read: number;
  cache_creation: number;
  total_tokens: number;
  cost_usd: number;
  turn_count: number;
};

export type TokensByModelTimeseries = {
  metric: "tokens_by_model";
  bucket: "day";
  days: number;
  series: TokensByModelPoint[];
};

// ---------- /api/cowork/reconcile ----------

export type CoworkReconcileRow = {
  session_id: string;
  title?: string;
  process_name?: string;
  cowork_cost_usd: number;
  derived_cost_usd: number;
  drift_usd: number;
  drift_percent: number;
  over_threshold: boolean;
  unknown_model?: boolean;
  unknown_model_key?: string;
};

export type CoworkReconcileResult = {
  rows: CoworkReconcileRow[];
  sessions_total: number;
  sessions_over_threshold: number;
  cowork_total_usd: number;
  derived_total_usd: number;
  overall_drift_usd: number;
  overall_drift_percent: number;
  drift_threshold_percent: number;
};

// ---------- /api/analysis/headline ----------

export type AnalysisHeadline = {
  days: number;
  period: {
    cost_usd: number;
    prior_cost_usd: number;
    prior_is_zero: boolean;
    delta_pct: number;
    recorded_cost_share_pct: number;
    period_start: string;
    prior_start: string;
  };
  month: {
    to_date_usd: number;
    projection_usd: number;
    prior_month_same_day_usd: number;
    prior_month_is_zero: boolean;
    vs_prior_month_pct: number;
    budget_usd: number;
    budget_pct: number;
    days_elapsed: number;
    days_in_month: number;
  };
  output_rate: {
    output_tokens: number;
    rate_per_million: number;
  };
  cache_savings: {
    usd: number;
    cache_read_tokens: number;
    source_note: string;
  };
  cache: {
    read_tokens: number;
    write_tokens: number;
    efficacy: number;
  };
  high_context: {
    turns_over_100k: number;
    turns_over_200k: number;
    cost_over_100k_usd: number;
    cost_over_200k_usd: number;
    lc_eligible_turns: number;
    lc_surcharge_usd: number;
  };
  per_turn: {
    count: number;
    mean_usd: number;
    p95_usd: number;
  };
  burn_rate: {
    active_hours: number;
    cost_per_hour_usd: number;
    method_note: string;
  };
  top_model: {
    key: string;
    cost_usd: number;
    concentration_pct: number;
  };
  waste: {
    usd: number;
    tokens: number;
    blended_rate_per_million: number;
    source_note: string;
  };
};

// ---------- /api/analysis/trend ----------

export type AnalysisDim = "model" | "project" | "tool";

export type AnalysisTrendPoint = {
  bucket: string;
  key: string;
  total_tokens: number;
  cost_usd: number;
  turn_count: number;
};

export type AnalysisTrend = {
  metric: "trend";
  dim: AnalysisDim;
  bucket: "day";
  days: number;
  series: AnalysisTrendPoint[];
};

// ---------- /api/analysis/movers ----------

export type Mover = {
  key: string;
  prior_usd: number;
  current_usd: number;
  delta_usd: number;
  delta_pct: number;
};

export type Entrant = {
  key: string;
  current_usd: number;
};

// NOTE: increases / decreases / new_entrants come back as JSON `null`
// (not `[]`) when empty, because the Go handler builds them from nil
// slices. Treat as arrays at the read site (default to []).
export type AnalysisMovers = {
  dim: AnalysisDim;
  days: number;
  period_start: string;
  prior_start: string;
  increases: Mover[] | null;
  decreases: Mover[] | null;
  new_entrants: Entrant[] | null;
};

// ---------- /api/analysis/top-sessions ----------

export type TopSession = {
  id: string;
  tool: string;
  started_at: string;
  ended_at?: string;
  models: string[];
  turns: number;
  max_prompt_tokens: number;
  lc_turn_count: number;
  cost_usd: number;
  badges: string[];
};

export type AnalysisTopSessions = {
  days: number;
  limit: number;
  sessions: TopSession[];
};

// ---------- /api/analysis/routing-suggestions ----------

export type RoutingSuggestion = {
  session_id: string;
  current_model: string;
  suggested_model: string;
  current_cost_usd: number;
  suggested_cost_usd: number;
  savings_usd: number;
  reasons: string[];
};

export type AnalysisRoutingSuggestions = {
  days: number;
  suggestions: RoutingSuggestion[];
  total_savings_usd: number;
  sibling_map: Record<string, string>;
  thresholds: {
    max_trivial_prompt_tokens: number;
    max_trivial_output_tokens: number;
    min_savings_usd: number;
  };
  framing_note: string;
};

// ---------- /api/analysis/cost-by-hour ----------

export type HourBucket = {
  hour: number;
  cost_usd: number;
  turn_count: number;
};

export type AnalysisCostByHour = {
  days: number;
  timezone: string;
  buckets: HourBucket[];
};

// ---------- /api/analysis/cost-by-dow-hour ----------

// 2D bucket: day-of-week (0=Sun..6=Sat per Go's time.Weekday()) ×
// hour-of-day (0..23). Cost summed over the window. Frontend renders
// this as a 7×24 heatmap on the Analysis page's "When you spend".
export type DowHourCell = {
  dow: number;
  hour: number;
  cost_usd: number;
  turn_count: number;
};

export type AnalysisCostByDowHour = {
  days: number;
  timezone: string;
  cells: DowHourCell[];
};

// ---------- /api/analysis/cache-savings-trend ----------

export type CacheSavingsPoint = {
  day: string;
  savings_usd: number;
  cache_read_tokens: number;
};

export type AnalysisCacheSavingsTrend = {
  days: number;
  points: CacheSavingsPoint[];
};

// ---------- /api/session/<id> ----------

export type SessionModelBucket = {
  model: string;
  input: number;
  output: number;
  cache_read: number;
  cache_creation: number;
  reasoning?: number;
  web_search_requests?: number;
  turn_count: number;
  cost_usd: number;
  ai_cost_usd: number;
  tool_cost_usd: number;
  // Per-bucket AICost components (v1.6.13). Sum equals ai_cost_usd.
  // Feeds the session-detail Models Used panel's $-mode stacked bar.
  // Zero when the row's cost came from a recorded estimated_cost_usd
  // (OpenCode/Pi) instead of cost-engine pricing — the bar still
  // renders but as a single undifferentiated AI block.
  input_cost_usd: number;
  output_cost_usd: number;
  cache_read_cost_usd: number;
  cache_creation_cost_usd: number;
};

export type ActionBucket = {
  action_type: string;
  count: number;
  failures: number;
};

export type SessionDetail = {
  id: string;
  tool: string;
  project: string;
  model?: string;
  started_at: string;
  ended_at?: string;
  /** COALESCE(ended_at, MAX(actions.timestamp)) — real end of activity for
   *  open/never-closed sessions; drives Elapsed so it isn't start→now. */
  last_activity_at?: string;
  /** Carried context budget (estimated) shown for a session with no billed
   *  tokens — e.g. a cancelled, non-proxied cursor turn. Not a bill. */
  context_budget_tokens?: number;
  /** Human note explaining why billed tokens are empty (set only then). */
  tokens_note?: string;
  /** Presence of captured usage rows, independent of their numeric total. */
  token_usage_available?: boolean;
  total_actions: number;
  success_actions: number;
  failure_actions: number;
  /** Inline sub-agent activity volume (claude-code same-session sidechain
   *  model): actions flagged is_sidechain on this session. Drives the
   *  LineageBanner sidechain note; per-sub-agent breakdown lives in the
   *  System tab's Sub-agents section (/api/session/<id>/subagents). */
  sidechain_action_count: number;
  quality_score?: number;
  error_rate?: number;
  redundancy_ratio?: number;
  tokens: {
    input: number;
    output: number;
    cache_read: number;
    cache_creation: number;
    // 1h-ephemeral-tier subset of cache_creation; the rest is 5m
    // tier. Anthropic-only (0 elsewhere).
    cache_creation_1h: number;
    reasoning: number;
  };
  per_model: SessionModelBucket[];
  cost_usd: number;
  ai_cost_usd: number;
  tool_cost_usd: number;
  tool_breakdown: ActionBucket[];
  // C15 cache annotation — compact glance-view next to the per-model
  // cost breakdown. Nil when the session has no cache_events
  // (pre-cachetrack history / non-Anthropic provider). The full
  // Cache tab loads /api/session/<id>/cache.
  cache_summary?: SessionCacheAnnotation;
  // Codex fork/subagent lineage (migration 069). thread_source is
  // "subagent" for a spawned subagent, "user" for a normal/user-fork
  // session (absent for non-codex tools). forked_from_id non-empty =
  // forked/continued from that codex thread id; parent_in_db reports
  // whether a session row exists for it. children are the sessions
  // spawned FROM this one (always present, [] when none).
  forked_from_id?: string;
  parent_thread_id?: string;
  thread_source?: string;
  parent_in_db: boolean;
  children: SessionLineageChild[];
  // Capture-surface attribution (migration 107): the normalized kind
  // (cli | ide | desktop | sdk | web) and the concrete host token
  // ("vscode", "cursor", "jetbrains-idea", "claude-desktop", ...). Both
  // are OMITTED when no adapter stamped one — absence means UNKNOWN and
  // must never be rendered as "cli" (see the shared SurfaceBadge).
  surface?: string;
  surface_host?: string;
  // Resume-capability block (session-attach design Phase 3): how a CLOSED
  // session on this tool can be reopened, derived server-side by capability
  // shape. Always present.
  resume: SessionResumeInfo;
  // Session classification (see SessionRow above). Optional for the same
  // reason: a daemon that predates the feature omits them entirely.
  tags?: string[];
  favorite?: boolean;
  note?: string;
  rating?: number;
};

// ---------- session classification: tags / favorites / notes ----------
// docs/plans/session-classification-tags-plan-2026-07-31.md §4.

// TagRollup is one row of GET /api/sessions/tags: the vocabulary entry
// plus its per-tag rollup (session count, cost, tokens).
export type TagRollup = {
  tag: string;
  sessions: number;
  cost_usd: number;
  tokens: number;
};

export type TagRollupResponse = {
  tags: TagRollup[];
};

// SessionTagsRequest is the POST /api/session/<id>/tags body. `add`/`remove`
// are always sent (possibly empty); `favorite`/`note`/`rating`/`title` are
// null when the mutation does not touch them — null means "leave as is", not
// "clear". A rating of 0 clears it (unrated); 1-10 is a score. A title of ""
// clears it (falls back to the AI title, if any); `title` is optional so
// existing callers built before it existed keep compiling unchanged.
export type SessionTagsRequest = {
  add: string[];
  remove: string[];
  favorite: boolean | null;
  note: string | null;
  rating: number | null;
  title?: string | null;
};

// SessionTagsResponse is the current state of one session's classification —
// returned by both POST (post-mutation truth) and GET (read-only snapshot,
// same shape, no write) on /api/session/<id>/tags. `rating` is 0 when the
// session is unrated; `title` is "" when no developer title is set.
export type SessionTagsResponse = {
  tags: string[];
  favorite: boolean;
  note: string;
  rating: number;
  title?: string;
};

// TagManageRequest is the POST /api/sessions/tags/manage body: rename XOR
// delete, never both.
export type TagManageRequest =
  | { rename: { from: string; to: string } }
  | { delete: string };

export type TagManageResponse = {
  affected: number;
};

// SessionResumeInfo tells the Resume affordance which mechanism to offer,
// dispatched on `kind` (never a tool-name branch):
//   - "native":  a grounded native-resume contract — the Resume button POSTs
//                /resume then docks a terminal running the tool's own resume
//                (the real transcript). `subcommand` names the launcher verb.
//   - "handoff": no native resume, but the tool is launchable — point the
//                operator at the existing Continue-in… (fork) card instead of
//                duplicating it.
//   - "none":    neither — an honest-disabled affordance naming the gap.
export type SessionResumeInfo = {
  kind: "native" | "handoff" | "none";
  subcommand: string;
};

// SessionResumeResponse is the reply from POST /api/session/<id>/resume: the
// opaque terminal handle (`token`, identical to the launch wire shape so the
// dock path is the same) plus the durable run id.
export type SessionResumeResponse = SessionLaunchResponse & {
  run_id: string;
};

// One spawned (forked/subagent) session in a parent's lineage list.
// The rollup fields (omitempty server-side) surface what each sub-agent
// session cost without navigating into it — opencode sub-agents are
// separate sessions, unlike claude-code's same-session sidechains.
export type SessionLineageChild = {
  id: string;
  thread_source?: string;
  started_at: string;
  input_tokens?: number;
  output_tokens?: number;
  cost_usd?: number;
  action_count?: number;
};

// ---------- /api/session/<id>/cache (C13) ----------

export type SessionCacheAnnotation = {
  tier: "proxy" | "transcript" | "mixed" | "none";
  event_count: number;
  hit_count: number;
  write_count: number;
  rewrite_count: number;
  reanchor_count: number;
  mispredict_count: number;
  // zero_usage_count are turns whose tokens_read=0 AND
  // tokens_written=0 — observationally vacant; excluded from the
  // §10 mispredict rate per docs/cache-tracking.md.
  zero_usage_count: number;
  tokens_read: number;
  tokens_written: number;
  ratio: number;
  // has_flagged_rewrites means a tools_changed (or other neutral-
  // pill cause) was among the rewrites. UI renders neutrally, not
  // alarm-red.
  has_flagged_rewrites: boolean;
};

export type SessionCacheEntry = {
  prefix_hash: string;
  model: string;
  token_count: number;
  ttl_tier: string;
  tier: string;
  state: string;
  created_at: string;
  last_refresh_at: string;
  expires_at: string;
};

export type SessionCacheEvent = {
  timestamp: string;
  tier: string;
  model: string;
  kind: string;
  cause: string;
  predicted_kind?: string;
  tokens_read: number;
  tokens_written: number;
  message_id?: string;
  zero_usage?: boolean;
  // cost_delta_usd is the write paid minus the hypothetical read price;
  // omitted (undefined) when the reconciliation engine did not compute one,
  // 0 when the delta is genuinely zero. Feeds Efficiency.avoidable_usd.
  cost_delta_usd?: number;
};

export type SessionCacheTimelineItem = {
  kind: "baseline" | "anomaly";
  // baseline-only
  count?: number;
  baseline_read_sum?: number;
  baseline_write_sum?: number;
  first_at?: string;
  last_at?: string;
  // anomaly-only
  event?: SessionCacheEvent;
  flagged?: boolean;
};

export type SessionCacheResponse = {
  tier: "proxy" | "transcript" | "mixed" | "none";
  entries: SessionCacheEntry[];
  events: SessionCacheEvent[];
  efficiency: {
    read_tokens: number;
    written_tokens: number;
    ratio: number;
    avoidable_usd: number;
  };
  timeline: SessionCacheTimelineItem[];
};

// ---------- /api/session/<id>/cache/forecast (P2 / §14.2) ----------

export type CacheForecastWarning =
  | "cache_wont_engage"
  | "fast_mode_active"
  | "try_1h_tier"
  | "switch_never_pays_off"
  | "empty_prefix";

export type CacheForecastResponse = {
  session_id: string;
  current_model: string;
  candidate_model: string;

  current_prefix_tokens: number;
  avg_suffix_tokens: number;
  avg_output_tokens: number;
  estimated_remaining_turns: number;
  observed_turns: number;
  current_fast?: boolean;
  has_gaps_over_5_min?: boolean;
  candidate_min_cacheable?: number;

  switch_cost_usd: number;
  per_turn_before_usd: number;
  per_turn_after_usd: number;
  savings_per_turn_usd: number;
  break_even_turns: number;
  estimated_net_savings_usd: number;

  warnings?: CacheForecastWarning[];
};

// ---------- /api/session/<id>/predict (Next-Message Cost & Limit Predictor) ----------

export type PredictWarning =
  | "no_session_history"
  | "turns_inferred_prior"
  | "turns_inferred_default"
  | "empty_prefix"
  | "fast_mode_active"
  // The model has no pricing entry, so the dollar columns are absent while
  // the token facts (prefix, per-turn quantiles, fan-out) are real. Distinct
  // from no_session_history, which means no observed substrate at all.
  | "no_pricing";

export type PredictTurnsTier = "observed" | "prior" | "default";

export type PredictBand = {
  turns: number;
  fresh_input: number;
  output: number;
  per_turn_usd: number;
  message_usd: number;
};

export type PredictEstimate = {
  model: string;
  prefix_tokens: number;
  // has_estimate gates the DOLLAR half (bands' *_usd): it needs both an
  // observed shape and a pricing entry. has_shape gates the FACT half
  // (prefix_tokens, band token dimensions, turns_tier, sample counts),
  // which is present for any session with an observed turn regardless of
  // pricing. has_shape=true with has_estimate=false is "observed turns,
  // unpriced model".
  has_estimate: boolean;
  has_shape: boolean;
  turns_tier: PredictTurnsTier | "";
  low: PredictBand;
  mid: PredictBand;
  high: PredictBand;
  sample_turns: number;
  sample_messages: number;
  warnings?: PredictWarning[];
};

export type PredictLimitGauge = {
  available: boolean;
  needs_proxy: boolean;
  no_window?: boolean;
  // "proxy" (Anthropic response headers) or "transcript" (the tool's own
  // session log, e.g. codex token_count rate_limits). Empty when unavailable.
  source?: string;
  observed_age?: string;
  window_5h_util?: number;
  window_5h_reset?: number;
  window_7d_util?: number;
  window_7d_reset?: number;
  observed_at_unix?: number;
};

export type PredictResponse = {
  session_id: string;
  model: string;
  tool: string;
  estimate: PredictEstimate;
  reason?: string;
  limit: PredictLimitGauge;
};

// ---------- /api/session/<id>/tasks + /api/tasks (task tracking) ----------
// docs/task-tracking.md — session-level todo/plan checklist decode. Field
// names mirror internal/taskreport/report.go's JSON tags exactly (this
// codebase does not transform keys between Go and TS).

export type TaskTokenTotals = {
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
  reasoning_tokens: number;
};

// TaskCostBucket bundles a bucket's tokens/actions with its priced cost and
// the "don't lie about precision" flag: unpriced=true means at least one row
// in this bucket had neither a recorded provider cost nor a pricing-table
// entry for its model — cost_usd is then a known UNDER-count, and a surface
// must render "unpriced" rather than implying $0.00 is the true cost.
export type TaskCostBucket = {
  tokens: TaskTokenTotals;
  actions_count: number;
  cost_usd: number;
  unpriced: boolean;
};

// TaskReportItem is one task's full lifecycle + cost row (Go: ReportItem).
export type TaskReportItem = {
  key: string;
  key_kind: "native_id" | "content_hash";
  content: string;
  active_form?: string;
  owner?: string;
  status: string;
  raw_status?: string;
  order: number;
  unmatched: boolean;
  // never_activated / still_open / elapsed_seconds / terminal_status /
  // first_in_progress_unix / terminal_at_unix mirror taskflow.TaskSummary
  // (docs/task-tracking.md "Honesty caveats"): a task can close without
  // ever passing through in_progress (never_activated), or still be open
  // at measurement time (still_open, elapsed so far — never a fabricated
  // completion).
  never_activated: boolean;
  still_open: boolean;
  elapsed_seconds: number;
  terminal_status?: string;
  first_in_progress_unix?: number;
  terminal_at_unix?: number;
} & TaskCostBucket;

// SessionTaskReport is GET /api/session/<id>/tasks's payload.
export type SessionTaskReport = {
  session_id: string;
  /** Usage captured in the main attribution scope; sidechain is separate. */
  token_usage_available?: boolean;
  // has_tasks gates the calm empty state — most sessions (measured ~80%)
  // never used a task tool at all. This is the majority case, not a
  // degraded state.
  has_tasks: boolean;
  items?: TaskReportItem[];
  // between_tasks / shared are the two non-per-task buckets a surface must
  // render as first-class rows, never a rounding residual — only ~52% of a
  // session's tokens are attributable to one specific task on average.
  between_tasks: TaskCostBucket;
  shared: TaskCostBucket;
  // sidechain is present only when a sub-agent contributed usage AND
  // include_sidechains is false (the default) — reported as its own
  // separate total, never folded into whichever task happened to be open.
  sidechain?: TaskCostBucket | null;
  // unmatched_count is the "N items could not be matched" substrate.
  // all_keys_native tells a surface whether to suppress that caveat
  // entirely — a genuinely keyed tool never loses an item to a wording
  // change.
  unmatched_count: number;
  all_keys_native: boolean;
  // match_mode / concurrent_attribution / include_sidechains echo the
  // [tasks] config this report was computed under.
  match_mode: string;
  concurrent_attribution: string;
  include_sidechains: boolean;
  // cost_note is the fixed "list pricing, never a billed amount"
  // disclaimer, populated whenever this report carries any cost figure —
  // render it verbatim.
  cost_note?: string;
};

// ToolTaskRollup is one tool's slice of a TaskRollup.
export type ToolTaskRollup = {
  tool: string;
  sessions: number;
  tasks: number;
  cost_usd: number;
  // unpriced mirrors TaskCostBucket.unpriced at tool granularity: true
  // when at least one row folded into this tool's cost_usd had neither
  // a recorded provider cost nor a pricing-table entry for its model —
  // render "unpriced", never imply cost_usd is the true total.
  unpriced: boolean;
};

export type TaskLifecycleCounts = {
  created: number;
  completed: number;
  cancelled: number;
  never_activated: number;
  still_open: number;
  unmatched: number;
  all_sessions_keys_native: boolean;
};

// TaskRollup is GET /api/tasks's payload — a project/tool/window aggregate.
export type TaskRollup = {
  since_unix?: number;
  until_unix?: number;
  project_id?: number;
  // project_root / tool echo the string-keyed filters (project root
  // path / session tool) a caller passed to GET /api/tasks — the
  // dashboard's global project filter never resolves to a numeric id.
  project_root?: string;
  tool?: string;
  sessions_with_tasks: number;
  attributed_single: TaskCostBucket;
  between_tasks: TaskCostBucket;
  shared: TaskCostBucket;
  counts: TaskLifecycleCounts;
  by_tool: ToolTaskRollup[];
  cost_note?: string;
};

// Output Composition (Verbosity) — GET /api/session/<id>/verbosity.
export type VerbosityLangBytes = {
  language: string;
  bytes: number;
  category: string;
};

export type VerbosityResponse = {
  session_id: string;
  total_bytes: number;
  code_bytes: number;
  explain_bytes: number;
  code_pct: number;
  explain_pct: number;
  code_explain_ratio?: number;
  by_category: Record<string, number>;
  channels: {
    narrative_bytes: number;
    artifact_bytes: number;
    artifact_untagged_bytes: number;
    written_bytes: number;
    command_bytes: number;
  };
  code_by_language: VerbosityLangBytes[];
  unknown_ext?: VerbosityLangBytes[];
  authored_captured: boolean;
  authored_measured_actions: number;
  authored_total_actions: number;
  backfill_recommended: boolean;
  backfill_settings_url: string;
  // Estimated token/$ attribution (plan §7) — labelled "est." on the card.
  // cost_estimated is false (and the $ figures absent) when there is no
  // priced model or no token rows for the session.
  cost_estimated: boolean;
  model?: string;
  est_output_tokens?: number;
  est_reasoning_tokens?: number;
  est_code_tokens?: number;
  est_explain_tokens?: number;
  est_code_usd?: number;
  est_explain_usd?: number;
  est_total_usd?: number;
};

// Output Composition cross-session rollup — GET /api/verbosity/aggregate.
export type VerbosityAggregateGroup = {
  key: string;
  code_bytes: number;
  explain_bytes: number;
  total_bytes: number;
  code_pct: number;
  explain_pct: number;
  code_explain_ratio?: number;
  top_languages: VerbosityLangBytes[];
  est_total_usd?: number;
  cost_estimated: boolean;
};

export type VerbosityAggregateResponse = {
  by: string;
  since_days: number;
  groups: VerbosityAggregateGroup[];
};

// ---------- /api/cache/overview (C14) ----------

export type CacheOverviewGlobal = {
  efficiency: {
    read_tokens: number;
    written_tokens: number;
    ratio: number;
    avoidable_usd: number;
  };
  event_count: number;
  session_count: number;
};

export type CacheOverviewModelRollup = {
  model: string;
  efficiency: {
    read_tokens: number;
    written_tokens: number;
    ratio: number;
    avoidable_usd: number;
  };
  event_count: number;
};

export type CacheOverviewProjectRollup = {
  project_id: number;
  project_root: string;
  efficiency: {
    read_tokens: number;
    written_tokens: number;
    ratio: number;
    avoidable_usd: number;
  };
  event_count: number;
};

export type CacheOverviewCauseRow = {
  cause: string;
  count: number;
  flagged?: boolean;
};

export type CacheOverviewSessionRow = {
  session_id: string;
  model: string;
  // Capture-path label rolled across this session's rewrite events:
  // "proxy" (Tier-1 live), "transcript" (Tier-2 backfill), or
  // "mixed" when both contributed. Omitted on rows with no tier
  // attribution (legacy events on pre-cachetrack corpora).
  tier?: string;
  rewrite_count: number;
  tokens_read: number;
  tokens_written: number;
  top_cause?: string;
};

export type CacheOverviewResponse = {
  global: CacheOverviewGlobal;
  per_model: CacheOverviewModelRollup[];
  per_project: CacheOverviewProjectRollup[];
  top_causes: CacheOverviewCauseRow[];
  worst_sessions: CacheOverviewSessionRow[];
};

// ---------- /api/cache/timeseries ----------

export type CacheTimeseriesPoint = {
  bucket: string;
  read_tokens: number;
  written_tokens: number;
  event_count: number;
  rewrite_count: number;
};

export type CacheTimeseriesResponse = {
  metric: "cache";
  bucket: "day";
  days: number;
  series: CacheTimeseriesPoint[];
};

// ---------- /api/cache/health ----------

export type CacheHealthDominantCause = {
  cause: string;
  count: number;
  share: number;
};

export type CacheHealthSummary = {
  graded_events: number;
  mispredicts: number;
  mispredict_rate: number;
  min_events_threshold: number;
  max_rate_threshold: number;
  gate_passed: boolean;
  bucket_mispredicts: number;
  inconsistent_rewrite_count: number;
  dominant_cause?: CacheHealthDominantCause;
  // Count of non-Anthropic api_turns rows over the last 7 days —
  // the proxy captured them (cost / tokens / model attribution all
  // work) but cachetrack didn't observe them because the engine's
  // attribution rules are Anthropic-shaped. Drives the info banner
  // on the Cache page that explicitly acknowledges "we saw N
  // codex sessions, just couldn't grade them" so the operator
  // doesn't read the empty Cache page as a bug.
  untracked_provider_turns?: number;
  untracked_provider_sessions?: number;
  untracked_provider_top_tool?: string;
  // §15.3 implicit-cache surfaces. Counts events whose kind is in
  // the implicit-cache closed set (implicit_hit / implicit_miss /
  // implicit_write). These events are EXCLUDED from
  // mispredict_rate / graded_events / mispredicts above (the
  // Anthropic gate) by design — the dashboard surfaces them
  // separately so operators can grade implicit-cache quality
  // without contaminating the soak-validated Anthropic signal.
  implicit_cache_events?: number;
  implicit_cache_hits?: number;
  implicit_cache_misses?: number;
  implicit_cache_writes?: number;
  // Consistency = (predicted == observed) / graded; the implicit-
  // cache analog of mispredict_rate. Bootstrap implicit_write
  // turns are excluded from the denominator.
  implicit_cache_consistency_rate?: number;
  implicit_cache_consistency_denom?: number;
  // hits / (hits + misses) — the prefix-survival rate.
  implicit_cache_prefix_churn_rate?: number;
};

// ---------- /api/cache/status ----------

export type CacheWindow = {
  model: string;
  scope: string;
  session_id: string;
  prefix_tokens: number;
  ttl_tier: string;
  expires_at: string;
  last_refresh: string;
  expiry_authoritative: boolean;
  refreshable_by_patch: boolean;
  supports_1h_tier: boolean;
  value_at_risk_usd: number;
};

export type CacheKeepWarmRecommendation = {
  action: "none" | "use_1h_tier" | "patch_ttl" | "replay_ping";
  pays_off: boolean;
  projected_savings_usd: number;
  resume_confidence: number;
  rationale: string;
};

export type CacheWindowStatus = {
  window: CacheWindow;
  severity: "ok" | "soon" | "critical" | "cold";
  seconds_to_expiry: number;
  value_at_risk_usd: number;
  estimated: boolean;
  recommendation: CacheKeepWarmRecommendation;
};

export type CacheStatusResponse = {
  enabled: boolean;
  keepwarm_mode: "off" | "advise" | "enforce";
  windows: CacheWindowStatus[] | null;
};

// ---------- /api/cloud/status + /api/cloud/session/<id> ----------
//
// Cloud Intelligence (Signed-in Free spine). Node-local state ONLY — nothing
// here reflects hosted-service state. sign_in is the LOCAL credential presence
// (a keychain read the daemon does through an injected seam, never a network
// call); it is absent when the dashboard runs without that seam. See plan §6
// CI-P5 and internal/intelligence/dashboard/cloud_account.go.

// CloudSignInView is the `sign_in` block on /api/cloud/status.
export type CloudSignInView = {
  // known=false ⇒ the probe is unwired or failed (error set); presence
  // fields are then meaningless.
  known: boolean;
  error?: string;
  // Derived headline: a WorkOS sign-in OR an API token is stored locally.
  signed_in: boolean;
  api_token_present: boolean;
  workos_sign_in_present: boolean;
  credential_backend?: string;
  // A WorkOS client id resolves (WORKOS_CLIENT_ID env, else
  // [cloud].workos_client_id). Without one Sign in cannot start.
  client_id_configured: boolean;
  login_running: boolean;
  // The Sign in / Sign out routes are wired (a subprocess runner exists).
  actions_available: boolean;
};

// CloudLoginState is GET /api/cloud/login/state (and the POST /api/cloud/login
// response): the one-at-a-time `observer cloud login` subprocess.
export type CloudLoginState = {
  running: boolean;
  // The AuthKit authorize URL captured from the child's output, once printed —
  // the manual fallback when the automatic browser open does not reach you.
  auth_url?: string;
  finished: boolean;
  ok: boolean;
  message?: string;
  started_at?: string;
  finished_at?: string;
};

export type CloudLogoutResponse = {
  ok: boolean;
  message?: string;
};

// CloudSyncState is GET /api/cloud/sync/state (and the POST /api/cloud/sync
// response): the one-at-a-time `observer cloud sync` subprocess — the
// dashboard equivalent of the CLI verb.
export type CloudSyncState = {
  session_id?: string;
  running: boolean;
  started_at?: string;
  finished_at?: string;
  // Absent/null until the run finishes (never run yet, or still running).
  ok?: boolean | null;
  exit_error?: string;
  // Last ~2KB of the child's combined stdout+stderr.
  tail?: string;
  // Store-derived — the newest synced enrichment result's received_at, the
  // same fact CloudStatusResponse.last_result_at reports.
  last_result_at?: string;
};

// CloudConfigView mirrors the editable [cloud] keys as GET /api/config
// reports them (Go field names) and PUT /api/config/section/cloud accepts.
export type CloudConfigView = {
  BaseURL: string;
  LoginPort: number;
  AutoSync: boolean;
  AutoSyncIntervalMinutes: number;
  AutoEnrich: boolean;
  WorkOSClientID: string;
};

export type CloudStatusResponse = {
  // active is store-derived (any receipt / outbox item / result / cursor), NOT
  // a sign-in state. false drives the honest optional-feature empty copy.
  active: boolean;
  receipts_total: number;
  receipts_live: number;
  // Every outbox state → count, incl. reconfirmation_required and terminals.
  outbox_by_state: Record<string, number>;
  outbox_total: number;
  // pending + failed_retryable subset (the manual drain set).
  sendable_count: number;
  results_total: number;
  last_result_at?: string;
  has_synced: boolean;
  // Always false this arc — allowance is server-reported at sync, never stored
  // node-side, so the UI shows an honest placeholder.
  allowance_known: boolean;
  descriptor: string;
  // Local sign-in presence; absent when the account seam is not wired.
  sign_in?: CloudSignInView | null;
};

export type CloudOutboxView = {
  id: string;
  state: string;
  retry_count: number;
  last_error?: string;
  receipt_id: string;
  created_at?: string;
  updated_at?: string;
};

export type CloudReceiptView = {
  id: string;
  purpose?: string;
  invalidated: boolean;
  created_at?: string;
};

export type CloudOverrideView = {
  user_value: string;
  updated_at?: string;
};

export type CloudResultView = {
  schema_version?: string;
  received_at?: string;
  model_route?: string;
  // The AI-suggested session_enrichment payload (title, taxonomy_tags,
  // suggested_tags, description, …), passed through as raw JSON.
  result: {
    title?: string;
    taxonomy_tags?: string[];
    suggested_tags?: string[];
    description?: string;
    confidence?: string;
    // limitations enumerates what the enrichment did NOT observe; evidence_refs
    // are identifiers into the evidence envelope the result cites. Both are
    // ordinary string lists per internal/cloudcontract/result.go, but rendered
    // defensively (never raw JSON) in case an older/foreign payload nests an
    // object per entry instead.
    limitations?: string[];
    evidence_refs?: unknown[];
    // The five NARRATIVE lists (internal/cloudcontract/result.go): what the
    // session did, whether the stated plans landed, what is broken, what
    // failed or is unresolved, and what to do next. All optional - a result
    // stored before these fields existed simply has none of them.
    work_done?: string[];
    plans_implemented?: string[];
    issues_found?: string[];
    failures?: string[];
    next_steps?: string[];
    [k: string]: unknown;
  };
  // field → user edit; the user value always wins visually.
  overrides?: Record<string, CloudOverrideView>;
};

export type CloudSessionResponse = {
  progress?: CloudEnrichmentProgress;
  session_id: string;
  // The pseudonym (e.g. "cs_...") this device already minted for the session
  // in the node-local cloud_session_map, if any — the ONLY identifier the
  // cloud service itself ever sees for this session. Absent when the session
  // has never been enrolled for cloud enrichment; a GET never mints one.
  cloud_session_id?: string;
  authority: string;
  authority_version?: number;
  eligible: boolean;
  excluded: boolean;
  excluded_reason?: string;
  receipts: CloudReceiptView[];
  outbox: CloudOutboxView[];
  result?: CloudResultView | null;
};

export type CloudEnrichmentProgress = {
  state: string;
  last_error?: string;
  updated_at?: string;
};

// ---------- Cloud actions: preview / consent / grants / delete-account ----------
//
// The session-card and Settings controls behind every remaining
// `observer cloud` CLI verb (operator directive: every verb needs a
// dashboard equivalent). Every one of these runs the identical consent-gated
// CLI as a bounded subprocess through CloudCommandRunner — see
// internal/intelligence/dashboard/cloud_account.go's header comment for the
// zero-egress invariant these routes preserve.

// CloudPurpose is the closed two-value consent-purpose vocabulary a preview
// or consent call names. "Title only" in the UI == structural_activity_insights
// alone; "Title, tags and description" == bounded_context_enrichment (which
// always implies and includes the structural purpose too).
export type CloudPurpose =
  | "structural_activity_insights"
  | "bounded_context_enrichment";

// CloudPreviewResponse is POST /api/cloud/preview: `cloud preview --session
// <id> --purpose <p>` run synchronously (bounded 90s, local-only — no
// network, so this never refuses on sign-in state). output is the child's
// combined stdout+stderr, capped at 256 KiB keeping the HEAD; truncated says
// whether the cap was hit.
export type CloudPreviewResponse = {
  upload_digest?: string;
  ok: boolean;
  output: string;
  exit_error?: string;
  truncated: boolean;
};

// CloudActionResponse is the shape shared by the simple one-shot action
// verbs (consent grant, consent revoke, delete-account): `cloud <verb> …`
// run synchronously.
export type CloudActionResponse = {
  ok: boolean;
  output: string;
  exit_error?: string;
};

// CloudConsentResponse is POST /api/cloud/consent: computes the purpose SET
// for the chosen purpose (structural → itself alone; bounded → itself plus
// structural), grants any missing standing receipt in that set when
// grant_standing is true, then records the session-scoped consent. granted
// lists only the purposes that newly received a standing grant during this
// call (already-live ones are not repeated here).
export type CloudConsentResponse = {
  ok: boolean;
  output: string;
  exit_error?: string;
};

// CloudConsentMissingError is the 409 JSON body when consent was posted with
// grant_standing:false but at least one purpose in the set has no live
// standing receipt yet.
export type CloudConsentMissingError = {
  error: "standing_grant_missing";
  missing: string[];
};

// CloudGrantMode mirrors store.CloudGrantMode's two values the way
// `observer cloud consent list` prints them; an empty/unset mode reads as
// per_upload.
export type CloudGrantMode = "standing" | "per_upload";

// CloudConsentGrantRow is one consent RECEIPT already on this device
// (GET /api/cloud/consent/grants "receipts", from store.ListCloudConsentReceipts).
export type CloudConsentGrantRow = {
  id: string;
  purpose: string;
  mode: CloudGrantMode;
  created_at: string;
  review_at?: string;
  invalidated_at?: string | null;
  live: boolean;
};

// CloudGrantable is one purpose this device COULD grant standing consent
// for (cloudgateway.StandingGrantable), with an honest reason when it
// cannot — never fabricated, shown as locked with `reason` in the UI.
export type CloudGrantable = {
  purpose: string;
  ok: boolean;
  reason?: string;
};

// CloudGrantsResponse is GET /api/cloud/consent/grants.
export type CloudGrantsResponse = {
  receipts: CloudConsentGrantRow[];
  grantable: CloudGrantable[];
};

// ---------- /api/cache/events ----------

export type CacheEventRow = {
  id: number;
  timestamp: string;
  session_id: string;
  model: string;
  tier: string;
  kind: string;
  cause?: string;
  predicted_kind?: string;
  tokens_read: number;
  tokens_written: number;
};

export type CacheEventsResponse = {
  rows: CacheEventRow[];
  total: number;
  limit: number;
  offset: number;
};

// ---------- /api/cache/entry-states ----------

export type CacheEntryStateRow = {
  state: string;
  count: number;
};

export type CacheEntryStatesResponse = {
  rows: CacheEntryStateRow[];
  total: number;
};

// ---------- /api/session/<id>/messages ----------

export type ToolCallRow = {
  // action_id is the actions.id primary key, used by the on-demand
  // /api/action/<id>/full_text endpoint when the copy / view-full-text
  // buttons need the untruncated body. Zero only on synthesized rows
  // (orphan-token stubs); skip the fetch for those.
  action_id: number;
  action_type: string;
  raw_tool_name: string;
  target: string;
  full_text?: string;
  // full_text_elided is true when raw_tool_input exceeded the per-row
  // inline cap (4 KiB) and was truncated for the /messages payload.
  // The UI must fetch /api/action/<id>/full_text for the untruncated
  // body before showing or copying.
  full_text_elided?: boolean;
  // has_full_output is true when actions.raw_tool_output is non-empty
  // for this row — i.e. the adapter captured a tool_result body that's
  // available via /api/action/<id>/full_text. The inline `excerpt`
  // stays 2 KiB (FTS5 cap); this flag tells the UI there's a fuller
  // version to offer behind the view-full-text affordance.
  has_full_output?: boolean;
  excerpt?: string;
  success: boolean;
  error_message?: string;
  timestamp: string;
  duration_ms?: number;
  permission_mode?: string;
  effort_level?: string;
  is_interrupt?: boolean;
  stop_reason?: string;
  service_tier?: string;
  // Browser-capture API-call details, populated only on browserchat
  // (chatgpt-web / claude-web / perplexity-web / gemini-web /
  // copilot-web) assistant_message rows — the upstream request path,
  // the extension's per-turn id provenance, the effective capture
  // granularity, and the estimated prompt/response token counts.
  // Absent for every coding-agent adapter.
  request_url?: string;
  id_source?: string;
  granularity?: string;
  prompt_tokens_est?: number;
  response_tokens_est?: number;
};

// ---------- /api/action/<id>/full_text ----------
// Returned by the on-demand fetch when the operator clicks a copy /
// view-full-text button. Both raw_tool_input + raw_tool_output are
// adapter-capped at 1 MiB; rows that overflowed adapter capture carry
// the trailing "…(content truncated at N bytes)…" marker so the UI
// can surface the truncation honestly.
export type ActionFullText = {
  action_id: number;
  action_type: string;
  target?: string;
  raw_tool_input?: string;
  raw_tool_output?: string;
};

export type ToolAccountEvidence = {
  key: string; email?: string; name?: string; account_id?: string;
  source: string; scope: string; stage: string; observed_at: string;
};
export type MessageAccount = {
  status: "observed" | "unknown" | "conflict";
  label: string;
  evidence: ToolAccountEvidence[];
};
export type MessageRow = {
  account?: MessageAccount;
  // seq is the row's 1..N ordinal in CHRONOLOGICAL order, assigned
  // server-side over the whole timeline. Stable across pagination and
  // across any sort_by reordering — the "#" column renders it (a
  // page-relative index would renumber under a non-default sort).
  // Non-optional on purpose: the handler assigns it unconditionally, and a
  // `?? i + 1` style fallback in a renderer would silently reinstate exactly
  // the page-relative numbering this field exists to replace. It also doubles
  // as the row-identity fallback for React keys when message_id is empty.
  seq: number;
  message_id: string;
  timestamp: string;
  role: string;
  model?: string;
  input: number;
  output: number;
  cache_read: number;
  cache_creation: number;
  cache_creation_1h: number;
  reasoning?: number;
  web_search_requests?: number;
  cost_usd: number;
  ai_cost_usd: number;
  tool_cost_usd: number;
  elapsed_ms?: number;
  // tps_ms is the denominator the Tok/s column divides output by — the
  // best available timing source the backend picked (see tps_basis).
  // Absent when no source applies (e.g. a single-inference non-proxied
  // codex turn) → Tok/s shows "—".
  tps_ms?: number;
  // tps_basis names which timing source tps_ms came from, for the Tok/s
  // tooltip: "measured" (proxy total_response_ms — the real per-call
  // wall-clock), "intra-turn" (MAX−MIN of a codex user-turn's
  // per-inference timestamps), or "elapsed" (gap-to-next-message, the
  // claude-code fallback).
  tps_basis?: "measured" | "intra-turn" | "elapsed";
  tool_duration_ms?: number;
  tool_call_count: number;
  // Per-turn reasoning effort — codex collaboration_mode.settings
  // .reasoning_effort, antigravity SKU-encoded (low/medium/high), or
  // any other adapter that captures a reasoning-effort knob. Empty
  // when the adapter doesn't expose one (Anthropic models, etc.).
  effort_level?: string;
  // Per-turn terminal reason (end_turn / max_tokens / tool_use /
  // stop_sequence / refusal) + served capacity tier (standard /
  // priority / batch), from the transcript. Empty when not captured.
  stop_reason?: string;
  service_tier?: string;
  // Fast indicates this turn was served in the provider's low-latency
  // "fast" tier (Anthropic Opus 4.8 speed:"fast"). cost_usd already
  // carries the 2x FastMultiplier premium. Renders a FAST badge.
  fast?: boolean;
  tool_calls: ToolCallRow[];
};

// NOTE: envelope key is `messages` (not `rows`) — different from
// /api/sessions and /api/actions. Confirmed in dashboard.go:1357.
export type SessionMessages = {
  account_summary?: { accounts: ToolAccountEvidence[]; observed: number; unknown: number; conflicts: number };
  session_id: string;
  messages: MessageRow[];
  total: number;
  limit: number;
  offset?: number;
};

// ---------- /api/session/<id>/raw-events ----------

export type RawEventSource = {
  path: string;
  rows: number;
  error?: string;
};

export type RawEventRow = {
  source_file: string;
  source_index: number;
  line: number;
  byte_offset: number;
  bytes: number;
  timestamp?: string;
  type?: string;
  payload_type?: string;
  role?: string;
  event_id?: string;
  valid_json: boolean;
  excerpt: string;
  excerpt_truncated?: boolean;
};

export type SessionRawEvents = {
  session_id: string;
  tool?: string;
  sources: RawEventSource[];
  rows: RawEventRow[];
  total: number;
  limit: number;
  offset: number;
  truncated?: boolean;
};

// ---------- /api/actions (Phase 4 extended) ----------

export type ActionListRow = {
  id: number;
  timestamp: string;
  tool: string;
  session_id: string;
  project: string;
  action_type: string;
  raw_tool_name: string;
  target: string;
  success: boolean;
  error_message?: string;
  message_id: string;
  permission_mode?: string;
  effort_level?: string;
  is_interrupt?: boolean;
  stop_reason?: string;
  service_tier?: string;
  // Source provenance — which JSONL / proxy capture produced this
  // row. May be empty for synthesized rows where the adapter doesn't
  // track an origin file.
  source_file?: string;
  source_event_id?: string;
  // First 280 chars of the action's indexed body (FTS5 excerpt).
  // Surfaces "what did the tool actually do" inline.
  excerpt?: string;
};

export type ActionsResponse = {
  rows: ActionListRow[];
  page: number;
  limit: number;
  total: number;
};

// ---------- /api/discover ----------

export type StaleReadFile = {
  file_path: string;
  project: string;
  stale_count: number;
  cross_thread_stale_count: number;
  total_reads: number;
  est_wasted_tokens: number;
  file_size_bytes: number;
};

export type RepeatedCommand = {
  command: string;
  command_hash: string;
  project: string;
  total_runs: number;
  no_change_reruns: number;
  successful_runs: number;
  failed_runs: number;
};

export type CrossToolFile = {
  file_path: string;
  project: string;
  tools: string[];
  accesses: number;
};

export type DiscoverSummary = {
  total_actions: number;
  stale_read_count: number;
  cross_thread_stale_count: number;
  est_wasted_tokens: number;
  repeated_command_groups: number;
  cross_tool_file_count: number;
  native_action_count: number;
  bash_action_count: number;
};

export type DiscoverResponse = {
  stale_reads: StaleReadFile[] | null;
  stale_total: number;
  stale_page: number;
  stale_limit: number;
  repeated_commands: RepeatedCommand[] | null;
  repeated_total: number;
  repeated_page: number;
  repeated_limit: number;
  cross_tool_files: CrossToolFile[] | null;
  native_vs_bash: unknown;
  summary: DiscoverSummary;
  blended_input_rate_per_million: number;
};

// ---------- /api/patterns ----------

export type PatternType =
  | "hot_file"
  | "cs_change"
  | "edit_test_pair"
  | "knowledge_snippet"
  | "command";

export type PatternRow = {
  project: string;
  pattern_type: string;
  data: string;
  confidence: number;
  observation_count: number;
};

export type PatternsResponse = {
  rows: PatternRow[];
  page: number;
  limit: number;
  total: number;
};

// ---------- /api/patterns/timeseries ----------

export type PatternsTimeseriesPoint = {
  day: string;
  total: number;
  by_type: Record<string, number>;
};

export type PatternsTimeseries = {
  days: number;
  points: PatternsTimeseriesPoint[];
};

// ---------- /api/compression/by-model ----------

export type CompressionByModelRow = {
  model: string;
  mechanism: string;
  events: number;
  original_bytes: number;
  compressed_bytes: number;
  saved_bytes: number;
  saved_tokens_est: number;
  saved_usd_est: number;
  // lossy marks an eviction mechanism (e.g. `drop`): original_bytes was
  // removed, not compressed. saved_* are 0; the bytes surface as
  // evicted_bytes and must render as "evicted", never as savings.
  lossy: boolean;
  evicted_bytes: number;
};

export type CompressionByModelResponse = {
  days: number;
  rows: CompressionByModelRow[];
};

// ---------- /api/compression/events ----------

export type CompressionEvent = {
  id: number;
  api_turn_id: number;
  timestamp: string;
  mechanism: string;
  original_bytes: number;
  compressed_bytes: number;
  saved_bytes: number;
  original_tokens_est: number;
  compressed_tokens_est: number;
  saved_tokens_est: number;
  saved_usd_est: number;
  msg_index: number;
  importance_score: number;
  model: string;
  session_id: string;
  message_id: string;
  is_subagent_runtime: boolean;
  // lossy marks an eviction mechanism (e.g. `drop`): original_bytes was
  // removed, not compressed. saved_* are 0; evicted_bytes carries the
  // removed volume and must render as "evicted", never as savings.
  lossy: boolean;
  evicted_bytes: number;
};

export type CompressionEventsResponse = {
  rows: CompressionEvent[];
  page: number;
  limit: number;
  total: number;
};

// ---------- /api/compression/timeseries ----------

export type CompressionMechStats = {
  count: number;
  original_bytes: number;
  compressed_bytes: number;
  saved_bytes: number;
  saved_usd_est: number;
  // lossy marks an eviction mechanism (e.g. `drop`): saved_bytes /
  // saved_usd_est are 0 and evicted_bytes carries the removed volume.
  lossy: boolean;
  evicted_bytes: number;
};

export type CompressionTimeseriesPoint = {
  bucket: string;
  by_mechanism: Record<string, CompressionMechStats>;
  total_saved_bytes: number;
  total_saved_usd_est: number;
  total_count: number;
  // total_evicted_bytes is the byte volume removed by lossy-eviction
  // mechanisms in this bucket — excluded from total_saved_bytes.
  total_evicted_bytes: number;
};

export type CompressionTimeseries = {
  metric: "compression_events";
  days: number;
  series: CompressionTimeseriesPoint[];
};

// ---------- /api/compression/retrieval ----------

export type ShaCount = { sha: string; count: number };
export type ActionIdCount = { action_id: number; count: number };

export type StashedSample = {
  sha: string;
  snippet: string;
  bytes: number;
  count: number;
  retrieved_count: number;
};

export type CompressionRetrieval = {
  days: number;
  stash_retrievals: number;
  search_hits: number;
  total_stashes: number;
  retrieve_rate: number;
  top_retrieved_shas: ShaCount[];
  top_searched_actions: ActionIdCount[];
  stashed_samples: StashedSample[];
  hints: unknown[];
};

// ---------- /api/compaction/events ----------

export type CompactionEvent = {
  id: number;
  session_id: string;
  timestamp: string;
  tool: string;
  pre_action_count: number;
  injected_at?: string;
  ghost_files_after_count: number;
  file_snapshot_count: number;
};

export type CompactionEventsResponse = {
  days: number;
  count: number;
  sessions_affected: number;
  injections_fired: number;
  events: CompactionEvent[];
};

// ---------- /api/compression/rolling-cost ----------

export type CompressionRollingCost = {
  days: number;
  summary_calls: number;
  summary_input_tokens: number;
  summary_output_tokens: number;
  summary_cost_usd: number;
  rolling_savings_bytes: number;
  rolling_savings_tokens_est: number;
  rolling_savings_cost_usd_est: number;
  net_delta_usd: number;
};

// ---------- /api/setup/claude + /api/setup/codex ----------

export type SetupClaude = {
  tool: "claude";
  proxy_port: number;
  proxy_url: string;
  credentials_path: string;
  has_oauth_credentials: boolean;
  claude_binary_found: boolean;
  claude_binary_path?: string;
  launcher_command: string;
  status: "oauth_ready" | "api_key_ready" | "claude_not_installed" | string;
  // Durable routing state — the env.ANTHROPIC_BASE_URL block in
  // ~/.claude/settings.json (managed by POST /api/setup/claude).
  settings_path?: string;
  routed_base_url?: string;
  routed_to_observer: boolean;
  would_register: boolean;
  would_register_error?: string;
};

// SetupRoutePostResponse is the shared POST /api/setup/{claude,codex}
// response shape (claudeSetupPostResponse / codexSetupPostResponse
// server-side). Snapshot is the tool's fresh GET snapshot.
export type SetupRoutePostResponse = {
  tool: string;
  config_path: string;
  base_url: string;
  added: boolean;
  already_set: boolean;
  dry_run: boolean;
  error?: string;
};

export type SetupCodex = {
  tool: "codex";
  config_path: string;
  config_exists: boolean;
  proxy_port: number;
  desired_base_url: string;
  desired_model_provider: string;
  current_base_url?: string;
  current_model_provider?: string;
  has_reserved_openai_block: boolean;
  auth_mode?: string;
  status: string;
  would_register: boolean;
  would_register_error?: string;
};

// ---------- /api/tools/breakdown ----------

// Capture-depth honesty block (taxonomy plan §4). expressible_categories
// is 0 AND vocabulary_declared false when tooltax has no rows for the
// tool — an honest "not mapped", not "expresses nothing".
export type ToolBreakdownCoverage = {
  observed_categories: number;
  expressible_categories: number;
  // How many observed categories fall OUTSIDE the declared vocabulary.
  // observed_categories can exceed expressible_categories (the shared
  // mcp__ rule and harness failure/meta events belong to no adapter's
  // declared vocabulary), so the two are never a ratio — this key is
  // what explains the excess. See lib/actions.ts::coverageCaption.
  observed_beyond_declared: number;
  canonical_categories: number;
  vocabulary_declared: boolean;
};

export type ToolBreakdown = {
  tool: string;
  total: number;
  by_type: Record<string, number>;
  // Canonical taxonomy dimensions, computed server-side through
  // internal/tooltax at query time (never stored). by_surface is keyed on
  // the canonical surfaces plus "unresolved" for rows whose native tool
  // name did not resolve.
  by_category: Record<string, number>;
  by_surface: Record<string, number>;
  coverage: ToolBreakdownCoverage;
};

export type ToolsBreakdownResponse = {
  days: number;
  // The canonical key spaces, in tooltax display order.
  categories: string[];
  surfaces: string[];
  tools: ToolBreakdown[];
};

// ---------- /api/config ----------

// ModelPricing matches config.ModelPricing 1:1 — the keys come from
// the Go field names (no JSON tag → PascalCase in JSON), so the TS
// shape mirrors that.
export type ModelPricing = {
  Input: number;
  Output: number;
  CacheRead: number;
  CacheCreation: number;
  CacheCreation1h: number;
  LongContextThreshold: number;
  LongContextInput: number;
  LongContextOutput: number;
  LongContextCacheRead: number;
  LongContextCacheCreation: number;
  LongContextCacheCreation1h: number;
};

export type IntelligenceConfig = {
  CodeGraph: { Enabled: boolean };
  Pricing: { Models: Record<string, ModelPricing> };
  APIKeyEnv: string;
  SummaryModel: string;
  MonthlyBudgetUSD: number;
};

// The full Config object — most sections are opaque to the dashboard
// (we render them as read-only JSON). Intelligence + a few others
// are typed enough to drive forms.
export type ConfigShape = {
  Observer: Record<string, unknown>;
  Intelligence: IntelligenceConfig;
  Proxy: Record<string, unknown>;
  Compression: Record<string, unknown>;
  [key: string]: unknown;
};

export type ConfigResponse = {
  config_path: string;
  config: ConfigShape;
  editable_sections: string[];
  // Every resolvable compression profile — built-ins + user profiles
  // (P3.4). Dynamic option source for the Settings Profiles selects.
  profile_names?: string[];
  // T2 credential redaction (config plan §4.3 / P0-1). The daemon never
  // sends credential VALUES: [selfobs].secret, [selfobs].token,
  // [observer.process.etw].token and [routing].key_pool come back as
  // redacted_sentinel instead. This map is dotted config path → whether a
  // value is configured there, so a surface that wants to mention a
  // credential renders a read-only "credential configured" state from the
  // boolean and never an editable control. Writing a credential is refused
  // with 403; sending the sentinel back preserves what is on disk.
  redacted_secrets?: Record<string, boolean>;
  // The exact placeholder substituted above, so nothing has to hardcode it.
  redacted_sentinel?: string;
  // Optimistic-concurrency base for PUT /api/config/keys: sha256 of the
  // file bytes as served. A stale value gets a 409 naming the diverged keys
  // (dashboard-config-management plan §2.4).
  config_etag?: string;
  // Double-submit confirm token the sensitive-tier (T1) keys must echo in
  // X-Observer-Confirm on PUT /api/config/keys.
  confirm_token?: string;
  // Wire-shape version of GET /api/config/schema this daemon serves.
  schema_version?: number;
};

// GET /api/tools/status — the Connected-tools matrix (P4.1). One row
// per supported tool; nil probes mean the integration doesn't exist
// for that tool (n/a, not false).
export type ToolProbe = {
  registered: boolean;
  partial?: boolean;
  detail?: string;
};

export type ToolStatusRow = {
  tool: string;
  detected: boolean;
  detected_path?: string;
  enabled: boolean;
  action_count: number;
  last_seen_at?: string;
  hooks?: ToolProbe;
  mcp?: ToolProbe;
  proxy?: ToolProbe;
};

export type ToolsStatusResponse = {
  tools: ToolStatusRow[];
  generated_at: string;
};

// GET /api/mcp/value — the MCP value meter (P4.10). Mirrors the
// advisor's mcp_overhead math (~1,900 schema tokens/turn; 3 calls per
// 100 turns = worth-it line). verdict no_data covers BOTH "no turns"
// and "audit disabled" — silence with audit off means invisibility,
// not absence.
export type MCPValueResponse = {
  window_days: number;
  audit_enabled: boolean;
  calls: number;
  ok_calls: number;
  denied_calls: number;
  bytes_returned: number;
  by_tool: { tool: string; calls: number; bytes: number }[];
  turns_estimate: number;
  calls_per_100_turns: number;
  overhead_tokens_estimate: number;
  schema_tokens_per_turn: number;
  threshold_calls_per_100: number;
  verdict: "active" | "low_use" | "unused" | "no_data";
};

// POST /api/tools/launch — best-effort terminal launch (P4.6).
// command is ALWAYS set (the copy-paste fallback); spawned=false with
// detail is the honest no-spawn outcome, never an error state.
export type ToolLaunchResponse = {
  tool: string;
  routed: boolean;
  command: string;
  method: string;
  spawned: boolean;
  detail?: string;
};

// GET /api/health/doctor — the `observer doctor` checks (P4.8).
export type DoctorReport = {
  checks: {
    name: string;
    status: "ok" | "warn" | "fail";
    message: string;
    details?: string[];
  }[];
  ok: number;
  warn: number;
  fail: number;
  all_ok: boolean;
  generated_at: string;
  // local_detail_withheld marks this response as the remote-facing
  // projection: the caller reached the route over a remotely-exposed
  // listener, so every filesystem root the daemon could identify has
  // been rewritten to a placeholder ("~", "<config>", "<db>", "<exe>",
  // "<tmp>", "<token-file>", "<other-home>"/"<other-home-N>") in each
  // check's message and details. Checks, statuses and counts are
  // unchanged. It is NOT a claim of complete redaction — paths under no
  // known root, OS-convention paths like /etc/codex/*.toml, and the org
  // enrolment check's user email all survive it.
  //
  // OPTIONAL ON THE WIRE, two ways: the Go field carries `omitempty`, so
  // even a current daemon omits it on the local projection, and a daemon
  // older than this feature never sends it at all. `undefined` therefore
  // means "not withheld" and must render exactly like `false` — never as
  // a banner.
  local_detail_withheld?: boolean;
};

// GET /api/health/failures — recent failures grouped by command
// (P4.11). recovered = at least one attempt in the group eventually
// succeeded; the error/session/project fields come from the group's
// most recent failure.
export type HealthFailuresResponse = {
  window_days: number;
  total: number;
  failures: {
    command: string;
    fails: number;
    retries: number;
    recovered: boolean;
    last_at: string;
    error_category?: string;
    error_message?: string;
    session_id: string;
    project?: string;
  }[];
};

// GET /api/setup/codex-hooks — codex per-hook trust state (P4.3).
// Read-only: trust is approved inside codex itself; the instruction
// string tells the user exactly what to run there.
export type CodexHookTrust = {
  status:
    | "no_codex"
    | "no_hooks"
    | "config_missing"
    | "needs_trust"
    | "all_trusted"
    | "feature_disabled";
  hooks_file?: string;
  config_file?: string;
  registered_events?: string[];
  trusted_events?: string[];
  untrusted_events?: string[];
  feature_flag_enabled: boolean;
  instruction?: string;
};

// GET /api/config/profiles/<name> — one profile resolved against the
// master config, plus its raw TOML body for display.
export type ProfileShowResponse = {
  name: string;
  builtin: boolean;
  editable: boolean;
  raw: string;
  resolved: {
    Conversation?: {
      Mode?: string;
      TargetRatio?: number;
      PreserveLastN?: number;
      CompressTypes?: string[];
      Logs?: { MaxLines?: number; Head?: number; Tail?: number };
    };
    [key: string]: unknown;
  };
};

// The baked-in defaults come from `cost.Pricing` (snake_case JSON
// tags), NOT `config.ModelPricing` (PascalCase). Two distinct Go
// structs, two distinct wire shapes. Convert between them at the
// override-add boundary.
export type CostPricing = {
  input: number;
  output: number;
  cache_read: number;
  cache_creation: number;
  cache_creation_1h: number;
  long_context_threshold?: number;
  long_context_input?: number;
  long_context_output?: number;
  long_context_cache_read?: number;
  long_context_cache_creation?: number;
  long_context_cache_creation_1h?: number;
  web_search_per_request?: number;
};

// DatedCostPricing is one rate period in a model's historical rate
// timeline — `cost.DatedPricing` on the wire: a `cost.Pricing` (see
// CostPricing above) plus the `effective_from` instant the rate took
// hold. The zero value ("0001-01-01T00:00:00Z", Go's time.Time zero)
// means "since forever" — the oldest period in a timeline.
export type DatedCostPricing = CostPricing & {
  effective_from: string;
};

export type PricingDefaultsResponse = {
  defaults: Record<string, CostPricing>;
  // The baked-in HISTORICAL rate timelines, keyed like `defaults`.
  // Only present for models whose price actually changed — absent or
  // empty on a stock build with no dated entries. See
  // internal/intelligence/cost/dated.go.
  dated_defaults?: Record<string, DatedCostPricing[]>;
};

export function costPricingToConfig(p: CostPricing): ModelPricing {
  return {
    Input: p.input ?? 0,
    Output: p.output ?? 0,
    CacheRead: p.cache_read ?? 0,
    CacheCreation: p.cache_creation ?? 0,
    CacheCreation1h: p.cache_creation_1h ?? 0,
    LongContextThreshold: p.long_context_threshold ?? 0,
    LongContextInput: p.long_context_input ?? 0,
    LongContextOutput: p.long_context_output ?? 0,
    LongContextCacheRead: p.long_context_cache_read ?? 0,
    LongContextCacheCreation: p.long_context_cache_creation ?? 0,
    LongContextCacheCreation1h: p.long_context_cache_creation_1h ?? 0,
  };
}

// ---------- /api/backfill/status + /api/backfill/run + jobs ----------

export type BackfillMode = {
  mode: string;
  flag: string;
  description: string;
  candidates: number; // -1 = file scan needed
  candidates_note?: string;
};

export type BackfillStatusResponse = {
  modes: BackfillMode[];
};

export type BackfillJobStatus = "running" | "done" | "failed" | string;

export type BackfillJob = {
  id: string;
  mode: string;
  status: BackfillJobStatus;
  started_at: string;
  ended_at?: string;
  exit_code?: number;
  output: string;
  error?: string;
};

export type BackfillRunResponse = {
  job_id: string;
  mode: string;
  status: BackfillJobStatus;
  started_at: string;
};

export type BackfillJobsListResponse = {
  jobs: BackfillJob[];
};

// ---- Teams / Org enrolment -------------------------------------------------

export type EnrolmentLastPush = {
  pushed_at: string;
  status: string;
  row_count: number;
  bytes: number;
  error?: string;
};

// EnrolmentStatus is GET /api/enrolment/status. `enrolled` is always present;
// the rest are populated only when enrolled. On a solo-local install (org mode
// off) the server returns { enrolled: false }.
export type EnrolmentStatus = {
  enrolled: boolean;
  org_id?: string;
  org_name?: string;
  org_server_url?: string;
  user_email?: string;
  enrolled_at?: string;
  credential_store?: string;
  last_push?: EnrolmentLastPush | null;
  // push_paused is present ONLY while the oversized-batch circuit is open: the
  // composed rollup exceeded the accepted push limit, so the push loop is
  // parked and nothing is reaching the org server. Absent is the normal case.
  push_paused?: EnrolmentPushPaused | null;
};

// EnrolmentPushPaused is the open oversized-batch circuit. `reason` is the
// underlying serialized-bytes-vs-limit diagnostic; `until` is when the push
// loop retries (RFC3339).
export type EnrolmentPushPaused = {
  reason?: string;
  until: string;
};

// EnrolmentInvite is POST /api/enrolment/invite. The org server mints a
// one-time enrolment token for a teammate who is ALREADY a member of the org;
// `command` is the paste-ready enroll line. The token is shown once and is
// never stored node-side — the org server holds only its argon2id hash.
// minted_this_month / monthly_cap report the caller's per-member allowance.
export type EnrolmentInvite = {
  token: string;
  token_id: string;
  user_email: string;
  expires_at: string;
  org_url: string;
  minted_this_month: number;
  monthly_cap: number;
  command: string;
};

// --- Advisor (suggestions engine, spec §15.7) ---

// AdvisorSuggestion is one row of GET /api/suggestions.
export type AdvisorSuggestion = {
  dedup_key: string;
  detector: string;
  category: "cost" | "latency" | "quality" | "hygiene";
  scope: "session" | "project" | "global";
  scope_id?: string;
  severity: "info" | "advice" | "warning";
  title: string;
  nudge: string;
  savings_usd?: number;
  savings_min?: number;
  confidence: number;
  evidence: {
    numbers?: Record<string, number>;
    items?: { label: string; value: number; unit?: string }[];
    math?: string;
  };
  computed_at: string;
  window_days: number;
  // C3 (P4.4): machine-actionable remediation. kind drives the one
  // renderer in Suggestions.tsx; unknown kinds render nothing.
  action?: { kind: string; target: string; label: string };
};

// AdvisorReport is GET /api/suggestions.
export type AdvisorReport = {
  suggestions: AdvisorSuggestion[] | null;
  total_savings_usd: number;
  total_savings_min: number;
  window_days: number;
  generated_at: string;
  sessions_scanned: number;
};

// AdvisorListResponse is the paginated/filtered GET /api/suggestions shape
// (filters + pagination are handler-side; totals reflect the filtered set
// pre-pagination).
export type AdvisorListResponse = {
  suggestions: AdvisorSuggestion[] | null;
  total_count: number;
  page: number;
  limit: number;
  total_savings_usd: number;
  total_savings_min: number;
  by_category: Record<string, number>;
  by_detector: Record<string, number>;
  window_days: number;
  generated_at: string;
  sessions_scanned: number;
};

// ---------- Process Observability (docs/process-observability.md §13) ----------
// /api/session/<id>/processes (SessionProcessResponse) +
// /api/process/findings (ProcessFindingsResponse). Node-local OS-level
// process capture: the per-session tree + observe-only findings.

// ProcessFinding mirrors store.ProcessFindingRow — an observe-only §14 signal
// derived from the captured envelope (never blocks).
export type ProcessFinding = {
  rule_id: string;
  severity: string; // "info" | "warn" | "high"
  process_key: string;
  session_id: string;
  tool?: string;
  exe_basename?: string;
  target_kind?: string;
  target?: string;
  detail?: string;
  timestamp: string;
  action_id?: number;
  turn_index?: number;
};

// MetricSample is one sparkline point (mirrors processobs.MetricSample): a
// timestamped resource reading. cpu_ms cumulative; ws = working set bytes;
// rb/wb = cumulative disk read/write bytes.
export type MetricSample = {
  t: string;
  cpu_ms: number;
  ws: number;
  rb: number;
  wb: number;
};

// ProcessNode mirrors dashboard.ProcessNode — one process in the tree, with
// children nested. action_id/command carry the §9.2.4 message/action link;
// the metric fields + metric_samples carry the §dashboard-enhancements
// resource snapshot (Windows poll capturer; network absent — needs ETW).
export type ProcessNode = {
  process_key: string;
  pid: number;
  ppid: number;
  exe: string;
  argv_preview?: string;
  cwd?: string;
  attribution_source: string;
  attribution_confidence: string;
  exited: boolean;
  exit_code: number;
  exit_signal?: number;
  duration_ms: number;
  // started_at is the wall-clock instant the process was first observed
  // (RFC3339 UTC); the drawer shows the actual capture time. Empty when
  // unknown.
  started_at?: string;
  is_boundary?: boolean;
  action_id?: number;
  turn_index?: number;
  command?: string;
  // message_id is the assistant message that issued the spawning command
  // (§9.2.4) — present only on action-correlated processes.
  message_id?: string;
  seccomp_mode?: string;
  capabilities_eff?: string;
  apparmor_label?: string;
  selinux_label?: string;
  container_id?: string;
  // Resource metrics (present only when captured; network absent — needs ETW).
  cpu_ms?: number;
  working_set_bytes?: number;
  peak_rss_bytes?: number;
  read_bytes?: number;
  write_bytes?: number;
  thread_count?: number;
  handle_count?: number;
  metric_samples?: MetricSample[];
  network_count?: number;
  children: ProcessNode[];
};

export type SessionProcessResponse = {
  session_id: string;
  total: number;
  network_total?: number;
  roots: ProcessNode[];
  findings: ProcessFinding[];
  diagnostics: ProcessDiagnostics;
};

export type ProcessDiagnostics = {
  process_enabled: boolean;
  process_backend?: string;
  process_network_enabled: boolean;
  process_network_capture_bodies?: string;
  process_network_body_capture: boolean;
  config_writable: boolean;
  restart_required: boolean;
  process_rows: number;
  network_events: number;
  proxy_only_network_events: number;
  reason_codes: string[];
  process_settings_url: string;
  proxy_settings_url: string;
  backfill_settings_url: string;
  restart_settings_url: string;
};

// /api/process/findings — recent cross-session rollup.
export type ProcessFindingsResponse = {
  window_hours: number;
  total: number;
  by_rule: Record<string, number>;
  by_severity: Record<string, number>;
  findings: ProcessFinding[];
};

export type ProcessNetworkBody = {
  id: number;
  process_event_id: number;
  capture_source: string;
  api_turn_id?: number;
  request_id?: string;
  method?: string;
  url?: string;
  host?: string;
  status_code?: number;
  duration_ms?: number;
  request_headers_json?: string;
  response_headers_json?: string;
  request_body?: string;
  request_body_sha256?: string;
  request_body_bytes?: number;
  request_body_truncated?: boolean;
  response_body?: string;
  response_body_sha256?: string;
  response_body_bytes?: number;
  response_body_truncated?: boolean;
  response_content_type?: string;
  body_unavailable_reason?: string;
  created_at: string;
};

export type ProcessNetworkEvent = {
  id: number;
  process_run_id?: number;
  process_key: string;
  timestamp: string;
  session_id?: string;
  project_id?: number;
  tool?: string;
  action_id?: number;
  turn_index?: number;
  target_kind?: string;
  target?: string;
  target_hash?: string;
  severity?: string;
  finding_rule_id?: string;
  details_json?: string;
  has_body: boolean;
  body?: ProcessNetworkBody;
  exe_basename?: string;
  pid?: number;
};

export type SessionNetworkResponse = {
  session_id: string;
  total: number;
  events: ProcessNetworkEvent[];
};

// Session handoff / continue-anywhere (docs/session-handoff.md).
// GET /api/session/<id>/handoff/estimate + POST /api/session/<id>/handoff.
export type HandoffBoundary = {
  index: number;
  role: "user" | "assistant";
  time?: string;
  stable: boolean;
  reason?: string;
  cumulative_share: number;
  preview: string;
  tool_call_count?: number;
};

export type HandoffTarget = {
  tool: string;
  transcript_tier: string;
  inject_lanes: string[];
  // launchable is true when this target can be started in the dashboard's
  // embedded web terminal (a grounded launcher AND the feature enabled on
  // this dashboard process). Drives the "Launch <tool> here" action.
  launchable?: boolean;
  note?: string;
};

// SessionLaunchResponse is the reply from POST /api/session/<id>/launch: the
// opaque session handle the client opens a /ws/launch/<token> websocket with.
export type SessionLaunchResponse = {
  token: string;
  subcommand: string;
  session_id: string;
  // Additive/optional (review finding 8): whether the launched terminal has a
  // browsable directory on this machine, so the dock can enable Files/Git
  // immediately without waiting for a /api/launch/sessions rehydrate. Since the
  // 2026-08-28 ruling this is true for a default-cwd launch too (the panel then
  // serves the terminal's working directory and labels it as such); it is false
  // only when there is nothing local to browse, e.g. an SSH terminal.
  // Absence ≡ false.
  has_project_root?: boolean;
};

// ToolPreflight is the reply from GET /api/terminal/launch/preflight?tool=<name>
// — the pre-launch binary-resolution verdict (tool-binary-resolution arc). It
// tells the New-Terminal dialog, before a launch, whether the daemon can resolve
// the tool's binary and — when it cannot — the grounded install command to fix
// it. `install_command` is the human display string only (the argv never crosses
// the wire; the server owns it at the install endpoint). Verdict is a closed
// vocabulary: "ok" | "ok_off_path" | "shadowed" | "foreign_only" | "not_found".
export type ToolPreflight = {
  tool: string;
  verdict: string;
  bin?: string;
  notes?: string[];
  install_command?: string;
  can_install: boolean;
  /**
   * The honest-zero companion to `install_command` (audit DI-03): the grounded
   * REASON there is no guided install for this tool on this OS. The server
   * fills it ONLY when no install plan exists — never alongside a usable
   * `install_command` — and omits it when empty, so an older daemon simply
   * doesn't send the key. See installGuidanceFor in lib/toolInstall.ts.
   */
  install_note?: string;
  /**
   * Present ("gui") only when the preflight was resolved for a GUI launchable
   * (T2.3, ide-desktop-launch-plan-2026-09-03.md §2). Absent for every
   * terminal-tool preflight, including on an older daemon — the verdict
   * vocabulary and every other field are unchanged either way.
   */
  kind?: "gui";
};

// GUILaunchable mirrors ONE element of GET /api/terminal/sessions'
// `gui_launchables` (ide-desktop-launch-plan-2026-09-03.md §2.4) — an IDE or
// desktop-app row the New-Terminal dialog can install/launch. Only ADVERTISED
// rows are ever sent (Lifecycle.Advertised() && Spec.Launchable()); an older
// daemon omits the key entirely, which the dialog reads as "no GUI apps",
// never as an error.
//
// `adapter` is "" for a HOST row (an editor like vscode/jetbrains-idea that
// has no adapter of its own) — `hosts` then lists the adapters that launch
// AI-tool sessions inside it, and the picker shows that instead of a watched
// pill (a host has no capture of its own to be watched).
export type GUILaunchable = {
  id: string;
  label: string;
  adapter: string;
  surface: "ide" | "desktop";
  allowed: boolean;
  watched: boolean;
  wrap_kind: "none" | "child_env" | "config_write";
  wrap_reason: string;
  project_dir_argv: boolean;
  grounded: boolean;
  note: string;
  hosts: string[];
};

// GUIRun mirrors ONE element of GET /api/terminal/sessions' `gui_runs` — a
// live (or recently-exited) GUI launch this daemon spawned. Read-only
// telemetry; there is no PTY behind it, so it never docks a terminal tab.
export type GUIRun = {
  run_id: string;
  id: string;
  label: string;
  pid: number;
  launched_at: string;
  wrap_applied: boolean;
  wrap_note: string;
  /** Launch-composition advisories (launcher-stub pid caveat, ignored project dir). Absent on an older daemon. */
  notes?: string[];
  exited: boolean;
  exit_code: number;
};

// GUILaunchResponse is the 200 reply from POST /api/terminal/launch when the
// request body carries `kind: "gui"`. Distinct from FreshLaunchResponse
// (NewTerminalDialog.tsx): there is no `token` / no websocket — the dialog
// reports success (pid + wrap outcome) and closes without docking anything.
export type GUILaunchResponse = {
  kind: "gui";
  run_id: string;
  pid: number;
  tool: string;
  label: string;
  wrap_applied: boolean;
  wrap_note: string;
  notes?: string[];
};

// LaunchableTool mirrors ONE element of GET /api/terminal/sessions'
// `launchable_tool_info` (Go: internal/intelligence/dashboard.LaunchableTool) —
// a SIBLING of the plain `launchable_tools` string list, never a replacement.
// It annotates a picker entry with the TWO INDEPENDENT allow-lists that decide
// what happens after Start (audit DI-06 / DI-07):
//   allowed — [terminal.launch].allowed_tools, the LAUNCH gate (default empty
//             = deny-all), enforced server-side at spawn time;
//   watched — [observer.watch].enabled_adapters, the CAPTURE gate. A tool can
//             be allowed yet unwatched (it launches and records nothing) or
//             watched yet refused at launch — hence two flags, not one.
// "installed" is deliberately absent: answering it would run the binary
// resolver once per launchable tool on every poll of this VIEW route; the
// per-tool /api/terminal/launch/preflight answers it on demand.
export type LaunchableTool = {
  tool: string;
  allowed: boolean;
  watched: boolean;
};

// TerminalSessionsMeta is the annotation half of GET /api/terminal/sessions the
// New-Terminal dialog reads (the `sessions` array itself is consumed
// elsewhere). `launchable_tool_info` is same-length/same-order as
// `launchable_tools`; an older daemon omits it, which means UNKNOWN — never
// "not allowed".
export type TerminalSessionsMeta = {
  launchable_tools?: string[];
  launchable_tool_info?: LaunchableTool[];
  allowed_project_roots?: string[];
  shell_enabled?: boolean;
  /** IDE / desktop-app rows (T2.3). Absent ⇒ no GUI section, never an error. */
  gui_launchables?: GUILaunchable[];
  /** Live/recent GUI runs this daemon spawned. Absent ⇒ nothing to list. */
  gui_runs?: GUIRun[];
};

// ModelSuggestion is one entry in ToolModels.models — either a model the tool
// has actually been launched with before ("history", carrying the observed
// count + last-used timestamp) or a model SuperBased knows the tool supports
// but has no local usage for ("known"). `count`/`last_used` are present only
// for source "history".
export type ModelSuggestion = {
  model: string;
  count?: number;
  last_used?: string;
  source: "history" | "known";
};

// ToolModels is the reply from GET /api/terminal/launch/models?tool=<name> —
// the model-picker suggestion list for the New-Terminal dialog (B5). When
// `supported` is false the tool has no concept of a selectable model and
// `models` is empty; the dialog renders no picker in that case. Server order
// is preserved verbatim (history entries first, then known entries).
export type ToolModels = {
  tool: string;
  supported: boolean;
  models: ModelSuggestion[];
};

// SandboxSourceAvail is one entry of SandboxAvailability.sources — whether a
// given workspace source ("live" | "clone-local" | "clone-remote" |
// "worktree") is currently usable for a sandboxed launch, and why not when it
// isn't (e.g. clone-remote reporting available:false because
// allow_remote_clone is unset).
export type SandboxSourceAvail = {
  id: string;
  available: boolean;
  reason?: string;
};

// SandboxToolAvail is one entry of SandboxAvailability.tools, keyed by tool
// name — whether that tool has a grounded SandboxSpec registry row it can be
// launched under a sandbox with (v1 grounds only claude-code; every other
// launchable tool carries an honest reason instead).
export type SandboxToolAvail = {
  available: boolean;
  reason?: string;
};

// SandboxAvailability is the reply from GET /api/terminal/sandbox (B9) — the
// New-Terminal dialog's sandbox probe, mirroring the B5 ToolModels fail-soft
// pattern (always 200, even when the feature is fully off). `verdict` is a
// closed vocabulary: "available" | "unsupported_platform" | "backend_missing"
// | "backend_too_old" | "userns_denied" | "tool_unmapped" |
// "disabled_by_config" | "workspace_prep_failed". `reason` names the exact
// gap in human terms (which sysctl is denied, which bwrap version was found,
// …) so the dialog's disabled copy can quote it verbatim rather than being
// generic.
export type SandboxAvailability = {
  available: boolean;
  verdict?: string;
  reason?: string;
  backend?: string;
  backend_version?: string;
  home_mode?: string;
  default_on: boolean;
  sources?: SandboxSourceAvail[];
  tools?: Record<string, SandboxToolAvail>;
};

// SSHProfileInfo is one row of GET /api/terminal/ssh — an operator-authored
// remote system from [[terminal.ssh.profiles]] in the daemon's own config
// (docs/plans/ssh-remote-profiles-plan-2026-08-27.md).
//
// This is an OUTBOUND concept: Observer spawns an `ssh` client to reach the
// machine. It is unrelated to the [remote]/Tailscale feature (and to
// lib/remoteTerminal.ts), which is INBOUND — exposing THIS dashboard to a
// paired device.
//
// Note what is NOT here: no key material and no key PATH. `key_hint` is the
// key file's basename only, so the dashboard never discloses the operator's
// filesystem layout. The client sends `name` back on launch and nothing else;
// every connection parameter is resolved server-side.
export type SSHProfileInfo = {
  name: string;
  label: string;
  target: string;
  jump?: string;
  has_key: boolean;
  key_hint?: string;
};

// SSHProfilesResponse is the reply from GET /api/terminal/ssh. Fail-soft like
// SandboxAvailability: always 200, with enabled:false when the feature is off
// or absent, so the dialog can simply omit the system selector.
export type SSHProfilesResponse = {
  enabled: boolean;
  profiles: SSHProfileInfo[];
};

// InstanceState is the honest lifecycle of one remote instance's port forward.
// "connecting" is visible while a connect is in flight (including from another
// tab); "error" always comes with a reason.
export type InstanceState = "disconnected" | "connecting" | "connected" | "error";

// InstanceInfo is one row of GET /api/instances — a remote developer machine
// running its OWN Observer install, reached by an `ssh -N -L` local port
// forward to that machine's dashboard port.
//
// It is the SAME operator-authored [[terminal.ssh.profiles]] list the SSH
// terminal picker reads (one allow-list, two surfaces), extended with the live
// forward state. `url` is a LOOPBACK address and is present only while the
// forward actually answers, so the UI never links to a dead port.
//
// Note what is NOT here, exactly as with SSHProfileInfo: no key material and no
// key PATH. The client sends a profile NAME in the path and an empty body;
// every connection parameter, including the remote dashboard port, is resolved
// server-side from the daemon's own config.
export type InstanceInfo = {
  name: string;
  label: string;
  target: string;
  dashboard_port: number;
  has_key: boolean;
  key_hint?: string;
  jump?: string;
  state: InstanceState;
  local_port?: number;
  url?: string;
  error?: string;
};

// InstancesResponse is the reply from GET /api/instances. Fail-soft like
// SSHProfilesResponse: always 200, with enabled:false when the feature is off
// or absent, so the header simply omits the switcher.
export type InstancesResponse = {
  enabled: boolean;
  instances: InstanceInfo[];
};

// InstanceTestResult is the payload of POST /api/instances/{name}/test — the
// bounded, non-interactive connectivity probe (known_hosts + auth) run
// without opening a forward. Mirrors the Go dashboard.InstanceTestResult
// wire shape field-for-field.
export type InstanceTestResult = {
  known_hosts_checked: boolean;
  known_hosts_ok: boolean;
  auth_ok: boolean;
  latency_ms: number;
  stderr?: string;
};

// AttachInfo is one row of GET /api/attach/sessions — a LIVE, non-setup
// daemon-owned terminal run the dashboard can join as a second seat over the
// existing /ws/launch/<token> bridge (docs/plans/session-attach-design-2026-07-19.md
// §4). The list now covers every live daemon-owned run — kind fresh, handoff,
// attach, and resume — not attach-only; non-exited rows; session_id is "" until
// the row correlates to an observer session (a dashboard-launched terminal
// typically takes ~10-30s for the correlation sweep to fill this in). A given
// session_id can now have more than one live row; callers that need a single
// row pick the newest by created_at. Jump-in is offered ONLY for these rows
// (exact liveness — daemon-owned PTY), never inferred from recency.
export type AttachInfo = {
  token: string;
  subcommand: string;
  kind: string;
  tool: string;
  session_id: string;
  run_id: string;
  created_at: string;
  attached: boolean;
  viewers: number;
  writer_holder: string;
  exited: boolean;
  exit_code: number;
  // Additive/optional (review finding 8): whether the attach session has a
  // browsable directory on this machine (an allow-listed project root, else the
  // run's own working directory), so a jumped-in seat enables Files/Git
  // immediately. Absence ≡ false.
  has_project_root?: boolean;
};

export type AttachSessionsResponse = { sessions: AttachInfo[] };

export type HandoffEstimateRow = {
  mode: string;
  tokens: number;
  cost_usd: number;
  note: string;
};

export type HandoffResponse = {
  session_id: string;
  target_tool?: string;
  target_model: string;
  carry_used: string;
  degrade_reason?: string;
  context_warning?: string;
  /** Whether the source adapter implements the un-excerpted (full-body) read
   * the "Full + cache" carry needs — mirrors
   * handoff.EstimateResult.SourceHasFullReader. false for every source
   * except claudecode/codex/kimicode/grok; the modal greys out that option
   * when this is false instead of silently offering an identical-to-full
   * choice. */
  full_cache_available: boolean;
  fork: {
    requested_index?: number;
    resolved_index: number;
    snapped?: boolean;
    reason?: string;
    fork_time?: string;
  };
  estimate: {
    target_model: string;
    fork_share: number;
    rows: HandoffEstimateRow[];
    stay?: {
      next_message_low_usd: number;
      next_message_mid_usd: number;
      next_message_high_usd: number;
      has_band: boolean;
      cache_value_at_risk_usd: number;
      has_cache_value: boolean;
    };
  };
  boundaries?: HandoffBoundary[];
  targets?: HandoffTarget[];
  doc?: string;
  doc_path?: string;
  short_id?: string;
  handoff_id?: number;
  gitignore_hint?: boolean;
  dry_run?: boolean;
};

// ---------- /api/session/<id>/loc + /api/loc/summary ----------
//
// Lines-of-code authorship
// (docs/plans/lines-of-code-tracking-plan-2026-09-07.md §3.2/§3.5). Wire
// shapes mirror internal/intelligence/dashboard/loc.go field for field.
//
// The honesty rules live in the PAYLOAD, not in the UI's head:
//   - `human_capture` is "none" until an editor reports saves. While it is
//     "none" there is NO `ai_share` on the summary payload, and no surface
//     may synthesise one - with nothing measuring the developer's own
//     typing the share is 100% by construction, which is a claim about the
//     developer, not a fact about the agent.
//   - `capture_note` is the server-owned sentence for that state. Render it
//     verbatim; do not re-word it per surface.
//   - `low_confidence_files` / `overwrite_files` travel WITH each bucket so a
//     caveat can sit next to the number instead of in a footnote.

export type LOCStats = {
  added_code: number;
  modified_code: number;
  deleted_code: number;
  added_comment: number;
  deleted_comment: number;
  whitespace: number;
  blank: number;
  unknown: number;
  // code_touched = added_code + modified_code. The headline "lines of code
  // written". Deleted lines are deliberately NOT in it.
  code_touched: number;
  total: number;
};

export type LOCActor = "ai" | "human" | "system" | "unknown";

export type LOCCategory =
  | "code"
  | "docs"
  | "config"
  | "generated"
  | "vendored"
  | "unknown";

// LOCBucket is one (actor, sidechain, category) cell.
export type LOCBucket = {
  actor: LOCActor | string;
  sidechain: boolean;
  category: LOCCategory | string;
  files: number;
  low_confidence_files: number;
  overwrite_files: number;
  deleted_files: number;
  stats: LOCStats;
};

export type LOCLanguage = {
  language: string;
  category: LOCCategory | string;
  files: number;
  stats: LOCStats;
};

export type LOCHumanCapture = "none" | "vscode";

export type SessionLOCResponse = {
  session_id: string;
  buckets: LOCBucket[];
  languages: LOCLanguage[];
  files: number;
  human_capture: LOCHumanCapture | string;
  capture_note: string;
  classifier_version: number;
  // Pre-summed CODE-only roll-ups; the card never has to know the bucket
  // algebra to render its headline figures.
  ai_main: LOCStats;
  ai_sidechain: LOCStats;
  human: LOCStats;
  system: LOCStats;
  // Non-code buckets, kept separate so a documentation-heavy session reads
  // as documentation-heavy instead of inflating the code number.
  docs: LOCStats;
  config: LOCStats;
};

// Org-served Cloud Intelligence result cached on this node (GET
// /api/session/<id>/org-intel). The node cache carries only the content the
// org derived — no provider / model / tokens / cost. `enriched` is the
// discriminator: false with a `reason` is the honest empty state.
export type OrgIntelResultRow = {
  session_id: string;
  job_id: string;
  title: string;
  description: string;
  taxonomy_tags: string[];
  suggested_tags: string[];
  limitations: string[];
  // NOTE: the five narrative lists (work_done / plans_implemented /
  // issues_found / failures / next_steps) are NOT on this row yet. The org
  // rail's prompt asks for them and its validator rejects a leaky one, but
  // org_intel_results has no column for them, so nothing reaches the node
  // cache to type here. See internal/orgserver/intel/executor.go
  // ::normalizedToResult for the deferred, migration-bearing wave.
  confidence: string;
  schema_version: string;
  fetched_at: string;
};

export type OrgIntelResponse = {
  enriched: boolean;
  reason?: string;
  result?: OrgIntelResultRow;
};

export type LOCDay = {
  day: string;
  project_id: number;
  actor: LOCActor | string;
  files: number;
  stats: LOCStats;
};

export type LOCSummaryResponse = {
  days: number;
  buckets: LOCBucket[];
  by_day: LOCDay[];
  human_capture: LOCHumanCapture | string;
  capture_note: string;
  ai_code_touched: number;
  human_code_touched: number;
  // PRESENT ONLY when human_capture !== "none". Absent is not zero - it
  // means "no denominator exists", and no surface may fill it in.
  ai_share?: number;
  classifier_version: number;
};

// UpdateOrgRefusal names a push the org server most recently REFUSED because
// this node runs below its configured minimum agent version (enterprise update
// management W5). It is the one condition where the node is neither idle nor
// updating and still needs the operator's attention right now: nothing is
// reaching the org at all.
export type UpdateOrgRefusal = {
  message: string;
  min_version?: string;
  your_version?: string;
  at?: string;
};

// UpdateStatusResponse is GET /api/update/status - the ORG-SERVED answer to
// "does this node have an update", as opposed to the click-gated npm probe in
// lib/version.ts which asks the public registry.
//
// `enabled: false` means [update].enabled is off on this node. Every other
// field is then empty, and the surface must say the feature is OFF rather than
// implying the node is up to date.
export type UpdateStatusResponse = {
  enabled: boolean;
  version?: string;
  channel?: string;
  state: string;
  reason?: string;
  error_class?: string;
  target_version?: string;
  manifest_version?: number;
  last_manifest_seen_at?: string;
  install_method?: string;
  self_apply: boolean;
  // advice is what to run INSTEAD when this node cannot replace its own
  // binary (an npm/brew/apt-owned install). Never a silent "up to date".
  advice?: string;
  auto_apply: boolean;
  auto_apply_reason?: string;
  window?: string;
  org_refusal?: UpdateOrgRefusal;
};
