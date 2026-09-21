// Shared design-system types.
//
// These are the STABLE, structural data-shape aliases the shared charts and
// pills consume. They mirror the same-named aliases in each app's own
// `lib/types.ts` (e.g. web/src/lib/types.ts). Because they are compile-time-
// only structural types, an app's `CostPoint` and this `CostPoint` are
// mutually assignable — there is no runtime or visual coupling. Kept here so
// the DS package is self-contained without importing an app's 2,900-line
// domain types file. Only add a type here when a shared component needs it.

import type { ReactNode } from "react";
import type { MessageColumnPreset, MessageSortKey } from "./messagesModel";

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

export type ActionsPoint = {
  bucket: string;
  total: number;
  failures: number;
  by_tool: Record<string, number>;
};

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

export type Reliability =
  | "accurate"
  | "approximate"
  | "unreliable"
  | "unknown"
  | "";

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

export type AnalysisTrendPoint = {
  bucket: string;
  key: string;
  total_tokens: number;
  cost_usd: number;
  turn_count: number;
};

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

export type CacheSavingsPoint = {
  day: string;
  savings_usd: number;
  cache_read_tokens: number;
};

export type CacheTimeseriesPoint = {
  bucket: string;
  read_tokens: number;
  written_tokens: number;
  event_count: number;
  rewrite_count: number;
};

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

// ============================================================================
// Session-detail row types (shared, structural)
// ----------------------------------------------------------------------------
// These mirror the node's web/src/lib/types.ts shapes so the promoted shared
// session-detail components (MessagesTable, KpiBand, TokenBucketsPanel,
// ModelsUsedPanel, CacheKpiStrip, CacheTimelineList, ProcessTree) can be typed
// against one contract that BOTH the node's SessionDetail-derived rows and the
// org's rollup rows are structurally assignable to. Compile-time only; if a
// node shape changes, update the mirror here too (per docs/app-design-system.md
// "Known follow-ons").
// ============================================================================

// ---------- Messages table ----------

// ActionFullText is the on-demand body payload the Messages table's copy /
// view-full-text affordances resolve. On the node it is fetched from
// /api/action/<id>/full_text; the shared MessagesTable receives a fetchFullText
// callback so the org can back it with its audited tool-bodies route (or omit
// it for an honest "not available here" state).
export type ActionFullText = {
  action_id?: number;
  action_type?: string;
  target?: string;
  raw_tool_input?: string;
  raw_tool_output?: string;
};

// ToolCallRowLike — one tool call expanded under a message row.
export type ToolCallRowLike = {
  action_id: number;
  action_type: string;
  raw_tool_name: string;
  target: string;
  full_text?: string;
  full_text_elided?: boolean;
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
  request_url?: string;
  id_source?: string;
  granularity?: string;
  prompt_tokens_est?: number;
  response_tokens_est?: number;
};

// MessageAccountEvidenceLike / MessageAccountLike — the per-message login
// attribution the node ships (ToolAccountEvidence / MessageAccount in the node
// types). Kept structurally compatible so the node's richer types assign to
// these; the org omits `account` entirely (optional on MessageRowLike).
export type MessageAccountEvidenceLike = {
  email?: string;
  name?: string;
  account_id?: string;
  source: string;
  stage: string;
  observed_at: string;
};
export type MessageAccountLike = {
  status: "observed" | "unknown" | "conflict";
  label: string;
  evidence: MessageAccountEvidenceLike[];
};

// MessageRowLike — one reconstructed message row (assistant turn or synthesized
// user prompt) with its per-turn token/cost/timing metrics and tool calls.
export type MessageRowLike = {
  // Per-message login attribution observed at capture time. Absent for the org
  // (it does not ship account evidence) and for adapters that expose no login.
  account?: MessageAccountLike;
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
  tps_ms?: number;
  tps_basis?: "measured" | "intra-turn" | "elapsed";
  tool_duration_ms?: number;
  // tool_call_count is the projected count of tool calls on this message. Kept
  // REQUIRED: the node and the org both ship it (the org via a projection), and
  // web2's own sortValue returns it as a bare number, so widening it to
  // optional would break web2's current usage. The Tools cell reads it as
  // `?? 0` regardless, so count-only rendering works either way.
  tool_call_count: number;
  effort_level?: string;
  stop_reason?: string;
  service_tier?: string;
  fast?: boolean;
  // tool_calls is optional: the node ships the expandable per-call array; the
  // org ships only the count (tool_call_count) and no array (it passes []).
  // When the array is absent/empty but the count is present, the Tools cell
  // renders the count with the expander disabled ("tool calls not shipped").
  tool_calls?: ToolCallRowLike[];
  // attachments records the files/images/audio the USER attached to this
  // prompt turn (Issue 1). PRESENCE + KIND (+ optional media_type) only —
  // never a filename or bytes. Absent/empty on non-user turns, on adapters
  // that don't capture attachments, and on the org (no org data yet); the
  // Att cell renders "-" in that case.
  attachments?: MessageAttachmentLike[];
};

// MessageAttachmentLike is one user-attachment's metadata: a coarse kind
// (image | file | audio) and an optional IANA media_type. It carries no
// filename and no bytes by construction (Issue 1 privacy rule).
export type MessageAttachmentLike = {
  kind: string;
  media_type?: string;
};

// ExtraMessageColumn is an app-supplied column the shared MessagesTable renders
// as a real column, AFTER the built-in columns and BEFORE the Content column.
// It lets the org promote its Src / Reasoning / TTFB / tool-count fields out of
// the per-row body into first-class columns. `presets` names which column
// presets show it (default: every preset; the "all" preset always shows it, and
// an extra column that IS the active sort is never hidden). `sortKey`, when set,
// makes the header a server-side sort control. `render` returns the CELL
// CONTENT for one row (the table wraps it in a <td>). Absent (the node) => the
// table renders exactly the built-in columns, unchanged.
export type ExtraMessageColumn = {
  id: string;
  header: ReactNode;
  // width is the column's px contribution to the table min-width (layout
  // budget, like MessageColumn.width). Defaults to 90 when unset.
  width?: number;
  presets?: MessageColumnPreset[];
  render: (row: MessageRowLike) => ReactNode;
  sortKey?: MessageSortKey;
};

// ---------- Overview: token buckets + models used ----------

// TokenBucketsLike — the token movement split the Token buckets panel renders.
export type TokenBucketsLike = {
  input: number;
  output: number;
  cache_read: number;
  cache_creation: number;
  cache_creation_1h: number;
  reasoning: number;
};

// SessionModelBucketLike — one per-model row with per-bucket token + cost
// components, driving the Models used stacked bar.
export type SessionModelBucketLike = {
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
  input_cost_usd: number;
  output_cost_usd: number;
  cache_read_cost_usd: number;
  cache_creation_cost_usd: number;
};

// ---------- Cache tab ----------

export type CacheTier = "proxy" | "transcript" | "mixed" | "none";

// CacheKpiLike — the session-scoped cache KPI counts the strip renders.
export type CacheKpiLike = {
  tier: CacheTier;
  event_count: number;
  hit_count: number;
  write_count: number;
  rewrite_count: number;
  reanchor_count: number;
  mispredict_count: number;
  zero_usage_count: number;
  tokens_read: number;
  tokens_written: number;
  ratio: number;
  has_flagged_rewrites: boolean;
};

// CacheEventLike — one cache event (anomaly) in the timeline.
export type CacheEventLike = {
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
  // omitted when the reconciliation engine did not compute one, 0 when the
  // delta is genuinely zero. Feeds the efficiency tile's avoidable_usd.
  cost_delta_usd?: number;
};

// CacheTimelineItemLike — one row of the cache timeline: a baseline roll-up or
// an anomaly event.
export type CacheTimelineItemLike = {
  kind: "baseline" | "anomaly";
  count?: number;
  baseline_read_sum?: number;
  baseline_write_sum?: number;
  first_at?: string;
  last_at?: string;
  event?: CacheEventLike;
  flagged?: boolean;
};

// ---------- Process tree ----------

// MetricSampleLike — one sparkline point of a process's resource series.
export type MetricSampleLike = {
  t: string;
  cpu_ms: number;
  ws: number;
  rb: number;
  wb: number;
};

// ProcessNodeLike — one process in the tree. Both the node's ProcessNode and an
// org row assembled from parent_run_key (SessionProcessRunRow) map onto this;
// the org builds `children` from parent_run_key before rendering.
export type ProcessNodeLike = {
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
  started_at?: string;
  is_boundary?: boolean;
  action_id?: number;
  turn_index?: number;
  command?: string;
  message_id?: string;
  seccomp_mode?: string;
  capabilities_eff?: string;
  apparmor_label?: string;
  selinux_label?: string;
  container_id?: string;
  cpu_ms?: number;
  working_set_bytes?: number;
  peak_rss_bytes?: number;
  read_bytes?: number;
  write_bytes?: number;
  thread_count?: number;
  handle_count?: number;
  metric_samples?: MetricSampleLike[];
  network_count?: number;
  children: ProcessNodeLike[];
};

// ---------- Task tracking (docs/task-tracking.md) ----------
//
// The shapes GET /api/session/<id>/tasks returns on the node
// (internal/taskreport.Report) and the org projection returns on web2. Both
// map onto these structural aliases, exactly like CacheEventLike above.

// TaskTokenTotalsLike — one bucket's token split.
export type TaskTokenTotalsLike = {
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
  reasoning_tokens: number;
};

// TaskCostBucketLike — a bucket's tokens/actions plus its priced cost and the
// "don't lie about precision" flag: unpriced=true means at least one row had
// neither a recorded provider cost nor a pricing entry, so cost_usd is a known
// UNDER-count and the surface must render "unpriced", never imply $0.00.
export type TaskCostBucketLike = {
  tokens: TaskTokenTotalsLike;
  actions_count: number;
  cost_usd: number;
  unpriced: boolean;
};

// TaskItemLike — one task's lifecycle + cost row (Go: taskreport.ReportItem).
// never_activated / still_open / terminal_status carry the honesty caveats:
// a task can close without ever passing through in_progress, or still be open
// at measurement time (elapsed so far — never a fabricated completion).
export type TaskItemLike = TaskCostBucketLike & {
  key: string;
  key_kind?: string;
  content: string;
  active_form?: string;
  owner?: string;
  status: string;
  raw_status?: string;
  order?: number;
  unmatched?: boolean;
  never_activated: boolean;
  still_open: boolean;
  elapsed_seconds: number;
  terminal_status?: string;
  first_in_progress_unix?: number;
  terminal_at_unix?: number;
};

// TaskReportLike — the whole per-session task report. has_tasks gates the calm
// empty state (measured ~80% of sessions never call a todo/plan tool);
// between_tasks / shared are first-class buckets, never a rounding residue;
// sidechain is reported separately and never folded into a task.
export type TaskReportLike = {
  session_id?: string;
  token_usage_available?: boolean;
  has_tasks: boolean;
  items?: TaskItemLike[];
  between_tasks: TaskCostBucketLike;
  shared: TaskCostBucketLike;
  sidechain?: TaskCostBucketLike | null;
  unmatched_count: number;
  all_keys_native: boolean;
  match_mode?: string;
  concurrent_attribution?: string;
  include_sidechains?: boolean;
  cost_note?: string;
};

// ExtraTaskColumn is an app-supplied column the shared TasksTab renders AFTER
// the built-in Cost column. It mirrors ExtraMessageColumn (minus presets and
// server-side sorting, which the task table has neither of): `render` returns
// the CELL CONTENT for one row and the table wraps it in a <td>. Absent (the
// node) => exactly the built-in columns, unchanged. `renderBucket` fills the
// same column on the between-tasks / shared / sidechain summary rows; when it
// is omitted those cells render an em dash.
export type ExtraTaskColumn = {
  id: string;
  header: ReactNode;
  // width is the column's px contribution to the table min-width (layout
  // budget, like ExtraMessageColumn.width). Defaults to 90 when unset.
  width?: number;
  align?: "left" | "right";
  render: (row: TaskItemLike) => ReactNode;
  renderBucket?: (bucket: TaskCostBucketLike, label: string) => ReactNode;
};

// ---------- Sub-agents ----------

// SubAgentLike — one sub-agent row: either a separately linked child session
// (session_id set) or a legacy inline sidechain window. The token/cost rollups
// ride token_usage.is_sidechain (node migration 087) and are absent/zero until
// a post-087 ingest heals older transcripts; a hook_only row has no transcript
// or usage at all, only a lifecycle stop.
export type SubAgentLike = {
  session_id?: string;
  hook_only?: boolean;
  stop_action_id?: number;
  id?: string;
  label: string;
  type?: string;
  start: string;
  end?: string;
  open: boolean;
  action_count: number;
  error_count: number;
  input_tokens?: number;
  output_tokens?: number;
  cache_read_tokens?: number;
  cache_creation_tokens?: number;
  cost_usd?: number;
};

// ---------- Org-served Cloud Intelligence result ----------

// IntelResultLike — one org-served enrichment result, normalized so BOTH the
// org session drawer (web2) and the node session drawer (web) render it through
// the one shared IntelResultCard. It is the structural union of two sources:
// the org server's per-session result (GET /api/org/sessions/{id}/intel —
// carries provider / model / job state / tokens / cost) and the node-local
// org_intel_cache row the node pulled back (GET /api/session/{id}/org-intel —
// carries no provider/model/tokens/cost, only the content the org derived).
// Every meta field is therefore optional: the card renders what is present and
// omits what is not, never fabricating a zero cost or an empty provider.
export type IntelResultLike = {
  title?: string;
  description?: string;
  confidence?: string;
  taxonomyTags?: string[];
  suggestedTags?: string[];
  // evidenceRefs are the server-side grounding tokens ("a136", "m5",
  // "activity_mix"). They are kept on the type because callers still carry
  // them, but the card does NOT render them: they are internal identifiers,
  // not something to show a developer.
  evidenceRefs?: string[];
  limitations?: string[];
  // The five NARRATIVE lists (internal/cloudcontract/result.go): what the
  // session did, whether the stated plans landed, what is broken, what failed
  // or is unresolved, and what to do next. All optional - a result produced
  // before these fields existed simply carries none of them.
  workDone?: string[];
  plansImplemented?: string[];
  issuesFound?: string[];
  failures?: string[];
  nextSteps?: string[];
  schemaVersion?: string;
  // generatedAt is the result's own timestamp: the org's created_at, or the
  // node's fetched-at for a cached pull. The caller labels which via
  // IntelResultCardProps.generatedAtLabel.
  generatedAt?: string;
  // Org-only execution metadata (absent on the node cache).
  provider?: string;
  model?: string;
  jobState?: string;
  tokensIn?: number;
  tokensOut?: number;
  costUsd?: number;
};
