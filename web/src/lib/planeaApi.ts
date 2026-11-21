// planeaApi - the row shapes of the machine's Plane A ("Your apps") routes,
// as the pages read them. The B5 routes are pinned by
// docs/plans/plane-a-sdk-buildout/contracts/node-routes.md; scores and
// experiments by contracts/scores.md and experiments.md (lane B7), prompts
// by contracts/prompts.md (lane B8), alerts and the explorer by
// contracts/alerts.md (lane B9). A field a route may not send yet (an older
// daemon) is optional. Pure types plus two tiny helpers; no React.

import type { PlaneACostProvenance, PlaneATraceIdentity } from "../../../shared/components/planea/types.ts";
import type { AdmissionMark } from "./admissionMark.ts";

/** Query params every window route takes. */
export type WindowQuery = { days: number };

// ---------------------------------------------------------------- traces

export interface AppTraceRow extends PlaneATraceIdentity {
  trace_id: string;
  root_name: string;
  source: string;
  session_id: string;
  status: string;
  started_at: string;
  ended_at: string;
  duration_ms: number;
  span_count: number;
  /** Null when no span of the trace is priced (L-06): never read it as $0. */
  cost_usd: number | null;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
  reasoning_tokens: number;
  total_tokens: number;
  error_count?: number;
  model?: string;
  provider?: string;
  /** The trace's most restrictive admission verdict (FX-C, B-1); absent
   *  when the trace has none. */
  admission?: AdmissionMark;
}

export interface AppTracesResult {
  traces: AppTraceRow[];
  total?: number;
  /** Per trace id: where its cost came from (W4-2, contracts/cost-source.md §5). */
  cost_provenance?: Record<string, PlaneACostProvenance>;
}

/** One span of GET /api/obs/trace/{id} (internal/obs/store SpanRow). Token
 *  and cost fields are null when not reported. */
export interface AppSpanRow {
  span_id: string;
  parent_span_id: string;
  kind: string;
  name: string;
  status: string;
  started_at: string;
  ended_at: string;
  duration_ms: number;
  model: string;
  provider: string;
  input_tokens: number | null;
  output_tokens: number | null;
  cache_read_tokens: number | null;
  cache_write_tokens: number | null;
  reasoning_tokens: number | null;
  cost_usd: number | null;
  cost_source: string;
  /** Every kept number (W4-2, contracts/cost-source.md §3). */
  cost_detail?: unknown;
  request_id: string;
  status_message?: string;
  error_type?: string;
}

export interface AppContentRow {
  span_id: string;
  kind: string;
  content: string;
  content_hash: string;
  time: string;
}

export interface AppProxyEnrichment {
  found: boolean;
  provider: string;
  model: string;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_creation_tokens: number;
  cost_usd: number;
}

/** One cost-bearing span of a TraceCost (contracts/cost-source.md §6). */
export interface AppSpanCost {
  span_id: string;
  model: string;
  cost_usd: number | null;
  cost_source: string;
  reported_usd: number | null;
  computed_usd: number | null;
  exact_usd: number | null;
  cost_delta_usd: number | null;
  gateway_request_id: string | null;
}

/** A trace's SDK-visible cost (contracts/cost-source.md §6). */
export interface AppTraceCost {
  trace_id: string;
  cost_usd: number | null;
  cost_provenance: PlaneACostProvenance;
  spans: AppSpanCost[];
}

export interface AppTraceDetail {
  trace: AppTraceRow;
  spans: AppSpanRow[];
  content: AppContentRow[];
  enrichments?: Record<string, AppProxyEnrichment>;
  /** W4-2: the trace's cost with each span's source (proxy_exact when this
   *  machine's proxy served the call) and the delta. */
  cost?: AppTraceCost;
  cost_provenance?: PlaneACostProvenance;
}

// -------------------------------------------------------------- sessions

export interface AppSessionRow extends PlaneATraceIdentity {
  session_id: string;
  trace_count: number;
  total_tokens: number;
  total_cost: number;
  error_count: number;
  first_at: string;
  last_at: string;
}

export interface AppSessionsResult {
  window_days: number;
  total: number;
  limit: number;
  offset: number;
  unsessioned: number;
  truncated: boolean;
  sessions: AppSessionRow[];
}

// ------------------------------------------------------------- analytics

export interface AppDimCount {
  key: string;
  traces: number;
  tokens: number;
  cost_usd: number;
}

export interface AppAnalyticsResult {
  window_days: number;
  truncated: boolean;
  total_traces: number;
  total_spans: number;
  total_tokens: number;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  reasoning_tokens: number;
  total_cost_usd: number;
  error_traces: number;
  error_rate: number;
  avg_duration_ms: number;
  latency_p50_ms: number;
  latency_p95_ms: number;
  latency_p99_ms: number;
  sessions: number;
  end_users: number;
  by_day: { date: string; traces: number; tokens: number; cost_usd: number; error_traces: number }[];
  by_model: AppDimCount[];
  by_source: AppDimCount[];
  by_service: AppDimCount[];
  by_environment: AppDimCount[];
  by_kind: { kind: string; spans: number; p50_ms: number; p95_ms: number; avg_ms: number }[];
  error_causes: AppDimCount[];
}

// ------------------------------------------------------------- end users

export interface AppEndUserRow {
  end_user: string;
  cost_usd: number;
  traces: number;
  total_tokens: number;
  cost_share: number;
  error_traces: number;
  p50_ms: number;
  p95_ms: number;
  sessions: number;
  last_at: string;
  service?: string;
}

export interface AppEndUsersResult {
  window_days: number;
  truncated: boolean;
  total_cost_usd: number;
  no_end_user_traces: number;
  no_end_user_cost_usd: number;
  end_users: AppEndUserRow[];
}

// ------------------------------------------------- evals (existing routes)

export interface AppEvalDataset {
  id: number;
  name: string;
  description: string;
  created_at: string;
  item_count: number;
}

/** GET /api/obs/eval/runs row (internal/obs/store EvalRunListRow). */
export interface AppEvalRun {
  id: number;
  dataset_id: number;
  dataset_name: string;
  name: string;
  scorers: string;
  started_at: string;
  ended_at: string;
  total: number;
  passed: number;
  mean_score: number;
  status: string;
}

/** One score of GET /api/obs/eval/run/{id} (RunScoreRow). */
export interface AppRunScore {
  item_id: number;
  span_id: string;
  trace_id: string;
  scorer: string;
  score: number;
  passed: boolean;
  rationale: string;
}

export interface AppEvalRunDetail {
  run: AppEvalRun;
  scores: AppRunScore[];
}

// ------------------------------------------------- scores (lane B7)

/** One score (contracts/scores.md section 3). */
export interface AppScore {
  id: string;
  trace_id: string;
  span_id?: string;
  name: string;
  value: string;
  value_num?: number | null;
  kind: "numeric" | "boolean" | "categorical" | string;
  source: string;
  comment?: string;
  comment_present?: boolean;
  scorer?: { name?: string; version?: string };
  run_id?: string;
  created_at: string;
}

export interface AppScoresResult {
  scores: AppScore[];
  next_cursor?: string;
}

/** One row of GET /api/obs/scores/summary (contracts/scores.md section 7:
 *  per name, source and kind). Every aggregate is optional: which ones
 *  apply depends on the kind. */
export interface AppScoreSummaryRow {
  name: string;
  source: string;
  kind: string;
  count: number;
  mean?: number | null;
  min?: number | null;
  max?: number | null;
  p50?: number | null;
  true_rate?: number | null;
  top_values?: { value: string; count: number }[] | null;
}

// ------------------------------------------------ prompts (lane B8)

/** One prompt in GET /api/obs/sdk/prompts (contracts/prompts.md section 3). */
export interface AppPromptListRow {
  name: string;
  type: string;
  latest_version: number;
  labels: Partial<Record<"production" | "staging", number>>;
  updated_at: string;
}

export interface AppPromptList {
  prompts: AppPromptListRow[];
  next_after?: string;
}

/** One resolved prompt (contracts/prompts.md section 2's 200 body). */
export interface AppPrompt {
  name: string;
  version: number;
  type: string;
  prompt: unknown;
  config?: unknown;
  labels?: string[];
  variables?: string[];
  created_at?: string;
}

// ------------------------------------------------- alerts (lane B9)

export type AppAlertDimensions = { model: string; user: string; tag: string; service: string };

export interface AppAlertRule {
  name: string;
  metric: string;
  comparator: string;
  threshold: number;
  window_minutes: number;
  cooldown_minutes: number;
  dimensions: AppAlertDimensions;
  current_value: number | null;
  breaching: boolean;
  last_fired_at: string;
}

export interface AppAlertsResult {
  enabled: boolean;
  interval_minutes: number;
  webhook_configured: boolean;
  slack_configured: boolean;
  /** Lane C9 (W5-5); absent from an older daemon. */
  pagerduty_configured?: boolean;
  email: boolean;
  metrics: string[];
  dimensions: string[];
  rules: AppAlertRule[];
}

export interface AppAlertFiring {
  rule_name: string;
  metric: string;
  comparator: string;
  threshold: number;
  value: number;
  window_minutes: number;
  dimensions: AppAlertDimensions;
  delivered: boolean;
  fired_at: string;
}

/** One group of GET /api/obs/explorer/groups (contracts/alerts.md). */
export interface AppExplorerGroup {
  group_key: string;
  label: string;
  trace_count: number;
  error_count: number;
  error_rate: number;
  total_tokens: number;
  // null when no span in the group is priced (the table prints "Unpriced").
  total_cost_usd: number | null;
  avg_cost_per_trace: number | null;
  p50_duration_ms: number;
  p95_duration_ms: number;
  p99_duration_ms: number;
  first_at: string;
  last_at: string;
}

export interface AppExplorerGroups {
  by: string;
  window_days: number;
  total_groups: number;
  truncated_groups: number;
  groups: AppExplorerGroup[];
  // How a trace's tokens and cost reach its groups: "span" (by model) or
  // "trace" (the whole trace counts under each of its groups).
  attribution?: "span" | "trace";
  // True when one trace can count in full under several groups, so the
  // totals can add up to more than the window; note says so in words.
  totals_may_overlap?: boolean;
  note?: string;
}

// ------------------------------------------------------------ helpers

/** The Your apps window choices (days). */
export const APP_WINDOWS = [1, 7, 30, 90] as const;

/** routeMissing reports a read whose route this daemon does not serve yet
 *  (a 404, or the SPA shell answering an unknown path: a non-JSON body).
 *  Pages show "needs a newer daemon" for it, never a generic failure. */
export function routeMissing(err: unknown): boolean {
  if (err == null) return false;
  const status = (err as { status?: unknown }).status;
  if (typeof status === "number") return status === 404;
  return err instanceof SyntaxError || /JSON|Unexpected token/i.test(String((err as Error).message ?? err));
}
