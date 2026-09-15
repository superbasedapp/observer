// Typed view of the observer dashboard's /api/* surface, sized to
// what the extension consumes (not the whole REST API).
//
// Captured live against http://127.0.0.1:8081/api/analysis/headline
// on 2026-06-02. Fields the status bar / sidebar read are strictly
// typed; fields they don't are passed through as `unknown` so
// upstream wire-shape evolution doesn't break the bundle.

export interface HeadlinePeriod {
  cost_usd: number;
  delta_pct: number;
  period_start: string;
  prior_cost_usd: number;
  prior_is_zero: boolean;
  prior_start: string;
  recorded_cost_share_pct: number;
}

export interface HeadlineTopModel {
  key: string;
  cost_usd: number;
  concentration_pct: number;
}

export interface HeadlineMonth {
  budget_pct: number;
  budget_usd: number;
  days_elapsed: number;
  days_in_month: number;
  prior_month_is_zero: boolean;
  prior_month_same_day_usd: number;
  projection_usd: number;
  to_date_usd: number;
  vs_prior_month_pct: number;
}

export interface HeadlineBurnRate {
  active_hours: number;
  cost_per_hour_usd: number;
  method_note?: string;
}

export interface HeadlineResponse {
  days: number;
  period: HeadlinePeriod;
  top_model: HeadlineTopModel;
  month: HeadlineMonth;
  burn_rate: HeadlineBurnRate;
  // Pass-through fields we don't model strictly so wire-shape drift
  // upstream (waste, high_context, cache_savings, …) doesn't break
  // the bundle. The status bar + sidebar only need the four above.
  [key: string]: unknown;
}

export interface HealthResponse {
  ok: boolean;
  [key: string]: unknown;
}

// -- /api/file/state -------------------------------------------------

export interface FileStateResponse {
  path: string;
  last_read_at: string;
  last_read_by: string;
  edit_count_24h: number;
  stale_rereads_24h: number;
  tools_touched: string[];
  [key: string]: unknown;
}

// -- /api/health/watcher --------------------------------------------

export interface WatcherFileLag {
  path: string;
  byte_offset: number;
  file_size: number;
  behind_bytes: number;
  behind_seconds?: number;
  last_parsed?: string;
  action_count?: number;
  suspected_misrouted?: boolean;
  misroute_reason?: string;
  [key: string]: unknown;
}

export interface WatcherHealthResponse {
  behind_count: number;
  behind_total_bytes: number;
  checked_at: string;
  files: WatcherFileLag[];
  [key: string]: unknown;
}

// -- /api/sessions ----------------------------------------------------

export interface SessionRow {
  id: string;
  tool: string;
  project: string;
  started_at: string;
  last_seen_at: string;
  duration_seconds: number;
  total_actions: number;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_creation_tokens: number;
  total_tokens: number;
  cost_usd: number;
  ai_cost_usd: number;
  tool_cost_usd: number;
  cost_reliability: string;
  models: string[];
  // title is the developer's OWN session title (migration 116) — distinct
  // from cloud_title (the AI-generated one) and always wins over it wherever
  // an "effective title" is rendered. Both optional/absent when unset.
  title?: string;
  cloud_title?: string;
  [key: string]: unknown;
}

export interface SessionsResponse {
  days: number;
  limit: number;
  page: number;
  rows: SessionRow[];
  [key: string]: unknown;
}

// -- /api/discover ---------------------------------------------------

export interface DiscoverCrossToolFile {
  file_path: string;
  project: string;
  tools: string[];
  accesses: number;
  [key: string]: unknown;
}

export interface DiscoverResponse {
  cross_tool_files: DiscoverCrossToolFile[];
  [key: string]: unknown;
}

// -- /api/cost -------------------------------------------------------

export interface CostTokens {
  input: number;
  output: number;
  cache_read: number;
  cache_creation: number;
  reasoning: number;
  web_search_requests: number;
  [key: string]: unknown;
}

export interface CostRow {
  key: string;
  tokens: CostTokens;
  cost_usd: number;
  ai_cost_usd: number;
  tool_cost_usd: number;
  turn_count: number;
  source: string;
  reliability: string;
  pricing_source: string;
  [key: string]: unknown;
}

export interface CostResponse {
  group_by: string;
  source: string;
  days: number;
  since: string;
  rows: CostRow[];
  [key: string]: unknown;
}

export interface CacheWindow {
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
}

export interface CacheKeepWarmRecommendation {
  action: string;
  pays_off: boolean;
  projected_savings_usd: number;
  resume_confidence: number;
  rationale: string;
}

export interface CacheWindowStatus {
  window: CacheWindow;
  severity: string;
  seconds_to_expiry: number;
  value_at_risk_usd: number;
  estimated: boolean;
  recommendation: CacheKeepWarmRecommendation;
}

export interface CacheStatusResponse {
  enabled: boolean;
  keepwarm_mode: string;
  windows: CacheWindowStatus[] | null;
}
