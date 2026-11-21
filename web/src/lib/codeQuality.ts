// codeQuality.ts: the Projects page Quality tab's wire types and its pure
// wording (docs/projects-page.md "Quality metrics"). The server decides
// every state and its reason (internal/codequality's ordered state tables);
// this module only formats what it sent. A metric whose state is not
// "measured" is NEVER rendered as a number: the tile shows "not measured"
// and the server's reason.

export type QualityState =
  | "measured"
  | "off"
  | "root_missing"
  | "no_report"
  | "unreadable"
  | "no_lines"
  | "not_in_build"
  | "archived"
  | "codeintel_off"
  | "not_indexed"
  | "no_symbols"
  | "no_supported_files"
  | "count_pending"
  | "no_functions";

export interface QualityReport {
  path: string;
  format: "lcov" | "cobertura" | "jacoco" | "gocover";
  modified_at: string;
  lines: number;
  covered: number;
  files: number;
  totals_only?: boolean;
  skipped_records?: number;
  use: "counted" | "same_run";
  same_run_as?: string;
}

export interface QualityProblem {
  path: string;
  kind: "too_large" | "symlink" | "unreadable" | "unrecognized" | "parse_error" | "no_lines" | "capped";
}

export interface QualityFileLine {
  path: string;
  report: string;
  lines: number;
  covered: number;
  percent?: number;
}

export interface QualityCloneGroup {
  size: number;
  lines: number;
  members: { name: string; file: string; start_line: number; end_line: number }[];
}

export interface QualityCoverage {
  state: QualityState;
  reason: string;
  lines: number;
  covered: number;
  percent?: number;
  newest_report_at?: string;
  oldest_report_at?: string;
  reports: QualityReport[];
  problems: QualityProblem[];
  least_covered: QualityFileLine[];
  locations: { path: string; format: string; writer: string }[];
}

export interface QualityDuplication {
  state: QualityState;
  reason: string;
  eligible_symbols: number;
  cloned_symbols: number;
  eligible_lines: number;
  cloned_lines: number;
  groups: number;
  symbol_share?: number;
  line_share?: number;
  top_groups: QualityCloneGroup[];
  skipped_buckets: number;
  indexed_files: number;
  last_indexed_at?: string;
  stale: boolean;
  truncated: boolean;
  method: { min_lines: number; min_shared_bands: number; total_bands: number; kinds: string[] };
}

export interface QualityComplexFunction {
  name: string;
  kind: string;
  lang: string;
  file: string;
  start_line: number;
  end_line: number;
  complexity: number;
}

export interface QualityComplexity {
  state: QualityState;
  reason: string;
  functions: number;
  over: number;
  over_share?: number;
  mean?: number;
  p50: number;
  p90: number;
  max: number;
  per_language: { lang: string; functions: number; over: number; p90: number; max: number }[];
  top: QualityComplexFunction[];
  counted_files: number;
  pending_files: number;
  uncounted_files: number;
  uncounted_langs: string[];
  indexed_files: number;
  last_indexed_at?: string;
  stale: boolean;
  truncated: boolean;
  method: { threshold: number; kinds: string[] };
}

export interface QualityDay {
  day: string;
  measured_at: string;
  coverage_state: QualityState;
  coverage_percent?: number;
  coverage_lines: number;
  dup_state: QualityState;
  dup_line_share?: number;
  dup_cloned_lines: number;
  dup_groups: number;
  // "" for a day recorded before complexity was.
  complexity_state: QualityState | "";
  complexity_over_share?: number;
  complexity_functions: number;
  complexity_p90: number;
  complexity_max: number;
}

export interface QualityChange {
  from_day?: string;
  to_day?: string;
  from?: number;
  to?: number;
  delta?: number;
  days: number;
}

export interface ProjectQuality {
  project_id: number;
  enabled: boolean;
  measured_at: string;
  coverage: QualityCoverage;
  duplication: QualityDuplication;
  complexity: QualityComplexity;
  history: QualityDay[];
  trend: { coverage: QualityChange; duplication: QualityChange; complexity: QualityChange };
  window_days: number;
}

// A short label per state, for a tile's headline when not measured.
const STATE_LABEL: Record<QualityState, string> = {
  measured: "measured",
  off: "off",
  root_missing: "folder not on this machine",
  no_report: "no coverage report found",
  unreadable: "report unreadable",
  no_lines: "report has no lines",
  not_in_build: "not in this build",
  archived: "index archived",
  codeintel_off: "code intelligence off",
  not_indexed: "not indexed yet",
  no_symbols: "no functions to compare",
  no_supported_files: "no counted language",
  count_pending: "waiting for the next index",
  no_functions: "no functions counted",
};

/**
 * stateLabel is the short label of a not-measured state. An empty state is
 * a day recorded before that metric was, shown as a dash.
 */
export function stateLabel(state: QualityState | string): string {
  if (state === "") return "—";
  return STATE_LABEL[state as QualityState] ?? state;
}

/** isMeasured reports whether a metric may show numbers. */
export function isMeasured(state: QualityState | string): boolean {
  return state === "measured";
}

/** pct formats a server percentage (already 0-100), or a dash when absent. */
export function pct(v: number | undefined | null, digits = 1): string {
  if (v == null || !Number.isFinite(v)) return "—";
  return `${v.toFixed(digits)}%`;
}

/**
 * coverageHeadline is the coverage tile's value: the percentage when
 * measured, else "not measured" (never 0%).
 */
export function coverageHeadline(c: QualityCoverage): string {
  return isMeasured(c.state) ? pct(c.percent) : "not measured";
}

/** duplicationHeadline is the duplication tile's value. */
export function duplicationHeadline(d: QualityDuplication): string {
  return isMeasured(d.state) ? pct(d.line_share) : "not measured";
}

/**
 * complexityHeadline is the complexity tile's value: the share of functions
 * over the threshold when measured, else "not measured" (never 0%).
 */
export function complexityHeadline(c: QualityComplexity): string {
  return isMeasured(c.state) ? pct(c.over_share) : "not measured";
}

/**
 * complexityFilesNote says which indexed files the figure leaves out and
 * why: files waiting for the next index pass, and files no counter covers
 * (heuristic parser or a language without a rule table). "" when none.
 */
export function complexityFilesNote(c: QualityComplexity): string {
  const parts: string[] = [];
  if (c.pending_files > 0) {
    parts.push(`${c.pending_files} file${c.pending_files === 1 ? " waits" : "s wait"} for the next index pass`);
  }
  if (c.uncounted_files > 0) {
    const langs = c.uncounted_langs.length > 0 ? ` (${c.uncounted_langs.join(", ")})` : "";
    parts.push(
      `${c.uncounted_files} file${c.uncounted_files === 1 ? " has" : "s have"} no counter${langs}: heuristic parser or a language without a rule table`,
    );
  }
  return parts.join("; ");
}

/**
 * changeText states a metric's movement over the window in percentage
 * points: "+3.2 pts since 2026-10-05 (12 measured days)". With fewer than
 * two measured days it says so instead of inventing a trend.
 */
export function changeText(c: QualityChange): string {
  if (c.days === 0) return "no measured days in this window";
  if (c.delta == null || c.days < 2) return "one measured day in this window, no trend yet";
  const sign = c.delta > 0 ? "+" : c.delta < 0 ? "−" : "±";
  return `${sign}${Math.abs(c.delta).toFixed(1)} pts since ${c.from_day} (${c.days} measured days)`;
}

const PROBLEM_TEXT: Record<QualityProblem["kind"], string> = {
  too_large: "too large to read",
  symlink: "a symbolic link, not followed",
  unreadable: "could not be read",
  unrecognized: "not a coverage format Observer reads",
  parse_error: "could not be parsed",
  no_lines: "holds no instrumented lines",
  capped: "skipped, too many reports",
};

/** problemText is the reason a found report was not used. */
export function problemText(kind: QualityProblem["kind"] | string): string {
  return PROBLEM_TEXT[kind as QualityProblem["kind"]] ?? kind;
}

const FORMAT_LABEL: Record<string, string> = {
  lcov: "lcov",
  cobertura: "Cobertura XML",
  jacoco: "JaCoCo XML",
  gocover: "Go coverprofile",
};

/** formatLabel names a report format. */
export function formatLabel(f: string): string {
  return FORMAT_LABEL[f] ?? f;
}
