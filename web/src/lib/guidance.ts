// Guidance-file discovery for the Projects page: per-project instructions /
// skills / agents / commands / rules / config files the AI tools themselves
// read (CLAUDE.md, .cursorrules, AGENTS.md, .claude/skills/*, etc). The Go
// side (`internal/...` guidance scanner, built in parallel) owns discovery +
// parsing; this module is a thin typed fetch layer + the pure grouping/label
// helpers the page and card need.
//
// Types mirror the API contract in the GUID-C bundle brief:
//   GET /api/projects/guidance/summary -> GuidanceSummaryRow[]
//   GET /api/projects/guidance?root=<abs> -> ProjectGuidanceResponse
//   GET /api/projects/guidance/file?root=<abs>&rel=<rel> -> GuidanceFileResponse

import { fetchJSON } from "@/lib/api";
import { toolMeta } from "@/lib/tools";

export type GuidanceKind =
  | "instructions"
  | "skill"
  | "agent"
  | "command"
  | "rule"
  | "config";

export type GuidanceScope = "project" | "user";

export type GuidanceRow = {
  project_root: string;
  tool: string;
  kind: GuidanceKind;
  scope: GuidanceScope;
  // rel_path only: the API deliberately does not serialize the absolute
  // host path (project-scope rows are relative to the project root,
  // user-scope rows are "~/"-prefixed and relative to the home directory).
  rel_path: string;
  name: string;
  description?: string;
  size_bytes: number;
  content_hash?: string;
  modified_at?: string;
  frontmatter?: Record<string, string>;
  present: boolean;
  first_seen?: string;
  last_scanned?: string;
  parse_error?: string;
  // Wave-2 usage join. invoked_* count skill_invoke actions matched on the
  // backend's SkillKey identity; loaded_* count instructions_loaded actions
  // matched on the file's absolute path. Both are scoped to this project and
  // to the response's usage_window_days.
  invoked_count?: number;
  last_invoked_at?: string;
  loaded_count?: number;
  last_loaded_at?: string;
  // usage is the honest three-way answer. `not_measurable` is NOT a zero:
  // it means no capture signal exists that could ever name this file for
  // this tool, so the UI must never render it as "never invoked".
  usage?: GuidanceUsageState;
};

export type GuidanceUsageState = "invoked" | "never_invoked" | "not_measurable";

export type GuidanceSummaryRow = {
  project_root: string;
  files: number;
  last_scanned?: string;
};

export type ProjectGuidanceResponse = {
  root: string;
  scanned_at?: string;
  rows: GuidanceRow[];
  // Keyed by tool id. `false` means Observer cannot tell whether the tool
  // actually invoked/used the file at all (never render "0 invocations" for
  // those — see usageLine below). `true` means a capture signal exists, and
  // since wave 2 each row of such a tool also carries a real count.
  //
  // Note this is a per-TOOL answer; measurability is really per (tool, kind)
  // — a tool can emit skill_invoke without emitting instructions_loaded — so
  // the authoritative per-row answer is the row's own `usage` field.
  tools_measurable: Record<string, boolean>;
  // usage_window_days is the lookback the per-row counts cover (90 today).
  usage_window_days?: number;
  usage_since?: string;
  // usage_unavailable means the backend's usage read did not complete
  // (bounded by a server-side timeout), so every row's `usage` is
  // `not_measurable` for THAT reason rather than because the tool emits no
  // signal. The two must read differently: "Observer cannot see this" vs
  // "Observer did not look this time".
  usage_unavailable?: boolean;
  usage_error_class?: "timeout" | "query";
};

export const DEFAULT_GUIDANCE_USAGE_WINDOW_DAYS = 90;

export type GuidanceFileResponse = {
  rel_path: string;
  content: string;
  truncated: boolean;
  scrubbed: boolean;
};

export const PROJECTS_GUIDANCE_SUMMARY_PATH = "/api/projects/guidance/summary";
export const PROJECTS_GUIDANCE_PATH = "/api/projects/guidance";
export const PROJECTS_GUIDANCE_FILE_PATH = "/api/projects/guidance/file";

export function fetchProjectsGuidanceSummary(
  signal?: AbortSignal,
): Promise<GuidanceSummaryRow[]> {
  return fetchJSON<GuidanceSummaryRow[]>(PROJECTS_GUIDANCE_SUMMARY_PATH, undefined, {
    signal,
  });
}

export function fetchProjectGuidance(
  root: string,
  signal?: AbortSignal,
): Promise<ProjectGuidanceResponse> {
  return fetchJSON<ProjectGuidanceResponse>(
    PROJECTS_GUIDANCE_PATH,
    { root },
    { signal },
  );
}

export function fetchGuidanceFile(
  root: string,
  rel: string,
  signal?: AbortSignal,
): Promise<GuidanceFileResponse> {
  return fetchJSON<GuidanceFileResponse>(
    PROJECTS_GUIDANCE_FILE_PATH,
    { root, rel },
    { signal },
  );
}

// ---------------------------------------------------------------- labels

export const KIND_ORDER: GuidanceKind[] = [
  "instructions",
  "skill",
  "agent",
  "command",
  "rule",
  "config",
];

const KIND_LABELS: Record<GuidanceKind, string> = {
  instructions: "Instructions",
  skill: "Skills",
  agent: "Agents",
  command: "Commands",
  rule: "Rules",
  config: "Config",
};

// formatKind renders the plural section label for a guidance kind. Falls
// back to a title-cased echo of the raw value for a kind the frontend
// doesn't know about yet (additive — a new backend kind never breaks the
// page).
export function formatKind(kind: string): string {
  return KIND_LABELS[kind as GuidanceKind] ?? titleCase(kind);
}

// formatTool reuses the shared tool registry so a guidance-file's tool
// label matches every other tool badge in the dashboard rather than
// maintaining a second name map.
export function formatTool(tool: string): string {
  return toolMeta(tool).label;
}

function titleCase(s: string): string {
  if (!s) return s;
  return s
    .split(/[-_\s]+/)
    .filter(Boolean)
    .map((w) => w[0].toUpperCase() + w.slice(1))
    .join(" ");
}

// ---------------------------------------------------------------- grouping

export type GuidanceKindGroup = {
  kind: GuidanceKind | string;
  rows: GuidanceRow[];
};

export type GuidanceToolGroup = {
  tool: string;
  kinds: GuidanceKindGroup[];
  total: number;
};

// groupGuidance is pure: rows in, grouped-by-tool-then-kind out. Callers
// decide scope splitting (e.g. filter to scope==="project" vs "user" before
// calling this) so the grouping itself carries no scope opinion.
//
// Ordering: tools alphabetically by their display label (stable regardless
// of API row order), kinds in the fixed KIND_ORDER with any unknown kind
// appended after, rows within a kind by name.
export function groupGuidance(rows: GuidanceRow[]): GuidanceToolGroup[] {
  const byTool = new Map<string, GuidanceRow[]>();
  for (const r of rows) {
    const list = byTool.get(r.tool);
    if (list) list.push(r);
    else byTool.set(r.tool, [r]);
  }

  const groups: GuidanceToolGroup[] = [];
  for (const [tool, toolRows] of byTool) {
    const byKind = new Map<string, GuidanceRow[]>();
    for (const r of toolRows) {
      const list = byKind.get(r.kind);
      if (list) list.push(r);
      else byKind.set(r.kind, [r]);
    }
    const kinds: GuidanceKindGroup[] = [];
    for (const kind of KIND_ORDER) {
      const kindRows = byKind.get(kind);
      if (kindRows) {
        kinds.push({ kind, rows: sortRows(kindRows) });
        byKind.delete(kind);
      }
    }
    // Any kind the fixed order doesn't know about yet — appended, sorted
    // alphabetically, never dropped.
    for (const kind of [...byKind.keys()].sort()) {
      kinds.push({ kind, rows: sortRows(byKind.get(kind)!) });
    }
    groups.push({ tool, kinds, total: toolRows.length });
  }

  groups.sort((a, b) => formatTool(a.tool).localeCompare(formatTool(b.tool)));
  return groups;
}

function sortRows(rows: GuidanceRow[]): GuidanceRow[] {
  return [...rows].sort((a, b) => a.name.localeCompare(b.name));
}

// usageLine returns the per-tool honesty line: never a fabricated
// "0 invocations" count. `measurable` is `tools_measurable[tool]` from the
// API response (undefined treated as false — the conservative, honest
// default when the backend hasn't reported on a tool at all).
export function usageLine(
  tool: string,
  measurable: boolean | undefined,
  windowDays: number = DEFAULT_GUIDANCE_USAGE_WINDOW_DAYS,
): string {
  if (!measurable) {
    return `Usage is not measurable for ${formatTool(tool)} yet`;
  }
  return `Usage tracked over the last ${windowDays}d`;
}

// ---------------------------------------------------------------- usage

// GuidanceUsagePill is the structured per-row usage fact the card renders.
// It carries no formatted time on purpose: relative-time formatting lives in
// lib/format, and keeping this pure means the "what do we actually know"
// decision is testable and has exactly one home.
//
// A row whose `usage` is `not_measurable` yields null — the tool-group header
// already says so, and a per-row pill there would be noise pretending to be
// data.
export type GuidanceUsagePill = {
  // "invoked" for skills (a skill_invoke action), "loaded" for always-on
  // instruction files (an instructions_loaded action). Different verbs
  // because they are genuinely different events.
  verb: "invoked" | "loaded";
  count: number;
  last?: string;
  never: boolean;
};

export function guidanceUsagePill(row: GuidanceRow): GuidanceUsagePill | null {
  if (!row.usage || row.usage === "not_measurable") return null;
  // A row can in principle carry both counts (a file that is both loaded and
  // invoked); the kind decides which event the pill is about.
  const loaded = row.kind === "instructions";
  const count = (loaded ? row.loaded_count : row.invoked_count) ?? 0;
  const last = loaded ? row.last_loaded_at : row.last_invoked_at;
  return {
    verb: loaded ? "loaded" : "invoked",
    count,
    last: count > 0 ? last : undefined,
    never: row.usage === "never_invoked" || count === 0,
  };
}

// GuidanceUsageSummary counts only what is MEASURABLE. `measurable` is the
// denominator a summary line may honestly use: counting a cursor rule (which
// no capture signal can name) as "not invoked" would turn an unmeasured file
// into an unused one.
export type GuidanceUsageSummary = {
  measurable: number;
  invoked: number;
};

export function summarizeGuidanceUsage(
  rows: GuidanceRow[],
  kind?: GuidanceKind,
): GuidanceUsageSummary {
  let measurable = 0;
  let invoked = 0;
  for (const r of rows) {
    if (kind && r.kind !== kind) continue;
    if (!r.usage || r.usage === "not_measurable") continue;
    measurable++;
    if (r.usage === "invoked") invoked++;
  }
  return { measurable, invoked };
}

// formatGuidanceUsageSummary renders the Projects-panel headline, or null
// when there is nothing measurable to summarise (in which case the panel says
// nothing rather than "0 of 0").
export function formatGuidanceUsageSummary(
  summary: GuidanceUsageSummary,
  windowDays: number = DEFAULT_GUIDANCE_USAGE_WINDOW_DAYS,
  noun = "skills",
): string | null {
  if (summary.measurable === 0) return null;
  return `${summary.invoked} of ${summary.measurable} ${noun} invoked in ${windowDays}d`;
}

// formatUsageUnavailable is the copy for a degraded usage read. It says what
// happened, not what the data shows, because in this state there is no data
// to show — and it must never be confused with a real "never invoked".
export function formatUsageUnavailable(
  errorClass: ProjectGuidanceResponse["usage_error_class"],
): string {
  return errorClass === "timeout"
    ? "Usage counts unavailable - the lookup timed out. The inventory below is complete."
    : "Usage counts unavailable - the lookup failed. The inventory below is complete.";
}
