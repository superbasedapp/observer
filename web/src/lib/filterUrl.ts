// filterUrl - the global FilterBar state <-> query-string codec.
//
// The node dashboard's global filters (window, custom range, tool, project,
// model, free-text query) live in the URL so a reload, back/forward and a copied
// link all land on the same view. This module is the ONE owner of that
// mapping: FILTER_PARAMS is a table walked top-down (param name -> filter
// field -> parse/validate -> default). A value that does not parse is
// IGNORED (the field falls back), never guessed.
//
// Param names deliberately avoid the page-owned ones (Sessions ?session=
// ?watch=, the session and project drawers' ?dtab=, every page tab's ?tab=,
// Settings ?section=, Search ?q=, Projects/Cost statement ?project= ?root=,
// Benchmarks ?run=, Routing ?reason= ?applied=, Cost statement ?month=,
// Terminals ?dock=, Code security's Findings filters, lib/codeSecurityApi.ts
// FINDINGS_URL_PARAMS, pinned apart in its test): applyFilterParams only
// ever sets or deletes the names in this table, so a page's own params are
// never clobbered.
//
// Pure (no React, no router, no DOM) so it runs under node --test.

import { parseGranChoice, type GranChoice } from "../../../shared/lib/granularity.ts";

/** Window is the global time-scope selector shared by every page. */
export type Window =
  | "1h"
  | "12h"
  | "1d"
  | "7d"
  | "14d"
  | "30d"
  | "90d"
  | "1y"
  | "all"
  | "custom";

/**
 * CustomRange holds RFC3339-UTC ISO strings for the "custom" window. `until`
 * may be "" meaning "now".
 */
export type CustomRange = { since: string; until: string };

/** UrlFilters is the slice of filter state that travels in the URL. */
export type UrlFilters = {
  win: Window;
  customRange: CustomRange;
  tool: string;
  project: string;
  /**
   * model is the global Model filter (`model=`; "all" = unfiltered). The
   * value is a model id exactly as the store holds it ("claude-opus-4-7",
   * "openrouter/qwen/qwen3-coder:free"); the server decides grain
   * (internal/modelfilter).
   */
  model: string;
  query: string;
  /**
   * gran is the chart time granularity (`gran=`; "auto" = the shared Auto
   * rule in shared/lib/granularity.ts). Global like the window: every
   * time-series card's control reads and writes this one value.
   */
  gran: GranChoice;
};

export const WINDOW_VALUES: readonly Window[] = [
  "1h",
  "12h",
  "1d",
  "7d",
  "14d",
  "30d",
  "90d",
  "1y",
  "all",
  "custom",
];

/** isWindow reports whether v is one of the window presets. */
export function isWindow(v: unknown): v is Window {
  return typeof v === "string" && (WINDOW_VALUES as readonly string[]).includes(v);
}

// RFC3339_TZ matches an ISO-8601 datetime that carries an EXPLICIT timezone
// (`Z` or a `+HH:MM` offset). Date-only and timezone-less datetimes are
// excluded: Date.parse accepts them but the strict RFC3339 backend rejects
// them.
const RFC3339_TZ =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?(\.\d+)?(Z|[+-]\d{2}:?\d{2})$/;

/**
 * canonicalIso normalizes an RFC3339 string to canonical UTC form (always
 * `...Z`), or returns null when the value is not a timezone-explicit,
 * parseable datetime.
 */
export function canonicalIso(v: unknown): string | null {
  if (typeof v !== "string" || !RFC3339_TZ.test(v)) return null;
  const ms = Date.parse(v);
  if (!Number.isFinite(ms)) return null;
  return new Date(ms).toISOString();
}

/**
 * validRange returns the canonical range when `since` parses and `until` is
 * either empty or parses AND is strictly after `since`; otherwise null.
 */
export function validRange(since: unknown, until: unknown): CustomRange | null {
  const s = canonicalIso(since);
  if (!s) return null;
  if (until == null || until === "") return { since: s, until: "" };
  const u = canonicalIso(until);
  if (!u || Date.parse(u) <= Date.parse(s)) return null;
  return { since: s, until: u };
}

/** FILTER_DEFAULTS is what every field falls back to. */
export const FILTER_DEFAULTS: UrlFilters = {
  win: "30d",
  customRange: { since: "", until: "" },
  tool: "all",
  project: "all",
  model: "all",
  query: "",
  gran: "auto",
};

// Free-text fields: no control characters, bounded length. A tool id is a
// short slug; a project filter is a root path; the query is what the palette
// input holds.
const TOOL_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
// eslint-disable-next-line no-control-regex
const CONTROL_RE = /[\u0000-\u001f\u007f]/;

function parseTool(raw: string): string | null {
  return TOOL_RE.test(raw) ? raw : null;
}

function parseText(max: number) {
  return (raw: string): string | null =>
    raw.trim() !== "" && raw.length <= max && !CONTROL_RE.test(raw) ? raw : null;
}

// A project root HASH (sha256 hex of the root, Code security's spelling) is
// never a root path. Code security's Findings tab wrote one under `proj=`
// until 2026-11-06 (lib/codeSecurityApi.ts), so links from that build (a
// bookmark, the history, an open tab) still carry one: it is ignored, never
// shown in the Project chip as a raw hash or sent as the project filter.
const ROOT_HASH_RE = /^[0-9a-f]{64}$/i;

function parseProject(raw: string): string | null {
  const v = parseText(4096)(raw);
  return v != null && !ROOT_HASH_RE.test(v.trim()) ? v : null;
}

/**
 * FilterParam is one row of the table: the query-string name, the filter
 * field it carries, how to parse a raw value (null = invalid, ignore), and
 * how to read the field back for writing (null = at default, omit the param).
 */
export type FilterParam = {
  param: string;
  field: "win" | "since" | "until" | "tool" | "project" | "model" | "query" | "gran";
  parse: (raw: string) => string | null;
  write: (f: UrlFilters) => string | null;
};

/** FILTER_PARAMS is the table, walked top-down. */
export const FILTER_PARAMS: readonly FilterParam[] = [
  {
    param: "window",
    field: "win",
    parse: (raw) => (isWindow(raw) ? raw : null),
    write: (f) => (f.win === FILTER_DEFAULTS.win ? null : f.win),
  },
  {
    // since/until only mean something under window=custom; they are only
    // written then, and only honoured when they form a valid range.
    param: "since",
    field: "since",
    parse: canonicalIso,
    write: (f) => (f.win === "custom" ? canonicalIso(f.customRange.since) : null),
  },
  {
    param: "until",
    field: "until",
    parse: canonicalIso,
    write: (f) =>
      f.win === "custom" && f.customRange.until ? canonicalIso(f.customRange.until) : null,
  },
  {
    param: "tool",
    field: "tool",
    parse: parseTool,
    write: (f) => (f.tool === FILTER_DEFAULTS.tool || f.tool === "" ? null : f.tool),
  },
  {
    param: "proj",
    field: "project",
    parse: parseProject,
    write: (f) => (f.project === FILTER_DEFAULTS.project || f.project === "" ? null : f.project),
  },
  {
    // Model ids carry "/", ":" and "." ("openrouter/qwen/qwen3-coder:free"),
    // so the parse is the bounded free-text rule, capped where the server's
    // own bound (internal/modelfilter.MaxLen) is.
    param: "model",
    field: "model",
    parse: parseText(200),
    write: (f) => (f.model === FILTER_DEFAULTS.model || f.model === "" ? null : f.model),
  },
  {
    param: "search",
    field: "query",
    parse: parseText(200),
    write: (f) => (f.query.trim() === "" ? null : f.query),
  },
  {
    param: "gran",
    field: "gran",
    parse: (raw) => parseGranChoice(raw),
    write: (f) => (f.gran === FILTER_DEFAULTS.gran ? null : f.gran),
  },
];

/** FILTER_PARAM_NAMES lists every query-string name this module owns. */
export const FILTER_PARAM_NAMES: readonly string[] = FILTER_PARAMS.map((r) => r.param);

/**
 * parseFilterParams reads the filter fields PRESENT and VALID in `search`
 * (a location.search string, with or without the leading "?"). Absent or
 * invalid params are simply missing from the result. window=custom only
 * survives with a valid since/until pair; since/until without
 * window=custom are ignored.
 */
export function parseFilterParams(search: string): Partial<UrlFilters> {
  const p = new URLSearchParams(search);
  const raw: Partial<Record<FilterParam["field"], string>> = {};
  for (const row of FILTER_PARAMS) {
    const v = p.get(row.param);
    if (v == null) continue;
    const parsed = row.parse(v);
    if (parsed != null) raw[row.field] = parsed;
  }
  const out: Partial<UrlFilters> = {};
  if (raw.win === "custom") {
    const range = validRange(raw.since, raw.until ?? "");
    if (range) {
      out.win = "custom";
      out.customRange = range;
    }
  } else if (raw.win) {
    out.win = raw.win as Window;
  }
  if (raw.tool != null) out.tool = raw.tool;
  if (raw.project != null) out.project = raw.project;
  if (raw.model != null) out.model = raw.model;
  if (raw.query != null) out.query = raw.query;
  if (raw.gran != null) out.gran = raw.gran as GranChoice;
  return out;
}

/**
 * serializeFilterParams maps filter state to {param: value | null}; null
 * means "at default, omit the param".
 */
export function serializeFilterParams(f: UrlFilters): Record<string, string | null> {
  const out: Record<string, string | null> = {};
  for (const row of FILTER_PARAMS) out[row.param] = row.write(f);
  return out;
}

/**
 * applyFilterParams returns `search` with this module's params set to the
 * state in `f` (and removed at their default). Every other param is left
 * exactly as it was, in its original order. Returns "" or "?a=b...".
 */
export function applyFilterParams(search: string, f: UrlFilters): string {
  const p = new URLSearchParams(search);
  for (const [name, value] of Object.entries(serializeFilterParams(f))) {
    if (value == null) p.delete(name);
    else p.set(name, value);
  }
  const s = p.toString();
  return s ? `?${s}` : "";
}

/**
 * reconcileFromUrl decides the filter state after a location change.
 *
 *  - "pop" (back/forward, or the first load): the URL is the source of
 *    truth; a field absent from it takes `fallback` for that field.
 *  - "push" (an in-app navigation or a page's own replace): a field the URL
 *    carries wins (a deep link), a field it lacks keeps `current` (the
 *    active filter follows the user to the new page and is written back).
 *
 * `fallback` is what "absent" means under "pop": the defaults on back/forward,
 * the viewer's stored preference on the first load (URL, then storage, then
 * defaults).
 */
export function reconcileFromUrl(
  current: UrlFilters,
  search: string,
  mode: "pop" | "push",
  fallback: UrlFilters = FILTER_DEFAULTS,
): UrlFilters {
  const fromUrl = parseFilterParams(search);
  const base = mode === "pop" ? fallback : current;
  return {
    win: fromUrl.win ?? base.win,
    // The stored range is only meaningful under window=custom; it is kept
    // (never blanked) so the Custom editor reopens on the last range.
    customRange: fromUrl.customRange ?? current.customRange,
    tool: fromUrl.tool ?? base.tool,
    project: fromUrl.project ?? base.project,
    model: fromUrl.model ?? base.model,
    query: fromUrl.query ?? base.query,
    gran: fromUrl.gran ?? base.gran,
  };
}

/** sameUrlFilters compares two states field by field. */
export function sameUrlFilters(a: UrlFilters, b: UrlFilters): boolean {
  return (
    a.win === b.win &&
    a.customRange.since === b.customRange.since &&
    a.customRange.until === b.customRange.until &&
    a.tool === b.tool &&
    a.project === b.project &&
    a.model === b.model &&
    a.query === b.query &&
    a.gran === b.gran
  );
}
