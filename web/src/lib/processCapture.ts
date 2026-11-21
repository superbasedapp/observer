// processCapture - the pure model behind the process capture limits UI
// (docs/plans/process-capture-budget-plan-2026-11-04.md sections 8 and 9):
//
//   - the table of the observer.process.capture.* keys (the Settings rows, the
//     data-volume card's query and its per-setting labels all read it),
//   - the data-volume estimate model (GET /api/process/capture/estimate),
//   - the System tab's capture line, rolled-up grouping and tree-window merge
//     (GET /api/session/<id>/processes/summary and ?limit=&to=).
//
// No React, no fetch, no DOM: table-tested in processCapture.test.ts.

import { fmtBytes, fmtInt } from "../../../shared/lib/format.ts";
import type { ProcessCaptureEstimate, ProcessNode, ProcessSummaryResponse } from "./types.ts";

// ---------------------------------------------------------------------------
// The capture keys (plan 9.1)

/** CAPTURE_KEY_PREFIX is the TOML path every capture key lives under. */
export const CAPTURE_KEY_PREFIX = "observer.process.capture.";

export type CaptureFieldKind = "bool" | "int" | "list" | "select";

export type CaptureFieldDef = {
  /** key is the dotted key under [observer.process.capture] (plan 9.1). */
  key: string;
  /** path locates the value in the config JSON's `Capture` object (Go field names). */
  path: [string] | [string, string];
  kind: CaptureFieldKind;
  /** label is the short name the data-volume card prints for the setting. */
  label: string;
};

/**
 * CAPTURE_FIELDS is every observer.process.capture.* key, in plan 9.1 order.
 * The Settings specs (sectionSpecs.ts) name the same fields by `path`; a test
 * keeps the two in step. Keys are typed as plain strings, not the generated
 * ConfigKeyPath union, so this compiles before the Go side regenerates it.
 */
export const CAPTURE_FIELDS: readonly CaptureFieldDef[] = [
  { key: "enabled", path: ["Enabled"], kind: "bool", label: "Capture limits on" },
  { key: "budget.per_tool_call", path: ["Budget", "PerToolCall"], kind: "int", label: "Runs kept per tool call" },
  { key: "budget.per_session", path: ["Budget", "PerSession"], kind: "int", label: "Runs kept per session" },
  { key: "budget.per_minute", path: ["Budget", "PerMinute"], kind: "int", label: "Runs kept per minute" },
  { key: "services.track", path: ["Services", "Track"], kind: "bool", label: "Track services" },
  { key: "services.detach_after_minutes", path: ["Services", "DetachAfterMinutes"], kind: "int", label: "Service detach delay" },
  { key: "services.exemplars_per_service", path: ["Services", "ExemplarsPerService"], kind: "int", label: "Runs kept per service" },
  { key: "services.tail_minutes", path: ["Services", "TailMinutes"], kind: "int", label: "Service tail" },
  { key: "services.extra_basenames", path: ["Services", "ExtraBasenames"], kind: "list", label: "Extra service programs" },
  { key: "fold.enabled", path: ["Fold", "Enabled"], kind: "bool", label: "Fold routine helpers" },
  { key: "fold.extra_basenames", path: ["Fold", "ExtraBasenames"], kind: "list", label: "Extra folded programs" },
  { key: "metrics.ring_min_lifetime_seconds", path: ["Metrics", "RingMinLifetimeSeconds"], kind: "int", label: "Metric ring minimum lifetime" },
  { key: "rollups.bucket_seconds", path: ["Rollups", "BucketSeconds"], kind: "int", label: "Rollup bucket width" },
  { key: "unattributed.pending_hours", path: ["Unattributed", "PendingHours"], kind: "int", label: "Unattributed wait" },
  { key: "unattributed.mode", path: ["Unattributed", "Mode"], kind: "select", label: "Unattributed after the wait" },
];

/** CAPTURE_CONFIG_KEYS are the full TOML key paths (observer.process.capture.<key>). */
export const CAPTURE_CONFIG_KEYS: readonly string[] = CAPTURE_FIELDS.map((f) => CAPTURE_KEY_PREFIX + f.key);

/** captureKeyLabel names a setting for the card; an unknown key is shown as sent. */
export function captureKeyLabel(key: string): string {
  const bare = key.startsWith(CAPTURE_KEY_PREFIX) ? key.slice(CAPTURE_KEY_PREFIX.length) : key;
  return CAPTURE_FIELDS.find((f) => f.key === bare)?.label ?? bare;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return v != null && typeof v === "object" && !Array.isArray(v);
}

/** captureDraft returns the Capture object of a Process section draft, or null (older daemon). */
export function captureDraft(processDraft: unknown): Record<string, unknown> | null {
  if (!isRecord(processDraft)) return null;
  const cap = processDraft["Capture"];
  return isRecord(cap) ? cap : null;
}

function captureValue(cap: Record<string, unknown>, f: CaptureFieldDef): unknown {
  if (f.path.length === 1) return cap[f.path[0]];
  const sub = cap[f.path[0]];
  return isRecord(sub) ? sub[f.path[1]] : undefined;
}

/**
 * captureDraftQuery serialises the Process draft's capture values as the
 * estimate endpoint's query (plan 9.3: the 9.1 keys, dotted). Booleans are
 * "true"/"false", lists comma-joined (an emptied list is sent empty so it
 * overrides a saved one). A key with no value in the draft is left out and the
 * server keeps its current value. Null when the draft carries no capture
 * config, which is a daemon without the feature.
 */
export function captureDraftQuery(processDraft: unknown): string | null {
  const cap = captureDraft(processDraft);
  if (!cap) return null;
  const qs = new URLSearchParams();
  for (const f of CAPTURE_FIELDS) {
    const v = captureValue(cap, f);
    if (v === undefined || v === null) {
      if (f.kind === "list") qs.set(f.key, "");
      continue;
    }
    switch (f.kind) {
      case "bool":
        qs.set(f.key, v ? "true" : "false");
        break;
      case "int":
        if (typeof v === "number" && Number.isFinite(v)) qs.set(f.key, String(Math.trunc(v)));
        break;
      case "list":
        qs.set(f.key, Array.isArray(v) ? v.map(String).join(",") : "");
        break;
      default:
        qs.set(f.key, String(v));
    }
  }
  return qs.toString();
}

// ---------------------------------------------------------------------------
// The data-volume estimate

function num(v: unknown): number {
  return typeof v === "number" && Number.isFinite(v) ? v : 0;
}

/** parseEstimate normalises an estimate response; any missing number is 0. */
export function parseEstimate(raw: unknown): ProcessCaptureEstimate {
  const r = isRecord(raw) ? raw : {};
  const basis = isRecord(r.basis) ? r.basis : {};
  const cur = isRecord(r.current) ? r.current : {};
  const proj = isRecord(r.projected) ? r.projected : {};
  const by = Array.isArray(r.by_setting) ? r.by_setting : [];
  return {
    basis: { days: num(basis.days), sessions: num(basis.sessions), observed_rows: num(basis.observed_rows) },
    current: { rows_per_day: num(cur.rows_per_day), bytes_per_day: num(cur.bytes_per_day) },
    projected: {
      rows_per_day: num(proj.rows_per_day),
      bytes_per_day: num(proj.bytes_per_day),
      rollup_rows_per_day: num(proj.rollup_rows_per_day),
      org_rows_per_day: num(proj.org_rows_per_day),
    },
    by_setting: by
      .filter(isRecord)
      .filter((s) => typeof s.key === "string")
      .map((s) => ({ key: String(s.key), rows_per_day: num(s.rows_per_day) })),
  };
}

export type DeltaTone = "success" | "warn" | "neutral";

export type DeltaPill = { tone: DeltaTone; text: string };

/**
 * deltaPill is the glanceable change of `value` against `current`: green when
 * the volume falls, amber when it rises, neutral when it does not move.
 */
export function deltaPill(current: number, value: number): DeltaPill {
  if (value === current) return { tone: "neutral", text: "no change" };
  if (current <= 0) return value > 0 ? { tone: "warn", text: "new" } : { tone: "neutral", text: "no change" };
  const pct = ((value - current) / current) * 100;
  if (Math.abs(pct) < 0.05) return { tone: "neutral", text: "no change" };
  const abs = Math.abs(pct);
  const digits = abs < 10 ? 1 : 0;
  return { tone: pct < 0 ? "success" : "warn", text: `${pct < 0 ? "-" : "+"}${abs.toFixed(digits)}%` };
}

export type SettingImpact = {
  key: string;
  label: string;
  rowsPerDay: number;
  /** delta is rowsPerDay minus the current rows per day. */
  delta: number;
  pill: DeltaPill;
  /** barPct is rowsPerDay as a share of the largest value shown, 0 to 100. */
  barPct: number;
};

export type EstimateModel = {
  /** hasHistory is false when the node has no stored runs to replay. */
  hasHistory: boolean;
  basisText: string;
  rows: { current: number; projected: number; pill: DeltaPill };
  bytes: { current: number; projected: number; pill: DeltaPill };
  rollupRowsPerDay: number;
  orgRowsPerDay: number;
  /** settings are the per-setting impacts, biggest change first. */
  settings: SettingImpact[];
};

/** basisText words the sample the estimate was computed from. */
export function basisText(b: ProcessCaptureEstimate["basis"]): string {
  const days = `${fmtInt(b.days)} day${b.days === 1 ? "" : "s"}`;
  const sessions = `${fmtInt(b.sessions)} session${b.sessions === 1 ? "" : "s"}`;
  return `from the last ${days}, ${sessions}, ${fmtInt(b.observed_rows)} stored process${b.observed_rows === 1 ? "" : "es"}`;
}

/**
 * estimateModel turns an estimate into what the card draws. Settings are
 * ordered by the size of their change against the current rows per day, then
 * by volume, then by name, so the biggest contributors come first and an
 * unchanged setting sinks to the bottom.
 */
export function estimateModel(e: ProcessCaptureEstimate): EstimateModel {
  const cur = e.current.rows_per_day;
  const peak = Math.max(cur, e.projected.rows_per_day, ...e.by_setting.map((s) => s.rows_per_day), 1);
  const settings = e.by_setting
    .map<SettingImpact>((s) => ({
      key: s.key,
      label: captureKeyLabel(s.key),
      rowsPerDay: s.rows_per_day,
      delta: s.rows_per_day - cur,
      pill: deltaPill(cur, s.rows_per_day),
      barPct: s.rows_per_day <= 0 ? 0 : Math.max(2, Math.min(100, (s.rows_per_day / peak) * 100)),
    }))
    .sort((a, b) => Math.abs(b.delta) - Math.abs(a.delta) || b.rowsPerDay - a.rowsPerDay || a.label.localeCompare(b.label));
  return {
    hasHistory: e.basis.observed_rows > 0,
    basisText: basisText(e.basis),
    rows: { current: cur, projected: e.projected.rows_per_day, pill: deltaPill(cur, e.projected.rows_per_day) },
    bytes: {
      current: e.current.bytes_per_day,
      projected: e.projected.bytes_per_day,
      pill: deltaPill(e.current.bytes_per_day, e.projected.bytes_per_day),
    },
    rollupRowsPerDay: e.projected.rollup_rows_per_day,
    orgRowsPerDay: e.projected.org_rows_per_day,
    settings,
  };
}

/** fmtPerDay prints a row count as "12,345 / day". */
export function fmtRowsPerDay(n: number): string {
  return `${fmtInt(n)} / day`;
}

/** fmtBytesPerDay prints a byte count as "3.4 MB / day". */
export function fmtBytesPerDay(n: number): string {
  return `${fmtBytes(n)} / day`;
}

// ---------------------------------------------------------------------------
// The System tab: summary words and rolled-up groups
//
// Promoted to shared/lib/processCaptureSummary.ts so the org drawer's System
// panel (web2/) reads the same model; re-exported here so every importer of
// this module is unchanged.

export {
  ROLLUPS_PER_PAGE,
  ROLLUP_KINDS,
  RECENT_SERVICE_MS,
  SERVICES_PER_PAGE,
  budgetHit,
  captureLine,
  captureLineParts,
  parseSummary,
  rollupKindLabel,
  rollupPage,
  rollupTotals,
  servicesRunning,
  sortRollups,
  type RollupKindTotal,
  type RollupRow,
} from "../../../shared/lib/processCaptureSummary.ts";
import { parseSummary } from "../../../shared/lib/processCaptureSummary.ts";

// ---------------------------------------------------------------------------
// The tree window

/** TREE_WINDOW_LIMIT is the row cap the System tab asks the tree for. */
export const TREE_WINDOW_LIMIT = 2000;

function walk(nodes: readonly ProcessNode[], fn: (n: ProcessNode) => void): void {
  for (const n of nodes) {
    fn(n);
    if (n.children?.length) walk(n.children, fn);
  }
}

/** countNodes counts every process in a forest. */
export function countNodes(roots: readonly ProcessNode[]): number {
  let n = 0;
  walk(roots, () => {
    n += 1;
  });
  return n;
}

/** oldestStartedAt is the earliest started_at in a forest (RFC3339), or null. */
export function oldestStartedAt(roots: readonly ProcessNode[]): string | null {
  let best: string | null = null;
  let bestMs = Infinity;
  walk(roots, (n) => {
    const ms = n.started_at ? Date.parse(n.started_at) : NaN;
    if (Number.isFinite(ms) && ms < bestMs) {
      bestMs = ms;
      best = n.started_at ?? null;
    }
  });
  return best;
}

/**
 * mergeWindows joins the roots of earlier windows with the newest window,
 * oldest first. A root present in two windows (the boundary row) is kept once,
 * from the later window. Roots are matched by process_key; a child whose
 * parent sits in another window stays a root of its own window.
 */
export function mergeWindows(earlier: readonly ProcessNode[][], newest: readonly ProcessNode[]): ProcessNode[] {
  const out = new Map<string, ProcessNode>();
  for (const w of earlier) for (const r of w) out.set(r.process_key, r);
  for (const r of newest) out.set(r.process_key, r);
  return [...out.values()].sort((a, b) => {
    const ta = a.started_at ? Date.parse(a.started_at) : 0;
    const tb = b.started_at ? Date.parse(b.started_at) : 0;
    return ta - tb;
  });
}

/** windowNote is the "Showing the most recent 2,000 of N" line over a truncated tree. */
export function windowNote(shown: number, total: number | undefined): string {
  const of = total != null && total > shown ? ` of ${fmtInt(total)}` : "";
  return `Showing the most recent ${fmtInt(shown)}${of}`;
}

// ---------------------------------------------------------------------------
// The summary fetch outcome

export type SummaryOutcome =
  | { kind: "ok"; etag: string | null; data: ProcessSummaryResponse }
  | { kind: "not_modified" }
  | { kind: "unavailable" }
  | { kind: "error"; status: number };

/**
 * summaryOutcome reads one summary response: 200 carries the body (and its
 * ETag), 304 means the copy on screen is current, 404 means a daemon without
 * the endpoint (the panel keeps today's behaviour), anything else is an error.
 */
export function summaryOutcome(status: number, etag: string | null, body: unknown): SummaryOutcome {
  if (status === 304) return { kind: "not_modified" };
  if (status === 404) return { kind: "unavailable" };
  if (status >= 200 && status < 300) return { kind: "ok", etag, data: parseSummary(body) };
  return { kind: "error", status };
}
