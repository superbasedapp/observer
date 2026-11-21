// processCaptureSummary - the pure model behind a session's process capture
// summary (docs/plans/process-capture-budget-plan-2026-11-04.md sections 4.7,
// 4.8 and 9.3), shared by the node System tab (web/, which reads
// GET /api/session/<id>/processes/summary) and the org drawer's System panel
// (web2/, which reads the `capture` block of
// GET /api/org/sessions/{id}/processes). The two documents carry the same
// field names; the org's `budget` has only `hit` and it has no `findings`.
//
// Promoted from web/src/lib/processCapture.ts (which re-exports everything
// here, so its importers are unchanged). No React, no fetch, no DOM; tested in
// web/src/lib/processCapture.test.ts and web2/src/lib/orgProcessCapture.test.ts.

import { fmtInt } from "./format.ts";

// ---------------------------------------------------------------------------
// The summary document

// ProcessSummaryService is one service root of a session (plan 9.3): a
// long-lived process the agent started (a dev server, a watcher) tracked
// beyond its tool call.
export type ProcessSummaryService = {
  root_key: string;
  exe: string;
  argv_preview?: string;
  started_at?: string;
  last_seen?: string;
  action_id?: number;
  turn_index?: number;
  message_id?: string;
  kept?: number;
  rolled_up?: number;
  cpu_sum_ms?: number;
  peak_rss_bytes?: number;
};

// ProcessSummaryRollup is one rolled-up group (runs the capture budget counted
// but did not keep as rows).
export type ProcessSummaryRollup = {
  group_kind: string; // "budget" | "fold" | "service" | "unattributed"
  exe_basename?: string;
  example_argv_preview?: string;
  parent_process_key?: string;
  service_root_key?: string;
  action_id?: number;
  count: number;
  failed_count?: number;
  duration_sum_ms?: number;
  duration_max_ms?: number;
  cpu_sum_ms?: number;
  peak_rss_bytes?: number;
  first_seen?: string;
  last_seen?: string;
};

export type ProcessSummaryResponse = {
  observed: number;
  kept: number;
  folded: number;
  rolled_up: number;
  service_kept: number;
  service_rolled_up: number;
  dropped: number;
  budget?: {
    per_tool_call?: number;
    per_session?: number;
    per_minute?: number;
    hit?: boolean | number;
  };
  services?: ProcessSummaryService[];
  rollups?: ProcessSummaryRollup[];
  findings?: number;
  // legacy: the session predates the capture table (no stats row).
  legacy?: boolean;
};

function isRecord(v: unknown): v is Record<string, unknown> {
  return v != null && typeof v === "object" && !Array.isArray(v);
}

function num(v: unknown): number {
  return typeof v === "number" && Number.isFinite(v) ? v : 0;
}

function flag(v: boolean | number | undefined): boolean {
  return typeof v === "number" ? v > 0 : Boolean(v);
}

/** budgetHit reports whether the session ran into a capture budget. */
export function budgetHit(s: ProcessSummaryResponse): boolean {
  return flag(s.budget?.hit);
}

/**
 * captureLineParts are the words of the capture line, in order:
 * "Kept 3,412 of 92,428", "61,203 folded", "24,880 rolled up",
 * "2,933 service rows", "budget hit". Zero parts are left out; a session
 * captured before capture limits has the one honest sentence instead.
 */
export function captureLineParts(s: ProcessSummaryResponse): string[] {
  if (s.legacy) return ["Captured before capture limits"];
  const parts = [`Kept ${fmtInt(s.kept)} of ${fmtInt(s.observed)}`];
  if (s.folded > 0) parts.push(`${fmtInt(s.folded)} folded`);
  if (s.rolled_up > 0) parts.push(`${fmtInt(s.rolled_up)} rolled up`);
  if (s.service_kept > 0) parts.push(`${fmtInt(s.service_kept)} service rows`);
  if (s.service_rolled_up > 0) parts.push(`${fmtInt(s.service_rolled_up)} service rolled up`);
  if (s.dropped > 0) parts.push(`${fmtInt(s.dropped)} dropped`);
  if (budgetHit(s)) parts.push("budget hit");
  return parts;
}

/** captureLine is captureLineParts joined for one line. */
export function captureLine(s: ProcessSummaryResponse): string {
  return captureLineParts(s).join(" · ");
}

/** parseSummary normalises a summary document; missing counts are 0 and lists empty. */
export function parseSummary(raw: unknown): ProcessSummaryResponse {
  const r = isRecord(raw) ? raw : {};
  const services = Array.isArray(r.services) ? (r.services.filter(isRecord) as unknown as ProcessSummaryService[]) : [];
  const rollups = Array.isArray(r.rollups) ? (r.rollups.filter(isRecord) as unknown as ProcessSummaryRollup[]) : [];
  const budget = isRecord(r.budget) ? (r.budget as ProcessSummaryResponse["budget"]) : undefined;
  return {
    observed: num(r.observed),
    kept: num(r.kept),
    folded: num(r.folded),
    rolled_up: num(r.rolled_up),
    service_kept: num(r.service_kept),
    service_rolled_up: num(r.service_rolled_up),
    dropped: num(r.dropped),
    budget,
    services,
    rollups,
    findings: typeof r.findings === "number" ? r.findings : undefined,
    legacy: r.legacy === true,
  };
}

/** hasSummaryRows reports whether a summary has anything to show beyond the line. */
export function hasSummaryRows(s: ProcessSummaryResponse): boolean {
  return s.observed > 0 || (s.services?.length ?? 0) > 0 || (s.rollups?.length ?? 0) > 0;
}

/** SERVICES_PER_PAGE and ROLLUPS_PER_PAGE: both blocks page like the findings list. */
export const SERVICES_PER_PAGE = 10;
export const ROLLUPS_PER_PAGE = 10;

/** RECENT_SERVICE_MS: a service seen this recently still counts as running. */
export const RECENT_SERVICE_MS = 120_000;

/** servicesRunning reports whether any service was seen alive within RECENT_SERVICE_MS of now. */
export function servicesRunning(services: readonly ProcessSummaryService[] | undefined, nowMs: number): boolean {
  return (services ?? []).some((s) => {
    const t = s.last_seen ? Date.parse(s.last_seen) : NaN;
    return Number.isFinite(t) && nowMs - t < RECENT_SERVICE_MS;
  });
}

/** pageOf is one 1-based page of rows (page clamped into range). */
export function pageOf<T>(rows: readonly T[], page: number, perPage: number): T[] {
  const last = Math.max(1, Math.ceil(rows.length / perPage));
  const p = Math.min(Math.max(1, page), last);
  return rows.slice((p - 1) * perPage, p * perPage);
}

// ---------------------------------------------------------------------------
// Rolled-up groups

/** ROLLUP_KINDS is the display order of the rollup group kinds, with their words. */
export const ROLLUP_KINDS: readonly { kind: string; label: string }[] = [
  { kind: "budget", label: "Over budget" },
  { kind: "fold", label: "Folded helpers" },
  { kind: "service", label: "Service children" },
  { kind: "unattributed", label: "Unattributed" },
];

/** rollupKindLabel names a group kind; an unknown kind is shown as sent. */
export function rollupKindLabel(kind: string): string {
  return ROLLUP_KINDS.find((k) => k.kind === kind)?.label ?? (kind || "Other");
}

function kindRank(kind: string): number {
  const i = ROLLUP_KINDS.findIndex((k) => k.kind === kind);
  return i < 0 ? ROLLUP_KINDS.length : i;
}

/** sortRollups orders rollups by group kind, then biggest count first. */
export function sortRollups(rollups: readonly ProcessSummaryRollup[]): ProcessSummaryRollup[] {
  return rollups
    .map((r, i) => ({ r, i }))
    .sort((a, b) => kindRank(a.r.group_kind) - kindRank(b.r.group_kind) || b.r.count - a.r.count || a.i - b.i)
    .map((x) => x.r);
}

export type RollupKindTotal = { kind: string; label: string; groups: number; count: number; failed: number };

/** rollupTotals sums the rollups per group kind, in display order. */
export function rollupTotals(rollups: readonly ProcessSummaryRollup[]): RollupKindTotal[] {
  const by = new Map<string, RollupKindTotal>();
  for (const r of rollups) {
    const t = by.get(r.group_kind) ?? { kind: r.group_kind, label: rollupKindLabel(r.group_kind), groups: 0, count: 0, failed: 0 };
    t.groups += 1;
    t.count += r.count;
    t.failed += r.failed_count ?? 0;
    by.set(r.group_kind, t);
  }
  return [...by.values()].sort((a, b) => kindRank(a.kind) - kindRank(b.kind));
}

export type RollupRow = { rollup: ProcessSummaryRollup; heading?: string };

/**
 * rollupPage is one page of the sorted rollups. A row carries `heading` where
 * its group kind starts, and on a page's first row, so a page never opens
 * without saying what group it is in.
 */
export function rollupPage(sorted: readonly ProcessSummaryRollup[], page: number, perPage: number): RollupRow[] {
  const start = Math.max(0, (page - 1) * perPage);
  const slice = sorted.slice(start, start + perPage);
  return slice.map((rollup, i) => {
    const prev = i === 0 ? undefined : slice[i - 1];
    return !prev || prev.group_kind !== rollup.group_kind ? { rollup, heading: rollupKindLabel(rollup.group_kind) } : { rollup };
  });
}
