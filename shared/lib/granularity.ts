// Chart time granularity - the TypeScript mirror of internal/timebucket.
//
// ONE vocabulary (5m / 1h / 1d / 1w), ONE Auto rule, ONE 2000-point cap, and
// ONE bucket formatter for every time-series chart in every app surface
// (web/, web2/, webcloud/). The Go package owns the bucketing itself (the
// server floors rows into viewer-zone buckets and zero-fills the grid); this
// module decides what to ASK for and how to LABEL what comes back.
//
// Both sides are pinned by ONE fixture, shared/lib/granularity.fixture.json
// (web/src/lib/granularity.test.ts and internal/timebucket's Go tests read
// it). Plan: docs/plans/chart-time-granularity-plan-2026-09-29.md.
//
// Pure: no React, no DOM, no fetch. Formatting uses the reader's default
// time zone, which is the zone viewerTimeZone() sends as `tz=`, so a label
// always reads the same wall clock the server bucketed by.

import { cachedDateTimeFormat } from "./format.ts";

export type Granularity = "5m" | "1h" | "1d" | "1w";
/** GranChoice is what a viewer picks: a granularity, or Auto. */
export type GranChoice = Granularity | "auto";

export const MAX_POINTS = 2000;

export type GranularityRule = {
  gran: Granularity;
  stepMs: number;
  /** Largest span Auto assigns this granularity to (inclusive); 0 = unbounded. */
  autoMaxSpanMs: number;
  /** Exempt from the point cap (the server clamps its grid to the data). */
  alwaysAllowed: boolean;
};

const MIN = 60_000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;

/** GRANULARITY_TABLE mirrors internal/timebucket.Table, finest first. */
export const GRANULARITY_TABLE: readonly GranularityRule[] = [
  { gran: "5m", stepMs: 5 * MIN, autoMaxSpanMs: 3 * HOUR, alwaysAllowed: false },
  { gran: "1h", stepMs: HOUR, autoMaxSpanMs: 7 * DAY, alwaysAllowed: false },
  { gran: "1d", stepMs: DAY, autoMaxSpanMs: 180 * DAY, alwaysAllowed: true },
  { gran: "1w", stepMs: 7 * DAY, autoMaxSpanMs: 0, alwaysAllowed: true },
];

export const GRANULARITIES: readonly Granularity[] = GRANULARITY_TABLE.map((r) => r.gran);

/** DAILY_ONLY is the choice set for a chart fed by a day-grained summary. */
export const DAILY_ONLY: readonly Granularity[] = ["1d", "1w"];

export function isGranularity(v: unknown): v is Granularity {
  return typeof v === "string" && (GRANULARITIES as readonly string[]).includes(v);
}

/** parseGranChoice reads a `gran=` URL value; null when it is not valid. */
export function parseGranChoice(v: unknown): GranChoice | null {
  if (v === "auto") return "auto";
  return isGranularity(v) ? v : null;
}

function ruleOf(g: Granularity): GranularityRule {
  return GRANULARITY_TABLE.find((r) => r.gran === g)!;
}

/** bucketMs returns a granularity's nominal bucket width. */
export function bucketMs(g: Granularity): number {
  return ruleOf(g).stepMs;
}

/** chooseGranularity is the Auto rule. spanMs = Infinity for an unbounded window. */
export function chooseGranularity(spanMs: number): Granularity {
  for (const r of GRANULARITY_TABLE) {
    if (r.autoMaxSpanMs === 0 || spanMs <= r.autoMaxSpanMs) return r.gran;
  }
  return GRANULARITY_TABLE[GRANULARITY_TABLE.length - 1].gran;
}

/** pointCount mirrors timebucket.Points: floor(span/step)+1. */
export function pointCount(spanMs: number, g: Granularity): number {
  if (!(spanMs >= 0)) return 0;
  if (!Number.isFinite(spanMs)) return Number.MAX_SAFE_INTEGER;
  return Math.floor(spanMs / bucketMs(g)) + 1;
}

/**
 * allowedGranularities lists the granularities a span permits (finest
 * first), optionally restricted to what a surface can serve (`only`, e.g.
 * DAILY_ONLY for a chart fed by a daily summary).
 */
export function allowedGranularities(
  spanMs: number,
  only?: readonly Granularity[],
): Granularity[] {
  return GRANULARITY_TABLE.filter(
    (r) =>
      (r.alwaysAllowed || pointCount(spanMs, r.gran) <= MAX_POINTS) &&
      (!only || only.includes(r.gran)),
  ).map((r) => r.gran);
}

/**
 * effectiveChoice is what a chart should actually request: the viewer's
 * choice when the span (and the surface) allows it, else Auto. A stale
 * `gran=5m` in the URL after widening the window to 30d never produces a
 * server 400.
 */
export function effectiveChoice(
  choice: GranChoice,
  spanMs: number,
  only?: readonly Granularity[],
): GranChoice {
  if (choice === "auto") return "auto";
  return allowedGranularities(spanMs, only).includes(choice) ? choice : "auto";
}

/**
 * resolveGranularity mirrors timebucket.Resolve's granularity pick: an
 * explicit allowed choice, else Auto walking down the table to the first
 * granularity the surface serves.
 */
export function resolveGranularity(
  choice: GranChoice,
  spanMs: number,
  only?: readonly Granularity[],
): Granularity {
  const eff = effectiveChoice(choice, spanMs, only);
  if (eff !== "auto") return eff;
  const auto = chooseGranularity(spanMs);
  if (!only || only.includes(auto)) return auto;
  const i = GRANULARITIES.indexOf(auto);
  return GRANULARITIES.slice(i).find((g) => only.includes(g)) ?? only[only.length - 1];
}

const LABELS: Record<GranChoice, string> = {
  auto: "Auto",
  "5m": "5 min",
  "1h": "Hour",
  "1d": "Day",
  "1w": "Week",
};

/** granularityLabel is the control's option label. */
export function granularityLabel(g: GranChoice): string {
  return LABELS[g];
}

const UNITS: Record<Granularity, string> = {
  "5m": "5 min",
  "1h": "hour",
  "1d": "day",
  "1w": "week",
};

/** granularityUnit is the unit noun a title uses ("hour"). */
export function granularityUnit(g: Granularity): string {
  return UNITS[g];
}

/** perBucketTitle derives a chart title: perBucketTitle("Spend", "1h") = "Spend per hour". */
export function perBucketTitle(prefix: string, g: Granularity | null | undefined): string {
  return `${prefix} per ${UNITS[g ?? "1d"]}`;
}

/** asGranularity reads a response's `bucket` field (legacy "day"/"hour" included). */
export function asGranularity(v: unknown): Granularity {
  if (isGranularity(v)) return v;
  if (v === "hour") return "1h";
  if (v === "week") return "1w";
  return "1d";
}

/** viewerTimeZone is the IANA zone the SPA sends as `tz=` ("UTC" when unknown). */
export function viewerTimeZone(): string {
  try {
    const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
    return tz || "UTC";
  } catch {
    return "UTC";
  }
}

const DAY_KEY = /^(\d{4})-(\d{2})-(\d{2})$/;

/**
 * bucketTime returns a bucket's instant (epoch ms). A calendar-day key
 * ("2026-09-29") is the reader's LOCAL midnight - `new Date("2026-09-29")`
 * would read UTC midnight and label the previous day west of UTC. Numbers
 * pass through (as do epoch-ms strings, which a numeric Recharts axis hands
 * its tooltip); anything unparseable is NaN.
 */
export function bucketTime(bucket: string | number): number {
  if (typeof bucket === "number") return bucket;
  // A numeric time axis hands the tooltip its value as a string.
  if (/^-?\d{10,}$/.test(bucket)) return Number(bucket);
  const m = DAY_KEY.exec(bucket);
  if (m) return new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3])).getTime();
  return Date.parse(bucket);
}

const DAY_OPTS: Intl.DateTimeFormatOptions = { month: "short", day: "numeric" };
const TIME_OPTS: Intl.DateTimeFormatOptions = { hour: "2-digit", minute: "2-digit", hourCycle: "h23" };

const fmtMemo = new Map<string, string>();

/**
 * fmtBucket labels a bucket for its granularity - the ONE chart bucket
 * formatter:
 *   sub-day  "Sep 29, 14:00" (label) / "14:00", or "Sep 29" at local midnight (tick)
 *   day      "Sep 29"
 *   week     "Week of Sep 28" (label) / "Sep 28" (tick)
 * An unparseable bucket is returned unchanged.
 */
export function fmtBucket(
  bucket: string | number,
  gran: Granularity,
  mode: "label" | "tick" = "label",
): string {
  const key = `${gran}|${mode}|${bucket}`;
  let out = fmtMemo.get(key);
  if (out !== undefined) return out;
  const ms = bucketTime(bucket);
  if (!Number.isFinite(ms)) {
    out = String(bucket);
  } else {
    const d = new Date(ms);
    const day = cachedDateTimeFormat("en-US", DAY_OPTS).format(d);
    if (gran === "5m" || gran === "1h") {
      const time = cachedDateTimeFormat("en-GB", TIME_OPTS).format(d);
      if (mode === "label") out = `${day}, ${time}`;
      else out = d.getHours() === 0 && d.getMinutes() === 0 ? day : time;
    } else if (gran === "1w") {
      out = mode === "label" ? `Week of ${day}` : day;
    } else {
      out = day;
    }
  }
  if (fmtMemo.size >= 4096) fmtMemo.clear();
  fmtMemo.set(key, out);
  return out;
}

/** bucketTickFormatter / bucketLabelFormatter bind fmtBucket for a Recharts axis / tooltip. */
export function bucketTickFormatter(gran: Granularity): (v: string | number) => string {
  return (v) => fmtBucket(v, gran, "tick");
}

export function bucketLabelFormatter(gran: Granularity): (v: string | number) => string {
  return (v) => fmtBucket(v, gran, "label");
}

/** granParams is the query-param pair a time-series fetch sends. */
export function granParams(choice: GranChoice): { gran: GranChoice; tz: string } {
  return { gran: choice, tz: viewerTimeZone() };
}
