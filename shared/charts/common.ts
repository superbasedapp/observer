import {
  bucketLabelFormatter,
  bucketTickFormatter,
  bucketTime,
  type Granularity,
} from "../lib/granularity.ts";

// Shared Recharts axis/grid styling so every chart in the app looks
// identical. Adjustments here propagate site-wide.

export const CHART_AXIS = {
  stroke: "var(--line-3)",
  tick: { fill: "var(--fg-3)", fontSize: 10 },
  tickLine: false,
  axisLine: false,
} as const;

export const CHART_GRID = {
  stroke: "var(--line-1)",
  vertical: false,
} as const;


const MAX_DAY_TICKS = 10;

/**
 * dayTicks picks the axis ticks for a SUB-DAY grid that spans several days:
 * the buckets at local midnight (which fmtBucket labels with the date),
 * thinned to at most MAX_DAY_TICKS. Returns undefined when the default
 * ticks already read well (day/week buckets, or a grid inside one day).
 */
export function dayTicks(
  rows: readonly object[],
  gran: Granularity,
  key: string,
): (string | number)[] | undefined {
  if (gran !== "5m" && gran !== "1h") return undefined;
  const mids: (string | number)[] = [];
  for (const r of rows) {
    const v = (r as Record<string, unknown>)[key];
    if (typeof v !== "string" && typeof v !== "number") continue;
    const d = new Date(bucketTime(v));
    if (d.getHours() === 0 && d.getMinutes() === 0) mids.push(v);
  }
  if (mids.length < 2) return undefined;
  const step = Math.ceil(mids.length / MAX_DAY_TICKS);
  return mids.filter((_, i) => i % step === 0);
}

/**
 * timeAxis returns the XAxis props for a time-series AREA/LINE chart at a
 * granularity: a NUMERIC time axis on the bucket start `t` (epoch ms, which
 * every time-series endpoint now returns) when every row carries one, else a
 * categorical axis on `fallbackKey` (a caller whose rows predate `t`). Ticks
 * go through the ONE bucket formatter (shared/lib/granularity.ts fmtBucket);
 * a multi-day sub-day grid ticks at local midnights so the dates show.
 */
export function timeAxis(
  rows: readonly object[],
  gran: Granularity,
  fallbackKey = "bucket",
) {
  const numeric =
    rows.length > 0 &&
    rows.every((r) => Number.isFinite((r as { t?: unknown }).t as number) && (r as { t: number }).t > 0);
  const tickFormatter = bucketTickFormatter(gran);
  const key = numeric ? "t" : fallbackKey;
  const ticks = dayTicks(rows, gran, key);
  return numeric
    ? {
        dataKey: "t",
        type: "number" as const,
        scale: "time" as const,
        domain: ["dataMin", "dataMax"] as [string, string],
        tickFormatter,
        ...(ticks ? { ticks } : {}),
      }
    : { dataKey: fallbackKey, tickFormatter, ...(ticks ? { ticks } : {}) };
}

/**
 * categoryAxis returns the XAxis props for a time-series BAR chart: a
 * categorical axis on the bucket key (the zero-filled grid keeps the
 * spacing honest), labelled through fmtBucket, with midnight ticks on a
 * multi-day sub-day grid.
 */
export function categoryAxis(rows: readonly object[], gran: Granularity, key = "bucket") {
  const ticks = dayTicks(rows, gran, key);
  return {
    dataKey: key,
    tickFormatter: bucketTickFormatter(gran),
    ...(ticks ? { ticks, interval: 0 as const } : {}),
  };
}

/** bucketTooltipLabel is the tooltip label formatter for a granularity. */
export function bucketTooltipLabel(gran: Granularity): (raw: string) => string {
  return bucketLabelFormatter(gran);
}

/** GridPoint is one entry of a multi-key time-series response's `grid`. */
export type GridPoint = { bucket: string; t: number };
