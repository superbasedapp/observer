import { memo, useMemo } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { ChartTooltip } from "./ChartTooltip";
import { ChartLegend } from "./ChartLegend";
import { fmtCompact } from "../lib/format";
import type { Granularity } from "../lib/granularity";
import type { TokensByModelPoint } from "../lib/types";
import { bucketTooltipLabel, categoryAxis, CHART_AXIS, CHART_GRID, type GridPoint } from "./common";
import { useChartMotion } from "./useChartMotion";
import { modelLegendLabel, modelSeriesColorMap, OTHER_SERIES_KEY } from "./modelLegend";

// Per-bucket stacked bars where each segment is one model. Top 6
// models by total tokens become real series; the rest collapse
// into "other" so the legend stays readable.
//
// Colour is by model FAMILY (modelSeriesColors: one family table owns model
// colour; a 2nd/3rd model of a family is a shade of it), not by rank, and
// the legend shows each model's family mark.
export const TokensByModelChart = memo(function TokensByModelChart({
  data,
  height = 240,
  topN = 6,
  granularity = "1d",
  grid,
}: {
  data: TokensByModelPoint[];
  height?: number;
  topN?: number;
  /** Bucket granularity the rows were served at (the response `bucket`); drives the axis/tooltip labels. */
  granularity?: Granularity;
  /** The response `grid` (every bucket of the window) for zero-fill. */
  grid?: readonly GridPoint[];
}) {
  const { rows, modelKeys, colorFor } = useMemo(
    () => flatten(data, topN, grid),
    [data, topN, grid],
  );

  const motion = useChartMotion(rows, "bucket", "", modelKeys.length);
  return (
    <ResponsiveContainer width="100%" height={height + 28}>
      <BarChart data={rows} margin={{ top: 8, right: 12, left: 0, bottom: 0 }}>
        <Legend
          verticalAlign="top"
          align="left"
          content={<ChartLegend renderLabel={modelLegendLabel} />}
        />
        <CartesianGrid {...CHART_GRID} />
        <XAxis {...CHART_AXIS} {...categoryAxis(rows, granularity)} />
        <YAxis {...CHART_AXIS} tickFormatter={fmtCompact} />
        <Tooltip
          content={
            <ChartTooltip
              labelKey="bucket"
              labelFormatter={bucketTooltipLabel(granularity)}
              formatItem={(name, value) => `${name}: ${fmtCompact(value)}`}
            />
          }
          cursor={{ fill: "var(--bg-4)", opacity: 0.4 }}
        />
        {modelKeys.map((k, i) => (
          <Bar
            {...motion}
            key={k}
            dataKey={k}
            name={k}
            stackId="model"
            fill={colorFor(k)}
            radius={i === modelKeys.length - 1 ? [3, 3, 0, 0] : [0, 0, 0, 0]}
          />
        ))}
      </BarChart>
    </ResponsiveContainer>
  );
});

const OTHER_COLOR = "var(--tool-other)";

function flatten(data: TokensByModelPoint[], topN: number, grid?: readonly GridPoint[]) {
  // Aggregate per model to pick top-N.
  const total: Record<string, number> = {};
  for (const p of data) {
    total[p.model] = (total[p.model] ?? 0) + (p.total_tokens || 0);
  }
  const ranked = Object.entries(total)
    .sort((a, b) => b[1] - a[1])
    .map(([k]) => k);
  const top = new Set(ranked.slice(0, topN));
  const collapse = (m: string) => (top.has(m) ? m : OTHER_SERIES_KEY);

  // Pivot data → one row per bucket with one key per model.
  // Seed every bucket of the served grid (zero-fill order) so an empty
  // bucket keeps its slot on the axis; rows sort by bucket start `t`.
  const byBucket = new Map<string, Record<string, number | string>>();
  for (const g of grid ?? []) byBucket.set(g.bucket, { bucket: g.bucket, t: g.t });
  for (const p of data) {
    const row = byBucket.get(p.bucket) ?? { bucket: p.bucket, t: p.t ?? 0 };
    const key = collapse(p.model);
    row[key] = (Number(row[key]) || 0) + (p.total_tokens || 0);
    byBucket.set(p.bucket, row);
  }

  const rows = [...byBucket.values()].sort((a, b) =>
    Number(a.t) !== Number(b.t)
      ? Number(a.t) - Number(b.t)
      : String(a.bucket) < String(b.bucket)
        ? -1
        : 1,
  );

  const modelKeys = [...ranked.slice(0, topN)];
  if (ranked.length > topN) modelKeys.push(OTHER_SERIES_KEY);

  const colorMap = modelSeriesColorMap(modelKeys);
  const colorFor = (k: string) => colorMap.get(k) ?? OTHER_COLOR;

  return { rows, modelKeys, colorFor };
}
