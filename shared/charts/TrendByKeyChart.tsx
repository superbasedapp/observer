import { memo, useMemo, type ReactNode } from "react";
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
import { fmtUSD } from "../lib/format";
import type { Granularity } from "../lib/granularity";
import type { AnalysisTrendPoint } from "../lib/types";
import { bucketTooltipLabel, categoryAxis, CHART_AXIS, CHART_GRID, type GridPoint } from "./common";
import { toolMeta } from "../lib/tools";
import { useChartMotion } from "./useChartMotion";
import { modelLegendLabel, modelSeriesColorMap, OTHER_SERIES_KEY } from "./modelLegend";

// Spend per bucket stacked by key - the Analysis tab's dim-toggle chart.
// `colorMode` picks the palette from a table (never a branch on a key's
// value): "model" colours by model FAMILY exactly like TokensByModelChart
// (modelSeriesColors) and marks the legend with each family's logo; "tool"
// reaches into the tool registry; "project" cycles through a neutral palette
// since there's no canonical project color.
type ColorMode = "model" | "project" | "tool";

const PROJECT_COLORS = [
  "var(--accent)",
  "var(--info)",
  "var(--success)",
  "var(--warn)",
  "var(--tok-read)",
  "var(--tok-out)",
  "var(--tok-write)",
];

const OTHER_COLOR = "var(--tool-other)";

// Series keys (ranked, "other" tail included) -> key -> colour, per mode.
const PALETTE_BY_MODE: Record<ColorMode, (keys: string[]) => Map<string, string>> = {
  model: (keys) => modelSeriesColorMap(keys),
  tool: (keys) => new Map(keys.map((k) => [k, toolMeta(k).colorVar])),
  project: (keys) =>
    new Map(keys.map((k, i) => [k, PROJECT_COLORS[i % PROJECT_COLORS.length]])),
};

// Legend label renderer per mode; a mode with no row keeps plain text.
const LEGEND_LABEL_BY_MODE: Partial<Record<ColorMode, (name: string) => ReactNode>> = {
  model: modelLegendLabel,
};

export const TrendByKeyChart = memo(function TrendByKeyChart({
  data,
  colorMode = "model",
  topN = 6,
  height = 280,
  granularity = "1d",
  grid,
}: {
  data: AnalysisTrendPoint[];
  colorMode?: ColorMode;
  topN?: number;
  height?: number;
  /** Bucket granularity the rows were served at (the response `bucket`); drives the axis/tooltip labels. */
  granularity?: Granularity;
  /** The response `grid` (every bucket of the window) for zero-fill. */
  grid?: readonly GridPoint[];
}) {
  const { rows, keys, colorFor } = useMemo(
    () => flatten(data, topN, colorMode, grid),
    [data, topN, colorMode, grid],
  );

  const motion = useChartMotion(rows, "bucket", colorMode, keys.length);
  return (
    <ResponsiveContainer width="100%" height={height + 28}>
      <BarChart data={rows} margin={{ top: 8, right: 12, left: 0, bottom: 0 }}>
        <Legend
          verticalAlign="top"
          align="left"
          content={<ChartLegend renderLabel={LEGEND_LABEL_BY_MODE[colorMode]} />}
        />
        <CartesianGrid {...CHART_GRID} />
        <XAxis {...CHART_AXIS} {...categoryAxis(rows, granularity)} />
        <YAxis {...CHART_AXIS} tickFormatter={(v) => fmtUSD(Number(v))} />
        <Tooltip
          content={
            <ChartTooltip
              labelKey="bucket"
              labelFormatter={bucketTooltipLabel(granularity)}
              formatItem={(name, value) => `${name}: ${fmtUSD(value)}`}
            />
          }
          cursor={{ fill: "var(--bg-4)", opacity: 0.4 }}
        />
        {keys.map((k, i) => (
          <Bar
            {...motion}
            key={k}
            dataKey={k}
            name={k}
            stackId="trend"
            fill={colorFor(k)}
            radius={i === keys.length - 1 ? [3, 3, 0, 0] : [0, 0, 0, 0]}
          />
        ))}
      </BarChart>
    </ResponsiveContainer>
  );
});

function flatten(
  data: AnalysisTrendPoint[],
  topN: number,
  mode: ColorMode,
  grid?: readonly GridPoint[],
) {
  const total: Record<string, number> = {};
  for (const p of data) {
    total[p.key] = (total[p.key] ?? 0) + (p.cost_usd || 0);
  }
  const ranked = Object.entries(total)
    .sort((a, b) => b[1] - a[1])
    .map(([k]) => k);
  const top = new Set(ranked.slice(0, topN));
  const collapse = (k: string) => (top.has(k) ? k : OTHER_SERIES_KEY);

  // Seed every bucket of the served grid (zero-fill order) so an empty
  // bucket keeps its slot on the axis; rows sort by bucket start `t`.
  const byBucket = new Map<string, Record<string, number | string>>();
  for (const g of grid ?? []) byBucket.set(g.bucket, { bucket: g.bucket, t: g.t });
  for (const p of data) {
    const row = byBucket.get(p.bucket) ?? { bucket: p.bucket, t: p.t ?? 0 };
    const key = collapse(p.key);
    row[key] = (Number(row[key]) || 0) + (p.cost_usd || 0);
    byBucket.set(p.bucket, row);
  }
  const rows = [...byBucket.values()].sort((a, b) =>
    Number(a.t) !== Number(b.t)
      ? Number(a.t) - Number(b.t)
      : String(a.bucket) < String(b.bucket)
        ? -1
        : 1,
  );
  const keys = [...ranked.slice(0, topN)];
  if (ranked.length > topN) keys.push(OTHER_SERIES_KEY);

  const colorMap = PALETTE_BY_MODE[mode](keys);
  colorMap.set(OTHER_SERIES_KEY, OTHER_COLOR);
  const colorFor = (k: string) => colorMap.get(k) ?? OTHER_COLOR;

  return { rows, keys, colorFor };
}
