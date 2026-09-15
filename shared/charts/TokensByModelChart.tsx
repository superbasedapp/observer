import { useMemo } from "react";
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
import type { TokensByModelPoint } from "../lib/types";
import { CHART_AXIS, CHART_GRID } from "./common";

// Per-day stacked bars where each segment is one model. Top 6
// models by total tokens become real series; the rest collapse
// into "other" so the legend stays readable.
//
// Color palette is deliberately a small, distinguishable set
// of token-bucket-adjacent hues plus tool colors as fallback.
export function TokensByModelChart({
  data,
  height = 240,
  topN = 6,
}: {
  data: TokensByModelPoint[];
  height?: number;
  topN?: number;
}) {
  const { rows, modelKeys, colorFor } = useMemo(
    () => flatten(data, topN),
    [data, topN],
  );

  return (
    <ResponsiveContainer width="100%" height={height + 28}>
      <BarChart data={rows} margin={{ top: 8, right: 12, left: 0, bottom: 0 }}>
        <Legend
          verticalAlign="top"
          align="left"
          height={28}
          content={<ChartLegend />}
        />
        <CartesianGrid {...CHART_GRID} />
        <XAxis dataKey="bucket" {...CHART_AXIS} tickFormatter={shortDate} />
        <YAxis {...CHART_AXIS} tickFormatter={fmtCompact} />
        <Tooltip
          content={
            <ChartTooltip
              labelKey="bucket"
              labelFormatter={shortDate}
              formatItem={(name, value) => `${name}: ${fmtCompact(value)}`}
            />
          }
          cursor={{ fill: "var(--bg-4)", opacity: 0.4 }}
        />
        {modelKeys.map((k, i) => (
          <Bar
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
}

// Cycle through a small set of distinguishable hues for arbitrary
// model keys. Tokens come from the design system so theme switches
// remain automatic.
const MODEL_COLORS = [
  "var(--tok-net)",
  "var(--tok-read)",
  "var(--tok-out)",
  "var(--tok-write)",
  "var(--info)",
  "var(--success)",
  "var(--warn)",
];

const OTHER_COLOR = "var(--tool-other)";

function flatten(data: TokensByModelPoint[], topN: number) {
  // Aggregate per model to pick top-N.
  const total: Record<string, number> = {};
  for (const p of data) {
    total[p.model] = (total[p.model] ?? 0) + (p.total_tokens || 0);
  }
  const ranked = Object.entries(total)
    .sort((a, b) => b[1] - a[1])
    .map(([k]) => k);
  const top = new Set(ranked.slice(0, topN));
  const collapse = (m: string) => (top.has(m) ? m : "other");

  // Pivot data → one row per bucket with one key per model.
  const byBucket = new Map<string, Record<string, number | string>>();
  for (const p of data) {
    const row = byBucket.get(p.bucket) ?? { bucket: p.bucket };
    const key = collapse(p.model);
    row[key] = (Number(row[key]) || 0) + (p.total_tokens || 0);
    byBucket.set(p.bucket, row);
  }

  const rows = [...byBucket.values()].sort((a, b) =>
    String(a.bucket) < String(b.bucket) ? -1 : 1,
  );

  const modelKeys = [...ranked.slice(0, topN)];
  if (ranked.length > topN) modelKeys.push("other");

  const colorMap = new Map<string, string>();
  modelKeys.forEach((m, i) => {
    if (m === "other") colorMap.set(m, OTHER_COLOR);
    else colorMap.set(m, MODEL_COLORS[i % MODEL_COLORS.length]);
  });
  const colorFor = (k: string) => colorMap.get(k) ?? OTHER_COLOR;

  return { rows, modelKeys, colorFor };
}

function shortDate(s: string): string {
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) return s;
  return d.toLocaleDateString("en-US", { month: "short", day: "numeric" });
}
