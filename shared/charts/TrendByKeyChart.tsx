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
import { fmtUSD } from "../lib/format";
import type { AnalysisTrendPoint } from "../lib/types";
import { CHART_AXIS, CHART_GRID } from "./common";
import { toolMeta } from "../lib/tools";

// Daily spend stacked by key — the Analysis tab's dim-toggle chart.
// `colorMode` picks the palette: "model" uses the same rotating set
// as TokensByModelChart so users see consistent model coloring; "tool"
// reaches into the tool registry; "project" cycles through a neutral
// palette since there's no canonical project color.
const PROJECT_COLORS = [
  "var(--accent)",
  "var(--info)",
  "var(--success)",
  "var(--warn)",
  "var(--tok-read)",
  "var(--tok-out)",
  "var(--tok-write)",
];

const MODEL_COLORS = [
  "var(--tok-net)",
  "var(--tok-read)",
  "var(--tok-out)",
  "var(--tok-write)",
  "var(--info)",
  "var(--success)",
  "var(--warn)",
];

export function TrendByKeyChart({
  data,
  colorMode = "model",
  topN = 6,
  height = 280,
}: {
  data: AnalysisTrendPoint[];
  colorMode?: "model" | "project" | "tool";
  topN?: number;
  height?: number;
}) {
  const { rows, keys, colorFor } = useMemo(
    () => flatten(data, topN, colorMode),
    [data, topN, colorMode],
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
        <YAxis {...CHART_AXIS} tickFormatter={(v) => fmtUSD(Number(v))} />
        <Tooltip
          content={
            <ChartTooltip
              labelKey="bucket"
              labelFormatter={shortDate}
              formatItem={(name, value) => `${name}: ${fmtUSD(value)}`}
            />
          }
          cursor={{ fill: "var(--bg-4)", opacity: 0.4 }}
        />
        {keys.map((k, i) => (
          <Bar
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
}

function flatten(
  data: AnalysisTrendPoint[],
  topN: number,
  mode: "model" | "project" | "tool",
) {
  const total: Record<string, number> = {};
  for (const p of data) {
    total[p.key] = (total[p.key] ?? 0) + (p.cost_usd || 0);
  }
  const ranked = Object.entries(total)
    .sort((a, b) => b[1] - a[1])
    .map(([k]) => k);
  const top = new Set(ranked.slice(0, topN));
  const collapse = (k: string) => (top.has(k) ? k : "other");

  const byBucket = new Map<string, Record<string, number | string>>();
  for (const p of data) {
    const row = byBucket.get(p.bucket) ?? { bucket: p.bucket };
    const key = collapse(p.key);
    row[key] = (Number(row[key]) || 0) + (p.cost_usd || 0);
    byBucket.set(p.bucket, row);
  }
  const rows = [...byBucket.values()].sort((a, b) =>
    String(a.bucket) < String(b.bucket) ? -1 : 1,
  );
  const keys = [...ranked.slice(0, topN)];
  if (ranked.length > topN) keys.push("other");

  const colorMap = new Map<string, string>();
  keys.forEach((k, i) => {
    if (k === "other") {
      colorMap.set(k, "var(--tool-other)");
      return;
    }
    if (mode === "tool") {
      colorMap.set(k, toolMeta(k).colorVar);
    } else if (mode === "project") {
      colorMap.set(k, PROJECT_COLORS[i % PROJECT_COLORS.length]);
    } else {
      colorMap.set(k, MODEL_COLORS[i % MODEL_COLORS.length]);
    }
  });
  const colorFor = (k: string) => colorMap.get(k) ?? "var(--tool-other)";

  return { rows, keys, colorFor };
}

function shortDate(s: string): string {
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) return s;
  return d.toLocaleDateString("en-US", { month: "short", day: "numeric" });
}
