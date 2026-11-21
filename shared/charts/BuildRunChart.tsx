import { memo, useMemo } from "react";
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { ChartTooltip } from "./ChartTooltip";
import { ChartLegend } from "./ChartLegend";
import { CHART_AXIS, CHART_GRID } from "./common";
import { dollarsShown, fmtCompact, fmtUSD } from "../lib/format";
import { useChartMotion } from "./useChartMotion";

// One UTC day of a service's build-vs-run cost (Plane A W5-8, lane C3): what
// coding agents spent building the projects the service links to (build) and
// what the service spent running (run). The org route
// (GET /api/org/crossplane/services/{service}) and the machine's Your apps
// route both serve this shape.
export interface BuildRunPoint {
  date: string;
  build_cost_usd: number;
  run_cost_usd: number;
  build_tokens: number;
  run_tokens: number;
}

// The two series, in legend order. Colours are design tokens, never literals.
const SERIES = [
  { key: "build", name: "Build (coding agents)", color: "var(--accent)" },
  { key: "run", name: "Run (the service)", color: "var(--info)" },
] as const;

// BuildRunChart draws the two series side by side per day: dollars, or the
// token volume behind them in the token display mode (format.ts).
export const BuildRunChart = memo(function BuildRunChart({
  points,
  height = 220,
}: {
  points: BuildRunPoint[];
  height?: number;
}) {
  const dollars = dollarsShown();
  const rows = useMemo(
    () =>
      points.map((p) => ({
        date: p.date,
        build: dollars ? p.build_cost_usd : p.build_tokens,
        run: dollars ? p.run_cost_usd : p.run_tokens,
      })),
    [points, dollars],
  );
  const fmt = (n: number) => (dollars ? fmtUSD(n) : fmtCompact(n));
  const motion = useChartMotion(rows, "date", "buildrun", SERIES.length);
  return (
    <ResponsiveContainer width="100%" height={height + 28}>
      <BarChart data={rows} margin={{ top: 8, right: 12, left: 0, bottom: 0 }}>
        <Legend verticalAlign="top" align="left" content={<ChartLegend />} />
        <CartesianGrid {...CHART_GRID} />
        <XAxis {...CHART_AXIS} dataKey="date" tickFormatter={(d) => String(d).slice(5)} minTickGap={16} />
        <YAxis {...CHART_AXIS} tickFormatter={(v) => fmt(Number(v))} />
        <Tooltip
          content={<ChartTooltip labelKey="date" formatItem={(name, value) => `${name}: ${fmt(value)}`} />}
          cursor={{ fill: "var(--bg-4)", opacity: 0.4 }}
        />
        {SERIES.map((s) => (
          <Bar {...motion} key={s.key} dataKey={s.key} name={s.name} fill={s.color} radius={[3, 3, 0, 0]} />
        ))}
      </BarChart>
    </ResponsiveContainer>
  );
});
