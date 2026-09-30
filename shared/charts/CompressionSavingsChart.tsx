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
import { fmtBytes, fmtCompact, fmtUSD } from "../lib/format";
import type { Granularity } from "../lib/granularity";
import type { CompressionTimeseriesPoint } from "../lib/types";
import { bucketTooltipLabel, categoryAxis, CHART_AXIS, CHART_GRID } from "./common";
import { useChartMotion } from "./useChartMotion";

export type SavingsUnit = "tokens" | "usd" | "bytes";

// Mechanism color palette — picks distinguishable hues from the
// design system without colliding with the 4 billing-bucket
// tokens used by Cost / Overview charts.
const MECH_COLORS: Record<string, string> = {
  json: "var(--tok-net)",
  code: "var(--tok-read)",
  logs: "var(--success)",
  text: "var(--tok-out)",
  diff: "var(--warn)",
  html: "var(--accent)",
  drop: "var(--danger)",
  read_cache: "var(--tok-write)",
  tools: "var(--info)",
  stash: "var(--act-agent)",
  rolling_summary: "var(--act-user)",
};

const FALLBACK = "var(--tool-other)";

export const CompressionSavingsChart = memo(function CompressionSavingsChart({
  data,
  unit,
  height = 240,
  granularity = "1d",
}: {
  data: CompressionTimeseriesPoint[];
  unit: SavingsUnit;
  height?: number;
  /** Bucket granularity the rows were served at (the response `bucket`); drives the axis/tooltip labels. */
  granularity?: Granularity;
}) {
  const { rows, mechs, fmtTick } = useMemo(() => {
    // Build a single row per bucket with one key per mechanism.
    const mechSet = new Set<string>();
    const rows: Record<string, number | string>[] = [];
    for (const p of data) {
      const row: Record<string, number | string> = { bucket: p.bucket };
      for (const [mech, stats] of Object.entries(p.by_mechanism)) {
        mechSet.add(mech);
        row[mech] =
          unit === "tokens"
            ? Math.max(0, stats.saved_bytes) / 4
            : unit === "usd"
              ? stats.saved_usd_est
              : Math.max(0, stats.saved_bytes);
      }
      rows.push(row);
    }
    const mechs = [...mechSet].sort();
    const fmtTick =
      unit === "usd"
        ? (v: number | string) => fmtUSD(Number(v))
        : unit === "bytes"
          ? (v: number | string) => fmtBytes(Number(v))
          : (v: number | string) => fmtCompact(Number(v));
    return { rows, mechs, fmtTick };
  }, [data, unit]);

  const motion = useChartMotion(rows, "bucket", unit, mechs.length);
  return (
    <ResponsiveContainer width="100%" height={height + 28}>
      <BarChart data={rows} margin={{ top: 8, right: 12, left: 0, bottom: 0 }}>
        <Legend
          verticalAlign="top"
          align="left"
          content={<ChartLegend />}
        />
        <CartesianGrid {...CHART_GRID} />
        <XAxis {...CHART_AXIS} {...categoryAxis(rows, granularity)} />
        <YAxis {...CHART_AXIS} tickFormatter={fmtTick} />
        <Tooltip
          content={
            <ChartTooltip
              labelKey="bucket"
              labelFormatter={bucketTooltipLabel(granularity)}
              formatItem={(name, value) =>
                `${name}: ${
                  unit === "usd"
                    ? fmtUSD(value)
                    : unit === "bytes"
                      ? fmtBytes(value)
                      : fmtCompact(value)
                }`
              }
            />
          }
          cursor={{ fill: "var(--bg-4)", opacity: 0.4 }}
        />
        {mechs.map((m, i) => (
          <Bar
            {...motion}
            key={m}
            dataKey={m}
            name={m}
            stackId="mech"
            fill={MECH_COLORS[m] ?? FALLBACK}
            radius={i === mechs.length - 1 ? [3, 3, 0, 0] : [0, 0, 0, 0]}
          />
        ))}
      </BarChart>
    </ResponsiveContainer>
  );
});
