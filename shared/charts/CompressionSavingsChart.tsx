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
import { fmtBytes, fmtCompact, fmtUSD } from "../lib/format";
import type { CompressionTimeseriesPoint } from "../lib/types";
import { CHART_AXIS, CHART_GRID } from "./common";

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

export function CompressionSavingsChart({
  data,
  unit,
  height = 240,
}: {
  data: CompressionTimeseriesPoint[];
  unit: SavingsUnit;
  height?: number;
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
        <YAxis {...CHART_AXIS} tickFormatter={fmtTick} />
        <Tooltip
          content={
            <ChartTooltip
              labelKey="bucket"
              labelFormatter={shortDate}
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
}

function shortDate(s: string): string {
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) return s;
  return d.toLocaleDateString("en-US", { month: "short", day: "numeric" });
}
