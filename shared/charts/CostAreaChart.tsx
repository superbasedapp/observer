import {
  Area,
  AreaChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { ChartTooltip } from "./ChartTooltip";
import { ChartLegend } from "./ChartLegend";
import { fmtCompact, fmtUSD } from "../lib/format";
import type { CostPoint } from "../lib/types";
import { CHART_AXIS, CHART_GRID } from "./common";

export type CostAreaMode = "tokens" | "cost";

// Four Anthropic billing buckets in stacking order (bottom → top):
// net input < cache write < cache read < output. In "tokens" mode
// (default) renders the 4-bucket stack; in "cost" mode renders a
// single area of cost_usd over time so the Overview tab can offer
// the Tokens | Cost $ toggle per the design.
export function CostAreaChart({
  data,
  mode = "tokens",
}: {
  data: CostPoint[];
  mode?: CostAreaMode;
}) {
  return (
    <ResponsiveContainer width="100%" height={250}>
      <AreaChart
        data={data}
        margin={{ top: 8, right: 12, left: 0, bottom: 0 }}
      >
        <Legend
          verticalAlign="top"
          align="left"
          height={28}
          content={<ChartLegend />}
        />
        <defs>
          {(["net", "write", "read", "out"] as const).map((k) => (
            <linearGradient
              key={k}
              id={`cost-grad-${k}`}
              x1="0"
              y1="0"
              x2="0"
              y2="1"
            >
              <stop
                offset="0%"
                stopColor={`var(--tok-${k})`}
                stopOpacity="0.7"
              />
              <stop
                offset="100%"
                stopColor={`var(--tok-${k})`}
                stopOpacity="0.05"
              />
            </linearGradient>
          ))}
          <linearGradient id="cost-grad-usd" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--accent)" stopOpacity="0.75" />
            <stop offset="100%" stopColor="var(--accent)" stopOpacity="0" />
          </linearGradient>
        </defs>
        <CartesianGrid {...CHART_GRID} />
        <XAxis dataKey="bucket" {...CHART_AXIS} tickFormatter={shortDate} />
        <YAxis
          {...CHART_AXIS}
          tickFormatter={
            mode === "cost"
              ? (v: number | string) => fmtUSD(Number(v))
              : fmtCompact
          }
        />
        <Tooltip
          content={
            <ChartTooltip
              labelKey="bucket"
              labelFormatter={shortDate}
              formatItem={(name, value) =>
                mode === "cost"
                  ? `${name}: ${fmtUSD(value)}`
                  : `${name}: ${fmtCompact(value)}`
              }
              extra={(row) =>
                mode === "tokens" && row.cost_usd != null
                  ? `${fmtUSD(Number(row.cost_usd))} total`
                  : null
              }
            />
          }
          cursor={{ stroke: "var(--line-3)" }}
        />
        {mode === "cost" ? (
          <Area
            type="monotone"
            dataKey="cost_usd"
            name="Cost $"
            stroke="var(--accent)"
            fill="url(#cost-grad-usd)"
            strokeWidth={1.6}
          />
        ) : (
          <>
            <Area
              type="monotone"
              dataKey="input"
              name="Net Input"
              stroke="var(--tok-net)"
              fill="url(#cost-grad-net)"
              strokeWidth={1.4}
              stackId="1"
            />
            <Area
              type="monotone"
              dataKey="cache_creation"
              name="Cache Write"
              stroke="var(--tok-write)"
              fill="url(#cost-grad-write)"
              strokeWidth={1.4}
              stackId="1"
            />
            <Area
              type="monotone"
              dataKey="cache_read"
              name="Cache Read"
              stroke="var(--tok-read)"
              fill="url(#cost-grad-read)"
              strokeWidth={1.4}
              stackId="1"
            />
            <Area
              type="monotone"
              dataKey="output"
              name="Output"
              stroke="var(--tok-out)"
              fill="url(#cost-grad-out)"
              strokeWidth={1.4}
              stackId="1"
            />
          </>
        )}
      </AreaChart>
    </ResponsiveContainer>
  );
}

function shortDate(s: string): string {
  // ISO day buckets are 2026-05-15 — show "May 15".
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) return s;
  return d.toLocaleDateString("en-US", { month: "short", day: "numeric" });
}
