import { memo } from "react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { ChartTooltip } from "./ChartTooltip";
import { ChartLegendFrame, type ChartLegendItem } from "./ChartLegend";
import { fmtCompact, fmtUSD } from "../lib/format";
import type { Granularity } from "../lib/granularity";
import type { CostPoint } from "../lib/types";
import { bucketTooltipLabel, CHART_AXIS, CHART_GRID, timeAxis } from "./common";
import { useChartMotion } from "./useChartMotion";

export type CostAreaMode = "tokens" | "cost";

// The four Anthropic billing buckets. In "tokens" mode (default) each
// bucket is its OWN overlaid area, NOT a stack: every line, and every hover
// dot, sits at that bucket's real value, so the height you read is the
// number the tooltip prints. A stack put Output's line (and its hover dot)
// on top of Cache Read, so an Output of 14M/day drew at 4.5B - Cache Read
// is routinely 100x the other buckets, and whichever series sits on top of
// it inherits its height. The day total lives in the tooltip footer.
//
// Areas paint back to front in TOKEN_SERIES order (typically largest
// first, so the smaller buckets stay visible over the big translucent
// Cache Read fill); the legend keeps the billing order instead.
// In "cost" mode it renders a single area of cost_usd over time so the
// Overview tab can offer the Tokens | Cost $ toggle per the design.
type TokenSeries = {
  key: "input" | "cache_creation" | "cache_read" | "output";
  name: string;
  tok: "net" | "write" | "read" | "out";
};

const TOKEN_SERIES: TokenSeries[] = [
  { key: "cache_read", name: "Cache Read", tok: "read" },
  { key: "cache_creation", name: "Cache Write", tok: "write" },
  { key: "input", name: "Net Input", tok: "net" },
  { key: "output", name: "Output", tok: "out" },
];

// Billing order for the legend: net input, cache write, cache read, output.
const LEGEND_ORDER: TokenSeries["key"][] = [
  "input",
  "cache_creation",
  "cache_read",
  "output",
];

const TOKEN_LEGEND: ChartLegendItem[] = LEGEND_ORDER.map((k) => {
  const s = TOKEN_SERIES.find((t) => t.key === k)!;
  return {
    value: s.name,
    id: s.key,
    color: `var(--tok-${s.tok})`,
  };
});

// Cost mode draws one series.
const COST_LEGEND: ChartLegendItem[] = [
  { value: "Cost $", id: "cost_usd", color: "var(--accent)" },
];

export const CostAreaChart = memo(function CostAreaChart({
  data,
  mode = "tokens",
  granularity = "1d",
}: {
  data: CostPoint[];
  mode?: CostAreaMode;
  /** Bucket granularity the rows were served at (the response `bucket`); drives the axis/tooltip labels. */
  granularity?: Granularity;
}) {
  // The legend renders in normal flow above the plot (ChartLegendFrame), so
  // a wrap at phone width can never land on the top y-axis tick.
  const motion = useChartMotion(data, "bucket", mode);
  return (
    <ChartLegendFrame height={250} items={mode === "tokens" ? TOKEN_LEGEND : COST_LEGEND}>
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart
          data={data}
          margin={{ top: 8, right: 12, left: 0, bottom: 0 }}
        >
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
          <XAxis {...CHART_AXIS} {...timeAxis(data, granularity)} />
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
                labelFormatter={bucketTooltipLabel(granularity)}
                sort={mode === "tokens" ? "value" : "reverse"}
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
              {...motion}
              type="monotone"
              dataKey="cost_usd"
              name="Cost $"
              stroke="var(--accent)"
              fill="url(#cost-grad-usd)"
              strokeWidth={1.6}
            />
          ) : (
            TOKEN_SERIES.map((t) => (
              <Area
                {...motion}
                key={t.key}
                type="monotone"
                dataKey={t.key}
                name={t.name}
                stroke={`var(--tok-${t.tok})`}
                fill={`url(#cost-grad-${t.tok})`}
                strokeWidth={1.4}
              />
            ))
          )}
        </AreaChart>
      </ResponsiveContainer>
    </ChartLegendFrame>
  );
});
