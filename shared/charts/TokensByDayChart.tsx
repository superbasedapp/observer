import { memo } from "react";
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
import type { CostPoint } from "../lib/types";
import { bucketTooltipLabel, categoryAxis, CHART_AXIS, CHART_GRID } from "./common";
import { useChartMotion } from "./useChartMotion";

// Per-bucket stacked bars across the 4 Anthropic billing buckets.
// Sibling to CostAreaChart on the Overview but in bar form, which
// the brief flags as the right call for the Cost tab's "Token
// volume per day" panel (read as totals, not trends).
export const TokensByDayChart = memo(function TokensByDayChart({
  data,
  height = 240,
  granularity = "1d",
}: {
  data: CostPoint[];
  height?: number;
  /** Bucket granularity the rows were served at (the response `bucket`); drives the axis/tooltip labels. */
  granularity?: Granularity;
}) {
  const motion = useChartMotion(data, "bucket", "", 4);
  return (
    <ResponsiveContainer width="100%" height={height + 28}>
      <BarChart data={data} margin={{ top: 8, right: 12, left: 0, bottom: 0 }}>
        <Legend
          verticalAlign="top"
          align="left"
          content={
            <ChartLegend
              colors={{
                "Net Input": "var(--tok-net)",
                "Cache Write": "var(--tok-write)",
                "Cache Read": "var(--tok-read)",
                Output: "var(--tok-out)",
              }}
            />
          }
        />
        <defs>
          {(["net", "write", "read", "out"] as const).map((k) => (
            <linearGradient
              key={k}
              id={`tokens-by-day-${k}`}
              x1="0"
              y1="0"
              x2="0"
              y2="1"
            >
              <stop
                offset="0%"
                stopColor={`var(--tok-${k})`}
                stopOpacity="1"
              />
              <stop
                offset="100%"
                stopColor={`var(--tok-${k})`}
                stopOpacity="0.55"
              />
            </linearGradient>
          ))}
        </defs>
        <CartesianGrid {...CHART_GRID} />
        <XAxis {...CHART_AXIS} {...categoryAxis(data, granularity)} />
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
        <Bar
          {...motion}
          dataKey="input"
          name="Net Input"
          stackId="tok"
          fill="url(#tokens-by-day-net)"
          radius={[0, 0, 0, 0]}
        />
        <Bar
          {...motion}
          dataKey="cache_creation"
          name="Cache Write"
          stackId="tok"
          fill="url(#tokens-by-day-write)"
        />
        <Bar
          {...motion}
          dataKey="cache_read"
          name="Cache Read"
          stackId="tok"
          fill="url(#tokens-by-day-read)"
        />
        <Bar
          {...motion}
          dataKey="output"
          name="Output"
          stackId="tok"
          fill="url(#tokens-by-day-out)"
          radius={[3, 3, 0, 0]}
        />
      </BarChart>
    </ResponsiveContainer>
  );
});
