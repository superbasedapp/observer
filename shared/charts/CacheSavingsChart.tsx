import { memo } from "react";
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
import { fmtUSD } from "../lib/format";
import type { Granularity } from "../lib/granularity";
import type { CacheSavingsPoint } from "../lib/types";
import { bucketTooltipLabel, CHART_AXIS, CHART_GRID, timeAxis } from "./common";
import { useChartMotion } from "./useChartMotion";

// The one series' legend entry. A fixed payload (not the Area's own name)
// keeps the tooltip's `savings_usd` key untouched; the colour is given
// explicitly because the area's fill is a gradient url().
const SAVINGS_LEGEND = [
  { value: "Saved by cache reads", type: "circle" as const, color: "var(--success)" },
];

// CacheSavingsChart: dollars saved by cache reads per bucket. The legend is on by
// default (`legend={false}` for a caller that labels the series itself); the
// container grows by the legend row so the plot keeps `height`.
export const CacheSavingsChart = memo(function CacheSavingsChart({
  data,
  height = 180,
  legend = true,
  granularity = "1d",
}: {
  data: CacheSavingsPoint[];
  height?: number;
  legend?: boolean;
  /** Bucket granularity the rows were served at (the response `bucket`); drives the axis/tooltip labels. */
  granularity?: Granularity;
}) {
  const motion = useChartMotion(data, "day");
  return (
    <ResponsiveContainer width="100%" height={legend ? height + 24 : height}>
      <AreaChart
        data={data}
        margin={{ top: 8, right: 12, left: 0, bottom: 0 }}
      >
        {legend && (
          <Legend
            verticalAlign="top"
            align="left"
            payload={SAVINGS_LEGEND}
            content={<ChartLegend />}
          />
        )}
        <defs>
          <linearGradient id="cache-savings-grad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--success)" stopOpacity="0.7" />
            <stop offset="100%" stopColor="var(--success)" stopOpacity="0" />
          </linearGradient>
        </defs>
        <CartesianGrid {...CHART_GRID} />
        <XAxis {...CHART_AXIS} {...timeAxis(data, granularity, "day")} />
        <YAxis {...CHART_AXIS} tickFormatter={(v) => fmtUSD(Number(v))} />
        <Tooltip
          content={
            <ChartTooltip
              labelKey="day"
              labelFormatter={bucketTooltipLabel(granularity)}
              formatItem={(name, value) =>
                name === "savings_usd"
                  ? `Saved: ${fmtUSD(value)}`
                  : `${name}: ${value}`
              }
            />
          }
          cursor={{ stroke: "var(--line-3)" }}
        />
        <Area
          {...motion}
          type="monotone"
          dataKey="savings_usd"
          stroke="var(--success)"
          fill="url(#cache-savings-grad)"
          strokeWidth={1.6}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
});
