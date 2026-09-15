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
import { fmtUSD } from "../lib/format";
import type { CacheSavingsPoint } from "../lib/types";
import { CHART_AXIS, CHART_GRID } from "./common";

export function CacheSavingsChart({
  data,
  height = 180,
}: {
  data: CacheSavingsPoint[];
  height?: number;
}) {
  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart
        data={data}
        margin={{ top: 8, right: 12, left: 0, bottom: 0 }}
      >
        <defs>
          <linearGradient id="cache-savings-grad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--success)" stopOpacity="0.7" />
            <stop offset="100%" stopColor="var(--success)" stopOpacity="0" />
          </linearGradient>
        </defs>
        <CartesianGrid {...CHART_GRID} />
        <XAxis dataKey="day" {...CHART_AXIS} tickFormatter={shortDate} />
        <YAxis {...CHART_AXIS} tickFormatter={(v) => fmtUSD(Number(v))} />
        <Tooltip
          content={
            <ChartTooltip
              labelKey="day"
              labelFormatter={shortDate}
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
          type="monotone"
          dataKey="savings_usd"
          stroke="var(--success)"
          fill="url(#cache-savings-grad)"
          strokeWidth={1.6}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}

function shortDate(s: string): string {
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) return s;
  return d.toLocaleDateString("en-US", { month: "short", day: "numeric" });
}
