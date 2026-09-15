import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { ChartTooltip } from "./ChartTooltip";
import { ChartLegend } from "./ChartLegend";
import { fmtCompact } from "../lib/format";
import type { CacheTimeseriesPoint } from "../lib/types";
import { CHART_AXIS, CHART_GRID } from "./common";

// CacheTrafficChart — per-day stacked bars of cache_read +
// cache_write tokens. Matches the Cost-page TokensByDayChart
// rhythm so the two pages read in the same visual idiom.
export function CacheTrafficChart({
  data,
  height = 220,
}: {
  data: CacheTimeseriesPoint[];
  height?: number;
}) {
  return (
    <ResponsiveContainer width="100%" height={height + 28}>
      <BarChart data={data} margin={{ top: 8, right: 12, left: 0, bottom: 0 }}>
        <Legend
          verticalAlign="top"
          align="left"
          height={28}
          content={<ChartLegend />}
        />
        <defs>
          {(["read", "write"] as const).map((k) => (
            <linearGradient
              key={k}
              id={`cache-traffic-${k}`}
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
        <Bar
          dataKey="written_tokens"
          name="Cache Write"
          stackId="tok"
          fill="url(#cache-traffic-write)"
          radius={[0, 0, 0, 0]}
        />
        <Bar
          dataKey="read_tokens"
          name="Cache Read"
          stackId="tok"
          fill="url(#cache-traffic-read)"
          radius={[3, 3, 0, 0]}
        />
      </BarChart>
    </ResponsiveContainer>
  );
}

// CacheEventsChart — per-day stacked bars of event_count, with
// rewrite_count rendered as a warn-toned subset of the same stack
// so the operator sees both the total cadence AND the invalidation
// pressure at a glance. Bars total to event_count because the
// rewrites are a subset of events, not additive.
export function CacheEventsChart({
  data,
  height = 220,
}: {
  data: CacheTimeseriesPoint[];
  height?: number;
}) {
  // Recompute: events minus rewrites as the "healthy" bucket, with
  // rewrites stacked on top. Sum reads as the total event count.
  const stacked = data.map((p) => ({
    bucket: p.bucket,
    healthy: Math.max(0, p.event_count - p.rewrite_count),
    rewrites: p.rewrite_count,
  }));
  return (
    <ResponsiveContainer width="100%" height={height + 28}>
      <BarChart data={stacked} margin={{ top: 8, right: 12, left: 0, bottom: 0 }}>
        <Legend
          verticalAlign="top"
          align="left"
          height={28}
          content={<ChartLegend />}
        />
        <defs>
          <linearGradient id="cache-events-healthy" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--info)" stopOpacity="1" />
            <stop offset="100%" stopColor="var(--info)" stopOpacity="0.55" />
          </linearGradient>
          <linearGradient id="cache-events-rewrites" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--warn)" stopOpacity="1" />
            <stop offset="100%" stopColor="var(--warn)" stopOpacity="0.55" />
          </linearGradient>
        </defs>
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
        <Bar
          dataKey="healthy"
          name="Healthy events"
          stackId="ev"
          fill="url(#cache-events-healthy)"
          radius={[0, 0, 0, 0]}
        />
        <Bar
          dataKey="rewrites"
          name="Rewrites"
          stackId="ev"
          fill="url(#cache-events-rewrites)"
          radius={[3, 3, 0, 0]}
        />
      </BarChart>
    </ResponsiveContainer>
  );
}

// CacheRatioChart — per-day point-wise cache_read ÷ cache_write
// ratio, rendered as a line. Days with zero writes show as a
// gap (null), avoiding a misleading flat zero. Sibling to Cost's
// CacheSavingsChart but framed around the engine's headline
// efficiency ratio rather than dollar savings.
export function CacheRatioChart({
  data,
  height = 180,
}: {
  data: CacheTimeseriesPoint[];
  height?: number;
}) {
  const pts = data.map((p) => ({
    bucket: p.bucket,
    ratio: p.written_tokens > 0 ? p.read_tokens / p.written_tokens : null,
  }));
  return (
    <ResponsiveContainer width="100%" height={height}>
      <LineChart data={pts} margin={{ top: 8, right: 12, left: 0, bottom: 0 }}>
        <CartesianGrid {...CHART_GRID} />
        <XAxis dataKey="bucket" {...CHART_AXIS} tickFormatter={shortDate} />
        <YAxis
          {...CHART_AXIS}
          tickFormatter={(v) =>
            typeof v === "number" && Number.isFinite(v) ? `${v.toFixed(0)}×` : ""
          }
        />
        <Tooltip
          content={
            <ChartTooltip
              labelKey="bucket"
              labelFormatter={shortDate}
              formatItem={(name, value) =>
                name === "ratio"
                  ? typeof value === "number"
                    ? `Ratio: ${value.toFixed(1)}×`
                    : "Ratio: —"
                  : `${name}: ${value}`
              }
            />
          }
          cursor={{ stroke: "var(--line-3)" }}
        />
        <Line
          type="monotone"
          dataKey="ratio"
          stroke="var(--accent)"
          strokeWidth={1.8}
          dot={{ r: 2.5, fill: "var(--accent)" }}
          connectNulls={false}
        />
      </LineChart>
    </ResponsiveContainer>
  );
}

function shortDate(s: string): string {
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) return s;
  return d.toLocaleDateString("en-US", { month: "short", day: "numeric" });
}
