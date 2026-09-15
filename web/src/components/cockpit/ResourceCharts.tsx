import { useMemo } from "react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { TooltipProps } from "recharts";
import type {
  NameType,
  ValueType,
} from "recharts/types/component/DefaultTooltipContent";
import { CHART_AXIS, CHART_GRID } from "@/components/charts/common";
import { ChartState } from "@/components/ChartState";
import { fmtBytes } from "@/lib/format";

// ResourceCharts — the Session Cockpit's live compute/memory/disk/network
// charts.
//
// These replace three 48×14px axis-less sparklines that were (a) drawn from a
// SINGLE arbitrarily-chosen process rather than the session's whole subtree and
// (b) plotting the RAW cumulative cpu_ms / read+write counters, which can only
// ever look like a straight ramp — never a CPU% or a B/s. All the derivation
// (bucketing onto a common grid, differentiating the counters, summing the
// instantaneous RSS) happens server-side in GET /api/session/<id>/metrics; this
// component only renders what that endpoint already resolved.
//
// Layout is small-multiples: one series per chart (so identity comes from the
// chart's own title, not from a colour legend), one shared time axis under the
// stack, and a header that states the window actually covered.

// SessionMetricPoint mirrors dashboard.SessionMetricPoint. A null rate is a
// real GAP in coverage — materially different from 0 ("covered, and idle") —
// so it must never be coerced to zero.
export type SessionMetricPoint = {
  t: string;
  cpu_pct: number | null;
  rss_bytes: number | null;
  read_bps: number | null;
  write_bps: number | null;
  disk_bps: number | null;
  net_rx_bps?: number | null;
  net_tx_bps?: number | null;
  procs: number;
};

// SessionMetricsResponse mirrors dashboard.SessionMetricsResponse.
export type SessionMetricsResponse = {
  session_id: string;
  bucket_ms: number;
  sample_interval_ms: number;
  from?: string;
  to?: string;
  window_ms: number;
  points: SessionMetricPoint[];
  processes: number;
  sampled_processes: number;
  rate_processes: number;
  window_truncated: boolean;
  cpu_scale: string;
  cpu_cores: number;
  series: { cpu: boolean; rss: boolean; disk: boolean; network: boolean };
  process_enabled: boolean;
  reason?: string;
};

type Row = {
  ms: number;
  cpu: number | null;
  rss: number | null;
  disk: number | null;
  read: number | null;
  write: number | null;
  net: number | null;
  rx: number | null;
  tx: number | null;
  procs: number;
};

const CHART_H = 62;
const AXIS_H = 18;
const Y_WIDTH = 42;

// EMPTY_REASONS maps the server's machine-readable reason code to the honest
// operator sentence. Table-driven: a new code is a new row, not a new branch.
// SystemSection normally intercepts the capture-disabled case with its enable
// CTA before this component renders; the row here covers the window where the
// two polls disagree (config flipped between them).
const EMPTY_REASONS: Record<string, string> = {
  capture_disabled: "Process capture is off, so no resource samples are being recorded.",
  no_processes: "No processes have been attributed to this session yet.",
  no_samples: "Processes captured, but no resource samples have landed yet.",
  awaiting_second_sample:
    "Waiting for a second sample - CPU and disk are cumulative counters, so a rate needs two readings.",
  no_points: "No plottable samples in the retained window.",
};

// ChartSpec is one small-multiple in the stack — a data table, not a chain of
// conditionals, so the row order IS the render order and availability is a
// per-row predicate.
type ChartSpec = {
  title: string;
  dataKey: "cpu" | "rss" | "disk" | "net";
  color: string;
  available: (m: SessionMetricsResponse) => boolean;
  unit: (m: SessionMetricsResponse) => string;
  yFmt: (v: number) => string;
  tooltipItem: (row: Row) => string | null;
};

const CHARTS: ChartSpec[] = [
  {
    title: "CPU",
    dataKey: "cpu",
    color: "var(--accent)",
    available: (m) => m.series.cpu,
    unit: cpuUnit,
    yFmt: (v) => `${trim(v)}%`,
    tooltipItem: (row) => (row.cpu == null ? null : `CPU: ${trim(row.cpu)}% of one core`),
  },
  {
    title: "Memory",
    dataKey: "rss",
    color: "var(--tok-out)",
    available: (m) => m.series.rss,
    unit: () => "RSS, summed",
    yFmt: (v) => fmtBytes(v),
    tooltipItem: (row) => (row.rss == null ? null : `RSS: ${fmtBytes(row.rss)}`),
  },
  {
    title: "Disk I/O",
    dataKey: "disk",
    color: "var(--tok-write)",
    available: (m) => m.series.disk,
    unit: () => "read + write",
    // Rates are fractional bytes/sec; fmtBytes only reads well on integers.
    yFmt: (v) => `${fmtBytes(Math.round(v))}/s`,
    tooltipItem: (row) =>
      row.disk == null
        ? null
        : `Disk: ${fmtBytes(Math.round(row.disk))}/s (read ${fmtBytes(
            Math.round(row.read ?? 0),
          )}/s · write ${fmtBytes(Math.round(row.write ?? 0))}/s)`,
  },
  {
    title: "Network I/O",
    dataKey: "net",
    color: "var(--tok-net)",
    available: (m) => m.series.network,
    // "TCP only" is not a hedge, it is the measurement's actual scope: the
    // per-process counters come from eBPF socket accounting over TCP payload
    // bytes, so a QUIC/UDP-heavy workload legitimately reads near zero here.
    // Labelling this "network" flat would claim total traffic.
    unit: () => "rx + tx · TCP only",
    // Rates are fractional bytes/sec; fmtBytes only reads well on integers.
    yFmt: (v) => `${fmtBytes(Math.round(v))}/s`,
    tooltipItem: (row) =>
      row.net == null
        ? null
        : `Network: ${fmtBytes(Math.round(row.net))}/s (rx ${fmtBytes(
            Math.round(row.rx ?? 0),
          )}/s · tx ${fmtBytes(Math.round(row.tx ?? 0))}/s, TCP only)`,
  },
];

export function ResourceCharts({
  metrics,
  loading,
  error,
}: {
  metrics: SessionMetricsResponse | null;
  loading: boolean;
  error: Error | null;
}) {
  const rows: Row[] = useMemo(
    () =>
      (metrics?.points ?? []).map((p) => {
        // rx/tx are separate wire fields with no server-side total (unlike
        // disk, which ships disk_bps). The combined value is derived here the
        // same way the server derives DiskBps — sum the covered halves — and
        // stays null when NEITHER half was covered, so an uncovered bucket is
        // still a gap rather than a zero.
        const rx = p.net_rx_bps ?? null;
        const tx = p.net_tx_bps ?? null;
        return {
          ms: Date.parse(p.t),
          cpu: p.cpu_pct,
          rss: p.rss_bytes,
          disk: p.disk_bps,
          read: p.read_bps,
          write: p.write_bps,
          net: rx == null && tx == null ? null : (rx ?? 0) + (tx ?? 0),
          rx,
          tx,
          procs: p.procs,
        };
      }),
    [metrics],
  );

  // Points can only exist because some series contributed, but guard anyway:
  // rendering an empty chart stack would be worse than saying nothing. Every
  // series belongs in this test: a host that measures only ONE of them still
  // has real data, and omitting a flag here would print "no resource samples"
  // over a non-empty points array — a fabricated no-data claim.
  const anySeries = Boolean(
    metrics?.series.cpu || metrics?.series.rss || metrics?.series.disk || metrics?.series.network,
  );
  const hasAny = rows.length > 0 && anySeries;
  const reason = metrics?.reason ?? "";
  const emptyHint = hasAny
    ? undefined
    : EMPTY_REASONS[reason] ?? "No resource samples in the retained window.";

  // A window narrower than ~5 minutes wants seconds in its tick labels.
  const fine = (metrics?.window_ms ?? 0) < 5 * 60 * 1000;
  const tickFmt = (v: number) => clock(v, fine);

  // Only the series the server says it MEASURED are rendered. An unmeasured
  // series is omitted outright — drawing it as a flat zero would claim
  // "nothing happened" when the truth is "nothing was measured". The network
  // series arrived exactly this way: one more CHARTS row gated on
  // series.network, no other change. A host without the eBPF socket probes
  // sends series.network=false and simply gets a three-chart stack.
  const visible = CHARTS.filter((c) => metrics != null && c.available(metrics));

  return (
    <div>
      <WindowLabel metrics={metrics} />
      <ChartState
        loading={loading && !metrics}
        error={error && !metrics ? error : null}
        empty={!hasAny}
        emptyHint={emptyHint}
        // A loading skeleton reserves roughly the chart stack so the panel
        // doesn't jump; an empty/explained state stays one line tall.
        height={loading && !metrics ? CHART_H * 2 : 44}
      >
        <div className="space-y-1">
          {metrics && visible.map((c, i) => (
            <MiniChart
              key={c.dataKey}
              title={c.title}
              unit={c.unit(metrics)}
              dataKey={c.dataKey}
              color={c.color}
              gradientId={`cockpit-res-${c.dataKey}`}
              rows={rows}
              yFmt={c.yFmt}
              tickFmt={tickFmt}
              // Only the bottom visible chart draws the shared time axis, so
              // the stack keeps one time base even when a series is missing.
              showAxis={i === visible.length - 1}
              tooltipItem={c.tooltipItem}
            />
          ))}
        </div>
      </ChartState>
    </div>
  );
}

// WindowLabel states what is actually on screen: the window covered by the
// retained samples (derived from the data, never a hardcoded capture cadence),
// the bucket width, and how many processes contributed. The sample ring is
// in-memory in the daemon's Attributor and capped, so a truncated window is
// called out rather than passed off as the process's whole life.
function WindowLabel({ metrics }: { metrics: SessionMetricsResponse | null }) {
  if (!metrics || metrics.points.length === 0) return null;
  const win = fmtDur(metrics.window_ms);
  const bucket = fmtDur(metrics.bucket_ms);
  const procs = metrics.sampled_processes;
  // "live" is asserted from the data, not assumed: the newest bucket has to be
  // recent relative to the bucket width itself (which tracks the capture
  // cadence), otherwise the series is stale and says so.
  const lastMs = Date.parse(metrics.points[metrics.points.length - 1]?.t ?? "");
  const staleAfter = Math.max(3 * metrics.bucket_ms, 30_000);
  const ageMs = Number.isNaN(lastMs) ? Number.POSITIVE_INFINITY : Date.now() - lastMs;
  const live = ageMs < staleAfter;
  return (
    <div className="mb-1 flex flex-wrap items-center gap-x-2 text-[10px] text-fg-4">
      <span title={`${metrics.from} → ${metrics.to}`}>last {win}</span>
      <span>·</span>
      {live ? (
        <span className="text-success" title="The newest bucket is current.">
          live
        </span>
      ) : (
        <span className="text-warn" title="No sample has landed recently - the series below is not current.">
          stale · {fmtDur(ageMs)} old
        </span>
      )}
      <span>·</span>
      <span title="Each point aggregates this much wall time.">{bucket} buckets</span>
      <span>·</span>
      <span title="Every process attributed to this session that carries resource samples. All of them are summed - not just one.">
        {procs} {procs === 1 ? "process" : "processes"}
      </span>
      {metrics.window_truncated && (
        <>
          <span>·</span>
          <span
            className="text-warn"
            title="Older samples have already been dropped: the per-process sample ring is capped and lives in the daemon's memory, so it also resets when the daemon restarts. The window above is shorter than the process's life."
          >
            window limited by sample ring
          </span>
        </>
      )}
    </div>
  );
}

// MiniChart is one small-multiple: a single series, so identity comes from the
// title rather than a colour legend. Only the bottom chart draws the shared
// time axis; the y-axis width is identical on every chart so the plot areas
// line up and the visible charts read as one stack.
function MiniChart({
  title,
  unit,
  dataKey,
  color,
  gradientId,
  rows,
  yFmt,
  tickFmt,
  showAxis,
  tooltipItem,
}: {
  title: string;
  unit: string;
  dataKey: "cpu" | "rss" | "disk" | "net";
  color: string;
  gradientId: string;
  rows: Row[];
  yFmt: (v: number) => string;
  tickFmt: (v: number) => string;
  showAxis: boolean;
  tooltipItem: (row: Row) => string | null;
}) {
  return (
    <div>
      <div className="flex items-baseline justify-between text-[10px] leading-tight">
        <span className="font-medium text-fg-2">{title}</span>
        <span className="text-fg-4">{unit}</span>
      </div>
      <ResponsiveContainer width="100%" height={CHART_H + (showAxis ? AXIS_H : 0)}>
        <AreaChart data={rows} margin={{ top: 4, right: 4, left: 0, bottom: 0 }}>
          <defs>
            <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={color} stopOpacity="0.45" />
              <stop offset="100%" stopColor={color} stopOpacity="0.04" />
            </linearGradient>
          </defs>
          <CartesianGrid {...CHART_GRID} />
          <XAxis
            dataKey="ms"
            type="number"
            scale="time"
            domain={["dataMin", "dataMax"]}
            {...CHART_AXIS}
            tick={showAxis ? { fill: "var(--fg-3)", fontSize: 9 } : false}
            height={showAxis ? AXIS_H : 0}
            hide={!showAxis}
            tickFormatter={tickFmt}
            interval="preserveStartEnd"
            minTickGap={44}
          />
          <YAxis
            {...CHART_AXIS}
            tick={{ fill: "var(--fg-3)", fontSize: 9 }}
            width={Y_WIDTH}
            tickCount={3}
            tickFormatter={(v: number) => yFmt(v)}
          />
          <Tooltip
            content={<ResourceTooltip color={color} line={tooltipItem} />}
            cursor={{ stroke: "var(--line-3)" }}
          />
          <Area
            type="monotone"
            dataKey={dataKey}
            name={title}
            stroke={color}
            strokeWidth={1.6}
            fill={`url(#${gradientId})`}
            dot={false}
            activeDot={{ r: 2.5, strokeWidth: 0 }}
            isAnimationActive={false}
            connectNulls={false}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

// ResourceTooltip is a one-series tooltip in the shared chart-tooltip styling.
// It renders the bucket's own row (so the disk chart can break its total into
// read/write, and the network chart into rx/tx) and, crucially, says "no
// coverage" for a null bucket instead of implying zero.
function ResourceTooltip({
  active,
  payload,
  label,
  color,
  line,
}: TooltipProps<ValueType, NameType> & {
  color: string;
  line: (row: Row) => string | null;
}) {
  if (!active || !payload || !payload.length) return null;
  const row = (payload[0]?.payload ?? {}) as Row;
  const text = line(row);
  return (
    <div className="rounded-2 border border-line-3 bg-bg-3/95 px-3 py-2 text-[11px] shadow-2 backdrop-blur">
      <div className="mb-1 text-fg-3">{clockFull(Number(label))}</div>
      {text ? (
        <div className="flex items-center gap-2 text-fg-1">
          <span className="h-1.5 w-1.5 rounded-full" style={{ background: color }} />
          <span>{text}</span>
        </div>
      ) : (
        <div className="text-fg-3">no coverage in this bucket</div>
      )}
      {text && (
        <div className="mt-1 border-t border-line-2 pt-1 text-fg-3">
          {row.procs} {row.procs === 1 ? "process" : "processes"}
        </div>
      )}
    </div>
  );
}

// cpuUnit labels the CPU scale honestly: values are per-core-summed, so a
// multi-threaded subtree legitimately exceeds 100% and the ceiling is the
// host's core count × 100.
function cpuUnit(m: SessionMetricsResponse): string {
  if (m.cpu_scale === "per_core_sum" && m.cpu_cores > 0) {
    return `% of one core · ${m.cpu_cores} cores`;
  }
  return "% of one core";
}

function trim(v: number): string {
  if (!Number.isFinite(v)) return "-";
  if (v >= 100) return v.toFixed(0);
  if (v >= 10) return v.toFixed(1);
  return v.toFixed(v < 1 ? 2 : 1);
}

function clock(ms: number, withSeconds: boolean): string {
  const d = new Date(ms);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    ...(withSeconds ? { second: "2-digit" } : {}),
  });
}

function clockFull(ms: number): string {
  const d = new Date(ms);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function fmtDur(ms: number): string {
  if (!Number.isFinite(ms) || ms <= 0) return "-";
  const s = Math.round(ms / 1000);
  if (s < 90) return `${s}s`;
  const m = Math.round(s / 60);
  if (m < 90) return `${m}m`;
  return `${(m / 60).toFixed(1)}h`;
}
