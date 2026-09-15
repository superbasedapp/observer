import { useEffect, useId, useMemo, useState } from "react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { getDigests, getInsights, getUsage } from "../api";
import type { DigestSummary, Insights, MixEntry } from "../api";
import { StatCard } from "@shared/primitives/StatCard";
import { ChartShell } from "@shared/primitives/ChartShell";
import { ChartTooltip } from "@shared/charts/ChartTooltip";
import { CHART_AXIS, CHART_GRID } from "@shared/charts/common";
import {
  fmtCompact,
  fmtDateRange,
  fmtDateTime,
  fmtInt,
  fmtPct,
  fmtRelative,
  fmtUSD as fmtUSDShared,
} from "@shared/lib/format";
import { JOB_STATE_LABELS, labelFor } from "../lib/labels";

// Overview v2 (divergence plan §3 W2 "Portal Overview v2"). Every card is built
// over the account-day materialization the structural rail produces, and every
// card states the window it actually covers. A card with no data says so; it
// never renders a fabricated zero, because "0 sessions" and "no window synced
// for that day" are different claims and only one of them is true.
//
// This rebuild swaps the hand-rolled `.card`/`.stat`/`.tile-*`/`.mixbar` markup
// for the shared design-system primitives (StatCard/ChartShell/Sparkline/
// recharts) so the cloud portal renders the same visual grammar as the local
// dashboard.

// fmtUSD mirrors the previous local formatter (4 decimals under $1, else the
// standard 2-decimal currency format) by picking the shared formatter's
// `precise` flag from the magnitude.
function fmtUSD(n: number): string {
  return fmtUSDShared(n, n < 1);
}

// bandShort/bandDetail split the old single bandLabel() string into a short
// headline word (for the StatCard's big value slot) plus the explanatory
// clause (for the sub line), so the coverage-band vocabulary still says what
// the band means rather than leaving a bare enum word to be over-read.
function bandShort(band: string): string {
  switch (band) {
    case "high":
      return "High";
    case "medium":
      return "Medium";
    case "low":
      return "Low";
    case "none":
      return "None";
    default:
      return band || "Unknown";
  }
}

function bandDetail(band: string): string {
  switch (band) {
    case "high":
      return "two thirds or more";
    case "medium":
      return "a third to two thirds";
    case "low":
      return "under a third";
    case "none":
      return "none";
    default:
      return "unknown";
  }
}

// shortDate renders an ISO day bucket ("2026-05-15") as "May 15", matching
// the shared CostAreaChart's tick/tooltip label convention.
function shortDate(s: string): string {
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) return s;
  return d.toLocaleDateString("en-US", { month: "short", day: "numeric" });
}

// MIX_COLORS reuses the portal's existing --mix-1..6 CSS custom properties
// (webcloud/src/styles.css) — the same categorical palette the old MixList
// used, so recoloring here is zero-drift from what shipped before.
const MIX_COLORS = [
  "var(--mix-1)",
  "var(--mix-2)",
  "var(--mix-3)",
  "var(--mix-4)",
  "var(--mix-5)",
  "var(--mix-6)",
];

// MixDonut is a small donut + legend, styled after the shared
// TopToolsDonut (shared/charts/TopToolsDonut.tsx) but generic over the
// portal's {key,count} MixEntry shape instead of tool metadata.
function MixDonut({
  entries,
  totalLabel,
}: {
  entries: MixEntry[];
  totalLabel: string;
}) {
  const id = useId();
  const top = useMemo(
    () => entries.slice().sort((a, b) => b.count - a.count).slice(0, 6),
    [entries],
  );
  const total = useMemo(() => top.reduce((a, e) => a + e.count, 0), [top]);
  const shownTotal = useMemo(
    () => entries.reduce((a, e) => a + e.count, 0),
    [entries],
  );

  if (total === 0) {
    return (
      <div className="grid h-[160px] place-items-center text-[12px] text-fg-3">
        No data yet
      </div>
    );
  }

  const data = top.map((e, i) => ({
    key: e.key,
    value: e.count,
    color: MIX_COLORS[i % MIX_COLORS.length],
  }));

  return (
    <div className="grid grid-cols-[140px_1fr] items-center gap-4">
      <div className="relative h-[140px]">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              dataKey="value"
              nameKey="key"
              innerRadius="65%"
              outerRadius="92%"
              paddingAngle={1.5}
              stroke="var(--bg-2)"
              strokeWidth={2}
              isAnimationActive={false}
            >
              {data.map((d, i) => (
                <Cell key={`${id}-${i}`} fill={d.color} />
              ))}
            </Pie>
            <Tooltip
              content={({ active, payload }) => {
                if (!active || !payload?.length) return null;
                const p = payload[0].payload as (typeof data)[number];
                return (
                  <div className="rounded-2 border border-line-3 bg-bg-3/95 px-3 py-2 text-[11px] shadow-2 backdrop-blur">
                    <div className="font-mono text-fg-1">{p.key}</div>
                    <div className="mt-0.5 text-fg-3">
                      {fmtCompact(p.value)} · {fmtPct(p.value / total)} of shown
                    </div>
                  </div>
                );
              }}
            />
          </PieChart>
        </ResponsiveContainer>
        <div className="pointer-events-none absolute inset-0 grid place-items-center">
          <div className="text-center">
            <div className="text-[16px] font-semibold leading-none tracking-tight text-fg-0">
              {fmtCompact(total)}
            </div>
            <div className="mt-1 text-[9px] uppercase tracking-[0.06em] text-fg-3">
              {totalLabel}
            </div>
          </div>
        </div>
      </div>
      <ul className="space-y-1">
        {data.map((d) => {
          const share = d.value / total;
          return (
            <li
              key={d.key}
              className="grid grid-cols-[8px_1fr_auto] items-baseline gap-2 text-[11.5px]"
            >
              <span
                className="block h-2 w-2 self-center rounded-pill"
                style={{ background: d.color }}
              />
              <span className="truncate text-fg-1">{d.key}</span>
              <span className="shrink-0 tabular-nums text-fg-3">
                {fmtCompact(d.value)} · {fmtPct(share)}
              </span>
            </li>
          );
        })}
      </ul>
      {shownTotal > total && (
        <p className="col-span-2 text-[10px] text-fg-4">
          Showing the top {data.length} of {entries.length}.
        </p>
      )}
    </div>
  );
}

// windowPill renders the small top-right capsule every StatCard in the top
// row carries, naming the window these numbers actually cover (matches
// StatCard's `cornerPill` convention — e.g. "window 30d").
function windowPill(days: number): JSX.Element {
  return (
    <span className="rounded-pill border border-line-3 bg-bg-3 px-1.5 py-0.5 text-[10px] text-fg-3">
      window {days}d
    </span>
  );
}

// formatDigestPeriod renders a digest's ISO week bounds ("YYYY-MM-DD" both
// ends) as a short human range, falling back to the raw strings rather than
// inventing a value when either end will not parse.
function formatDigestPeriod(start: string, end: string): string {
  return fmtDateRange(start, end);
}

// ProjectDigestsSection lists the latest weekly digest per project when any
// exist; otherwise, for a free account (whose plan never has digest_weekly),
// a quiet one-line locked note pointing at Billing. Rendered for every
// account (never a locked slot on the digests THEMSELVES, only the note).
function ProjectDigestsSection({
  digests,
  digestWeekly,
}: {
  digests: DigestSummary[] | null;
  digestWeekly: boolean | null;
}) {
  if (digests === null || digestWeekly === null) {
    return null; // still loading; the rest of the page does not wait on this
  }
  if (digests.length === 0) {
    if (digestWeekly) {
      return null; // Plus, just no digest has landed yet - nothing to say
    }
    return (
      <div className="rounded-3 border border-line-2 bg-bg-2 px-4 py-3 text-[12px] text-fg-2">
        Weekly project digests are part of Plus.{" "}
        <a href="/portal/billing" className="text-accent">
          See plans
        </a>
        .
      </div>
    );
  }
  return (
    <ChartShell
      title="Project digests"
      sub="One weekly rollup per project: themes, cost trend, and what to work on next."
    >
      <ul className="space-y-3">
        {digests.map((d) => (
          <li
            key={d.cloud_project_id}
            className="rounded-2 border border-line-2 bg-bg-3 p-3"
          >
            <div className="flex items-center justify-between gap-2">
              <span className="text-[12px] font-semibold text-fg-0">
                {d.headline || "Untitled digest"}
              </span>
              <span className="shrink-0 text-[10px] text-fg-3">
                {formatDigestPeriod(d.period_start, d.period_end)}
              </span>
            </div>
            {d.themes.length > 0 && (
              <div className="mt-1.5 flex flex-wrap gap-1.5">
                {d.themes.map((t) => (
                  <span
                    key={t}
                    className="rounded-pill border border-line-3 bg-bg-2 px-2 py-0.5 text-[10px] text-fg-3"
                  >
                    {t}
                  </span>
                ))}
              </div>
            )}
          </li>
        ))}
      </ul>
    </ChartShell>
  );
}

export function Overview() {
  const [data, setData] = useState<Insights | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [digests, setDigests] = useState<DigestSummary[] | null>(null);
  const [digestWeekly, setDigestWeekly] = useState<boolean | null>(null);

  useEffect(() => {
    let live = true;
    getInsights()
      .then((d) => {
        if (live) setData(d);
      })
      .catch((err: unknown) => {
        if (live)
          setError(err instanceof Error ? err.message : "failed to load");
      });
    return () => {
      live = false;
    };
  }, []);

  useEffect(() => {
    let live = true;
    // Best-effort, separate from the main structural load: a digest-fetch
    // failure degrades this one section rather than the whole page.
    getDigests()
      .then((d) => {
        if (live) setDigests(d.digests);
      })
      .catch(() => {
        if (live) setDigests([]);
      });
    getUsage()
      .then((u) => {
        if (live) setDigestWeekly(u.digest_weekly);
      })
      .catch(() => {
        if (live) setDigestWeekly(false);
      });
    return () => {
      live = false;
    };
  }, []);

  if (error) {
    return (
      <div className="rounded-3 border border-danger/30 bg-bg-2 px-4 py-3 text-[13px] text-danger">
        Could not load overview: {error}
      </div>
    );
  }
  if (!data) {
    return <div className="text-[13px] text-fg-3">Loading overview...</div>;
  }

  const s = data.summary;
  const hasStructural = s.active_days > 0;

  // The coverage line every structural card repeats. It names the real span of
  // the data, not the span of the query, so a 30-day window holding 3 days of
  // evidence reads as 3 days. The device count is window.devices — the devices
  // that synced INSIDE this window — not coverage.devices, which is
  // all-history and would credit a machine that has been offline for a year
  // (F13).
  const windowDevices = data.window.devices;
  const coverage = hasStructural
    ? `${s.active_days} day${s.active_days === 1 ? "" : "s"} with synced data, ` +
      `${fmtDateRange(s.first_day, s.last_day)}, from ` +
      `${windowDevices} device${windowDevices === 1 ? "" : "s"} in this window.`
    : "No structural windows have synced yet.";

  const enrichment = data.enrichment;
  const jobStateEntries: MixEntry[] = Object.entries(
    enrichment.jobs_by_state,
  ).map(([key, count]) => ({ key: labelFor(JOB_STATE_LABELS, key), count }));

  // Per-day series feed the top row's sparklines and the "Activity by day"
  // chart. `data.days` arrives oldest-first (the by-day list below reverses
  // it to show newest-first), which is exactly the left-to-right time order
  // both Sparkline and the recharts AreaChart want.
  const sessionsSpark = data.days.map((d) => d.session_count);
  const actionsSpark = data.days.map((d) => d.action_count);
  const costSpark = data.days.map((d) => d.cost_usd);
  const chartDays = data.days.map((d) => ({
    period: d.period,
    sessions: d.session_count,
    actions: d.action_count,
    cost: d.cost_usd,
  }));

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-[20px] font-semibold text-fg-0">Overview</h1>
        <p className="mt-1 text-[11px] text-fg-3">
          {data.structural_disclosure}
        </p>
      </div>

      {!hasStructural && (
        <div className="rounded-3 border border-line-2 bg-bg-2 px-4 py-3 text-[12px] text-fg-2">
          No structural windows have synced yet. Grant the metadata purpose
          and run a sync from a device; the first completed day appears here
          after that day ends.
        </div>
      )}

      {/* Top stat row */}
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard
          label="Active days"
          value={fmtInt(s.active_days)}
          sub={`of the last ${data.window.days} days`}
          cornerPill={windowPill(data.window.days)}
        />
        <StatCard
          label="Sessions"
          value={fmtInt(s.session_count)}
          sub={`across ${fmtInt(s.max_device_count)} device${s.max_device_count === 1 ? "" : "s"} on the busiest day`}
          spark={sessionsSpark}
          sparkColor="var(--mix-1)"
        />
        <StatCard
          label="Actions"
          value={fmtInt(s.action_count)}
          sub={coverage}
          spark={actionsSpark}
          sparkColor="var(--mix-2)"
        />
        <StatCard
          label="Estimated cost"
          value={fmtUSD(s.cost_usd)}
          sub="your provider estimate, not a SuperBased bill"
          spark={costSpark}
          sparkColor="var(--accent)"
          accent
        />
      </div>

      {/* Tokens + tool/model mix */}
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        <StatCard
          label="Tokens"
          value={fmtCompact(s.tokens_in + s.tokens_out)}
          sub="in + out, this window"
        >
          <div className="mt-2 grid grid-cols-3 gap-2 text-center">
            <div>
              <div className="text-[10px] uppercase tracking-[0.06em] text-fg-3">
                In
              </div>
              <div className="mt-0.5 text-[13px] font-semibold tabular-nums text-fg-0">
                {fmtCompact(s.tokens_in)}
              </div>
            </div>
            <div>
              <div className="text-[10px] uppercase tracking-[0.06em] text-fg-3">
                Out
              </div>
              <div className="mt-0.5 text-[13px] font-semibold tabular-nums text-fg-0">
                {fmtCompact(s.tokens_out)}
              </div>
            </div>
            <div>
              <div className="text-[10px] uppercase tracking-[0.06em] text-fg-3">
                Cache read
              </div>
              <div className="mt-0.5 text-[13px] font-semibold tabular-nums text-fg-0">
                {fmtCompact(s.cache_read_tokens)}
              </div>
            </div>
          </div>
        </StatCard>

        <ChartShell title="Cloud enrichment" sub={enrichment.disclosure}>
          {enrichment.jobs_total === 0 && enrichment.results_total === 0 ? (
            <p className="text-[12px] text-fg-3">No enrichment jobs yet.</p>
          ) : (
            <div className="grid grid-cols-1 items-start gap-6 sm:grid-cols-2">
              <MixDonut entries={jobStateEntries} totalLabel="jobs" />
              <ul className="space-y-1.5 text-[12px]">
                <li className="flex items-center justify-between border-b border-line-1 pb-1.5">
                  <span className="text-fg-3">Jobs total</span>
                  <span className="tabular-nums text-fg-0">
                    {fmtInt(enrichment.jobs_total)}
                  </span>
                </li>
                <li className="flex items-center justify-between border-b border-line-1 pb-1.5">
                  <span className="text-fg-3">Results total</span>
                  <span className="tabular-nums text-fg-0">
                    {fmtInt(enrichment.results_total)}
                  </span>
                </li>
                <li className="flex items-center justify-between">
                  <span className="text-fg-3">Last result</span>
                  <span className="text-fg-0" title={enrichment.last_result_at ?? undefined}>
                    {enrichment.last_result_at ? (
                      <>
                        {fmtDateTime(enrichment.last_result_at)}{" "}
                        <span className="text-fg-3">
                          ({fmtRelative(enrichment.last_result_at)})
                        </span>
                      </>
                    ) : (
                      "None yet"
                    )}
                  </span>
                </li>
              </ul>
            </div>
          )}
        </ChartShell>
      </div>

      {/* Activity by day */}
      <ChartShell title="Activity by day" sub={coverage}>
        {chartDays.length >= 2 ? (
          <ResponsiveContainer width="100%" height={260}>
            <AreaChart
              data={chartDays}
              margin={{ top: 8, right: 12, left: 0, bottom: 0 }}
            >
              <defs>
                <linearGradient id="ov-sessions" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="var(--mix-1)" stopOpacity="0.55" />
                  <stop offset="100%" stopColor="var(--mix-1)" stopOpacity="0" />
                </linearGradient>
                <linearGradient id="ov-actions" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="var(--mix-2)" stopOpacity="0.4" />
                  <stop offset="100%" stopColor="var(--mix-2)" stopOpacity="0" />
                </linearGradient>
                <linearGradient id="ov-cost" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="var(--accent)" stopOpacity="0.35" />
                  <stop offset="100%" stopColor="var(--accent)" stopOpacity="0" />
                </linearGradient>
              </defs>
              <CartesianGrid {...CHART_GRID} />
              <XAxis dataKey="period" {...CHART_AXIS} tickFormatter={shortDate} />
              <YAxis yAxisId="count" {...CHART_AXIS} tickFormatter={fmtCompact} />
              <YAxis
                yAxisId="cost"
                orientation="right"
                {...CHART_AXIS}
                tickFormatter={(v: number | string) => fmtUSD(Number(v))}
              />
              <Tooltip
                content={
                  <ChartTooltip
                    labelKey="period"
                    labelFormatter={shortDate}
                    formatItem={(name, value) =>
                      name === "Cost $"
                        ? `${name}: ${fmtUSD(value)}`
                        : `${name}: ${fmtCompact(value)}`
                    }
                  />
                }
                cursor={{ stroke: "var(--line-3)" }}
              />
              <Area
                yAxisId="count"
                type="monotone"
                dataKey="sessions"
                name="Sessions"
                stroke="var(--mix-1)"
                fill="url(#ov-sessions)"
                strokeWidth={1.6}
              />
              <Area
                yAxisId="count"
                type="monotone"
                dataKey="actions"
                name="Actions"
                stroke="var(--mix-2)"
                fill="url(#ov-actions)"
                strokeWidth={1.4}
              />
              <Area
                yAxisId="cost"
                type="monotone"
                dataKey="cost"
                name="Cost $"
                stroke="var(--accent)"
                fill="url(#ov-cost)"
                strokeWidth={1.4}
              />
            </AreaChart>
          </ResponsiveContainer>
        ) : (
          <div className="grid h-[220px] place-items-center text-[12px] text-fg-3">
            Not enough synced days yet to chart a trend.
          </div>
        )}
      </ChartShell>

      {/* Tool + model family mix */}
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        <ChartShell title="Tool mix" sub={coverage}>
          <MixDonut entries={s.tool_mix} totalLabel="actions" />
        </ChartShell>
        <ChartShell title="Model family mix" sub={coverage}>
          <MixDonut entries={s.model_family_mix} totalLabel="actions" />
        </ChartShell>
      </div>

      {/* Project digests (W5) */}
      <ProjectDigestsSection digests={digests} digestWeekly={digestWeekly} />

      {/* Evidence coverage */}
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <StatCard
          label="Verification coverage"
          value={bandShort(s.verification_coverage_band)}
          sub={`${bandDetail(s.verification_coverage_band)} · ${fmtInt(s.sessions_with_verification)} of ${fmtInt(s.session_count)} sessions`}
        />
        <StatCard
          label="Outcome evidence"
          value={bandShort(s.outcome_evidence_band)}
          sub={`${bandDetail(s.outcome_evidence_band)} · ${fmtInt(s.sessions_with_outcomes)} of ${fmtInt(s.session_count)} sessions`}
        />
      </div>
      <p className="text-[11px] text-fg-3">
        A low band means these aggregates are thinly evidenced, not that the
        work was bad.
      </p>
    </div>
  );
}
