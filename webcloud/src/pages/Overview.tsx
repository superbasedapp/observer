import { useEffect, useMemo, useState } from "react";
import { Link, useLocation, useNavigate, useSearchParams } from "react-router-dom";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { getDigests, getInsights, getUsage } from "../api";
import type { DigestSummary } from "../api";
import { StatCard } from "@shared/primitives/StatCard";
import { HeroStat } from "@shared/primitives/HeroStat";
import {
  SegmentedControl,
  type Segment,
} from "@shared/primitives/SegmentedControl";
import { Stagger, UpdatingBadge } from "@shared/primitives/Motion";
import { chartMotion } from "@shared/lib/motion";
import { usePortalQuery } from "../lib/query";
import { DashboardSkeleton, ErrorPanel } from "../components/LoadState";
import { ChartShell } from "@shared/primitives/ChartShell";
import { ChartTooltip } from "@shared/charts/ChartTooltip";
import { CHART_AXIS, CHART_GRID } from "@shared/charts/common";
import {
  fmtCompact,
  fmtDateRange,
  fmtDateTime,
  fmtInt,
  fmtRelative,
  fmtUSD as fmtUSDShared,
} from "@shared/lib/format";
import {
  bucketLabelFormatter,
  bucketTickFormatter,
  perBucketTitle,
} from "@shared/lib/granularity";
import {
  Activity,
  FolderGit2,
  Sparkles,
  Wrench,
  type LucideIcon,
} from "lucide-react";
import { PageHeader } from "@shared/primitives/PageHeader";
import { MetricIcon } from "@shared/primitives/MetricIcon";
import { metricIcon } from "@shared/lib/metricIcons";
import { PortalMetricIcon } from "../lib/metricIcons";
import { routeIcon } from "../lib/nav";
import { EmptyState } from "@shared/primitives/EmptyState";
import { LiveDot } from "@shared/primitives/LiveDot";
import { SuccessCheck } from "@shared/primitives/SuccessCheck";
import { jobsInFlight } from "../lib/vocab";
import { Pill } from "@shared/primitives/Pill";
import { RawIdHint } from "../components/RawIdHint";
import {
  MixDonut,
  jobMixSlices,
  modelFamilySlices,
  toolMixSlices,
} from "../components/MixDonut";

// SECTION_ICONS: one glyph per Overview section title (ChartShell headers).
// The model-family mix reuses the shared "top model" metric glyph (Bot) via
// MetricIcon's table so the two never drift.
// The portal's activity series is daily by construction (one row per
// account-day), so its bucket formatter is bound once at "1d".
const DAY_TICK = bucketTickFormatter("1d");
const DAY_LABEL = bucketLabelFormatter("1d");

const SECTION_ICONS = {
  activity: Activity,
  enrichment: Sparkles,
  toolMix: Wrench,
  digests: FolderGit2,
} as const satisfies Record<string, LucideIcon>;

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
const COVERAGE_BAND: Readonly<Record<string, { short: string; detail: string }>> = {
  high: { short: "High", detail: "two thirds or more" },
  medium: { short: "Medium", detail: "a third to two thirds" },
  low: { short: "Low", detail: "under a third" },
  none: { short: "None", detail: "none" },
};

// An unknown band keeps its raw word (or "Unknown") and an "unknown" clause.
function bandShort(band: string): string {
  return COVERAGE_BAND[band]?.short ?? (band || "Unknown");
}

function bandDetail(band: string): string {
  return COVERAGE_BAND[band]?.detail ?? "unknown";
}

// windowPill renders the small top-right capsule every StatCard in the top
// row carries, naming the window these numbers actually cover (matches
// StatCard's `cornerPill` convention — e.g. "window 30d").
function windowPill(days: number): JSX.Element {
  return <Pill variant="neutral">window {days}d</Pill>;
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
        <Link to="/billing" className="text-accent">
          See plans
        </Link>
        .
      </div>
    );
  }
  return (
    <ChartShell
      title="Project digests"
      icon={SECTION_ICONS.digests}
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
                {/* A theme is a free-text phrase from the digest, so it keeps
                    its own casing (case="none") on the shared neutral Pill. */}
                {d.themes.map((t) => (
                  <Pill key={t} variant="neutral" case="none">
                    {t}
                  </Pill>
                ))}
              </div>
            )}
          </li>
        ))}
      </ul>
    </ChartShell>
  );
}

// Window presets for the Overview. The chosen window lives in the URL
// (?days=, shareable) and is remembered per browser (a convenience only:
// storage can be unavailable, so every access is wrapped).
const WINDOW_OPTIONS: Segment<"7" | "30" | "90">[] = [
  { value: "7", label: "7d" },
  { value: "30", label: "30d" },
  { value: "90", label: "90d" },
];
const DAYS_STORAGE_KEY = "sbci.overview.days";

function parseDays(v: string | null | undefined): 7 | 30 | 90 | null {
  return v === "7" ? 7 : v === "30" ? 30 : v === "90" ? 90 : null;
}

function storedDays(): 7 | 30 | 90 | null {
  try {
    return parseDays(localStorage.getItem(DAYS_STORAGE_KEY));
  } catch {
    return null;
  }
}

type ActivitySeries = "sessions" | "actions" | "cost";
const ACTIVITY_SERIES: Segment<ActivitySeries>[] = [
  { value: "sessions", label: "Sessions" },
  { value: "actions", label: "Actions" },
  { value: "cost", label: "Cost" },
];
const SERIES_META: Record<
  ActivitySeries,
  { name: string; color: string; fmt: (n: number) => string }
> = {
  sessions: { name: "Sessions", color: "var(--info)", fmt: fmtCompact },
  actions: { name: "Actions", color: "var(--success)", fmt: fmtCompact },
  cost: { name: "Cost $", color: "var(--accent)", fmt: fmtUSD },
};

export function Overview() {
  const [params, setParams] = useSearchParams();
  const days = parseDays(params.get("days")) ?? storedDays() ?? 30;
  const setDays = (d: 7 | 30 | 90) => {
    try {
      localStorage.setItem(DAYS_STORAGE_KEY, String(d));
    } catch {
      // Storage unavailable: the URL still carries the choice.
    }
    const next = new URLSearchParams(params);
    next.set("days", String(d));
    setParams(next, { replace: true });
  };
  const [series, setSeries] = useState<ActivitySeries>("sessions");

  // One-shot confirmation from the consent setup screen, which lands here
  // with { consentSaved: true } in the history state. It is read once, then
  // dropped from the history entry so a reload does not repeat it.
  const location = useLocation();
  const navigate = useNavigate();
  const [consentSaved] = useState(
    () => (location.state as { consentSaved?: boolean } | null)?.consentSaved === true,
  );
  useEffect(() => {
    if ((location.state as { consentSaved?: boolean } | null)?.consentSaved) {
      navigate({ pathname: location.pathname, search: location.search }, { replace: true, state: null });
    }
  }, [location, navigate]);

  // One cached query per window; a window change keeps the previous numbers
  // on screen (dimmed) until the new ones land.
  const insights = usePortalQuery(
    `insights:${days}`,
    () => getInsights(days),
    [],
    { keepPrevious: true },
  );
  // Best-effort side reads: a failure degrades only the digests section.
  // "usage" is the SAME key the Usage page reads, so the two share one GET.
  const digestsQ = usePortalQuery("digests", getDigests);
  const usageQ = usePortalQuery("usage", getUsage);
  const digests = digestsQ.data?.digests ?? (digestsQ.error ? [] : null);
  const digestWeekly = usageQ.data
    ? usageQ.data.digest_weekly
    : usageQ.error
      ? false
      : null;

  // The activity chart's rows, memoized on the response (and computed before
  // the early returns below, as a hook must be): a re-render for any other
  // reason (the digests / usage reads landing) hands recharts the SAME array,
  // so it neither re-runs its layout nor replays the series animation.
  // Rows use the ISO day as "period"; the axis labels it through the ONE
  // shared bucket formatter (shared/lib/granularity.ts fmtBucket at "1d"),
  // the same convention every app's time-series charts use. The portal's
  // substrate (structural_account_days) is one row per account-day, so it
  // stays daily: there is no sub-day window here, by design.
  const chartDays = useMemo(
    () =>
      (insights.data?.days ?? []).map((d) => ({
        period: d.period,
        sessions: d.session_count,
        actions: d.action_count,
        cost: d.cost_usd,
      })),
    [insights.data],
  );

  const data = insights.data;
  if (insights.error && !data) {
    return (
      <ErrorPanel variant="page" what="overview" error={insights.error} onRetry={insights.reload} />
    );
  }
  if (!data) {
    return <DashboardSkeleton />;
  }
  const stale = insights.isStale;

  const s = data.summary;
  const hasStructural = s.active_days > 0;

  // The coverage line names the real span of the data, not the span of the
  // query, so a 30-day window holding 3 days of evidence reads as 3 days.
  // It is stated ONCE, under the page title, instead of under every card.
  // The device count is window.devices - the devices that synced INSIDE this
  // window - not coverage.devices, which is all-history and would credit a
  // machine that has been offline for a year (F13).
  const windowDevices = data.window.devices;
  const coverage = hasStructural
    ? `${s.active_days} day${s.active_days === 1 ? "" : "s"} with synced data, ` +
      `${fmtDateRange(s.first_day, s.last_day)}, from ` +
      `${windowDevices} device${windowDevices === 1 ? "" : "s"} in this window.`
    : "No structural windows have synced yet.";

  const enrichment = data.enrichment;
  const jobSlices = jobMixSlices(enrichment.jobs_by_state);
  const inFlight = jobsInFlight(enrichment.jobs_by_state);

  // `data.days` arrives oldest-first, which is the left-to-right time order
  // both Sparkline and the recharts AreaChart want.
  const sessionsSpark = data.days.map((d) => d.session_count);
  const actionsSpark = data.days.map((d) => d.action_count);
  const costSpark = data.days.map((d) => d.cost_usd);
  const meta = SERIES_META[series];

  return (
    <Stagger className="flex flex-col gap-6">
      <PageHeader
        title="Overview"
        icon={routeIcon("/overview")}
        sub={
          <>
            {coverage}
            <span className="mt-0.5 block text-[11px]">
              {data.structural_disclosure}
            </span>
          </>
        }
        right={
          <div className="flex items-center gap-2">
            <UpdatingBadge show={stale} />
            <SegmentedControl
              options={WINDOW_OPTIONS}
              value={String(days) as "7" | "30" | "90"}
              onChange={(v) => setDays(parseDays(v) ?? 30)}
            />
          </div>
        }
      />

      {consentSaved && <SuccessCheck label="Your sharing choices are saved" />}

      {!hasStructural && (
        <EmptyState
          illustration="enrich"
          illustrationSize={140}
          title="No structural windows have synced yet"
          steps={[
            "Grant the metadata purpose.",
            "Run a sync from a device.",
            "The first completed day appears here after that day ends.",
          ]}
        />
      )}

      {/* Top stat row: the lead (spend) tile carries the aurora accent. */}
      <Stagger className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <HeroStat
          label="Estimated cost"
          icon={<MetricIcon metric="spend" />}
          value={fmtUSD(s.cost_usd)}
          sub="your provider estimate, not a SuperBased bill"
          spark={costSpark}
          aurora
          stale={stale}
          cornerPill={windowPill(data.window.days)}
        />
        <StatCard
          label="Active days"
          icon={<PortalMetricIcon metric="activeDays" />}
          value={fmtInt(s.active_days)}
          sub={`of the last ${data.window.days} days`}
          stale={stale}
        />
        <StatCard
          label="Sessions"
          icon={<MetricIcon metric="sessions" />}
          value={fmtInt(s.session_count)}
          sub={`across ${fmtInt(s.max_device_count)} device${s.max_device_count === 1 ? "" : "s"} on the busiest day`}
          spark={sessionsSpark}
          sparkColor={SERIES_META.sessions.color}
          stale={stale}
        />
        <StatCard
          label="Actions"
          icon={<MetricIcon metric="actions" />}
          value={fmtInt(s.action_count)}
          sub="tool calls recorded across those sessions"
          spark={actionsSpark}
          sparkColor={SERIES_META.actions.color}
          stale={stale}
        />
      </Stagger>

      {/* Activity by day: one series at a time, each on its own scale, so
          sessions are no longer flattened under the much larger action
          counts on a shared axis. */}
      <ChartShell
        title={perBucketTitle("Activity", "1d")}
        icon={SECTION_ICONS.activity}
        sub="Per synced day in this window · daily data only."
        stale={stale}
        right={
          <SegmentedControl
            size="sm"
            options={ACTIVITY_SERIES}
            value={series}
            onChange={setSeries}
          />
        }
      >
        {chartDays.length >= 2 ? (
          <ResponsiveContainer width="100%" height={260}>
            <AreaChart
              data={chartDays}
              margin={{ top: 8, right: 12, left: 0, bottom: 0 }}
            >
              <defs>
                <linearGradient id="ov-series" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={meta.color} stopOpacity="0.45" />
                  <stop offset="100%" stopColor={meta.color} stopOpacity="0" />
                </linearGradient>
              </defs>
              <CartesianGrid {...CHART_GRID} />
              <XAxis dataKey="period" {...CHART_AXIS} tickFormatter={DAY_TICK} />
              <YAxis
                {...CHART_AXIS}
                tickFormatter={(v: number | string) => meta.fmt(Number(v))}
              />
              <Tooltip
                content={
                  <ChartTooltip
                    labelKey="period"
                    labelFormatter={DAY_LABEL}
                    formatItem={(name, value) => `${name}: ${meta.fmt(value)}`}
                  />
                }
                cursor={{ stroke: "var(--line-3)" }}
              />
              <Area
                {...chartMotion()}
                key={series}
                type="monotone"
                dataKey={series}
                name={meta.name}
                stroke={meta.color}
                fill="url(#ov-series)"
                strokeWidth={1.6}
              />
            </AreaChart>
          </ResponsiveContainer>
        ) : (
          <div className="grid min-h-[220px] place-items-center">
            <EmptyState
              variant="inline"
              illustration="chart"
              illustrationSize={112}
              title="Not enough synced days yet to chart a trend"
            />
          </div>
        )}
      </ChartShell>

      {/* Tokens + enrichment */}
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        <StatCard
          label="Tokens"
          icon={<MetricIcon metric="tokens" />}
          value={fmtCompact(s.tokens_in + s.tokens_out)}
          sub="in + out, this window"
          stale={stale}
        >
          <div className="mt-2 grid grid-cols-3 gap-2 text-center">
            {(
              [
                ["In", s.tokens_in],
                ["Out", s.tokens_out],
                ["Cache read", s.cache_read_tokens],
              ] as const
            ).map(([label, n]) => (
              <div key={label}>
                <div className="text-[10px] uppercase tracking-[0.06em] text-fg-3">
                  {label}
                </div>
                <div className="mt-0.5 text-[13px] font-semibold tabular-nums text-fg-0">
                  {fmtCompact(n)}
                </div>
              </div>
            ))}
          </div>
        </StatCard>

        <ChartShell
          title="Cloud enrichment"
          icon={SECTION_ICONS.enrichment}
          sub={enrichment.disclosure} stale={stale}>
          {enrichment.jobs_total === 0 && enrichment.results_total === 0 ? (
            <EmptyState
              variant="inline"
              illustration="enrich"
              illustrationSize={96}
              title="No enrichment jobs yet"
            />
          ) : (
            <div className="grid grid-cols-1 items-start gap-5 2xl:grid-cols-2">
              <MixDonut slices={jobSlices} totalLabel="jobs" />
              <ul className="space-y-1.5 text-[12px]">
                <li className="flex items-center justify-between border-b border-line-1 pb-1.5">
                  <span className="text-fg-3">Jobs total</span>
                  <span className="inline-flex items-center gap-2 tabular-nums text-fg-0">
                    {inFlight > 0 && (
                      <span className="inline-flex items-center gap-1.5 text-[11px] text-fg-3">
                        <LiveDot tone="accent" />
                        {fmtInt(inFlight)} in progress
                      </span>
                    )}
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
                  {enrichment.last_result_at ? (
                    <RawIdHint id={enrichment.last_result_at} className="text-fg-0">
                      {fmtDateTime(enrichment.last_result_at)}{" "}
                      <span className="text-fg-3">
                        ({fmtRelative(enrichment.last_result_at)})
                      </span>
                    </RawIdHint>
                  ) : (
                    <span className="text-fg-0">None yet</span>
                  )}
                </li>
              </ul>
            </div>
          )}
        </ChartShell>
      </div>

      {/* Tool + model family mix */}
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        <ChartShell
          title="Tool mix"
          icon={SECTION_ICONS.toolMix}
          sub="Share of actions by tool."
          stale={stale}
        >
          <MixDonut slices={toolMixSlices(s.tool_mix)} totalLabel="actions" />
        </ChartShell>
        <ChartShell
          title="Model family mix"
          icon={metricIcon("topModel")}
          sub="Share of actions by model family."
          stale={stale}
        >
          <MixDonut slices={modelFamilySlices(s.model_family_mix)} totalLabel="actions" />
        </ChartShell>
      </div>

      {/* Project digests (W5) */}
      <ProjectDigestsSection digests={digests} digestWeekly={digestWeekly} />

      {/* Evidence coverage */}
      <div className="flex flex-col gap-2">
        <Stagger className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <StatCard
            label="Verification coverage"
            icon={<PortalMetricIcon metric="verificationCoverage" />}
            value={bandShort(s.verification_coverage_band)}
            sub={`${bandDetail(s.verification_coverage_band)} · ${fmtInt(s.sessions_with_verification)} of ${fmtInt(s.session_count)} sessions`}
            stale={stale}
          />
          <StatCard
            label="Outcome evidence"
            icon={<PortalMetricIcon metric="outcomeEvidence" />}
            value={bandShort(s.outcome_evidence_band)}
            sub={`${bandDetail(s.outcome_evidence_band)} · ${fmtInt(s.sessions_with_outcomes)} of ${fmtInt(s.session_count)} sessions`}
            stale={stale}
          />
        </Stagger>
        <p className="text-[11px] text-fg-3">
          A low band means these aggregates are thinly evidenced, not that the
          work was bad.
        </p>
      </div>
    </Stagger>
  );
}
