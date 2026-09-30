import { hasNonZero } from "@shared/lib/seriesEmpty";
import { useMemo, useState, type ReactNode } from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { Link } from "react-router-dom";
import {
  ChartShell,
  ModelId,
  PageHeader,
  Pill,
  SegmentedControl,
  Skeleton,
  StatCard,
  ToolBadge,
  Tooltip,
  SectionNav,
  type SectionNavItem,
  Stagger,
} from "@/components/primitives";
import { HelpInd, TitleWithHelp } from "@/components/HelpInd";
import { CopyOnClick } from "@/components/CopyOnClick";
import {
  CacheSavingsChart,
  DowHourHeatmap,
  TrendByKeyChart,
} from "@/components/charts";
import { ChartState } from "@/components/ChartState";
import { DataTable } from "@/components/DataTable";
import { useFilters, useGranularity, windowDaysApprox, windowParams } from "@/lib/filters";
import { GranControl } from "@/components/GranControl";
import { asGranularity, perBucketTitle, viewerTimeZone } from "@shared/lib/granularity";
import { useApi } from "@/lib/useApi";
import { fmtBytes, fmtCompact, fmtInt, fmtPct, fmtTaskUSD, fmtUSD } from "@/lib/format";
import type {
  AnalysisCacheSavingsTrend,
  AnalysisCostByDowHour,
  AnalysisDim,
  AnalysisHeadline,
  AnalysisMovers,
  AnalysisRoutingSuggestions,
  AnalysisTopSessions,
  AnalysisTrend,
  Entrant,
  Mover,
  StatusScoped,
  StatusSnapshot,
  TaskCostBucket,
  TaskRollup,
  VerbosityAggregateResponse,
} from "@/lib/types";
import { navIcon } from "@/lib/nav";
import { MetricIcon } from "@/components/MetricIcon";
import {
  ArrowUpDown,
  BadgePlus,
  ChartBarStacked,
  ChartColumnStacked,
  ChartLine,
  Clock,
  ListOrdered,
  ListTodo,
  Split,
  type LucideIcon,
} from "lucide-react";

// One glyph per analysis section card title (the ChartShell `icon` slot): the
// chart or table shape the section shows, never decoration.
const SECTION_ICONS = {
  dailySpend: ChartColumnStacked,
  whenYouSpend: Clock,
  cacheSavingsTrend: ChartLine,
  topMovers: ArrowUpDown,
  newThisPeriod: BadgePlus,
  topSessions: ListOrdered,
  routingEfficiency: Split,
  outputComposition: ChartBarStacked,
  tasks: ListTodo,
} satisfies Record<string, LucideIcon>;

// VerbDim is the Output-composition rollup dimension (no "tool" facet — the
// aggregate keys on model/project/day).
type VerbDim = "model" | "project" | "day";


const ANALYSIS_SECTIONS: SectionNavItem[] = [
  { id: "an-headline", label: "Headline" },
  { id: "an-trend", label: "Spend trend" },
  { id: "an-when", label: "When and cache" },
  { id: "an-changed", label: "What changed" },
  { id: "an-sessions", label: "Top sessions" },
  { id: "an-routing", label: "Routing" },
  { id: "an-output", label: "Output" },
  { id: "an-tasks", label: "Tasks" },
];

export function AnalysisPage() {
  const { win, customRange, tool, project } = useFilters();
  const winParams = windowParams(win, customRange);
  const projectParam = project === "all" ? undefined : project;
  const toolParam = tool === "all" ? undefined : tool;

  const [dim, setDim] = useState<AnalysisDim>("model");
  const [vbDim, setVbDim] = useState<VerbDim>("model");

  const head = useApi<AnalysisHeadline>(
    "/api/analysis/headline",
    { ...winParams, tool: toolParam, project: projectParam },
    [win, customRange, tool, project],
  );
  // Only the all-time project count is read from /api/status. The payload
  // changes on every 5 s TopBar/Sidebar poll (uptime is stamped per request),
  // so select the one field: the page, and its ~10 charts, re-render only
  // when the count itself changes.
  const projectsAllTime = useApi<StatusSnapshot, number>("/api/status", undefined, [], {
    select: selectProjectCount,
  });
  const scoped = useApi<StatusScoped>(
    "/api/status/scoped",
    { ...winParams, tool: toolParam, project: projectParam },
    [win, customRange, tool, project],
  );
  // Chart bucket: the shared granularity rule + the viewer's `gran=`.
  const gran = useGranularity();
  const trend = useApi<AnalysisTrend>(
    "/api/analysis/trend",
    { ...winParams, ...gran.params, dim, tool: toolParam, project: projectParam },
    [win, customRange, dim, tool, project, gran.params],
  );
  // The day-of-week x hour heatmap stays cyclic by design; it honours the
  // global window and buckets in the viewer's zone.
  const hours = useApi<AnalysisCostByDowHour>(
    "/api/analysis/cost-by-dow-hour",
    { ...winParams, tz: viewerTimeZone(), tool: toolParam, project: projectParam },
    [win, customRange, tool, project],
  );
  const savings = useApi<AnalysisCacheSavingsTrend>(
    "/api/analysis/cache-savings-trend",
    { ...winParams, ...gran.params, tool: toolParam, project: projectParam },
    [win, customRange, tool, project, gran.params],
  );
  const trendGran = asGranularity(trend.data?.bucket ?? gran.expected);
  const savingsGran = asGranularity(savings.data?.bucket ?? gran.expected);
  const movers = useApi<AnalysisMovers>(
    "/api/analysis/movers",
    { ...winParams, dim, tool: toolParam, project: projectParam },
    [win, customRange, dim, tool, project],
  );
  const topSessions = useApi<AnalysisTopSessions>(
    "/api/analysis/top-sessions",
    { ...winParams, limit: 12, tool: toolParam, project: projectParam },
    [win, customRange, tool, project],
  );
  const routing = useApi<AnalysisRoutingSuggestions>(
    "/api/analysis/routing-suggestions",
    { ...winParams, limit: 8, tool: toolParam, project: projectParam },
    [win, customRange, tool, project],
  );
  // /api/verbosity/aggregate takes a day-grained `since_days` (not
  // the standard days/hours/since window shape), so it uses the
  // rounded-up day count for sub-day / custom windows.
  const verbosity = useApi<VerbosityAggregateResponse>(
    "/api/verbosity/aggregate",
    { by: vbDim, since_days: windowDaysApprox(win, customRange) },
    [win, customRange, vbDim],
  );
  // /api/tasks (docs/task-tracking.md) takes the same days/hours/since/until
  // window shape as every other analysis endpoint here, plus the same
  // `project`/`tool` string-keyed filters (project's root_path / a
  // session's tool) analysisScopeClause already applies elsewhere on
  // this page — NOT the numeric `project_id` the endpoint also accepts
  // for API compatibility, which nothing in the frontend resolves to.
  const taskRollup = useApi<TaskRollup>(
    "/api/tasks",
    { ...winParams, tool: toolParam, project: projectParam },
    [win, customRange, tool, project],
  );

  return (
    <div className="space-y-6 p-4 sm:p-6">
      <PageHeader
        icon={navIcon("analysis")}
        title="Analysis"
        sub="Spending insights for the selected window. Headline KPIs comparing this period to the prior period, daily trend with a dimension toggle, top movers, and cost-sensitive signals - $/M output, cache savings, high-context turns, per-turn variance, burn rate, top-model concentration, and routing efficiency suggestions."
        helpId="tab.analysis"
      />
      {/* The page grew into one long column: a sticky chip row jumps to each
          section and tracks the one in view. */}
      <SectionNav items={ANALYSIS_SECTIONS} />
      <span id="an-headline" aria-hidden className="-mb-6 block scroll-mt-14" />
      <HeadlineGrid
        data={head.data}
        projectsAllTime={projectsAllTime.data}
        scoped={scoped.data}
        trend={trend.data}
        savings={savings.data}
        win={win}
        loading={head.loading}
      />

      {/* Spend per bucket by dim */}
      <span id="an-trend" aria-hidden className="-mb-6 block scroll-mt-14" />
      <ChartShell
        title={<TitleWithHelp text={perBucketTitle("Spend", trendGran)} helpId="chart.analysis_trend" />}
        icon={SECTION_ICONS.dailySpend}
        sub={`${perBucketTitle("Cost", trendGran)}, stacked by ${dim} · ${win}`}
        right={
          <div className="flex flex-wrap items-center gap-2">
            <GranControl served={trend.data} />
            <SegmentedControl<AnalysisDim>
              options={[
                { value: "model", label: "Model" },
                { value: "project", label: "Project" },
                { value: "tool", label: "Tool" },
              ]}
              value={dim}
              onChange={setDim}
            />
          </div>
        }
      >
        <ChartState
          loading={trend.loading}
          stale={trend.isStale}
          onRetry={trend.reload}
          error={trend.error}
          denied={trend.denied}
          deniedPermission={trend.deniedPermission}
          empty={!trend.data?.series?.length}
          emptyHint="No spend data in this window."
          height={280}
        >
          {trend.data && (
            <TrendByKeyChart
              data={trend.data.series}
              grid={trend.data.grid}
              granularity={trendGran}
              colorMode={dim}
              topN={6}
            />
          )}
        </ChartState>
      </ChartShell>

      {/* Hourly heatmap + cache savings trend side by side */}
      <span id="an-when" aria-hidden className="-mb-6 block scroll-mt-14" />
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <ChartShell
          title={<TitleWithHelp text="When you spend" helpId="chart.analysis_cost_by_hour" />}
          icon={SECTION_ICONS.whenYouSpend}
          sub={`Cost by hour of day × day of week · ${hours.data?.timezone ?? "UTC"} · ${win}`}
        >
          <ChartState
            loading={hours.loading}
            stale={hours.isStale}
            onRetry={hours.reload}
            error={hours.error}
            denied={hours.denied}
            deniedPermission={hours.deniedPermission}
            empty={!hours.data?.cells.some((c) => c.cost_usd > 0)}
            emptyHint="No hourly spend in window."
            height={200}
          >
            {hours.data && (
              <DowHourHeatmap
                cells={hours.data.cells}
                timezone={hours.data.timezone}
              />
            )}
          </ChartState>
        </ChartShell>

        <ChartShell
          title={<TitleWithHelp text="Cache savings trend" helpId="chart.analysis_cache_savings_trend" />}
          icon={SECTION_ICONS.cacheSavingsTrend}
          sub={`${perBucketTitle("Saved", savingsGran)} · counterfactual: cache_read priced at input rate vs cache_read rate`}
          right={<GranControl served={savings.data} />}
        >
          <ChartState
            loading={savings.loading}
            stale={savings.isStale}
            onRetry={savings.reload}
            error={savings.error}
            denied={savings.denied}
            deniedPermission={savings.deniedPermission}
            empty={!hasNonZero(savings.data?.points, ["cache_read_tokens"])}
            emptyHint="No cache-read traffic in window."
            height={200}
          >
            {savings.data && (
              <CacheSavingsChart data={savings.data.points} granularity={savingsGran} />
            )}
          </ChartState>
        </ChartShell>
      </div>

      {/* What changed */}
      <span id="an-changed" aria-hidden className="-mb-6 block scroll-mt-14" />
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <ChartShell
          title={<TitleWithHelp text="Top movers" helpId="chart.analysis_movers" />}
          icon={SECTION_ICONS.topMovers}
          sub={`Δ$ vs prior ${win} · grouped by ${dim}`}
        >
          <ChartState
            loading={movers.loading}
            stale={movers.isStale}
            onRetry={movers.reload}
            error={movers.error}
            denied={movers.denied}
            deniedPermission={movers.deniedPermission}
            empty={
              !(movers.data?.increases ?? []).length &&
              !(movers.data?.decreases ?? []).length
            }
            emptyHint="No period-over-period change."
            height={220}
          >
            {movers.data && <MoversList movers={movers.data} />}
          </ChartState>
        </ChartShell>

        <ChartShell
          title={<TitleWithHelp text="New this period" helpId="chart.analysis_new_entrants" />}
          icon={SECTION_ICONS.newThisPeriod}
          sub={`Keys that appeared in this ${win} but not the prior`}
        >
          <ChartState
            loading={movers.loading}
            stale={movers.isStale}
            onRetry={movers.reload}
            error={movers.error}
            denied={movers.denied}
            deniedPermission={movers.deniedPermission}
            empty={!(movers.data?.new_entrants ?? []).length}
            emptyHint="No new entrants."
            height={220}
          >
            {movers.data && (
              <EntrantsList
                entrants={movers.data.new_entrants ?? []}
                dim={movers.data.dim}
              />
            )}
          </ChartState>
        </ChartShell>
      </div>

      {/* Top expensive sessions */}
      <span id="an-sessions" aria-hidden className="-mb-6 block scroll-mt-14" />
      <ChartShell
        title={<TitleWithHelp text="Top expensive sessions" helpId="chart.analysis_top_sessions" />}
        icon={SECTION_ICONS.topSessions}
        sub={`Ranked by cost · ${win} · click to drill into session`}
        right={
          <Link
            to="/sessions"
            className="text-[11px] font-medium text-accent hover:text-accent-strong"
          >
            All sessions →
          </Link>
        }
      >
        <ChartState
          loading={topSessions.loading}
          stale={topSessions.isStale}
          onRetry={topSessions.reload}
          error={topSessions.error}
          denied={topSessions.denied}
          deniedPermission={topSessions.deniedPermission}
          empty={!topSessions.data?.sessions?.length}
          emptyHint="No spend in window."
          height={240}
        >
          {topSessions.data && (
            <TopSessionsTable rows={topSessions.data.sessions} />
          )}
        </ChartState>
      </ChartShell>

      {/* Routing efficiency suggestions */}
      <span id="an-routing" aria-hidden className="-mb-6 block scroll-mt-14" />
      <ChartShell
        title={<TitleWithHelp text="Routing efficiency" helpId="chart.analysis_routing" />}
        icon={SECTION_ICONS.routingEfficiency}
        sub={
          routing.data?.framing_note ||
          "Informational only - model choice may be deliberate"
        }
        right={
          routing.data ? (
            <span className="text-[11px] text-fg-3">
              potential savings:{" "}
              <strong className="text-success">
                {fmtUSD(routing.data.total_savings_usd)}
              </strong>
            </span>
          ) : null
        }
      >
        <ChartState
          loading={routing.loading}
          stale={routing.isStale}
          onRetry={routing.reload}
          error={routing.error}
          denied={routing.denied}
          deniedPermission={routing.deniedPermission}
          empty={!routing.data?.suggestions?.length}
          emptyHint="No routing opportunities detected."
          height={200}
        >
          {routing.data && (
            <RoutingList suggestions={routing.data.suggestions} />
          )}
        </ChartState>
      </ChartShell>

      {/* Output composition — code vs explanation across the window */}
      <span id="an-output" aria-hidden className="-mb-6 block scroll-mt-14" />
      <ChartShell
        title={<TitleWithHelp text="Output composition" helpId="chart.analysis_verbosity" />}
        icon={SECTION_ICONS.outputComposition}
        sub={`Code (writes + commands + code blocks) vs explanation by ${vbDim} · bytes exact, $ estimated · ${win}`}
        right={
          <SegmentedControl<VerbDim>
            options={[
              { value: "model", label: "Model" },
              { value: "project", label: "Project" },
              { value: "day", label: "Day" },
            ]}
            value={vbDim}
            onChange={setVbDim}
          />
        }
      >
        <ChartState
          loading={verbosity.loading}
          stale={verbosity.isStale}
          onRetry={verbosity.reload}
          error={verbosity.error}
          denied={verbosity.denied}
          deniedPermission={verbosity.deniedPermission}
          empty={!verbosity.data?.groups?.length}
          emptyHint="No assistant output captured in window."
          height={240}
        >
          {verbosity.data && (
            <VerbosityAggregateTable
              groups={verbosity.data.groups}
              dim={vbDim}
              keyDim={verbosity.data.by}
            />
          )}
        </ChartState>
      </ChartShell>

      <span id="an-tasks" aria-hidden className="-mb-6 block scroll-mt-14" />
      {/* Task tracking — session-level todo/plan checklist rollup
          (docs/task-tracking.md). */}
      <ChartShell
        title="Tasks"
        icon={SECTION_ICONS.tasks}
        sub={`Session-level todo/plan checklist tracking · ${win}`}
      >
        <ChartState
          loading={taskRollup.loading && !taskRollup.data}
          error={taskRollup.error}
          denied={taskRollup.denied}
          deniedPermission={taskRollup.deniedPermission}
          onRetry={taskRollup.reload}
          empty={!taskRollup.data}
          emptyHint="No task data in this range"
          height={160}
        >
          {taskRollup.data && <TaskRollupSection data={taskRollup.data} />}
        </ChartState>
      </ChartShell>
    </div>
  );
}

// ----------------------------------------------------- Output composition

function VerbosityAggregateTable({
  groups,
  dim,
  keyDim,
}: {
  groups: VerbosityAggregateResponse["groups"];
  dim: VerbDim;
  // The dimension the RESPONSE was grouped by (can lag `dim` while a
  // re-fetch is in flight); it picks how each group key renders.
  keyDim: string;
}) {
  type Group = VerbosityAggregateResponse["groups"][number];
  const columns = useMemo<ColumnDef<Group, unknown>[]>(
    () => [
      {
        id: "key",
        header: dim,
        accessorFn: (g) => g.key,
        cell: ({ row }) => (
          <Tooltip
            content={<span className="break-all font-mono">{row.original.key}</span>}
            maxWidth={360}
          >
            <span
              tabIndex={0}
              className="block max-w-[200px] cursor-help truncate font-mono text-fg-1 focus:outline-none"
            >
              <DimKey dim={keyDim} value={row.original.key} />
            </span>
          </Tooltip>
        ),
      },
      {
        id: "code",
        header: "Code",
        accessorFn: (g) => g.code_bytes,
        meta: { align: "right" },
        cell: ({ row }) => (
          <span className="text-info">{fmtBytes(row.original.code_bytes)}</span>
        ),
      },
      {
        id: "explain",
        header: "Explain",
        accessorFn: (g) => g.explain_bytes,
        meta: { align: "right" },
        cell: ({ row }) => (
          <span className="text-fg-2">{fmtBytes(row.original.explain_bytes)}</span>
        ),
      },
      {
        id: "bar",
        header: "Code vs explain",
        accessorFn: (g) => g.code_pct,
        cell: ({ row }) => <CodeExplainBar codePct={row.original.code_pct} />,
      },
      {
        id: "ratio",
        header: "Ratio",
        accessorFn: (g) => g.code_explain_ratio ?? -1,
        meta: { align: "right" },
        cell: ({ row }) => (
          <span className="text-fg-2">
            {row.original.code_explain_ratio == null
              ? "-"
              : `${row.original.code_explain_ratio.toFixed(2)}×`}
          </span>
        ),
      },
      {
        id: "langs",
        header: "Top languages",
        enableSorting: false,
        cell: ({ row }) => (
          <span className="line-clamp-1 max-w-[220px] font-mono text-[11px] text-fg-2">
            {row.original.top_languages.length
              ? row.original.top_languages
                  .slice(0, 4)
                  .map((l) => l.language)
                  .join(", ")
              : "-"}
          </span>
        ),
      },
      {
        id: "usd",
        header: "Est. $",
        accessorFn: (g) => (g.cost_estimated ? g.est_total_usd : -1),
        meta: { align: "right" },
        cell: ({ row }) => (
          <span className="text-fg-1">
            {row.original.cost_estimated ? fmtUSD(row.original.est_total_usd) : "-"}
          </span>
        ),
      },
    ],
    [dim, keyDim],
  );
  return (
    <div>
      <DataTable<Group>
        data={groups}
        columns={columns}
        rowKey={(g) => g.key}
        minWidth={760}
      />
      <p className="mt-2 pl-2 text-[10px] text-fg-3">
        Code = file writes + shell commands + fenced code blocks. Bytes are
        exact; “Est. $” apportions each group's output tokens by content type
        and prices at the model's output rate.
      </p>
    </div>
  );
}

// CodeExplainBar is a two-segment bar: code (info) vs explanation (muted).
function CodeExplainBar({ codePct }: { codePct: number }) {
  const code = Math.max(0, Math.min(100, codePct));
  return (
    <div className="flex items-center gap-2">
      <div className="flex h-2 w-28 overflow-hidden rounded-pill bg-bg-3">
        <div className="bg-info" style={{ width: `${code}%` }} />
        <div className="bg-fg-3/50" style={{ width: `${100 - code}%` }} />
      </div>
      <span className="tabular-nums text-[10px] text-fg-3">
        {Math.round(code)}%
      </span>
    </div>
  );
}

// ----------------------------------------------------- Headline grid

function selectProjectCount(s: StatusSnapshot): number {
  return s.counts?.projects ?? 0;
}

function HeadlineGrid({
  data,
  projectsAllTime,
  scoped,
  trend,
  savings,
  win,
  loading,
}: {
  data: AnalysisHeadline | null;
  projectsAllTime: number | null;
  scoped: StatusScoped | null;
  trend: AnalysisTrend | null;
  savings: AnalysisCacheSavingsTrend | null;
  win: string;
  loading: boolean;
}) {
  if (loading && !data) {
    return (
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-6">
        {Array.from({ length: 12 }).map((_, i) => (
          <Skeleton key={i} className="h-[88px] rounded-3 border border-line-2" />
        ))}
      </div>
    );
  }
  if (!data) return null;

  const periodDelta = data.period.prior_is_zero ? null : data.period.delta_pct;
  const monthDelta = data.month.prior_month_is_zero
    ? null
    : data.month.vs_prior_month_pct;
  const budget = data.month.budget_usd;
  const budgetPct = budget > 0 ? data.month.budget_pct : null;

  // Derive sparkline arrays from the timeseries the page already
  // fetches — real data, not hand-waved curves. /api/analysis/trend
  // returns one row per (bucket, key) plus the zero-fill `grid`; fold to
  // per-bucket totals in bucket-start order.
  const byBucket = new Map<string, { t: number; v: number }>();
  for (const g of trend?.grid ?? []) byBucket.set(g.bucket, { t: g.t, v: 0 });
  for (const p of trend?.series ?? []) {
    const cur = byBucket.get(p.bucket) ?? { t: p.t, v: 0 };
    cur.v += p.cost_usd;
    byBucket.set(p.bucket, cur);
  }
  const dailySpend = [...byBucket.values()].sort((a, b) => a.t - b.t).map((b) => b.v);
  // Cumulative MTD trajectory — running sum of daily cost across the
  // window. Useful even when the window != calendar month.
  const dailyCumulative: number[] = [];
  let acc = 0;
  for (const v of dailySpend) {
    acc += v;
    dailyCumulative.push(acc);
  }
  const dailySavings = (savings?.points ?? []).map((p) => p.savings_usd);

  return (
    <Stagger className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-6">
      <StatCard
        label={`Spend (${win})`}
        helpId="tile.analysis.period_cost"
        icon={<MetricIcon metric="spend" />}
        loading={loading}
        value={fmtUSD(data.period.cost_usd)}
        delta={periodDelta == null ? undefined : periodDelta / 100}
        deltaPrior={
          data.period.prior_is_zero
            ? undefined
            : `vs prior ${win} ${fmtUSD(data.period.prior_cost_usd)}`
        }
        sub={
          data.period.recorded_cost_share_pct > 0
            ? `${data.period.recorded_cost_share_pct.toFixed(0)}% recorded`
            : undefined
        }
        spark={dailySpend}
        sparkColor="var(--accent)"
        accent
      />

      <StatCard
        label="Month to Date"
        helpId="tile.analysis.mtd"
        icon={<MetricIcon metric="monthToDate" />}
        loading={loading}
        value={fmtUSD(data.month.to_date_usd)}
        delta={monthDelta == null ? undefined : monthDelta / 100}
        deltaPrior={
          data.month.prior_month_is_zero
            ? `vs prior MTD day ${data.month.days_elapsed}`
            : `vs prior MTD day ${data.month.days_elapsed} ${fmtUSD(data.month.prior_month_same_day_usd)}`
        }
        sub={
          data.month.projection_usd > 0
            ? `proj. ${fmtUSD(data.month.projection_usd)}`
            : undefined
        }
        spark={dailyCumulative}
        sparkColor="var(--tok-net)"
      >
        {budgetPct != null && (
          <div className="mt-2">
            <div className="flex justify-between text-[10px] text-fg-3">
              <span>budget</span>
              <span>
                {fmtUSD(data.month.to_date_usd)} / {fmtUSD(budget)}
              </span>
            </div>
            <div className="mt-0.5 h-1 w-full overflow-hidden rounded-pill bg-bg-3">
              <span
                className="block h-full"
                style={{
                  width: `${Math.min(100, budgetPct)}%`,
                  background:
                    budgetPct > 100
                      ? "var(--danger)"
                      : budgetPct > 80
                        ? "var(--warn)"
                        : "var(--success)",
                }}
              />
            </div>
          </div>
        )}
      </StatCard>

      <StatCard
        label="$/M Output"
        helpId="tile.analysis.output_rate"
        icon={<MetricIcon metric="pricePerMOutput" />}
        loading={loading}
        value={fmtUSD(data.output_rate.rate_per_million)}
        sub={`${fmtCompact(data.output_rate.output_tokens)} tokens`}
      />

      <StatCard
        label="Cache Savings"
        helpId="tile.analysis.cache_savings"
        icon={<MetricIcon metric="savings" />}
        loading={loading}
        value={fmtUSD(data.cache_savings.usd)}
        sub={`${fmtCompact(data.cache_savings.cache_read_tokens)} read`}
        spark={dailySavings}
        sparkColor="var(--success)"
      />

      <StatCard
        label="Cache Efficacy"
        helpId="tile.analysis.cache_efficacy"
        icon={<MetricIcon metric="cacheHitRate" />}
        loading={loading}
        value={fmtPct(data.cache.efficacy)}
        sub={`${fmtCompact(data.cache.read_tokens)} / ${fmtCompact(
          data.cache.read_tokens + data.cache.write_tokens,
        )}`}
      />

      <StatCard
        label="High Context"
        helpId="tile.analysis.high_context"
        icon={<MetricIcon metric="highContext" />}
        loading={loading}
        value={fmtInt(data.high_context.turns_over_100k)}
        sub={`${fmtInt(data.high_context.turns_over_200k)} over 200K · ${fmtUSD(data.high_context.cost_over_100k_usd)}`}
        warn={data.high_context.turns_over_200k > 0}
      />

      <StatCard
        label="$ per Turn"
        helpId="tile.analysis.per_turn"
        icon={<MetricIcon metric="costPerTurn" />}
        loading={loading}
        value={fmtUSD(data.per_turn.mean_usd)}
        sub={`p95 ${fmtUSD(data.per_turn.p95_usd)} · ${fmtInt(data.per_turn.count)} turns`}
      />

      <StatCard
        label="Burn Rate"
        helpId="tile.analysis.burn_rate"
        icon={<MetricIcon metric="burnRate" />}
        loading={loading}
        value={fmtUSD(data.burn_rate.cost_per_hour_usd)}
        unit="/h"
        sub={`${fmtInt(data.burn_rate.active_hours)} active hours`}
      />

      <StatCard
        label="Top Model"
        helpId="tile.analysis.top_model"
        icon={<MetricIcon metric="topModel" />}
        loading={loading}
        value={
          data.top_model.key ? (
            <ModelId model={data.top_model.key} markSize={18} className="min-w-0 text-[18px]" />
          ) : (
            <span className="font-mono text-[18px]">-</span>
          )
        }
        sub={`${fmtPct(data.top_model.concentration_pct, 1, false)} concentration · ${fmtUSD(data.top_model.cost_usd)}`}
      />

      <StatCard
        label="Waste"
        helpId="tile.analysis.waste"
        icon={<MetricIcon metric="waste" />}
        loading={loading}
        value={fmtUSD(data.waste.usd)}
        sub={`${fmtCompact(data.waste.tokens)} stale-read tokens`}
        warn={data.waste.usd > 1}
      />

      <StatCard
        label="Budget MTD"
        icon={<MetricIcon metric="budget" />}
        loading={loading}
        value={
          budget > 0
            ? fmtUSD(Math.max(0, budget - data.month.to_date_usd))
            : fmtUSD(data.month.projection_usd)
        }
        sub={
          budget > 0
            ? `${fmtUSD(data.month.to_date_usd)} of ${fmtUSD(budget)} spent`
            : "no budget set · projection shown"
        }
        warn={budget > 0 && data.month.to_date_usd > budget * 0.8}
      />

      <StatCard
        label={`Sessions (${win})`}
        helpId="tile.sessions"
        icon={<MetricIcon metric="sessions" />}
        loading={loading}
        value={fmtInt(scoped?.sessions)}
        sub={
          projectsAllTime
            ? `across ${fmtInt(projectsAllTime)} projects all-time`
            : undefined
        }
      />
    </Stagger>
  );
}

// ----------------------------------------------------- Movers / Entrants

// Per-dimension key renderer, table-driven (CLAUDE.md #5): a MODEL key gets
// the shared ModelId (family mark + label); every other dimension (project,
// tool, day) renders as plain text, inheriting the cell's mono style. The
// dim comes from the RESPONSE (`dim` / `by`), so stale rows from a previous
// dimension never render through the wrong renderer.
const DIM_KEY_RENDER: Partial<Record<string, (key: string) => ReactNode>> = {
  model: (key) => <ModelId model={key} className="max-w-full" />,
};

function DimKey({ dim, value }: { dim: string; value: string }) {
  const render = DIM_KEY_RENDER[dim];
  return <>{render ? render(value) : value}</>;
}

function MoversList({ movers }: { movers: AnalysisMovers }) {
  return (
    <div className="space-y-4">
      <MoversBlock
        title="Increases"
        rows={movers.increases ?? []}
        dim={movers.dim}
        positive
      />
      <MoversBlock
        title="Decreases"
        rows={movers.decreases ?? []}
        dim={movers.dim}
        positive={false}
      />
    </div>
  );
}

function MoversBlock({
  title,
  rows,
  dim,
  positive,
}: {
  title: string;
  rows: Mover[];
  dim: string;
  positive: boolean;
}) {
  const columns = useMemo<ColumnDef<Mover, unknown>[]>(() => {
    const deltaCls = positive ? "text-success" : "text-danger";
    const deltaPct = (m: Mover) =>
      m.prior_usd > 0 ? (m.delta_usd / m.prior_usd) * 100 : null;
    return [
      {
        id: "key",
        header: "Key",
        accessorFn: (m) => m.key,
        cell: ({ row }) => (
          <Tooltip
            content={<span className="break-all font-mono">{row.original.key}</span>}
            maxWidth={360}
          >
            <span
              tabIndex={0}
              className="block max-w-[180px] cursor-help truncate font-mono text-fg-1 focus:outline-none"
            >
              <DimKey dim={dim} value={row.original.key} />
            </span>
          </Tooltip>
        ),
      },
      {
        id: "prior",
        header: "Prior $",
        accessorFn: (m) => m.prior_usd,
        meta: { align: "right" },
        cell: ({ row }) => <span className="text-fg-3">{fmtUSD(row.original.prior_usd)}</span>,
      },
      {
        id: "current",
        header: "Current $",
        accessorFn: (m) => m.current_usd,
        meta: { align: "right" },
        cell: ({ row }) => <span className="text-fg-1">{fmtUSD(row.original.current_usd)}</span>,
      },
      {
        id: "delta",
        header: "Δ $",
        accessorFn: (m) => m.delta_usd,
        meta: { align: "right" },
        cell: ({ row }) => (
          <span className={`font-medium ${deltaCls}`}>
            {row.original.delta_usd > 0 ? "+" : ""}
            {fmtUSD(row.original.delta_usd)}
          </span>
        ),
      },
      {
        id: "pct",
        header: "Δ %",
        accessorFn: (m) => deltaPct(m) ?? Number.NEGATIVE_INFINITY,
        meta: { align: "right" },
        cell: ({ row }) => {
          const p = deltaPct(row.original);
          return (
            <span className={deltaCls}>
              {p == null ? "-" : `${p > 0 ? "+" : ""}${p.toFixed(1)}%`}
            </span>
          );
        },
      },
    ];
  }, [dim, positive]);
  if (!rows.length) {
    return (
      <div>
        <div className="mb-1.5 text-[10px] font-semibold uppercase tracking-[0.06em] text-fg-3">
          {title}
        </div>
        <div className="text-[11px] text-fg-4">none</div>
      </div>
    );
  }
  return (
    <div>
      <div className="mb-1.5 text-[10px] font-semibold uppercase tracking-[0.06em] text-fg-3">
        {title}
      </div>
      <DataTable<Mover>
        data={rows}
        columns={columns}
        rowKey={(m) => m.key}
        minWidth={400}
      />
    </div>
  );
}

const entrantColumns = (dim: string): ColumnDef<Entrant, unknown>[] => [
  {
    id: "key",
    header: "Key",
    accessorFn: (e) => e.key,
    cell: ({ row }) => (
      <Tooltip
        content={<span className="break-all font-mono">{row.original.key}</span>}
        maxWidth={360}
      >
        <span
          tabIndex={0}
          className="block max-w-[220px] cursor-help truncate font-mono text-fg-1 focus:outline-none"
        >
          <DimKey dim={dim} value={row.original.key} />
        </span>
      </Tooltip>
    ),
  },
  {
    id: "current",
    header: "Current $",
    accessorFn: (e) => e.current_usd,
    meta: { align: "right" },
    cell: ({ row }) => (
      <span className="font-medium text-success">{fmtUSD(row.original.current_usd)}</span>
    ),
  },
];

function EntrantsList({ entrants, dim }: { entrants: Entrant[]; dim: string }) {
  const columns = useMemo(() => entrantColumns(dim), [dim]);
  if (!entrants.length) {
    return <div className="text-[11px] text-fg-4">none</div>;
  }
  return (
    <DataTable<Entrant>
      data={entrants}
      columns={columns}
      rowKey={(e) => e.key}
      minWidth={260}
    />
  );
}

// ----------------------------------------------------- Top sessions

type TopSession = AnalysisTopSessions["sessions"][number];

// TOP_SESSION_COLUMNS: "#" is the server's rank (the row's position in
// the response), so it stays attached to its session under any re-sort.
const TOP_SESSION_COLUMNS: ColumnDef<TopSession, unknown>[] = [
  {
    id: "rank",
    header: "#",
    enableSorting: false,
    cell: ({ row }) => <span className="tabular-nums text-fg-3">{row.index + 1}</span>,
  },
  {
    id: "tool",
    header: () => <>Tool<HelpInd id="column.sessions.tool" /></>,
    accessorFn: (s) => s.tool,
    cell: ({ row }) => <ToolBadge tool={row.original.tool} />,
  },
  {
    id: "session",
    header: () => <>Session<HelpInd id="column.sessions.id" /></>,
    enableSorting: false,
    cell: ({ row }) => (
      <CopyOnClick value={row.original.id} className="whitespace-nowrap font-mono text-[11.5px] text-fg-2">
        {row.original.id.slice(0, 8)}…{row.original.id.slice(-4)}
      </CopyOnClick>
    ),
  },
  {
    id: "models",
    header: "Models",
    enableSorting: false,
    cell: ({ row }) => (
      <span className="flex min-w-0 max-w-[280px] items-center gap-2 overflow-hidden text-fg-2">
        {row.original.models.map((m) => (
          <ModelId key={m} model={m} className="min-w-0" />
        ))}
      </span>
    ),
  },
  {
    id: "turns",
    header: () => <>Turns<HelpInd id="column.cost.turns" /></>,
    accessorFn: (s) => s.turns,
    meta: { align: "right" },
    cell: ({ row }) => <span className="text-fg-1">{fmtInt(row.original.turns)}</span>,
  },
  {
    id: "max_prompt",
    header: "Max prompt",
    accessorFn: (s) => s.max_prompt_tokens,
    meta: { align: "right" },
    cell: ({ row }) => <span className="text-fg-2">{fmtCompact(row.original.max_prompt_tokens)}</span>,
  },
  {
    id: "cost",
    header: () => <>Cost<HelpInd id="column.sessions.cost" /></>,
    accessorFn: (s) => s.cost_usd,
    meta: { align: "right" },
    cell: ({ row }) => (
      <strong className="text-fg-0">{fmtUSD(row.original.cost_usd)}</strong>
    ),
  },
  {
    id: "badges",
    header: "Why flagged",
    enableSorting: false,
    cell: ({ row }) => (
      // No wrap: a squeezed column would stack the badges three high and
      // triple every row at phone width; the table scrolls instead.
      <div className="flex gap-1 whitespace-nowrap">
        {row.original.badges.map((b) => (
          <BadgePill key={b} kind={b} />
        ))}
      </div>
    ),
  },
];

function TopSessionsTable({ rows }: { rows: TopSession[] }) {
  return (
    <DataTable<TopSession>
      data={rows}
      columns={TOP_SESSION_COLUMNS}
      rowKey={(s) => s.id}
      // DataTable pads every cell (px-2), so the old 760 floor left the
      // session/models columns wrapping at phone width.
      minWidth={840}
    />
  );
}

function BadgePill({ kind }: { kind: string }) {
  switch (kind) {
    case "opus":
      return <Pill variant="warn">opus</Pill>;
    case "lc_tier":
      return <Pill variant="danger">LC tier</Pill>;
    case "many_turns":
      return <Pill variant="info">many turns</Pill>;
    case "large_prompt":
      return <Pill variant="accent">large prompt</Pill>;
    default:
      return <Pill>{kind}</Pill>;
  }
}

// ----------------------------------------------------- Routing list

type RoutingSuggestion = AnalysisRoutingSuggestions["suggestions"][number];

const ROUTING_COLUMNS: ColumnDef<RoutingSuggestion, unknown>[] = [
  {
    id: "session",
    header: "Session",
    enableSorting: false,
    cell: ({ row }) => (
      <CopyOnClick value={row.original.session_id} className="whitespace-nowrap font-mono text-[11px] text-fg-2">
        {row.original.session_id.slice(0, 8)}…
      </CopyOnClick>
    ),
  },
  {
    id: "migration",
    header: "Suggested migration",
    enableSorting: false,
    cell: ({ row }) => (
      <span className="inline-flex items-center gap-1.5 text-[11px]">
        <ModelId model={row.original.current_model} className="min-w-0" />
        <span className="text-fg-4">→</span>
        <ModelId model={row.original.suggested_model} className="min-w-0" />
      </span>
    ),
  },
  {
    id: "current",
    header: "Current $",
    accessorFn: (s) => s.current_cost_usd,
    meta: { align: "right" },
    cell: ({ row }) => <span className="text-fg-2">{fmtUSD(row.original.current_cost_usd)}</span>,
  },
  {
    id: "suggested",
    header: "Suggest $",
    accessorFn: (s) => s.suggested_cost_usd,
    meta: { align: "right" },
    cell: ({ row }) => <span className="text-fg-2">{fmtUSD(row.original.suggested_cost_usd)}</span>,
  },
  {
    id: "savings",
    header: "Savings",
    accessorFn: (s) => s.savings_usd,
    meta: { align: "right" },
    cell: ({ row }) => (
      <span className="font-medium text-success">{fmtUSD(row.original.savings_usd)}</span>
    ),
  },
  {
    id: "reasons",
    header: "Reasoning",
    enableSorting: false,
    cell: ({ row }) => (
      <span className="flex flex-wrap gap-1">
        {row.original.reasons.map((r) => (
          <Pill key={r}>{r}</Pill>
        ))}
      </span>
    ),
  },
];

function RoutingList({ suggestions }: { suggestions: RoutingSuggestion[] }) {
  return (
    <DataTable<RoutingSuggestion>
      data={suggestions}
      columns={ROUTING_COLUMNS}
      rowKey={(s) => s.session_id}
      minWidth={840}
    />
  );
}

// ----------------------------------------------------- Task tracking

type TaskToolRow = TaskRollup["by_tool"][number];

const TASK_TOOL_COLUMNS: ColumnDef<TaskToolRow, unknown>[] = [
  {
    id: "tool",
    header: "Tool",
    accessorFn: (t) => t.tool,
    cell: ({ row }) => <ToolBadge tool={row.original.tool} />,
  },
  {
    id: "sessions",
    header: "Sessions",
    accessorFn: (t) => t.sessions,
    meta: { align: "right" },
    cell: ({ row }) => <span className="text-fg-2">{fmtInt(row.original.sessions)}</span>,
  },
  {
    id: "tasks",
    header: "Tasks",
    accessorFn: (t) => t.tasks,
    meta: { align: "right" },
    cell: ({ row }) => <span className="text-fg-2">{fmtInt(row.original.tasks)}</span>,
  },
  {
    id: "cost",
    header: "Cost",
    // Unpriced sorts below every priced row rather than as $0.
    accessorFn: (t) => (t.unpriced ? -1 : t.cost_usd),
    meta: { align: "right" },
    cell: ({ row }) =>
      row.original.unpriced ? (
        <span className="text-fg-3">unpriced</span>
      ) : (
        <span className="text-fg-1">{fmtTaskUSD(row.original.cost_usd)}</span>
      ),
  },
];

function TaskRollupSection({ data }: { data: TaskRollup }) {
  if (data.sessions_with_tasks === 0) {
    return (
      <p className="text-[11.5px] text-fg-3">
        No sessions in this window used a todo/plan tool — most don't; this
        is the normal case, not a gap.
      </p>
    );
  }

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <TaskKpi label="Sessions" value={fmtInt(data.sessions_with_tasks)} />
        <TaskKpi label="Created" value={fmtInt(data.counts.created)} />
        <TaskKpi label="Completed" value={fmtInt(data.counts.completed)} />
        <TaskKpi label="Cancelled" value={fmtInt(data.counts.cancelled)} />
        <TaskKpi
          label="Never activated"
          value={fmtInt(data.counts.never_activated)}
        />
        <TaskKpi label="Still open" value={fmtInt(data.counts.still_open)} />
      </div>

      {data.by_tool.length > 0 && (
        <DataTable<TaskToolRow>
          data={data.by_tool}
          columns={TASK_TOOL_COLUMNS}
          rowKey={(t) => t.tool}
          minWidth={480}
        />
      )}

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        <TaskBucketCard
          label="Attributed to one task"
          bucket={data.attributed_single}
        />
        <TaskBucketCard label="Between tasks" bucket={data.between_tasks} />
        <TaskBucketCard label="Shared (2+ tasks)" bucket={data.shared} />
      </div>

      {data.counts.unmatched > 0 && !data.counts.all_sessions_keys_native && (
        <p className="text-[10.5px] text-fg-3">
          {data.counts.unmatched} item(s) across these sessions could not be
          matched across updates (the tool has no stable id — text changed
          between snapshots).
        </p>
      )}
      {data.cost_note && (
        <p className="text-[10.5px] text-fg-3">{data.cost_note}</p>
      )}
    </div>
  );
}

function TaskKpi({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-3 border border-line-2 bg-bg-2 px-3 py-2">
      <div className="text-[10px] font-medium uppercase tracking-[0.05em] text-fg-3">
        {label}
      </div>
      <div className="mt-0.5 tabular-nums text-[15px] font-semibold text-fg-1">
        {value}
      </div>
    </div>
  );
}

function TaskBucketCard({
  label,
  bucket,
}: {
  label: string;
  bucket: TaskCostBucket;
}) {
  return (
    <div className="rounded-3 border border-line-2 bg-bg-2 px-3 py-2">
      <div className="text-[10px] font-medium uppercase tracking-[0.05em] text-fg-3">
        {label}
      </div>
      <div className="mt-0.5 tabular-nums text-[14px] font-semibold text-fg-1">
        {bucket.unpriced ? (
          <span className="text-fg-3">unpriced</span>
        ) : (
          fmtTaskUSD(bucket.cost_usd)
        )}
      </div>
      <div className="mt-0.5 text-[10.5px] text-fg-3">
        {fmtCompact(bucket.tokens.input_tokens)} in /{" "}
        {fmtCompact(bucket.tokens.output_tokens)} out ·{" "}
        {fmtInt(bucket.actions_count)} actions
      </div>
    </div>
  );
}
