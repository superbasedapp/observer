import { useState } from "react";
import { Link } from "react-router-dom";
import {
  ChartShell,
  PageHeader,
  Pill,
  SegmentedControl,
  StatCard,
  ToolBadge,
  Tooltip,
} from "@/components/primitives";
import { HelpInd, TitleWithHelp } from "@/components/HelpInd";
import { CopyOnClick } from "@/components/CopyOnClick";
import {
  AlertIcon,
  BoltIcon,
  CalendarIcon,
  CoinsIcon,
  DropletIcon,
  LayersIcon,
  PercentIcon,
  SparklesIcon,
} from "@/components/icons";
import {
  CacheSavingsChart,
  DowHourHeatmap,
  TrendByKeyChart,
} from "@/components/charts";
import { ChartState } from "@/components/ChartState";
import { useFilters, windowDaysApprox, windowParams } from "@/lib/filters";
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

// VerbDim is the Output-composition rollup dimension (no "tool" facet — the
// aggregate keys on model/project/day).
type VerbDim = "model" | "project" | "day";

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
  const status = useApi<StatusSnapshot>("/api/status");
  const scoped = useApi<StatusScoped>(
    "/api/status/scoped",
    { ...winParams, tool: toolParam, project: projectParam },
    [win, customRange, tool, project],
  );
  const trend = useApi<AnalysisTrend>(
    "/api/analysis/trend",
    { ...winParams, dim, tool: toolParam, project: projectParam },
    [win, customRange, dim, tool, project],
  );
  const hours = useApi<AnalysisCostByDowHour>(
    "/api/analysis/cost-by-dow-hour",
    { ...winParams, tool: toolParam, project: projectParam },
    [win, customRange, tool, project],
  );
  const savings = useApi<AnalysisCacheSavingsTrend>(
    "/api/analysis/cache-savings-trend",
    { ...winParams, tool: toolParam, project: projectParam },
    [win, customRange, tool, project],
  );
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
    <div className="space-y-6 p-6">
      <PageHeader
        title="Analysis"
        sub="Spending insights for the selected window. Headline KPIs comparing this period to the prior period, daily trend with a dimension toggle, top movers, and cost-sensitive signals - $/M output, cache savings, high-context turns, per-turn variance, burn rate, top-model concentration, and routing efficiency suggestions."
        helpId="tab.analysis"
      />
      <HeadlineGrid
        data={head.data}
        status={status.data}
        scoped={scoped.data}
        trend={trend.data}
        savings={savings.data}
        win={win}
        loading={head.loading}
      />

      {/* Daily spend by dim */}
      <ChartShell
        title={<TitleWithHelp text="Daily spend" helpId="chart.analysis_trend" />}
        sub={`Cost per day, stacked by ${dim} · ${win}`}
        right={
          <SegmentedControl<AnalysisDim>
            options={[
              { value: "model", label: "Model" },
              { value: "project", label: "Project" },
              { value: "tool", label: "Tool" },
            ]}
            value={dim}
            onChange={setDim}
          />
        }
      >
        <ChartState
          loading={trend.loading}
          error={trend.error}
          empty={!trend.data?.series?.length}
          emptyHint="No spend data in this window."
          height={280}
        >
          {trend.data && (
            <TrendByKeyChart
              data={trend.data.series}
              colorMode={dim}
              topN={6}
            />
          )}
        </ChartState>
      </ChartShell>

      {/* Hourly heatmap + cache savings trend side by side */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <ChartShell
          title={<TitleWithHelp text="When you spend" helpId="chart.analysis_cost_by_hour" />}
          sub={`Cost by hour of day × day of week · ${hours.data?.timezone ?? "UTC"} · ${win}`}
        >
          <ChartState
            loading={hours.loading}
            error={hours.error}
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
          sub="Counterfactual: cache_read priced at input rate vs cache_read rate"
        >
          <ChartState
            loading={savings.loading}
            error={savings.error}
            empty={!savings.data?.points?.length}
            emptyHint="No cache-read traffic in window."
            height={200}
          >
            {savings.data && <CacheSavingsChart data={savings.data.points} />}
          </ChartState>
        </ChartShell>
      </div>

      {/* What changed */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <ChartShell
          title={<TitleWithHelp text="Top movers" helpId="chart.analysis_movers" />}
          sub={`Δ$ vs prior ${win} · grouped by ${dim}`}
        >
          <ChartState
            loading={movers.loading}
            error={movers.error}
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
          sub={`Keys that appeared in this ${win} but not the prior`}
        >
          <ChartState
            loading={movers.loading}
            error={movers.error}
            empty={!(movers.data?.new_entrants ?? []).length}
            emptyHint="No new entrants."
            height={220}
          >
            {movers.data && (
              <EntrantsList entrants={movers.data.new_entrants ?? []} />
            )}
          </ChartState>
        </ChartShell>
      </div>

      {/* Top expensive sessions */}
      <ChartShell
        title={<TitleWithHelp text="Top expensive sessions" helpId="chart.analysis_top_sessions" />}
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
          error={topSessions.error}
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
      <ChartShell
        title={<TitleWithHelp text="Routing efficiency" helpId="chart.analysis_routing" />}
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
          error={routing.error}
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
      <ChartShell
        title={<TitleWithHelp text="Output composition" helpId="chart.analysis_verbosity" />}
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
          error={verbosity.error}
          empty={!verbosity.data?.groups?.length}
          emptyHint="No assistant output captured in window."
          height={240}
        >
          {verbosity.data && (
            <VerbosityAggregateTable groups={verbosity.data.groups} dim={vbDim} />
          )}
        </ChartState>
      </ChartShell>

      {/* Task tracking — session-level todo/plan checklist rollup
          (docs/task-tracking.md). */}
      <ChartShell
        title="Tasks"
        sub={`Session-level todo/plan checklist tracking · ${win}`}
      >
        <ChartState
          loading={taskRollup.loading && !taskRollup.data}
          error={taskRollup.error}
          empty={!taskRollup.data}
          emptyHint="Loading task rollup…"
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
}: {
  groups: VerbosityAggregateResponse["groups"];
  dim: VerbDim;
}) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[760px] text-left text-[11.5px]">
        <thead className="text-[10px] uppercase tracking-[0.06em] text-fg-3">
          <tr className="border-b border-line-2">
            <th className="py-1.5 pl-2 font-medium">{dim}</th>
            <th className="py-1.5 text-right font-medium">Code</th>
            <th className="py-1.5 text-right font-medium">Explain</th>
            <th className="py-1.5 pl-3 font-medium">Code vs explain</th>
            <th className="py-1.5 text-right font-medium">Ratio</th>
            <th className="py-1.5 pl-3 font-medium">Top languages</th>
            <th className="py-1.5 pr-2 text-right font-medium">Est. $</th>
          </tr>
        </thead>
        <tbody>
          {groups.map((g) => (
            <tr
              key={g.key}
              className="border-b border-line-1 last:border-b-0 hover:bg-bg-3/40"
            >
              <Tooltip
                content={<span className="break-all font-mono">{g.key}</span>}
                maxWidth={360}
              >
                <td
                  tabIndex={0}
                  className="max-w-[200px] cursor-help truncate py-1.5 pl-2 font-mono text-fg-1 focus:outline-none"
                >
                  {g.key}
                </td>
              </Tooltip>
              <td className="py-1.5 text-right tabular-nums text-info">
                {fmtBytes(g.code_bytes)}
              </td>
              <td className="py-1.5 text-right tabular-nums text-fg-2">
                {fmtBytes(g.explain_bytes)}
              </td>
              <td className="py-1.5 pl-3">
                <CodeExplainBar codePct={g.code_pct} />
              </td>
              <td className="py-1.5 text-right tabular-nums text-fg-2">
                {g.code_explain_ratio == null
                  ? "-"
                  : `${g.code_explain_ratio.toFixed(2)}×`}
              </td>
              <td className="max-w-[220px] py-1.5 pl-3 font-mono text-[11px] text-fg-2">
                <span className="line-clamp-1">
                  {g.top_languages.length
                    ? g.top_languages
                        .slice(0, 4)
                        .map((l) => l.language)
                        .join(", ")
                    : "-"}
                </span>
              </td>
              <td className="py-1.5 pr-2 text-right tabular-nums text-fg-1">
                {g.cost_estimated ? fmtUSD(g.est_total_usd) : "-"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
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
      <div className="flex h-2 w-28 overflow-hidden rounded-full bg-bg-1">
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

function HeadlineGrid({
  data,
  status,
  scoped,
  trend,
  savings,
  win,
  loading,
}: {
  data: AnalysisHeadline | null;
  status: StatusSnapshot | null;
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
          <div
            key={i}
            className="h-[88px] animate-pulse rounded-3 border border-line-2 bg-bg-2"
          />
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
  // returns one row per (day, key); fold to daily totals first.
  const dailyByDay = new Map<string, number>();
  for (const p of trend?.series ?? []) {
    dailyByDay.set(p.bucket, (dailyByDay.get(p.bucket) ?? 0) + p.cost_usd);
  }
  const dailySpend = [...dailyByDay.keys()]
    .sort()
    .map((d) => dailyByDay.get(d) ?? 0);
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
    <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-6">
      <StatCard
        label={`Spend (${win})`}
        helpId="tile.analysis.period_cost"
        icon={<CoinsIcon />}
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
        icon={<CalendarIcon />}
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
        icon={<PercentIcon />}
        loading={loading}
        value={fmtUSD(data.output_rate.rate_per_million)}
        sub={`${fmtCompact(data.output_rate.output_tokens)} tokens`}
      />

      <StatCard
        label="Cache Savings"
        helpId="tile.analysis.cache_savings"
        icon={<DropletIcon />}
        loading={loading}
        value={fmtUSD(data.cache_savings.usd)}
        sub={`${fmtCompact(data.cache_savings.cache_read_tokens)} read`}
        spark={dailySavings}
        sparkColor="var(--success)"
      />

      <StatCard
        label="Cache Efficacy"
        helpId="tile.analysis.cache_efficacy"
        icon={<PercentIcon />}
        loading={loading}
        value={fmtPct(data.cache.efficacy)}
        sub={`${fmtCompact(data.cache.read_tokens)} / ${fmtCompact(
          data.cache.read_tokens + data.cache.write_tokens,
        )}`}
      />

      <StatCard
        label="High Context"
        helpId="tile.analysis.high_context"
        icon={<AlertIcon />}
        loading={loading}
        value={fmtInt(data.high_context.turns_over_100k)}
        sub={`${fmtInt(data.high_context.turns_over_200k)} over 200K · ${fmtUSD(data.high_context.cost_over_100k_usd)}`}
        warn={data.high_context.turns_over_200k > 0}
      />

      <StatCard
        label="$ per Turn"
        helpId="tile.analysis.per_turn"
        icon={<CoinsIcon />}
        loading={loading}
        value={fmtUSD(data.per_turn.mean_usd)}
        sub={`p95 ${fmtUSD(data.per_turn.p95_usd)} · ${fmtInt(data.per_turn.count)} turns`}
      />

      <StatCard
        label="Burn Rate"
        helpId="tile.analysis.burn_rate"
        icon={<BoltIcon />}
        loading={loading}
        value={fmtUSD(data.burn_rate.cost_per_hour_usd)}
        unit="/h"
        sub={`${fmtInt(data.burn_rate.active_hours)} active hours`}
      />

      <StatCard
        label="Top Model"
        helpId="tile.analysis.top_model"
        icon={<SparklesIcon />}
        loading={loading}
        value={
          <span className="font-mono text-[18px]">
            {data.top_model.key || "-"}
          </span>
        }
        sub={`${fmtPct(data.top_model.concentration_pct, 1, false)} concentration · ${fmtUSD(data.top_model.cost_usd)}`}
      />

      <StatCard
        label="Waste"
        helpId="tile.analysis.waste"
        icon={<AlertIcon />}
        loading={loading}
        value={fmtUSD(data.waste.usd)}
        sub={`${fmtCompact(data.waste.tokens)} stale-read tokens`}
        warn={data.waste.usd > 1}
      />

      <StatCard
        label="Budget MTD"
        icon={<CalendarIcon />}
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
        icon={<LayersIcon />}
        loading={loading}
        value={fmtInt(scoped?.sessions)}
        sub={
          status?.counts.projects
            ? `across ${fmtInt(status.counts.projects)} projects all-time`
            : undefined
        }
      />
    </div>
  );
}

// ----------------------------------------------------- Movers / Entrants

function MoversList({ movers }: { movers: AnalysisMovers }) {
  return (
    <div className="space-y-4">
      <MoversBlock
        title="Increases"
        rows={movers.increases ?? []}
        positive
      />
      <MoversBlock
        title="Decreases"
        rows={movers.decreases ?? []}
        positive={false}
      />
    </div>
  );
}

function MoversBlock({
  title,
  rows,
  positive,
}: {
  title: string;
  rows: Mover[];
  positive: boolean;
}) {
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
      <table className="w-full text-left text-[11px]">
        <thead className="text-[10px] uppercase tracking-[0.06em] text-fg-3">
          <tr>
            <th className="py-1 pl-1 font-medium">Key</th>
            <th className="py-1 text-right font-medium">Prior $</th>
            <th className="py-1 text-right font-medium">Current $</th>
            <th className="py-1 text-right font-medium">Δ $</th>
            <th className="py-1 pl-2 text-right font-medium">Δ %</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((m) => {
            const deltaPct = m.prior_usd > 0
              ? (m.delta_usd / m.prior_usd) * 100
              : null;
            const deltaCls = positive ? "text-success" : "text-danger";
            return (
              <tr
                key={m.key}
                className="border-t border-line-1 hover:bg-bg-3/40"
              >
                <Tooltip
                  content={<span className="break-all font-mono">{m.key}</span>}
                  maxWidth={360}
                >
                  <td
                    tabIndex={0}
                    className="max-w-[180px] cursor-help truncate py-1 pl-1 font-mono text-fg-1 focus:outline-none"
                  >
                    {m.key}
                  </td>
                </Tooltip>
                <td className="py-1 text-right tabular-nums text-fg-3">
                  {fmtUSD(m.prior_usd)}
                </td>
                <td className="py-1 text-right tabular-nums text-fg-1">
                  {fmtUSD(m.current_usd)}
                </td>
                <td
                  className={`py-1 text-right tabular-nums font-medium ${deltaCls}`}
                >
                  {m.delta_usd > 0 ? "+" : ""}
                  {fmtUSD(m.delta_usd)}
                </td>
                <td
                  className={`py-1 pl-2 text-right tabular-nums ${deltaCls}`}
                >
                  {deltaPct == null
                    ? "-"
                    : `${deltaPct > 0 ? "+" : ""}${deltaPct.toFixed(1)}%`}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function EntrantsList({ entrants }: { entrants: Entrant[] }) {
  if (!entrants.length) {
    return <div className="text-[11px] text-fg-4">none</div>;
  }
  return (
    <table className="w-full text-left text-[11px]">
      <thead className="text-[10px] uppercase tracking-[0.06em] text-fg-3">
        <tr>
          <th className="py-1 pl-1 font-medium">Key</th>
          <th className="py-1 text-right font-medium">Current $</th>
        </tr>
      </thead>
      <tbody>
        {entrants.map((e) => (
          <tr key={e.key} className="border-t border-line-1 hover:bg-bg-3/40">
            <Tooltip
              content={<span className="break-all font-mono">{e.key}</span>}
              maxWidth={360}
            >
              <td
                tabIndex={0}
                className="max-w-[220px] cursor-help truncate py-1 pl-1 font-mono text-fg-1 focus:outline-none"
              >
                {e.key}
              </td>
            </Tooltip>
            <td className="py-1 text-right font-medium tabular-nums text-success">
              {fmtUSD(e.current_usd)}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

// ----------------------------------------------------- Top sessions

function TopSessionsTable({
  rows,
}: {
  rows: AnalysisTopSessions["sessions"];
}) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[760px] text-left text-[11.5px]">
        <thead className="text-[10px] uppercase tracking-[0.06em] text-fg-3">
          <tr className="border-b border-line-2">
            <th className="py-1.5 pl-2 text-left font-medium">#</th>
            <th className="py-1.5 text-left font-medium">Tool<HelpInd id="column.sessions.tool" /></th>
            <th className="py-1.5 text-left font-medium">Session<HelpInd id="column.sessions.id" /></th>
            <th className="py-1.5 text-left font-medium">Models</th>
            <th className="py-1.5 text-right font-medium">Turns<HelpInd id="column.cost.turns" /></th>
            <th className="py-1.5 text-right font-medium">Max prompt</th>
            <th className="py-1.5 text-right font-medium">Cost<HelpInd id="column.sessions.cost" /></th>
            <th className="py-1.5 pl-3 text-left font-medium">Why flagged</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((s, i) => (
            <tr
              key={s.id}
              className="border-b border-line-1 last:border-b-0 hover:bg-bg-3/40"
            >
              <td className="py-1.5 pl-2 tabular-nums text-fg-3">
                {i + 1}
              </td>
              <td className="py-1.5">
                <ToolBadge tool={s.tool} />
              </td>
              <td className="py-1.5">
                <CopyOnClick
                  value={s.id}
                  className="font-mono text-[11.5px] text-fg-2"
                >
                  {s.id.slice(0, 8)}…{s.id.slice(-4)}
                </CopyOnClick>
              </td>
              <td className="max-w-[280px] py-1.5 font-mono text-fg-2">
                <span className="line-clamp-1">{s.models.join(", ")}</span>
              </td>
              <td className="py-1.5 text-right tabular-nums text-fg-1">
                {fmtInt(s.turns)}
              </td>
              <td className="py-1.5 text-right tabular-nums text-fg-2">
                {fmtCompact(s.max_prompt_tokens)}
              </td>
              <td className="py-1.5 text-right tabular-nums text-fg-0">
                <strong>{fmtUSD(s.cost_usd)}</strong>
              </td>
              <td className="py-1.5 pl-3">
                <div className="flex flex-wrap gap-1">
                  {s.badges.map((b) => (
                    <BadgePill key={b} kind={b} />
                  ))}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
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

function RoutingList({
  suggestions,
}: {
  suggestions: AnalysisRoutingSuggestions["suggestions"];
}) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[760px] text-left text-[11.5px]">
        <thead className="text-[10px] uppercase tracking-[0.06em] text-fg-3">
          <tr className="border-b border-line-2">
            <th className="py-1.5 pl-2 font-medium">Session</th>
            <th className="py-1.5 font-medium">Suggested migration</th>
            <th className="py-1.5 text-right font-medium">Current $</th>
            <th className="py-1.5 text-right font-medium">Suggest $</th>
            <th className="py-1.5 text-right font-medium">Savings</th>
            <th className="py-1.5 pl-3 font-medium">Reasoning</th>
          </tr>
        </thead>
        <tbody>
          {suggestions.map((s) => (
            <tr
              key={s.session_id}
              className="border-b border-line-1 hover:bg-bg-3/40 last:border-b-0"
            >
              <td className="py-1.5 pl-2">
                <CopyOnClick
                  value={s.session_id}
                  className="font-mono text-[11px] text-fg-2"
                >
                  {s.session_id.slice(0, 8)}…
                </CopyOnClick>
              </td>
              <td className="py-1.5">
                <span className="inline-flex items-center gap-1.5 font-mono text-[11px]">
                  <span className="text-warn">{s.current_model}</span>
                  <span className="text-fg-4">→</span>
                  <span className="text-success">{s.suggested_model}</span>
                </span>
              </td>
              <td className="py-1.5 text-right tabular-nums text-fg-2">
                {fmtUSD(s.current_cost_usd)}
              </td>
              <td className="py-1.5 text-right tabular-nums text-fg-2">
                {fmtUSD(s.suggested_cost_usd)}
              </td>
              <td className="py-1.5 text-right font-medium tabular-nums text-success">
                {fmtUSD(s.savings_usd)}
              </td>
              <td className="py-1.5 pl-3">
                <span className="flex flex-wrap gap-1">
                  {s.reasons.map((r) => (
                    <Pill key={r}>{r}</Pill>
                  ))}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ----------------------------------------------------- Task tracking

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
        <div className="overflow-x-auto">
          <table className="w-full min-w-[480px] text-left text-[11.5px]">
            <thead className="text-[10px] uppercase tracking-[0.06em] text-fg-3">
              <tr className="border-b border-line-2">
                <th className="py-1.5 pl-2 font-medium">Tool</th>
                <th className="py-1.5 text-right font-medium">Sessions</th>
                <th className="py-1.5 text-right font-medium">Tasks</th>
                <th className="py-1.5 pr-2 text-right font-medium">Cost</th>
              </tr>
            </thead>
            <tbody>
              {data.by_tool.map((t) => (
                <tr
                  key={t.tool}
                  className="border-b border-line-1 last:border-b-0 hover:bg-bg-3/40"
                >
                  <td className="py-1.5 pl-2">
                    <ToolBadge tool={t.tool} />
                  </td>
                  <td className="py-1.5 text-right tabular-nums text-fg-2">
                    {fmtInt(t.sessions)}
                  </td>
                  <td className="py-1.5 text-right tabular-nums text-fg-2">
                    {fmtInt(t.tasks)}
                  </td>
                  <td className="py-1.5 pr-2 text-right tabular-nums text-fg-1">
                    {t.unpriced ? (
                      <span className="text-fg-3">unpriced</span>
                    ) : (
                      fmtTaskUSD(t.cost_usd)
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
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
