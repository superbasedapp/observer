import { useMemo } from "react";
import { Link } from "react-router-dom";
import {
  ChartShell,
  PageHeader,
  Pill,
  ReliabilityPill,
  StatCard,
  Tooltip,
} from "@/components/primitives";
import { HelpInd, TitleWithHelp } from "@/components/HelpInd";
import {
  BoltIcon,
  CoinsIcon,
  DatabaseIcon,
  DropletIcon,
  SparklesIcon,
} from "@/components/icons";
import {
  CacheSavingsChart,
  TokensByDayChart,
  TokensByModelChart,
} from "@/components/charts";
import { ChartState } from "@/components/ChartState";
import { BudgetCard } from "@/components/BudgetCard";
import { LOCPerDollarTile } from "@/components/LOCPerDollarTile";
import { HeroWordmark } from "@/components/HeroWordmark";
import {
  useFilters,
  windowDaysApprox,
  windowLabel,
  windowParams,
  windowSpanHours,
} from "@/lib/filters";
import { useApi } from "@/lib/useApi";
import { fmtCompact, fmtInt, fmtPct, fmtUSD } from "@/lib/format";
import type {
  AnalysisCacheSavingsTrend,
  CostSummary,
  CostTimeseries,
  CoworkReconcileResult,
  SessionCacheAnnotation,
  TokensByModelTimeseries,
} from "@/lib/types";

export function CostPage() {
  const { win, customRange, tool, project } = useFilters();
  const winParams = windowParams(win, customRange);
  const bucket = windowSpanHours(win, customRange) <= 48 ? "hour" : "day";
  const winLbl = windowLabel(win, customRange);
  // /api/loc/summary is day-granular only, so the LOC-per-$ tile takes the
  // window rounded up to whole days and fetches its own denominator at the
  // same day count rather than reusing this page's filtered cost.
  const locDays = windowDaysApprox(win, customRange);
  const projectParam = project === "all" ? undefined : project;
  const toolParam = tool === "all" ? undefined : tool;

  const models = useApi<CostSummary>(
    "/api/models",
    { ...winParams, tool: toolParam, project: projectParam },
    [win, customRange, tool, project],
  );
  const costTs = useApi<CostTimeseries>(
    "/api/timeseries/cost",
    { ...winParams, bucket, tool: toolParam, project: projectParam },
    [win, customRange, tool, project],
  );
  const tokensByModel = useApi<TokensByModelTimeseries>(
    "/api/timeseries/tokens-by-model",
    { ...winParams, tool: toolParam, project: projectParam },
    [win, customRange, tool, project],
  );
  const cacheSavings = useApi<AnalysisCacheSavingsTrend>(
    "/api/analysis/cache-savings-trend",
    { ...winParams, tool: toolParam, project: projectParam },
    [win, customRange, tool, project],
  );
  const cowork = useApi<CoworkReconcileResult>("/api/cowork/reconcile");

  const summary = useMemo(() => summarize(models.data), [models.data]);
  const sparks = useMemo(() => deriveSparks(costTs.data), [costTs.data]);

  return (
    <div className="space-y-6 p-6">
      <PageHeader
        title="Cost"
        sub="Per-model token consumption split into the four billable buckets - net input, cache read, cache write, output - with computed cost. Hover any column header for the formula."
        helpId="tab.cost"
        right={
          <Link
            to="/report"
            className="shrink-0 text-[11px] font-medium text-accent hover:text-accent-strong"
          >
            Monthly statement →
          </Link>
        }
      />
      {/* Summary band — 6 KPIs matching design: Total / API Turns /
          Net Input / Cache R / Cache W / Output. Reasoning surfaces
          as a 7th tile only when present (e.g. captured antigravity
          rows expose reasoning_tokens distinctly; Anthropic folds it
          into output and so this tile renders 0 / hidden there). */}
      <div
        className={`relative grid grid-cols-2 gap-3 pb-4 md:grid-cols-3 ${(summary.reasoning ?? 0) > 0 ? "xl:grid-cols-7" : "xl:grid-cols-6"}`}
      >
        {/* Camera-ready pass (growth-review §4): this hero band is the
            surface people screenshot for "what my AI coding actually
            costs" posts — a subtle corner wordmark survives that crop. */}
        <HeroWordmark />
        <StatCard
          label={`Total spend (${winLbl})`}
          helpId="metric.cost_usd"
          icon={<CoinsIcon />}
          loading={models.loading || costTs.loading}
          value={fmtUSD(summary.cost)}
          sub={summary.reliability || "-"}
          spark={sparks.cost}
          sparkColor="var(--accent)"
          accent
        />
        <StatCard
          label="API Turns"
          helpId="tile.api_turns"
          icon={<BoltIcon />}
          loading={costTs.loading}
          value={fmtInt(summary.turns)}
          sub="accurate token source"
          spark={sparks.turns}
          sparkColor="var(--info)"
        />
        <StatCard
          label="Net Input"
          helpId="metric.net_input"
          icon={<DatabaseIcon />}
          loading={costTs.loading || models.loading}
          value={fmtCompact(summary.tokens.input)}
          sub="tokens"
          spark={sparks.input}
          sparkColor="var(--tok-net)"
        />
        <StatCard
          label="Cache Read"
          helpId="metric.cache_read"
          icon={<DropletIcon />}
          loading={costTs.loading || models.loading}
          value={fmtCompact(summary.tokens.cache_read)}
          sub={`${fmtPct(summary.cacheEfficacy)} efficacy`}
          spark={sparks.cacheRead}
          sparkColor="var(--tok-read)"
        />
        <StatCard
          label="Cache Write"
          helpId="metric.cache_creation"
          icon={<DropletIcon />}
          loading={costTs.loading || models.loading}
          value={fmtCompact(summary.tokens.cache_creation)}
          sub="setup overhead"
          spark={sparks.cacheWrite}
          sparkColor="var(--tok-write)"
        />
        <StatCard
          label="Output"
          helpId="metric.output"
          icon={<SparklesIcon />}
          loading={costTs.loading || models.loading}
          value={fmtCompact(summary.tokens.output)}
          sub="response tokens"
          spark={sparks.output}
          sparkColor="var(--tok-out)"
        />
        {(summary.reasoning ?? 0) > 0 && (
          <StatCard
            label="Reasoning"
            icon={<SparklesIcon />}
            loading={models.loading}
            value={fmtCompact(summary.reasoning)}
            sub="billed at output rate"
            spark={sparks.output}
            sparkColor="var(--act-agent)"
          />
        )}
      </div>

      {/* Budget guardrails (P6.3) — advisory monthly budgets with
          80/100% thresholds and a month-end forecast. */}
      <BudgetCard />

      {/* AI code lines per dollar (lines-of-code tracking §3.4). Lives on
          Cost because the denominator is this page's own subject and its
          window control is already here; on Overview it would be a cost
          question on a health page. */}
      <LOCPerDollarTile
        days={locDays}
        windowLabel={winLbl}
        filtered={tool !== "all" || project !== "all"}
      />

      {/* Model table — unknown-model warning + Group/Export controls
          in panel header per design 1.13 / dC5. */}
      <ChartShell
        title="Cost by model"
        sub={`Top ${fmtInt(models.data?.rows.length)} · per-bucket share, cost reliability, source · ${winLbl}`}
        right={
          <div className="flex items-center gap-2">
            {(models.data?.fast_turn_count ?? 0) > 0 && (
              <Tooltip content="Turns served in a provider's low-latency fast tier - Anthropic Opus 4.8 (speed:&quot;fast&quot;) or OpenAI/Codex (service_tier:&quot;priority&quot;), billed at the model's fast-mode premium (2×–2.5×). Cost shown already includes the premium.">
                <span className="inline-flex items-center gap-1.5 rounded-2 border border-info/40 bg-info-soft px-2.5 py-1 text-[10.5px] font-medium text-info">
                  <span aria-hidden>⚡</span>
                  {fmtInt(models.data?.fast_turn_count)} fast-tier turn
                  {(models.data?.fast_turn_count ?? 0) === 1 ? "" : "s"} ·{" "}
                  {fmtUSD(models.data?.total_fast_cost_usd ?? 0)}
                </span>
              </Tooltip>
            )}
            {(models.data?.unknown_model_count ?? 0) > 0 && (
              <Tooltip content="Open Settings → Pricing to add overrides">
                <Link
                  to="/settings"
                  className="inline-flex items-center gap-2 rounded-2 border border-warn/40 bg-warn-soft px-2.5 py-1 text-[10.5px] font-medium text-warn hover:bg-warn-soft/80"
                >
                  <span aria-hidden>!</span>
                  {fmtInt(models.data?.unknown_model_count)} unknown model
                  {(models.data?.unknown_model_count ?? 0) === 1 ? "" : "s"} ·
                  add pricing override →
                </Link>
              </Tooltip>
            )}
            <Tooltip content="Download per-model cost table as CSV">
              <button
                type="button"
                onClick={() => exportModelsCsv(models.data)}
                disabled={!models.data?.rows.length}
                className="rounded-2 border border-line-2 bg-bg-2 px-2 py-1 text-[10.5px] text-fg-2 hover:bg-bg-3 disabled:opacity-40"
              >
                Export
              </button>
            </Tooltip>
          </div>
        }
      >
        <ChartState
          loading={models.loading}
          error={models.error}
          empty={!models.data?.rows.length}
          emptyHint="No model data in this window."
        >
          {models.data && (
            <ModelTable rows={models.data.rows} cacheByKey={models.data.cache_by_key} />
          )}
        </ChartState>
      </ChartShell>

      {/* Two time-series side by side */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <ChartShell
          title={<TitleWithHelp text="Token volume per day" helpId="chart.token_volume_per_day" />}
          sub={`Stacked by Anthropic billing bucket · ${winLbl}`}
        >
          <ChartState
            loading={costTs.loading}
            error={costTs.error}
            empty={!costTs.data?.series.length}
            emptyHint="No cost data."
          >
            {costTs.data && <TokensByDayChart data={costTs.data.series} />}
          </ChartState>
        </ChartShell>

        <ChartShell
          title={<TitleWithHelp text="Token volume per day · by model" helpId="chart.token_volume_by_model" />}
          sub={`Top 6 models · ${winLbl}`}
        >
          <ChartState
            loading={tokensByModel.loading}
            error={tokensByModel.error}
            empty={!tokensByModel.data?.series.length}
            emptyHint="No model-attributed data."
          >
            {tokensByModel.data && (
              <TokensByModelChart data={tokensByModel.data.series} />
            )}
          </ChartState>
        </ChartShell>
      </div>

      {/* Cache savings trend */}
      <ChartShell
        title={<TitleWithHelp text="Cache savings trend" helpId="chart.analysis_cache_savings_trend" />}
        sub="Counterfactual: cache_read priced at input rate vs cache_read rate"
      >
        <ChartState
          loading={cacheSavings.loading}
          error={cacheSavings.error}
          empty={!cacheSavings.data?.points.length}
          emptyHint="No cache-read traffic in window."
          height={180}
        >
          {cacheSavings.data && (
            <CacheSavingsChart data={cacheSavings.data.points} />
          )}
        </ChartState>
      </ChartShell>

      {/* Cowork reconciliation — render only when there's data */}
      {cowork.data && cowork.data.sessions_total > 0 && (
        <CoworkReconcileCard data={cowork.data} />
      )}
    </div>
  );
}

// Build a CSV from the current per-model rows and trigger a browser
// download. Mirrors the legacy "Export Excel" affordance but emits
// CSV (lighter, no xlsx dep) so the user can pivot in Numbers/Sheets.
function exportModelsCsv(summary?: CostSummary | null) {
  if (!summary?.rows?.length) return;
  const header = [
    "model",
    "input_tokens",
    "cache_read_tokens",
    "cache_creation_tokens",
    "output_tokens",
    "reasoning_tokens",
    "turn_count",
    "ai_cost_usd",
    "tool_cost_usd",
    "total_cost_usd",
    "source",
    "reliability",
  ].join(",");
  const lines = summary.rows.map((r) =>
    [
      escapeCsv(r.key),
      r.tokens.input,
      r.tokens.cache_read,
      r.tokens.cache_creation,
      r.tokens.output,
      r.tokens.reasoning || 0,
      r.turn_count,
      r.ai_cost_usd,
      r.tool_cost_usd,
      r.cost_usd,
      escapeCsv(r.source),
      escapeCsv(r.reliability),
    ].join(","),
  );
  const csv = [header, ...lines].join("\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `cost-by-model-${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function escapeCsv(s: string | undefined): string {
  if (!s) return "";
  if (/[",\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

function deriveSparks(ts?: CostTimeseries | null) {
  const series = ts?.series ?? [];
  return {
    cost: series.map((p) => p.cost_usd || 0),
    turns: series.map((p) => p.turn_count || 0),
    input: series.map((p) => p.input || 0),
    cacheRead: series.map((p) => p.cache_read || 0),
    cacheWrite: series.map((p) => p.cache_creation || 0),
    output: series.map((p) => p.output || 0),
  };
}

// Honesty rule (mirrors Overview.tsx's status.error / discover.data
// pattern): a falsy `s` means "we don't have a resolved answer yet"
// - either still loading or the query failed - never "the answer is
// zero". Returning `undefined` fields here (instead of the old
// all-zero object) lets fmtUSD/fmtInt/fmtCompact/fmtPct - which are
// already null-safe, see lib/format.ts - render "-" for every tile
// below rather than a confident "$0.00" while nothing has loaded.
// Once `s` resolves, a genuine zero renders as a genuine zero.
function summarize(s?: CostSummary | null) {
  if (!s) {
    return {
      cost: undefined as number | undefined,
      turns: undefined as number | undefined,
      tokens: {
        input: undefined as number | undefined,
        output: undefined as number | undefined,
        cache_read: undefined as number | undefined,
        cache_creation: undefined as number | undefined,
        cache_creation_1h: undefined as number | undefined,
        reasoning: undefined as number | undefined,
        web_search_requests: undefined as number | undefined,
      },
      reliability: "",
      cacheEfficacy: undefined as number | undefined,
      reasoning: undefined as number | undefined,
    };
  }
  const t = s.total_tokens;
  const cacheTotal = (t.cache_read || 0) + (t.cache_creation || 0);
  const cacheEfficacy = cacheTotal > 0 ? (t.cache_read || 0) / cacheTotal : 0;
  return {
    cost: s.total_cost_usd,
    turns: s.turn_count,
    tokens: t,
    reliability: s.reliability,
    cacheEfficacy,
    reasoning: t.reasoning || 0,
  };
}

// ------------------------------------------------------------ ModelTable

function ModelTable({
  rows,
  cacheByKey,
}: {
  rows: CostSummary["rows"];
  cacheByKey?: CostSummary["cache_by_key"];
}) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[1240px] text-left text-[11.5px]">
        <thead className="text-[10px] uppercase tracking-[0.06em] text-fg-3">
          <tr className="border-b border-line-2">
            <Th>Model<HelpInd id="column.cost.model" /></Th>
            <Th align="right">Net %<HelpInd id="column.cost.net_in" /></Th>
            <Th align="right">Cache R %<HelpInd id="column.cost.cache_r" /></Th>
            <Th align="right">Cache W %<HelpInd id="column.cost.cache_w" /></Th>
            <Th align="right">Out %<HelpInd id="column.cost.output" /></Th>
            <Th align="right">Net Input<HelpInd id="column.cost.net_in" /></Th>
            <Th align="right">Cache Read<HelpInd id="column.cost.cache_r" /></Th>
            <Th align="right">Cache Write<HelpInd id="column.cost.cache_w" /></Th>
            <Th align="right">Output<HelpInd id="column.cost.output" /></Th>
            <Th align="right">Reasoning</Th>
            <Th align="right">Turns<HelpInd id="column.cost.turns" /></Th>
            <Th align="right">AI $<HelpInd id="column.cost.cost" /></Th>
            <Th align="right">Tool $<HelpInd id="column.cost.cost" /></Th>
            <Th align="right">Total $<HelpInd id="column.cost.cost" /></Th>
            <Th>Source<HelpInd id="column.cost.source" /></Th>
            <Th>Reliability<HelpInd id="column.cost.reliab" /></Th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <ModelRow
              key={r.key}
              row={r}
              zebra={i % 2 === 1}
              cache={cacheByKey?.[r.key]}
            />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function MixCell({ pct, color }: { pct: number; color: string }) {
  return (
    <td className="px-2 py-1.5 text-right">
      <div className="ml-auto flex max-w-[88px] items-center justify-end gap-2">
        <div className="h-1.5 w-12 overflow-hidden rounded-pill bg-bg-3">
          <span
            className="block h-full"
            style={{ width: `${pct * 100}%`, background: color }}
          />
        </div>
        <span className="tabular-nums text-fg-2">{fmtPct(pct)}</span>
      </div>
    </td>
  );
}

function ModelRow({
  row,
  zebra,
  cache,
}: {
  row: CostSummary["rows"][number];
  zebra?: boolean;
  cache?: SessionCacheAnnotation;
}) {
  const t = row.tokens;
  const total =
    (t.input || 0) +
    (t.output || 0) +
    (t.cache_read || 0) +
    (t.cache_creation || 0);
  const mix = {
    net: total > 0 ? (t.input || 0) / total : 0,
    read: total > 0 ? (t.cache_read || 0) / total : 0,
    write: total > 0 ? (t.cache_creation || 0) / total : 0,
    out: total > 0 ? (t.output || 0) / total : 0,
  };
  return (
    <tr
      className={
        "border-b border-line-1 last:border-b-0 hover:bg-bg-3 " +
        (zebra ? "bg-bg-3/40" : "")
      }
    >
      <Td>
        <span className="inline-flex items-center gap-1.5">
          <span className="font-mono font-semibold text-fg-0">{row.key}</span>
          {(row.fast_turn_count ?? 0) > 0 && (
            <Tooltip
              content={
                <span>
                  {row.fast_turn_count} fast-tier turn
                  {row.fast_turn_count === 1 ? "" : "s"} (Anthropic{" "}
                  <code>speed:&quot;fast&quot;</code> / Codex{" "}
                  <code>service_tier:&quot;priority&quot;</code>) ·{" "}
                  {fmtUSD(row.fast_cost_usd ?? 0)} at the model's fast-mode premium
                </span>
              }
              maxWidth={320}
            >
              <span tabIndex={0} className="cursor-help focus:outline-none">
                <Pill variant="info" title="fast-tier spend (premium price)">
                  ⚡ {row.fast_turn_count}
                </Pill>
              </span>
            </Tooltip>
          )}
          {cache && cache.event_count > 0 && (
            <CacheAnnotationPill cache={cache} />
          )}
        </span>
      </Td>
      <MixCell pct={mix.net} color="var(--tok-net)" />
      <MixCell pct={mix.read} color="var(--tok-read)" />
      <MixCell pct={mix.write} color="var(--tok-write)" />
      <MixCell pct={mix.out} color="var(--tok-out)" />
      <Td align="right" mono>
        {fmtCompact(t.input)}
      </Td>
      <Td align="right" mono>
        {fmtCompact(t.cache_read)}
      </Td>
      <Td align="right" mono>
        {fmtCompact(t.cache_creation)}
      </Td>
      <Td align="right" mono>
        {fmtCompact(t.output)}
      </Td>
      <Td align="right" mono>
        {t.reasoning > 0 ? fmtCompact(t.reasoning) : "-"}
      </Td>
      <Td align="right" mono>
        {fmtInt(row.turn_count)}
      </Td>
      <Td align="right" mono>
        {fmtUSD(row.ai_cost_usd)}
      </Td>
      <Td align="right" mono>
        {row.tool_cost_usd > 0 ? fmtUSD(row.tool_cost_usd) : "-"}
      </Td>
      <Td align="right" mono>
        <strong className="text-fg-0">{fmtUSD(row.cost_usd)}</strong>
      </Td>
      <Td>
        <SourcePill source={row.source} />
      </Td>
      <Td>
        <ReliabilityPill value={row.reliability} />
      </Td>
    </tr>
  );
}

function SourcePill({ source }: { source: string }) {
  switch (source) {
    case "proxy":
      return <Pill variant="info">proxy</Pill>;
    case "jsonl":
      return <Pill>jsonl</Pill>;
    case "mixed":
      return <Pill variant="warn">mixed</Pill>;
    default:
      return <Pill>-</Pill>;
  }
}

function Th({
  children,
  align,
}: {
  children: React.ReactNode;
  align?: "left" | "right";
}) {
  return (
    <th
      className={
        "px-2 py-1.5 font-medium " +
        (align === "right" ? "text-right" : "text-left")
      }
    >
      {children}
    </th>
  );
}

function Td({
  children,
  align,
  mono,
}: {
  children: React.ReactNode;
  align?: "left" | "right";
  mono?: boolean;
}) {
  return (
    <td
      className={
        "px-2 py-1.5 " +
        (align === "right" ? "text-right tabular-nums " : "") +
        (mono ? "font-mono text-fg-2 " : "text-fg-1")
      }
    >
      {children}
    </td>
  );
}

// ----------------------------------------------------- Cowork card

function CoworkReconcileCard({ data }: { data: CoworkReconcileResult }) {
  return (
    <ChartShell
      title="Cowork cost reconciliation"
      sub={`SuperBased-derived vs Cowork-authoritative spend · drift threshold ${data.drift_threshold_percent.toFixed(1)}%`}
    >
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <StatCard
          label="Cowork sessions"
          value={fmtInt(data.sessions_total)}
          sub={`${data.sessions_over_threshold} over threshold`}
          warn={data.sessions_over_threshold > 0}
        />
        <StatCard
          label="Cowork total"
          value={fmtUSD(data.cowork_total_usd)}
          sub="authoritative"
        />
        <StatCard
          label="SuperBased derived"
          value={fmtUSD(data.derived_total_usd)}
          sub="pricing-table × tokens"
        />
        <StatCard
          label="Drift"
          value={fmtUSD(data.overall_drift_usd)}
          sub={fmtPct(data.overall_drift_percent, 1, false)}
          warn={Math.abs(data.overall_drift_percent) > data.drift_threshold_percent}
        />
      </div>

      <div className="mt-4 overflow-x-auto">
        <table className="w-full min-w-[760px] text-left text-[11.5px]">
          <thead className="text-[10px] uppercase tracking-[0.06em] text-fg-3">
            <tr className="border-b border-line-2">
              <Th>Process</Th>
              <Th>Title</Th>
              <Th align="right">Cowork $</Th>
              <Th align="right">SuperBased $</Th>
              <Th align="right">Δ $</Th>
              <Th align="right">Δ %</Th>
            </tr>
          </thead>
          <tbody>
            {data.rows.slice(0, 30).map((r) => (
              <tr
                key={r.session_id}
                className="border-b border-line-1 last:border-b-0 hover:bg-bg-3/40"
              >
                <Td mono>{r.process_name || "-"}</Td>
                <Td>
                  <span className="line-clamp-1 max-w-[280px] text-fg-2">
                    {r.title || <em className="text-fg-4">-</em>}
                  </span>
                </Td>
                <Td align="right" mono>
                  {fmtUSD(r.cowork_cost_usd)}
                </Td>
                <Td align="right" mono>
                  {fmtUSD(r.derived_cost_usd)}
                </Td>
                <Td align="right" mono>
                  <span
                    className={
                      r.drift_usd > 0
                        ? "text-danger"
                        : r.drift_usd < 0
                          ? "text-success"
                          : "text-fg-2"
                    }
                  >
                    {fmtUSD(r.drift_usd)}
                  </span>
                </Td>
                <Td align="right" mono>
                  <span className={r.over_threshold ? "text-warn" : "text-fg-2"}>
                    {fmtPct(r.drift_percent, 1, false)}
                  </span>
                </Td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </ChartShell>
  );
}

// CacheAnnotationPill renders the spec §13 cost-view cache
// annotation inline with the Model column. Compact pill: ratio
// + event count, tooltip carries the full hit/write/rewrite/
// mispredict breakdown. Pill variant follows operator UI steer
// #2: flagged rewrites surface a NEUTRAL pill (legitimate MCP
// toggles); real rewrites surface the warn variant; hit-
// dominated rows render info.
function CacheAnnotationPill({ cache }: { cache: SessionCacheAnnotation }) {
  const ratio = cache.ratio > 0 ? `${cache.ratio.toFixed(1)}×` : "-";
  let variant: "info" | "neutral" | "warn" = "info";
  if (cache.has_flagged_rewrites) {
    variant = "neutral";
  } else if (cache.rewrite_count > 0) {
    variant = "warn";
  }
  const labelKindCounts = [
    cache.hit_count && `${fmtInt(cache.hit_count)} hit`,
    cache.write_count && `${fmtInt(cache.write_count)} write`,
    cache.rewrite_count && `${fmtInt(cache.rewrite_count)} rewrite`,
    cache.mispredict_count &&
      (cache.zero_usage_count === cache.mispredict_count
        ? `${fmtInt(cache.mispredict_count)} zero-usage misp`
        : `${fmtInt(cache.mispredict_count)} mispredict`),
  ]
    .filter(Boolean)
    .join(" · ");
  return (
    <Tooltip
      content={
        <span>
          Cache · {ratio} R/W · {fmtInt(cache.event_count)} events ·{" "}
          {labelKindCounts || "no events"}
          {cache.has_flagged_rewrites && (
            <>
              <br />
              <em className="text-fg-3">
                flagged rewrites present (e.g. tools_changed on MCP server
                toggle); cause is correct but alert level is reduced.
              </em>
            </>
          )}
        </span>
      }
      maxWidth={360}
    >
      <span tabIndex={0} className="cursor-help focus:outline-none">
        <Pill variant={variant} title="cache events">
          🗄️ {ratio}
        </Pill>
      </span>
    </Tooltip>
  );
}
