import { hasNonZero } from "@shared/lib/seriesEmpty";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import type { ColumnDef } from "@tanstack/react-table";
import { DataTable } from "@/components/DataTable";
import {
  Button,
  ChartShell,
  Icon,
  ModelId,
  PageHeader,
  Pill,
  ReliabilityPill,
  SegmentedControl,
  StatCard,
  Tooltip,
  Stagger,
  Table,
} from "@/components/primitives";
import { HelpInd, TitleWithHelp } from "@/components/HelpInd";
import {
  CacheSavingsChart,
  CostAreaChart,
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
  useGranularity,
} from "@/lib/filters";
import { GranControl } from "@/components/GranControl";
import { asGranularity, granularityUnit, perBucketTitle } from "@shared/lib/granularity";
import { useApi } from "@/lib/useApi";
import { fmtCompact, fmtInt, fmtPct, fmtUSD } from "@/lib/format";
import { MixCell, Td, Th } from "@/components/tableCells";
import type {
  AnalysisCacheSavingsTrend,
  CostSummary,
  CostTimeseries,
  CoworkReconcileResult,
  CoworkReconcileRow,
  SessionCacheAnnotation,
  TokensByModelTimeseries,
} from "@/lib/types";
import {
  ChartColumn,
  ChartColumnStacked,
  ChartLine,
  DatabaseZap,
  Download,
  Scale,
  Table2,
  TriangleAlert,
  Zap,
  type LucideIcon,
} from "lucide-react";
import { SOURCE_TIER } from "@shared/lib/sourceVocab";
import { cacheSummaryTone } from "@shared/lib/cacheVocab";
import { VocabPill } from "@shared/lib/vocabPill";
import { navIcon } from "@/lib/nav";
import { MetricIcon } from "@/components/MetricIcon";

// One glyph per cost section card title (the ChartShell `icon` slot): the
// chart or table shape the section shows, never decoration.
const SECTION_ICONS = {
  costByModel: Table2,
  perDay: ChartColumnStacked,
  volumeByModel: ChartColumn,
  cacheSavingsTrend: ChartLine,
  coworkReconcile: Scale,
} satisfies Record<string, LucideIcon>;

export function CostPage() {
  const { win, customRange, tool, project } = useFilters();
  const winParams = windowParams(win, customRange);
  // Chart bucket: the shared granularity rule + the viewer's `gran=`
  // choice (lib/filters.tsx useGranularity), never an inline threshold.
  const gran = useGranularity();
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
    { ...winParams, ...gran.params, tool: toolParam, project: projectParam },
    [win, customRange, tool, project, gran.params],
  );
  // Per-bucket chart: token volume (default) or dollars per bucket.
  const [dailyMode, setDailyMode] = useState<"tokens" | "cost">("tokens");
  const tokensByModel = useApi<TokensByModelTimeseries>(
    "/api/timeseries/tokens-by-model",
    { ...winParams, ...gran.params, tool: toolParam, project: projectParam },
    [win, customRange, tool, project, gran.params],
  );
  const cacheSavings = useApi<AnalysisCacheSavingsTrend>(
    "/api/analysis/cache-savings-trend",
    { ...winParams, ...gran.params, tool: toolParam, project: projectParam },
    [win, customRange, tool, project, gran.params],
  );
  const costGran = asGranularity(costTs.data?.bucket ?? gran.expected);
  const modelGran = asGranularity(tokensByModel.data?.bucket ?? gran.expected);
  const savingsGran = asGranularity(cacheSavings.data?.bucket ?? gran.expected);
  const cowork = useApi<CoworkReconcileResult>("/api/cowork/reconcile");

  const summary = useMemo(() => summarize(models.data), [models.data]);
  const sparks = useMemo(() => deriveSparks(costTs.data), [costTs.data]);

  return (
    <div className="space-y-6 p-4 sm:p-6">
      <PageHeader
        icon={navIcon("cost")}
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
          icon={<MetricIcon metric="spend" />}
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
          icon={<MetricIcon metric="apiTurns" />}
          loading={costTs.loading}
          value={fmtInt(summary.turns)}
          sub="accurate token source"
          spark={sparks.turns}
          sparkColor="var(--info)"
        />
        <StatCard
          label="Net Input"
          helpId="metric.net_input"
          icon={<MetricIcon metric="netInput" />}
          loading={costTs.loading || models.loading}
          value={fmtCompact(summary.tokens.input)}
          sub="tokens"
          spark={sparks.input}
          sparkColor="var(--tok-net)"
        />
        <StatCard
          label="Cache Read"
          helpId="metric.cache_read"
          icon={<MetricIcon metric="cacheRead" />}
          loading={costTs.loading || models.loading}
          value={fmtCompact(summary.tokens.cache_read)}
          sub={`${fmtPct(summary.cacheEfficacy)} efficacy`}
          spark={sparks.cacheRead}
          sparkColor="var(--tok-read)"
        />
        <StatCard
          label="Cache Write"
          helpId="metric.cache_creation"
          icon={<MetricIcon metric="cacheWrite" />}
          loading={costTs.loading || models.loading}
          value={fmtCompact(summary.tokens.cache_creation)}
          sub="setup overhead"
          spark={sparks.cacheWrite}
          sparkColor="var(--tok-write)"
        />
        <StatCard
          label="Output"
          helpId="metric.output"
          icon={<MetricIcon metric="output" />}
          loading={costTs.loading || models.loading}
          value={fmtCompact(summary.tokens.output)}
          sub="response tokens"
          spark={sparks.output}
          sparkColor="var(--tok-out)"
        />
        {(summary.reasoning ?? 0) > 0 && (
          <StatCard
            label="Reasoning"
            icon={<MetricIcon metric="reasoning" />}
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
        icon={SECTION_ICONS.costByModel}
        sub={`Top ${fmtInt(models.data?.rows.length)} · per-bucket share, cost reliability, source · ${winLbl}`}
        right={
          <div className="flex items-center gap-2">
            {(models.data?.fast_turn_count ?? 0) > 0 && (
              <Tooltip content="Turns served in a provider's low-latency fast tier - Anthropic Opus 4.8 (speed:&quot;fast&quot;) or OpenAI/Codex (service_tier:&quot;priority&quot;), billed at the model's fast-mode premium (2×–2.5×). Cost shown already includes the premium.">
                <span tabIndex={0} className="inline-flex items-center gap-1.5 rounded-2 border border-info/40 bg-info-soft px-2.5 py-1 text-[10.5px] font-medium text-info focus:outline-none focus-visible:ring-2 focus-visible:ring-accent-ring">
                  <Icon icon={Zap} size="xs" />
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
                  <Icon icon={TriangleAlert} size="xs" className="shrink-0" />
                  {fmtInt(models.data?.unknown_model_count)} unknown model
                  {(models.data?.unknown_model_count ?? 0) === 1 ? "" : "s"} ·
                  add pricing override →
                </Link>
              </Tooltip>
            )}
            <Tooltip content="Download per-model cost table as CSV">
              <Button
                size="sm"
                iconLeft={Download}
                onClick={() => exportModelsCsv(models.data)}
                disabled={!models.data?.rows.length}
              >
                Export
              </Button>
            </Tooltip>
          </div>
        }
      >
        <ChartState
          loading={models.loading}
          stale={models.isStale}
          onRetry={models.reload}
          error={models.error}
          denied={models.denied}
          deniedPermission={models.deniedPermission}
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
          title={
            <TitleWithHelp
              text={
                dailyMode === "cost"
                  ? perBucketTitle("Spend", costGran)
                  : perBucketTitle("Token volume", costGran)
              }
              helpId="chart.token_volume_per_day"
            />
          }
          icon={SECTION_ICONS.perDay}
          sub={
            dailyMode === "cost"
              ? `Priced cost in dollars · ${winLbl}`
              : `Stacked by Anthropic billing bucket · ${winLbl}`
          }
          right={
            <div className="flex flex-wrap items-center gap-2">
              <GranControl served={costTs.data} />
              <SegmentedControl<"tokens" | "cost">
                options={[
                  { value: "tokens", label: "Tokens" },
                  { value: "cost", label: `$ / ${granularityUnit(costGran)}` },
                ]}
                value={dailyMode}
                onChange={setDailyMode}
                size="sm"
              />
            </div>
          }
        >
          <ChartState
            loading={costTs.loading}
            stale={costTs.isStale}
            onRetry={costTs.reload}
            error={costTs.error}
            denied={costTs.denied}
            deniedPermission={costTs.deniedPermission}
            empty={!hasNonZero(costTs.data?.series, ["turn_count"])}
            emptyHint="No cost data."
          >
            {costTs.data &&
              (dailyMode === "cost" ? (
                <CostAreaChart data={costTs.data.series} mode="cost" granularity={costGran} />
              ) : (
                <TokensByDayChart data={costTs.data.series} granularity={costGran} />
              ))}
          </ChartState>
        </ChartShell>

        <ChartShell
          title={
            <TitleWithHelp
              text={`${perBucketTitle("Token volume", modelGran)} · by model`}
              helpId="chart.token_volume_by_model"
            />
          }
          icon={SECTION_ICONS.volumeByModel}
          sub={`Top 6 models · ${winLbl}`}
          right={<GranControl served={tokensByModel.data} />}
        >
          <ChartState
            loading={tokensByModel.loading}
            stale={tokensByModel.isStale}
            onRetry={tokensByModel.reload}
            error={tokensByModel.error}
            denied={tokensByModel.denied}
            deniedPermission={tokensByModel.deniedPermission}
            empty={!tokensByModel.data?.series.length}
            emptyHint="No model-attributed data."
          >
            {tokensByModel.data && (
              <TokensByModelChart
                data={tokensByModel.data.series}
                grid={tokensByModel.data.grid}
                granularity={modelGran}
              />
            )}
          </ChartState>
        </ChartShell>
      </div>

      {/* Cache savings trend */}
      <ChartShell
        title={<TitleWithHelp text="Cache savings trend" helpId="chart.analysis_cache_savings_trend" />}
        icon={SECTION_ICONS.cacheSavingsTrend}
        sub={`${perBucketTitle("Saved", savingsGran)} · counterfactual: cache_read priced at input rate vs cache_read rate`}
        right={<GranControl served={cacheSavings.data} />}
      >
        <ChartState
          loading={cacheSavings.loading}
          stale={cacheSavings.isStale}
          onRetry={cacheSavings.reload}
          error={cacheSavings.error}
          denied={cacheSavings.denied}
          deniedPermission={cacheSavings.deniedPermission}
          empty={!hasNonZero(cacheSavings.data?.points, ["cache_read_tokens"])}
          emptyHint="No cache-read traffic in window."
          height={180}
        >
          {cacheSavings.data && (
            <CacheSavingsChart data={cacheSavings.data.points} granularity={savingsGran} />
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
    <Table
      minWidth={1240}
      zebra
      head={
        <tr>
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
      }
    >
      {rows.map((r) => (
        <ModelRow key={r.key} row={r} cache={cacheByKey?.[r.key]} />
      ))}
    </Table>
  );
}

function ModelRow({
  row,
  cache,
}: {
  row: CostSummary["rows"][number];
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
    <tr className="border-b border-line-1 last:border-b-0">
      <Td>
        <span className="inline-flex items-center gap-1.5">
          <ModelId model={row.key} className="min-w-0 font-semibold" />
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
                <Pill variant="info" icon={Zap} title="fast-tier spend (premium price)">
                  {row.fast_turn_count}
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

// SourcePill renders the token capture source with the ONE capture-tier
// tone (@shared/lib/sourceVocab) and glyph; an absent source is a dash.
function SourcePill({ source }: { source: string }) {
  if (!source) return <Pill>-</Pill>;
  return <VocabPill vocab="sourceTier" table={SOURCE_TIER} value={source} />;
}

// ----------------------------------------------------- Cowork card

function CoworkReconcileCard({ data }: { data: CoworkReconcileResult }) {
  return (
    <ChartShell
      title="Cowork cost reconciliation"
      icon={SECTION_ICONS.coworkReconcile}
      sub={`SuperBased-derived vs Cowork-authoritative spend · drift threshold ${data.drift_threshold_percent.toFixed(1)}%`}
    >
      <Stagger className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <StatCard
          label="Cowork sessions"
          icon={<MetricIcon metric="sessions" />}
          value={fmtInt(data.sessions_total)}
          sub={`${data.sessions_over_threshold} over threshold`}
          warn={data.sessions_over_threshold > 0}
        />
        <StatCard
          label="Cowork total"
          icon={<MetricIcon metric="vendorReportedCost" />}
          value={fmtUSD(data.cowork_total_usd)}
          sub="authoritative"
        />
        <StatCard
          label="SuperBased derived"
          icon={<MetricIcon metric="derivedCost" />}
          value={fmtUSD(data.derived_total_usd)}
          sub="pricing-table × tokens"
        />
        <StatCard
          label="Drift"
          icon={<MetricIcon metric="drift" />}
          value={fmtUSD(data.overall_drift_usd)}
          sub={fmtPct(data.overall_drift_percent, 1, false)}
          warn={Math.abs(data.overall_drift_percent) > data.drift_threshold_percent}
        />
      </Stagger>

      <div className="mt-4">
        <DataTable<CoworkReconcileRow>
          data={data.rows.slice(0, 30)}
          columns={COWORK_COLUMNS}
          rowKey={(r) => r.session_id}
          minWidth={760}
        />
      </div>
    </ChartShell>
  );
}

// COWORK_COLUMNS: the server orders the reconciliation rows; every column
// sorts by its raw value on a header click.
const COWORK_COLUMNS: ColumnDef<CoworkReconcileRow, unknown>[] = [
  {
    id: "process",
    header: "Process",
    accessorFn: (r) => r.process_name || "",
    meta: { mono: true },
    cell: ({ row }) => row.original.process_name || "-",
  },
  {
    id: "title",
    header: "Title",
    accessorFn: (r) => r.title || "",
    cell: ({ row }) => (
      <span className="line-clamp-1 max-w-[280px] text-fg-2">
        {row.original.title || <em className="text-fg-4">-</em>}
      </span>
    ),
  },
  {
    id: "cowork",
    header: "Cowork $",
    accessorFn: (r) => r.cowork_cost_usd,
    meta: { align: "right", mono: true },
    cell: ({ row }) => fmtUSD(row.original.cowork_cost_usd),
  },
  {
    id: "derived",
    header: "SuperBased $",
    accessorFn: (r) => r.derived_cost_usd,
    meta: { align: "right", mono: true },
    cell: ({ row }) => fmtUSD(row.original.derived_cost_usd),
  },
  {
    id: "drift_usd",
    header: "Δ $",
    accessorFn: (r) => r.drift_usd,
    meta: { align: "right", mono: true },
    cell: ({ row }) => {
      const d = row.original.drift_usd;
      return (
        <span className={d > 0 ? "text-danger" : d < 0 ? "text-success" : "text-fg-2"}>
          {fmtUSD(d)}
        </span>
      );
    },
  },
  {
    id: "drift_pct",
    header: "Δ %",
    accessorFn: (r) => r.drift_percent,
    meta: { align: "right", mono: true },
    cell: ({ row }) => (
      <span className={row.original.over_threshold ? "text-warn" : "text-fg-2"}>
        {fmtPct(row.original.drift_percent, 1, false)}
      </span>
    ),
  },
];

// CacheAnnotationPill renders the spec §13 cost-view cache
// annotation inline with the Model column. Compact pill: ratio
// + event count, tooltip carries the full hit/write/rewrite/
// mispredict breakdown. The pill variant is cacheSummaryTone
// (@shared/lib/cacheVocab CACHE_SUMMARY_TONE_RULES): flagged
// rewrites take CACHE_FLAG's warn, other rewrites warn, and
// rewrite-free rows render info.
function CacheAnnotationPill({ cache }: { cache: SessionCacheAnnotation }) {
  const ratio = cache.ratio > 0 ? `${cache.ratio.toFixed(1)}×` : "-";
  const variant = cacheSummaryTone(cache);
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
                toggle); a known cause, worth a look if it dominates.
              </em>
            </>
          )}
        </span>
      }
      maxWidth={360}
    >
      <span tabIndex={0} className="cursor-help focus:outline-none">
        <Pill variant={variant} icon={DatabaseZap} title="cache events">
          {ratio}
        </Pill>
      </span>
    </Tooltip>
  );
}
