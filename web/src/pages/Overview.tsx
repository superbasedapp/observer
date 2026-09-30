import { hasNonZero } from "@shared/lib/seriesEmpty";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import type { ColumnDef } from "@tanstack/react-table";
import { DataTable } from "@/components/DataTable";
import {
  ActionsAreaChart,
  CostAreaChart,
  type CostAreaMode,
  TopToolsDonut,
} from "@/components/charts";
import { ChartState } from "@/components/ChartState";
import {
  Button,
  ChartShell,
  HeroStat,
  Icon,
  ModelId,
  PageHeader,
  Pill,
  SegmentedControl,
  Stagger,
  StatCard,
  ToolBadge,
  Tooltip,
  TruncatedPath,
} from "@/components/primitives";
import { HelpInd, TitleWithHelp } from "@/components/HelpInd";
import { OnboardingCard } from "@/components/OnboardingCard";
import { MilestonesCard } from "@/components/MilestonesCard";
import { CommunityCard } from "@/components/CommunityCard";
import {
  useFilters,
  windowLabel,
  windowParams,
  useGranularity,
} from "@/lib/filters";
import { useApi } from "@/lib/useApi";
import { useNowTick } from "@/lib/useNowTick";
import { modelSeriesColors } from "@/lib/models";
import {
  OVERVIEW_SECTIONS,
  loadOverviewLayout,
  moveSection,
  saveOverviewLayout,
  toggleSection,
  type OverviewLayout,
  type OverviewSectionId,
} from "@/lib/overviewLayout";
import {
  fmtCompact,
  fmtDateTime,
  fmtDuration,
  fmtInt,
  fmtUSD,
} from "@/lib/format";
import type {
  ActionsTimeseries,
  CacheOverviewResponse,
  CostSummary,
  CostTimeseries,
  DiscoverResponse,
  SessionsResponse,
  StatusScoped,
  StatusSnapshot,
  ToolsResponse,
} from "@/lib/types";
import {
  ArrowDown,
  ArrowUp,
  ChartArea,
  ChartBar,
  ChartLine,
  ChartPie,
  Settings2,
  Table2,
  type LucideIcon,
} from "lucide-react";
import { navIcon } from "@/lib/nav";
import { GranControl } from "@/components/GranControl";
import { asGranularity, perBucketTitle } from "@shared/lib/granularity";
import { cacheCauseTone } from "@shared/lib/cacheVocab";
import { MetricIcon } from "@/components/MetricIcon";

// One glyph per overview section card title (the ChartShell `icon` slot): the
// chart or table shape the section shows, never decoration.
const SECTION_ICONS = {
  costOverTime: ChartArea,
  actionsOverTime: ChartLine,
  topModels: ChartBar,
  topTools: ChartPie,
  recentSessions: Table2,
} satisfies Record<string, LucideIcon>;

export function OverviewPage() {
  const [costMode, setCostMode] = useState<CostAreaMode>(loadCostMode);
  const pickCostMode = (m: CostAreaMode) => {
    setCostMode(m);
    try {
      localStorage.setItem(COST_MODE_KEY, m);
    } catch {
      // Storage unavailable: the choice lasts this page view.
    }
  };
  const [layout, setLayout] = useState<OverviewLayout>(loadOverviewLayout);
  const updateLayout = (next: OverviewLayout) => {
    setLayout(next);
    saveOverviewLayout(next);
  };
  const { win, customRange, tool, project } = useFilters();
  const winParams = windowParams(win, customRange);
  // Chart bucket: the shared granularity rule + the viewer's `gran=` choice
  // (lib/filters.tsx useGranularity), never an inline span threshold.
  const gran = useGranularity();
  const winLbl = windowLabel(win, customRange);
  const toolParam = tool === "all" ? undefined : tool;
  const projectParam = project === "all" ? undefined : project;

  // /api/status is shared with the TopBar + Sidebar pollers through the
  // query cache: one request per tick. Its payload changes on every poll
  // (uptime is stamped per request), so the page selects the two fields it
  // reads and re-renders only when one of them changes; "last activity"
  // stays live through its own leaf tick (LastActivityAgo).
  const status = useApi<StatusSnapshot, OverviewStatusSlice>("/api/status", undefined, [], {
    select: selectOverviewStatus,
  });
  const scoped = useApi<StatusScoped>(
    "/api/status/scoped",
    { ...winParams, tool: toolParam, project: projectParam },
    [win, customRange, tool, project],
  );
  const costTs = useApi<CostTimeseries>(
    "/api/timeseries/cost",
    { ...winParams, ...gran.params, tool: toolParam, project: projectParam },
    [win, customRange, tool, project, gran.params],
  );
  const actionsTs = useApi<ActionsTimeseries>(
    "/api/timeseries/actions",
    { ...winParams, ...gran.params, tool: toolParam, project: projectParam },
    [win, customRange, tool, project, gran.params],
  );
  const costGran = asGranularity(costTs.data?.bucket ?? gran.expected);
  const actionsGran = asGranularity(actionsTs.data?.bucket ?? gran.expected);
  const models = useApi<CostSummary>(
    "/api/models",
    { ...winParams, tool: toolParam, project: projectParam },
    [win, customRange, tool, project],
  );
  const tools = useApi<ToolsResponse>(
    "/api/tools",
    { ...winParams, project: projectParam },
    [win, customRange, project],
  );
  const sessions = useApi<SessionsResponse>(
    "/api/sessions",
    { limit: 6, page: 1, tool: toolParam, project: projectParam },
    [tool, project],
  );
  // Discover is only used for the stale-reads KPI tile; pull a thin
  // slice with no pagination payload, and only the stale-read pass
  // (sections=stale): the full report's repeated-command and rerun passes
  // were the slowest request on the page and this tile reads none of them.
  const discover = useApi<DiscoverResponse>(
    "/api/discover",
    {
      ...winParams,
      sections: "stale",
      stale_limit: 1,
      repeated_limit: 1,
      tool: toolParam,
      project: projectParam,
    },
    [win, customRange, tool, project],
  );
  // Cache overview (C14) drives the Cache efficiency KPI tile.
  // Pulls the global rollup + top causes; the worst_sessions list
  // is loaded but only used by the linkTo page once we ship a
  // standalone cache overview page.
  const cache = useApi<CacheOverviewResponse>("/api/cache/overview");

  const kpis = deriveKpis(costTs.data, actionsTs.data);
  const staleCount = discover.data?.summary.stale_read_count;
  const apiTurns = scoped.data?.api_turns;

  const sections: Record<OverviewSectionId, ReactNode> = {
    kpis: (
      /* KPI band: the window's spend leads as a 2x2 hero (it was computed
         and never shown), beside six operational tiles in a 3x2 block. The
         band cascades in on page entry (sb-stagger) and numbers count up. */
      <Stagger className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-5">
        <HeroStat
          label={`Spend · ${winLbl}`}
          icon={<MetricIcon metric="spend" />}
          helpId="chart.cost_over_time"
          aurora
          className="col-span-2 md:col-span-3 xl:col-span-2 xl:row-span-2"
          loading={costTs.loading}
          stale={costTs.isStale}
          value={costTs.data ? fmtUSD(kpis.cost) : "-"}
          sub={
            costTs.data
              ? `${fmtInt(kpis.turns)} priced turns · ${fmtCompact(kpis.tokens)} tokens`
              : costTs.error
                ? "spend unavailable"
                : "-"
          }
          spark={kpis.costSpark}
          sparkMode="wide"
        />
        <StatCard
          label="Sessions"
          helpId="tile.sessions"
          icon={<MetricIcon metric="sessions" />}
          loading={scoped.loading}
          stale={scoped.isStale}
          value={fmtInt(scoped.data?.sessions)}
          cornerPill={
            <Pill variant="success" className="normal-case">
              window {winLbl}
            </Pill>
          }
          sub={
            // Honesty rule: "no activity yet" is a CLAIM about a loaded,
            // empty database — it must never render off an unresolved
            // /api/status. That endpoint is a whole-DB scan, so on a large
            // corpus `status.data` is legitimately null for the first several
            // seconds of a page load (and again on any aborted poll). Only a
            // RESOLVED response gets to make the claim; while the request is
            // in flight, or when it failed outright, the subtitle stays
            // neutral. ERROR FIRST, before any use of retained data: the
            // cache keeps the last good payload across a failed refetch.
            status.error
              ? "activity unavailable"
              : status.data?.last_action_at
                ? <LastActivityAgo iso={status.data.last_action_at} />
                : status.data
                  ? "no activity yet"
                  : "-"
          }
        />
        <StatCard
          label="Actions"
          helpId="chart.actions_over_time"
          icon={<MetricIcon metric="actions" />}
          linkTo="/actions"
          loading={scoped.loading}
          stale={scoped.isStale}
          value={fmtInt(scoped.data?.actions)}
          sub={
            kpis.failures > 0
              ? `${fmtInt(kpis.failures)} failed · ${((kpis.failures / Math.max(1, kpis.actionsTotal)) * 100).toFixed(1)}%`
              : actionsTs.data
                ? "no failures in window"
                : "-"
          }
          warn={kpis.actionsTotal > 0 && kpis.failures / kpis.actionsTotal > 0.1}
          spark={kpis.actionsSpark}
          sparkColor="var(--accent)"
        />
        <StatCard
          label="API Turns (proxy)"
          helpId="tile.api_turns"
          icon={<MetricIcon metric="apiTurns" />}
          loading={scoped.loading}
          stale={scoped.isStale}
          value={fmtInt(apiTurns)}
          sub={
            // Only a RESOLVED response may claim the proxy is not engaged.
            apiTurns == null
              ? "-"
              : apiTurns === 0
                ? "proxy not engaged · accurate-token source"
                : `accurate token source · ${fmtInt(scoped.data?.token_usage)} rows`
          }
          warn={apiTurns === 0}
          spark={kpis.turnsSpark}
          sparkColor="var(--tok-net)"
        />
        <StatCard
          label="Token Rows (jsonl)"
          helpId="tile.token_rows"
          icon={<MetricIcon metric="tokenRows" />}
          loading={scoped.loading}
          stale={scoped.isStale}
          value={fmtCompact(scoped.data?.token_usage)}
          // Token VOLUME per bucket (was the $ series by mistake).
          spark={kpis.tokenSpark}
          sparkColor="var(--tok-read)"
          sub="plentiful but unreliable · de-duped at cost time"
        />
        <StatCard
          label="Stale re-reads"
          helpId="metric.stale_count"
          icon={<MetricIcon metric="staleRereads" />}
          linkTo="/discovery"
          loading={discover.loading}
          stale={discover.isStale}
          value={staleCount != null ? fmtInt(staleCount) : "-"}
          warn={(staleCount ?? 0) > 0}
          cornerPill={
            // "Nominal" is a claim about a LOADED zero, never about a
            // pending or failed request.
            staleCount === 0 ? (
              <Pill variant="info">all systems nominal</Pill>
            ) : undefined
          }
          sub={
            discover.error
              ? "discovery unavailable"
              : discover.data?.summary.cross_thread_stale_count
                ? `${fmtInt(discover.data.summary.cross_thread_stale_count)} cross-thread`
                : "from Discovery tab"
          }
        />
        <CacheEfficiencyTile data={cache.data} loading={cache.loading} />
      </Stagger>
    ),
    trends: (
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <ChartShell
          title={<TitleWithHelp text="Cost over time" helpId="chart.cost_over_time" />}
          icon={SECTION_ICONS.costOverTime}
          stale={costTs.isStale}
          sub={
            costMode === "cost"
              ? `${perBucketTitle("Cost", costGran)} in dollars · ${winLbl}`
              : `${perBucketTitle("Tokens", costGran)} by Anthropic billing bucket · ${winLbl}`
          }
          right={
            <div className="flex flex-wrap items-center gap-2">
              <GranControl served={costTs.data} />
              <SegmentedControl<CostAreaMode>
                options={[
                  { value: "tokens", label: "Tokens" },
                  { value: "cost", label: "Cost $" },
                ]}
                value={costMode}
                onChange={pickCostMode}
                size="sm"
              />
            </div>
          }
        >
          <ChartState
            loading={costTs.loading}
            error={costTs.error}
            denied={costTs.denied}
            deniedPermission={costTs.deniedPermission}
            onRetry={costTs.reload}
            empty={!hasNonZero(costTs.data?.series, ["turn_count"])}
            emptyHint="No cost data in this window."
          >
            {costTs.data && (
              <CostAreaChart data={costTs.data.series} mode={costMode} granularity={costGran} />
            )}
          </ChartState>
        </ChartShell>

        <ChartShell
          title={<TitleWithHelp text="Actions over time" helpId="chart.actions_over_time" />}
          icon={SECTION_ICONS.actionsOverTime}
          stale={actionsTs.isStale}
          sub={`${perBucketTitle("Actions", actionsGran)}, stacked by tool · ${winLbl}`}
          right={<GranControl served={actionsTs.data} />}
        >
          <ChartState
            loading={actionsTs.loading}
            error={actionsTs.error}
            denied={actionsTs.denied}
            deniedPermission={actionsTs.deniedPermission}
            onRetry={actionsTs.reload}
            empty={!hasNonZero(actionsTs.data?.series, ["total"])}
            emptyHint="No actions in this window."
          >
            {actionsTs.data && (
              <ActionsAreaChart data={actionsTs.data.series} granularity={actionsGran} />
            )}
          </ChartState>
        </ChartShell>
      </div>
    ),
    top: (
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <ChartShell
          title={<TitleWithHelp text="Top models by tokens" helpId="chart.top_models" />}
          icon={SECTION_ICONS.topModels}
          stale={models.isStale}
          sub={`Net input + cache read + output · ${winLbl}`}
        >
          <ChartState
            kind="list"
            loading={models.loading}
            error={models.error}
            denied={models.denied}
            deniedPermission={models.deniedPermission}
            onRetry={models.reload}
            empty={!models.data?.rows?.length}
            emptyHint="No model data yet."
          >
            {models.data && <TopModelsBars rows={models.data.rows} />}
          </ChartState>
        </ChartShell>

        <ChartShell
          title={<TitleWithHelp text="Top tools by actions" helpId="chart.top_tools" />}
          icon={SECTION_ICONS.topTools}
          stale={tools.isStale}
          sub={`Donut + success rate · ${winLbl}`}
        >
          <ChartState
            kind="donut"
            loading={tools.loading}
            error={tools.error}
            denied={tools.denied}
            deniedPermission={tools.deniedPermission}
            onRetry={tools.reload}
            empty={!tools.data?.tools?.length}
            emptyHint="No tools active in window."
          >
            {tools.data && <TopToolsDonut tools={tools.data.tools} />}
          </ChartState>
        </ChartShell>
      </div>
    ),
    recent: (
      <ChartShell
        title="Recent sessions"
        icon={SECTION_ICONS.recentSessions}
        stale={sessions.isStale}
        sub="Most recent 6 - click through for the full list"
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
          kind="table"
          loading={sessions.loading}
          error={sessions.error}
          denied={sessions.denied}
          deniedPermission={sessions.deniedPermission}
          onRetry={sessions.reload}
          empty={!sessions.data?.rows?.length}
          emptyHint="No sessions yet. With the daemon running, a session appears here the moment you use an AI tool - route Claude Code / Codex through the proxy from the Compression page's Proxy banner, or wire hooks + MCP with `observer init`."
        >
          {sessions.data && <RecentSessions rows={sessions.data.rows} />}
        </ChartState>
      </ChartShell>
    ),
    // Community & support — star the repo, report problems, share/refer,
    // send feedback. Hideable from Customize (it was not dismissable).
    community: <CommunityCard />,
  };

  const visible = layout.order.filter((id) => !layout.hidden.includes(id));

  return (
    <div className="space-y-6 p-4 sm:p-6">
      <PageHeader
        icon={navIcon("overview")}
        title="Overview"
        sub="High-level snapshot - KPI tiles, daily cost and activity, plus top-N models and tools across the selected window."
        helpId="tab.overview"
        right={<CustomizeOverview layout={layout} onChange={updateLayout} />}
      />
      {/* First-run onboarding (P5.1/F1+D-1): renders only while the
          DB has zero sessions; permanently dismissable. */}
      <OnboardingCard sessions={status.data?.sessions ?? null} />
      {/* Milestones (P5.6/D-4): once-each, max one visible,
          dismissable; existing installs retire crossed ones silently. */}
      <MilestonesCard sessions={status.data?.sessions ?? null} />
      {/* Sections in the operator's chosen order; each rises in on page
          entry (sb-stagger on the wrapper). */}
      <Stagger className="space-y-6">
        {visible.map((id) => (
          <section key={id} aria-label={sectionLabel(id)}>
            {sections[id]}
          </section>
        ))}
      </Stagger>
      {visible.length === 0 && (
        <p className="rounded-3 border border-dashed border-line-3 p-6 text-center text-[12px] text-fg-3">
          Every section is hidden. Use Customize to bring them back.
        </p>
      )}
    </div>
  );
}

const COST_MODE_KEY = "superbased.overview.costMode";

function loadCostMode(): CostAreaMode {
  try {
    const v = localStorage.getItem(COST_MODE_KEY);
    if (v === "cost" || v === "tokens") return v;
  } catch {
    // Storage unavailable.
  }
  return "tokens";
}

function sectionLabel(id: OverviewSectionId): string {
  return OVERVIEW_SECTIONS.find((s) => s.id === id)?.label ?? id;
}

// CustomizeOverview: show / hide and reorder the Overview sections, saved
// per browser. A small popover; keyboard reachable, Esc and outside-click
// close it.
function CustomizeOverview({
  layout,
  onChange,
}: {
  layout: OverviewLayout;
  onChange: (l: OverviewLayout) => void;
}) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    const onDown = (e: MouseEvent) => {
      if (!rootRef.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("keydown", onKey);
    document.addEventListener("mousedown", onDown);
    return () => {
      document.removeEventListener("keydown", onKey);
      document.removeEventListener("mousedown", onDown);
    };
  }, [open]);
  const btn =
    "sb-press inline-flex items-center rounded-2 px-1.5 py-0.5 text-[11px] text-fg-3 hover:bg-bg-4 hover:text-fg-1 disabled:opacity-30 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent-ring";
  return (
    <div ref={rootRef} className="relative">
      <Button
        size="sm"
        iconLeft={Settings2}
        aria-expanded={open}
        aria-haspopup="dialog"
        onClick={() => setOpen((o) => !o)}
        className="sb-press"
      >
        Customize
      </Button>
      {open && (
        <div
          role="dialog"
          aria-label="Customize Overview"
          className="sb-scale-in absolute right-0 top-full z-30 mt-2 w-72 origin-top-right rounded-3 border border-line-2 bg-bg-2 p-3 shadow-3"
        >
          <p className="mb-2 text-[10.5px] font-semibold uppercase tracking-[0.06em] text-fg-3">
            Sections
          </p>
          <ul className="space-y-1">
            {layout.order.map((id, i) => {
              const shown = !layout.hidden.includes(id);
              return (
                <li
                  key={id}
                  className="flex items-center gap-2 rounded-2 px-1.5 py-1 hover:bg-bg-3"
                >
                  <label className="flex min-w-0 flex-1 cursor-pointer items-center gap-2 text-[12px] text-fg-1">
                    <input
                      type="checkbox"
                      checked={shown}
                      onChange={() => onChange(toggleSection(layout, id))}
                      className="accent-[var(--accent)]"
                    />
                    <span className={shown ? "truncate" : "truncate text-fg-3 line-through"}>
                      {sectionLabel(id)}
                    </span>
                  </label>
                  <button
                    type="button"
                    aria-label={`Move ${sectionLabel(id)} up`}
                    disabled={i === 0}
                    onClick={() => onChange(moveSection(layout, id, -1))}
                    className={btn}
                  >
                    <Icon icon={ArrowUp} size="xs" />
                  </button>
                  <button
                    type="button"
                    aria-label={`Move ${sectionLabel(id)} down`}
                    disabled={i === layout.order.length - 1}
                    onClick={() => onChange(moveSection(layout, id, 1))}
                    className={btn}
                  >
                    <Icon icon={ArrowDown} size="xs" />
                  </button>
                </li>
              );
            })}
          </ul>
          <div className="mt-2 flex justify-end border-t border-line-1 pt-2">
            <button
              type="button"
              onClick={() => onChange({ order: OVERVIEW_SECTIONS.map((s) => s.id), hidden: [] })}
              className="text-[11px] font-medium text-accent hover:text-accent-strong"
            >
              Reset to default
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// --------------------------------------------------------------- helpers

// CacheEfficiencyTile is the main-dashboard tile fed by
// /api/cache/overview (the C14 backend). Shows the global R/W
// ratio as the headline number + event/session counts as the sub
// line + a small cornerPill that surfaces the top non-baseline
// cause when one dominates.
//
// Empty corpus (no cache_events yet) renders as muted "—" so the
// tile doesn't claim "0×" health on a fresh install where the
// rate is undefined. Same for an Anthropic-cold install where
// the proxy hasn't intercepted any cache-capable traffic.
//
// Operator UI steers carried over from the SessionDetailPanel
// Cache panel:
//
//   #1 — baseline aggregation: the headline is the R/W ratio,
//        which is the cache-payback signal. The frontend doesn't
//        itemize individual events here.
//   #2 — one tone owner: the corner pill reads cacheCauseTone
//        (@shared/lib/cacheVocab) - a flagged cause (tools_changed
//        today; per docs/cache-tracking.md known-limitations) takes
//        CACHE_FLAG's warn, any other cause its CACHE_CAUSE tone.
function CacheEfficiencyTile({
  data,
  loading,
}: {
  data: CacheOverviewResponse | null | undefined;
  loading: boolean;
}) {
  const global = data?.global;
  const efficiency = global?.efficiency;
  const ratio = efficiency?.ratio ?? 0;
  const eventCount = global?.event_count ?? 0;
  const sessionCount = global?.session_count ?? 0;

  // Pick the dominant non-baseline cause for the corner pill.
  // suffix_growth + hit are the healthy baseline that dominates a
  // long warm session; skip those so the pill surfaces the most
  // operator-actionable cause.
  const dominantCause = pickDominantNonBaselineCause(data?.top_causes ?? []);

  const value =
    eventCount > 0 && efficiency && efficiency.written_tokens > 0
      ? `${ratio.toFixed(1)}×`
      : "-";
  const subLine =
    eventCount > 0
      ? `${fmtInt(eventCount)} events · ${fmtInt(sessionCount)} sessions · read ${fmtCompact(efficiency?.read_tokens ?? 0)}`
      : "no cache events yet · enable [cachetrack] or `observer backfill --cache-rescan`";

  const cornerPill =
    dominantCause && dominantCause.count > 0 ? (
      <Pill variant={cacheCauseTone(dominantCause.cause, dominantCause.flagged)} className="normal-case">
        {dominantCause.cause}
      </Pill>
    ) : undefined;

  return (
    <StatCard
      label="Cache efficiency (all time)"
      helpId="tile.cache_efficiency"
      icon={<MetricIcon metric="cacheHitRate" />}
      loading={loading}
      value={value}
      sub={subLine}
      cornerPill={cornerPill}
    />
  );
}

// pickDominantNonBaselineCause returns the largest-count cause
// other than suffix_growth (which is the healthy baseline). Ties
// broken by lexicographic order so the tile is deterministic.
function pickDominantNonBaselineCause(
  causes: CacheOverviewResponse["top_causes"],
): CacheOverviewResponse["top_causes"][number] | null {
  let best: CacheOverviewResponse["top_causes"][number] | null = null;
  for (const c of causes) {
    if (c.cause === "suffix_growth") continue;
    if (
      best == null ||
      c.count > best.count ||
      (c.count === best.count && c.cause < best.cause)
    ) {
      best = c;
    }
  }
  return best;
}

// OverviewStatusSlice is all the page reads from /api/status.
type OverviewStatusSlice = { last_action_at: string | null; sessions: number | null };

function selectOverviewStatus(s: StatusSnapshot): OverviewStatusSlice {
  return { last_action_at: s.last_action_at || null, sessions: s.counts?.sessions ?? null };
}

// LastActivityAgo re-renders itself every 5 s so the relative time walks
// without re-rendering the page (it used to ride the page-wide status poll).
function LastActivityAgo({ iso }: { iso: string }) {
  useNowTick(5000);
  return <>{`last activity ${relativeTime(iso)}`}</>;
}

// Ago is the recent-sessions "started X ago" cell: it walks on its own tick
// (the page no longer re-renders on every status poll, and table rows are
// memoized, so nothing else would refresh it).
function Ago({ iso }: { iso: string }) {
  useNowTick(5000);
  return <>{relativeTime(iso)}</>;
}

function deriveKpis(
  cost?: CostTimeseries | null,
  actions?: ActionsTimeseries | null,
) {
  const series = cost?.series ?? [];
  const cost_usd = series.reduce((acc, p) => acc + (p.cost_usd || 0), 0);
  const turns = series.reduce((acc, p) => acc + (p.turn_count || 0), 0);
  const bucketTokens = (p: CostTimeseries["series"][number]) =>
    (p.input || 0) + (p.output || 0) + (p.cache_read || 0) + (p.cache_creation || 0);
  const actionsSeries = actions?.series ?? [];
  return {
    cost: cost_usd,
    turns,
    tokens: series.reduce((acc, p) => acc + bucketTokens(p), 0),
    costSpark: series.map((p) => p.cost_usd || 0),
    turnsSpark: series.map((p) => p.turn_count || 0),
    tokenSpark: series.map(bucketTokens),
    actionsTotal: actionsSeries.reduce((a, p) => a + (p.total || 0), 0),
    failures: actionsSeries.reduce((a, p) => a + (p.failures || 0), 0),
    // `total` already counts every action in the bucket; the old sum over
    // every numeric key double-counted `failures`.
    actionsSpark: actionsSeries.map((p) => p.total || 0),
  };
}

function relativeTime(iso: string): string {
  const t = new Date(iso).getTime();
  if (!Number.isFinite(t)) return "-";
  const diffMs = Date.now() - t;
  if (diffMs < 0) return "in the future";
  return `${fmtDuration(diffMs)} ago`;
}

function TopModelsBars({ rows }: { rows: CostSummary["rows"] }) {
  const top = rows.slice(0, 8);
  // Colour by model FAMILY (one family table owns model colour), with a
  // shade per extra model of the same family - not by rank.
  const colors = modelSeriesColors(top.map((r) => r.key));
  const max = Math.max(
    1,
    ...top.map(
      (r) =>
        r.tokens.input + r.tokens.cache_read + r.tokens.output,
    ),
  );
  return (
    <ul className="space-y-1.5">
      {top.map((r, i) => {
        const total =
          r.tokens.input + r.tokens.cache_read + r.tokens.output;
        const pct = (total / max) * 100;
        const color = colors[i];
        return (
          <li key={r.key} className="space-y-0.5">
            <div className="flex items-baseline justify-between gap-2">
              <ModelId model={r.key} className="min-w-0 text-[11px]" />
              <span className="shrink-0 text-[11px] text-fg-3 tabular-nums">
                {fmtCompact(total)} · {fmtUSD(r.cost_usd)}
              </span>
            </div>
            <div className="h-2 w-full overflow-hidden rounded-pill bg-bg-3">
              <span
                className="sb-bar-grow block h-full origin-left rounded-pill"
                style={{
                  transform: `scaleX(${pct / 100})`,
                  background: color,
                  animationDelay: `${i * 40}ms`,
                }}
              />
            </div>
          </li>
        );
      })}
    </ul>
  );
}

type RecentSessionRow = SessionsResponse["rows"][number];

// RECENT_SESSION_COLUMNS keeps the list's recency order (the card is "the
// six most recent sessions"), so no column sorts.
const RECENT_SESSION_COLUMNS: ColumnDef<RecentSessionRow, unknown>[] = [
  {
    id: "tool",
    header: () => <>Tool<HelpInd id="column.sessions.tool" /></>,
    enableSorting: false,
    cell: ({ row }) => <ToolBadge tool={row.original.tool} />,
  },
  {
    id: "project",
    header: () => <>Project<HelpInd id="column.sessions.project" /></>,
    enableSorting: false,
    meta: { mono: true },
    cell: ({ row }) =>
      row.original.project ? (
        <TruncatedPath value={row.original.project} className="max-w-[280px] text-[11px]" />
      ) : (
        <Pill>no project</Pill>
      ),
  },
  {
    id: "started",
    header: () => <>Started<HelpInd id="column.sessions.started" /></>,
    enableSorting: false,
    cell: ({ row }) => (
      <Tooltip content={fmtDateTime(row.original.started_at)}>
        <span tabIndex={0} className="cursor-help text-[11px] text-fg-3 focus:outline-none">
          <Ago iso={row.original.started_at} />
        </span>
      </Tooltip>
    ),
  },
  {
    id: "actions",
    header: () => <>Actions<HelpInd id="column.sessions.actions" /></>,
    enableSorting: false,
    meta: { align: "right" },
    cell: ({ row }) => <span className="text-fg-1">{fmtInt(row.original.total_actions)}</span>,
  },
  {
    id: "tokens",
    header: () => <>Tokens<HelpInd id="column.sessions.tokens" /></>,
    enableSorting: false,
    meta: { align: "right" },
    cell: ({ row }) => <span className="text-fg-2">{fmtCompact(row.original.total_tokens)}</span>,
  },
  {
    id: "cost",
    header: () => <>Cost<HelpInd id="column.sessions.cost" /></>,
    enableSorting: false,
    meta: { align: "right" },
    cell: ({ row }) => <span className="text-fg-1">{fmtUSD(row.original.cost_usd)}</span>,
  },
  {
    id: "elapsed",
    header: () => <>Elapsed<HelpInd id="column.sessions.elapsed" /></>,
    enableSorting: false,
    meta: { align: "right" },
    cell: ({ row }) => (
      <span className="text-fg-3">{fmtDuration(row.original.duration_seconds * 1000)}</span>
    ),
  },
];

function RecentSessions({ rows }: { rows: SessionsResponse["rows"] }) {
  return (
    <DataTable<RecentSessionRow>
      data={rows.slice(0, 6)}
      columns={RECENT_SESSION_COLUMNS}
      rowKey={(s) => s.id}
      minWidth={540}
    />
  );
}
