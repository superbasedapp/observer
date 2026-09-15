import { useState } from "react";
import { Link } from "react-router-dom";
import {
  ActionsAreaChart,
  CostAreaChart,
  type CostAreaMode,
  TopToolsDonut,
} from "@/components/charts";
import { ChartState } from "@/components/ChartState";
import {
  ChartShell,
  PageHeader,
  Pill,
  SegmentedControl,
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
  AlertIcon,
  BoltIcon,
  DatabaseIcon,
  LayersIcon,
} from "@/components/icons";
import {
  useFilters,
  windowLabel,
  windowParams,
  windowSpanHours,
} from "@/lib/filters";
import { useApi } from "@/lib/useApi";
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

export function OverviewPage() {
  const [costMode, setCostMode] = useState<CostAreaMode>("tokens");
  const { win, customRange, tool, project } = useFilters();
  const winParams = windowParams(win, customRange);
  const bucket = windowSpanHours(win, customRange) <= 48 ? "hour" : "day";
  const winLbl = windowLabel(win, customRange);
  const toolParam = tool === "all" ? undefined : tool;
  const projectParam = project === "all" ? undefined : project;

  const status = useApi<StatusSnapshot>("/api/status");
  const scoped = useApi<StatusScoped>(
    "/api/status/scoped",
    { ...winParams, tool: toolParam, project: projectParam },
    [win, customRange, tool, project],
  );
  const costTs = useApi<CostTimeseries>(
    "/api/timeseries/cost",
    { ...winParams, bucket, tool: toolParam, project: projectParam },
    [win, customRange, tool, project],
  );
  const actionsTs = useApi<ActionsTimeseries>(
    "/api/timeseries/actions",
    { ...winParams, bucket, tool: toolParam, project: projectParam },
    [win, customRange, tool, project],
  );
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
  // slice with no pagination payload.
  const discover = useApi<DiscoverResponse>(
    "/api/discover",
    {
      ...winParams,
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

  const kpis = deriveKpis(costTs.data, actionsTs.data, status.data);

  return (
    <div className="space-y-6 p-6">
      <PageHeader
        title="Overview"
        sub="High-level snapshot - KPI tiles, daily cost and activity, plus top-N models and tools across the selected window."
        helpId="tab.overview"
      />
      {/* First-run onboarding (P5.1/F1+D-1): renders only while the
          DB has zero sessions; permanently dismissable. */}
      <OnboardingCard sessions={status.data?.counts?.sessions ?? null} />
      {/* Milestones (P5.6/D-4): once-each, max one visible,
          dismissable; existing installs retire crossed ones silently. */}
      <MilestonesCard sessions={status.data?.counts?.sessions ?? null} />
      {/* KPI grid */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-5">
        <StatCard
          label="Sessions"
          helpId="tile.sessions"
          icon={<LayersIcon />}
          loading={scoped.loading}
          value={fmtInt(scoped.data?.sessions)}
          cornerPill={
            <span
              title={`window ${winLbl}`}
              className="rounded-pill border border-success/40 bg-success-soft px-1.5 py-0.5 text-[9.5px] font-medium text-success"
            >
              window {winLbl}
            </span>
          }
          sub={
            // Honesty rule: "no activity yet" is a CLAIM about a loaded,
            // empty database — it must never render off an unresolved
            // /api/status. That endpoint is a whole-DB scan the SPA polls
            // from three places at once, so on a large corpus `status.data`
            // is legitimately null for the first several seconds of a page
            // load (and again on any aborted poll). Falling through to the
            // empty-state copy there told a busy install it had never been
            // used. Only a RESOLVED response gets to make the claim; while
            // the request is in flight, or when it failed outright, the
            // subtitle stays neutral.
            // ERROR FIRST, before any use of retained data. useApi keeps the
            // last good payload across a failed refetch, so checking
            // `status.data` first would keep printing "last activity 4m ago"
            // — or, from a stale-empty payload, "no activity yet" — while the
            // endpoint is actually failing, which is a stronger claim than
            // the page can support at that moment.
            status.error
              ? "activity unavailable"
              : status.data?.last_action_at
                ? `last activity ${relativeTime(status.data.last_action_at)}`
                : status.data
                  ? "no activity yet"
                  : "-"
          }
          spark={kpis.actionsSpark}
          sparkColor="var(--accent)"
        />
        <StatCard
          label="API Turns (proxy)"
          helpId="tile.api_turns"
          icon={<BoltIcon />}
          loading={scoped.loading}
          value={fmtInt(scoped.data?.api_turns)}
          sub={
            (scoped.data?.api_turns ?? 0) === 0
              ? "proxy not engaged · accurate-token source"
              : `accurate token source · ${fmtInt(scoped.data?.token_usage)} rows`
          }
          warn={(scoped.data?.api_turns ?? 0) === 0}
          spark={kpis.turnsSpark}
          sparkColor="var(--tok-net)"
        />
        <StatCard
          label="Token Rows (jsonl)"
          helpId="tile.token_rows"
          icon={<DatabaseIcon />}
          loading={scoped.loading}
          value={fmtCompact(scoped.data?.token_usage)}
          spark={kpis.costSpark}
          sparkColor="var(--tok-read)"
          sub="plentiful but unreliable · de-duped at cost time"
        />
        <StatCard
          label="Stale re-reads"
          helpId="metric.stale_count"
          icon={<AlertIcon />}
          linkTo="/discovery"
          loading={discover.loading}
          value={
            discover.data ? fmtInt(discover.data.summary.stale_read_count) : "-"
          }
          warn={
            (discover.data?.summary.stale_read_count ?? 0) > 0
          }
          cornerPill={
            (discover.data?.summary.stale_read_count ?? 0) === 0 ? (
              <span className="rounded-pill border border-info/40 bg-info-soft px-1.5 py-0.5 text-[9.5px] font-medium text-info">
                all systems nominal
              </span>
            ) : undefined
          }
          sub={
            discover.data?.summary.cross_thread_stale_count
              ? `${fmtInt(discover.data.summary.cross_thread_stale_count)} cross-thread`
              : "from Discovery tab"
          }
        />
        <CacheEfficiencyTile data={cache.data} loading={cache.loading} />
      </div>

      {/* Two time-series charts side by side on wide screens */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <ChartShell
          title={<TitleWithHelp text="Cost over time" helpId="chart.cost_over_time" />}
          sub={
            costMode === "cost"
              ? `Daily cost in dollars · ${winLbl}`
              : `Tokens by Anthropic billing bucket · ${winLbl}`
          }
          right={
            <SegmentedControl<CostAreaMode>
              options={[
                { value: "tokens", label: "Tokens" },
                { value: "cost", label: "Cost $" },
              ]}
              value={costMode}
              onChange={setCostMode}
              size="sm"
            />
          }
        >
          <ChartState
            loading={costTs.loading}
            error={costTs.error}
            empty={!costTs.data?.series?.length}
            emptyHint="No cost data in this window."
          >
            {costTs.data && (
              <CostAreaChart data={costTs.data.series} mode={costMode} />
            )}
          </ChartState>
        </ChartShell>

        <ChartShell
          title={<TitleWithHelp text="Actions over time" helpId="chart.actions_over_time" />}
          sub={`Stacked by tool · ${winLbl}`}
        >
          <ChartState
            loading={actionsTs.loading}
            error={actionsTs.error}
            empty={!actionsTs.data?.series?.length}
            emptyHint="No actions in this window."
          >
            {actionsTs.data && (
              <ActionsAreaChart data={actionsTs.data.series} />
            )}
          </ChartState>
        </ChartShell>
      </div>

      {/* Top models + Top tools side by side */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <ChartShell
          title={<TitleWithHelp text="Top models by tokens" helpId="chart.top_models" />}
          sub={`Net input + cache read + output · ${winLbl}`}
        >
          <ChartState
            loading={models.loading}
            error={models.error}
            empty={!models.data?.rows?.length}
            emptyHint="No model data yet."
          >
            {models.data && <TopModelsBars rows={models.data.rows} />}
          </ChartState>
        </ChartShell>

        <ChartShell
          title={<TitleWithHelp text="Top tools by actions" helpId="chart.top_tools" />}
          sub={`Donut + success rate · ${winLbl}`}
        >
          <ChartState
            loading={tools.loading}
            error={tools.error}
            empty={!tools.data?.tools?.length}
            emptyHint="No tools active in window."
          >
            {tools.data && <TopToolsDonut tools={tools.data.tools} />}
          </ChartState>
        </ChartShell>
      </div>

      {/* Recent sessions mini-list */}
      <ChartShell
        title="Recent sessions"
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
          loading={sessions.loading}
          error={sessions.error}
          empty={!sessions.data?.rows?.length}
          emptyHint="No sessions yet. With the daemon running, a session appears here the moment you use an AI tool - route Claude Code / Codex through the proxy from the Compression page's Proxy banner, or wire hooks + MCP with `observer init`."
        >
          {sessions.data && <RecentSessions rows={sessions.data.rows} />}
        </ChartState>
      </ChartShell>
      {/* Community & support — star the repo, report problems,
          share/refer, send feedback. Persistent (not dismissable). */}
      <CommunityCard />
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
//   #2 — flagged honesty: when the dominant non-baseline cause
//        is a flagged one (tools_changed today; per
//        docs/cache-tracking.md known-limitations), the corner
//        pill renders in neutral tone, not warn. A real
//        invalidation (system_changed / expiry / model-switch
//        in the top cause) gets the warn tone.
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
      <span
        className={clsxPill(dominantCause.flagged === true)}
      >
        {dominantCause.cause}
      </span>
    ) : undefined;

  return (
    <StatCard
      label="Cache efficiency"
      helpId="tile.cache_efficiency"
      icon={<DatabaseIcon />}
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

// clsxPill chooses the cornerPill tone based on whether the
// dominant cause is flagged (operator UI steer #2 — neutral, not
// alarm-red).
function clsxPill(flagged: boolean): string {
  return flagged
    ? "rounded-pill border border-fg-3/40 bg-bg-3 px-1.5 py-0.5 text-[9.5px] font-medium text-fg-2"
    : "rounded-pill border border-warn/40 bg-warn-soft px-1.5 py-0.5 text-[9.5px] font-medium text-warn";
}

function deriveKpis(
  cost?: CostTimeseries | null,
  actions?: ActionsTimeseries | null,
  _status?: StatusSnapshot | null,
) {
  const series = cost?.series ?? [];
  const cost_usd = series.reduce((acc, p) => acc + (p.cost_usd || 0), 0);
  const turns = series.reduce((acc, p) => acc + (p.turn_count || 0), 0);
  const actionsSeries = actions?.series ?? [];
  return {
    cost: cost_usd,
    turns,
    costSpark: series.map((p) => p.cost_usd || 0),
    turnsSpark: series.map((p) => p.turn_count || 0),
    actionsSpark: actionsSeries.map(
      (p) =>
        Object.entries(p)
          .filter(([k]) => k !== "bucket")
          .reduce((a, [, v]) => a + (typeof v === "number" ? v : 0), 0),
    ),
  };
}

function relativeTime(iso: string): string {
  const t = new Date(iso).getTime();
  if (!Number.isFinite(t)) return "-";
  const diffMs = Date.now() - t;
  if (diffMs < 0) return "in the future";
  return `${fmtDuration(diffMs)} ago`;
}

// Per-model palette. Pulled from design tokens so themes follow.
const MODEL_PALETTE = [
  "var(--tok-net)",
  "var(--tok-read)",
  "var(--tok-out)",
  "var(--tok-write)",
  "var(--info)",
  "var(--success)",
  "var(--warn)",
  "var(--accent)",
];

function TopModelsBars({ rows }: { rows: CostSummary["rows"] }) {
  const top = rows.slice(0, 8);
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
        const color = MODEL_PALETTE[i % MODEL_PALETTE.length];
        return (
          <li key={r.key} className="space-y-0.5">
            <div className="flex items-baseline justify-between gap-2">
              <span className="flex items-center gap-1.5 truncate">
                <span
                  className="h-1.5 w-1.5 shrink-0 rounded-pill"
                  style={{ background: color }}
                />
                <span className="truncate font-mono text-[11px] text-fg-1">
                  {r.key}
                </span>
              </span>
              <span className="shrink-0 text-[11px] text-fg-3 tabular-nums">
                {fmtCompact(total)} · {fmtUSD(r.cost_usd)}
              </span>
            </div>
            <div className="h-2 w-full overflow-hidden rounded-pill bg-bg-3">
              <span
                className="block h-full"
                style={{ width: `${pct}%`, background: color }}
              />
            </div>
          </li>
        );
      })}
    </ul>
  );
}

function RecentSessions({ rows }: { rows: SessionsResponse["rows"] }) {
  return (
    <div className="-mx-1 overflow-x-auto px-1">
    <table className="w-full min-w-[540px] text-left text-[12px]">
      <thead className="text-[10.5px] uppercase tracking-[0.06em] text-fg-3">
        <tr>
          <th className="py-1.5 font-medium">Tool<HelpInd id="column.sessions.tool" /></th>
          <th className="py-1.5 font-medium">Project<HelpInd id="column.sessions.project" /></th>
          <th className="py-1.5 font-medium">Started<HelpInd id="column.sessions.started" /></th>
          <th className="py-1.5 text-right font-medium">Actions<HelpInd id="column.sessions.actions" /></th>
          <th className="py-1.5 text-right font-medium">Tokens<HelpInd id="column.sessions.tokens" /></th>
          <th className="py-1.5 text-right font-medium">Cost<HelpInd id="column.sessions.cost" /></th>
          <th className="py-1.5 text-right font-medium">Elapsed<HelpInd id="column.sessions.elapsed" /></th>
        </tr>
      </thead>
      <tbody>
        {rows.slice(0, 6).map((s) => (
          <tr key={s.id} className="border-t border-line-1 hover:bg-bg-3/40">
            <td className="py-1.5">
              <ToolBadge tool={s.tool} />
            </td>
            <td className="max-w-[280px] py-1.5 font-mono text-[11px] text-fg-2">
              {s.project ? (
                <TruncatedPath value={s.project} />
              ) : (
                <Pill>no project</Pill>
              )}
            </td>
            <Tooltip content={fmtDateTime(s.started_at)}>
              <td tabIndex={0} className="cursor-help py-1.5 text-[11px] text-fg-3 focus:outline-none">
                {relativeTime(s.started_at)}
              </td>
            </Tooltip>
            <td className="py-1.5 text-right tabular-nums text-fg-1">
              {fmtInt(s.total_actions)}
            </td>
            <td className="py-1.5 text-right tabular-nums text-fg-2">
              {fmtCompact(s.total_tokens)}
            </td>
            <td className="py-1.5 text-right tabular-nums text-fg-1">
              {fmtUSD(s.cost_usd)}
            </td>
            <td className="py-1.5 text-right tabular-nums text-fg-3">
              {fmtDuration(s.duration_seconds * 1000)}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
    </div>
  );
}
