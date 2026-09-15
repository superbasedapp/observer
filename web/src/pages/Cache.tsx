import { useMemo, useState } from "react";
import { ChartShell, PageHeader, Pill, StatCard } from "@/components/primitives";
import { ChartState } from "@/components/ChartState";
import { CacheExpiryCard } from "@/components/CacheExpiryCard";
import { HelpInd, TitleWithHelp } from "@/components/HelpInd";
import { SessionDetailPanel } from "@/components/SessionDetailPanel";
import {
  BoltIcon,
  CoinsIcon,
  DatabaseIcon,
  DropletIcon,
} from "@/components/icons";
import {
  CacheEventsChart,
  CacheRatioChart,
  CacheTrafficChart,
} from "@/components/charts";
import {
  useFilters,
  windowDaysApprox,
  windowLabel,
  windowParams,
} from "@/lib/filters";
import { useApi } from "@/lib/useApi";
import { fmtCompact, fmtDateTime, fmtInt, fmtPct, fmtShortId, fmtUSD } from "@/lib/format";
import type {
  CacheEntryStatesResponse,
  CacheEventRow,
  CacheEventsResponse,
  CacheHealthSummary,
  CacheOverviewCauseRow,
  CacheOverviewResponse,
  CacheOverviewSessionRow,
  CacheTimeseriesResponse,
} from "@/lib/types";

// CachePage — standalone /cache route that consumes /api/cache/overview
// in full. The Overview tile shows the headline R/W ratio; this page
// surfaces the full per-model / per-project / top-causes / worst-sessions
// rollups in the same visual rhythm as the Cost page so the two reads
// like a coherent surface.
//
// Operator UI steers maintained throughout:
//   #1 — never itemize baseline events. The Top causes histogram is a
//        proportional bar list with suffix_growth + hit dominating; the
//        tally is event count, not invalidation count.
//   #2 — render flagged causes neutrally (not alarm-red). CausePill
//        renders Flagged=true entries with the neutral variant; real
//        invalidation causes keep the warn tone.
export function CachePage() {
  // Cache page honors the global TopBar filters the same way Cost /
  // Analysis / Overview do. Backend handler (handleCacheOverview)
  // accepts the same days / tool / project query-param shape.
  // Days==0 is the "all-time" sentinel so the page is non-empty even
  // when the corpus pre-dates the operator's default window.
  const { win, customRange, tool, project } = useFilters();
  // Cache endpoints use 0 (not 36500) as their all-time sentinel.
  const winParams = windowParams(win, customRange, { allSentinel: 0 });
  // Prior-period comparison is day-grained: shift the window back by
  // its own span in whole days (sub-day / custom windows round up).
  const priorSpanDays = windowDaysApprox(win, customRange, 0);
  const toolParam = tool === "all" ? undefined : tool;
  const projectParam = project === "all" ? undefined : project;
  const cache = useApi<CacheOverviewResponse>(
    "/api/cache/overview",
    { ...winParams, tool: toolParam, project: projectParam },
    [win, customRange, tool, project],
    { refreshMs: 15000 },
  );
  // Prior-period fetch — shifts the window backward by the same
  // span so the operator sees ↑/↓ deltas vs the previous equivalent
  // period. Skipped when win="all" (no meaningful prior on a
  // full-corpus view). Lighter refresh (60s) since deltas are
  // slow-moving signals.
  const priorCache = useApi<CacheOverviewResponse>(
    win === "all" ? null : "/api/cache/overview",
    {
      days: priorSpanDays,
      period_offset_days: priorSpanDays,
      tool: toolParam,
      project: projectParam,
    },
    [win, customRange, tool, project],
    { refreshMs: 60000 },
  );
  // Timeseries powers sparklines on the four headline tiles. Daily
  // bucket; defaults to days=30 when the window is "all" so the
  // sparkline still reads as recent-trajectory rather than a flat
  // multi-year line.
  const timeseries = useApi<CacheTimeseriesResponse>(
    "/api/cache/timeseries",
    {
      ...(win === "all" ? { days: 30 } : winParams),
      tool: toolParam,
      project: projectParam,
    },
    [win, customRange, tool, project],
    { refreshMs: 30000 },
  );
  const sparks = useMemo(() => deriveSparks(timeseries.data), [timeseries.data]);
  // Engine-health summary is global (mispredict rate / WARN signals
  // are not windowed metrics — they describe the cachetrack engine,
  // not the operator's filter scope). Refreshes at the same cadence
  // as /api/status so the banner stays accurate without being noisy.
  const health = useApi<CacheHealthSummary>("/api/cache/health", undefined, [], {
    refreshMs: 30000,
  });
  // Filter scope is "non-default" when window != all OR tool != all
  // OR project != all. Used to switch the empty-state copy between
  // "enable cachetrack" (legitimately empty corpus) and "no events
  // match the filters" (corpus is non-empty but the current scope
  // narrowed it down to zero). Truth source: the global health
  // summary's graded_events — if the engine has graded ANY event
  // ever, the corpus isn't empty, so the right empty-state is the
  // filter-mismatch one.
  const filtersActive = win !== "all" || tool !== "all" || project !== "all";
  const corpusHasEvents = (health.data?.graded_events ?? 0) > 0;
  const winLabel = win === "all" ? "all time" : windowLabel(win, customRange);
  // Recent events — paginated drill-down below the charts. Page
  // size 50 / no page state in URL (yet); refresh 30s.
  const [eventsOffset, setEventsOffset] = useState(0);
  const events = useApi<CacheEventsResponse>(
    "/api/cache/events",
    {
      ...winParams,
      tool: toolParam,
      project: projectParam,
      limit: 50,
      offset: eventsOffset,
    },
    [win, customRange, tool, project, eventsOffset],
    { refreshMs: 30000 },
  );
  // Entry-state distribution — engine global (no window filter; the
  // entries table is a current snapshot, not a historical series).
  const entryStates = useApi<CacheEntryStatesResponse>(
    "/api/cache/entry-states",
    undefined,
    [],
    { refreshMs: 60000 },
  );
  // Empty-state copy is filter-aware AND provider-aware. As of §15.3
  // OpenAI / codex / OpenAI-routed adapters ALSO emit implicit-cache
  // events, so an OpenAI-dominated install is no longer silently
  // empty — but events land on the separate (lower-fidelity)
  // implicit surface. Tell the operator which case applies so they
  // don't go hunting for a config knob that wouldn't fix it.
  const hasUntracked = (health.data?.untracked_provider_turns ?? 0) > 0;
  const hasImplicit = (health.data?.implicit_cache_events ?? 0) > 0;
  const emptyHint =
    filtersActive && corpusHasEvents
      ? "No cache events match the current filters. Try widening the window, clearing the tool / project filter, or resetting from the TopBar."
      : hasUntracked && !corpusHasEvents && !hasImplicit
        ? `Recent traffic is dominated by ${health.data?.untracked_provider_top_tool || "non-Anthropic"} sessions. These route through the implicit-cache surface, but no implicit-cache events were captured - the running binary may pre-date implicit support (restart on the current build), or retrofit history via Settings → Backfill → cache-rescan.`
        : "No cache events recorded yet. Cache tracking is on by default (toggle under Settings → Cache tracking); to retrofit historical transcripts, run cache-rescan from Settings → Backfill.";
  const [openSessionId, setOpenSessionId] = useState<string | null>(null);

  return (
    <div className="space-y-6 p-6">
      <PageHeader
        title="Cache"
        sub="Prompt-cache observation, attribution, and forecasting across providers. Anthropic gets marker-aware grading; OpenAI / codex / OpenAI-routed adapters get implicit-cache tracking on a separate, lower-fidelity surface (graded against per-session prefix estimates, not provider markers). Local, passive, network-free."
        helpId="tab.cache"
      />

      <CacheExpiryCard />

      <ChartState
        loading={cache.loading}
        error={cache.error}
        empty={!cache.data || (cache.data.global.event_count ?? 0) === 0}
        emptyHint={emptyHint}
        height={120}
      >
        {cache.data && (
          <CacheContent
            data={cache.data}
            priorData={priorCache.data ?? null}
            sparks={sparks}
            timeseries={timeseries.data ?? null}
            timeseriesLoading={timeseries.loading}
            timeseriesError={timeseries.error}
            health={health.data ?? null}
            winLabel={winLabel}
            events={events.data ?? null}
            eventsLoading={events.loading}
            eventsError={events.error}
            eventsOffset={eventsOffset}
            onEventsOffsetChange={setEventsOffset}
            entryStates={entryStates.data ?? null}
            onOpenSession={setOpenSessionId}
          />
        )}
      </ChartState>

      <SessionDetailPanel
        sessionId={openSessionId}
        open={openSessionId != null}
        onClose={() => setOpenSessionId(null)}
        onOpenSession={(id) => setOpenSessionId(id)}
      />
    </div>
  );
}

type CacheSparks = {
  ratio: number[];
  read: number[];
  write: number[];
  events: number[];
};

function CacheContent({
  data,
  priorData,
  sparks,
  timeseries,
  timeseriesLoading,
  timeseriesError,
  health,
  winLabel,
  events,
  eventsLoading,
  eventsError,
  eventsOffset,
  onEventsOffsetChange,
  entryStates,
  onOpenSession,
}: {
  data: CacheOverviewResponse;
  priorData: CacheOverviewResponse | null;
  sparks: CacheSparks;
  timeseries: CacheTimeseriesResponse | null;
  timeseriesLoading: boolean;
  timeseriesError: Error | null;
  health: CacheHealthSummary | null;
  winLabel: string;
  events: CacheEventsResponse | null;
  eventsLoading: boolean;
  eventsError: Error | null;
  eventsOffset: number;
  onEventsOffsetChange: (n: number) => void;
  entryStates: CacheEntryStatesResponse | null;
  onOpenSession: (sid: string) => void;
}) {
  const global = data.global;
  const ratio = global.efficiency?.ratio ?? 0;
  const readTokens = global.efficiency?.read_tokens ?? 0;
  const writeTokens = global.efficiency?.written_tokens ?? 0;
  const avoidable = global.efficiency?.avoidable_usd ?? 0;
  const totalTraffic = readTokens + writeTokens;
  const readShare = totalTraffic > 0 ? readTokens / totalTraffic : 0;
  const writeShare = totalTraffic > 0 ? writeTokens / totalTraffic : 0;

  // Distinct model + project counts derived from rollups, used as
  // secondary signals on the headline tiles.
  const modelCount = data.per_model.length;
  const projectCount = data.per_project.length;

  // Per-tile deltas vs the prior period of equal length. StatCard
  // follows the cost-aware convention: up = danger-red, down =
  // success-green. Cache uses inverse semantics on some tiles —
  // ratio / read / events going UP is GOOD (more cache reuse), so
  // we sign-flip those deltas before passing them in. Write +
  // avoidable spend keep the natural up=bad sign (more overhead).
  const deltas = useMemo(() => {
    if (!priorData) {
      return { ratio: null, read: null, write: null, events: null };
    }
    const cur = data.global;
    const prev = priorData.global;
    const flipDelta = (now: number, then: number) => {
      // Sign-flipped: a healthy increase (now > then) renders down/
      // green by feeding StatCard a NEGATIVE delta.
      const raw = pctChange(now, then);
      return raw == null ? null : -raw;
    };
    return {
      ratio: flipDelta(cur.efficiency?.ratio ?? 0, prev.efficiency?.ratio ?? 0),
      read: flipDelta(
        cur.efficiency?.read_tokens ?? 0,
        prev.efficiency?.read_tokens ?? 0,
      ),
      write: pctChange(
        cur.efficiency?.written_tokens ?? 0,
        prev.efficiency?.written_tokens ?? 0,
      ),
      events: flipDelta(cur.event_count ?? 0, prev.event_count ?? 0),
    };
  }, [data.global, priorData]);
  const priorLabel = priorData ? `vs prior ${winLabel}` : undefined;

  // Build per-dimension row arrays once so the rendered table and
  // the Export button consume the same data shape.
  const modelRows = useMemo<ByDimensionRow[]>(
    () =>
      data.per_model.map((m) => ({
        key: m.model,
        display: m.model,
        title: m.model,
        read: m.efficiency?.read_tokens ?? 0,
        write: m.efficiency?.written_tokens ?? 0,
        ratio: m.efficiency?.ratio ?? 0,
        events: m.event_count,
        avoidable: m.efficiency?.avoidable_usd ?? 0,
        mono: true,
      })),
    [data.per_model],
  );
  const projectRows = useMemo<ByDimensionRow[]>(
    () =>
      data.per_project.map((p) => ({
        key: String(p.project_id),
        display: shortProjectPath(p.project_root),
        title: p.project_root || "(unknown)",
        read: p.efficiency?.read_tokens ?? 0,
        write: p.efficiency?.written_tokens ?? 0,
        ratio: p.efficiency?.ratio ?? 0,
        events: p.event_count,
        avoidable: p.efficiency?.avoidable_usd ?? 0,
        mono: true,
      })),
    [data.per_project],
  );

  return (
    <>
      {/* Provider-coverage info banner — info-toned (not warn). Fires
          when the proxy has captured api_turns from non-Anthropic
          providers (codex/openai/etc.) that cachetrack intentionally
          skipped. Without this, the operator who routes a codex
          session through the proxy lands on an empty Cache page and
          reads it as a bug — the banner says "yes, we saw it; here's
          why nothing's tracked." Mirrors Cost's unknown-model pill
          rhythm but on the engine-coverage axis. */}
      <UntrackedProviderBanner health={health} />

      {/* Engine-health WARN banner — fires when the cachetrack engine
          surfaces a grading-gate failure, a dominant non-baseline
          cause, an inconsistent rewrite shape, or bucket-mismatch
          drift. Mirrors the unknown-model pill pattern on Cost. */}
      <CacheHealthBanner health={health} />

      {/* Headline KPI row — mirrors Cost's accent-hero rhythm. The
          ratio tile is the accent hero; the three siblings render with
          the default tile gradient. Distinct icons per tile so a
          glance through the row reads like Cost's KPI strip. */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        <StatCard
          label={`Cache ratio (${winLabel})`}
          helpId="tile.cache_ratio"
          icon={<DatabaseIcon />}
          value={ratio > 0 ? `${ratio.toFixed(1)}×` : "-"}
          sub={
            ratio > 0
              ? `R ${fmtCompact(readTokens)} · W ${fmtCompact(writeTokens)} tokens`
              : "no writes yet"
          }
          delta={deltas.ratio ?? undefined}
          deltaLabel={priorLabel}
          spark={sparks.ratio}
          sparkColor="var(--accent)"
          accent
        />
        <StatCard
          label={`Cache read (${winLabel})`}
          helpId="metric.cache_read"
          icon={<DropletIcon />}
          value={fmtCompact(readTokens)}
          sub={
            totalTraffic > 0
              ? `${fmtPct(readShare)} of cache traffic · ${fmtInt(modelCount)} model${modelCount === 1 ? "" : "s"}`
              : "tokens served from provider cache"
          }
          delta={deltas.read ?? undefined}
          deltaLabel={priorLabel}
          spark={sparks.read}
          sparkColor="var(--tok-read)"
        />
        <StatCard
          label={`Cache write (${winLabel})`}
          helpId="metric.cache_creation"
          icon={<DropletIcon />}
          value={fmtCompact(writeTokens)}
          sub={
            totalTraffic > 0
              ? `${fmtPct(writeShare)} of cache traffic · setup overhead`
              : "tokens written to provider cache"
          }
          delta={deltas.write ?? undefined}
          deltaLabel={priorLabel}
          spark={sparks.write}
          sparkColor="var(--tok-write)"
        />
        <StatCard
          label={`${avoidable > 0 ? "Avoidable spend" : "Cache events"} (${winLabel})`}
          helpId={avoidable > 0 ? "tile.cache_avoidable" : "tile.cache_events"}
          icon={avoidable > 0 ? <CoinsIcon /> : <BoltIcon />}
          value={
            avoidable > 0 ? fmtUSD(avoidable) : fmtInt(global.event_count ?? 0)
          }
          sub={
            avoidable > 0
              ? `${fmtInt(global.event_count ?? 0)} events · ${fmtInt(global.session_count ?? 0)} sessions`
              : `${fmtInt(global.session_count ?? 0)} session${global.session_count === 1 ? "" : "s"} · ${fmtInt(projectCount)} project${projectCount === 1 ? "" : "s"}`
          }
          delta={deltas.events ?? undefined}
          deltaLabel={priorLabel}
          spark={sparks.events}
          sparkColor={avoidable > 0 ? "var(--warn)" : "var(--info)"}
          warn={avoidable > 0}
        />
        <MispredictRateTile health={health} />
      </div>

      {/* §15.3 implicit-cache row — renders only when implicit-cache
          events exist in the window (OpenAI / codex / OpenAI-routed
          adapters). Surfaces prefix-survival rate + engine-consistency
          on a separate row from the Anthropic gate so the operator
          can't conflate the two surfaces. */}
      {(health?.implicit_cache_events ?? 0) > 0 && (
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          <ImplicitCacheTile health={health} />
          <div className="rounded-3 border border-fg-2/10 bg-bg-2/40 px-3 py-2 text-[11px] text-fg-2">
            <span className="font-semibold uppercase tracking-[0.06em] text-info">
              Implicit cache scope
            </span>{" "}
            §15.3 reduced attribution path. Anthropic-only events are graded
            by the marker-aware §10 gate above; OpenAI / codex / cline-cli-
            via-deepseek / opencode+kilo-on-OpenAI events grade against a
            per-session 128-token-granule prefix estimate. The two
            surfaces are kept disjoint by design (
            <HelpInd id="glossary.cachetrack_codex_limitation" />
            ).
          </div>
        </div>
      )}

      {/* Two-column rollups — By model + By project — promoted from
          single-line bullets to real tables with mix bars and explicit
          Read / Write / Events / Ratio columns. Matches the Cost
          ModelTable cadence so a single CSS pass styles both. */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <ChartShell
          title={<TitleWithHelp text="By model" helpId="chart.cache_by_model" />}
          sub={`Per-model cache traffic · ${fmtInt(modelCount)} model${modelCount === 1 ? "" : "s"}`}
          right={
            <ExportButton
              disabled={modelRows.length === 0}
              onClick={() => exportByDimensionCsv("model", "cache-by-model", modelRows)}
            />
          }
        >
          {modelRows.length === 0 ? (
            <EmptyHint text="No model-attributed cache traffic." />
          ) : (
            <ByDimensionTable
              keyHeader="Model"
              keyHelpId="column.cost.model"
              rows={modelRows}
            />
          )}
        </ChartShell>

        <ChartShell
          title={<TitleWithHelp text="By project" helpId="chart.cache_by_project" />}
          sub={`Per-project cache traffic · ${fmtInt(projectCount)} project${projectCount === 1 ? "" : "s"}`}
          right={
            <ExportButton
              disabled={projectRows.length === 0}
              onClick={() => exportByDimensionCsv("project", "cache-by-project", projectRows)}
            />
          }
        >
          {projectRows.length === 0 ? (
            <EmptyHint text="No project-attributed cache traffic." />
          ) : (
            <ByDimensionTable
              keyHeader="Project"
              keyHelpId="column.sessions.project"
              rows={projectRows}
            />
          )}
        </ChartShell>
      </div>

      {/* Per-day chart panels — mirrors the Cost page's three-chart
          cadence below its table. Cache traffic (R+W stacked) +
          Events (healthy + rewrites stacked) sit side by side; the
          ratio trajectory gets a full-width row underneath since
          the ratio's signal is easier to read uncluttered. */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <ChartShell
          title={<TitleWithHelp text="Cache traffic per day" helpId="chart.cache_traffic_per_day" />}
          sub="Read + write tokens, stacked"
        >
          <ChartState
            loading={timeseriesLoading}
            error={timeseriesError}
            empty={!timeseries?.series?.length}
            emptyHint="No cache traffic in window."
            height={220}
          >
            {timeseries?.series?.length ? (
              <CacheTrafficChart data={timeseries.series} />
            ) : null}
          </ChartState>
        </ChartShell>

        <ChartShell
          title={<TitleWithHelp text="Events per day" helpId="chart.cache_events_per_day" />}
          sub="Healthy events + rewrites (warn) overlay"
        >
          <ChartState
            loading={timeseriesLoading}
            error={timeseriesError}
            empty={!timeseries?.series?.length}
            emptyHint="No events in window."
            height={220}
          >
            {timeseries?.series?.length ? (
              <CacheEventsChart data={timeseries.series} />
            ) : null}
          </ChartState>
        </ChartShell>
      </div>

      <ChartShell
        title={<TitleWithHelp text="Cache ratio trajectory" helpId="chart.cache_ratio_trajectory" />}
        sub="Per-day point-wise R/W ratio · gaps on zero-write days"
      >
        <ChartState
          loading={timeseriesLoading}
          error={timeseriesError}
          empty={!timeseries?.series?.length}
          emptyHint="No cache traffic in window."
          height={180}
        >
          {timeseries?.series?.length ? (
            <CacheRatioChart data={timeseries.series} />
          ) : null}
        </ChartState>
      </ChartShell>

      {/* Entry-state distribution — global snapshot from cache_entries.
          Not windowed (the entries table is a current snapshot, not
          a historical series). Compact row above Top causes. */}
      <ChartShell
        title={<TitleWithHelp text="Entry state distribution" helpId="chart.cache_entry_states" />}
        sub="cache_entries grouped by state · live = healthy warm; unverified / expired / invalidated = engine declared stale"
      >
        {!entryStates || entryStates.rows.length === 0 ? (
          <EmptyHint text="No cache entries yet - the engine populates this table as it sees writes." />
        ) : (
          <EntryStatesBar rows={entryStates.rows} total={entryStates.total} />
        )}
      </ChartShell>

      {/* Recent cache events — paginated drill-down. Mirrors the
          Compression tab's recent-events list shape. */}
      <ChartShell
        title={<TitleWithHelp text="Recent cache events" helpId="chart.cache_recent_events" />}
        sub={
          events
            ? `Showing ${events.rows.length} of ${fmtInt(events.total)} events · newest first`
            : "loading…"
        }
        right={
          events && events.total > events.limit ? (
            <Pager
              total={events.total}
              limit={events.limit}
              offset={eventsOffset}
              onChange={onEventsOffsetChange}
            />
          ) : undefined
        }
      >
        <ChartState
          loading={eventsLoading}
          error={eventsError}
          empty={!events || events.rows.length === 0}
          emptyHint="No cache events match the current filters."
        >
          {events && events.rows.length > 0 ? (
            <RecentEventsTable rows={events.rows} onOpen={onOpenSession} />
          ) : null}
        </ChartState>
      </ChartShell>

      {/* Lower row — Top causes (proportional bars) + Worst sessions
          (real table with click-through). */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <ChartShell
          title={<TitleWithHelp text="Top causes" helpId="chart.cache_top_causes" />}
          sub="suffix_growth + hit dominate a healthy session; bars scale to event count"
        >
          {data.top_causes.length === 0 ? (
            <EmptyHint text="No cause data." />
          ) : (
            <TopCausesBars rows={data.top_causes} />
          )}
        </ChartShell>

        <ChartShell
          title={<TitleWithHelp text="Worst sessions" helpId="chart.cache_worst_sessions" />}
          sub="ranked by rewrite count · click a row to open the session's cache timeline"
        >
          {data.worst_sessions.length === 0 ? (
            <EmptyHint text="No rewrites yet - the cache hasn't been invalidated for any session in the corpus." />
          ) : (
            <WorstSessionsTable
              rows={data.worst_sessions}
              onOpen={onOpenSession}
            />
          )}
        </ChartShell>
      </div>
    </>
  );
}

// ----------------------------------------------------- Mispredict-rate tile

// MispredictRateTile surfaces the cachetrack grading-gate result
// as a fifth headline tile. Renders the rate (0% on healthy
// corpora), the graded-event denominator, and the gate-pass/fail
// state. Warn-toned when GatePassed=false AND we have enough events
// to judge; info-toned when below the grading minimum (denominator
// too thin to judge yet).
function MispredictRateTile({
  health,
}: {
  health: CacheHealthSummary | null;
}) {
  if (!health) {
    return (
      <StatCard
        label="Mispredict rate"
        helpId="tile.cache_mispredict_rate"
        icon={<BoltIcon />}
        value="-"
        sub="loading engine health"
      />
    );
  }
  const denom = health.graded_events;
  const pct = health.mispredict_rate;
  const minEvents = health.min_events_threshold;
  const belowMinimum = denom < minEvents;
  const warnNow = !belowMinimum && !health.gate_passed;
  let sub: string;
  if (belowMinimum) {
    sub = `${fmtInt(denom)}/${fmtInt(minEvents)} graded - below grading minimum`;
  } else if (warnNow) {
    sub = `${fmtInt(health.mispredicts)} mispredicts / ${fmtInt(denom)} graded · >${fmtPct(health.max_rate_threshold)} gate`;
  } else {
    sub = `${fmtInt(health.mispredicts)} mispredicts / ${fmtInt(denom)} graded · grading gate passed`;
  }
  return (
    <StatCard
      label="Anthropic mispredict rate"
      helpId="tile.cache_mispredict_rate"
      icon={<BoltIcon />}
      value={denom > 0 ? fmtPct(pct) : "-"}
      sub={sub}
      warn={warnNow}
    />
  );
}

// ImplicitCacheTile renders §15.3 implicit-cache efficiency: the
// prefix-survival rate (hits / (hits + misses)) over OpenAI / codex /
// OpenAI-routed adapter cache_events. Hidden when no implicit events
// exist in the window. The "lower fidelity" framing is honest — the
// implicit-cache path grades against per-session prefix estimates,
// not provider markers.
function ImplicitCacheTile({
  health,
}: {
  health: CacheHealthSummary | null;
}) {
  if (!health) return null;
  const events = health.implicit_cache_events ?? 0;
  if (events === 0) return null;
  const hits = health.implicit_cache_hits ?? 0;
  const misses = health.implicit_cache_misses ?? 0;
  const churn = health.implicit_cache_prefix_churn_rate ?? 0;
  const consistency = health.implicit_cache_consistency_rate ?? 0;
  const consistencyDenom = health.implicit_cache_consistency_denom ?? 0;
  // High miss rate flagged as warn — operator-actionable signal
  // that the prompt prefix is churning (eviction or prompt drift).
  const warnNow = hits + misses > 0 && hits / (hits + misses) < 0.5;
  return (
    <StatCard
      label="Implicit prefix-survival"
      helpId="tile.cache_implicit_prefix_survival"
      icon={<DropletIcon />}
      value={hits + misses > 0 ? fmtPct(churn) : "-"}
      sub={
        consistencyDenom > 0
          ? `${fmtInt(hits)}H / ${fmtInt(misses)}M · engine consistency ${fmtPct(consistency)} (lower fidelity)`
          : `${fmtInt(hits)} hit${hits === 1 ? "" : "s"} / ${fmtInt(misses)} miss${misses === 1 ? "" : "es"} · lower fidelity than Anthropic`
      }
      warn={warnNow}
    />
  );
}

// ----------------------------------------------------- Untracked-provider banner

// UntrackedProviderBanner surfaces the §15.3 implicit-cache coverage
// reality. Before §15.3 this banner said "we saw codex but didn't
// grade it"; with §15.3 OpenAI / codex / OpenAI-routed adapters DO
// emit cache_events — they land on a separate (lower-fidelity)
// implicit-cache surface, NOT the Anthropic §10 gate. The banner
// flips between three states:
//
//   1. Implicit-cache events present → "tracked via implicit cache
//      (lower fidelity)" — informative, not a warning.
//   2. Untracked turns but no implicit events → "proxy / binary may
//      pre-date §15.3" — actionable hint.
//   3. Neither → hidden.
//
// Info-toned (not warn) in every case; not engine drift.
function UntrackedProviderBanner({
  health,
}: {
  health: CacheHealthSummary | null;
}) {
  if (!health) return null;
  const untrackedTurns = health.untracked_provider_turns ?? 0;
  const untrackedSessions = health.untracked_provider_sessions ?? 0;
  const tool = health.untracked_provider_top_tool || "OpenAI";
  const implicitEvents = health.implicit_cache_events ?? 0;

  if (untrackedTurns === 0 && implicitEvents === 0) return null;

  // §15.3 path: implicit events present → "tracked via implicit cache"
  if (implicitEvents > 0) {
    const churn = health.implicit_cache_prefix_churn_rate ?? 0;
    const consistency = health.implicit_cache_consistency_rate ?? 0;
    return (
      <div className="flex flex-wrap items-center gap-2 rounded-3 border border-info/30 bg-info-soft/30 px-3 py-2 text-[11px] text-fg-2">
        <span className="font-semibold uppercase tracking-[0.06em] text-info">
          Provider coverage
        </span>
        <span>
          <strong className="text-fg-1">
            {fmtInt(implicitEvents)} implicit-cache event
            {implicitEvents === 1 ? "" : "s"}
          </strong>{" "}
          tracked via §15.3 reduced attribution (lower fidelity than the
          Anthropic marker-aware path - graded on per-session prefix
          estimates, not provider markers). Prefix-survival {fmtPct(churn)}
          {consistency > 0 ? ` · engine consistency ${fmtPct(consistency)}` : ""}
          . Anthropic §10 gate is unmoved.
        </span>
        <HelpInd id="glossary.cachetrack_codex_limitation" />
      </div>
    );
  }

  // Pre-§15.3 binary or no implicit traffic captured yet.
  return (
    <div className="flex flex-wrap items-center gap-2 rounded-3 border border-info/30 bg-info-soft/30 px-3 py-2 text-[11px] text-fg-2">
      <span className="font-semibold uppercase tracking-[0.06em] text-info">
        Provider coverage
      </span>
      <span>
        Proxy observed{" "}
        <strong className="text-fg-1">
          {fmtInt(untrackedSessions)} {tool} session
          {untrackedSessions === 1 ? "" : "s"}
        </strong>{" "}
        ({fmtInt(untrackedTurns)} turn{untrackedTurns === 1 ? "" : "s"}) in the
        last 7 days but captured zero implicit-cache events - the daemon
        binary may pre-date §15.3 (rebuild + restart). Tokens, cost, and
        actions are captured normally for these sessions either way.
      </span>
      <HelpInd id="glossary.cachetrack_codex_limitation" />
    </div>
  );
}

// ----------------------------------------------------- Health banner

// CacheHealthBanner surfaces the cachetrack engine's two
// informational secondary checks (read:write consistency + cause
// concentration) + the bucket-mispredict drift surface as small
// pills inside one banner row. Hidden entirely
// when every signal is clean. Mirrors Cost's unknown-model pill
// pattern but rolls multiple signals into one banner since they're
// all engine-health flavored.
function CacheHealthBanner({ health }: { health: CacheHealthSummary | null }) {
  if (!health) return null;
  const pills: React.ReactNode[] = [];
  if (health.dominant_cause) {
    const c = health.dominant_cause;
    pills.push(
      <span
        key="dominant"
        className="inline-flex items-center gap-1.5 rounded-2 border border-warn/40 bg-warn-soft px-2.5 py-1 text-[10.5px] font-medium text-warn"
        title="A non-baseline cause exceeds the 80% share threshold over graded events - likely an over-firing rule. Open the engine-health entry in the help drawer for the full check list."
      >
        <span aria-hidden>!</span>
        {c.cause} dominates ({fmtPct(c.share)} of {fmtInt(c.count)} events)
      </span>,
    );
  }
  if (health.inconsistent_rewrite_count > 0) {
    pills.push(
      <span
        key="inconsistent"
        className="inline-flex items-center gap-1.5 rounded-2 border border-warn/40 bg-warn-soft px-2.5 py-1 text-[10.5px] font-medium text-warn"
        title="Rewrite events with tokens_read > 3× tokens_written are mechanically inconsistent with a real invalidation - the cause may be mislabeled."
      >
        <span aria-hidden>!</span>
        {fmtInt(health.inconsistent_rewrite_count)} inconsistent rewrite
        {health.inconsistent_rewrite_count === 1 ? "" : "s"}
      </span>,
    );
  }
  if (health.bucket_mispredicts > 0) {
    pills.push(
      <span
        key="bucket"
        className="inline-flex items-center gap-1.5 rounded-2 border border-warn/40 bg-warn-soft px-2.5 py-1 text-[10.5px] font-medium text-warn"
        title="bucket(predicted) ≠ bucket(observed) - engine drift the grading-rate gate is blind to (growth-turn mispredicts can land in the same hit-vs-write bucket and slip past the rate check)."
      >
        <span aria-hidden>!</span>
        {fmtInt(health.bucket_mispredicts)} bucket-mismatch event
        {health.bucket_mispredicts === 1 ? "" : "s"}
      </span>,
    );
  }
  if (pills.length === 0) return null;
  return (
    <div className="flex flex-wrap items-center gap-2 rounded-3 border border-warn/30 bg-warn-soft/30 px-3 py-2 text-[11px] text-fg-2">
      <span className="font-semibold uppercase tracking-[0.06em] text-warn">
        Engine warnings
      </span>
      {pills}
    </div>
  );
}

// ----------------------------------------------------- Empty hint

function EmptyHint({ text }: { text: string }) {
  return <p className="px-1 py-2 text-[11px] text-fg-3">{text}</p>;
}

// ----------------------------------------------------- By-dimension table

type ByDimensionRow = {
  key: string;
  display: string;
  title: string;
  read: number;
  write: number;
  ratio: number;
  events: number;
  avoidable: number;
  mono?: boolean;
};

// ByDimensionTable renders the per-model / per-project rollup as a
// proper table: mix bars (R% / W%) on the left, absolute token
// columns next, then the strong-typeface ratio. Mirrors Cost's
// ModelTable cadence (Th/Td/MixCell pattern) so the two pages share
// visual rhythm. keyHelpId points to the help entry that explains
// the leftmost key column (model name for By-model, project root
// for By-project).
function ByDimensionTable({
  keyHeader,
  keyHelpId,
  rows,
}: {
  keyHeader: string;
  keyHelpId: string;
  rows: ByDimensionRow[];
}) {
  // maxAvoidable used to highlight rows pulling the most overhead $.
  const maxAvoidable = useMemo(
    () => Math.max(0, ...rows.map((r) => r.avoidable)),
    [rows],
  );
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[640px] text-left text-[11.5px]">
        <thead className="text-[10px] uppercase tracking-[0.06em] text-fg-3">
          <tr className="border-b border-line-2">
            <Th>{keyHeader}<HelpInd id={keyHelpId} /></Th>
            <Th align="right">R %<HelpInd id="metric.cache_read" /></Th>
            <Th align="right">W %<HelpInd id="metric.cache_creation" /></Th>
            <Th align="right">Read<HelpInd id="metric.cache_read" /></Th>
            <Th align="right">Write<HelpInd id="metric.cache_creation" /></Th>
            <Th align="right">Events<HelpInd id="tile.cache_events" /></Th>
            <Th align="right">Ratio<HelpInd id="tile.cache_ratio" /></Th>
            <Th align="right">Avoidable<HelpInd id="tile.cache_avoidable" /></Th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => {
            const total = r.read + r.write;
            const readPct = total > 0 ? r.read / total : 0;
            const writePct = total > 0 ? r.write / total : 0;
            return (
              <tr
                key={r.key}
                className={
                  "border-b border-line-1 last:border-b-0 hover:bg-bg-3 " +
                  (i % 2 === 1 ? "bg-bg-3/40" : "")
                }
              >
                <Td mono={r.mono} title={r.title}>
                  <span className="block max-w-[260px] truncate">
                    {r.display}
                  </span>
                </Td>
                <MixCell pct={readPct} color="var(--tok-read)" />
                <MixCell pct={writePct} color="var(--tok-write)" />
                <Td align="right" mono>
                  {fmtCompact(r.read)}
                </Td>
                <Td align="right" mono>
                  {fmtCompact(r.write)}
                </Td>
                <Td align="right" mono>
                  {fmtInt(r.events)}
                </Td>
                <Td align="right" mono>
                  <strong className="text-fg-0">
                    {r.ratio > 0 ? `${r.ratio.toFixed(1)}×` : "-"}
                  </strong>
                </Td>
                <Td align="right" mono>
                  {r.avoidable > 0 ? (
                    <span
                      className={
                        r.avoidable === maxAvoidable
                          ? "font-semibold text-warn"
                          : "text-fg-2"
                      }
                    >
                      {fmtUSD(r.avoidable)}
                    </span>
                  ) : (
                    <span className="text-fg-3">-</span>
                  )}
                </Td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// ----------------------------------------------------- Top causes bars

function TopCausesBars({ rows }: { rows: CacheOverviewCauseRow[] }) {
  const max = Math.max(1, ...rows.map((r) => r.count));
  return (
    <ul className="space-y-1.5">
      {rows.map((c) => {
        const width = (c.count / max) * 100;
        const variant = causeVariant(c.cause, c.flagged === true);
        const barColor =
          variant === "info"
            ? "var(--info)"
            : variant === "warn"
              ? "var(--warn)"
              : "var(--fg-3)";
        return (
          <li
            key={c.cause}
            className="flex items-center gap-3 text-[11.5px]"
          >
            <span className="w-[180px] shrink-0">
              <CausePill cause={c.cause} flagged={c.flagged === true} />
            </span>
            <span className="relative flex-1">
              <span
                aria-hidden
                className="block h-2 overflow-hidden rounded-pill bg-bg-3"
              >
                <span
                  className="block h-full transition-[width] duration-200"
                  style={{
                    width: `${width}%`,
                    background: barColor,
                    opacity: 0.85,
                  }}
                />
              </span>
            </span>
            <span className="w-[68px] shrink-0 text-right font-mono tabular-nums text-fg-2">
              {fmtInt(c.count)}
            </span>
          </li>
        );
      })}
    </ul>
  );
}

// ----------------------------------------------------- Worst sessions table

function WorstSessionsTable({
  rows,
  onOpen,
}: {
  rows: CacheOverviewSessionRow[];
  onOpen: (sid: string) => void;
}) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[640px] text-left text-[11.5px]">
        <thead className="text-[10px] uppercase tracking-[0.06em] text-fg-3">
          <tr className="border-b border-line-2">
            <Th>Session<HelpInd id="column.sessions.id" /></Th>
            <Th>Model<HelpInd id="column.cost.model" /></Th>
            <Th>Tier<HelpInd id="glossary.proxy_vs_jsonl" /></Th>
            <Th align="right">Rewrites<HelpInd id="chart.cache_worst_sessions" /></Th>
            <Th align="right">Read<HelpInd id="metric.cache_read" /></Th>
            <Th align="right">Write<HelpInd id="metric.cache_creation" /></Th>
            <Th>Top cause<HelpInd id="chart.cache_top_causes" /></Th>
          </tr>
        </thead>
        <tbody>
          {rows.map((s, i) => (
            <tr
              key={s.session_id}
              className={
                "cursor-pointer border-b border-line-1 last:border-b-0 transition-colors hover:bg-bg-3 " +
                (i % 2 === 1 ? "bg-bg-3/40" : "")
              }
              onClick={() => onOpen(s.session_id)}
            >
              <Td mono title={s.session_id}>
                <span className="font-mono text-accent">
                  {fmtShortId(s.session_id, 8)}
                </span>
              </Td>
              <Td mono>
                <span className="block max-w-[180px] truncate">
                  {s.model || "-"}
                </span>
              </Td>
              <Td>
                <TierPill tier={s.tier} />
              </Td>
              <Td align="right" mono>
                <strong className="text-fg-0">{fmtInt(s.rewrite_count)}</strong>
              </Td>
              <Td align="right" mono>
                {fmtCompact(s.tokens_read)}
              </Td>
              <Td align="right" mono>
                {fmtCompact(s.tokens_written)}
              </Td>
              <Td>
                {s.top_cause ? (
                  <CausePill
                    cause={s.top_cause}
                    flagged={s.top_cause === "tools_changed"}
                  />
                ) : (
                  <span className="text-fg-3">-</span>
                )}
              </Td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// TierPill renders the capture-path tier from the worst-sessions
// row. proxy = Tier-1 live (info-toned, the real-time path);
// transcript = Tier-2 backfill (neutral, historical reconstruction);
// mixed = both (warn-toned because it signals a re-walked session
// where the engine ran twice and may have grading drift). Empty
// tier renders as a plain dash so the table doesn't carry a
// misleading pill on legacy rows.
function TierPill({ tier }: { tier?: string }) {
  if (!tier) return <span className="text-fg-3">-</span>;
  if (tier === "proxy") return <Pill variant="info">{tier}</Pill>;
  if (tier === "transcript") return <Pill variant="neutral">{tier}</Pill>;
  if (tier === "mixed") return <Pill variant="warn">{tier}</Pill>;
  return <Pill variant="neutral">{tier}</Pill>;
}

// ----------------------------------------------------- Th / Td / MixCell

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
  title,
}: {
  children: React.ReactNode;
  align?: "left" | "right";
  mono?: boolean;
  title?: string;
}) {
  return (
    <td
      title={title}
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

// ----------------------------------------------------- Cause pill

// causeVariant maps a cause label to its visual tone. Operator UI
// steer #2: flagged causes render neutrally (currently tools_changed
// — legitimate MCP server toggles); suffix_growth + hit are the
// healthy info-toned baseline; real invalidation causes go warn.
function causeVariant(
  cause: string,
  flagged: boolean,
): "info" | "neutral" | "warn" {
  if (flagged) return "neutral";
  if (cause === "suffix_growth" || cause === "hit") return "info";
  if (cause === "reanchor" || cause === "below_min") return "neutral";
  return "warn";
}

function CausePill({ cause, flagged }: { cause: string; flagged: boolean }) {
  const variant = causeVariant(cause, flagged);
  return <Pill variant={variant}>{cause}</Pill>;
}

// shortProjectPath compacts a long absolute path for display. Keeps
// the last two segments — usually enough to identify the project
// without wrapping the row. Full path lives in title= for hover.
function shortProjectPath(p: string): string {
  if (!p) return "(unknown)";
  const segments = p.split("/").filter(Boolean);
  if (segments.length <= 2) return p;
  return ".../" + segments.slice(-2).join("/");
}

// ----------------------------------------------------- EntryStatesBar

// EntryStatesBar renders the cache_entries.state breakdown as a
// horizontal stacked bar — live (info), unverified (neutral),
// expired (warn), invalidated (danger). The bar is full-width;
// each segment carries the share % and the absolute count.
function EntryStatesBar({
  rows,
  total,
}: {
  rows: { state: string; count: number }[];
  total: number;
}) {
  if (total === 0) {
    return <EmptyHint text="cache_entries table is empty." />;
  }
  return (
    <div className="space-y-3">
      <div className="flex h-3 w-full overflow-hidden rounded-pill bg-bg-3">
        {rows.map((r) => {
          const pct = (r.count / total) * 100;
          return (
            <span
              key={r.state || "(unknown)"}
              className="block h-full transition-[width] duration-200"
              style={{
                width: `${pct}%`,
                background: entryStateColor(r.state),
              }}
              title={`${r.state}: ${fmtInt(r.count)} (${fmtPct(r.count / total)})`}
            />
          );
        })}
      </div>
      <ul className="flex flex-wrap gap-x-4 gap-y-1 text-[11px]">
        {rows.map((r) => (
          <li
            key={r.state || "(unknown)"}
            className="flex items-center gap-1.5"
          >
            <span
              aria-hidden
              className="inline-block h-2 w-2 rounded-pill"
              style={{ background: entryStateColor(r.state) }}
            />
            <span className="font-mono text-fg-2">{r.state || "(empty)"}</span>
            <span className="tabular-nums text-fg-3">
              {fmtInt(r.count)} · {fmtPct(r.count / total)}
            </span>
          </li>
        ))}
        <li className="ml-auto tabular-nums text-fg-3">
          total {fmtInt(total)}
        </li>
      </ul>
    </div>
  );
}

function entryStateColor(state: string): string {
  switch (state) {
    case "live":
      return "var(--info)";
    case "unverified":
      return "var(--fg-3)";
    case "expired":
      return "var(--warn)";
    case "invalidated":
      return "var(--danger)";
    default:
      return "var(--line-3)";
  }
}

// ----------------------------------------------------- Pager

// Pager is a minimal prev/next pair used by the recent-events
// drill-down. Doesn't show absolute page numbers — operator-facing
// signal is "more to see" rather than "exactly page 3 of 12".
function Pager({
  total,
  limit,
  offset,
  onChange,
}: {
  total: number;
  limit: number;
  offset: number;
  onChange: (n: number) => void;
}) {
  const atStart = offset === 0;
  const atEnd = offset + limit >= total;
  const cls = (disabled: boolean) =>
    "rounded-2 border border-line-2 bg-bg-2 px-2 py-1 text-[10.5px] text-fg-2 hover:bg-bg-3 disabled:opacity-40 " +
    (disabled ? "cursor-not-allowed" : "");
  return (
    <div className="flex items-center gap-1.5">
      <button
        type="button"
        disabled={atStart}
        onClick={() => onChange(Math.max(0, offset - limit))}
        className={cls(atStart)}
      >
        ← Prev
      </button>
      <span className="px-1 text-[10.5px] tabular-nums text-fg-3">
        {fmtInt(offset + 1)}–{fmtInt(Math.min(offset + limit, total))} of{" "}
        {fmtInt(total)}
      </span>
      <button
        type="button"
        disabled={atEnd}
        onClick={() => onChange(offset + limit)}
        className={cls(atEnd)}
      >
        Next →
      </button>
    </div>
  );
}

// ----------------------------------------------------- RecentEventsTable

// RecentEventsTable renders the paginated /api/cache/events rows
// in a slim table. Click a row to open the session's Cache panel.
// Bucket-mismatch rows (predicted ≠ observed bucket) get a small
// warn-toned ⚠ next to the predicted column so the operator can
// scan for engine drift at a glance.
function RecentEventsTable({
  rows,
  onOpen,
}: {
  rows: CacheEventRow[];
  onOpen: (sid: string) => void;
}) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[860px] text-left text-[11.5px]">
        <thead className="text-[10px] uppercase tracking-[0.06em] text-fg-3">
          <tr className="border-b border-line-2">
            <Th>When</Th>
            <Th>Session<HelpInd id="column.sessions.id" /></Th>
            <Th>Model<HelpInd id="column.cost.model" /></Th>
            <Th>Tier<HelpInd id="glossary.proxy_vs_jsonl" /></Th>
            <Th>Kind</Th>
            <Th>Cause</Th>
            <Th>Predicted</Th>
            <Th align="right">Read<HelpInd id="metric.cache_read" /></Th>
            <Th align="right">Write<HelpInd id="metric.cache_creation" /></Th>
          </tr>
        </thead>
        <tbody>
          {rows.map((ev, i) => (
            <tr
              key={ev.id}
              className={
                "cursor-pointer border-b border-line-1 last:border-b-0 transition-colors hover:bg-bg-3 " +
                (i % 2 === 1 ? "bg-bg-3/40" : "")
              }
              onClick={() => onOpen(ev.session_id)}
            >
              <Td mono title={fmtDateTime(ev.timestamp)}>{fmtShortTimestamp(ev.timestamp)}</Td>
              <Td mono title={ev.session_id}>
                <span className="font-mono text-accent">
                  {fmtShortId(ev.session_id, 8)}
                </span>
              </Td>
              <Td mono>
                <span className="block max-w-[180px] truncate">
                  {ev.model || "-"}
                </span>
              </Td>
              <Td>
                <TierPill tier={ev.tier} />
              </Td>
              <Td>
                <KindPill kind={ev.kind} />
              </Td>
              <Td>
                {ev.cause ? (
                  <CausePill
                    cause={ev.cause}
                    flagged={ev.cause === "tools_changed"}
                  />
                ) : (
                  <span className="text-fg-3">-</span>
                )}
              </Td>
              <Td mono>
                {ev.predicted_kind ? (
                  <span
                    className={
                      ev.predicted_kind !== ev.kind ? "text-warn" : "text-fg-3"
                    }
                    title={
                      ev.predicted_kind !== ev.kind
                        ? `Predicted ${ev.predicted_kind}, observed ${ev.kind} - possible engine drift`
                        : undefined
                    }
                  >
                    {ev.predicted_kind}
                  </span>
                ) : (
                  <span className="text-fg-3">-</span>
                )}
              </Td>
              <Td align="right" mono>
                {fmtCompact(ev.tokens_read)}
              </Td>
              <Td align="right" mono>
                {fmtCompact(ev.tokens_written)}
              </Td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// KindPill maps the cache_events.kind label to a tonal pill.
// hit/write are healthy (info); rewrites are warn-toned;
// mispredict / reanchor / below_min are neutral diagnostic kinds.
function KindPill({ kind }: { kind: string }) {
  if (kind === "hit" || kind === "write") return <Pill variant="info">{kind}</Pill>;
  if (
    kind === "invalidation_rewrite" ||
    kind === "expiry_rewrite" ||
    kind === "model_switch_rewrite" ||
    kind === "compaction_reset"
  ) {
    return <Pill variant="warn">{kind}</Pill>;
  }
  return <Pill variant="neutral">{kind}</Pill>;
}

// fmtShortTimestamp truncates an ISO timestamp to "MMM dd HH:MM"
// for the recent-events table; full timestamp lives on hover via
// the row's title (the operator can copy the full ISO from the
// session detail panel when they need it).
function fmtShortTimestamp(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
}

// pctChange returns the signed fractional change from `then` to
// `now` (e.g. 0.12 for +12%, -0.05 for −5%). Returns null when
// either side is non-finite OR the base is zero (no meaningful
// percentage from a zero baseline). StatCard treats a null delta
// as "no delta to show" (the badge is suppressed).
function pctChange(now: number, then: number): number | null {
  if (!Number.isFinite(now) || !Number.isFinite(then)) return null;
  if (then === 0) return null;
  return (now - then) / Math.abs(then);
}

// ExportButton mirrors Cost's plain button used in the
// `ChartShell.right` slot. Disabled when there's nothing to
// export so the user can't trigger an empty-CSV download.
function ExportButton({
  onClick,
  disabled,
}: {
  onClick: () => void;
  disabled: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className="rounded-2 border border-line-2 bg-bg-2 px-2 py-1 text-[10.5px] text-fg-2 hover:bg-bg-3 disabled:opacity-40"
      title="Download this rollup as CSV"
    >
      Export
    </button>
  );
}

// exportByDimensionCsv serializes a ByDimensionRow array into the
// shared CSV column shape (key / read / write / read_pct / write_pct
// / events / ratio / avoidable_usd) and triggers a browser download.
// Mirrors Cost.tsx::exportModelsCsv but operates on the cache
// rollup row shape — same Blob + ObjectURL pattern.
function exportByDimensionCsv(
  dimension: "model" | "project",
  fileStem: string,
  rows: ByDimensionRow[],
) {
  if (rows.length === 0) return;
  const header = [
    dimension,
    "read_tokens",
    "write_tokens",
    "read_pct",
    "write_pct",
    "events",
    "ratio",
    "avoidable_usd",
  ].join(",");
  const lines = rows.map((r) => {
    const total = r.read + r.write;
    const readPct = total > 0 ? r.read / total : 0;
    const writePct = total > 0 ? r.write / total : 0;
    return [
      escapeCsv(r.title || r.display),
      r.read,
      r.write,
      readPct.toFixed(4),
      writePct.toFixed(4),
      r.events,
      r.ratio.toFixed(4),
      r.avoidable.toFixed(6),
    ].join(",");
  });
  const csv = [header, ...lines].join("\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${fileStem}-${isoDateStamp()}.csv`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function escapeCsv(s: string): string {
  if (!s) return "";
  if (/[",\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

// isoDateStamp returns today's date as YYYY-MM-DD without pulling
// a date library - used to disambiguate exported CSV file names.
function isoDateStamp(): string {
  return new Date().toISOString().slice(0, 10);
}

// deriveSparks turns the daily timeseries into per-tile spark
// arrays. The ratio series is computed point-wise (read / write)
// with a divide-by-zero guard so the hero tile reads its own
// per-day cadence rather than just mirroring the cache_read line.
function deriveSparks(ts?: CacheTimeseriesResponse | null): CacheSparks {
  const empty: CacheSparks = { ratio: [], read: [], write: [], events: [] };
  if (!ts?.series?.length) return empty;
  return {
    ratio: ts.series.map((p) =>
      p.written_tokens > 0 ? p.read_tokens / p.written_tokens : 0,
    ),
    read: ts.series.map((p) => p.read_tokens),
    write: ts.series.map((p) => p.written_tokens),
    events: ts.series.map((p) => p.event_count),
  };
}
