import { hasNonZero } from "@shared/lib/seriesEmpty";
import { Fragment, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import type { ColumnDef } from "@tanstack/react-table";
import {
  ChartShell,
  HeroStat,
  Icon,
  ModelId,
  PageHeader,
  Pill,
  SegmentedControl,
  StatCard,
  Tooltip,
  Stagger,
  SuccessCheck,
} from "@/components/primitives";
import { HelpInd, TitleWithHelp } from "@/components/HelpInd";
import { CopyOnClick } from "@/components/CopyOnClick";
import {
  CompressionSavingsChart,
  SavingsByMechanismDonut,
  type SavingsUnit,
} from "@/components/charts";
import { ChartState } from "@/components/ChartState";
import { ExperimentsCard } from "@/components/ExperimentsCard";
import { DataTable, Pagination } from "@/components/DataTable";
import { useFilters, useGranularity, windowParams } from "@/lib/filters";
import { GranControl } from "@/components/GranControl";
import { asGranularity, granularityUnit, perBucketTitle } from "@shared/lib/granularity";
import { useApi } from "@/lib/useApi";
import {
  fmtBytes,
  fmtCompact,
  fmtDateTime,
  fmtInt,
  fmtPct,
  fmtShortId,
  fmtUSD,
} from "@/lib/format";
import type {
  CompactionEventsResponse,
  CompressionByModelResponse,
  CompressionEventsResponse,
  CompressionRetrieval,
  CompressionRollingCost,
  CompressionTimeseries,
  SetupClaude,
  SetupCodex,
} from "@/lib/types";
import { ChevronDown, ChevronUp } from "lucide-react";
import { navIcon } from "@/lib/nav";
import { MetricIcon } from "@/components/MetricIcon";

const EVENTS_LIMIT = 25;

// Explanatory copy for lossy-eviction mechanisms (e.g. `drop`). Their
// bytes are removed from the payload with no compressed form, so they
// are rendered as "evicted" and never as savings or dollars saved —
// see internal/intelligence/dashboard/compression_mechanism.go.
const EVICTED_TOOLTIP =
  "Evicted (dropped) content - low-importance messages removed from the payload, not compressed. There is no compressed form, so this is not a byte saving. The removed content is recoverable via the search_past_outputs / stash markers.";
const EVICTED_USD_TOOLTIP =
  "Not a dollar saving. Evicted content has no compressed form to price - showing a $ figure here would present lossy eviction as compression savings.";

export function CompressionPage() {
  const { win, customRange, tool, project } = useFilters();
  const winParams = windowParams(win, customRange);
  // Three endpoints below are capped at a year of history server-side;
  // windowParams clamps the span to match (day/hours/custom all).
  const cappedParams = windowParams(win, customRange, { maxDays: 365 });
  // Chart bucket: the shared granularity rule + the viewer's `gran=`.
  const gran = useGranularity();
  const projectParam = project === "all" ? undefined : project;
  const toolParam = tool === "all" ? undefined : tool;

  const [unit, setUnit] = useState<SavingsUnit>("usd");
  const [page, setPage] = useState(1);

  const setupClaude = useApi<SetupClaude>("/api/setup/claude");
  const setupCodex = useApi<SetupCodex>("/api/setup/codex");
  const timeseries = useApi<CompressionTimeseries>(
    "/api/compression/timeseries",
    { ...winParams, ...gran.params, tool: toolParam, project: projectParam },
    [win, customRange, tool, project, gran.params],
  );
  const tsGran = asGranularity(timeseries.data?.bucket ?? gran.expected);
  const hasCompression = hasNonZero(timeseries.data?.series, ["total_count"]);
  const events = useApi<CompressionEventsResponse>(
    "/api/compression/events",
    { ...winParams, page, limit: EVENTS_LIMIT, tool: toolParam, project: projectParam },
    [win, customRange, page, tool, project],
  );
  const retrieval = useApi<CompressionRetrieval>(
    "/api/compression/retrieval",
    { ...cappedParams, tool: toolParam, project: projectParam },
    [win, customRange, tool, project],
  );
  const compaction = useApi<CompactionEventsResponse>(
    "/api/compaction/events",
    { ...cappedParams, tool: toolParam, project: projectParam },
    [win, customRange, tool, project],
  );
  const rolling = useApi<CompressionRollingCost>(
    "/api/compression/rolling-cost",
    { ...cappedParams, tool: toolParam, project: projectParam },
    [win, customRange, tool, project],
  );
  const byModel = useApi<CompressionByModelResponse>(
    "/api/compression/by-model",
    { ...winParams, tool: toolParam, project: projectParam },
    [win, customRange, tool, project],
  );

  const totals = useMemo(
    () => deriveTotals(timeseries.data),
    [timeseries.data],
  );
  // Kept undefined rather than defaulted, so the two tiles that show an
  // estimated token count em-dash alongside the byte total they derive
  // from instead of claiming a confident 0.
  const tokensEst = totals.bytes === undefined ? undefined : totals.bytes / 4;

  return (
    <div className="space-y-6 p-4 sm:p-6">
      <PageHeader
        icon={navIcon("compression")}
        title="Compression"
        sub="How many tokens, dollars, and bytes the proxy saved by trimming conversation context before forwarding upstream. KPIs, daily savings trajectory, savings-by-mechanism donut, recent events, and beta surfaces (SROD retrieve rate, compaction events, rolling-summarisation net delta)."
        helpId="tab.compression"
      />
      <SetupBanner
        claude={setupClaude.data}
        codex={setupCodex.data}
        onChanged={() => {
          setupClaude.reload();
          setupCodex.reload();
        }}
      />

      {/* Design 1.22: HeroStat for Total savings (~2/5 of the row at
          xl, full width below xl) + 4 smaller StatCards on the right.
          The hero's sub-line carries the events + bytes + token
          breakdown so the four right-side tiles can keep their
          narrower focus. */}
      <div className="grid grid-cols-1 gap-3 xl:grid-cols-[1.4fr_minmax(0,1fr)_minmax(0,1fr)_minmax(0,1fr)_minmax(0,1fr)]">
        <HeroStat
          label="Total compression savings"
          icon={<MetricIcon metric="compressionSavings" />}
          loading={timeseries.loading}
          value={fmtUSD(totals.usd)}
          sub={
            <>
              across {fmtInt(totals.events)} compression events ·{" "}
              {fmtBytes(totals.bytes)} trimmed from upstream payloads · ~
              {fmtCompact(tokensEst)} tokens
              {(totals.evicted ?? 0) > 0 && (
                <>
                  {" · "}
                  <Tooltip content={EVICTED_TOOLTIP}>
                    <span
                      tabIndex={0}
                      className="cursor-help text-warn focus:outline-none"
                    >
                      {fmtBytes(totals.evicted)} evicted (not counted as
                      savings)
                    </span>
                  </Tooltip>
                </>
              )}
            </>
          }
          spark={totals.sparkUsd}
          sparkColor="var(--success)"
          variant="accent"
        />
        <StatCard
          label="Tokens saved"
          icon={<MetricIcon metric="tokens" />}
          loading={timeseries.loading}
          value={fmtCompact(tokensEst)}
          sub="≈ bytes ÷ 4 (Claude tokenizer)"
          spark={totals.sparkBytes}
          sparkColor="var(--tok-net)"
        />
        <StatCard
          label="Dollars saved"
          icon={<MetricIcon metric="savings" />}
          loading={timeseries.loading}
          value={fmtUSD(totals.usd)}
          sub="priced at row's model input rate"
          spark={totals.sparkUsd}
          sparkColor="var(--success)"
        />
        <StatCard
          label="Bytes saved"
          icon={<MetricIcon metric="bytes" />}
          loading={timeseries.loading}
          value={fmtBytes(totals.bytes)}
          sub={`across ${fmtInt(totals.days)} active ${granularityUnit(tsGran)}${totals.days === 1 ? "" : "s"}`}
          spark={totals.sparkBytes}
          sparkColor="var(--tok-read)"
        />
        <StatCard
          label="Turns compressed"
          icon={<MetricIcon metric="turnsCompressed" />}
          loading={timeseries.loading}
          value={fmtInt(totals.events)}
          sub={
            totals.topMech
              ? `top mech: ${totals.topMech}`
              : "events across the window"
          }
          spark={totals.sparkEvents}
          sparkColor="var(--accent)"
        />
      </div>

      {/* Profile experiments (P6.4) — productized A/B over Track-R
          profiles; reports recompute arms from the session hash. */}
      <ExperimentsCard />

      {/* Savings: per-bucket stack + by-mechanism donut, side-by-side */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[1.5fr_1fr]">
        <ChartShell
          title={<TitleWithHelp text={perBucketTitle("Savings", tsGran)} helpId="chart.compression_over_time" />}
          sub={`${describeUnit(unit)}. Mechanisms: json / code / logs / text / diff / html / drop / tools / stash / read_cache / rolling_summary.`}
          right={
            <div className="flex flex-wrap items-center gap-2">
              <GranControl served={timeseries.data} />
              <SegmentedControl<SavingsUnit>
                options={[
                  { value: "usd", label: "$" },
                  { value: "tokens", label: "Tokens" },
                  { value: "bytes", label: "Bytes" },
                ]}
                value={unit}
                onChange={setUnit}
              />
            </div>
          }
        >
          <ChartState
            loading={timeseries.loading && !timeseries.data}
            error={timeseries.error}
            denied={timeseries.denied}
            deniedPermission={timeseries.deniedPermission}
            empty={!hasCompression}
            emptyHint="No compression events in window. The proxy compresses request bodies on the way out - make sure Claude Code is routed through the proxy (see Setup banner above)."
            height={260}
          >
            {timeseries.data && (
              <CompressionSavingsChart
                data={timeseries.data.series}
                unit={unit}
                granularity={tsGran}
              />
            )}
          </ChartState>
        </ChartShell>

        <ChartShell
          title={<TitleWithHelp text="Savings by mechanism" helpId="chart.compression_by_mechanism" />}
          sub={`Rolled-up share of ${describeUnit(unit).toLowerCase()} per mechanism · ${win}`}
        >
          <ChartState
            loading={timeseries.loading && !timeseries.data}
            error={timeseries.error}
            denied={timeseries.denied}
            deniedPermission={timeseries.deniedPermission}
            empty={!hasCompression}
            emptyHint="No compression activity to break down."
            height={260}
          >
            {timeseries.data && (
              <SavingsByMechanismDonut
                data={timeseries.data}
                unit={unit}
              />
            )}
          </ChartState>
        </ChartShell>
      </div>

      {/* Per-model breakdown */}
      <ChartShell
        title={<TitleWithHelp text="Per-model breakdown" helpId="chart.compression.by_model" />}
        sub="Compression savings rolled up per model × mechanism. $ is estimated by pricing saved bytes at the model's input rate (4 bytes/token)."
      >
        <ChartState
          loading={byModel.loading && !byModel.data}
          error={byModel.error}
          denied={byModel.denied}
          deniedPermission={byModel.deniedPermission}
          empty={!byModel.loading && !byModel.data?.rows.length}
          emptyHint="No per-model compression activity in window."
          height={180}
        >
          {byModel.data && <CompressionByModelTable rows={byModel.data.rows} />}
        </ChartState>
      </ChartShell>

      {/* Recent events table */}
      <ChartShell
        title="Recent compression events"
        sub={`Latest events with per-row mechanism, savings, importance, message slot. ${fmtInt(events.data?.total)} total in window.`}
      >
        <ChartState
          loading={events.loading && !events.data}
          error={events.error}
          denied={events.denied}
          deniedPermission={events.deniedPermission}
          empty={!events.loading && !events.data?.rows.length}
          emptyHint="No compression events recorded."
          height={200}
        >
          {events.data && <CompressionEventsTable rows={events.data.rows} />}
        </ChartState>
        {events.data && (
          <Pagination
            page={events.data.page}
            limit={events.data.limit}
            total={events.data.total}
            onPage={setPage}
            loading={events.loading}
          />
        )}
      </ChartShell>

      {/* SROD — Stash & Retrieve on Demand */}
      <ChartShell
        title={
          <span className="flex items-center gap-2">
            Reversibility - SROD (Stash &amp; Retrieve on Demand)
            <BetaTag>gpb</BetaTag>
          </span>
        }
        sub="Is stash-and-retrieve paying off? Large tool outputs are offloaded to a local stash and replaced inline with a marker; the model pulls them back on demand. A low retrieve rate is healthy - it means the offloaded bodies were rarely needed."
      >
        <ChartState
          loading={retrieval.loading && !retrieval.data}
          error={retrieval.error}
          denied={retrieval.denied}
          deniedPermission={retrieval.deniedPermission}
          empty={!retrieval.data || retrieval.data.total_stashes === 0}
          emptyHint="No stashes recorded in window. SROD activates on tool_result bodies above the importance threshold."
          height={200}
        >
          {retrieval.data && <RetrievalPanel data={retrieval.data} />}
        </ChartState>
      </ChartShell>

      {/* Compaction events */}
      <ChartShell
        title={
          <span className="flex items-center gap-2">
            Compaction events
            <BetaTag>d23</BetaTag>
          </span>
        }
        sub="Post-compact recovery - when Claude Code's /compact fires, the proxy injects ghost-file snapshots so the next turn knows what was already loaded."
      >
        <ChartState
          loading={compaction.loading && !compaction.data}
          error={compaction.error}
          denied={compaction.denied}
          deniedPermission={compaction.deniedPermission}
          empty={!compaction.data || compaction.data.count === 0}
          emptyHint="No /compact events in window."
          height={200}
        >
          {compaction.data && <CompactionPanel data={compaction.data} />}
        </ChartState>
      </ChartShell>

      {/* Rolling summarisation net cost */}
      <ChartShell
        title={
          <span className="flex items-center gap-2">
            Rolling-summarisation net cost
            <BetaTag>d20</BetaTag>
          </span>
        }
        sub="Anthropic Haiku summary calls vs. the cache_creation savings they unlock on subsequent turns. Positive = paying off."
      >
        <ChartState
          loading={rolling.loading && !rolling.data}
          error={rolling.error}
          denied={rolling.denied}
          deniedPermission={rolling.deniedPermission}
          empty={!rolling.data || rolling.data.summary_calls === 0}
          emptyHint="No rolling-summary calls in window."
          height={140}
        >
          {rolling.data && <RollingPanel data={rolling.data} />}
        </ChartState>
      </ChartShell>
    </div>
  );
}

// --------------------------------------------------------------- helpers

// deriveTotals yields undefined — never 0 — for every metric when there
// is no timeseries to total. StatCard's loading flag also goes false on
// error, so an all-zero fallback stops pulsing and settles into a
// confident "$0.00 saved across 0 events", which is a different claim
// from "we don't know yet". The formatters in lib/format.ts are all
// null-safe and render an em dash, so loading keeps the pulse and an
// error settles to a STATIC em dash. Follow-up to e3847247, which fixed
// the identical shape in Cost.tsx's summarize().
function deriveTotals(ts?: CompressionTimeseries | null) {
  if (!ts) {
    return {
      usd: undefined,
      bytes: undefined,
      evicted: undefined,
      events: undefined,
      days: undefined,
      topMech: "",
      topMechUSD: undefined,
      sparkUsd: [] as number[],
      sparkBytes: [] as number[],
      sparkEvents: [] as number[],
    };
  }
  let usd = 0,
    bytes = 0,
    evicted = 0,
    events = 0,
    days = 0;
  const byMech: Record<string, number> = {};
  const sparkUsd: number[] = [];
  const sparkBytes: number[] = [];
  const sparkEvents: number[] = [];
  for (const p of ts.series) {
    if (p.total_saved_usd_est > 0 || p.total_saved_bytes > 0 || p.total_count > 0)
      days++;
    usd += p.total_saved_usd_est;
    bytes += p.total_saved_bytes;
    evicted += p.total_evicted_bytes;
    events += p.total_count;
    sparkUsd.push(p.total_saved_usd_est);
    sparkBytes.push(p.total_saved_bytes);
    sparkEvents.push(p.total_count);
    for (const [m, s] of Object.entries(p.by_mechanism)) {
      byMech[m] = (byMech[m] ?? 0) + s.saved_usd_est;
    }
  }
  let topMech = "",
    topMechUSD = 0;
  for (const [m, v] of Object.entries(byMech)) {
    if (v > topMechUSD) {
      topMech = m;
      topMechUSD = v;
    }
  }
  return {
    usd,
    bytes,
    evicted,
    events,
    days,
    topMech,
    topMechUSD,
    sparkUsd,
    sparkBytes,
    sparkEvents,
  };
}

function describeUnit(u: SavingsUnit): string {
  switch (u) {
    case "usd":
      return "Dollars saved";
    case "tokens":
      return "Token estimate (saved_bytes ÷ 4)";
    case "bytes":
      return "Bytes saved";
  }
}

// --------------------------------------------------------------- Setup

function SetupBanner({
  claude,
  codex,
  onChanged,
}: {
  claude: SetupClaude | null;
  codex: SetupCodex | null;
  onChanged: () => void;
}) {
  const [expanded, setExpanded] = useState<"claude" | "codex" | null>(null);
  if (!claude && !codex) return null;
  const claudeOK =
    claude?.status === "oauth_ready" || claude?.status === "api_key_ready";
  const codexOK = codex?.status === "routed_to_observer";
  const allOK = claudeOK && codexOK;
  const intent = allOK ? "success" : "warn";
  const intentBorder =
    intent === "success" ? "border-success/30" : "border-warn/30";
  const intentBg = intent === "success" ? "bg-success-soft" : "bg-warn-soft";
  const intentFg = intent === "success" ? "text-success" : "text-warn";
  return (
    <div
      className={`rounded-3 border text-[11.5px] ${intentBorder} ${intentBg}`}
    >
      <div className="flex items-center gap-3 px-4 py-2">
        <span className={`font-semibold ${intentFg}`}>Proxy</span>
        <StatusPill
          label="Claude"
          status={claude?.status ?? "unknown"}
          ok={claudeOK}
          active={expanded === "claude"}
          onClick={() =>
            setExpanded((cur) => (cur === "claude" ? null : "claude"))
          }
        />
        <StatusPill
          label="Codex"
          status={codex?.status ?? "unknown"}
          ok={codexOK}
          active={expanded === "codex"}
          onClick={() =>
            setExpanded((cur) => (cur === "codex" ? null : "codex"))
          }
        />
        {claude && claude.proxy_port > 0 && (
          <span className="text-fg-3">port {claude.proxy_port}</span>
        )}
        <div className="flex-1" />
        {!allOK && (
          <Link
            to="/settings?section=compression"
            className="rounded-2 border border-line-2 bg-bg-2 px-2.5 py-1 font-semibold text-fg-1 hover:bg-bg-3"
          >
            Configure now
          </Link>
        )}
      </div>
      {expanded === "claude" && claude && (
        <>
          <ExpandedDetail
            rows={[
              ["Status", claude.status],
              ["Proxy port", claude.proxy_port ? String(claude.proxy_port) : "-"],
              ["Proxy URL", claude.proxy_url || "-"],
              ["Credentials path", claude.credentials_path || "-"],
              ["OAuth credentials", claude.has_oauth_credentials ? "yes" : "no"],
              [
                "Claude binary",
                claude.claude_binary_found
                  ? claude.claude_binary_path || "found"
                  : "not installed",
              ],
              ["Launcher command", claude.launcher_command || "-"],
              [
                "Durable route",
                claude.routed_to_observer
                  ? `routed to this observer (${claude.routed_base_url})`
                  : claude.routed_base_url
                    ? `set to ${claude.routed_base_url}`
                    : "(not set)",
              ],
              ["Settings file", claude.settings_path || "-"],
            ]}
          />
          <RouteAction
            endpoint="/api/setup/claude"
            routed={claude.routed_to_observer}
            wouldRegister={claude.would_register}
            conflictError={claude.would_register_error}
            configPath={claude.settings_path || "~/.claude/settings.json"}
            writeSummary={`Writes "env": { "ANTHROPIC_BASE_URL": "${claude.proxy_url}" } into the file below. Claude Code picks it up on its next session - every session then routes through the proxy (exact tokens, compression, cache tracking) with no wrapper command.`}
            routedNote="New Claude Code sessions route through this observer. Undo: remove the env entry from settings.json, or run `observer uninstall --claude-code`."
            onChanged={onChanged}
          />
        </>
      )}
      {expanded === "codex" && codex && (
        <>
          <ExpandedDetail
            rows={[
              ["Status", codex.status],
              ["Config path", codex.config_path || "-"],
              ["Config exists", codex.config_exists ? "yes" : "no"],
              ["Proxy port", codex.proxy_port ? String(codex.proxy_port) : "-"],
              ["Desired base URL", codex.desired_base_url || "-"],
              [
                "Current base URL",
                codex.current_base_url || "(unset)",
              ],
              [
                "Desired model provider",
                codex.desired_model_provider || "-",
              ],
              [
                "Reserved openai block",
                codex.has_reserved_openai_block ? "yes" : "no",
              ],
              ...(codex.auth_mode
                ? [["Auth mode", codex.auth_mode] as const]
                : []),
              ...(codex.would_register_error
                ? [["Register error", codex.would_register_error] as const]
                : []),
            ]}
          />
          <RouteAction
            endpoint="/api/setup/codex"
            routed={codex.status === "routed_to_observer"}
            wouldRegister={codex.would_register}
            conflictError={codex.would_register_error}
            configPath={codex.config_path || "~/.codex/config.toml"}
            writeSummary={`Adds an "${codex.desired_model_provider}" model provider with base_url ${codex.desired_base_url} to the file below and points codex at it. Codex picks it up on its next run - sessions route through the proxy with no wrapper command.`}
            routedNote="Codex routes through this observer. Undo: remove the provider from config.toml, or run `observer uninstall --codex`."
            onChanged={onChanged}
          />
        </>
      )}
    </div>
  );
}

// RouteAction — the L1 one-click durable-routing control (usability
// arc P1.5/P1.6). Explicit-consent flow: the button never writes on
// first click; it expands a preview of the exact file change, and only
// the confirm click POSTs. A 409 conflict (a base URL the user set
// deliberately) surfaces the server's explanation and requires a
// separate force confirmation.
function RouteAction({
  endpoint,
  routed,
  wouldRegister,
  conflictError,
  configPath,
  writeSummary,
  routedNote,
  onChanged,
}: {
  endpoint: string;
  routed: boolean;
  wouldRegister: boolean;
  conflictError?: string;
  configPath: string;
  writeSummary: string;
  routedNote: string;
  onChanged: () => void;
}) {
  const [phase, setPhase] = useState<
    "idle" | "confirm" | "forceConfirm" | "working"
  >("idle");
  const [err, setErr] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);

  async function run(force: boolean) {
    setPhase("working");
    setErr(null);
    try {
      const res = await fetch(endpoint, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ force }),
      });
      const out = (await res.json().catch(() => null)) as
        | { error?: string; already_set?: boolean }
        | null;
      if (res.status === 409) {
        setErr(out?.error ?? "conflict - an existing value blocks the write");
        setPhase("forceConfirm");
        return;
      }
      if (!res.ok) {
        throw new Error(out?.error || `HTTP ${res.status}`);
      }
      setDone(
        out?.already_set
          ? "Already routed - nothing to change."
          : "Routed. New sessions go through the proxy.",
      );
      setPhase("idle");
      onChanged();
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
      setPhase("idle");
    }
  }

  return (
    <div className="border-t border-line-1 px-4 py-3 text-[11.5px]">
      {routed ? (
        <p className="m-0 text-fg-3">
          <span className="font-semibold text-success">Routed.</span>{" "}
          {routedNote}
        </p>
      ) : (
        <div className="space-y-2">
          {phase === "idle" && (
            <div className="flex flex-wrap items-center gap-3">
              <button
                type="button"
                onClick={() => setPhase("confirm")}
                className="rounded-2 bg-accent px-2.5 py-1 font-semibold text-accent-on transition-opacity hover:opacity-90"
              >
                Route through the observer proxy…
              </button>
              {!wouldRegister && conflictError && (
                <span className="text-warn">{conflictError}</span>
              )}
              {done && <SuccessCheck label={done} />}
              {err && <span className="text-danger">{err}</span>}
            </div>
          )}
          {(phase === "confirm" || phase === "forceConfirm") && (
            <div className="rounded-2 border border-line-2 bg-bg-2 p-3">
              <p className="m-0 text-fg-2">{writeSummary}</p>
              <p className="m-0 mt-1 font-mono text-fg-3">{configPath}</p>
              {phase === "forceConfirm" && err && (
                <p className="m-0 mt-2 text-warn">
                  {err} - overwriting replaces a value you (or another
                  tool) set deliberately.
                </p>
              )}
              <div className="mt-2 flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => run(phase === "forceConfirm")}
                  className={`rounded-2 px-2.5 py-1 font-semibold ${
                    phase === "forceConfirm"
                      ? "bg-warn text-bg-0"
                      : "bg-accent text-accent-on"
                  } transition-opacity hover:opacity-90`}
                >
                  {phase === "forceConfirm"
                    ? "Force overwrite"
                    : "Write it"}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setPhase("idle");
                    setErr(null);
                  }}
                  className="rounded-2 border border-line-2 bg-bg-2 px-2.5 py-1 text-fg-2 hover:bg-bg-3"
                >
                  Cancel
                </button>
              </div>
            </div>
          )}
          {phase === "working" && <span className="text-fg-3">Writing…</span>}
        </div>
      )}
    </div>
  );
}

function StatusPill({
  label,
  status,
  ok,
  active,
  onClick,
}: {
  label: string;
  status: string;
  ok: boolean;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <Tooltip content={`Show ${label} setup detail`}>
    <button
      type="button"
      onClick={onClick}
      className={`inline-flex items-center gap-1.5 rounded-pill border px-2 py-0.5 text-[10.5px] transition-colors ${
        active
          ? "border-accent/60 bg-bg-2"
          : "border-line-2 bg-bg-2/60 hover:border-line-3"
      }`}
    >
      <span className="font-semibold text-fg-2">{label}:</span>
      <span className={ok ? "font-mono text-success" : "font-mono text-warn"}>
        {status}
      </span>
      <Icon icon={active ? ChevronUp : ChevronDown} size={10} className="text-fg-4" />
    </button>
    </Tooltip>
  );
}

function ExpandedDetail({
  rows,
}: {
  rows: readonly (readonly [string, string])[];
}) {
  if (rows.length === 0) return null;
  return (
    <dl className="grid grid-cols-[140px_minmax(0,1fr)] gap-x-3 gap-y-1 border-t border-line-1 px-4 py-2 text-[11px]">
      {rows.map(([k, v]) => (
        <Fragment key={k}>
          <dt className="text-fg-3">{k}</dt>
          <dd className="min-w-0 break-words font-mono text-fg-1">{v}</dd>
        </Fragment>
      ))}
    </dl>
  );
}

// --------------------------------------------------------------- Events

type CompressionEventRow = CompressionEventsResponse["rows"][number];
type CompactionEventRow = CompactionEventsResponse["events"][number];
// KeyedByModelRow carries a row key that survives client sorting (the
// server may repeat a model|mechanism pair).
type KeyedByModelRow = CompressionByModelResponse["rows"][number] & { rowKey: string };

// SAVE_BANDS colours a save ratio, walked top-down: the first row whose
// `min` the ratio reaches wins. A negative ratio (the compressor grew the
// payload) is its own band; anything else below 20%, and a non-number,
// renders neutral.
type SaveBand = { min: number; bar: string; text: string };
const SAVE_NEUTRAL: SaveBand = { min: 0, bar: "var(--fg-3)", text: "text-fg-3" };
const SAVE_BANDS: readonly SaveBand[] = [
  { min: 0.5, bar: "var(--success)", text: "text-success" },
  { min: 0.2, bar: "var(--info)", text: "text-fg-1" },
  SAVE_NEUTRAL,
  { min: -Infinity, bar: "var(--danger)", text: "text-danger" },
];

function saveBand(ratio: number): SaveBand {
  return SAVE_BANDS.find((b) => ratio >= b.min) ?? SAVE_NEUTRAL;
}

// IMPORTANCE_BANDS colours an importance score the same way.
const IMPORTANCE_BANDS: readonly { min: number; text: string }[] = [
  { min: 0.7, text: "text-success" },
  { min: 0.4, text: "text-fg-1" },
  { min: -Infinity, text: "text-fg-3" },
];

function importanceText(score: number): string {
  return IMPORTANCE_BANDS.find((b) => score >= b.min)?.text ?? "text-fg-3";
}

// EvictedDash is the "-" a lossy (evicted) row shows where a dollar saving
// would be, with the reason in a tooltip.
function EvictedDash() {
  return (
    <Tooltip content={EVICTED_USD_TOOLTIP}>
      <span tabIndex={0} className="cursor-help text-fg-4 focus:outline-none">
        -
      </span>
    </Tooltip>
  );
}

// EvictedBytes is the saved-bytes cell of a lossy row.
function EvictedBytes({ bytes }: { bytes: number }) {
  return (
    <Tooltip content={EVICTED_TOOLTIP}>
      <span tabIndex={0} className="cursor-help text-warn focus:outline-none">
        {fmtBytes(bytes)} evicted
      </span>
    </Tooltip>
  );
}

// RelativeWhen is a relative timestamp with the absolute one in a tooltip.
function RelativeWhen({ iso }: { iso: string }) {
  return (
    <Tooltip content={fmtDateTime(iso)}>
      <span tabIndex={0} className="cursor-help text-fg-2 focus:outline-none">
        {relativeTime(iso)}
      </span>
    </Tooltip>
  );
}

// The events list is SERVER-paginated newest first, so no column sorts (a
// client sort would only reorder the current page).
const COMPRESSION_EVENT_COLUMNS: ColumnDef<CompressionEventRow, unknown>[] = [
  {
    id: "when",
    header: "When",
    enableSorting: false,
    cell: ({ row }) => <RelativeWhen iso={row.original.timestamp} />,
  },
  {
    id: "mech",
    header: "Mech",
    enableSorting: false,
    cell: ({ row }) => (
      <span className={"font-mono " + (row.original.lossy ? "text-warn" : "text-fg-1")}>
        {row.original.mechanism}
      </span>
    ),
  },
  {
    id: "model",
    header: () => <>Model<HelpInd id="column.compression.model" /></>,
    enableSorting: false,
    meta: { mono: true },
    cell: ({ row }) =>
      row.original.model ? <ModelId model={row.original.model} className="min-w-0" /> : "-",
  },
  {
    id: "original",
    header: () => <>Original<HelpInd id="column.compression.original" /></>,
    enableSorting: false,
    meta: { align: "right" },
    cell: ({ row }) => <span className="text-fg-2">{fmtBytes(row.original.original_bytes)}</span>,
  },
  {
    id: "compressed",
    header: () => <>Compressed<HelpInd id="column.compression.compressed" /></>,
    enableSorting: false,
    meta: { align: "right" },
    cell: ({ row }) =>
      row.original.lossy ? (
        <span className="text-fg-4">-</span>
      ) : (
        <span className="text-fg-2">{fmtBytes(row.original.compressed_bytes)}</span>
      ),
  },
  {
    id: "saved",
    header: () => <>Saved<HelpInd id="column.compression.saved" /></>,
    enableSorting: false,
    meta: { align: "right" },
    cell: ({ row }) =>
      row.original.lossy ? (
        <EvictedBytes bytes={row.original.evicted_bytes} />
      ) : (
        <span className="text-fg-1">{fmtBytes(row.original.saved_bytes)}</span>
      ),
  },
  {
    id: "save_pct",
    header: () => <>Save %<HelpInd id="column.compression.saved_pct" /></>,
    enableSorting: false,
    meta: { align: "right" },
    cell: ({ row }) => {
      const r = row.original;
      if (r.lossy) {
        return (
          <div className="flex justify-end">
            <Tooltip content={EVICTED_TOOLTIP}>
              <span tabIndex={0} className="cursor-help text-right text-warn focus:outline-none">
                evicted
              </span>
            </Tooltip>
          </div>
        );
      }
      const savePct = r.original_bytes > 0 ? r.saved_bytes / r.original_bytes : 0;
      const band = saveBand(savePct);
      return (
        <div className="ml-auto flex max-w-[140px] items-center justify-end gap-2">
          <div className="h-1.5 w-[80px] overflow-hidden rounded-pill bg-bg-3">
            <span
              className="block h-full"
              style={{
                width: `${Math.max(0, Math.min(100, savePct * 100))}%`,
                background: band.bar,
              }}
            />
          </div>
          <span className={"tabular-nums " + band.text}>{fmtPct(savePct)}</span>
        </div>
      );
    },
  },
  {
    id: "saved_usd",
    header: () => <>$ saved<HelpInd id="column.compression.saved" /></>,
    enableSorting: false,
    meta: { align: "right" },
    cell: ({ row }) =>
      row.original.lossy ? (
        <EvictedDash />
      ) : (
        <span className="text-fg-0">
          {row.original.saved_usd_est > 0 ? fmtUSD(row.original.saved_usd_est) : "-"}
        </span>
      ),
  },
  {
    id: "slot",
    header: "Slot",
    enableSorting: false,
    meta: { align: "right" },
    cell: ({ row }) => (
      <span className="text-fg-3">{row.original.msg_index >= 0 ? row.original.msg_index : "-"}</span>
    ),
  },
  {
    id: "importance",
    header: "Importance",
    enableSorting: false,
    meta: { align: "right" },
    cell: ({ row }) => {
      const score = row.original.importance_score;
      if (score <= 0) return <span className="text-fg-4">-</span>;
      return (
        <Tooltip content={`importance_score = ${score.toFixed(3)}`}>
          <span tabIndex={0} className={`cursor-help focus:outline-none ${importanceText(score)}`}>
            {score.toFixed(2)}
          </span>
        </Tooltip>
      );
    },
  },
  {
    id: "session",
    header: "Session",
    enableSorting: false,
    cell: ({ row }) =>
      row.original.session_id ? (
        <CopyOnClick value={row.original.session_id} className="font-mono text-[11px] text-fg-2">
          {fmtShortId(row.original.session_id, 8)}
        </CopyOnClick>
      ) : (
        <span className="text-fg-4">-</span>
      ),
  },
  {
    id: "source",
    header: "Source",
    enableSorting: false,
    cell: ({ row }) =>
      row.original.is_subagent_runtime ? <Pill variant="accent">subagent</Pill> : <Pill>main</Pill>,
  },
];

function CompressionEventsTable({
  rows,
}: {
  rows: CompressionEventsResponse["rows"];
}) {
  return (
    <DataTable<CompressionEventRow>
      data={rows}
      columns={COMPRESSION_EVENT_COLUMNS}
      rowKey={(r) => String(r.id)}
      minWidth={1080}
      zebra
    />
  );
}

// The compaction list is the 12 most recent events; its order is the point,
// so no column sorts.
const COMPACTION_COLUMNS: ColumnDef<CompactionEventRow, unknown>[] = [
  {
    id: "when",
    header: "When",
    enableSorting: false,
    cell: ({ row }) => <RelativeWhen iso={row.original.timestamp} />,
  },
  {
    id: "tool",
    header: "Tool",
    enableSorting: false,
    meta: { mono: true },
    cell: ({ row }) => row.original.tool,
  },
  {
    id: "session",
    header: "Session",
    enableSorting: false,
    meta: { mono: true },
    cell: ({ row }) => (
      <span title={row.original.session_id}>{fmtShortId(row.original.session_id, 8)}</span>
    ),
  },
  {
    id: "pre_actions",
    header: "Pre-actions",
    enableSorting: false,
    meta: { align: "right" },
    cell: ({ row }) => <span className="text-fg-1">{fmtInt(row.original.pre_action_count)}</span>,
  },
  {
    id: "ghost_files",
    header: "Ghost files",
    enableSorting: false,
    meta: { align: "right" },
    cell: ({ row }) => <span className="text-fg-2">{fmtInt(row.original.ghost_files_after_count)}</span>,
  },
  {
    id: "file_snapshot",
    header: "File snapshot",
    enableSorting: false,
    meta: { align: "right" },
    cell: ({ row }) => <span className="text-fg-2">{fmtInt(row.original.file_snapshot_count)}</span>,
  },
  {
    id: "injected",
    header: "Injected",
    enableSorting: false,
    cell: ({ row }) =>
      row.original.injected_at ? <Pill variant="success">yes</Pill> : <Pill variant="danger">no</Pill>,
  },
];

// --------------------------------------------------------------- Retrieval

function RetrievalPanel({ data }: { data: CompressionRetrieval }) {
  return (
    <div className="space-y-3">
      <Stagger className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <StatCard label="Total stashes" icon={<MetricIcon metric="stashes" />} value={fmtInt(data.total_stashes)} />
        <StatCard
          label="Retrievals"
          icon={<MetricIcon metric="retrievals" />}
          value={fmtInt(data.stash_retrievals)}
          sub={
            data.total_stashes > 0
              ? fmtPct(data.stash_retrievals / data.total_stashes)
              : undefined
          }
        />
        <StatCard
          label="Retrieve rate"
          icon={<MetricIcon metric="retrieveRate" />}
          value={fmtPct(data.retrieve_rate)}
          sub="% retrieves per stash"
          accent={data.retrieve_rate > 0.5}
        />
        <StatCard
          label="Search hits"
          icon={<MetricIcon metric="searchHits" />}
          value={fmtInt(data.search_hits)}
          sub="FTS5 lookups"
        />
      </Stagger>

      {(data.stashed_samples.length > 0 ||
        data.top_searched_actions.length > 0) && (
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          {data.stashed_samples.length > 0 && (
            <div className="rounded-2 border border-line-1 bg-bg-3/40 p-3">
              <div className="mb-2 text-[10px] font-semibold uppercase tracking-[0.06em] text-fg-3">
                What&apos;s getting stashed
              </div>
              <ul className="space-y-1.5 text-[11px]">
                {data.stashed_samples.map((s) => (
                  <li key={s.sha} className="flex items-baseline gap-2">
                    <Tooltip
                      content={<span className="break-all font-mono">{s.sha}</span>}
                      maxWidth={360}
                    >
                      <span
                        tabIndex={0}
                        className="min-w-0 flex-1 cursor-help truncate font-mono text-fg-1 focus:outline-none"
                        title={s.snippet}
                      >
                        {s.snippet}
                      </span>
                    </Tooltip>
                    <span className="shrink-0 tabular-nums text-fg-3">
                      {fmtBytes(s.bytes)}
                      {s.retrieved_count > 0 && (
                        <span className="ml-1.5 text-accent">
                          ↩{fmtInt(s.retrieved_count)}
                        </span>
                      )}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}
          {data.top_searched_actions.length > 0 && (
            <div className="rounded-2 border border-line-1 bg-bg-3/40 p-3">
              <div className="mb-2 text-[10px] font-semibold uppercase tracking-[0.06em] text-fg-3">
                Top searched actions
              </div>
              <ul className="space-y-1 text-[11px]">
                {data.top_searched_actions.slice(0, 8).map((a) => (
                  <li
                    key={a.action_id}
                    className="flex items-baseline justify-between gap-2"
                  >
                    <span className="font-mono text-fg-1">
                      #{a.action_id}
                    </span>
                    <span className="tabular-nums text-fg-2">
                      {fmtInt(a.count)} hits
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// --------------------------------------------------------------- Compaction

function CompactionPanel({ data }: { data: CompactionEventsResponse }) {
  const rejectRate =
    data.count > 0 ? 1 - data.injections_fired / data.count : 0;
  return (
    <div className="space-y-3">
      <Stagger className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <StatCard label="/compact events" icon={<MetricIcon metric="compactEvents" />} value={fmtInt(data.count)} />
        <StatCard
          label="Sessions affected"
          icon={<MetricIcon metric="sessions" />}
          value={fmtInt(data.sessions_affected)}
        />
        <StatCard
          label="Injections fired"
          icon={<MetricIcon metric="injections" />}
          value={fmtInt(data.injections_fired)}
          sub={
            data.count > 0
              ? `${fmtPct(data.injections_fired / data.count)} of events`
              : undefined
          }
        />
        <StatCard
          label="Reject rate"
          icon={<MetricIcon metric="rejectRate" />}
          value={fmtPct(rejectRate)}
          warn={rejectRate > 0.2}
          sub="injection unavailable or skipped"
        />
      </Stagger>

      {data.events.length > 0 && (
        <DataTable<CompactionEventRow>
          data={data.events.slice(0, 12)}
          columns={COMPACTION_COLUMNS}
          rowKey={(e) => String(e.id)}
          minWidth={700}
        />
      )}
    </div>
  );
}

// --------------------------------------------------------------- Rolling

function RollingPanel({ data }: { data: CompressionRollingCost }) {
  const positive = data.net_delta_usd > 0;
  return (
    <Stagger className="grid grid-cols-2 gap-3 md:grid-cols-4">
      <StatCard
        label="Summary calls"
        icon={<MetricIcon metric="summaryCalls" />}
        value={fmtInt(data.summary_calls)}
        sub={`${fmtCompact(data.summary_input_tokens)} in · ${fmtCompact(data.summary_output_tokens)} out`}
      />
      <StatCard
        label="Summary cost"
        icon={<MetricIcon metric="summaryCost" />}
        value={fmtUSD(data.summary_cost_usd)}
        sub="Haiku spend"
      />
      <StatCard
        label="Savings unlocked"
        icon={<MetricIcon metric="savingsUnlocked" />}
        value={fmtUSD(data.rolling_savings_cost_usd_est)}
        sub={`${fmtCompact(data.rolling_savings_tokens_est)} cache_creation tokens`}
      />
      <StatCard
        label="Net delta"
        icon={<MetricIcon metric="netDelta" />}
        value={fmtUSD(data.net_delta_usd)}
        accent={positive}
        warn={!positive}
        sub={positive ? "paying off" : "losing money"}
      />
    </Stagger>
  );
}

// --------------------------------------------------------------- utils

// BetaTag — small green capsule next to a section title that flags
// the underlying protocol / draft ID (gpb / d23 / d20). Matches the
// design's section-status chip styling.
// The by-model rollup is not paginated, so every column sorts by its raw
// value; a lossy row sorts its Save % below every real ratio.
const BY_MODEL_COLUMNS: ColumnDef<KeyedByModelRow, unknown>[] = [
  {
    id: "model",
    header: "Model",
    accessorKey: "model",
    meta: { mono: true },
    cell: ({ row }) => (
      <span className="text-fg-1">
        <ModelId model={row.original.model} className="min-w-0" />
      </span>
    ),
  },
  {
    id: "mechanism",
    header: "Mechanism",
    accessorKey: "mechanism",
    cell: ({ row }) =>
      row.original.lossy ? (
        <Pill variant="warn" title={EVICTED_TOOLTIP}>
          {row.original.mechanism}
        </Pill>
      ) : (
        <Pill>{row.original.mechanism}</Pill>
      ),
  },
  {
    id: "events",
    header: "Events",
    accessorFn: (r) => r.events,
    meta: { align: "right" },
    cell: ({ row }) => <span className="text-fg-2">{fmtInt(row.original.events)}</span>,
  },
  {
    id: "original",
    header: "Original",
    accessorFn: (r) => r.original_bytes,
    meta: { align: "right" },
    cell: ({ row }) => <span className="text-fg-2">{fmtBytes(row.original.original_bytes)}</span>,
  },
  {
    id: "compressed",
    header: "Compressed",
    accessorFn: (r) => (r.lossy ? -1 : r.compressed_bytes),
    meta: { align: "right" },
    cell: ({ row }) =>
      row.original.lossy ? (
        <span className="text-fg-4">-</span>
      ) : (
        <span className="text-fg-2">{fmtBytes(row.original.compressed_bytes)}</span>
      ),
  },
  {
    id: "saved",
    header: "Saved",
    accessorFn: (r) => (r.lossy ? r.evicted_bytes : r.saved_bytes),
    meta: { align: "right" },
    cell: ({ row }) =>
      row.original.lossy ? (
        <EvictedBytes bytes={row.original.evicted_bytes} />
      ) : (
        <span className="text-fg-0">{fmtBytes(row.original.saved_bytes)}</span>
      ),
  },
  {
    id: "save_pct",
    header: "Save %",
    accessorFn: (r) =>
      r.lossy ? -Infinity : r.original_bytes > 0 ? r.saved_bytes / r.original_bytes : 0,
    meta: { align: "right" },
    cell: ({ row }) => {
      const r = row.original;
      if (r.lossy) return <span className="text-fg-4">evicted</span>;
      const savePct = r.original_bytes > 0 ? (r.saved_bytes / r.original_bytes) * 100 : 0;
      return <span className="text-fg-1">{`${savePct.toFixed(1)}%`}</span>;
    },
  },
  {
    id: "saved_usd",
    header: "$ saved (est)",
    accessorFn: (r) => (r.lossy ? -1 : r.saved_usd_est),
    meta: { align: "right" },
    cell: ({ row }) =>
      row.original.lossy ? (
        <EvictedDash />
      ) : row.original.saved_usd_est > 0 ? (
        <span className="font-semibold text-fg-0">{fmtUSD(row.original.saved_usd_est)}</span>
      ) : (
        <span className="text-fg-4">-</span>
      ),
  },
];

function CompressionByModelTable({
  rows,
}: {
  rows: CompressionByModelResponse["rows"];
}) {
  const keyed = useMemo<KeyedByModelRow[]>(
    () => rows.map((r, i) => ({ ...r, rowKey: `${r.model}|${r.mechanism}|${i}` })),
    [rows],
  );
  return (
    <div className="overflow-hidden rounded-2 border border-line-1">
      <DataTable<KeyedByModelRow>
        data={keyed}
        columns={BY_MODEL_COLUMNS}
        rowKey={(r) => r.rowKey}
        minWidth={820}
        zebra
      />
    </div>
  );
}

function BetaTag({ children }: { children: React.ReactNode }) {
  return (
    <Pill variant="success">{children}</Pill>
  );
}

function relativeTime(iso: string): string {
  const t = new Date(iso).getTime();
  if (!Number.isFinite(t)) return "-";
  const ms = Date.now() - t;
  if (ms < 0) return "future";
  const s = ms / 1000;
  if (s < 60) return `${Math.round(s)}s ago`;
  const m = s / 60;
  if (m < 60) return `${Math.round(m)}m ago`;
  const h = m / 60;
  if (h < 24) return `${Math.round(h)}h ago`;
  const d = h / 24;
  if (d < 14) return `${Math.round(d)}d ago`;
  return `${Math.round(d / 7)}w ago`;
}
