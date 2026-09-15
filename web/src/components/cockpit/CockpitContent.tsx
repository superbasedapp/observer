import { useMemo, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { IdLink, Pill, ToolBadge } from "@/components/primitives";
import { ResourceCharts, type SessionMetricsResponse } from "./ResourceCharts";
import { useApi } from "@/lib/useApi";
import { useNowTick } from "@/lib/useNowTick";
import { isRemoteView } from "@/lib/remote";
import { markRestartPending } from "@/lib/restartPending";
import { fmtBytes, fmtCompact, fmtInt, fmtUSD } from "@/lib/format";
import {
  activityLabel,
  basename,
  burnRate,
  enableProcessCapture,
  flattenProcs,
  fmtAgo,
  fmtCountdown,
  fmtElapsed,
  fmtTps,
  isLive,
  networkSummary,
  newestAssistantWithOutput,
  newestMessage,
  runningProcessCount,
  secondsSince,
  secondsUntil,
  shortId,
  tokensPerSec,
  tpsBasisLabel,
  utilPct,
  WEAK_LINK_CONFIDENCE,
  type BurnRate,
  type SessionNetworkSummary,
  type TerminalLinkErrorInfo,
  type TerminalSessionLink,
} from "@/lib/cockpit";
import type {
  CacheStatusResponse,
  CacheWindowStatus,
  MessageRow,
  PredictResponse,
  ProcessNode,
  SessionDetail,
  SessionMessages,
  SessionProcessResponse,
} from "@/lib/types";

// CockpitContent — Phase-2 body of the Session Cockpit. Given a resolved
// terminal→session link, it polls the per-section vitals (each an independent
// useApi so one failing endpoint never blanks the others) and lays them out
// compact and glanceable, top→bottom by glance priority. NOT a clone of the
// session-detail page — no message bodies, no big charts, no timelines.

type CockpitContentProps = {
  link: TerminalSessionLink | null;
  linkError: TerminalLinkErrorInfo | null;
  linkLoading: boolean;
  // Client mount instant — the elapsed floor before a session start time is
  // known (the link wire carries no launch timestamp).
  mountMs: number;
};

export function CockpitContent({ link, linkError, linkLoading, mountMs }: CockpitContentProps) {
  const now = useNowTick(1000);
  const correlated = Boolean(link?.correlated && link.session_id);
  const sessionId = correlated && link ? link.session_id : "";
  const tool = link?.tool ?? "";
  const confidence = link?.confidence ?? 0;

  // Phase 2 — independent per-section polls, all gated on a correlated session
  // id (null path ⇒ no request). Cadences per the frozen data lifecycle.
  const session = useApi<SessionDetail>(
    sessionId ? `/api/session/${sessionId}` : null,
    undefined,
    [sessionId],
    { refreshMs: 5000 },
  );
  const messages = useApi<SessionMessages>(
    sessionId ? `/api/session/${sessionId}/messages` : null,
    { tail: 6 },
    [sessionId],
    { refreshMs: 5000 },
  );
  const predict = useApi<PredictResponse>(
    sessionId ? `/api/session/${sessionId}/predict` : null,
    undefined,
    [sessionId],
    { refreshMs: 15000 },
  );
  const cache = useApi<CacheStatusResponse>(
    sessionId ? `/api/cache/status` : null,
    sessionId ? { session: sessionId } : {},
    [sessionId],
    { refreshMs: 5000 },
  );
  const procs = useApi<SessionProcessResponse>(
    sessionId ? `/api/session/${sessionId}/processes` : null,
    undefined,
    [sessionId],
    { refreshMs: 5000 },
  );
  // Subtree-aggregated, server-differentiated resource series for the System
  // charts. Deliberately a SEPARATE poll from /processes: the tree endpoint
  // also drives debounced correlation WRITE passes, while this one is a pure
  // read. Same 5s cadence as the tree so the two stay visually in step; the
  // bucket is left to the server, which derives it from the observed sampling
  // cadence rather than any hardcoded interval.
  const metrics = useApi<SessionMetricsResponse>(
    sessionId ? `/api/session/${sessionId}/metrics` : null,
    undefined,
    [sessionId],
    { refreshMs: 5000 },
  );
  const network = useApi<SessionNetworkSummary>(
    sessionId ? `/api/session/${sessionId}/network` : null,
    { summary: 1 },
    [sessionId],
    { refreshMs: 10000 },
  );

  // Derived once, unconditionally (rules of hooks): safe on empty roots.
  const flat = useMemo(() => flattenProcs(procs.data?.roots), [procs.data]);

  // --- Degraded gates ------------------------------------------------------
  if (linkError?.code === "remote_view_disabled") {
    return (
      <Body>
        <DegradedNote
          title="Remote terminal view is disabled"
          lines={[
            "This dashboard is paired to a remote device, and per-terminal session view is turned off for remote viewers.",
            "Open the cockpit from the owner-local dashboard, or enable remote terminal view in Settings.",
          ]}
        />
      </Body>
    );
  }
  if (!correlated) {
    return (
      <Body>
        <WaitingState
          tool={tool}
          mountMs={mountMs}
          now={now}
          loading={linkLoading}
          errored={Boolean(linkError && linkError.code !== "remote_view_disabled")}
        />
      </Body>
    );
  }

  // --- Correlated: derive glance values ------------------------------------
  const sd = session.data;
  const msgRows = messages.data?.messages ?? [];
  const newest = newestMessage(msgRows);
  const lastAssistant = newestAssistantWithOutput(msgRows);
  const lastActivityIso = newest?.timestamp ?? sd?.last_activity_at ?? sd?.started_at ?? null;
  const live = isLive(lastActivityIso, now);

  const startIso = sd?.started_at ?? new Date(mountMs).toISOString();
  const elapsedSecs = secondsSince(startIso, now);

  const runningCount = runningProcessCount(procs.data?.roots);
  const burn = burnRate(msgRows, sd?.cost_usd, elapsedSecs);

  return (
    <Body>
      {/* 1 — Header row */}
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <ToolBadge tool={tool} />
        <IdLink title={sessionId}>
          <Link to={`/sessions?session=${encodeURIComponent(sessionId)}`}>{shortId(sessionId)}</Link>
        </IdLink>
        <StatusDot live={live} lastActivityIso={lastActivityIso} now={now} />
        <span className="text-[11px] tabular-nums text-fg-3" title={`started ${startIso}`}>
          {fmtElapsed(elapsedSecs)}
        </span>
        {confidence > 0 && confidence < WEAK_LINK_CONFIDENCE && (
          <Pill
            variant="warn"
            title={`Heuristic correlation (confidence ${(confidence * 100).toFixed(0)}%): this terminal was matched to the session by activity, not an exact token binding. Only the out-of-band handshake (95%) is authoritative - treat this pairing as best-effort.`}
          >
            ≈ linked
          </Pill>
        )}
      </div>

      {/* 2 — Now strip */}
      <NowStrip
        newest={newest}
        lastAssistant={lastAssistant}
        runningCount={runningCount}
        procEnabled={procs.data?.diagnostics?.process_enabled}
        procLoaded={Boolean(procs.data)}
        procErr={procs.error}
        now={now}
        err={messages.error}
      />

      {/* 3 — Cost strip */}
      <CostStrip session={sd} predict={predict.data} burn={burn} err={session.error} />

      {/* 4 — Context & tokens */}
      <ContextTokens session={sd} predict={predict.data} />

      {/* 5 — Rate-limit gauge (hidden when absent) */}
      <RateLimitGauge limit={predict.data?.limit} />

      {/* 6 — Cache countdown (hidden when no live windows) */}
      <CacheCountdown windows={cache.data?.windows ?? []} now={now} err={cache.error} />

      {/* 7 — System */}
      <SystemSection
        procs={procs.data}
        flat={flat}
        metrics={metrics.data}
        metricsLoading={metrics.loading}
        metricsErr={metrics.error}
        network={network.data}
        networkErr={network.error}
        err={procs.error}
      />

      {/* 8 — Recent turns */}
      <RecentTurns rows={msgRows} sessionId={sessionId} err={messages.error} />
    </Body>
  );
}

// --- Layout scaffolding ----------------------------------------------------

function Body({ children }: { children: ReactNode }) {
  return <div className="h-full space-y-3 overflow-y-auto px-3 py-3 text-fg-1">{children}</div>;
}

function SectionLabel({ children }: { children: ReactNode }) {
  return (
    <div className="mb-1 text-[10px] font-semibold uppercase tracking-[0.07em] text-fg-3">
      {children}
    </div>
  );
}

function SectionErr({ label }: { label: string }) {
  return <div className="text-[10.5px] text-danger">{label} unavailable - retrying…</div>;
}

// --- Degraded states -------------------------------------------------------

function DegradedNote({ title, lines }: { title: string; lines: string[] }) {
  return (
    <div className="rounded-3 border border-line-2 bg-bg-2 p-3">
      <div className="text-[12px] font-semibold text-fg-1">{title}</div>
      {lines.map((l, i) => (
        <p key={i} className="mt-1 text-[11px] leading-relaxed text-fg-3">
          {l}
        </p>
      ))}
    </div>
  );
}

function WaitingState({
  tool,
  mountMs,
  now,
  loading,
  errored,
}: {
  tool: string;
  mountMs: number;
  now: number;
  loading: boolean;
  errored: boolean;
}) {
  const waited = Math.max(0, Math.floor((now - mountMs) / 1000));
  const toolLabel = tool || "the tool";
  return (
    <div className="rounded-3 border border-line-2 bg-bg-2 p-3">
      <div className="flex items-center gap-2 text-[12px] text-fg-1">
        <span className="inline-block size-2 animate-pulse rounded-full bg-info" aria-hidden />
        Waiting for session…
      </div>
      <p className="mt-1 text-[11px] text-fg-3">
        {toolLabel} running · {fmtElapsed(waited)}
      </p>
      {errored && (
        <p className="mt-1 text-[11px] text-warn">
          The link check failed on the last poll; still retrying.
        </p>
      )}
      {!errored && !loading && waited > 60 && (
        <p className="mt-2 text-[10.5px] leading-relaxed text-fg-4">
          Some launches can't be auto-linked to a session. If this persists, check the{" "}
          <Link to="/sessions" className="text-accent hover:underline">
            Sessions page
          </Link>{" "}
          for the running session.
        </p>
      )}
    </div>
  );
}

// --- 1: status dot ---------------------------------------------------------

function StatusDot({
  live,
  lastActivityIso,
  now,
}: {
  live: boolean;
  lastActivityIso: string | null;
  now: number;
}) {
  const since = secondsSince(lastActivityIso, now);
  const label = live ? "live" : since != null ? `idle · ${fmtAgo(since)}` : "idle";
  return (
    <span className="inline-flex items-center gap-1 text-[10.5px] text-fg-3" title={label}>
      <span
        className={`inline-block size-1.5 rounded-full ${live ? "bg-success" : "bg-fg-4"}`}
        aria-hidden
      />
      {live ? "live" : "idle"}
    </span>
  );
}

// --- 2: Now strip ----------------------------------------------------------

function NowStrip({
  newest,
  lastAssistant,
  runningCount,
  procEnabled,
  procLoaded,
  procErr,
  now,
  err,
}: {
  newest: MessageRow | null;
  lastAssistant: MessageRow | null;
  runningCount: number;
  procEnabled?: boolean;
  procLoaded: boolean;
  procErr: Error | null;
  now: number;
  err: Error | null;
}) {
  if (err && !newest) return <SectionErr label="Activity" />;
  const since = newest ? secondsSince(newest.timestamp, now) : null;
  const tps = lastAssistant ? tokensPerSec(lastAssistant) : null;
  const measured = lastAssistant?.tps_basis === "measured";
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded-2 border border-line-1 bg-bg-2/50 px-2.5 py-1.5 text-[11px]">
      <span className="text-fg-2">
        {newest ? (
          <>
            <span className="font-medium text-fg-1">{activityLabel(newest)}</span>{" "}
            <span className="text-fg-3">· {fmtAgo(since)}</span>
          </>
        ) : (
          <span className="text-fg-3">no messages yet</span>
        )}
      </span>
      <span className="text-fg-4">|</span>
      <span className="flex items-center gap-1 text-fg-2" title={lastAssistant ? tpsBasisLabel(lastAssistant.tps_basis) : "no timed assistant turn yet"}>
        {tps != null ? (
          <>
            <span className="font-medium tabular-nums text-fg-1">{fmtTps(tps)}</span>
            <Pill variant={measured ? "success" : "neutral"}>{measured ? "measured" : "est."}</Pill>
          </>
        ) : (
          <span className="text-fg-3">- tok/s</span>
        )}
      </span>
      <span className="text-fg-4">|</span>
      <span className="text-fg-2" title="processes still running in the captured tree">
        {procEnabled === false ? (
          <span className="text-fg-3">proc off</span>
        ) : !procLoaded ? (
          // Don't render a failed/absent /processes fetch as "0 proc live" -
          // that reads as an observed zero. Show an honest unavailable marker.
          <span className="text-fg-4" title={procErr ? "process vitals unavailable" : "loading process vitals…"}>
            proc {procErr ? "n/a" : "…"}
          </span>
        ) : (
          <>
            <span className="font-medium tabular-nums text-fg-1">{fmtInt(runningCount)}</span>{" "}
            <span className="text-fg-3">proc live</span>
            {/* Fix 4: useApi retains the last good tree on a later poll failure;
                mark it stale so the retained count isn't read as current. */}
            {procErr && (
              <span
                className="text-warn"
                title="The last process refresh failed; showing the previous count."
              >
                {" "}· stale
              </span>
            )}
          </>
        )}
      </span>
    </div>
  );
}

// --- 3: Cost strip ---------------------------------------------------------

function fmtCost(n: number | null | undefined): string {
  if (n == null || !Number.isFinite(n)) return "-";
  return fmtUSD(n, n > 0 && n < 0.1);
}

function CostStrip({
  session,
  predict,
  burn,
  err,
}: {
  session?: SessionDetail | null;
  predict?: PredictResponse | null;
  burn: BurnRate | null;
  err: Error | null;
}) {
  if (err && !session) return <SectionErr label="Cost" />;
  const est = predict?.estimate;
  const nextLo = est?.has_estimate ? est.low.message_usd : null;
  const nextHi = est?.has_estimate ? est.high.message_usd : null;
  // Projection is the running total plus one hour at the current rate —
  // the forward number a rate exists to produce. Only meaningful once the
  // total is known, so it follows cost_usd rather than defaulting it.
  const total = session?.cost_usd;
  const projected =
    burn && total != null && Number.isFinite(total)
      ? total + burn.usdPerHour
      : null;
  return (
    <div>
      <SectionLabel>Cost</SectionLabel>
      <div className="flex items-end justify-between gap-3 rounded-2 border border-line-1 bg-bg-2/50 px-2.5 py-2">
        <div>
          <div className="text-[22px] font-semibold leading-none tabular-nums text-fg-0">
            {fmtCost(session?.cost_usd)}
          </div>
          <div className="mt-1 text-[10.5px] text-fg-3">
            AI {fmtCost(session?.ai_cost_usd)} · tool {fmtCost(session?.tool_cost_usd)}
          </div>
        </div>
        <div className="text-right" title={burnTitle(burn)}>
          <div className="text-[10px] uppercase tracking-wide text-fg-4">burn</div>
          <div className="text-[12px] font-medium tabular-nums text-fg-1">
            {burn ? (
              <>
                {fmtCost(burn.usdPerHour)}
                <span className="text-fg-3">/h</span>
              </>
            ) : (
              <span className="text-fg-4">-</span>
            )}
          </div>
          <div className="text-[10px] tabular-nums text-fg-3">
            {projected != null ? <>+1h ≈ {fmtCost(projected)}</> : " "}
          </div>
        </div>
        <div className="text-right">
          <div className="text-[10px] uppercase tracking-wide text-fg-4">next msg</div>
          <div className="text-[12px] font-medium tabular-nums text-fg-1">
            {nextLo != null && nextHi != null ? (
              <>≈ {fmtCost(nextLo)}–{fmtCost(nextHi)}</>
            ) : (
              <span className="text-fg-4">-</span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// burnTitle names the basis on hover rather than in the strip, which has no
// room for it. The distinction matters: a "recent" rate is what the session
// is costing now, a "session" rate is diluted by every idle stretch since it
// started, and reading one as the other is the whole risk of showing a rate.
function burnTitle(burn: BurnRate | null): string {
  if (!burn) {
    return "No burn rate yet - a rate needs at least two timed turns, or a session with elapsed time and a known cost.";
  }
  if (burn.basis === "recent") {
    return `Current rate: ${burn.turns} turn(s) over ${fmtElapsed(burn.spanSecs)}. The oldest fetched turn sets the window start and is excluded from the total, so the rate isn't inflated by counting a cost incurred before the window.`;
  }
  return `Session average over ${fmtElapsed(burn.spanSecs)} elapsed - the same elapsed shown in the header. Diluted by any idle time; a current rate needs at least two timed turns.`;
}

// --- 4: Context & tokens ---------------------------------------------------

function ContextTokens({
  session,
  predict,
}: {
  session?: SessionDetail | null;
  predict?: PredictResponse | null;
}) {
  if (!session) return null;
  const budget = session.context_budget_tokens ?? 0;
  const current = predict?.estimate?.prefix_tokens ?? 0;
  const fillPct = budget > 0 && current > 0 ? Math.min(100, (current / budget) * 100) : null;
  const fillColor =
    fillPct == null ? "bg-fg-4" : fillPct > 90 ? "bg-danger" : fillPct > 70 ? "bg-warn" : "bg-accent";

  const t = session.tokens;
  const buckets: { label: string; value: number; cls: string }[] = [
    { label: "in", value: t.input, cls: "bg-accent" },
    { label: "out", value: t.output, cls: "bg-success" },
    { label: "c-read", value: t.cache_read, cls: "bg-info" },
    { label: "c-write", value: t.cache_creation, cls: "bg-warn" },
  ];
  const total = buckets.reduce((s, b) => s + Math.max(0, b.value), 0);

  return (
    <div>
      <SectionLabel>Context &amp; tokens</SectionLabel>
      {fillPct != null ? (
        <div className="mb-1.5">
          <div className="mb-0.5 flex items-center justify-between text-[10.5px] text-fg-3">
            <span>context fill</span>
            <span className="tabular-nums">
              {fmtCompact(current)} / {fmtCompact(budget)} · {fillPct.toFixed(0)}%
            </span>
          </div>
          <div className="h-1.5 overflow-hidden rounded-full bg-bg-3">
            <div className={`h-full ${fillColor}`} style={{ width: `${fillPct}%` }} />
          </div>
        </div>
      ) : (
        <div className="mb-1 text-[10.5px] text-fg-4" title="context budget not reported for this session">
          context fill n/a
        </div>
      )}
      {total > 0 ? (
        <>
          <div className="flex h-2 overflow-hidden rounded-full bg-bg-3">
            {buckets.map((b) =>
              b.value > 0 ? (
                <div
                  key={b.label}
                  className={b.cls}
                  style={{ width: `${(b.value / total) * 100}%` }}
                  title={`${b.label}: ${fmtInt(b.value)}`}
                />
              ) : null,
            )}
          </div>
          <div className="mt-1 flex flex-wrap gap-x-2.5 gap-y-0.5 text-[10px] text-fg-3">
            {buckets.map((b) => (
              <span key={b.label} className="tabular-nums">
                {b.label} {fmtCompact(b.value)}
              </span>
            ))}
          </div>
        </>
      ) : (
        <div className="text-[10.5px] text-fg-4">no billed tokens yet</div>
      )}
    </div>
  );
}

// --- 5: Rate-limit gauge ---------------------------------------------------

function RateLimitGauge({ limit }: { limit?: PredictResponse["limit"] }) {
  if (!limit || !limit.available) return null;
  const u5 = utilPct(limit.window_5h_util);
  const u7 = utilPct(limit.window_7d_util);
  if (u5 == null && u7 == null) return null;
  return (
    <div>
      <SectionLabel>Rate limit{limit.source ? ` · ${limit.source}` : ""}</SectionLabel>
      <div className="space-y-1">
        {u5 != null && <UtilBar label="5h" pct={u5} />}
        {u7 != null && <UtilBar label="7d" pct={u7} />}
      </div>
    </div>
  );
}

function UtilBar({ label, pct }: { label: string; pct: number }) {
  const cls = pct > 90 ? "bg-danger" : pct > 70 ? "bg-warn" : "bg-accent";
  return (
    <div className="flex items-center gap-2 text-[10.5px]">
      <span className="w-6 shrink-0 text-fg-3">{label}</span>
      <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-bg-3">
        <div className={`h-full ${cls}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="w-9 shrink-0 text-right tabular-nums text-fg-2">{pct.toFixed(0)}%</span>
    </div>
  );
}

// --- 6: Cache countdown ----------------------------------------------------

function CacheCountdown({
  windows,
  now,
  err,
}: {
  windows: CacheWindowStatus[];
  now: number;
  err: Error | null;
}) {
  // Live windows = anything not fully cold; the countdown is derived from the
  // window's absolute expiry so it ticks accurately between the 5s polls.
  const live = windows.filter((w) => w.severity !== "cold");
  if (err && windows.length === 0) return <SectionErr label="Cache" />;
  if (live.length === 0) return null;
  return (
    <div>
      <SectionLabel>Cache</SectionLabel>
      <div className="flex flex-wrap gap-1.5">
        {live.slice(0, 6).map((w, i) => {
          const secs = Math.max(0, secondsUntil(w.window.expires_at, now) ?? w.seconds_to_expiry);
          const critical = w.severity === "critical";
          return (
            <span
              key={`${w.window.scope}-${i}`}
              className={`inline-flex items-center gap-1 rounded-pill border px-2 py-0.5 text-[10px] tabular-nums ${
                critical ? "border-warn/40 bg-warn-soft text-warn" : "border-line-2 bg-bg-2 text-fg-2"
              }`}
              title={`${w.window.model} · ${w.window.ttl_tier} tier${w.estimated ? " · estimated expiry" : ""}`}
            >
              <span className="text-fg-3">{w.window.ttl_tier || "cache"}</span>
              <span className="font-medium">
                {w.estimated ? "~" : ""}
                {fmtCountdown(secs)}
              </span>
              {w.value_at_risk_usd > 0 && (
                <span className="text-fg-3">· {fmtUSD(w.value_at_risk_usd, true)} at risk</span>
              )}
            </span>
          );
        })}
      </div>
    </div>
  );
}

// --- 7: System -------------------------------------------------------------

function SystemSection({
  procs,
  flat,
  metrics,
  metricsLoading,
  metricsErr,
  network,
  networkErr,
  err,
}: {
  procs?: SessionProcessResponse | null;
  flat: ProcessNode[];
  metrics?: SessionMetricsResponse | null;
  metricsLoading: boolean;
  metricsErr: Error | null;
  network?: SessionNetworkSummary | null;
  networkErr: Error | null;
  err: Error | null;
}) {
  const enabled = procs?.diagnostics?.process_enabled;
  if (err && !procs) return <SectionErr label="System" />;

  // CTA state — process telemetry off.
  if (procs && enabled === false) {
    return (
      <div>
        <SectionLabel>System</SectionLabel>
        <ProcessEnableCTA />
      </div>
    );
  }
  if (!procs) return null;

  const recent = [...flat]
    .sort((a, b) => {
      const ta = a.started_at ? Date.parse(a.started_at) : 0;
      const tb = b.started_at ? Date.parse(b.started_at) : 0;
      return tb - ta;
    })
    .slice(0, 6);

  return (
    <div>
      <SectionLabel>System</SectionLabel>
      <div className="mb-2">
        <ResourceCharts metrics={metrics ?? null} loading={metricsLoading} error={metricsErr} />
      </div>

      {recent.length > 0 && (
        <div className="space-y-0.5">
          {recent.map((n) => (
            <div key={n.process_key} className="flex items-center gap-2 text-[11px]">
              <span
                className={`inline-block size-1.5 shrink-0 rounded-full ${n.exited ? "bg-fg-4" : "bg-success"}`}
                title={n.exited ? "exited" : "running"}
                aria-hidden
              />
              <span className="min-w-0 flex-1 truncate font-mono text-fg-1" title={n.command || n.exe}>
                {basename(n.exe)}
              </span>
              <span className="shrink-0 text-fg-4">{n.pid > 0 ? `pid ${n.pid}` : "tool log"}</span>
            </div>
          ))}
        </div>
      )}

      <NetworkTraffic
        network={network}
        networkEnabled={procs?.diagnostics?.process_network_enabled}
        bodyCapture={procs?.diagnostics?.process_network_body_capture}
        err={networkErr}
      />
    </div>
  );
}

// NetworkTraffic renders the server-side ?summary=1 aggregate: proxied API
// calls (with body byte totals when measured) on one line, OS-observed process
// connections (honestly labelled — NOT proxied API calls) on a separate line
// when present.
//   • Network capture off entirely ⇒ an honest "off" line, NOT "0 calls" from
//     an empty summary (Fix 3).
//   • A failed/absent fetch with no cached data ⇒ an unavailable marker, NEVER
//     "0 calls" (Fix D).
//   • Bytes render ONLY when > 0. With calls but zero measured bytes the byte
//     figures are suppressed rather than shown as a misleading measured
//     "↑0 B ↓0 B" (Fix 2). The zero-byte tooltip only CLAIMS body capture is
//     off when the diagnostics body-capture flag actually says so; otherwise it
//     says no bytes have been recorded yet — a zero summary alone doesn't prove
//     capture is disabled (Fix 4).
//   • A later refresh failure while cached data is shown ⇒ a "· stale" marker
//     so the silently-retained counts aren't read as current.
function NetworkTraffic({
  network,
  networkEnabled,
  bodyCapture,
  err,
}: {
  network?: SessionNetworkSummary | null;
  networkEnabled?: boolean;
  bodyCapture?: boolean;
  err: Error | null;
}) {
  if (networkEnabled === false) {
    return (
      <div
        className="mt-2 text-[10.5px] text-fg-4"
        title="Network capture is off - set [observer.process.network].enabled to record this session's outbound API/network activity."
      >
        Network capture off
      </div>
    );
  }
  if (err && !network) {
    return (
      <div className="mt-2 text-[10.5px] text-danger">API traffic unavailable - retrying…</div>
    );
  }
  const sum = networkSummary(network);
  const hasBytes = sum.request_bytes > 0 || sum.response_bytes > 0;
  const stale = Boolean(err && network);
  return (
    <div className="mt-2 space-y-0.5">
      <div
        className="text-[10.5px] text-fg-3"
        title={
          hasBytes
            ? "Body byte totals exist only for SuperBased-proxied/plaintext API flows; per-process network bytes are not captured."
            : bodyCapture === false
              ? "Body byte capture is off ([observer.process.network].capture_bodies) - proxied calls are counted, but their request/response bytes were not measured."
              : "No request/response bytes have been recorded yet for this session's proxied calls."
        }
      >
        API traffic (proxied): {fmtInt(sum.proxied_calls)} calls
        {hasBytes && (
          <>
            {" · "}↑{fmtBytes(sum.request_bytes)} ↓{fmtBytes(sum.response_bytes)}
          </>
        )}
        {stale && (
          <span className="text-warn" title="The last network refresh failed; showing the previous values.">
            {" "}· stale
          </span>
        )}
      </div>
      {sum.os_connections > 0 && (
        <div
          className="text-[10.5px] text-fg-4"
          title="OS-observed outbound connections from the captured process tree - raw sockets, not proxied API calls (no body bytes)."
        >
          Network connections: {fmtInt(sum.os_connections)}
        </div>
      )}
    </div>
  );
}

// switchedToAutoNotice renders the honest reason the server switched the
// configured backend to automatic selection, branching on the prior value:
//   - a named backend → it "cannot capture on this machine"
//   - the literal "off" → it "was set to off"
//   - empty / unset    → it "was unset"
function switchedToAutoNotice(previousBackend: string): string {
  if (previousBackend === "off") {
    return "The capture backend was switched to automatic selection because it was set to off.";
  }
  if (previousBackend === "") {
    return "The capture backend was switched to automatic selection because it was unset.";
  }
  return `The capture backend was switched to automatic selection because "${previousBackend}" cannot capture on this machine.`;
}

function ProcessEnableCTA() {
  const remote = isRemoteView();
  const [state, setState] = useState<"idle" | "saving" | "done" | "unsupported" | "err">("idle");
  const [msg, setMsg] = useState<string>("");
  // Populated when the server switched a non-runnable backend to automatic
  // selection — the success notice names the prior value (Fix 3).
  const [switchedToAuto, setSwitchedToAuto] = useState(false);
  const [previousBackend, setPreviousBackend] = useState<string>("");
  // The server-authored honest message for a host with no runnable backend.
  const [unsupportedDetail, setUnsupportedDetail] = useState<string>("");

  async function onEnable() {
    setState("saving");
    setMsg("");
    try {
      const res = await enableProcessCapture();
      if (res.unsupported) {
        setUnsupportedDetail(res.unsupportedDetail);
        setState("unsupported");
        return;
      }
      if (res.restart_required) markRestartPending("process");
      setSwitchedToAuto(res.switchedToAuto);
      setPreviousBackend(res.previousBackend);
      setState("done");
    } catch (e) {
      setState("err");
      setMsg(e instanceof Error ? e.message : String(e));
    }
  }

  if (state === "unsupported") {
    return (
      <div className="rounded-2 border border-warn/30 bg-warn-soft/40 p-2.5 text-[11px]">
        <div className="font-medium text-fg-1">Process capture unavailable on this machine</div>
        <p className="mt-1 text-fg-3">
          {unsupportedDetail || "Process capture has no runnable backend on this platform yet."}
        </p>
      </div>
    );
  }

  if (state === "done") {
    return (
      <div className="rounded-2 border border-success/30 bg-success-soft/40 p-2.5 text-[11px]">
        <div className="font-medium text-fg-1">Process capture enabled</div>
        {switchedToAuto && <p className="mt-1 text-fg-3">{switchedToAutoNotice(previousBackend)}</p>}
        <p className="mt-1 text-fg-3">
          Capture starts after the daemon restarts. Restart from{" "}
          <Link to="/settings?section=health" className="text-accent hover:underline">
            Settings → Health
          </Link>
          .
        </p>
      </div>
    );
  }

  return (
    <div className="rounded-2 border border-line-2 bg-bg-2 p-2.5">
      <p className="text-[11px] leading-relaxed text-fg-3">
        OS-level process telemetry (CPU / memory / disk, spawned-process tree) is off, so this
        session has no system vitals.
      </p>
      <div className="mt-2 flex items-center gap-2">
        <button
          type="button"
          onClick={onEnable}
          disabled={state === "saving" || remote}
          title={
            remote
              ? "Config changes are owner-local - enable process capture from the local dashboard."
              : "Turns on process capture, preserving the configured backend."
          }
          className="rounded-2 border border-accent/40 bg-accent-soft px-2.5 py-1 text-[11px] font-medium text-accent hover:bg-accent-soft/70 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {state === "saving" ? "Enabling…" : "Enable"}
        </button>
        {state === "err" && <span className="text-[10.5px] text-danger">{msg || "save failed"}</span>}
      </div>
    </div>
  );
}

// --- 8: Recent turns -------------------------------------------------------

function roleGlyph(role: string): string {
  switch (role) {
    case "assistant":
      return "A";
    case "user":
      return "U";
    case "tool":
      return "T";
    default:
      return role ? role[0].toUpperCase() : "?";
  }
}

function RecentTurns({
  rows,
  sessionId,
  err,
}: {
  rows: MessageRow[];
  sessionId: string;
  err: Error | null;
}) {
  if (err && rows.length === 0) return <SectionErr label="Recent turns" />;
  if (rows.length === 0) return null;
  const recent = [...rows]
    .sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp))
    .slice(0, 5);
  return (
    <div>
      <SectionLabel>Recent turns</SectionLabel>
      <div className="space-y-0.5">
        {recent.map((m) => {
          const tps = tokensPerSec(m);
          return (
            <Link
              key={m.message_id}
              to={`/sessions?session=${encodeURIComponent(sessionId)}`}
              className="flex items-center gap-2 rounded-2 px-1.5 py-1 text-[11px] hover:bg-fg-2/5"
            >
              <span
                className="grid size-4 shrink-0 place-items-center rounded-1 bg-bg-3 text-[9px] font-semibold text-fg-3"
                title={m.role}
              >
                {roleGlyph(m.role)}
              </span>
              <span className="w-14 shrink-0 tabular-nums text-fg-2" title="output tokens">
                {fmtCompact(m.output)} tok
              </span>
              <span className="w-14 shrink-0 tabular-nums text-fg-3">
                {tps != null ? fmtTps(tps) : "-"}
              </span>
              <span className="flex-1 text-right tabular-nums text-fg-2">{fmtCost(m.cost_usd)}</span>
            </Link>
          );
        })}
      </div>
    </div>
  );
}
