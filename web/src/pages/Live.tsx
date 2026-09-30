import { useState } from "react";
import clsx from "clsx";
import { Link } from "react-router-dom";
import {
  AnimatedValue,
  EmptyState,
  Icon,
  LiveDot,
  ModelId,
  PageHeader,
  Pill,
  TokenBar,
  ToolBadge,
  Tooltip,
  TruncatedPath,
} from "@/components/primitives";
import { ChartState } from "@/components/ChartState";
import { SessionDetailPanel } from "@/components/SessionDetailPanel";
import { useApi } from "@/lib/useApi";
import { fmtCompact, fmtDateTime, fmtDuration, fmtInt, fmtUSD } from "@/lib/format";
import { actionMeta } from "@/lib/actions";
import { vocabIcon } from "@shared/lib/vocabIcons";
import type { LiveResponse, LiveSession } from "@/lib/types";
import { navIcon } from "@/lib/nav";
import { useArrivals } from "@/lib/useArrivals";
import { useNowTick } from "@/lib/useNowTick";
import {
  HEARTBEAT_BANDS,
  HEARTBEAT_DOT,
  freshnessState,
  liveDotProps,
  withDotClass,
} from "@/lib/liveSignals";

// Live session view (P6.1): the "now playing" panel. One /api/live
// poll every 5 seconds (visibility-gated by useApi) renders every
// session with activity in the last 15 minutes — cost ticking,
// tokens accumulating, the most recent actions streaming in.
//
// Working surface — keeps the calm register throughout (§9.4).
export function LivePage() {
  // Clicking a live card opens the full session detail panel in place —
  // the same rich surface (tokens, per-turn/inference messages, cache,
  // cost predictor + limit gauge, process tree) the Sessions table uses.
  const [selected, setSelected] = useState<string | null>(null);
  // The panel is modal (scrim + scroll lock) and polls its own session, so
  // the card poll behind it pauses while it is open; on close the query
  // cache revalidates at once when the cards are overdue.
  const live = useApi<LiveResponse>(
    "/api/live",
    { window_minutes: 15 },
    [],
    { refreshMs: selected != null ? 0 : 5000 },
  );
  const active = live.data?.active ?? [];
  // Only a response for the current query counts: a session card or an
  // action row that lands on a later poll fades in once, the first
  // response never animates as a whole.
  const current = live.data != null && !live.isStale;
  const cardArrived = useArrivals(
    active.map((s) => s.session_id),
    current,
  );
  // The heartbeat ages between polls, so the dots re-read the clock on
  // their own tick rather than only when /api/live answers.
  const nowMs = useNowTick(5000);

  return (
    <div className="space-y-6 p-4 sm:p-6">
      <PageHeader
        icon={navIcon("live")}
        title="Live"
        sub="Now playing - sessions with activity in the last 15 minutes. Refreshes every 5 seconds while this tab is visible; cost and token rollups cover each session's lifetime."
        helpId="tab.live"
        right={
          active.length > 0 ? (
            <Pill variant="success">
              <LiveDot tone="success" className="h-1.5 w-1.5 shrink-0" />
              {active.length} active
            </Pill>
          ) : undefined
        }
      />
      <ChartState
        loading={live.loading}
        stale={live.isStale}
        onRetry={live.reload}
        error={live.error}
        denied={live.denied}
        deniedPermission={live.deniedPermission}
        empty={false}
        emptyHint=""
      >
        {active.length === 0 ? (
          <EmptyState
            illustration="sessions"
            title="Nothing playing right now"
            body={
              <>
                Sessions appear here the moment an AI tool makes a move. If
                nothing ever shows up, route Claude Code or Codex through the
                proxy from the{" "}
                <Link
                  to="/compression"
                  className="font-medium text-accent hover:text-accent-strong"
                >
                  Compression page
                </Link>{" "}
                - then watch this page while you work.
              </>
            }
          />
        ) : (
          <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
            {active.map((s) => (
              <LiveSessionCard
                key={s.session_id}
                s={s}
                current={current}
                arrived={cardArrived(s.session_id)}
                nowMs={nowMs}
                onOpen={() => setSelected(s.session_id)}
              />
            ))}
          </div>
        )}
      </ChartState>

      <SessionDetailPanel
        sessionId={selected}
        open={selected != null}
        onClose={() => setSelected(null)}
        onOpenSession={(id) => setSelected(id)}
      />
    </div>
  );
}

function LiveSessionCard({
  s,
  current,
  arrived,
  nowMs,
  onOpen,
}: {
  s: LiveSession;
  current: boolean;
  arrived: boolean;
  nowMs: number;
  onOpen: () => void;
}) {
  const total =
    s.tokens.input + s.tokens.output + s.tokens.cache_read + s.tokens.cache_write;
  const actionArrived = useArrivals(
    s.recent_actions.map((a) => String(a.id)),
    current,
  );
  return (
    <section
      role="button"
      tabIndex={0}
      onClick={onOpen}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onOpen();
        }
      }}
      className={clsx(
        "sb-lift cursor-pointer rounded-3 border border-line-2 bg-bg-2 p-4 hover:border-accent focus-visible:border-accent focus-visible:outline-none",
        arrived && "sb-fade-up",
      )}
    >
      <div className="flex items-center justify-between gap-3">
        <div className="flex min-w-0 items-center gap-2">
          {/* Heartbeat: how recent the newest activity is (HEARTBEAT_BANDS). */}
          <LiveDot
            {...withDotClass(
              liveDotProps(HEARTBEAT_DOT, freshnessState(HEARTBEAT_BANDS, s.last_activity, nowMs)),
              "h-2 w-2 shrink-0",
            )}
          />
          <ToolBadge tool={s.tool} />
          {s.project_root ? (
            <TruncatedPath
              value={s.project_root}
              className="font-mono text-[11px] text-fg-2"
            />
          ) : (
            <span className="truncate font-mono text-[11px] text-fg-2">
              no project
            </span>
          )}
          {s.models?.map((m) => (
            <Pill key={m} className="hidden min-w-0 md:inline-flex">
              <ModelId model={m} markSize={11} mono={false} className="min-w-0" />
            </Pill>
          ))}
        </div>
        <Link
          to={`/sessions?session=${encodeURIComponent(s.session_id)}`}
          onClick={(e) => e.stopPropagation()}
          className="shrink-0 text-[11px] font-medium text-accent hover:text-accent-strong"
        >
          Open in Sessions →
        </Link>
      </div>

      <div className="mt-3 flex flex-wrap items-baseline gap-x-5 gap-y-1">
        <span className="text-[20px] font-semibold tabular-nums tracking-[-0.02em] text-fg-0">
          <AnimatedValue value={fmtUSD(s.cost_usd)} />
        </span>
        <Stat label="tokens" value={fmtCompact(total)} />
        <Stat label="turns" value={fmtInt(s.turns)} />
        <Stat label="actions" value={fmtInt(s.actions_total)} />
        <span className="ml-auto text-[11px] text-fg-3">
          started {relTime(s.started_at)} · active {relTime(s.last_activity)}
        </span>
      </div>
      <TokenBar
        className="mt-2"
        format={fmtCompact}
        label="Session token mix"
        buckets={{
          netInput: s.tokens?.input,
          cacheRead: s.tokens?.cache_read,
          cacheWrite: s.tokens?.cache_write,
          output: s.tokens?.output,
        }}
      />

      {s.recent_actions.length > 0 && (
        <ul className="mt-3 space-y-1 border-t border-line-1 pt-2.5">
          {s.recent_actions.map((a) => (
            <li
              key={a.id}
              className={clsx(
                "flex items-center gap-2 text-[11.5px] leading-snug",
                actionArrived(String(a.id)) && "sb-fade-up",
              )}
            >
              <span
                aria-hidden
                className="h-1.5 w-1.5 shrink-0 rounded-pill"
                style={{
                  background: a.success ? "var(--success)" : "var(--danger)",
                }}
              />
              <span className="inline-flex shrink-0 items-center gap-1 text-fg-2">
                <Icon
                  icon={vocabIcon("actionType", a.action_type)}
                  size={12}
                  className="shrink-0"
                  style={{ color: actionMeta(a.action_type).colorVar }}
                />
                {actionMeta(a.action_type).label}
              </span>
              <span className="min-w-0 flex-1 truncate font-mono text-[10.5px] text-fg-3">
                {a.target}
              </span>
              <Tooltip content={fmtDateTime(a.timestamp)}>
                <span
                  tabIndex={0}
                  className="shrink-0 cursor-help tabular-nums text-[10.5px] text-fg-3 focus:outline-none"
                >
                  {relTime(a.timestamp)}
                </span>
              </Tooltip>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <span className="text-[12px] text-fg-2">
      <AnimatedValue value={value} className="font-medium text-fg-1" />{" "}
      <span className="text-fg-3">{label}</span>
    </span>
  );
}

function relTime(iso: string): string {
  const t = new Date(iso).getTime();
  if (!Number.isFinite(t)) return "-";
  const diff = Date.now() - t;
  if (diff < 0) return "now";
  if (diff < 10_000) return "just now";
  return `${fmtDuration(diff)} ago`;
}
