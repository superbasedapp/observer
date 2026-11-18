import { useEffect, useRef, useState, useSyncExternalStore } from "react";
import { Link } from "react-router-dom";
import clsx from "clsx";
import { ChevronUp, X } from "lucide-react";
import { AnimatedValue, Icon, LiveDot, ToolGlyphFrame, Tooltip } from "@/components/primitives";
import { ObsLanding } from "@shared/primitives/ObsFlight";
import { toolMeta } from "@shared/lib/tools";
import { getCostDisplayMode } from "@shared/lib/format";
import { SessionDetailPanel } from "@/components/SessionDetailPanel";
import { useOptionalLaunchDock } from "@/components/LaunchDock";
import { useApi } from "@/lib/useApi";
import { fetchJSON } from "@/lib/api";
import { useMediaQuery } from "@/lib/useMediaQuery";
import { useNowTick } from "@/lib/useNowTick";
import { useArrivals } from "@/lib/useArrivals";
import { isRemoteView } from "@/lib/remote";
import { useRemoteTerminalGate } from "@/lib/remoteTerminal";
import { isLiveStatus } from "@/lib/launchStatus";
import { terminalLinkPath, type TerminalSessionLink } from "@/lib/cockpit";
import { liveDotProps } from "@/lib/liveSignals";
import { dismissalsSnapshot, subscribeDismissals } from "@/lib/uiDismissals";
import { useDismissNotice } from "@/lib/useDismissNotice";
import {
  RECEIPT_AUTOCLOSE_MS,
  RECEIPT_NOTICE,
  RIBBON_DOT,
  RIBBON_TEXT,
  actionsText,
  advancedSessions,
  costCell,
  dockTokenFor,
  freshness,
  lastActivityMap,
  modelText,
  receiptLines,
  receiptVisible,
  stripLayout,
  stripOpen,
  timeText,
  tokensText,
  totalCostCell,
  type CostCell,
  type RibbonReceipt,
  type RibbonSession,
} from "@/lib/ribbon";
import { RIBBON_WIDE_QUERY } from "./RibbonChip";
import { useLiveRibbon, useRibbonMinimised } from "./useLiveRibbon";

// LiveRibbon is the live ribbon's strip (§8.2): a 32 px band under the top
// bar and the state banners, on screen only while a session is live, the
// tab is visible and the strip is not folded away. It also hosts the
// one-time first-prompt receipt and the session detail panel a segment
// opens. Every decision is lib/ribbon.ts; this component renders.
//
// It never shows an action, a file name or a path: per session the tool,
// the project's name, the model, tokens, cost and how long it has run.

/** On a wide screen up to three compact segments fit; narrower, one. */
const WIDE_SEGMENTS_QUERY = "(min-width: 1024px)";

export function LiveRibbon() {
  const ribbon = useLiveRibbon();
  const [minimised, setMinimised] = useRibbonMinimised();
  const wide = useMediaQuery(RIBBON_WIDE_QUERY);
  const roomy = useMediaQuery(WIDE_SEGMENTS_QUERY);
  const nowMs = useNowTick(5000);
  const dock = useOptionalLaunchDock();
  const gate = useRemoteTerminalGate();
  const [detailId, setDetailId] = useState<string | null>(null);
  const [popover, setPopover] = useState(false);

  // A pulse only when a session's last activity really advanced between two
  // readings; the first reading never pulses (lib/ribbon.ts advancedSessions).
  const prevRef = useRef<Record<string, string> | null>(null);
  const [pulses, setPulses] = useState<Record<string, number>>({});
  const sessions = ribbon.sessions;
  const reading = ribbon.current ? lastActivityMap(sessions) : null;
  const readingKey = reading ? JSON.stringify(reading) : "";
  useEffect(() => {
    if (!reading) return;
    const moved = advancedSessions(prevRef.current, sessions);
    prevRef.current = reading;
    if (moved.size === 0) return;
    setPulses((p) => {
      const next = { ...p };
      for (const id of moved) next[id] = (next[id] ?? 0) + 1;
      return next;
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [readingKey]);
  const arrived = useArrivals(
    sessions.map((s) => s.session_id),
    ribbon.current,
  );

  const open = stripOpen({ off: ribbon.off, live: ribbon.live, minimised, wide });
  const layout = stripLayout(sessions, ribbon.live, roomy ? 3 : 1);
  const mode = getCostDisplayMode();
  const canFocusTerminal = !gate.isRemote || gate.allowTerminal === true;

  // A segment opens its session: a dashboard terminal comes forward with its
  // Session details; any other session opens the detail panel in place.
  const openSession = async (id: string) => {
    setPopover(false);
    const live = canFocusTerminal && dock ? dock.sessions.filter((d) => isLiveStatus(dock.statuses[d.token])) : [];
    let token = dockTokenFor(id, live, {});
    if (!token && live.length > 0) {
      const links: Record<string, string> = {};
      await Promise.all(
        live.map((d) =>
          fetchJSON<TerminalSessionLink>(terminalLinkPath(d.token))
            .then((l) => {
              if (l.correlated && l.session_id) links[d.token] = l.session_id;
            })
            .catch(() => {}),
        ),
      );
      token = dockTokenFor(id, live, links);
    }
    if (token && dock) {
      dock.restore(token);
      dock.openSessionDetail(token);
      return;
    }
    setDetailId(id);
  };

  return (
    <div className="relative" data-testid="live-ribbon-host">
      {open && (
        <div
          role="region"
          aria-label="Live sessions"
          data-testid="live-ribbon"
          className="sb-fade-in flex h-8 items-center gap-2 border-b border-line-1 bg-bg-1 px-3 text-[11px] text-fg-2 sm:px-5"
        >
          {/* The segments clip on their own; the "+N" popover sits outside
              the clipped box so it can drop below the strip. */}
          <div className="flex min-w-0 items-center gap-2 overflow-hidden">
            {layout.mode !== "single" && <LeadTotal live={ribbon.live} sessions={sessions} mode={mode} />}
            {layout.shown.map((s, i) => (
              <Segment
                key={s.session_id}
                s={s}
                full={layout.mode === "single"}
                first={i === 0}
                nowMs={nowMs}
                mode={mode}
                pulse={pulses[s.session_id] ?? 0}
                arrived={arrived(s.session_id)}
                onOpen={() => void openSession(s.session_id)}
              />
            ))}
          </div>
          {layout.more > 0 && (
            <div className="relative shrink-0">
              <button
                type="button"
                onClick={() => setPopover((v) => !v)}
                aria-expanded={popover}
                aria-haspopup="dialog"
                data-testid="ribbon-more"
                className="rounded-2 border border-line-2 bg-bg-2 px-1.5 py-0.5 text-[10.5px] font-medium text-fg-2 hover:bg-bg-3 hover:text-fg-0"
              >
                {RIBBON_TEXT.more(layout.more)}
              </button>
              {popover && (
                <MorePopover
                  sessions={sessions}
                  total={ribbon.live}
                  nowMs={nowMs}
                  mode={mode}
                  onOpen={(id) => void openSession(id)}
                  onClose={() => setPopover(false)}
                />
              )}
            </div>
          )}
          <div className="min-w-0 flex-1" />
          <Link to="/live" className="hidden shrink-0 text-[10.5px] text-fg-3 hover:text-fg-0 md:inline">
            {RIBBON_TEXT.openLive}
          </Link>
          <Tooltip content={RIBBON_TEXT.minimise}>
            <button
              type="button"
              onClick={() => setMinimised(true)}
              aria-label={RIBBON_TEXT.minimise}
              data-testid="ribbon-minimise"
              className="grid h-6 w-6 shrink-0 place-items-center rounded-2 text-fg-3 hover:bg-bg-3 hover:text-fg-0"
            >
              <Icon icon={ChevronUp} size="xs" />
            </button>
          </Tooltip>
        </div>
      )}
      <ReceiptHost receipt={ribbon.receipt} ribbonOn={!ribbon.off} onOpenSession={(id) => setDetailId(id)} />
      <SessionDetailPanel
        sessionId={detailId}
        open={detailId != null}
        urlTabState={false}
        onClose={() => setDetailId(null)}
        onOpenSession={(id) => setDetailId(id)}
      />
    </div>
  );
}

// ---------------------------------------------------------------- parts

function CostText({ cell, className }: { cell: CostCell; className?: string }) {
  if (cell.kind === "hidden") return null;
  return (
    <span className={clsx("shrink-0 tabular-nums", cell.muted ? "text-fg-4" : "text-fg-1", className)}>
      {/* Tweens only between two real readings and ends on the server's
          value; no count-up from zero on mount. */}
      <AnimatedValue value={cell.text} countUp={false} />
    </span>
  );
}

function LeadTotal({ live, sessions, mode }: { live: number; sessions: RibbonSession[]; mode: ReturnType<typeof getCostDisplayMode> }) {
  const total = totalCostCell(sessions, mode);
  return (
    <span className="flex shrink-0 items-center gap-1.5 border-r border-line-2 pr-2 font-medium text-fg-1">
      <LiveDot tone="success" size="sm" />
      {RIBBON_TEXT.live(live)}
      {total.kind === "text" && (
        <>
          <span aria-hidden className="text-fg-4">
            ·
          </span>
          <CostText cell={total} />
        </>
      )}
    </span>
  );
}

function Sep() {
  return (
    <span aria-hidden className="shrink-0 text-fg-4">
      ·
    </span>
  );
}

function Segment({
  s,
  full,
  first,
  nowMs,
  mode,
  pulse,
  arrived,
  onOpen,
}: {
  s: RibbonSession;
  full: boolean;
  first: boolean;
  nowMs: number;
  mode: ReturnType<typeof getCostDisplayMode>;
  pulse: number;
  arrived: boolean;
  onOpen: () => void;
}) {
  const label = toolMeta(s.tool).label;
  const project = s.project || "no project";
  const tokens = tokensText(s);
  const model = modelText(s);
  const actions = actionsText(s);
  const cost = costCell(s, mode);
  const title = `${label} · ${project}. ${RIBBON_TEXT.lag}`;
  return (
    <button
      type="button"
      onClick={onOpen}
      title={title}
      data-testid="ribbon-segment"
      className={clsx(
        "relative flex min-w-0 items-center gap-1.5 rounded-2 px-1.5 py-0.5 hover:bg-bg-3 focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-ring)]",
        !first && !full && "border-l border-line-2 pl-2",
        arrived && "sb-fade-up",
      )}
    >
      <LiveDot {...liveDotProps(RIBBON_DOT, freshness(s, nowMs))} size="sm" />
      <ToolGlyphFrame tool={s.tool} size={14} pip={false} />
      {full && <span className="shrink-0 font-medium text-fg-1">{label}</span>}
      {full && <Sep />}
      <span className="min-w-0 truncate text-fg-1">{project}</span>
      {full && model && (
        <>
          <Sep />
          <span className="hidden min-w-0 truncate text-fg-3 lg:inline">{model}</span>
        </>
      )}
      {full && tokens && (
        <>
          <Sep />
          <span className="shrink-0 tabular-nums text-fg-2">
            <AnimatedValue value={tokens} countUp={false} />
          </span>
        </>
      )}
      {cost.kind === "text" && (
        <>
          <Sep />
          <CostText cell={cost} />
        </>
      )}
      {actions && (
        <>
          <Sep />
          <span className="shrink-0 text-fg-3">{actions}</span>
        </>
      )}
      {full && (
        <>
          <Sep />
          <span className="hidden shrink-0 text-fg-3 md:inline">{timeText(s, nowMs)}</span>
        </>
      )}
      {/* One soft underline per real advance of the session's last activity. */}
      {pulse > 0 && (
        <span
          key={pulse}
          aria-hidden
          className="pointer-events-none absolute inset-x-1 bottom-0 h-px origin-left bg-success motion-reduce:hidden"
          style={{ animation: "sb-value-flash var(--dur-slow) var(--ease-out) both" }}
        />
      )}
    </button>
  );
}

function MorePopover({
  sessions,
  total,
  nowMs,
  mode,
  onOpen,
  onClose,
}: {
  sessions: RibbonSession[];
  total: number;
  nowMs: number;
  mode: ReturnType<typeof getCostDisplayMode>;
  onOpen: (id: string) => void;
  onClose: () => void;
}) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const onDown = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose();
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [onClose]);
  const notListed = Math.max(0, total - sessions.length);
  return (
    <div
      ref={ref}
      role="dialog"
      aria-label="All live sessions"
      data-testid="ribbon-popover"
      className="sb-fade-in absolute left-0 top-full z-40 mt-1.5 w-[340px] max-w-[calc(100vw-24px)] rounded-3 border border-line-2 bg-bg-2 p-1.5 shadow-3"
    >
      <ul className="max-h-[320px] overflow-y-auto">
        {sessions.map((s) => {
          const cost = costCell(s, mode);
          return (
            <li key={s.session_id}>
              <button
                type="button"
                onClick={() => onOpen(s.session_id)}
                className="flex w-full items-center gap-2 rounded-2 px-2 py-1.5 text-left text-[11.5px] hover:bg-bg-3"
              >
                <LiveDot {...liveDotProps(RIBBON_DOT, freshness(s, nowMs))} size="sm" />
                <ToolGlyphFrame tool={s.tool} size={14} pip={false} />
                <span className="min-w-0 flex-1 truncate text-fg-1">
                  {toolMeta(s.tool).label} · {s.project || "no project"}
                </span>
                {cost.kind === "text" && (
                  <span className={clsx("shrink-0 tabular-nums", cost.muted ? "text-fg-4" : "text-fg-1")}>{cost.text}</span>
                )}
                <span className="shrink-0 text-[10.5px] text-fg-3">{timeText(s, nowMs)}</span>
              </button>
            </li>
          );
        })}
      </ul>
      <div className="mt-1 flex items-center justify-between border-t border-line-2 px-2 pt-1.5 text-[11px]">
        <span className="text-fg-3">{notListed > 0 ? RIBBON_TEXT.moreOnLive(notListed) : ""}</span>
        <Link to="/live" onClick={onClose} className="font-medium text-accent hover:text-accent-strong">
          {RIBBON_TEXT.openLive}
        </Link>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- receipt

// ReceiptHost shows the one-time "Your first captured prompt" card under the
// ribbon (§8.3). Once ever per install: the daemon fires it and keeps the
// numbers; closing it (a click anywhere on it, or 12 s) records the
// dismissal on the daemon so a second browser does not repeat it. Obs lands
// here, never on the ribbon itself.
function ReceiptHost({
  receipt,
  ribbonOn,
  onOpenSession,
}: {
  receipt: RibbonReceipt | null;
  ribbonOn: boolean;
  onOpenSession: (id: string) => void;
}) {
  const dismissals = useSyncExternalStore(subscribeDismissals, dismissalsSnapshot, dismissalsSnapshot);
  const demo = useApi<{ active: boolean }>("/api/demo", undefined, [], { refreshMs: 30000 }).data?.active === true;
  const dismiss = useDismissNotice();
  const visible = receiptVisible({
    receipt,
    ribbonOn,
    isRemote: isRemoteView(),
    dismissed: dismissals.has(RECEIPT_NOTICE),
    demo,
  });
  useEffect(() => {
    if (!visible) return;
    const id = window.setTimeout(() => dismiss(RECEIPT_NOTICE), RECEIPT_AUTOCLOSE_MS);
    return () => window.clearTimeout(id);
  }, [visible, dismiss]);
  if (!visible || !receipt) return null;
  const close = () => dismiss(RECEIPT_NOTICE);
  const lines = receiptLines(receipt, getCostDisplayMode());
  return (
    <div
      role="status"
      data-testid="ribbon-receipt"
      onClick={close}
      className="sb-fade-up absolute left-3 top-full z-30 mt-1.5 w-[min(340px,calc(100vw-24px))] rounded-3 border border-line-2 bg-bg-2 p-3 shadow-3 sm:left-5"
    >
      <div className="flex items-start gap-3">
        <ObsLanding size={36} />
        <div className="min-w-0 flex-1 text-[12px]">
          <div className="font-semibold text-fg-1">{RIBBON_TEXT.receiptTitle}</div>
          {lines.stats && <div className="mt-0.5 text-fg-2">{lines.stats}</div>}
          {lines.work && <div className="text-fg-3">{lines.work}</div>}
          <div className="mt-2 flex items-center gap-3">
            <button
              type="button"
              onClick={() => onOpenSession(receipt.session_id)}
              className="font-medium text-accent hover:text-accent-strong"
            >
              {RIBBON_TEXT.openSession}
            </button>
            <Link to="/cost" className="text-fg-3 hover:text-fg-0">
              {RIBBON_TEXT.nextCost}
            </Link>
          </div>
        </div>
        <button type="button" aria-label="Close" className="text-fg-4 hover:text-fg-2">
          <Icon icon={X} size="xs" />
        </button>
      </div>
    </div>
  );
}
