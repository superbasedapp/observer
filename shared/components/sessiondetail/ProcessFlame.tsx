import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent,
  type PointerEvent as ReactPointerEvent,
} from "react";
import clsx from "clsx";
import { fmtBytes, fmtClock, fmtDuration, fmtInt } from "../../lib/format";
import {
  FOLD_TOTAL_THRESHOLD,
  STACK_KEYS,
  buildTimeScale,
  buildUnits,
  chainOf,
  defaultWindow,
  failedChainKeys,
  fmtOffset,
  isAgentProcess,
  isDescendantOf,
  linearTicks,
  moveSelection,
  overviewBuckets,
  packLanes,
  turnMarkers,
  unitEnd,
  unitStart,
  zoomWindow,
  type ProcessStackIndex,
  type ProcessStackItem,
  type StackUnit,
} from "../../lib/processLayout";

// ProcessFlame - the chart half of the session-detail "Call stack" view. Each
// bar is one process: depth is which process started which (the spawn chain
// the operating system recorded), width is how long it ran. Siblings that ran
// at the same time stack into extra lanes so nothing is hidden.
//
// The default time scale is "Skip quiet": stretches where only long-running
// processes (the agent, MCP or dev servers) were alive are squeezed into
// striped bands, so short commands stay readable; widths inside active
// stretches stay true. "Real time" is one click away, and "Zoom to selection"
// is always real time.
//
// Pure presentation: the placed model comes from lib/processLayout, selection
// is owned by the caller (shared with Tree and Table), and the message link is
// injected (onOpenMessage) so the component never routes.

const ROW_H = 22;
const ROW_GAP = 3;
const BAND_GAP = 6;
const ROOT_BAR_H = 22;
/** Bars narrower than this many pixels draw as a thin tick without a label. */
const MIN_LABEL_PX = 4;
/** Overview strip resolution for large sessions. */
const OVERVIEW_BUCKETS = 120;

/** domId turns a process key into a safe element id. */
export function processDomId(prefix: string, key: string): string {
  return `${prefix}-${key.replace(/[^a-zA-Z0-9_-]/g, "_")}`;
}

/** endLabel is the short state word for a process. */
export function processStateLabel(it: ProcessStackItem): string {
  const n = it.node;
  if (it.derived) return it.failed ? "failed" : "ok";
  if (it.endKind === "running") return "running";
  if (it.endKind === "unseen") return "exit not seen";
  if ((n.exit_signal ?? 0) > 0) return `signal ${n.exit_signal}`;
  return `exit ${n.exit_code}`;
}

/** stateTone colours the state word. */
export function processStateTone(it: ProcessStackItem): string {
  if (it.failed) return "text-danger";
  if (it.endKind === "running") return "text-success";
  if (it.endKind === "unseen") return "text-fg-4";
  return "text-fg-3";
}

/** spawnLinkOf: the nearest frame in the chain that carries a message id. */
export function spawnLinkOf(index: ProcessStackIndex, key: string | null): ProcessStackItem | null {
  for (const it of chainOf(index, key)) if (it.node.message_id || it.node.turn_index != null) return it;
  return null;
}

function shortArgv(it: ProcessStackItem): string {
  const a = it.node.argv_preview || it.node.command || "";
  return a
    .replace(/^(ba|z|)sh -c /, "")
    .replace(/^node \S*\/(\.bin\/)?/, "")
    .slice(0, 120);
}

export type ProcessFlameProps = {
  index: ProcessStackIndex;
  selectedKey: string | null;
  onSelect: (key: string | null) => void;
  /** Opens the message (and so the turn) that started a process. Absent: links render as plain text. */
  onOpenMessage?: (messageId: string) => void;
  sessionLabel: string;
  nowMs: number;
  /** element id prefix, so two charts on one page never collide */
  idPrefix?: string;
};

export function ProcessFlame({
  index,
  selectedKey,
  onSelect,
  onOpenMessage,
  sessionLabel,
  nowMs,
  idPrefix = "procbar",
}: ProcessFlameProps) {
  const [scale, setScale] = useState<"quiet" | "real">("quiet");
  const [zoomed, setZoomed] = useState(false);
  const [failedOnly, setFailedOnly] = useState(false);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [hover, setHover] = useState<{ key: string; x: number; y: number } | null>(null);
  const [width, setWidth] = useState(800);
  const plotRef = useRef<HTMLDivElement>(null);
  const wrapRef = useRef<HTMLDivElement>(null);

  useLayoutEffect(() => {
    const el = plotRef.current;
    if (!el) return;
    const measure = () => setWidth(Math.max(120, el.clientWidth));
    measure();
    if (typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const large = index.items.length > FOLD_TOTAL_THRESHOLD;
  const sessionSpan = Math.max(1, index.maxEnd - index.minStart);
  // A large session shows a window of it, narrower on a narrow chart so a
  // phone is not handed a desktop's worth of bars.
  const windowWidth = Math.min(
    sessionSpan,
    Math.max(sessionSpan / 12, 5 * 60_000) * Math.min(1, Math.max(0.3, width / 1000)),
  );
  // winStart: where the reader moved the window; null = follow the selection.
  const [winStart, setWinStart] = useState<number | null>(null);

  // Keep the selection inside the window: a selection made elsewhere (Tree,
  // Table, a link) re-centres it.
  const sel = selectedKey && index.byKey.has(selectedKey) ? index.byKey.get(selectedKey)! : null;
  useEffect(() => {
    if (!large || winStart == null || !sel) return;
    if (sel.start < winStart || sel.start > winStart + windowWidth) setWinStart(null);
  }, [large, sel, winStart, windowWidth]);
  const win: [number, number] =
    winStart == null
      ? defaultWindow(index, sel ? sel.key : null, windowWidth)
      : [
          Math.min(Math.max(index.minStart, winStart), index.maxEnd - windowWidth),
          Math.min(Math.max(index.minStart, winStart), index.maxEnd - windowWidth) + windowWidth,
        ];

  const zoom = zoomed && sel ? zoomWindow(index, sel.key) : null;
  const domain: [number, number] = zoom
    ? zoom
    : large
      ? win
      : [index.minStart, Math.max(index.maxEnd, index.minStart + 1000)];
  const linear = scale === "real" || !!zoom;

  const visible = useMemo(() => (failedOnly ? failedChainKeys(index) : undefined), [failedOnly, index]);
  const units = useMemo(
    () =>
      buildUnits(index, { visible, selectedKey, expanded, fold: large }).filter(
        (u) => unitEnd(u) >= domain[0] && unitStart(u) <= domain[1],
      ),
    // domain is derived each render; its two numbers are the real dependency
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [index, visible, selectedKey, expanded, large, domain[0], domain[1]],
  );
  const span = domain[1] - domain[0];
  const lanes = useMemo(() => packLanes(units, span * 0.004), [units, span]);
  const ts = useMemo(
    () =>
      buildTimeScale(
        units.map((u) => ({ start: unitStart(u), end: unitEnd(u) })),
        domain,
        { collapse: !linear, sessionSpanMs: sessionSpan },
      ),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [units, domain[0], domain[1], linear, sessionSpan],
  );

  const anc = useMemo(() => new Set(chainOf(index, selectedKey).map((it) => it.key)), [index, selectedKey]);
  // Turn markers follow the filter: "Only failed chains" keeps the turns that
  // started something still shown.
  const turns = useMemo(() => {
    const all = turnMarkers(index);
    if (!visible) return all;
    const keep = new Set(index.items.filter((it) => visible.has(it.key)).map((it) => it.node.turn_index));
    return all.filter((t) => keep.has(t.turn));
  }, [index, visible]);

  // Row geometry: bands stacked top-down with a small gap between depths.
  const rowTop = useMemo(() => {
    const tops: number[] = [];
    let y = ROOT_BAR_H + BAND_GAP;
    for (const b of lanes.bands) {
      for (let i = 0; i < b.lanes; i++) tops[b.firstRow + i] = y + i * (ROW_H + ROW_GAP);
      y += b.lanes * (ROW_H + ROW_GAP) + BAND_GAP;
    }
    return { tops, height: y };
  }, [lanes]);

  const pct = (t: number) => ts.x(t) * 100;

  // Axis ticks: active-stretch starts on the squeezed scale, round steps when linear.
  const ticks = useMemo(() => {
    // Squeezed scale: a tick where each active stretch begins. With nothing to
    // squeeze the scale is linear anyway, so use round steps.
    const raw =
      linear || ts.gaps.length === 0 ? linearTicks(domain, Math.max(2, Math.floor(width / 110))) : ts.runStarts;
    const out: number[] = [];
    let last = Number.NEGATIVE_INFINITY;
    for (const t of raw) {
      const px = ts.x(t) * width;
      if (px - last < 64) continue;
      last = px;
      out.push(t);
    }
    return out;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [linear, domain[0], domain[1], width, ts]);

  const visibleSet = useMemo(() => {
    const s = new Set<string>();
    for (const u of units) if (u.kind === "process") s.add(u.key);
    return s;
  }, [units]);

  const onKeyDown = useCallback(
    (e: KeyboardEvent<HTMLDivElement>) => {
      const move = STACK_KEYS[e.key];
      if (move) {
        e.preventDefault();
        onSelect(moveSelection(index, selectedKey, move, visibleSet));
        return;
      }
      if (e.key === "Enter" && selectedKey && onOpenMessage) {
        const link = spawnLinkOf(index, selectedKey);
        if (link?.node.message_id) {
          e.preventDefault();
          onOpenMessage(link.node.message_id);
        }
      } else if (e.key === "Escape") {
        setHover(null);
      }
    },
    [index, selectedKey, visibleSet, onSelect, onOpenMessage],
  );

  const showHover = (key: string, e: ReactPointerEvent<HTMLElement>) => {
    const wrap = wrapRef.current;
    if (!wrap || e.pointerType === "touch") return;
    const r = wrap.getBoundingClientRect();
    setHover({ key, x: e.clientX - r.left, y: e.clientY - r.top });
  };

  const rangeLabel = `${fmtClock(new Date(domain[0]).toISOString())} to ${fmtClock(new Date(domain[1]).toISOString())} · ${fmtDuration(span)}`;
  const nowInDomain = index.items.some((it) => it.endKind === "running") && nowMs >= domain[0] && nowMs <= domain[1] + 1;

  return (
    <div ref={wrapRef} className="relative min-w-0 rounded-3 border border-line-2 bg-bg-2">
      {/* Header: legend, range, and the three chart controls. */}
      <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1.5 border-b border-line-1 px-3 py-2 text-[10.5px] text-fg-3">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <LegendSwatch className="border-info/60 bg-info-soft" label="agent" />
          <LegendSwatch className="border-line-3 bg-bg-4" label="finished" />
          <LegendSwatch className="border-danger/70 bg-danger-soft" label="failed" />
          <LegendSwatch className="border-line-3 bg-bg-4 shadow-[inset_0_-2px_0_var(--success)]" label="running" />
          <LegendSwatch className="border-dashed border-line-3 bg-transparent" label="tool log only" />
        </div>
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <span className="tabular-nums">{rangeLabel}</span>
          <div className="inline-flex overflow-hidden rounded-1 border border-line-2" role="group" aria-label="Time scale">
            <ScaleButton
              on={!linear}
              disabled={!!zoom}
              onClick={() => setScale("quiet")}
              title="Squeezes stretches where only long-running processes (the agent, MCP or dev servers) were alive, so short commands stay readable. Widths inside active stretches stay true."
            >
              Skip quiet
            </ScaleButton>
            <ScaleButton on={linear} onClick={() => setScale("real")} title="Plain wall-clock time">
              Real time
            </ScaleButton>
          </div>
          <button
            type="button"
            className={clsx("hover:text-fg-1 disabled:opacity-40", zoom && "text-accent")}
            disabled={!sel}
            aria-pressed={!!zoom}
            onClick={() => setZoomed((v) => !v)}
            title={sel ? "Zoom to the command that started the selected process" : "Pick a process first"}
          >
            {zoom ? "Fit session" : "Zoom to selection"}
          </button>
          <label className="inline-flex cursor-pointer items-center gap-1.5 hover:text-fg-1">
            <input
              type="checkbox"
              className="h-3 w-3 accent-[var(--accent)]"
              checked={failedOnly}
              onChange={(e) => setFailedOnly(e.target.checked)}
            />
            Only failed chains
          </label>
        </div>
      </div>

      {large && !zoom && (
        <OverviewStrip
          index={index}
          domain={domain}
          onMove={(a) => setWinStart(a)}
        />
      )}

      <div className="px-3 pb-2">
        {/* Axis: time ticks and turn markers. */}
        <div className="relative h-[34px] border-b border-line-1" aria-hidden={false}>
          {ticks.map((t) => (
            <span
              key={`t${t}`}
              className="absolute top-1 whitespace-nowrap text-[10px] tabular-nums text-fg-4"
              style={{ left: `${pct(t)}%`, transform: pct(t) > 92 ? "translateX(-100%)" : undefined }}
            >
              {fmtOffset(t - index.minStart)}
            </span>
          ))}
          <TurnMarkers
            turns={turns}
            domain={domain}
            x={(t) => ts.x(t)}
            width={width}
            selectedTurn={sel ? (spawnLinkOf(index, sel.key)?.node.turn_index ?? null) : null}
            onOpenMessage={onOpenMessage}
          />
        </div>

        {/* Plot */}
        <div
          ref={plotRef}
          role="tree"
          aria-label="Process call stack: which process started which, over time"
          aria-activedescendant={selectedKey && visibleSet.has(selectedKey) ? processDomId(idPrefix, selectedKey) : undefined}
          tabIndex={0}
          onKeyDown={onKeyDown}
          onPointerLeave={() => setHover(null)}
          className="relative mt-1.5 rounded-1 outline-none focus-visible:ring-2 focus-visible:ring-accent-ring"
          style={{ height: rowTop.height }}
        >
          {ts.gaps.map((g) => (
            <div
              key={`g${g.a}`}
              aria-hidden
              title={`Quiet for ${fmtDuration(g.b - g.a)}: only long-running processes alive`}
              className="absolute bottom-0 top-0 border-x border-dashed border-line-2"
              style={{
                left: `${pct(g.a)}%`,
                width: `${pct(g.b) - pct(g.a)}%`,
                backgroundImage:
                  "repeating-linear-gradient(135deg, transparent 0 4px, color-mix(in srgb, var(--line-2) 70%, transparent) 4px 5px)",
              }}
            />
          ))}
          {nowInDomain && (
            <div
              aria-hidden
              className="pointer-events-none absolute bottom-0 top-0 border-l border-success/60"
              style={{ left: `${pct(nowMs)}%` }}
            />
          )}
          <div
            className="absolute left-0 right-0 top-0 flex items-center truncate rounded-1 border border-line-3 bg-bg-4 px-2 text-[10.5px] text-fg-2"
            style={{ height: ROOT_BAR_H }}
          >
            {sessionLabel}
          </div>
          {units.map((u) => {
            const row = lanes.row.get(u.key) ?? 0;
            const top = rowTop.tops[row] ?? 0;
            const left = pct(unitStart(u));
            const w = Math.max(0, pct(unitEnd(u)) - left);
            const px = (w / 100) * width;
            if (u.kind === "group") {
              return (
                <GroupBar
                  key={u.key}
                  unit={u}
                  left={left}
                  width={w}
                  top={top}
                  onExpand={() => setExpanded((prev) => new Set(prev).add(u.key))}
                  inChain={u.members.some((m) => anc.has(m.key))}
                />
              );
            }
            const it = u.item;
            const isSel = it.key === selectedKey;
            const isAnc = !isSel && anc.has(it.key);
            const isDesc = !!selectedKey && !isSel && !isAnc && isDescendantOf(index, it.key, selectedKey);
            const dim = !!selectedKey && !isSel && !isAnc && !isDesc;
            const thin = px < MIN_LABEL_PX;
            return (
              <div
                key={it.key}
                id={processDomId(idPrefix, it.key)}
                role="treeitem"
                aria-level={it.depth + 1}
                aria-selected={isSel}
                aria-label={`${it.node.exe}${it.derived ? ", from tool log" : `, pid ${it.node.pid}`}, ${processStateLabel(it)}, ran ${fmtDuration(it.end - it.start)}`}
                onClick={(e) => {
                  e.stopPropagation();
                  onSelect(it.key);
                  plotRef.current?.focus({ preventScroll: true });
                }}
                onPointerMove={(e) => showHover(it.key, e)}
                className={clsx(
                  "absolute cursor-pointer overflow-hidden whitespace-nowrap rounded-[3px] border font-mono text-[10.5px] leading-[20px] transition-opacity duration-150",
                  thin ? "px-0" : "px-1.5",
                  // a tick has no room for a border or label: a solid mark
                  thin ? (it.failed ? "border-danger bg-danger" : "border-fg-4 bg-fg-4") : barTone(it),
                  isSel && "!border-accent !bg-accent !text-accent-on",
                  isAnc && "!border-accent ring-1 ring-accent-ring",
                  isDesc && "!border-accent-ring",
                  dim && "opacity-50",
                  hover?.key === it.key && "outline outline-1 outline-offset-1 outline-fg-3",
                )}
                style={{
                  left: `${left}%`,
                  width: thin ? 2 : `${w}%`,
                  minWidth: thin ? 2 : 3,
                  top,
                  height: ROW_H,
                  ...(it.endKind === "unseen"
                    ? {
                        WebkitMaskImage: "linear-gradient(90deg,#000 70%,rgba(0,0,0,.3))",
                        maskImage: "linear-gradient(90deg,#000 70%,rgba(0,0,0,.3))",
                      }
                    : null),
                }}
              >
                {!thin && (
                  <>
                    <span className={clsx(isSel ? "" : "text-fg-1", it.failed && !isSel && "text-danger")}>{it.node.exe || "?"}</span>{" "}
                    <span className={isSel ? "opacity-75" : "text-fg-3"}>{shortArgv(it)}</span>
                  </>
                )}
              </div>
            );
          })}
        </div>
      </div>

      <div className="flex flex-wrap justify-between gap-x-4 gap-y-1 border-t border-line-1 px-3 py-1.5 text-[10.5px] text-fg-4">
        <span>
          Each bar is one process. Lower bars were started by the bar above them. Width is how long it ran
          {ts.collapsed && ts.gaps.length ? "; striped bands are quiet stretches, squeezed" : ""}.
        </span>
        <span className="hidden sm:inline">
          ← → siblings · ↑ ↓ parent and child{onOpenMessage ? " · Enter opens the message" : ""}
        </span>
      </div>

      {hover && index.byKey.get(hover.key) && (
        <HoverCard
          item={index.byKey.get(hover.key)!}
          index={index}
          x={hover.x}
          y={hover.y}
          wrapWidth={wrapRef.current?.clientWidth ?? 800}
        />
      )}
    </div>
  );
}

/** barTone: the resting look of a bar, by what the process was. */
function barTone(it: ProcessStackItem): string {
  if (it.derived) return clsx("border-dashed border-line-3 bg-transparent", it.failed ? "text-danger" : "text-fg-2");
  if (it.failed) return "border-danger/60 bg-danger-soft text-danger";
  const base = isAgentProcess(it.node) ? "border-info/50 bg-info-soft" : "border-line-3 bg-bg-4";
  if (it.endKind === "running") return clsx(base, "shadow-[inset_0_-2px_0_var(--success)]");
  return base;
}

function LegendSwatch({ className, label }: { className: string; label: string }) {
  return (
    <span className="inline-flex items-center gap-1">
      <span className={clsx("inline-block h-[9px] w-[14px] rounded-[2px] border", className)} aria-hidden />
      {label}
    </span>
  );
}

function ScaleButton({
  on,
  disabled,
  onClick,
  title,
  children,
}: {
  on: boolean;
  disabled?: boolean;
  onClick: () => void;
  title: string;
  children: string;
}) {
  return (
    <button
      type="button"
      aria-pressed={on}
      disabled={disabled}
      onClick={onClick}
      title={title}
      className={clsx(
        "px-2 py-[1px] disabled:opacity-40",
        on ? "bg-accent-soft text-accent" : "text-fg-3 hover:text-fg-1",
      )}
    >
      {children}
    </button>
  );
}

function GroupBar({
  unit,
  left,
  width,
  top,
  onExpand,
  inChain,
}: {
  unit: Extract<StackUnit, { kind: "group" }>;
  left: number;
  width: number;
  top: number;
  onExpand: () => void;
  inChain: boolean;
}) {
  const label = `${unit.exe} ×${fmtInt(unit.members.length)}`;
  const hidden = unit.hiddenBelow ? `, ${fmtInt(unit.hiddenBelow)} more below them` : "";
  return (
    <button
      type="button"
      onClick={(e) => {
        e.stopPropagation();
        onExpand();
      }}
      title={`${fmtInt(unit.members.length)} similar processes folded into one bar${hidden}${unit.failedCount ? `, ${fmtInt(unit.failedCount)} failed` : ""}. Click to show each one.`}
      className={clsx(
        "absolute overflow-hidden whitespace-nowrap rounded-[3px] border px-1.5 text-left font-mono text-[10.5px] leading-[20px] text-fg-2",
        unit.failedCount ? "border-danger/60" : "border-line-3",
        inChain && "!border-accent",
      )}
      style={{
        left: `${left}%`,
        width: `${Math.max(width, 0.4)}%`,
        minWidth: 18,
        top,
        height: ROW_H,
        backgroundImage:
          "repeating-linear-gradient(90deg, var(--bg-4) 0 3px, color-mix(in srgb, var(--line-3) 70%, transparent) 3px 4px)",
      }}
    >
      {label}
    </button>
  );
}

function TurnMarkers({
  turns,
  domain,
  x,
  width,
  selectedTurn,
  onOpenMessage,
}: {
  turns: ReturnType<typeof turnMarkers>;
  domain: [number, number];
  x: (t: number) => number;
  width: number;
  selectedTurn: number | null;
  onOpenMessage?: (messageId: string) => void;
}) {
  let last = Number.NEGATIVE_INFINITY;
  return (
    <>
      {turns
        .filter((t) => t.at >= domain[0] && t.at <= domain[1])
        .map((t) => {
          const px = x(t.at) * width;
          const crowded = px - last < 30 && t.turn !== selectedTurn;
          if (!crowded) last = px;
          const title = `Turn ${t.turn}: its first process started here (${fmtInt(t.processes)} in this turn)${
            t.messageId && onOpenMessage ? ". Click to open the message" : ""
          }`;
          const cls = clsx(
            "absolute bottom-[-1px] -translate-x-1/2 border border-b-0",
            crowded
              ? "bottom-[3px] h-[6px] w-[6px] rounded-full border-b border-line-3 bg-bg-3"
              : "rounded-t-1 bg-bg-3 px-1 text-[9.5px] leading-[13px]",
            t.turn === selectedTurn ? "border-accent-ring text-accent" : "border-line-2 text-fg-3",
            t.messageId && onOpenMessage && "hover:border-accent-ring hover:text-accent",
          );
          const body = crowded ? null : `T${t.turn}`;
          return t.messageId && onOpenMessage ? (
            <button
              key={t.turn}
              type="button"
              className={cls}
              style={{ left: `${x(t.at) * 100}%` }}
              title={title}
              aria-label={`Open turn ${t.turn}`}
              onClick={() => onOpenMessage(t.messageId!)}
            >
              {body}
            </button>
          ) : (
            <span key={t.turn} className={cls} style={{ left: `${x(t.at) * 100}%` }} title={title}>
              {body}
            </span>
          );
        })}
    </>
  );
}

function OverviewStrip({
  index,
  domain,
  onMove,
}: {
  index: ProcessStackIndex;
  domain: [number, number];
  onMove: (start: number) => void;
}) {
  const ob = useMemo(() => overviewBuckets(index, OVERVIEW_BUCKETS), [index]);
  const max = Math.max(1, ...ob.counts);
  const span = Math.max(1, index.maxEnd - index.minStart);
  const winW = domain[1] - domain[0];
  const ref = useRef<HTMLDivElement>(null);
  const drag = useRef(false);
  const place = (clientX: number) => {
    const el = ref.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    const f = Math.min(1, Math.max(0, (clientX - r.left) / Math.max(1, r.width)));
    const center = index.minStart + f * span;
    onMove(Math.min(Math.max(index.minStart, center - winW / 2), index.maxEnd - winW));
  };
  const step = (dir: number) =>
    onMove(Math.min(Math.max(index.minStart, domain[0] + dir * winW * 0.5), index.maxEnd - winW));
  const mins = Math.max(1, Math.round(ob.bucketMs / 60_000));
  return (
    <div className="px-3 pt-2">
      <div className="mb-1 flex flex-wrap justify-between gap-2 text-[10.5px] text-fg-3">
        <span>
          {fmtInt(index.items.length)} processes · started per {mins} min · red marks failures
        </span>
        <span>Drag the window, or use ← → on it, to move through the session.</span>
      </div>
      <div
        ref={ref}
        role="slider"
        tabIndex={0}
        aria-label="Chart window within the session"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={Math.round(((domain[0] - index.minStart) / span) * 100)}
        aria-valuetext={`${fmtClock(new Date(domain[0]).toISOString())} to ${fmtClock(new Date(domain[1]).toISOString())}`}
        onPointerDown={(e) => {
          drag.current = true;
          (e.target as Element).setPointerCapture?.(e.pointerId);
          place(e.clientX);
        }}
        onPointerMove={(e) => drag.current && place(e.clientX)}
        onPointerUp={() => (drag.current = false)}
        onKeyDown={(e) => {
          if (e.key === "ArrowLeft" || e.key === "ArrowRight") {
            e.preventDefault();
            step(e.key === "ArrowLeft" ? -1 : 1);
          }
        }}
        className="relative h-[34px] cursor-pointer touch-none rounded-1 border border-line-1 bg-bg-3 outline-none focus-visible:ring-2 focus-visible:ring-accent-ring"
      >
        {ob.counts.map((c, i) => (
          <div
            key={i}
            aria-hidden
            className="absolute bottom-0 flex h-full items-end"
            style={{ left: `${(i / OVERVIEW_BUCKETS) * 100}%`, width: `${100 / OVERVIEW_BUCKETS}%` }}
          >
            <div className="mx-auto w-[70%] rounded-t-[1px] bg-fg-4/60" style={{ height: `${(c / max) * 100}%` }} />
            {ob.failures[i] > 0 && (
              <div
                className="absolute bottom-0 left-[15%] w-[70%] rounded-t-[1px] bg-danger"
                style={{ height: `${Math.max(12, (ob.failures[i] / max) * 100)}%` }}
              />
            )}
          </div>
        ))}
        <div
          aria-hidden
          className="absolute -bottom-[2px] -top-[2px] rounded-[3px] border-[1.5px] border-accent bg-accent-soft"
          style={{
            left: `${((domain[0] - index.minStart) / span) * 100}%`,
            width: `${(winW / span) * 100}%`,
            minWidth: 6,
          }}
        />
      </div>
      <div className="relative mt-0.5 h-[14px] text-[9.5px] text-fg-4" aria-hidden>
        <span className="absolute left-0">{fmtClock(new Date(index.minStart).toISOString())}</span>
        <span className="absolute right-0">{fmtClock(new Date(index.maxEnd).toISOString())}</span>
      </div>
    </div>
  );
}

function HoverCard({
  item,
  index,
  x,
  y,
  wrapWidth,
}: {
  item: ProcessStackItem;
  index: ProcessStackIndex;
  x: number;
  y: number;
  wrapWidth: number;
}) {
  const n = item.node;
  const parent = item.parentKey ? index.byKey.get(item.parentKey) : undefined;
  const link = spawnLinkOf(index, item.key);
  const W = 300;
  const left = Math.max(8, Math.min(x + 14, wrapWidth - W - 8));
  const ran =
    item.endKind === "running"
      ? `${fmtDuration(item.end - item.start)} so far`
      : item.endKind === "unseen"
        ? `at least ${fmtDuration(item.end - item.start)} (exit not seen)`
        : fmtDuration(item.end - item.start);
  const rows: Array<[string, string]> = [
    ["Started", `${fmtClock(n.started_at)} (${fmtOffset(item.start - index.minStart)})`],
    ["Ran for", ran],
  ];
  if (n.cpu_ms || n.working_set_bytes || n.peak_rss_bytes) {
    const mem = n.working_set_bytes || n.peak_rss_bytes;
    rows.push(["CPU · memory", `${n.cpu_ms ? fmtDuration(n.cpu_ms) : "-"} · ${mem ? fmtBytes(mem) : "-"}`]);
  }
  if (n.cwd) rows.push(["Folder", n.cwd]);
  if (link) rows.push(["Started by", `${link.node.turn_index != null ? `turn ${link.node.turn_index}` : "a tool call"}${link.node.command ? `: ${link.node.command}` : ""}`]);
  rows.push(["Depth", `${item.depth + 1} below the session`]);
  return (
    <div
      role="tooltip"
      className="pointer-events-none absolute z-20 rounded-3 border border-line-3 bg-bg-4 p-2.5 text-[11.5px] shadow-3"
      style={{ left, top: y + 16, width: W }}
    >
      <div className="flex flex-wrap items-center gap-1.5">
        <span className="font-mono font-semibold text-fg-0">{n.exe || "?"}</span>
        <span className="font-mono text-[10.5px] text-fg-3">
          {item.derived ? "from tool log" : `pid ${n.pid}${parent && !parent.derived ? ` · parent ${parent.node.pid}` : ""}`}
        </span>
        <span className={processStateTone(item)}>{processStateLabel(item)}</span>
      </div>
      {n.argv_preview && <div className="mt-1 break-all font-mono text-[10.5px] text-fg-2">{n.argv_preview}</div>}
      <dl className="mt-1.5 grid grid-cols-[84px_1fr] gap-x-2 gap-y-0.5">
        {rows.map(([k, v]) => (
          <div key={k} className="contents">
            <dt className="text-fg-3">{k}</dt>
            <dd className="m-0 break-all font-mono text-[10.5px] text-fg-1">{v}</dd>
          </div>
        ))}
      </dl>
      <div className="mt-1.5 border-t border-line-2 pt-1.5 text-[10.5px] text-fg-4">
        Click to select. The selection stays when you switch to Tree or Table.
      </div>
    </div>
  );
}
