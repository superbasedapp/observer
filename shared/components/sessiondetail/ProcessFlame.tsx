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
import { Minus, Plus } from "lucide-react";
import { Button, SegmentedControl } from "../../primitives";
import { fmtBytes, fmtClock, fmtDuration, fmtInt } from "../../lib/format";
import {
  FOLD_TOTAL_THRESHOLD,
  PAN_STEP,
  STACK_KEYS,
  ZOOM_STEP,
  barTier,
  brushDomain,
  buildTimeScale,
  buildUnits,
  centreAt,
  chainOf,
  chartKeyAction,
  clampDomain,
  clipSpan,
  failedChainKeys,
  fmtOffset,
  fmtSpan,
  fmtZoom,
  initialDomain,
  isAgentProcess,
  isDescendantOf,
  isWholeSession,
  linearTicks,
  minSpanFor,
  moveSelection,
  overviewBuckets,
  packLanes,
  panBy,
  resizeEdge,
  sessionBounds,
  turnMarkers,
  unitEnd,
  unitStart,
  wheelIntent,
  zoomAround,
  zoomLevel,
  zoomWindow,
  type ChartKeyAction,
  type ProcessStackIndex,
  type ProcessStackItem,
  type StackUnit,
  type TimeDomain,
  type TimeScale,
} from "../../lib/processLayout";

// ProcessFlame - the chart half of the session-detail "Call stack" view. Each
// bar is one process: depth is which process started which (the spawn chain
// the operating system recorded), width is how long it ran. Siblings that ran
// at the same time stack into extra lanes so nothing is hidden.
//
// The visible time window is state the reader stretches and moves: the zoom
// toolbar, Ctrl or Cmd + wheel (and a trackpad pinch) around the cursor, Shift
// + wheel or a sideways wheel to pan, dragging the plot to pan, dragging
// across the time axis to zoom to that stretch, the keys + - 0 and Shift+arrows
// on the focused plot, and the overview strip (move or resize the window).
// It opens on the whole session, or on a window of a large one.
//
// The default time scale is "Skip quiet": stretches inside the window where
// only long-running processes (the agent, MCP or dev servers) were alive are
// squeezed into striped bands, so short commands stay readable; widths inside
// active stretches stay true. "Real time" is one click away, and "Zoom to
// selection" is always real time.
//
// Pure presentation: the placed model comes from lib/processLayout, selection
// is owned by the caller (shared with Tree and Table), and the message link is
// injected (onOpenMessage) so the component never routes.

const ROW_H = 22;
const ROW_GAP = 3;
const BAND_GAP = 6;
const ROOT_BAR_H = 22;
/** The plot is at least this many rows tall, so a shallow session is not squashed. */
const MIN_PLOT_ROWS = 4;
const MIN_PLOT_H = ROOT_BAR_H + BAND_GAP + MIN_PLOT_ROWS * (ROW_H + ROW_GAP) + BAND_GAP;
/** Overview strip resolution. */
const OVERVIEW_BUCKETS = 120;
/** A pointer that moved less than this many pixels clicked rather than dragged. */
const DRAG_SLOP_PX = 3;

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

function clock(ms: number): string {
  return fmtClock(new Date(ms).toISOString());
}

/** clockRange: "Jun 25, 14:02:11 to 14:13:20" (the date once when both ends share it). */
function clockRange(a: number, b: number): string {
  const A = clock(a);
  const B = clock(b);
  const i = A.lastIndexOf(", ");
  const j = B.lastIndexOf(", ");
  if (i > 0 && j > 0 && A.slice(0, i) === B.slice(0, j)) return `${A} to ${B.slice(j + 2)}`;
  return `${A} to ${B}`;
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

/** The reader's window: null = the opening window, "fit" = the whole session, else a domain. */
type DomainChoice = TimeDomain | "fit" | null;

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
  const [selZoom, setSelZoom] = useState(false);
  const preZoom = useRef<DomainChoice>(null);
  const [failedOnly, setFailedOnly] = useState(false);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [hover, setHover] = useState<{ key: string; x: number; y: number } | null>(null);
  const [width, setWidth] = useState(800);
  const [choice, setChoice] = useState<DomainChoice>(null);
  /** a brush across the time axis, as plot fractions */
  const [brush, setBrush] = useState<{ a: number; b: number } | null>(null);
  const plotRef = useRef<HTMLDivElement>(null);
  const stageRef = useRef<HTMLDivElement>(null);
  const axisRef = useRef<HTMLDivElement>(null);
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
  const bounds = sessionBounds(index);
  const sessionSpan = bounds[1] - bounds[0];
  const minSpan = minSpanFor(bounds);
  const sel = selectedKey && index.byKey.has(selectedKey) ? index.byKey.get(selectedKey)! : null;

  // The opening window follows the selection (a large session opens around the
  // selection's top-level command); once the reader zooms or pans, their window
  // is kept, clamped to the session as it grows.
  const domain: [number, number] =
    choice === "fit"
      ? bounds
      : clampDomain(choice ?? initialDomain(index, sel ? sel.key : null, width), bounds, minSpan);
  const span = domain[1] - domain[0];
  const whole = isWholeSession(domain, bounds);
  const atMinSpan = span <= minSpan + 1e-6;
  const linear = scale === "real" || (selZoom && !!sel);

  const domainRef = useRef(domain);
  domainRef.current = domain;
  const setDomain = useCallback(
    (d: TimeDomain) => setChoice(clampDomain(d, bounds, minSpan)),
    // bounds is derived each render; its two numbers are the real dependency
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [bounds[0], bounds[1], minSpan],
  );

  // A selection made elsewhere (Tree, Table, a link, the keyboard) stays in
  // view: "Zoom to selection" follows it, a moved window re-centres on it.
  const selKey = sel ? sel.key : null;
  useEffect(() => {
    if (!sel) {
      if (selZoom) setSelZoom(false);
      return;
    }
    if (selZoom) {
      const z = zoomWindow(index, sel.key);
      if (z) setDomain(z);
      return;
    }
    if (choice == null || choice === "fit") return;
    const d = domainRef.current;
    if (sel.start < d[0] || sel.start > d[1]) setDomain(centreAt(d, sel.start, bounds));
    // only a change of selection re-centres; panning away from it must not snap back
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selKey]);

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
  const tsRef = useRef<TimeScale>(ts);
  tsRef.current = ts;

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
    return { tops, height: Math.max(y, MIN_PLOT_H) };
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

  // ---- zoom and pan ----

  const fit = useCallback(() => {
    setSelZoom(false);
    setChoice("fit");
  }, []);

  const toggleSelZoom = () => {
    if (selZoom) {
      setSelZoom(false);
      setChoice(preZoom.current);
      return;
    }
    const z = sel ? zoomWindow(index, sel.key) : null;
    if (!z) return;
    preZoom.current = choice;
    setSelZoom(true);
    setDomain(z);
  };

  const runChartKey = (act: ChartKeyAction) => {
    const d = domainRef.current;
    const w = d[1] - d[0];
    // Keyboard zoom anchors on the selection when it is in view, else the middle.
    const anchor = sel && sel.start >= d[0] && sel.start <= d[1] ? sel.start : (d[0] + d[1]) / 2;
    if (act === "zoomIn") setDomain(zoomAround(d, anchor, ZOOM_STEP, bounds, minSpan));
    else if (act === "zoomOut") setDomain(zoomAround(d, anchor, 1 / ZOOM_STEP, bounds, minSpan));
    else if (act === "fit") fit();
    else setDomain(panBy(d, (act === "panLeft" ? -1 : 1) * w * PAN_STEP, bounds));
  };

  const zoomCentre = (factor: number) => {
    const d = domainRef.current;
    setDomain(zoomAround(d, (d[0] + d[1]) / 2, factor, bounds, minSpan));
  };

  // Wheel: attached by hand with passive:false so preventDefault works for
  // the zoom and pan cases; a plain vertical wheel is never claimed and keeps
  // scrolling the page.
  const onWheelRef = useRef<(e: WheelEvent) => void>(() => {});
  onWheelRef.current = (e: WheelEvent) => {
    const intent = wheelIntent(e);
    const plot = plotRef.current;
    if (!intent || !plot) return;
    e.preventDefault();
    const r = plot.getBoundingClientRect();
    const d = domainRef.current;
    if (intent.kind === "zoom") {
      const f = (e.clientX - r.left) / Math.max(1, r.width);
      setDomain(zoomAround(d, tsRef.current.invert(f), intent.factor, bounds, minSpan));
    } else {
      setDomain(panBy(d, (intent.px / Math.max(1, r.width)) * (d[1] - d[0]), bounds));
    }
  };
  useEffect(() => {
    const el = stageRef.current;
    if (!el) return;
    const h = (e: WheelEvent) => onWheelRef.current(e);
    el.addEventListener("wheel", h, { passive: false });
    return () => el.removeEventListener("wheel", h);
  }, []);

  // Drag on the plot pans; a press that barely moved is a click (select).
  const drag = useRef<{ x: number; d: TimeDomain; id: number; moved: boolean } | null>(null);
  const suppressClick = useRef(false);
  const onPlotPointerDown = (e: ReactPointerEvent<HTMLDivElement>) => {
    if (e.button !== 0) return;
    suppressClick.current = false;
    drag.current = { x: e.clientX, d: domainRef.current, id: e.pointerId, moved: false };
  };
  const onPlotPointerMove = (e: ReactPointerEvent<HTMLDivElement>) => {
    const g = drag.current;
    if (!g) return;
    if (e.buttons === 0 && !g.moved) {
      // released outside the plot before it became a drag
      drag.current = null;
      return;
    }
    const dx = e.clientX - g.x;
    if (!g.moved) {
      if (Math.abs(dx) < DRAG_SLOP_PX) return;
      g.moved = true;
      suppressClick.current = true;
      setHover(null);
      plotRef.current?.setPointerCapture?.(g.id);
    }
    setDomain(panBy(g.d, (-dx / Math.max(1, width)) * (g.d[1] - g.d[0]), bounds));
  };
  const endPlotDrag = () => {
    const g = drag.current;
    drag.current = null;
    if (g?.moved) plotRef.current?.releasePointerCapture?.(g.id);
  };

  // Drag across the time axis draws a brush and zooms to it on release.
  const brushStart = useRef<number | null>(null);
  const axisFraction = (clientX: number) => {
    const el = axisRef.current;
    if (!el) return 0;
    const r = el.getBoundingClientRect();
    return Math.min(1, Math.max(0, (clientX - r.left) / Math.max(1, r.width)));
  };
  const onAxisPointerDown = (e: ReactPointerEvent<HTMLDivElement>) => {
    if (e.button !== 0 || (e.target as Element).closest?.("button")) return;
    const f = axisFraction(e.clientX);
    brushStart.current = f;
    setBrush({ a: f, b: f });
    axisRef.current?.setPointerCapture?.(e.pointerId);
  };
  const onAxisPointerMove = (e: ReactPointerEvent<HTMLDivElement>) => {
    if (brushStart.current == null) return;
    setBrush({ a: brushStart.current, b: axisFraction(e.clientX) });
  };
  const onAxisPointerUp = (e: ReactPointerEvent<HTMLDivElement>) => {
    if (brushStart.current == null) return;
    const a = brushStart.current;
    const b = axisFraction(e.clientX);
    brushStart.current = null;
    setBrush(null);
    if (Math.abs(b - a) * width < DRAG_SLOP_PX + 1) return;
    setDomain(brushDomain(ts.invert(a), ts.invert(b), bounds, minSpan));
  };
  const cancelBrush = useCallback(() => {
    brushStart.current = null;
    setBrush(null);
  }, []);
  const brushing = brush != null;
  useEffect(() => {
    if (!brushing || typeof window === "undefined") return;
    const onKey = (e: globalThis.KeyboardEvent) => {
      if (e.key === "Escape") cancelBrush();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [brushing, cancelBrush]);

  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    const act = chartKeyAction(e.key, e);
    if (act) {
      e.preventDefault();
      runChartKey(act);
      return;
    }
    const move = STACK_KEYS[e.key];
    if (move && !e.shiftKey) {
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
      cancelBrush();
    }
  };

  const showHover = (key: string, e: ReactPointerEvent<HTMLElement>) => {
    const wrap = wrapRef.current;
    if (!wrap || e.pointerType === "touch" || drag.current?.moved) return;
    const r = wrap.getBoundingClientRect();
    setHover({ key, x: e.clientX - r.left, y: e.clientY - r.top });
  };

  const nowInDomain = index.items.some((it) => it.endKind === "running") && nowMs >= domain[0] && nowMs <= domain[1] + 1;
  const readout = `${fmtZoom(zoomLevel(domain, bounds))} · ${whole ? "all of" : `${fmtSpan(span)} of`} ${fmtSpan(sessionSpan)}`;

  return (
    <div ref={wrapRef} className="relative min-w-0 rounded-3 border border-line-2 bg-bg-2">
      {/* Header: range, scale, filter, and the zoom toolbar. */}
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 border-b border-line-1 px-3 py-2 text-[10.5px] text-fg-3">
        <span className="tabular-nums" data-testid="flame-range">
          {clockRange(domain[0], domain[1])}
        </span>
        <div role="group" aria-label="Time scale">
          <SegmentedControl
            size="sm"
            value={linear ? "real" : "quiet"}
            onChange={(v) => setScale(v)}
            options={[
              {
                value: "quiet",
                label: "Skip quiet",
                disabled: selZoom && !!sel,
                disabledReason: "Zoom to selection is always real time. Press Fit to leave it.",
              },
              { value: "real", label: "Real time" },
            ]}
          />
        </div>
        <label className="inline-flex cursor-pointer items-center gap-1.5 hover:text-fg-1">
          <input
            type="checkbox"
            className="h-3 w-3 accent-[var(--accent)]"
            checked={failedOnly}
            onChange={(e) => setFailedOnly(e.target.checked)}
          />
          Only failed chains
        </label>
        <div role="toolbar" aria-label="Zoom" className="ml-auto flex flex-wrap items-center gap-1">
          <Button
            size="sm"
            variant="ghost"
            className="!px-1.5"
            iconLeft={Minus}
            aria-label="Zoom out"
            title="Zoom out (-)"
            disabled={whole}
            onClick={() => zoomCentre(1 / ZOOM_STEP)}
          />
          <Button
            size="sm"
            variant="ghost"
            className="!px-1.5"
            iconLeft={Plus}
            aria-label="Zoom in"
            title="Zoom in (+)"
            disabled={atMinSpan}
            onClick={() => zoomCentre(ZOOM_STEP)}
          />
          <Button size="sm" variant="ghost" disabled={whole && !selZoom} onClick={fit} title="Show the whole session (0)">
            Fit
          </Button>
          <Button
            size="sm"
            variant={selZoom && sel ? "soft" : "ghost"}
            aria-pressed={selZoom && !!sel}
            disabled={!sel}
            onClick={toggleSelZoom}
            title={sel ? "Zoom to the command that started the selected process, in real time" : "Pick a process first"}
          >
            Zoom to selection
          </Button>
          <span className="ml-1 whitespace-nowrap tabular-nums text-fg-2" data-testid="flame-zoom" aria-live="polite">
            {readout}
          </span>
        </div>
      </div>

      {/* Shown whenever the window is narrower than the session, and kept
          while the reader's own window reaches the whole of it, so dragging
          a handle to the end does not pull the strip away mid-drag. */}
      {(!whole || Array.isArray(choice)) && (
        <OverviewStrip index={index} domain={domain} bounds={bounds} minSpan={minSpan} onChange={setDomain} />
      )}

      <div className="px-3 pb-2">
        <div ref={stageRef} className="relative">
          {/* Axis: time ticks and turn markers. Drag across it to zoom to that stretch. */}
          <div
            ref={axisRef}
            className="relative h-[34px] cursor-crosshair touch-none select-none border-b border-line-1"
            title="Drag across the time axis to zoom to that stretch"
            onPointerDown={onAxisPointerDown}
            onPointerMove={onAxisPointerMove}
            onPointerUp={onAxisPointerUp}
            onPointerCancel={cancelBrush}
          >
            {ticks.map((t) => (
              <span
                key={`t${t}`}
                className="pointer-events-none absolute top-1 whitespace-nowrap text-[10px] tabular-nums text-fg-4"
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
            onPointerDown={onPlotPointerDown}
            onPointerMove={onPlotPointerMove}
            onPointerUp={endPlotDrag}
            onPointerCancel={endPlotDrag}
            onPointerLeave={() => setHover(null)}
            className={clsx(
              "relative mt-1.5 select-none rounded-1 outline-none focus-visible:ring-2 focus-visible:ring-accent-ring",
              !whole && "cursor-grab active:cursor-grabbing",
            )}
            style={{ height: rowTop.height, touchAction: "pan-y" }}
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
              const clip = clipSpan(unitStart(u), unitEnd(u), domain);
              const left = pct(clip.a);
              const w = Math.max(0, pct(clip.b) - left);
              const tier = barTier((w / 100) * width);
              if (u.kind === "group") {
                return (
                  <GroupBar
                    key={u.key}
                    unit={u}
                    left={left}
                    width={w}
                    top={top}
                    labelled={tier === "label"}
                    cutStart={clip.cutStart}
                    onExpand={() => {
                      if (suppressClick.current) return;
                      setExpanded((prev) => new Set(prev).add(u.key));
                    }}
                    inChain={u.members.some((m) => anc.has(m.key))}
                  />
                );
              }
              const it = u.item;
              const isSel = it.key === selectedKey;
              const isAnc = !isSel && anc.has(it.key);
              const isDesc = !!selectedKey && !isSel && !isAnc && isDescendantOf(index, it.key, selectedKey);
              const dim = !!selectedKey && !isSel && !isAnc && !isDesc;
              const thin = tier === "tick";
              return (
                <div
                  key={it.key}
                  id={processDomId(idPrefix, it.key)}
                  role="treeitem"
                  aria-level={it.depth + 1}
                  aria-selected={isSel}
                  aria-label={`${it.node.exe}${it.derived ? ", from tool log" : `, pid ${it.node.pid}`}, ${processStateLabel(it)}, started ${clock(it.start)}, ran ${fmtDuration(it.end - it.start)}`}
                  data-tier={tier}
                  onClick={(e) => {
                    e.stopPropagation();
                    if (suppressClick.current) return;
                    onSelect(it.key);
                    plotRef.current?.focus({ preventScroll: true });
                  }}
                  onDoubleClick={(e) => {
                    // Double-click opens the message (and so the turn) that
                    // started the process, the same link Enter follows.
                    const link = onOpenMessage ? spawnLinkOf(index, it.key) : null;
                    if (!link?.node.message_id) return;
                    e.stopPropagation();
                    onOpenMessage!(link.node.message_id);
                  }}
                  onPointerMove={(e) => showHover(it.key, e)}
                  className={clsx(
                    "absolute cursor-pointer overflow-hidden whitespace-nowrap rounded-[3px] border font-mono text-[10.5px] leading-[20px] transition-opacity duration-150",
                    tier === "label" ? "px-1.5" : "px-0",
                    clip.cutStart && "rounded-l-none",
                    clip.cutEnd && "rounded-r-none",
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
                  {tier === "label" && (
                    <span className="block truncate">
                      {clip.cutStart && (
                        <span aria-hidden className={isSel ? "opacity-75" : "text-fg-4"}>
                          ‹{" "}
                        </span>
                      )}
                      <span className={clsx(isSel ? "" : "text-fg-1", it.failed && !isSel && "text-danger")}>{it.node.exe || "?"}</span>{" "}
                      <span className={isSel ? "opacity-75" : "text-fg-3"}>{shortArgv(it)}</span>
                    </span>
                  )}
                </div>
              );
            })}
          </div>

          {brush && (
            <div
              aria-hidden
              className="pointer-events-none absolute bottom-0 top-0 border-x border-accent bg-accent-soft"
              style={{ left: `${Math.min(brush.a, brush.b) * 100}%`, width: `${Math.abs(brush.b - brush.a) * 100}%` }}
            />
          )}
        </div>
      </div>

      {/* Footer: the legend, what a bar means, and the keys. */}
      <div className="space-y-1 border-t border-line-1 px-3 py-1.5 text-[10.5px] text-fg-4">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <LegendSwatch className="border-info/60 bg-info-soft" label="agent" />
          <LegendSwatch className="border-line-3 bg-bg-4" label="finished" />
          <LegendSwatch className="border-danger/70 bg-danger-soft" label="failed" />
          <LegendSwatch className="border-line-3 bg-bg-4 shadow-[inset_0_-2px_0_var(--success)]" label="running" />
          <LegendSwatch className="border-dashed border-line-3 bg-transparent" label="tool log only" />
          <span className="min-w-0">
            Each bar is one process, started by the bar above it. Width is how long it ran
            {ts.collapsed && ts.gaps.length ? "; striped bands are quiet stretches, squeezed" : ""}.
          </span>
        </div>
        <div className="hidden sm:block">
          ← → siblings · ↑ ↓ parent and child{onOpenMessage ? " · Enter or double-click opens the message" : ""} · + − zoom · 0 fit ·
          Shift+← → pan · Ctrl+wheel zooms, Shift+wheel pans · drag the plot to pan, drag the time axis to zoom
        </div>
      </div>

      {hover && index.byKey.get(hover.key) && (
        <HoverCard
          item={index.byKey.get(hover.key)!}
          index={index}
          x={hover.x}
          y={hover.y}
          wrapWidth={wrapRef.current?.clientWidth ?? 800}
          canOpen={!!onOpenMessage}
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
      <span className={clsx("inline-block h-[8px] w-[12px] rounded-[2px] border", className)} aria-hidden />
      {label}
    </span>
  );
}

function GroupBar({
  unit,
  left,
  width,
  top,
  labelled,
  cutStart,
  onExpand,
  inChain,
}: {
  unit: Extract<StackUnit, { kind: "group" }>;
  left: number;
  width: number;
  top: number;
  labelled: boolean;
  cutStart: boolean;
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
      aria-label={`${label}: ${fmtInt(unit.members.length)} similar processes in one bar. Show each one`}
      title={`${fmtInt(unit.members.length)} similar processes folded into one bar${hidden}${unit.failedCount ? `, ${fmtInt(unit.failedCount)} failed` : ""}. Click to show each one.`}
      className={clsx(
        "absolute overflow-hidden whitespace-nowrap rounded-[3px] border text-left font-mono text-[10.5px] leading-[20px] text-fg-2",
        labelled ? "px-1.5" : "px-0",
        cutStart && "rounded-l-none",
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
      {labelled && <span className="block truncate">{label}</span>}
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
  domain: TimeDomain;
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

/** What a press on the overview strip grabbed. */
type StripGrab = "move" | "start" | "end";

function OverviewStrip({
  index,
  domain,
  bounds,
  minSpan,
  onChange,
}: {
  index: ProcessStackIndex;
  domain: TimeDomain;
  bounds: TimeDomain;
  minSpan: number;
  onChange: (d: TimeDomain) => void;
}) {
  const ob = useMemo(() => overviewBuckets(index, OVERVIEW_BUCKETS), [index]);
  const max = Math.max(1, ...ob.counts);
  const total = Math.max(1, bounds[1] - bounds[0]);
  const winW = domain[1] - domain[0];
  const ref = useRef<HTMLDivElement>(null);
  const drag = useRef<{ grab: StripGrab; t0: number; d: TimeDomain } | null>(null);
  const timeAt = (clientX: number) => {
    const el = ref.current;
    if (!el) return bounds[0];
    const r = el.getBoundingClientRect();
    const f = Math.min(1, Math.max(0, (clientX - r.left) / Math.max(1, r.width)));
    return bounds[0] + f * total;
  };
  const apply = (t: number) => {
    const g = drag.current;
    if (!g) return;
    if (g.grab === "move") onChange(panBy(g.d, t - g.t0, bounds));
    else onChange(resizeEdge(g.d, g.grab, t, bounds, minSpan));
  };
  const step = (dir: number) => onChange(panBy(domain, dir * winW * 0.5, bounds));
  const leftPct = ((domain[0] - bounds[0]) / total) * 100;
  const widthPct = (winW / total) * 100;
  return (
    <div className="px-3 pt-2">
      <div className="mb-1 flex flex-wrap justify-between gap-x-3 gap-y-0.5 text-[10.5px] text-fg-3">
        <span>
          {fmtInt(index.items.length)} processes · started per {fmtSpan(ob.bucketMs)} · red marks failures
        </span>
        <span className="tabular-nums" data-testid="overview-window">
          Window {clockRange(domain[0], domain[1])}
        </span>
      </div>
      <div
        ref={ref}
        role="slider"
        tabIndex={0}
        aria-label="Chart window within the session. Drag it to move, drag an edge to resize, click to centre it"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={Math.round(leftPct)}
        aria-valuetext={clockRange(domain[0], domain[1])}
        onPointerDown={(e) => {
          if (e.button !== 0) return;
          const t = timeAt(e.clientX);
          const part = (e.target as Element).closest?.("[data-part]")?.getAttribute("data-part") as StripGrab | null;
          if (part === "start" || part === "end" || part === "move") {
            drag.current = { grab: part, t0: t, d: domain };
          } else {
            // Clicked outside the window: centre it there, then keep dragging it.
            const c = centreAt(domain, t, bounds);
            onChange(c);
            drag.current = { grab: "move", t0: t, d: c };
          }
          (e.currentTarget as Element).setPointerCapture?.(e.pointerId);
        }}
        onPointerMove={(e) => drag.current && apply(timeAt(e.clientX))}
        onPointerUp={() => (drag.current = null)}
        onPointerCancel={() => (drag.current = null)}
        onKeyDown={(e) => {
          if (e.key === "ArrowLeft" || e.key === "ArrowRight") {
            e.preventDefault();
            step(e.key === "ArrowLeft" ? -1 : 1);
          }
        }}
        className="relative h-[34px] cursor-pointer touch-none select-none rounded-1 border border-line-1 bg-bg-3 outline-none focus-visible:ring-2 focus-visible:ring-accent-ring"
      >
        {ob.counts.map((c, i) => (
          <div
            key={i}
            aria-hidden
            className="pointer-events-none absolute bottom-0 flex h-full items-end"
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
          data-part="move"
          className="absolute -bottom-[2px] -top-[2px] cursor-grab rounded-[3px] border-[1.5px] border-accent bg-accent-soft active:cursor-grabbing"
          style={{ left: `${leftPct}%`, width: `${widthPct}%`, minWidth: 10 }}
        >
          <span
            data-part="start"
            className="absolute -left-[5px] bottom-0 top-0 flex w-[9px] cursor-ew-resize items-center justify-center"
          >
            <span className="h-[14px] w-[3px] rounded-full bg-accent" />
          </span>
          <span
            data-part="end"
            className="absolute -right-[5px] bottom-0 top-0 flex w-[9px] cursor-ew-resize items-center justify-center"
          >
            <span className="h-[14px] w-[3px] rounded-full bg-accent" />
          </span>
        </div>
      </div>
      <div className="relative mt-0.5 h-[14px] text-[9.5px] text-fg-4" aria-hidden>
        <span className="absolute left-0">{clock(bounds[0])}</span>
        <span className="absolute right-0">{clock(bounds[1])}</span>
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
  canOpen,
}: {
  item: ProcessStackItem;
  index: ProcessStackIndex;
  x: number;
  y: number;
  wrapWidth: number;
  /** canOpen: the chart can open a message (onOpenMessage was given). */
  canOpen?: boolean;
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
  // The message id is the same link the Tree and Table rows carry; on a
  // descendant it is inherited from the frame whose tool call started it.
  const messageId = link?.node.message_id;
  if (messageId) rows.push(["Message", messageId]);
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
        Click to select{messageId && canOpen ? "; double-click or Enter opens the message" : ""}. The selection stays when
        you switch to Tree or Table.
      </div>
    </div>
  );
}
