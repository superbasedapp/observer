import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { Tooltip } from "./Tooltip";
import { Icon } from "@shared/primitives/Icon";
import { useCompanionRegistry } from "./companion";
import {
  clampRectToViewport,
  usePointerDrag,
  type DragDelta,
  type Rect,
} from "@/lib/useDrag";
import { ArrowRightToLine, X } from "lucide-react";

// FloatingPanel — a NON-MODAL, draggable, resizable window primitive (the
// systemic fix behind the per-terminal project panel rework). Unlike SlideOver
// it has NO backdrop, NO aria-modal, NO body scroll-lock, and NEVER calls
// focus() on open: the page and any embedded terminal stay fully interactive
// behind it. SlideOver is deliberately untouched — its other users still want
// modal-drawer semantics.
//
// Coexistence: the root is registered with the terminal-companion registry
// (primitives/companion) so the expanded terminal's focusin trap (LaunchTerminal)
// allowlists focus landing inside the panel by EXACT node containment (not a
// self-asserted attribute selector). z-index is provider-owned (the `z` prop)
// and sits in a band above the expanded-terminal backdrop (z-80); pointer-down
// anywhere on the panel raises it via onRaise. Escape closes ONLY while focus
// is inside the panel.

const MIN_W = 360;
const MIN_H = 240;

/** Default placement: mirror the old right-docked drawer so nothing feels lost. */
function defaultRect(): Rect {
  const w = Math.min(880, Math.max(MIN_W, window.innerWidth - 32));
  const h = Math.max(MIN_H, Math.round(window.innerHeight * 0.82));
  return {
    x: Math.max(8, window.innerWidth - w - 16),
    y: Math.max(8, Math.round((window.innerHeight - h) / 2)),
    w,
    h,
  };
}

function loadRect(storageKey: string): Rect | null {
  try {
    const raw = localStorage.getItem(storageKey);
    if (!raw) return null;
    const p = JSON.parse(raw);
    if (
      typeof p?.x === "number" &&
      typeof p?.y === "number" &&
      typeof p?.w === "number" &&
      typeof p?.h === "number"
    ) {
      return { x: p.x, y: p.y, w: Math.max(MIN_W, p.w), h: Math.max(MIN_H, p.h) };
    }
  } catch {
    /* malformed — fall through to the default */
  }
  return null;
}

// Resize grips: a table of which viewport edges each grip drives (CLAUDE.md #5:
// decision logic is a data table, not a conditional ladder). n/w edges move the
// origin as well as the size; e/s edges grow only the size.
type Edge = "n" | "s" | "e" | "w";
const GRIPS: { dir: string; edges: Edge[]; cls: string }[] = [
  { dir: "n", edges: ["n"], cls: "left-2 right-2 top-0 h-1.5 cursor-ns-resize" },
  { dir: "s", edges: ["s"], cls: "left-2 right-2 bottom-0 h-1.5 cursor-ns-resize" },
  { dir: "w", edges: ["w"], cls: "top-2 bottom-2 left-0 w-1.5 cursor-ew-resize" },
  { dir: "e", edges: ["e"], cls: "top-2 bottom-2 right-0 w-1.5 cursor-ew-resize" },
  { dir: "nw", edges: ["n", "w"], cls: "left-0 top-0 h-2.5 w-2.5 cursor-nwse-resize" },
  { dir: "ne", edges: ["n", "e"], cls: "right-0 top-0 h-2.5 w-2.5 cursor-nesw-resize" },
  { dir: "sw", edges: ["s", "w"], cls: "left-0 bottom-0 h-2.5 w-2.5 cursor-nesw-resize" },
  { dir: "se", edges: ["s", "e"], cls: "right-0 bottom-0 h-2.5 w-2.5 cursor-nwse-resize" },
];

export function FloatingPanel({
  storageKey,
  z,
  onRaise,
  onClose,
  title,
  ariaLabel,
  subtitle,
  children,
  cascade = 0,
}: {
  storageKey: string;
  z: number;
  onRaise: () => void;
  onClose: () => void;
  title: ReactNode;
  /**
   * Explicit accessible name for the panel root. The title is a React node so
   * AT can't derive a distinguishing label from it; pass a plain string here so
   * multiple simultaneously-open panels are individually identifiable. Falls
   * back to the title (when it's a string) or "Panel".
   */
  ariaLabel?: string;
  subtitle?: ReactNode;
  children: ReactNode;
  /** In-memory +24px stagger per additional simultaneously-open panel. */
  cascade?: number;
}) {
  const rootRef = useRef<HTMLDivElement | null>(null);
  // Base rect (persisted, cascade-free); the applied rect adds the stagger. A
  // drag/resize writes the base back with the stagger subtracted so the shared
  // default doesn't drift as panels cascade.
  const [rect, setRect] = useState<Rect>(() => {
    const off = cascade * 24;
    const base = loadRect(storageKey) ?? defaultRect();
    return clampRectToViewport({ ...base, x: base.x + off, y: base.y + off });
  });
  const rectRef = useRef(rect);
  rectRef.current = rect;
  // Drag/resize start snapshot so cumulative deltas apply to a fixed origin.
  const dragStart = useRef<Rect>(rect);
  // True once a gesture actually moved/resized. A pointer-down + up with NO
  // move (e.g. a click on the title bar to raise the panel) must NOT persist:
  // the shared storage key is one-per-all-panels, so a never-moved panel
  // writing its stale rect would clobber a sibling's newer saved rect. We
  // persist ONLY on a real drag/resize gesture end (P2-6).
  const gestureMoved = useRef(false);

  // Register this panel's root as a terminal-companion surface so the expanded
  // terminal's focusin trap treats focus landing inside it as legitimate
  // coexistence (provider-owned exact-node allowlist, not a self-asserted
  // selector).
  const companion = useCompanionRegistry();
  useEffect(() => {
    const el = rootRef.current;
    if (!el || !companion) return;
    return companion.register(el);
  }, [companion]);

  const persist = useCallback(
    (r: Rect) => {
      const off = cascade * 24;
      const base = { x: r.x - off, y: r.y - off, w: r.w, h: r.h };
      try {
        localStorage.setItem(storageKey, JSON.stringify(base));
      } catch {
        /* storage blocked — the rect still applies for this tab */
      }
    },
    [storageKey, cascade],
  );

  // Title-bar drag: move the origin, clamped to the viewport (the title-drag
  // policy allows a panel to sit partly off-screen, keeping a strip reachable).
  const titleDrag = usePointerDrag({
    onStart: () => {
      dragStart.current = rectRef.current;
      gestureMoved.current = false;
      onRaise();
    },
    onMove: ({ dx, dy }: DragDelta) => {
      // Only a real move arms persistence (P2-5): a zero-delta pointermove
      // (e.g. a pen-pressure change with no cursor movement) must NOT flip
      // gestureMoved, or a never-actually-moved panel would persist its stale
      // rect and clobber a sibling's saved rect on the shared storage key.
      if (dx !== 0 || dy !== 0) gestureMoved.current = true;
      const s = dragStart.current;
      setRect(clampRectToViewport({ ...s, x: s.x + dx, y: s.y + dy }));
    },
    onEnd: () => {
      if (gestureMoved.current) persist(rectRef.current);
    },
  });

  // One resize gesture, parameterised by which edges the grabbed grip drives.
  // `resizing` is the edge set the ACCEPTED gesture drives; `pendingEdges` is
  // the grip the raw pointerdown proposes. Committing the edge only inside
  // onStart (which usePointerDrag fires ONLY for the accepted primary pointer)
  // stops a second touch on another grip from hijacking the first touch's
  // resize direction mid-gesture (P2-6): the second pointerdown is rejected
  // before onStart, so `resizing` is never overwritten.
  const resizing = useRef<Edge[]>([]);
  const pendingEdges = useRef<Edge[]>([]);
  const resizeDrag = usePointerDrag({
    onStart: () => {
      resizing.current = pendingEdges.current;
      dragStart.current = rectRef.current;
      gestureMoved.current = false;
      onRaise();
    },
    onMove: ({ dx, dy }: DragDelta) => {
      const s = dragStart.current;
      const edges = resizing.current;
      const m = 8;
      const vw = window.innerWidth;
      const vh = window.innerHeight;
      let { x, y, w, h } = s;
      if (edges.includes("e")) w = s.w + dx;
      if (edges.includes("s")) h = s.h + dy;
      if (edges.includes("w")) {
        w = s.w - dx;
        x = s.x + dx;
      }
      if (edges.includes("n")) {
        h = s.h - dy;
        y = s.y + dy;
      }
      // Enforce the minimum size WITHOUT letting a n/w drag walk the origin
      // past the min (clamp the origin to the far edge minus min).
      if (w < MIN_W) {
        if (edges.includes("w")) x = s.x + s.w - MIN_W;
        w = MIN_W;
      }
      if (h < MIN_H) {
        if (edges.includes("n")) y = s.y + s.h - MIN_H;
        h = MIN_H;
      }
      // Keep the RESIZED edges reachable on-screen (P2-8): unlike a title drag,
      // a resize must never push its own grip off the viewport. Pin a moving
      // n/w origin to the margin, then cap a growing e/s size so x+w / y+h stay
      // within the viewport. The far (anchored) edge is untouched.
      if (edges.includes("w") && x < m) {
        w = s.x + s.w - m;
        x = m;
      }
      if (edges.includes("n") && y < m) {
        h = s.y + s.h - m;
        y = m;
      }
      if (edges.includes("e")) w = Math.min(w, vw - m - x);
      if (edges.includes("s")) h = Math.min(h, vh - m - y);
      // Never below the minimum even after the on-screen cap.
      w = Math.max(MIN_W, w);
      h = Math.max(MIN_H, h);
      // Only a REAL size/origin change arms persistence (P2-5): a zero-delta
      // pointermove — or a delta the clamps fully absorb (e.g. at the minimum
      // size) — must not flip gestureMoved and clobber a sibling's saved rect.
      const c = rectRef.current;
      if (x !== c.x || y !== c.y || w !== c.w || h !== c.h) gestureMoved.current = true;
      setRect({ x, y, w, h });
    },
    onEnd: () => {
      if (gestureMoved.current) persist(rectRef.current);
    },
  });

  const snapDefault = useCallback(() => {
    // Apply the cascade stagger just like the initial placement (P2-4): the
    // APPLIED rect carries the +24px/slot offset, so persist() (which subtracts
    // it) round-trips to the true shared base. Omitting it here saved a base
    // shifted −24px and collided cascade slot 1 with slot 0.
    const off = cascade * 24;
    const base = defaultRect();
    const r = clampRectToViewport({ ...base, x: base.x + off, y: base.y + off });
    setRect(r);
    persist(r);
    onRaise();
  }, [persist, onRaise, cascade]);

  // Re-clamp on viewport resize so a shrunk window can't strand the panel.
  useEffect(() => {
    const onResize = () => setRect((r) => clampRectToViewport(r));
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);

  return (
    <div
      ref={rootRef}
      role="complementary"
      aria-label={ariaLabel ?? (typeof title === "string" ? title : "Panel")}
      onPointerDown={onRaise}
      onKeyDown={(e) => {
        // Escape closes ONLY when focus is inside this panel (this handler only
        // fires for a descendant-focused keydown). Stop it reaching the
        // terminal's document-level Escape handler.
        if (e.key === "Escape") {
          e.stopPropagation();
          onClose();
        }
      }}
      style={{ position: "fixed", left: rect.x, top: rect.y, width: rect.w, height: rect.h, zIndex: z }}
      className="flex flex-col overflow-hidden rounded-2 border border-line-2 bg-bg-1 shadow-drawer"
    >
      {/* Title bar — the drag handle. Double-click snaps back to the default. */}
      <header
        onPointerDown={(e) => {
          // Arm a drag only from the header's empty/drag region (P2-1). A
          // pointerdown on an interactive descendant (Close/Dock/tab controls)
          // must NOT start a drag or capture the pointer — otherwise pointer-up
          // is retargeted away from the button and its click is suppressed.
          if ((e.target as Element).closest("button,[role=button],input,a")) return;
          titleDrag.onPointerDown(e);
        }}
        onPointerMove={titleDrag.onPointerMove}
        onPointerUp={titleDrag.onPointerUp}
        onPointerCancel={titleDrag.onPointerCancel}
        onLostPointerCapture={titleDrag.onLostPointerCapture}
        onDoubleClick={snapDefault}
        className="flex shrink-0 cursor-grab touch-none select-none items-start justify-between gap-3 border-b border-line-1 bg-bg-2 px-4 py-2 active:cursor-grabbing"
      >
        <div className="min-w-0">
          <div className="truncate text-[13px] font-semibold text-fg-0">{title}</div>
          {subtitle && (
            <div className="mt-0.5 truncate text-[11px] text-fg-3">{subtitle}</div>
          )}
        </div>
        <div className="flex shrink-0 items-center gap-1">
          <Tooltip content="Dock to default position">
            <button
              type="button"
              onClick={snapDefault}
              aria-label="Dock to default position"
              className="grid h-6 w-6 place-items-center rounded-2 border border-line-2 bg-bg-1 text-fg-2 hover:bg-bg-3 hover:text-fg-0"
            >
              <Icon icon={ArrowRightToLine} size="sm" />
            </button>
          </Tooltip>
          <Tooltip content={<>Close <kbd>Esc</kbd></>}>
            <button
              type="button"
              onClick={onClose}
              aria-label="Close"
              className="grid h-6 w-6 place-items-center rounded-2 border border-line-2 bg-bg-1 text-fg-2 hover:bg-bg-3 hover:text-fg-0"
            >
              <Icon icon={X} size="sm" />
            </button>
          </Tooltip>
        </div>
      </header>
      <div className="min-h-0 flex-1 overflow-hidden">{children}</div>
      {/* Resize grips (edges + corners). */}
      {GRIPS.map((g) => (
        <div
          key={g.dir}
          onPointerDown={(e) => {
            pendingEdges.current = g.edges;
            resizeDrag.onPointerDown(e);
          }}
          onPointerMove={resizeDrag.onPointerMove}
          onPointerUp={resizeDrag.onPointerUp}
          onPointerCancel={resizeDrag.onPointerCancel}
          onLostPointerCapture={resizeDrag.onLostPointerCapture}
          aria-hidden
          className={`absolute touch-none ${g.cls}`}
        />
      ))}
    </div>
  );
}
