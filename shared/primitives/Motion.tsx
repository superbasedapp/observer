import clsx from "clsx";
import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
  type ElementType,
  type PointerEvent as ReactPointerEvent,
  type ReactNode,
} from "react";
import {
  easeOutCubic,
  formatNumeric,
  parseNumeric,
  planTween,
  prefersReducedMotion,
} from "../lib/motion";

// Count-up happens only as part of a page ENTRY (the first ~2.5 s after the
// app boots or PageTransition changes route), so a number that mounts later
// (a tab switch, an expanded row) just renders. Module state, one per app.
const COUNT_UP_WINDOW_MS = 2500;
let pageEnteredAt = typeof performance !== "undefined" ? performance.now() : 0;
function inPageEntry(): boolean {
  return (
    typeof performance !== "undefined" &&
    performance.now() - pageEnteredAt < COUNT_UP_WINDOW_MS
  );
}

// Shared motion primitives. The heavy lifting is CSS (shared/styles/motion.css);
// these components only attach the right class at the right moment, so every
// app gets the same timing, the same reduced-motion behaviour, and no motion
// library on its critical path. Pure: no fetch, no router, no app state.

/**
 * PageTransition re-plays a short enter animation whenever `routeKey`
 * changes. There is deliberately no exit phase: the incoming page is never
 * held back waiting for the outgoing one (the old AnimatePresence
 * mode="wait" cost every navigation ~140 ms).
 */
export function PageTransition({
  routeKey,
  className,
  children,
}: {
  routeKey: string;
  className?: string;
  children: ReactNode;
}) {
  // Stamp the page entry during render: the children's number tweens read it
  // in their own first render, which happens after this one.
  useMemo(() => {
    if (typeof performance !== "undefined") pageEnteredAt = performance.now();
  }, [routeKey]);
  return (
    <div key={routeKey} className={clsx("sb-page-enter", className)}>
      {children}
    </div>
  );
}

/** Stagger reveals its direct children one after another (fade + rise). */
export function Stagger({
  as: Tag = "div",
  className,
  style,
  children,
}: {
  as?: ElementType;
  className?: string;
  style?: CSSProperties;
  children: ReactNode;
}) {
  return (
    <Tag className={clsx("sb-stagger", className)} style={style}>
      {children}
    </Tag>
  );
}

/**
 * FadeIn wraps content that replaces a skeleton: it mounts when the data
 * lands, so the CSS animation plays exactly once, at that moment.
 */
export function FadeIn({
  as: Tag = "div",
  className,
  rise = false,
  children,
}: {
  as?: ElementType;
  className?: string;
  /** Add an 8px rise to the fade. */
  rise?: boolean;
  children: ReactNode;
}) {
  return <Tag className={clsx(rise ? "sb-fade-up" : "sb-fade-in", className)}>{children}</Tag>;
}

/**
 * staleClass dims a panel whose data belongs to the previous filter while the
 * new response is in flight (opacity only; pointer-events off so a stale row
 * is not clicked). Pair with UpdatingBadge in the panel header.
 */
export function staleClass(stale: boolean | undefined): string {
  return stale ? "sb-stale-able sb-stale" : "sb-stale-able";
}

/** UpdatingBadge: a small pulsing "Updating" chip for a revalidating panel. */
export function UpdatingBadge({
  show,
  label = "Updating",
  className,
}: {
  show: boolean;
  label?: string;
  className?: string;
}) {
  if (!show) return null;
  return (
    <span
      role="status"
      className={clsx(
        "sb-fade-in inline-flex items-center gap-1.5 rounded-pill border border-accent/30 bg-accent-soft px-2 py-0.5 text-[10.5px] font-medium text-accent",
        className,
      )}
    >
      <span aria-hidden className="sb-updating-dot" />
      {label}
    </span>
  );
}

/**
 * TopProgress is the thin gradient bar pinned to the top edge of its
 * (position:relative) host. It appears only after a foreground request has
 * been running for 250 ms, so fast responses never flash it.
 */
export function TopProgress({ active, className }: { active: boolean; className?: string }) {
  return (
    <div
      aria-hidden
      data-active={active ? "true" : "false"}
      className={clsx("sb-progress", className)}
    />
  );
}

/** Aurora paints the drifting brand glow behind a hero surface. */
export function Aurora({ className }: { className?: string }) {
  return <span aria-hidden className={clsx("sb-aurora", className)} />;
}

/**
 * spotlightHandlers returns pointer handlers that write the pointer position
 * into --sb-mx / --sb-my on the element (the .sb-spotlight overlay reads
 * them). One rAF per frame at most; no React state, so no re-render.
 */
export function spotlightHandlers() {
  let frame = 0;
  return {
    onPointerMove(e: ReactPointerEvent<HTMLElement>) {
      const el = e.currentTarget;
      const x = e.clientX;
      const y = e.clientY;
      if (frame) return;
      frame = requestAnimationFrame(() => {
        frame = 0;
        const r = el.getBoundingClientRect();
        el.style.setProperty("--sb-mx", `${x - r.left}px`);
        el.style.setProperty("--sb-my", `${y - r.top}px`);
      });
    },
  };
}

const AnimatedSlot = createContext(false);

/**
 * useInAnimatedSlot is true inside a value slot that animates (StatCard /
 * HeroStat / BigStat pass their value through AnimatedValue) when that value
 * is a node rather than text. A text-rendering component opts in by wrapping
 * its final string in <AnimatedValue>; outside such a slot it stays static.
 */
export function useInAnimatedSlot(): boolean {
  return useContext(AnimatedSlot);
}

/**
 * AnimatedValue tweens a number rendered as text. It accepts whatever the
 * caller already renders: a number, or a formatted string such as "$6,073.08",
 * "1.2M" or "42%" (anything with one number and short non-digit affixes).
 * Anything else ("3h 12m", a ReactNode) renders unchanged.
 *
 * On first mount it counts up from zero (short ease-out, most of the value is
 * on screen within ~150 ms); on a later change it tweens from the previous
 * value and flashes a brand underline so the eye catches what moved. Reduced
 * motion: renders the final value immediately.
 */
export function AnimatedValue({
  value,
  durationMs = 520,
  countUp = true,
  className,
}: {
  value: ReactNode;
  durationMs?: number;
  countUp?: boolean;
  className?: string;
}) {
  if (typeof value !== "string" && typeof value !== "number") {
    // A node (e.g. web2's <Money>, which picks $ / tokens / % by the org's
    // display mode) cannot be tweened from out here. Tell it it sits in an
    // animated slot; a component that renders its own text can then tween it
    // with <AnimatedValue> itself (useInAnimatedSlot).
    return <AnimatedSlot.Provider value={true}>{value}</AnimatedSlot.Provider>;
  }
  return (
    <Tween
      text={typeof value === "number" ? String(value) : value}
      durationMs={durationMs}
      countUp={countUp}
      className={className}
    />
  );
}

function Tween({
  text,
  durationMs,
  countUp,
  className,
}: {
  text: string;
  durationMs: number;
  countUp: boolean;
  className?: string;
}) {
  // Decide ONCE, at mount, whether this value counts up; start the display at
  // zero in that case so the first paint never shows the final number and
  // then jumps back.
  const [countUpAtMount] = useState(() => {
    const p = parseNumeric(text);
    return (
      countUp && p != null && p.value !== 0 && inPageEntry() && !prefersReducedMotion()
    );
  });
  const [display, setDisplay] = useState(() => {
    const p = parseNumeric(text);
    return countUpAtMount && p ? formatNumeric(p, 0) : text;
  });
  const [flash, setFlash] = useState(false);
  // shownRef mirrors `display` (what is on screen), so a tween always starts
  // from the screen: under React StrictMode the mount effect runs twice (the
  // first run's frame is cancelled) and a newer value can interrupt a tween
  // mid-flight; both resume from the shown number instead of snapping.
  const shownRef = useRef(display);
  const prevTargetRef = useRef<string | null>(null);
  const frameRef = useRef(0);

  useEffect(() => {
    const prevTarget = prevTargetRef.current;
    prevTargetRef.current = text;
    const show = (s: string) => {
      shownRef.current = s;
      setDisplay(s);
    };
    const plan = planTween(shownRef.current, prevTarget, text, prefersReducedMotion());
    if (plan.flash) triggerFlash();
    if (plan.kind === "snap") {
      show(text);
      return;
    }
    const { from, to } = plan;
    // The clock starts on the first painted frame, not here: a long first
    // render (a dashboard mounting its charts) would otherwise eat the whole
    // tween before a single frame of it is seen.
    let t0: number | null = null;
    cancelAnimationFrame(frameRef.current);
    const step = (t: number) => {
      if (t0 == null) t0 = t;
      const k = easeOutCubic((t - t0) / durationMs);
      if (k >= 1) {
        show(text);
        return;
      }
      show(formatNumeric(to, from + (to.value - from) * k));
      frameRef.current = requestAnimationFrame(step);
    };
    frameRef.current = requestAnimationFrame(step);
    return () => cancelAnimationFrame(frameRef.current);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [text]);

  const flashTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  function triggerFlash() {
    setFlash(false);
    requestAnimationFrame(() => setFlash(true));
    if (flashTimer.current) clearTimeout(flashTimer.current);
    flashTimer.current = setTimeout(() => setFlash(false), 950);
  }
  useEffect(
    () => () => {
      if (flashTimer.current) clearTimeout(flashTimer.current);
    },
    [],
  );

  return (
    <span
      className={clsx("sb-value tabular-nums", className)}
      data-flash={flash ? "true" : undefined}
    >
      {display}
    </span>
  );
}
