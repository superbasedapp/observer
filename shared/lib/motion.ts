// JS mirror of the shared motion tokens (shared/styles/tokens.css "Motion").
//
// CSS owns motion wherever it can (shared/styles/motion.css): classes are
// cheaper than JS and collapse automatically under prefers-reduced-motion.
// This module exists for the few places that need numbers in JS - framer-
// motion transitions (CommandPalette), recharts series animation,
// and the AnimatedNumber tween. Keep the values in sync with tokens.css.
//
// Pure: no React, no DOM access at import time (safe under node --test).

/** Durations in milliseconds (tokens.css --dur-*). */
export const DUR = {
  instant: 80,
  fast: 120,
  base: 200,
  slow: 320,
  slower: 560,
} as const;

/** Cubic-bezier control points (tokens.css --ease-*), framer-motion shape. */
export const EASE = {
  standard: [0.2, 0.7, 0.2, 1] as [number, number, number, number],
  out: [0.16, 1, 0.3, 1] as [number, number, number, number],
  inOut: [0.65, 0, 0.35, 1] as [number, number, number, number],
  spring: [0.34, 1.4, 0.64, 1] as [number, number, number, number],
};

/** Per-item delay of a staggered reveal (tokens.css --stagger). */
export const STAGGER_MS = 32;

/** prefersReducedMotion reads the OS setting; false outside a browser. */
export function prefersReducedMotion(): boolean {
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") {
    return false;
  }
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

/**
 * chartMotion returns the recharts series animation props every shared chart
 * spreads onto its <Area>/<Bar>/<Line>: a short ease-out (recharts' default
 * is a slow 1.5 s ease) that re-plays on data change, and off entirely under
 * reduced motion.
 */
export function chartMotion(): {
  isAnimationActive: boolean;
  animationDuration: number;
  animationEasing: "ease-out";
} {
  return {
    isAnimationActive: !prefersReducedMotion(),
    animationDuration: 450,
    animationEasing: "ease-out",
  };
}

type ChartRow = object;

function sameRow(a: ChartRow, b: ChartRow): boolean {
  if (a === b) return true;
  const ra = a as Record<string, unknown>;
  const rb = b as Record<string, unknown>;
  const ka = Object.keys(ra);
  if (ka.length !== Object.keys(rb).length) return false;
  for (const k of ka) {
    if (!Object.prototype.hasOwnProperty.call(rb, k) || !Object.is(ra[k], rb[k])) return false;
  }
  return true;
}

/**
 * chartUpdateAnimates decides whether a chart's series should re-play their
 * enter animation for a new `next` rows array (perf audit 2026-09-29). A
 * chart replays on data that is new to the reader: the first rows, a
 * different bucket range or count (a window change), a different series set,
 * or a change to any bucket but the newest (a filter change re-draws the
 * whole series). It does NOT replay for a live refresh that only moved the
 * newest bucket (the current day filling in) or changed nothing: that
 * snapped-to value is the honest update, and re-sweeping every series from
 * the baseline on each poll was both noise and a main-thread cost.
 * Rows are ordered oldest to newest by `xKey`. Pure; one test per rule.
 */
export function chartUpdateAnimates(
  prev: readonly ChartRow[] | null,
  next: readonly ChartRow[],
  xKey: string,
): boolean {
  if (prev == null) return true;
  if (prev === next) return false;
  if (prev.length !== next.length) return true;
  const n = next.length;
  for (let i = 0; i < n; i++) {
    const a = prev[i] as Record<string, unknown>;
    const b = next[i] as Record<string, unknown>;
    if (!Object.is(a[xKey], b[xKey])) return true;
  }
  if (n > 0) {
    const ka = Object.keys(prev[n - 1]).sort().join("\u0000");
    const kb = Object.keys(next[n - 1]).sort().join("\u0000");
    if (ka !== kb) return true;
  }
  for (let i = 0; i < n - 1; i++) {
    if (!sameRow(prev[i], next[i])) return true;
  }
  return false;
}

/**
 * MAX_ANIMATED_BARS caps how many bar rectangles a chart may animate (perf
 * re-measure 2026-09-30). recharts re-renders EVERY rectangle on every frame
 * of the enter animation and once more when it ends; a 7-day window at hourly
 * buckets stacks ~1,200 bars (169 buckets x 7 series), which measured ~100 ms
 * of main thread per frame (ten long tasks per load) - a sweep that stutters
 * at under 10 fps is not motion anyone sees, only a frozen page. Above the
 * cap the bars draw in place; at or under it (e.g. 31 daily buckets x 7
 * series = 217) they animate as before.
 */
export const MAX_ANIMATED_BARS = 400;

/**
 * barsAnimate is the cap rule: `bars` is buckets x stacked series. Undefined
 * (a chart that is not a bar chart) never hits the cap. Pure.
 */
export function barsAnimate(bars: number | undefined): boolean {
  return bars == null || bars <= MAX_ANIMATED_BARS;
}

/** easeOutCubic for JS tweens (close to --ease-out without the long tail). */
export function easeOutCubic(t: number): number {
  const x = Math.min(1, Math.max(0, t));
  return 1 - Math.pow(1 - x, 3);
}

/**
 * NumericParts is a formatted display string split around its first number,
 * e.g. "$6,073.08" -> { prefix: "$", value: 6073.08, decimals: 2,
 * grouped: true, suffix: "" }. Used to tween an already-formatted value
 * without the caller changing how it formats.
 */
export type NumericParts = {
  prefix: string;
  value: number;
  decimals: number;
  grouped: boolean;
  suffix: string;
};

const NUMERIC_RE = /^([^\d\-+]*?)([-+]?(?:\d{1,3}(?:,\d{3})+|\d+)(?:\.\d+)?)([^\d]*)$/;

/**
 * parseNumeric splits a display string into prefix / number / suffix. Returns
 * null when the string is not a single number with optional non-digit
 * affixes (so "3h 12m", "1.2 / 4.0", dates, and ids are never tweened).
 */
export function parseNumeric(text: string): NumericParts | null {
  const m = NUMERIC_RE.exec(text.trim());
  if (!m) return null;
  const [, rawPrefix, rawNum, suffix] = m;
  // An explicit "+" is display, not arithmetic: keep it in the prefix.
  const plus = rawNum.startsWith("+");
  const prefix = plus ? `${rawPrefix}+` : rawPrefix;
  const numStr = plus ? rawNum.slice(1) : rawNum;
  if (prefix.length > 4 || suffix.length > 6) return null;
  const grouped = numStr.includes(",");
  const plain = numStr.replace(/,/g, "");
  const value = Number(plain);
  if (!Number.isFinite(value)) return null;
  const dot = plain.indexOf(".");
  const decimals = dot >= 0 ? plain.length - dot - 1 : 0;
  return { prefix, value, decimals, grouped, suffix };
}

/** formatNumeric renders a tweened value back in the shape of `parts`. */
export function formatNumeric(parts: NumericParts, value: number): string {
  const fixed = Math.abs(value).toFixed(parts.decimals);
  let [int, frac] = fixed.split(".");
  if (parts.grouped) int = int.replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  const sign = value < 0 && Number(fixed) !== 0 ? "-" : "";
  return `${parts.prefix}${sign}${int}${frac !== undefined ? `.${frac}` : ""}${parts.suffix}`;
}

/**
 * sameShape reports whether two parsed values can tween into each other
 * (same affixes and precision), so "$12.00" -> "$14.50" animates but
 * "12 KB" -> "1.2 MB" snaps. Thousands grouping may differ ("$999" ->
 * "$1,000"); the tween renders in the TARGET's shape.
 */
export function sameShape(a: NumericParts, b: NumericParts): boolean {
  return a.prefix === b.prefix && a.suffix === b.suffix && a.decimals === b.decimals;
}

/**
 * slideFromX is the FLIP half of a layout change that must not be animated
 * itself (the nav rail's collapse switches the sidebar width in one frame):
 * given where `el`'s left edge was BEFORE the change, it plays a compositor-
 * only translateX from that spot to where the element now sits. A no-op under
 * reduced motion, for sub-pixel moves, or where Web Animations are missing.
 * Call it from a layout effect, after the DOM changed and before paint.
 */
export function slideFromX(el: HTMLElement, fromLeft: number): void {
  if (prefersReducedMotion() || typeof el.animate !== "function") return;
  const dx = fromLeft - el.getBoundingClientRect().left;
  if (Math.abs(dx) < 1) return;
  el.animate([{ transform: `translateX(${dx}px)` }, { transform: "translateX(0)" }], {
    duration: DUR.base,
    easing: `cubic-bezier(${EASE.out.join(",")})`,
  });
}

/** TweenPlan is what an animated number does when its target text changes. */
export type TweenPlan =
  | { kind: "snap"; flash: boolean }
  | { kind: "tween"; from: number; to: NumericParts; flash: boolean };

type TweenFacts = {
  shown: NumericParts | null;
  target: NumericParts | null;
  reduced: boolean;
};

// Ordered rules, first match wins: when a value must SNAP to its final text
// instead of tweening. Anything that falls through tweens from what is on
// screen now.
const SNAP_RULES: ReadonlyArray<(f: TweenFacts) => boolean> = [
  (f) => f.target == null, // not a single number: nothing to tween
  (f) => f.reduced, // reduced motion: the final value, immediately
  (f) => f.shown == null, // nothing numeric on screen to start from
  (f) => !sameShape(f.shown!, f.target!), // "12 KB" -> "1.2 MB" snaps
  (f) => f.shown!.value === f.target!.value, // already there
];

/**
 * planTween decides how an animated number reaches `targetText`. The tween
 * starts from what is SHOWN now (`shownText`), never from a remembered
 * previous target, so an interrupted tween (a newer value, or React
 * StrictMode re-running the effect) resumes from the screen instead of
 * snapping. `prevTarget` is the last target that was committed (null on
 * mount); a change of target flashes, a mount never does.
 */
export function planTween(
  shownText: string,
  prevTarget: string | null,
  targetText: string,
  reduced: boolean,
): TweenPlan {
  const flash = prevTarget != null && prevTarget !== targetText;
  const facts: TweenFacts = {
    shown: parseNumeric(shownText),
    target: parseNumeric(targetText),
    reduced,
  };
  if (SNAP_RULES.some((rule) => rule(facts))) return { kind: "snap", flash };
  return { kind: "tween", from: facts.shown!.value, to: facts.target!, flash };
}
