import { useRef } from "react";
import { barsAnimate, chartMotion, chartUpdateAnimates } from "../lib/motion";

/**
 * useChartMotion is chartMotion() for a chart whose `rows` can refresh while
 * it is on screen: the series animate on the first data, on a real reshape
 * (window, filter, series set, or a `variant` change such as a mode toggle)
 * and never for a live refresh that only moved the newest bucket (the
 * decision table is shared/lib/motion.ts chartUpdateAnimates). Reduced motion
 * still turns animation off everywhere. A bar chart passes `seriesCount` (the
 * number of stacked/grouped <Bar>s) so a dense grid (rows x series over
 * MAX_ANIMATED_BARS) draws in place instead of re-rendering every bar per
 * frame (shared/lib/motion.ts barsAnimate).
 */
export function useChartMotion(
  rows: readonly object[],
  xKey: string,
  variant: string = "",
  seriesCount?: number,
): ReturnType<typeof chartMotion> {
  const last = useRef<{ rows: readonly object[]; variant: string; animate: boolean } | null>(null);
  const cur = last.current;
  if (cur === null || cur.rows !== rows || cur.variant !== variant) {
    const animate =
      cur === null || cur.variant !== variant
        ? true
        : chartUpdateAnimates(cur.rows, rows, xKey);
    last.current = { rows, variant, animate };
  }
  const base = chartMotion();
  const bars = seriesCount == null ? undefined : rows.length * seriesCount;
  return {
    ...base,
    isAnimationActive: base.isAnimationActive && last.current!.animate && barsAnimate(bars),
  };
}
