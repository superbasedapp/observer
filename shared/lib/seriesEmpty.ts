// seriesEmpty: the ONE "does this time series have anything to draw"
// predicate. A time-series endpoint that buckets by granularity zero-fills
// its grid (internal/timebucket; docs/plans/chart-time-granularity-plan-
// 2026-09-29.md), so an empty window arrives as N all-zero points, never as
// []. A chart that tests `!data.length` therefore never shows its empty
// state; it must ask whether ANY point carries a non-zero value in the
// fields it draws. Pure (no React) so a test can load it.

/**
 * hasNonZero reports whether any point has a finite, non-zero number in any
 * of `keys`. A missing, null, NaN or zero value counts as nothing. With no
 * keys it is always false: the caller names the fields its chart draws.
 */
export function hasNonZero<T>(
  points: readonly T[] | null | undefined,
  keys: readonly (keyof T)[],
): boolean {
  if (!points || points.length === 0 || keys.length === 0) return false;
  for (const p of points) {
    for (const k of keys) {
      const v = (p as Record<keyof T, unknown>)[k];
      if (typeof v === "number" && Number.isFinite(v) && v !== 0) return true;
    }
  }
  return false;
}
