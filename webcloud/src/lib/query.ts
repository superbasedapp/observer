import { useCallback } from "react";
import { createQueryCache } from "@shared/lib/queryCache";
import {
  useQuery,
  useQueryActivity,
  type UseQueryOptions,
} from "@shared/lib/useQuery";

/**
 * portalCache is the cloud portal's single query cache
 * (shared/lib/queryCache). Every page reads through usePortalQuery, so:
 *   - two components asking for the same key share one request (Overview and
 *     Usage both read "usage" - one GET, not two);
 *   - navigating back to a page paints its last response at once and
 *     revalidates in the background (no "Loading..." flash);
 *   - a filter change (Overview window, Community metric/cohort) keeps the
 *     previous numbers on screen, dimmed, instead of unmounting the chart.
 */
export const portalCache = createQueryCache();

/** Foreground requests in flight: drives the shell's top progress bar. */
export function usePortalActivity(): number {
  return useQueryActivity(portalCache);
}

export type PortalQuery<T> = {
  data: T | null;
  /** Human message of the last failure (null while a retry runs). */
  error: string | null;
  /** Nothing to show yet: render the skeleton. */
  loading: boolean;
  /** The data on screen belongs to the previous key (a filter changed). */
  isStale: boolean;
  isRefreshing: boolean;
  reload: () => void;
};

export type PortalQueryOptions<T = unknown, S = T> = Pick<
  UseQueryOptions<T, S>,
  "refreshMs" | "keepPrevious" | "select"
>;

/**
 * usePortalQuery fetches `key` through `fetcher` via the shared cache. The
 * key must name every input of the request ("insights:30", "session:<id>").
 * `keepPrevious` defaults to FALSE here: most portal keys are entities (a
 * session id), where showing the previous one's data would be wrong; pass
 * true for filter-like keys. A null key disables the query.
 */
export function usePortalQuery<T, S = T>(
  key: string | null,
  fetcher: () => Promise<T>,
  deps: readonly unknown[] = [],
  opts: PortalQueryOptions<T, S> = {},
): PortalQuery<S> {
  // The portal API helpers take no AbortSignal; the cache still drops a
  // response nobody is subscribed to any more.
  const run = useCallback(() => fetcher(), [fetcher]);
  const q = useQuery<T, S>(portalCache, key, run, deps, {
    keepPrevious: opts.keepPrevious ?? false,
    refreshMs: opts.refreshMs,
    select: opts.select,
  });
  const raw = q.error;
  const error =
    raw != null && !(q.loading || q.isRefreshing)
      ? raw instanceof Error
        ? raw.message
        : typeof raw === "string"
          ? raw
          : "failed to load"
      : null;
  return {
    data: q.data,
    error,
    loading: q.loading,
    isStale: q.isStale,
    isRefreshing: q.isRefreshing,
    reload: q.reload,
  };
}

/** invalidatePortal refetches (or drops) a key after a mutation. */
export function invalidatePortal(key: string): void {
  portalCache.invalidate(key);
}
