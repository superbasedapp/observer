import { useCallback } from "react";
import { createQueryCache } from "@shared/lib/queryCache";
import { useQuery, useQueryActivity } from "@shared/lib/useQuery";
import { buildUrl, fetchJSON, type QueryParams } from "./api";
import { describeApiFailure } from "./apiFailure";

// Window-level CustomEvent emitted by the TopBar's Refresh button (and a few
// settings flows). One module-level listener refetches every key that has a
// mounted subscriber - one request per key, not one per component.
const REFRESH_EVENT = "dashboard-refresh";

/**
 * apiCache is the node dashboard's single query cache (shared/lib/queryCache).
 * Every useApi call reads through it, so N components polling the same
 * endpoint share one request and one timer (the old per-component hook sent
 * 3-4 identical /api/status requests per 5 s tick), and a page you navigate
 * back to paints its last response immediately while it revalidates.
 */
export const apiCache = createQueryCache();

if (typeof window !== "undefined") {
  window.addEventListener(REFRESH_EVENT, () => apiCache.refetchActive());
}

/** Number of foreground requests in flight (drives the TopBar progress bar). */
export function useApiActivity(): number {
  return useQueryActivity(apiCache);
}

export type ApiState<T> = {
  data: T | null;
  loading: boolean;
  error: Error | null;
  reload: () => void;
  /**
   * The data on screen belongs to the previous filter / page (same endpoint)
   * and the new response is in flight. Dim it (staleClass / the `stale`
   * prop on StatCard, ChartShell, Card) instead of pretending it is current.
   */
  isStale: boolean;
  /** The data on screen is being revalidated in the background. */
  isRefreshing: boolean;
  /** Epoch ms of the response on screen (0 = none yet). */
  updatedAt: number;
  /**
   * True when `error` is a denial (HTTP 403): pass it to ChartState's
   * `denied` so the panel renders the shared permission-denied state, never
   * the failed-to-load card. False while there is no error. `error` stays
   * set alongside it, so a caller that does not read `denied` renders
   * exactly as before. Classified by lib/apiFailure.ts.
   */
  denied: boolean;
  /** HTTP status of the failure on screen, or null (none, or no response). */
  status: number | null;
  /** The permission key the server's 403 named, when it named one. */
  deniedPermission: string | null;
};

// UseApiOptions configures optional refetch behaviour. Both fields
// default to "no auto refresh" — callers explicitly opt in for pages
// where the underlying data evolves while the user watches (live
// Antigravity-CLI capture, Session Detail mid-conversation).
export type UseApiOptions<T = unknown, S = T> = {
  // Keep a failed read visible until a later read succeeds. Consent-sensitive
  // controls must not re-enable merely because a refresh has started.
  retainErrorOnRefresh?: boolean;
  // refreshMs polls the endpoint every N milliseconds. <=0 disables
  // (default). Pauses while the document is hidden unless
  // refreshWhenHidden is set. Pollers of the same endpoint share one timer
  // at the fastest requested interval.
  refreshMs?: number;
  // refreshWhenHidden keeps the timer running while the tab is in
  // the background. Default false; the visible-only behaviour is the
  // right call for browser UI, but the option exists for headless
  // smoke tests.
  refreshWhenHidden?: boolean;
  // select narrows the reader to a slice of the payload: `data` becomes the
  // selected value, and the reader re-renders only when that slice changes
  // by value (shared/lib/useQuery.ts). Use it wherever a page or a large
  // component reads a few fields of a payload that changes on every poll
  // (/api/status stamps uptime per request), so the poll does not re-render
  // the whole page. With select, isRefreshing / updatedAt are not re-render
  // triggers.
  select?: (data: T) => S;
};

function pathOf(key: string): string {
  const q = key.indexOf("?");
  return q < 0 ? key : key.slice(0, q);
}

// Keep the previous response on screen (flagged isStale) only while the
// SAME endpoint is re-queried with different params - a filter change. A
// different path is a different resource (another session id): show its
// skeleton rather than the previous entity's data.
function samePath(prevKey: string, nextKey: string): boolean {
  return pathOf(prevKey) === pathOf(nextKey);
}

// useApi fetches `path` with `params` on mount and whenever the resulting
// URL or an entry of `deps` changes. Pages typically pass [win, tool,
// project] from useFilters so a filter change re-fires every query.
//
// Reads go through the shared query cache: concurrent requests for the same
// URL are deduplicated, polling is shared per URL, a remount paints the
// cached response at once (stale-while-revalidate), and in-flight requests
// are aborted when their last reader unmounts. The returned `loading` is
// true only when there is nothing to show; a filter change keeps the old
// data with isStale=true so the page can dim it.
export function useApi<T, S = T>(
  path: string | null,
  params?: QueryParams,
  deps: unknown[] = [],
  opts?: UseApiOptions<T, S>,
): ApiState<S> {
  const key = path == null ? null : buildUrl(path, params);
  const fetcher = useCallback(
    (signal: AbortSignal) => fetchJSON<T>(path as string, params, { signal }),
    // The fetcher is read through a ref inside useQuery; identity is moot.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [key],
  );
  const q = useQuery<T, S>(apiCache, key, fetcher, deps, {
    refreshMs: opts?.refreshMs,
    refreshWhenHidden: opts?.refreshWhenHidden,
    keepPrevious: samePath,
    select: opts?.select,
  });
  const retain = opts?.retainErrorOnRefresh ?? false;
  const raw = q.error;
  const err =
    raw == null ? null : raw instanceof Error ? raw : new Error(String(raw));
  // Without retainErrorOnRefresh a refetch hides the old error while it runs
  // (the previous hook cleared it at request start).
  const error = retain || !(q.isRefreshing || q.loading) ? err : null;
  // The denial reading follows the error's visibility: no error on screen,
  // no denial either.
  const failure = error == null ? null : describeApiFailure(raw);
  return {
    data: q.data,
    loading: q.loading,
    error,
    denied: failure?.denied ?? false,
    status: failure?.status ?? null,
    deniedPermission: failure?.permission ?? null,
    reload: q.reload,
    isStale: q.isStale,
    isRefreshing: q.isRefreshing,
    updatedAt: q.updatedAt,
  };
}
