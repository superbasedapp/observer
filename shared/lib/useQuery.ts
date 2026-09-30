import { useCallback, useEffect, useMemo, useReducer, useRef, useState } from "react";
import {
  keyBoundFetcher,
  replaceEqualDeep,
  selectionChanged,
  type Fetcher,
  type QueryCache,
} from "./queryCache";

// React binding for the shared query cache (shared/lib/queryCache.ts).
//
// Each app wraps this in its own hook (web/src/lib/useApi.ts,
// web2/src/lib/useApi.ts, webcloud's usePortalQuery) so call sites keep their
// existing shape; this file owns the semantics every app shares:
//
//   loading      - nothing to show yet for this key (render a skeleton);
//   isStale      - the data on screen belongs to the PREVIOUS key (a filter
//                  changed) and the new response is in flight - dim it;
//   isRefreshing - the data on screen is being revalidated (show a small
//                  "updating" dot, never a skeleton);
//   updatedAt    - when the data on screen was fetched.
//
// `select` narrows what a reader depends on: pass it when a page or a large
// component needs a small slice of a payload that changes on every poll
// (e.g. /api/status stamps uptime per request). The reader then re-renders
// only when its selected slice changes BY VALUE, and the slice keeps its
// identity across equal polls.

export type UseQueryOptions<T = unknown, S = T> = {
  /** Poll every N ms while mounted (shared across components per key). */
  refreshMs?: number;
  refreshWhenHidden?: boolean;
  /**
   * Keep showing the previous key's data (flagged isStale) while the new
   * key's first response is in flight. Default true: a filter change dims
   * the old numbers instead of blanking the page. Pass a predicate to decide
   * per transition (e.g. only when the path is unchanged).
   */
  keepPrevious?: boolean | ((prevKey: string, nextKey: string) => boolean);
  /** A cached response younger than this is not refetched on mount. */
  dedupMs?: number;
  /** A mount revalidation of data older than this counts as foreground. */
  foregroundAfterMs?: number;
  /**
   * Derive the slice this reader renders. With `select`, `data` is the
   * selected value (identity kept while it is deep-equal), and a cache
   * change re-renders the reader only when the slice, the error, or
   * whether there is data changes. Polls that change other fields of the
   * payload, and the fetching flag of a poll, do not re-render it; so with
   * `select`, `isRefreshing` and `updatedAt` reflect the last render and are
   * not re-render triggers (except that `fetching` still is while an error
   * is on screen, so a caller hiding the error during a retry stays right).
   * The function may be an inline closure; it runs on every render.
   */
  select?: (data: T) => S;
};

export type QueryResult<T> = {
  data: T | null;
  error: unknown;
  loading: boolean;
  isStale: boolean;
  isRefreshing: boolean;
  updatedAt: number;
  /** Force a refetch (foreground). */
  reload: () => void;
};

const DEFAULT_DEDUP_MS = 1500;
const DEFAULT_FOREGROUND_AFTER_MS = 15_000;

/**
 * useQuery reads `key` from `cache`, fetching through `fetcher` on mount, on
 * key change, and whenever an entry of `deps` changes (a forced refetch - the
 * old useApi contract). `key === null` disables the query.
 */
export function useQuery<T, S = T>(
  cache: QueryCache,
  key: string | null,
  fetcher: Fetcher<T>,
  deps: readonly unknown[] = [],
  opts: UseQueryOptions<T, S> = {},
): QueryResult<S> {
  // The hook's current key + fetcher, mutated in place every render so the
  // key-bound fetchers below always see the latest values.
  const live = useRef<{ key: string | null; fetcher: Fetcher<T> }>({ key, fetcher }).current;
  live.key = key;
  live.fetcher = fetcher;

  const refreshMs = opts.refreshMs ?? 0;
  const refreshWhenHidden = opts.refreshWhenHidden ?? false;
  const dedupMs = opts.dedupMs ?? DEFAULT_DEDUP_MS;
  const foregroundAfterMs = opts.foregroundAfterMs ?? DEFAULT_FOREGROUND_AFTER_MS;

  // Subscribe with plain component state rather than useSyncExternalStore:
  // uSES updates run in React's synchronous lane, so every fetch start and
  // response forced an immediate, unbatched re-render of each reader (the
  // node Overview's first data landed ~1.3 s later under 4x CPU throttling).
  // A state bump is batched and interruptible, the same scheduling the old
  // per-component hook had. The snapshot is read from the cache on render.
  const [, bump] = useReducer((n: number) => n + 1, 0);
  const snap = cache.getSnapshot(key ?? "\u0000none");
  const renderedSnapRef = useRef(snap);
  renderedSnapRef.current = snap;
  const selectRef = useRef(opts.select);
  selectRef.current = opts.select;
  // The selected slice on screen (see `select`), kept for identity.
  const selectedRef = useRef<{ has: boolean; value: unknown }>({ has: false, value: undefined });
  useEffect(() => {
    if (key == null) return;
    // Without `select` every snapshot change re-renders the reader (it may
    // read any field). With it, only a change the reader can see does.
    const onChange = () => {
      const select = selectRef.current;
      if (!select) {
        bump();
        return;
      }
      if (selectionChanged(renderedSnapRef.current, cache.getSnapshot(key), select, selectedRef.current)) {
        bump();
      }
    };
    const unsubscribe = cache.subscribe(key, onChange, { refreshMs, refreshWhenHidden });
    // A change between render and subscribe (another reader's response)
    // would otherwise be missed until the next unrelated render.
    if (cache.getSnapshot(key) !== renderedSnapRef.current) onChange();
    return unsubscribe;
  }, [cache, key, refreshMs, refreshWhenHidden]);

  // One fetcher per key, bound to it: the cache entry for a key this hook
  // has left must keep requesting THAT key (see keyBoundFetcher).
  const run = useMemo(
    () => keyBoundFetcher(key ?? "", fetcher, live),
    // Rebind only when the key changes; same-key fetcher updates arrive
    // through `live`.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [key],
  );

  // Fetch on mount / key change (SWR: skip when fresh) and force on a deps
  // change with the same key.
  const prevKeyRef = useRef<string | null | undefined>(undefined);
  useEffect(() => {
    if (key == null) {
      prevKeyRef.current = key;
      return;
    }
    const keyChanged = prevKeyRef.current !== key;
    prevKeyRef.current = key;
    const cur = cache.getSnapshot(key);
    if (keyChanged) {
      const age = cur.hasData ? Date.now() - cur.updatedAt : Infinity;
      void cache.fetch(key, run, {
        maxAgeMs: dedupMs,
        foreground: !cur.hasData || age > foregroundAfterMs,
      });
    } else {
      void cache.fetch(key, run, { force: true, foreground: true });
    }
    // deps are the caller's explicit refetch triggers.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [cache, key, run, dedupMs, foregroundAfterMs, ...deps]);

  // Keep-previous: remember the last data actually shown and which key it
  // belonged to.
  const shownRef = useRef<{ key: string; data: unknown } | null>(null);
  if (key != null && snap.hasData) {
    if (shownRef.current?.key !== key || shownRef.current.data !== snap.data) {
      shownRef.current = { key, data: snap.data };
    }
  }
  const prev = shownRef.current;
  const keep =
    key != null &&
    !snap.hasData &&
    prev != null &&
    prev.key !== key &&
    (typeof opts.keepPrevious === "function"
      ? opts.keepPrevious(prev.key, key)
      : opts.keepPrevious ?? true);

  const reload = useCallback(() => {
    if (key != null) void cache.fetch(key, run, { force: true, foreground: true });
  }, [cache, key, run]);

  const raw = snap.hasData ? (snap.data as T) : keep ? (prev!.data as T) : null;
  let data: S | null = raw as unknown as S | null;
  if (opts.select) {
    if (raw == null) {
      data = null;
    } else {
      const next = opts.select(raw);
      const cur = selectedRef.current;
      data = cur.has ? replaceEqualDeep(cur.value, next) : next;
      selectedRef.current = { has: true, value: data };
    }
  }
  const isStale = keep;
  const loading = key != null && !snap.hasData && !keep && (snap.fetching || snap.error == null);
  return {
    data,
    error: snap.error ?? null,
    loading,
    isStale,
    isRefreshing: snap.fetching && (snap.hasData || keep),
    updatedAt: snap.hasData ? snap.updatedAt : 0,
    reload,
  };
}

/**
 * useQueryActivity is the number of foreground requests in flight. It
 * re-renders only when that crosses zero; keep its reader a small leaf
 * component (the progress bar), never an app root.
 */
export function useQueryActivity(cache: QueryCache): number {
  const [active, setActive] = useState(() => cache.getActivity());
  useEffect(() => {
    const sync = () => setActive(cache.getActivity());
    sync();
    return cache.subscribeActivity(sync);
  }, [cache]);
  return active;
}
