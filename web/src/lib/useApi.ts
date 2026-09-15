import { useEffect, useRef, useState } from "react";
import { fetchJSON, type QueryParams } from "./api";

// Window-level CustomEvent emitted by the TopBar's Refresh button.
// Every useApi instance listens and bumps its tick — gives the
// operator a single "reload everything" affordance without
// per-hook plumbing.
const REFRESH_EVENT = "dashboard-refresh";

export type ApiState<T> = {
  data: T | null;
  loading: boolean;
  error: Error | null;
  reload: () => void;
};

// UseApiOptions configures optional refetch behaviour. Both fields
// default to "no auto refresh" — callers explicitly opt in for pages
// where the underlying data evolves while the user watches (live
// Antigravity-CLI capture, Session Detail mid-conversation).
export type UseApiOptions = {
  // Keep a failed read visible until a later read succeeds. Consent-sensitive
  // controls must not re-enable merely because a refresh has started.
  retainErrorOnRefresh?: boolean;
  // refreshMs polls the endpoint every N milliseconds. <=0 disables
  // (default). Pauses while the document is hidden unless
  // refreshWhenHidden is set — saves the proxy / dashboard server
  // from doing pointless work for a backgrounded tab.
  refreshMs?: number;
  // refreshWhenHidden keeps the timer running while the tab is in
  // the background. Default false; the visible-only behaviour is the
  // right call for browser UI, but the option exists for headless
  // smoke tests.
  refreshWhenHidden?: boolean;
};

// useApi fetches `path` with `params` on mount and whenever `deps`
// changes. Pages typically pass [win, tool, project] from useFilters
// so a filter change re-fires every query.
//
// Aborts in-flight requests on unmount + on rapid filter changes so
// stale responses can't clobber fresh ones. No caching — the dashboard
// is point-in-time enough that re-fetching on filter change is the
// right call.
//
// When opts.refreshMs > 0, the hook also self-polls on that interval
// so pages observing live capture (Sessions, Session Detail, status
// surfaces) pick up new rows without operator interaction.
export function useApi<T>(
  path: string | null,
  params?: QueryParams,
  deps: unknown[] = [],
  opts?: UseApiOptions,
): ApiState<T> {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(path != null);
  const [error, setError] = useState<Error | null>(null);
  const [tick, setTick] = useState(0);
  const abortRef = useRef<AbortController | null>(null);

  useEffect(() => {
    function onRefresh() {
      setTick((t) => t + 1);
    }
    window.addEventListener(REFRESH_EVENT, onRefresh);
    return () => window.removeEventListener(REFRESH_EVENT, onRefresh);
  }, []);

  // Auto-refetch loop. Off by default; opts.refreshMs > 0 turns it
  // on. The timer fires setTick which re-runs the fetch effect via
  // the [tick, ...deps] dependency list below. Tab-visibility gating
  // is applied at fire-time rather than via visibilitychange listeners
  // so the user-facing surface is one tick latency, not zero.
  const refreshMs = opts?.refreshMs ?? 0;
  const refreshWhenHidden = opts?.refreshWhenHidden ?? false;
  const retainErrorOnRefresh = opts?.retainErrorOnRefresh ?? false;
  useEffect(() => {
    if (refreshMs <= 0 || path == null) return;
    const id = window.setInterval(() => {
      if (!refreshWhenHidden && typeof document !== "undefined" && document.visibilityState === "hidden") {
        return;
      }
      setTick((t) => t + 1);
    }, refreshMs);
    return () => window.clearInterval(id);
  }, [refreshMs, refreshWhenHidden, path]);

  // hasDataRef tracks whether we've ever populated data for the
  // CURRENT path, so background refetches (auto-refresh ticks,
  // REFRESH_EVENT bumps) don't toggle loading=true and cause
  // skeleton/spinner flicker on top of valid already-rendered
  // content. Resets when path changes (different resource → user
  // expects a brief loading state on the new one).
  const hasDataRef = useRef(false);
  useEffect(() => {
    hasDataRef.current = false;
  }, [path]);
  useEffect(() => {
    if (!path) {
      setLoading(false);
      return;
    }
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    if (!hasDataRef.current) {
      setLoading(true);
    }
    if (!retainErrorOnRefresh) setError(null);
    fetchJSON<T>(path, params, { signal: ac.signal })
      .then((v) => {
        if (ac.signal.aborted) return;
        setError(null);
        // Skip setData when the response is byte-identical to what
        // we already have. Auto-refresh tickers fire every N seconds
        // even on idle sessions; without this guard, every tick
        // creates a new object reference and forces React to
        // reconcile every descendant — visible as flicker even when
        // nothing actually changed. JSON.stringify is reliable for
        // structured API payloads (no circular refs, key order is
        // stable for plain objects) and cheap enough at the scale
        // of a single API response.
        setData((prev) => {
          if (prev !== null) {
            try {
              if (JSON.stringify(prev) === JSON.stringify(v)) {
                return prev;
              }
            } catch {
              // Fall through to replace on any stringify failure.
            }
          }
          return v;
        });
        hasDataRef.current = true;
      })
      .catch((err: unknown) => {
        if (ac.signal.aborted) return;
        const e = err instanceof Error ? err : new Error(String(err));
        if (e.name === "AbortError") return;
        setError(e);
      })
      .finally(() => {
        if (!ac.signal.aborted) setLoading(false);
      });
    return () => ac.abort();
    // path is in the dep list so callers can omit it from deps when
    // it's a literal string. params is serialized by callers into deps
    // (e.g. [win, tool] over passing the whole params object) because
    // a stable identity isn't guaranteed.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [path, tick, retainErrorOnRefresh, ...deps]);

  return { data, loading, error, reload: () => setTick((t) => t + 1) };
}
