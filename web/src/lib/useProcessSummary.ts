import { useCallback, useEffect, useRef, useState } from "react";
import { summaryOutcome, type SummaryOutcome } from "./processCapture.ts";
import type { ProcessSummaryResponse } from "./types.ts";

// useProcessSummary reads GET /api/session/<id>/processes/summary (process
// capture budget plan 9.3), the small document the System tab shows first and
// polls instead of the tree. It keeps the response's ETag and sends it back as
// If-None-Match, so a poll of an unchanged session is a 304 with no body.
//
// A daemon without the endpoint answers 404: `unavailable` is then true, the
// poll stops, and the panel keeps its earlier behaviour (the tree alone).
//
// It uses fetch directly rather than fetchJSON/useApi because it must read the
// ETag response header and treat 304 as "unchanged", neither of which the
// shared client exposes. The route is a GET, so it needs no CSRF.

export type SummaryState = {
  data: ProcessSummaryResponse | null;
  /** etag of the response on screen; changes when the session's capture changes. */
  etag: string | null;
  unavailable: boolean;
  error: Error | null;
  loading: boolean;
};

const EMPTY: SummaryState = { data: null, etag: null, unavailable: false, error: null, loading: false };

async function fetchSummary(sessionId: string, etag: string | null, signal: AbortSignal): Promise<SummaryOutcome> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (etag) headers["If-None-Match"] = etag;
  const res = await fetch(`/api/session/${encodeURIComponent(sessionId)}/processes/summary`, { headers, signal });
  const body = res.status === 200 ? await res.json().catch(() => null) : null;
  return summaryOutcome(res.status, res.headers.get("ETag"), body);
}

/**
 * useProcessSummary loads the summary when `enabled` and re-reads it every
 * `pollMs` (0 = once). Polling pauses while the tab is hidden.
 */
export function useProcessSummary(sessionId: string | null, enabled: boolean, pollMs: number): SummaryState {
  const [state, setState] = useState<SummaryState>(EMPTY);
  const etagRef = useRef<string | null>(null);

  const run = useCallback(
    async (signal: AbortSignal) => {
      if (!sessionId) return;
      try {
        const out = await fetchSummary(sessionId, etagRef.current, signal);
        if (signal.aborted) return;
        switch (out.kind) {
          case "ok":
            etagRef.current = out.etag;
            setState({ data: out.data, etag: out.etag, unavailable: false, error: null, loading: false });
            break;
          case "not_modified":
            setState((s) => (s.loading || s.error ? { ...s, loading: false, error: null } : s));
            break;
          case "unavailable":
            etagRef.current = null;
            setState({ ...EMPTY, unavailable: true });
            break;
          case "error":
            setState((s) => ({ ...s, loading: false, error: new Error(`api ${out.status} /processes/summary`) }));
            break;
        }
      } catch (e) {
        if (signal.aborted) return;
        setState((s) => ({ ...s, loading: false, error: e instanceof Error ? e : new Error(String(e)) }));
      }
    },
    [sessionId],
  );

  useEffect(() => {
    etagRef.current = null;
    if (!enabled || !sessionId) {
      setState(EMPTY);
      return;
    }
    const ac = new AbortController();
    setState({ ...EMPTY, loading: true });
    void run(ac.signal);
    return () => ac.abort();
  }, [sessionId, enabled, run]);

  const stopped = state.unavailable;
  useEffect(() => {
    if (!enabled || !sessionId || pollMs <= 0 || stopped) return;
    const ac = new AbortController();
    const t = setInterval(() => {
      if (typeof document !== "undefined" && document.hidden) return;
      void run(ac.signal);
    }, pollMs);
    return () => {
      clearInterval(t);
      ac.abort();
    };
  }, [enabled, sessionId, pollMs, stopped, run]);

  return state;
}
