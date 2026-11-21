import { useEffect, useRef, useState } from "react";
import { fetchJSON, localConfirmHeaders } from "@/lib/api";
import {
  mergeTail,
  nextPollDelay,
  type PlaneASavedView,
  type PlaneATailPage,
  type PlaneATailRow,
  type PlaneAViewDraft,
} from "@shared/components/planea/explorerViewsModel";
import type { PlaneATailState } from "@shared/components/planea/liveTail";

// The machine's saved explorer views and live tail (Plane A W5-4, lane C9;
// contracts/alerts.md "Saved views, live tail and PagerDuty"):
// /api/obs/explorer/views (the writes are owner-local, the confirm token) and
// the live tail over server-sent events from /api/obs/explorer/tail/stream,
// falling back to polling /api/obs/explorer/tail when the browser has no
// EventSource or the stream is refused.

const VIEWS = "/api/obs/explorer/views";

export async function listMachineViews(): Promise<PlaneASavedView[]> {
  const r = await fetchJSON<{ views: PlaneASavedView[] }>(VIEWS);
  return r.views ?? [];
}

async function write<T>(method: "POST" | "PUT" | "DELETE", path: string, body?: unknown): Promise<T> {
  return fetchJSON<T>(path, undefined, {
    method,
    headers: { "content-type": "application/json", ...(await localConfirmHeaders()) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

export function saveMachineView(d: PlaneAViewDraft): Promise<PlaneASavedView> {
  return write<PlaneASavedView>("POST", VIEWS, { ...d, scope: "private" });
}

export async function deleteMachineView(id: string): Promise<void> {
  await write<unknown>("DELETE", `${VIEWS}/${encodeURIComponent(id)}`);
}

function tailQuery(filters: Record<string, string>, cursor: string, client = ""): string {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(filters)) if (v) q.set(k, v);
  if (cursor) q.set("cursor", cursor);
  // The daemon rate-limits each viewer; every tab reaches it from 127.0.0.1,
  // so the tab names itself (review finding R-C39).
  if (client) q.set("client", client);
  return q.toString();
}

/** tailClientId is a per-tab id for the tail's per-viewer limit. */
function tailClientId(): string {
  return `t${Math.random().toString(36).slice(2, 12)}`;
}

/** useMachineTail runs the live tail while enabled and not paused; filters
 *  are the explorer's query parameters. Changing them restarts it. */
export function useMachineTail(filters: Record<string, string>, enabled: boolean) {
  const [rows, setRows] = useState<PlaneATailRow[]>([]);
  const [state, setState] = useState<PlaneATailState>("stopped");
  const [paused, setPaused] = useState(false);
  const cursor = useRef("");
  const client = useRef(tailClientId());
  const key = JSON.stringify(filters);

  useEffect(() => {
    setRows([]);
    cursor.current = "";
  }, [key]);

  useEffect(() => {
    if (!enabled || paused) {
      setState(enabled ? "paused" : "stopped");
      return;
    }
    let stop = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let source: EventSource | undefined;
    const apply = (page: PlaneATailPage) => {
      cursor.current = page.cursor;
      setRows((buf) => mergeTail(buf, page.traces ?? [], page.buffer_limit || 200));
    };
    const poll = async () => {
      if (stop) return;
      try {
        const page = await fetchJSON<PlaneATailPage>(`/api/obs/explorer/tail?${tailQuery(filters, cursor.current, client.current)}`);
        apply(page);
        setState("live");
        timer = setTimeout(poll, nextPollDelay(page));
      } catch (e) {
        setState("reconnecting");
        const retry = (e as { status?: number }).status === 429 ? 3 : 5;
        timer = setTimeout(poll, nextPollDelay(null, retry));
      }
    };
    if (typeof window !== "undefined" && typeof window.EventSource !== "undefined") {
      try {
        source = new window.EventSource(`/api/obs/explorer/tail/stream?${tailQuery(filters, cursor.current)}`);
        source.onopen = () => setState("live");
        source.addEventListener("traces", (ev) => {
          try {
            apply(JSON.parse((ev as MessageEvent<string>).data) as PlaneATailPage);
          } catch {
            // A malformed frame is skipped; the next one carries the cursor.
          }
        });
        source.onerror = () => {
          // The browser reconnects with Last-Event-ID; a refused stream
          // (too many open) falls back to polling.
          if (source && source.readyState === EventSource.CLOSED) {
            source = undefined;
            void poll();
          } else {
            setState("reconnecting");
          }
        };
      } catch {
        void poll();
      }
    } else {
      void poll();
    }
    return () => {
      stop = true;
      if (timer) clearTimeout(timer);
      source?.close();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, enabled, paused]);

  return {
    rows,
    state,
    togglePause: () => setPaused((p) => !p),
    clear: () => setRows([]),
  };
}
