import { useState } from "react";
import {
  CacheKpiStrip,
  CacheTierBadge,
  CacheTimelineList,
} from "@shared/components/sessiondetail";
import { ChartState } from "@/components/ChartState";
import { CacheExpiryCard } from "@/components/CacheExpiryCard";
import { useApi } from "@/lib/useApi";
import type {
  SessionCacheAnnotation,
  SessionCacheResponse,
  SessionDetail,
} from "@/lib/types";

// Cache tab — "is this session's prompt cache working, and is it about to go
// cold?". CacheExpiryCard + CachePanel. The pure renderers (CacheTierBadge,
// CacheKpiStrip, CacheTimelineList) were promoted into the shared design
// system; the live-windows card (CacheExpiryCard) and the /cache timeline
// fetch stay node-side.
//
// HONEST EMPTY STATE. Both blocks can render nothing: CacheExpiryCard returns
// null when /api/cache/status reports no live windows for this session, and
// CachePanel is gated on d.cache_summary (absent when the cache-tracking
// engine never graded a turn for this session). Rather than leave a blank
// tab, the tab names the exact missing dependency — the same rule the
// disabled Jump in / Resume controls follow.
export function CacheTab({ d }: { d: SessionDetail }) {
  return (
    <div className="space-y-5">
      <CacheExpiryCard sessionId={d.id} />
      {d.cache_summary ? (
        <CachePanel sessionId={d.id} summary={d.cache_summary} />
      ) : (
        <p className="rounded-3 border border-dashed border-line-2 px-4 py-3 text-[11.5px] text-fg-3">
          No cache statistics for this session - the cache-tracking engine
          graded no turns here (<span className="font-mono">cache_summary</span>{" "}
          is absent from{" "}
          <span className="font-mono">/api/session/{d.id}</span>). That happens
          when <span className="font-mono">[cachetrack]</span> is disabled, or
          when the session predates it, or when the provider returns no cache
          token counts. Nothing is hidden here.
        </p>
      )}
      <p className="text-[10.5px] text-fg-4">
        Cache expiry lists only caches that are still live (or recently cold);
        a finished session usually shows none.
      </p>
    </div>
  );
}

// ----- Cache panel (C16) ------------------------------------------
//
// CachePanel renders the SessionDetailPanel Cache tab content. Two layers:
//
//   - the "summary" rail (always rendered): tier badge + KPI strip. Loads
//     from detail.cache_summary (already in the SessionDetail payload, C15).
//     The tier badge (CacheTierBadge) and the KPI grid (CacheKpiStrip) are the
//     shared renderers.
//
//   - the "timeline" (lazy-loaded on first expand): baseline roll-up rows +
//     anomaly items (CacheTimelineList, shared). Loads /api/session/<id>/cache
//     only when the operator clicks "Show timeline" so a closed-by-default
//     SessionDetailPanel makes only one round-trip on open.
function CachePanel({
  sessionId,
  summary,
}: {
  sessionId: string;
  summary: SessionCacheAnnotation;
}) {
  const [showTimeline, setShowTimeline] = useState(false);
  const timeline = useApi<SessionCacheResponse>(
    showTimeline ? `/api/session/${sessionId}/cache` : null,
    undefined,
    [sessionId, showTimeline],
  );

  return (
    <section className="mt-5 space-y-2">
      <h3 className="flex items-center justify-between gap-2">
        <span className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-3">
          Cache
          <CacheTierBadge tier={summary.tier} />
        </span>
        <button
          type="button"
          onClick={() => setShowTimeline((v) => !v)}
          className="text-[10.5px] text-accent hover:underline focus:outline-none"
        >
          {showTimeline ? "Hide timeline" : "Show timeline"}
        </button>
      </h3>

      <CacheKpiStrip summary={summary} />

      {showTimeline && (
        <ChartState
          loading={timeline.loading}
          error={timeline.error}
          empty={!timeline.data?.timeline?.length}
          emptyHint="No cache events recorded for this session."
          height={120}
        >
          {timeline.data && <CacheTimelineList timeline={timeline.data.timeline} />}
        </ChartState>
      )}
    </section>
  );
}
