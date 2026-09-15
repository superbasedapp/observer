import { Pill } from "../../primitives";
import { fmtCompact } from "../../lib/format";
import type { CacheEventLike, CacheTimelineItemLike } from "../../lib/types";

// CacheTimelineList — the pure renderer of the session-detail Cache timeline:
// baseline roll-up rows ("N normal warm growth events") and per-anomaly rows
// with the cause vocabulary pills. Promoted into the shared design system so
// the node (from its node-local cache_events) and the org (from its bucketed
// aggregate) render the same timeline shape. The /cache fetch stays node-side.

export function CacheTimelineList({
  timeline,
}: {
  timeline: CacheTimelineItemLike[];
}) {
  return (
    <ol className="space-y-1.5 text-[11px]">
      {timeline.map((item, i) => (
        <li key={i}>
          {item.kind === "baseline" ? (
            <BaselineRow item={item} />
          ) : item.event ? (
            <AnomalyRow event={item.event} flagged={!!item.flagged} />
          ) : null}
        </li>
      ))}
    </ol>
  );
}

function BaselineRow({ item }: { item: CacheTimelineItemLike }) {
  return (
    <div className="rounded-3 border bg-bg-2 px-3 py-1.5 text-fg-3">
      <span className="font-semibold text-fg-2">
        {item.count ?? 0} normal warm growth events
      </span>
      {item.baseline_read_sum != null && item.baseline_write_sum != null && (
        <>
          {" · "}
          <span className="tabular-nums">
            R {fmtCompact(item.baseline_read_sum)} / W {fmtCompact(item.baseline_write_sum)}
          </span>
        </>
      )}
      {item.first_at && item.last_at && (
        <>
          {" · "}
          <span className="tabular-nums">
            {fmtTimeShort(item.first_at)} – {fmtTimeShort(item.last_at)}
          </span>
        </>
      )}
    </div>
  );
}

function AnomalyRow({
  event,
  flagged,
}: {
  event: CacheEventLike;
  flagged: boolean;
}) {
  return (
    <div className="rounded-3 border border-fg-3/30 bg-bg-2 px-3 py-1.5">
      <div className="flex flex-wrap items-center gap-2">
        <CacheKindPill kind={event.kind} cause={event.cause} flagged={flagged} />
        <span className="font-mono text-[10.5px] text-fg-3">
          {fmtTimeShort(event.timestamp)}
        </span>
        <span className="text-[11px] text-fg-2">{event.cause || "(no cause)"}</span>
        <span className="tabular-nums text-[10.5px] text-fg-3">
          R {fmtCompact(event.tokens_read)} / W {fmtCompact(event.tokens_written)}
        </span>
        {event.predicted_kind && event.predicted_kind !== event.kind && (
          <span className="text-[10.5px] text-fg-3">
            predicted: {event.predicted_kind}
          </span>
        )}
        {event.zero_usage && (
          <Pill variant="neutral">zero-usage · excluded from rate</Pill>
        )}
      </div>
    </div>
  );
}

function CacheKindPill({
  kind,
  cause,
  flagged,
}: {
  kind: string;
  cause: string;
  flagged: boolean;
}) {
  if (flagged) {
    return <Pill variant="neutral">{kind}</Pill>;
  }
  switch (kind) {
    case "hit":
      return <Pill variant="success">{kind}</Pill>;
    case "reanchor":
      return <Pill variant="info">{kind}</Pill>;
    case "mispredict":
      return <Pill variant="warn">{kind}</Pill>;
    case "invalidation_rewrite":
    case "expiry_rewrite":
    case "model_switch_rewrite":
    case "compaction_reset":
      return <Pill variant="warn">{kind}</Pill>;
    default:
      void cause;
      return <Pill variant="info">{kind}</Pill>;
  }
}

function fmtTimeShort(iso: string): string {
  // Render HH:MM:SS from an RFC3339 timestamp. The Cache timeline
  // is per-session — same date for every event — so the date prefix
  // is uninformative. Short form keeps the row compact.
  const t = iso.slice(11, 19);
  return t || iso;
}
