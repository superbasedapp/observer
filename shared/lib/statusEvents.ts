// statusEvents: the Messages-table marker for STATUS readings (a rate_limit
// snapshot) that the server folds onto the message they follow instead of
// rendering them as rows of their own (internal/sessionmsg/status.go,
// sessionmsg.StatusWire - the same projection on the node and the org).
// Only CHANGED readings travel as status_events; status_event_count counts
// every reading folded onto the row. A row with no changed reading shows no
// marker at all - that is what removed the "Rate limit" row between every
// Codex turn.
//
// Pure (no React): the table renders statusMarker()'s output.

export type StatusEventLike = {
  action_type: string;
  ts: string;
  reason?: string;
  summary?: string;
  limited?: boolean;
};

export type StatusMarker = {
  // label is the compact inline text: the latest changed reading's summary,
  // or a generic word when the server had no reading body (the org).
  label: string;
  // lines are the tooltip lines, one per changed reading, oldest first.
  lines: string[];
  // limited is true when any changed reading on the row is a limit hit.
  limited: boolean;
};

// REASON_LABEL names each change reason sessionmsg / ratelimitstate emit.
const REASON_LABEL: Record<string, string> = {
  first: "first reading",
  status: "status changed",
  limit: "limit changed",
  plan: "plan changed",
  overage: "overage changed",
  windows: "windows changed",
  used_percent: "usage changed",
  reset: "window reset",
};

const KIND_LABEL: Record<string, string> = {
  rate_limit: "Rate limit",
};

function kindLabel(t: string): string {
  return KIND_LABEL[t] ?? t.replace(/_/g, " ");
}

// statusMarker returns the marker for a row, or null when the row carries no
// changed status reading.
export function statusMarker(row: {
  status_events?: StatusEventLike[] | null;
  status_event_count?: number;
}): StatusMarker | null {
  const evs = row.status_events ?? [];
  if (evs.length === 0) return null;
  const last = evs[evs.length - 1];
  const limited = evs.some((e) => e.limited === true);
  const label = last.summary
    ? last.summary
    : limited
      ? `${kindLabel(last.action_type).toLowerCase()} hit`
      : `${kindLabel(last.action_type).toLowerCase()} updated`;
  const lines = evs.map((e) => {
    const why = e.reason ? REASON_LABEL[e.reason] ?? e.reason : "changed";
    const what = e.summary ? `: ${e.summary}` : e.limited ? ": limited" : "";
    return `${kindLabel(e.action_type)} ${why}${what}`;
  });
  const total = row.status_event_count ?? evs.length;
  if (total > evs.length) {
    const same = total - evs.length;
    lines.push(`${same} unchanged reading${same === 1 ? "" : "s"} folded`);
  }
  return { label, lines, limited };
}
