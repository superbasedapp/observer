// Session-detail elapsed/time helpers, promoted into the shared design system
// so both the node (web/) and org (web2/) session-detail surfaces share one
// implementation. Pure functions only: no React, no fetch, no app state.
//
// Extracted VERBATIM from web/src/components/sessiondetail/shared.ts during the
// shared-component promotion (design-system arc). The node's shared.ts now
// re-exports these; sessionRecentlyActive stays node-side because it is typed
// against the node's SessionDetail.

// elapsedMillis measures start→end. `end` is ended_at when the session was
// cleanly closed, else last_activity_at (COALESCE'd server-side to the last
// action's timestamp); Date.now() is only the last resort for a session with
// no end AND no recorded activity. This stops a never-closed session from
// reporting start→now (the 583h bug).
export function elapsedMillis(start: string, end?: string | null): number | null {
  const s = new Date(start).getTime();
  if (!Number.isFinite(s)) return null;
  const e = end ? new Date(end).getTime() : Date.now();
  if (!Number.isFinite(e)) return null;
  return Math.max(0, e - s);
}

// ElapsedLike is the minimal session shape elapsedSub reads. Both the node's
// SessionDetail and any org row that carries ended_at/last_activity_at are
// structurally assignable to it.
export type ElapsedLike = {
  ended_at?: string | null;
  last_activity_at?: string | null;
};

// elapsedSub is the Elapsed tile's sub-label. Cleanly closed → the end date.
// Never closed but with recent activity (< 10 min ago) → "session in
// progress". Never closed and stale → the last-activity date, so an old
// unfinished session doesn't misleadingly read as still running.
export function elapsedSub(d: ElapsedLike): string {
  if (d.ended_at) return fmtDate(d.ended_at);
  const last = d.last_activity_at;
  if (!last) return "session in progress";
  const lastMs = new Date(last).getTime();
  if (Number.isFinite(lastMs) && Date.now() - lastMs < 10 * 60 * 1000) {
    return "session in progress";
  }
  return `last activity ${fmtDate(last)}`;
}

export function fmtDate(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function truncate(s: string, n: number): string {
  if (!s) return "";
  return s.length <= n ? s : s.slice(0, n - 1) + "…";
}
