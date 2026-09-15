import type { SessionDetail } from "@/lib/types";

export function hasRecordedUsage(d: SessionDetail): boolean {
  return d.token_usage_available ?? (d.per_model.length > 0);
}

// Shared helpers for the session-detail modules. The pure time helpers
// (elapsedMillis / elapsedSub / truncate / fmtDate) were promoted into the
// shared design system so the node and org session-detail surfaces share one
// implementation; they are re-exported here so existing @/...shared importers
// are unchanged. sessionRecentlyActive stays here because it is typed against
// the node's SessionDetail.

export {
  elapsedMillis,
  elapsedSub,
  fmtDate,
  truncate,
} from "@shared/lib/sessionElapsed";

// ----- helpers -----------------------------------------------------

// sessionRecentlyActive — the cheapest in-file honest signal for whether a
// bare session is worth offering a read-only "Watch" on: NOT cleanly ended,
// and last activity within 15 minutes (matching /api/live's window). The
// ended_at exclusion matters because the server sets last_activity_at to
// ended_at for closed sessions — without it a just-ended session would offer
// "Watch" on a conversation that can no longer move. Uses last_activity_at
// (server COALESCE of the newest action timestamp), falling back to
// started_at for a brand-new session that hasn't logged an action yet. A
// dead/stale session returns false → no watch affordance (honest-disabled).
// Known residual: a session active only through api_turns/token_usage rows
// (no recent actions) can under-report here; the Sessions page's watch pill
// uses the canonical /api/live signal and passes watch=true, which overrides.
export function sessionRecentlyActive(d: SessionDetail): boolean {
  if (d.ended_at) return false;
  const iso = d.last_activity_at ?? d.started_at;
  if (!iso) return false;
  const t = new Date(iso).getTime();
  if (!Number.isFinite(t)) return false;
  return Date.now() - t <= 15 * 60 * 1000;
}
