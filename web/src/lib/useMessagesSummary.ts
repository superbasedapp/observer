import { useApi } from "@/lib/useApi";
import type { MessagesSummaryResponse } from "@/lib/adminMessages";

/** The one summary read the sidebar badge, the toast and the command
 *  palette share (the query cache dedupes the URL, so they cost one poll). */
export const MESSAGES_SUMMARY_PATH = "/api/messages/summary";

/** MESSAGES_SUMMARY_POLL_MS: a minute, the bell's cadence. */
export const MESSAGES_SUMMARY_POLL_MS = 60_000;

/**
 * useMessagesSummary reads GET /api/messages/summary every minute. A refused
 * read (a remote view of this owner-local route, or a daemon that predates
 * messaging) leaves data null, which every reader treats as "not enrolled":
 * no nav item, no badge, no toast.
 */
export function useMessagesSummary() {
  return useApi<MessagesSummaryResponse>(MESSAGES_SUMMARY_PATH, undefined, [], {
    refreshMs: MESSAGES_SUMMARY_POLL_MS,
  });
}
