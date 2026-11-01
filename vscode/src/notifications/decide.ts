// Pure decision helpers for the M5 notifications. Lives in its own
// module so the unit suite can pin the threshold + dedup logic
// without spinning up a vscode runtime.

import type {
  HeadlineResponse,
  MessagesNewest,
  MessagesSummaryResponse,
  WatcherHealthResponse,
} from '../api/types';

export const BUDGET_PCT_THRESHOLD = 80;
export const WATCHER_BEHIND_BYTES_THRESHOLD = 10 * 1024;
export const WATCHER_DEDUP_MS = 5 * 60 * 1000;

export interface BudgetDecision {
  fire: boolean;
  pct?: number;
  toDateUsd?: number;
  budgetUsd?: number;
}

/**
 * decideBudget returns whether to surface the breach notification
 * for this headline payload. Fires only when:
 *
 *  - a positive monthly budget is configured (month.budget_usd > 0),
 *  - month.budget_pct >= 80, AND
 *  - we haven't already fired today (caller checks `lastFiredDay`).
 *
 * The "calendar day" is the UTC YYYY-MM-DD of `now` — keeps the
 * dedup deterministic across timezones and easy to test.
 */
export function decideBudget(
  data: HeadlineResponse,
  lastFiredDay: string | undefined,
  now: Date,
): BudgetDecision {
  const budgetUsd = data.month?.budget_usd ?? 0;
  const pct = data.month?.budget_pct ?? 0;
  if (budgetUsd <= 0 || pct < BUDGET_PCT_THRESHOLD) return { fire: false };
  const today = now.toISOString().slice(0, 10);
  if (lastFiredDay === today) return { fire: false };
  return {
    fire: true,
    pct,
    toDateUsd: data.month?.to_date_usd,
    budgetUsd,
  };
}

export interface WatcherDecision {
  fire: boolean;
  totalBytes?: number;
  worstFile?: string;
  worstBytes?: number;
}

/**
 * decideWatcherLag returns whether to surface the watcher-lag
 * notification for this /api/health/watcher payload.
 *
 *  - Threshold: behind_total_bytes > 10 KB (matches plan §9).
 *  - Dedup: identified by the worst-lagging file path; fire at most
 *    once per WATCHER_DEDUP_MS for the same path.
 *
 * The caller maintains the dedup map (`lastFiredAtMs` keyed by
 * worst-file path) and updates it when `fire === true`. We surface
 * the worst file in the toast so the operator can act on it directly.
 */
export function decideWatcherLag(
  data: WatcherHealthResponse,
  lastFiredAtMs: Map<string, number>,
  now: number,
): WatcherDecision {
  if ((data.behind_total_bytes ?? 0) <= WATCHER_BEHIND_BYTES_THRESHOLD) {
    return { fire: false };
  }
  const worst = (data.files ?? [])
    .filter((f) => !f.suspected_misrouted) // misrouted rows are stuck-by-design; don't nag
    .reduce<{ path: string; behind: number } | undefined>((acc, f) => {
      const behind = f.behind_bytes ?? 0;
      if (!acc || behind > acc.behind) return { path: f.path, behind };
      return acc;
    }, undefined);
  if (!worst) return { fire: false };
  const lastAt = lastFiredAtMs.get(worst.path);
  if (lastAt !== undefined && now - lastAt < WATCHER_DEDUP_MS) {
    return { fire: false };
  }
  return {
    fire: true,
    totalBytes: data.behind_total_bytes,
    worstFile: worst.path,
    worstBytes: worst.behind,
  };
}

export interface AdminMessageDecision {
  /** Show a notification now. */
  fire: boolean;
  /** Use showWarningMessage (an alert) instead of showInformationMessage. */
  warn?: boolean;
  /** The notification text. */
  text?: string;
  /** Offer Acknowledge (the message asked for one). */
  canAck?: boolean;
  message?: MessagesNewest;
  /** The message id to remember as notified (the caller persists it). */
  seen: number;
}

/**
 * decideAdminMessage returns whether to announce the newest admin message
 * from a GET /api/messages/summary payload (T-854).
 *
 *  - Only when the developer kept the VS Code surface on
 *    (surfaces.vscode) and the node is enrolled.
 *  - Reads `push`, which already applies the developer's alerts_only
 *    choice, never the raw counts.
 *  - Dedup on the org's message id, which only grows: a message is
 *    announced once, ever (the caller persists `seen` in globalState), and
 *    an older message never re-fires after a newer one was seen.
 *  - Only while it is still unread (push.unread > 0): a message read in the
 *    dashboard before the next poll is not announced.
 *
 * Copy names the author and never a pronoun (D-688 ruling 6).
 */
export function decideAdminMessage(
  data: MessagesSummaryResponse | null | undefined,
  lastSeenId: number,
): AdminMessageDecision {
  const prev = Number.isFinite(lastSeenId) ? lastSeenId : 0;
  if (!data || !data.enrolled) return { fire: false, seen: prev };
  const m = data.push?.newest ?? null;
  if (!m || m.message_id <= prev) return { fire: false, seen: prev };
  if (!data.surfaces?.vscode || (data.push?.unread ?? 0) <= 0) {
    return { fire: false, seen: m.message_id };
  }
  const who = m.author_name?.trim() || 'your admin';
  const what = m.subject?.trim() || 'a new message';
  const end = /[.!?]$/.test(what) ? '' : '.';
  const ask = m.require_ack ? ' They ask you to acknowledge it.' : '';
  return {
    fire: true,
    warn: m.kind === 'alert',
    text: `Message from your admin, ${who}: ${what}${end}${ask}`,
    canAck: m.require_ack,
    message: m,
    seen: m.message_id,
  };
}

/**
 * messagesStatusText is the status bar item's text, or null to hide it:
 * shown only while there is something unread (push.unread, alerts_only
 * already applied) on an enrolled node whose VS Code surface is on.
 */
export function messagesStatusText(data: MessagesSummaryResponse | null | undefined): string | null {
  if (!data || !data.enrolled || !data.surfaces?.vscode) return null;
  const n = data.push?.unread ?? 0;
  if (!Number.isFinite(n) || n <= 0) return null;
  return `${n > 99 ? '99+' : Math.floor(n)} from admin`;
}

/** messagesRoute is the dashboard route that opens one conversation. */
export function messagesRoute(threadId?: string): string {
  if (!threadId) return '/messages';
  return `/messages?thread=${encodeURIComponent(threadId)}`;
}
