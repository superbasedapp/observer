// Share history (T-159): Settings > Enrolment's action for `observer org
// backfill --all --confirm`. The daemon runs the CLI's own performer
// (POST /api/enrolment/share-history); this module holds the pure copy and
// progress arithmetic the card renders.

import type { EnrolTableCount } from "./enrolment.ts";

/** The POST /api/enrolment/share-history answer (the CLI's counts). */
export type ShareHistoryReport = {
  /** Rows already waiting to ship before the run. */
  eligible: number;
  /** Rows the rewind makes (or made) eligible: the history that predates enrolment. */
  would_unlock: number;
  /** The whole local corpus across the pushable tables. */
  total: number;
  /** True when the cursor was reset (a confirmed run). */
  rewound: boolean;
};

// count renders a row count with thousands separators (kept local so this
// module stays loadable by node --test, which cannot resolve the @shared alias).
const count = (n: number): string => Math.round(n).toLocaleString("en-US");

/** eligibleNow is how many rows are waiting to ship, over every table. */
export function eligibleNow(tables: EnrolTableCount[] | null | undefined): number {
  return (tables ?? []).reduce((sum, t) => sum + (t.eligible ?? 0), 0);
}

/**
 * shareHistoryProgress is how far the push loop has got since the rewind:
 * `started` rows were waiting right after it, `now` are waiting now. New
 * activity can lift `now` above `started`, so both ends are clamped. An empty
 * corpus is done at once. `observed` is false until the page has re-read the
 * overview since the rewind: the copy it holds until then predates the rewind
 * (nothing waiting) and must not read as done.
 */
export function shareHistoryProgress(
  started: number,
  now: number,
  observed: boolean,
): { sent: number; ratio: number; done: boolean } {
  if (started <= 0) return { sent: 0, ratio: 1, done: true };
  if (!observed) return { sent: 0, ratio: 0, done: false };
  const sent = Math.min(started, Math.max(0, started - now));
  return { sent, ratio: sent / started, done: now <= 0 };
}

/**
 * shareHistoryCrossEnrolmentWarning is the note before the confirm (operator
 * ruling D-273 item 2, review M3-12, amended by D-43 and the operator answer
 * of 2026-11-13, agent migration 250): rows captured under the organization
 * enrolled now, and personal use from before this machine first enrolled, go
 * to that organization; sessions captured under a previous enrolment (another
 * organization) stay on this machine. `observer org backfill --all` prints
 * the same note.
 */
export function shareHistoryCrossEnrolmentWarning(org: string): string {
  return (
    `The older rows go to ${org}: sessions captured while this machine was enrolled in it, and personal use from before it first enrolled anywhere. ` +
    `Sessions captured under a previous enrolment in another organization stay on this machine.`
  );
}

/** shareHistoryPreviewLine is the dry run in one sentence, before the confirm. */
export function shareHistoryPreviewLine(r: ShareHistoryReport): string {
  if (r.would_unlock <= 0) {
    return "Everything captured on this machine is already shared or waiting to ship. There is no older history to send.";
  }
  const one = r.would_unlock === 1;
  const head = one
    ? "1 older row is not shared yet. Sharing history sends it on the next push cycles"
    : `${count(r.would_unlock)} older rows are not shared yet. Sharing history sends them on the next push cycles`;
  if (r.eligible <= 0) return `${head}.`;
  return `${head}, along with the ${count(r.eligible)} already waiting.`;
}
