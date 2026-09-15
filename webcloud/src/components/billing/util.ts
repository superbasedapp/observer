// Shared pure helpers for the Billing page's split-out components
// (PlanComparison / SubscriptionCard) and the page shell itself. Keeping
// these in one place means the status vocabulary, the plan-token → human
// label mapping and the plan-comparison copy can never drift between the
// header pill, the hero card and the subscription card.

import { fmtDateTime, fmtRelative } from "@shared/lib/format";
import type { SubscriptionStatus } from "../../api";

export type StatusVariant = "success" | "danger" | "neutral" | "warn" | "info";

// isFuture reports whether an RFC3339 instant is still ahead of now. An
// unparseable or missing value is treated as not-future, so a canceled
// subscription with no honest end date reads as "access has ended" rather
// than inventing a date.
export function isFuture(iso: string | undefined): boolean {
  if (!iso) {
    return false;
  }
  const d = new Date(iso);
  return !Number.isNaN(d.getTime()) && d.getTime() > Date.now();
}

// withinThirtyDays gates the fmtRelative parenthetical: "in 6 days" reads
// better than "in 214 days", so the relative form only appears near now.
function withinThirtyDays(iso: string): boolean {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return false;
  return Math.abs(d.getTime() - Date.now()) <= 30 * 24 * 60 * 60 * 1000;
}

// dateWithRelative renders an instant via fmtDateTime, with a fmtRelative
// parenthetical only when the instant falls within 30 days of now. Returns
// "" for empty input rather than a placeholder dash, so callers can splice
// it into a sentence without an orphan character.
export function dateWithRelative(iso: string | null | undefined): string {
  if (!iso) return "";
  const dt = fmtDateTime(iso);
  return withinThirtyDays(iso) ? `${dt} (${fmtRelative(iso)})` : dt;
}

// humanPlanLabel maps the raw plan token ("free" / "plus_beta") onto the
// short human name a Pill should carry - never the raw token verbatim.
export function humanPlanLabel(planToken: string | null | undefined): string {
  return isPlusPlan(planToken) ? "Plus" : "Free";
}

export function isPlusPlan(planToken: string | null | undefined): boolean {
  return (planToken ?? "").startsWith("plus");
}

// statusMeta maps a Paddle subscription status onto an honest label plus the
// shared Pill variant. An unknown status is shown verbatim rather than
// hidden (defensive: the server's vocabulary can grow before this page's
// does).
export function statusMeta(
  status: SubscriptionStatus,
): { label: string; variant: StatusVariant } {
  switch (status) {
    case "active":
      return { label: "Active", variant: "success" };
    case "trialing":
      return { label: "Trial", variant: "info" };
    case "canceled":
      return { label: "Canceled", variant: "neutral" };
    case "past_due":
      return { label: "Past due", variant: "danger" };
    case "paused":
      return { label: "Paused", variant: "neutral" };
    case "refunded":
      return { label: "Refunded", variant: "danger" };
    case "charged_back":
      return { label: "Charged back", variant: "danger" };
    default:
      return { label: status, variant: "neutral" };
  }
}

// PLAN_COMPARISON_ROWS is the ruled §2 table (cloud-intelligence value-upgrade
// plan, 2026-09-15): what every account gets for free, and what Plus adds on
// top of it. No row is locked behind "coming soon" - everything free lists
// ships today.
export const PLAN_COMPARISON_ROWS: {
  label: string;
  free: string;
  plus: string;
}[] = [
  {
    label: "Title, tags, description and next step on every session",
    free: "Included",
    plus: "Included",
  },
  { label: "Sessions per day", free: "5", plus: "25" },
  { label: "Sessions per month", free: "100", plus: "500" },
  { label: "Weekly project digest", free: "Not included", plus: "Included" },
  { label: "Hosted history", free: "30 days", plus: "12 months" },
  {
    label: "Priority when the free pool is exhausted",
    free: "No",
    plus: "Own pool",
  },
];

// PLAN_COMPARISON_FOOTNOTE is the one line shown once beneath both plan
// cards, not per-card, since it applies equally to both.
export const PLAN_COMPARISON_FOOTNOTE =
  "The node keeps its own local copy of every result forever - only the " +
  "portal's hosted history, corrections and export window shrink after the " +
  "retention period above.";
