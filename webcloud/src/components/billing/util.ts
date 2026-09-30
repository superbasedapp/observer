// Shared pure helpers for the Billing page's split-out components
// (PlanComparison / SubscriptionCard) and the page shell itself. Keeping
// these in one place means the status vocabulary, the plan-token → human
// label mapping and the plan-comparison copy can never drift between the
// header pill, the hero card and the subscription card.

import { fmtDateTime, fmtRelative } from "@shared/lib/format";
import type { LucideIcon } from "lucide-react";
import type { Tone } from "@shared/lib/tone";
import { vocabView } from "@shared/lib/vocabEntry";
import type { SubscriptionStatus } from "../../api";
import { SUBSCRIPTION_STATUS } from "../../lib/vocab";

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

// statusMeta reads a Paddle subscription status from the ONE status table
// (lib/vocab.ts SUBSCRIPTION_STATUS) that the header pill, the subscription
// card and the hero all share: honest label, Pill variant, glyph. An unknown
// status is shown verbatim rather than hidden (defensive: the server's
// vocabulary can grow before this page's does).
export function statusMeta(
  status: SubscriptionStatus,
): { label: string; variant: Tone; icon: LucideIcon } {
  const v = vocabView("subscriptionStatus", SUBSCRIPTION_STATUS, status);
  return { label: v.label, variant: v.tone, icon: v.icon };
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

// PlanFeature is the planFeature vocabulary (VOCAB_ICONS.planFeature): a
// comparison cell that is a yes / no rather than a quantity.
export type PlanFeature = "included" | "not_included";

// PLAN_FEATURE_CELL maps the comparison table's yes / no cell text onto the
// planFeature vocabulary, so the row draws a Check or a Minus beside the
// words. A cell not listed here (a count, a retention window, "Own pool") is
// a value, not a yes / no, and renders as plain text.
export const PLAN_FEATURE_CELL: Readonly<Record<string, PlanFeature>> = {
  Included: "included",
  "Not included": "not_included",
  No: "not_included",
};

// PLAN_FEATURE_TONE colours the glyph: included reads as success, not
// included recedes (a dash, not an alarm).
export const PLAN_FEATURE_TONE: Readonly<Record<PlanFeature, string>> = {
  included: "text-success",
  not_included: "text-fg-4",
};

// PLAN_COMPARISON_FOOTNOTE is the one line shown once beneath both plan
// cards, not per-card, since it applies equally to both.
export const PLAN_COMPARISON_FOOTNOTE =
  "The node keeps its own local copy of every result forever - only the " +
  "portal's hosted history, corrections and export window shrink after the " +
  "retention period above.";
