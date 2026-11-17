// personalModel - the pure rules of the console's personal org (D-IND-8: an
// individual is an org of one on the one platform). It owns which org is the
// account's personal one, the personal card's state table (none / creating /
// a provisioning stage / active / suspended / failed / closing), the personal
// wording of the provisioning stages and of billing, and the rule for the old
// personal portal pages while the personal plane is still serving. No React,
// no fetch: the pages read these and personalModel.test.ts pins them.
//
// The stage labels, tones and "still moving" flags are orgsModel's
// PROVISIONING_STAGE; only the sentences are reworded here, because a team
// sentence ("Your team is being set up") would be wrong for a personal org.

import type { PersonalPlaneState, PortalOrg, ProvisioningStage } from "../api.ts";
import type { Tone } from "@shared/lib/tone";
import { BILLING_TEXT, PROVISIONING_STAGE, stageView, type BillingState, type StageView } from "./orgsModel.ts";

// ---------------------------------------------------------------------------
// Which org is personal
// ---------------------------------------------------------------------------

/** personalOrg returns the account's personal org from the orgs list, or
 * undefined while it has none. */
export function personalOrg(orgs: PortalOrg[] | undefined): PortalOrg | undefined {
  return (orgs ?? []).find((o) => o.kind === "personal");
}

/** teamOrgsOf returns the orgs that are not personal, in the list's order. */
export function teamOrgsOf(orgs: PortalOrg[] | undefined): PortalOrg[] {
  return (orgs ?? []).filter((o) => o.kind !== "personal");
}

/** isPersonal reports whether an org is a personal org. */
export function isPersonal(org: Pick<PortalOrg, "kind">): boolean {
  return org.kind === "personal";
}

// ---------------------------------------------------------------------------
// What a personal org is (said before the create and on its page)
// ---------------------------------------------------------------------------

/** PERSONAL_ORG_FACTS says what a personal org is, in plain sentences. */
export const PERSONAL_ORG_FACTS = {
  title: "Your personal dashboard",
  members: "It has one member: you. Only you see it.",
  privacy:
    "Summary only: counts, costs, timings, tool and model names, file paths as hashes. Never prompts, responses or file contents.",
  price: "It is free. You can move it to a paid personal plan later from its page.",
} as const;

/** PERSONAL_SETTING_UP is what the console shows while the personal
 * dashboard is created at sign-in (it is never a button to press). */
export const PERSONAL_SETTING_UP = "Setting up your personal dashboard...";

// ---------------------------------------------------------------------------
// The provisioning stages, worded for a personal org
// ---------------------------------------------------------------------------

/** PERSONAL_STAGE_SENTENCE words each stage for a personal org. */
export const PERSONAL_STAGE_SENTENCE: Readonly<Record<ProvisioningStage, string>> = {
  ready: "Your personal dashboard is ready.",
  closing: "Your personal dashboard is being closed.",
  unknown: "We could not read the progress of your personal dashboard's setup. Try again in a moment.",
  failed:
    "Setting up your personal dashboard stopped with an error. We have been alerted and will finish it; nothing you set up is lost.",
  finishing: "Your personal dashboard is almost ready.",
  waitlisted:
    "We are at capacity right now, so your personal dashboard is on the waitlist. It is created automatically as soon as there is room; you do not need to do anything.",
  queued: "Your personal dashboard is queued to be set up.",
  retrying: "Setting up your personal dashboard hit a temporary problem and is being retried automatically.",
  creating: "Your personal dashboard is being set up.",
};

/** stageViewFor reads a stage for an org of the given kind: the shared label,
 * tone and pending flag, with the personal sentence for a personal org. */
export function stageViewFor(stage: string | undefined, kind: PortalOrg["kind"]): StageView {
  const v = stageView(stage);
  if (kind !== "personal") return v;
  const key = (stage && stage in PROVISIONING_STAGE ? stage : "unknown") as ProvisioningStage;
  return { ...v, sentence: PERSONAL_STAGE_SENTENCE[key] };
}

// ---------------------------------------------------------------------------
// The personal card's state table
// ---------------------------------------------------------------------------

/** PersonalCardState is the one state the personal card renders. */
export type PersonalCardState =
  | "none"
  | "creating"
  | "provisioning"
  | "failed"
  | "active"
  | "suspended"
  | "closing";

/** PersonalCardInput is what the card decides from. */
export interface PersonalCardInput {
  /** org is the account's personal org, absent while it has none. */
  org?: PortalOrg;
  /** creating is true while the create request is in flight. */
  creating: boolean;
}

/** PersonalCardView is everything the personal card renders. */
export interface PersonalCardView {
  state: PersonalCardState;
  /** pill is the state as one pill; null when there is no org yet. */
  pill: { label: string; tone: Tone } | null;
  /** One honest sentence about where the personal org stands. */
  sentence: string;
  /** Still moving: the page polls. */
  pending: boolean;
  /** Offer "Create my personal dashboard". */
  canCreate: boolean;
  /** Show the dashboard and machines links (an active org only). */
  showLinks: boolean;
}

interface PersonalCardRule {
  state: PersonalCardState;
  match: (i: PersonalCardInput) => boolean;
}

// Walked top-down, first match wins.
const PERSONAL_CARD_RULES: PersonalCardRule[] = [
  { state: "creating", match: (i) => !i.org && i.creating },
  { state: "none", match: (i) => !i.org },
  { state: "failed", match: (i) => i.org?.status === "provisioning" && i.org.provisioning?.stage === "failed" },
  { state: "provisioning", match: (i) => i.org?.status === "provisioning" },
  { state: "active", match: (i) => i.org?.status === "active" },
  { state: "suspended", match: (i) => i.org?.status === "suspended" },
  { state: "closing", match: () => true },
];

/** personalCardState walks PERSONAL_CARD_RULES. */
export function personalCardState(i: PersonalCardInput): PersonalCardState {
  for (const r of PERSONAL_CARD_RULES) {
    if (r.match(i)) return r.state;
  }
  return "closing"; // unreachable: the last row matches everything
}

const CLOSING_SENTENCE: Readonly<Record<string, string>> = {
  pending_deletion: "Your personal dashboard is scheduled for deletion.",
  purging: "Your personal dashboard is being deleted.",
  purged: "Your personal dashboard was deleted.",
};

const CLOSING_PILL: Readonly<Record<string, { label: string; tone: Tone }>> = {
  pending_deletion: { label: "Deletion scheduled", tone: "danger" },
  purging: { label: "Deleting", tone: "danger" },
  purged: { label: "Deleted", tone: "neutral" },
};

/** personalCardView is the personal card's one decision function. */
export function personalCardView(i: PersonalCardInput): PersonalCardView {
  const state = personalCardState(i);
  const org = i.org;
  switch (state) {
    case "none":
      // Getting started v2: the personal dashboard is created at sign-in, so
      // "none" is a moment before it appears, never a button to press.
      return {
        state,
        pill: { label: "Setting up", tone: "info" },
        sentence: PERSONAL_SETTING_UP,
        pending: true,
        canCreate: false,
        showLinks: false,
      };
    case "creating":
      return {
        state,
        pill: { label: "Creating", tone: "info" },
        sentence: "Creating your personal dashboard.",
        pending: true,
        canCreate: false,
        showLinks: false,
      };
    case "failed":
    case "provisioning": {
      const s = stageViewFor(org?.provisioning?.stage, "personal");
      return {
        state,
        pill: { label: s.label, tone: s.tone },
        sentence: s.sentence,
        pending: s.pending,
        canCreate: false,
        showLinks: false,
      };
    }
    case "active":
      return {
        state,
        pill: { label: "Active", tone: "success" },
        sentence: PERSONAL_STAGE_SENTENCE.ready,
        pending: false,
        canCreate: false,
        showLinks: true,
      };
    case "suspended":
      return {
        state,
        pill: { label: "Suspended", tone: "warn" },
        sentence: "Your personal dashboard is suspended. Contact support if you did not expect this.",
        pending: false,
        canCreate: false,
        showLinks: false,
      };
    case "closing":
    default: {
      const status = org?.status ?? "pending_deletion";
      return {
        state: "closing",
        pill: CLOSING_PILL[status] ?? { label: status, tone: "neutral" },
        sentence: CLOSING_SENTENCE[status] ?? "Your personal dashboard is not available.",
        pending: false,
        canCreate: false,
        showLinks: false,
      };
    }
  }
}

/** dashboardUrl is the org's own dashboard address, taken from the
 * server-built machines page URL (its origin); null when the server sent
 * none. The console never composes a tenant host itself. */
export function dashboardUrl(org: Pick<PortalOrg, "machines_page_url">): string | null {
  if (!org.machines_page_url) return null;
  try {
    const u = new URL(org.machines_page_url);
    return u.protocol === "https:" || u.protocol === "http:" ? u.origin + "/" : null;
  } catch {
    return null;
  }
}

/** PERSONAL_CREATE_ERROR_TEXT words the personal create route's refusals;
 * an unknown code falls back to the server's own message. */
export const PERSONAL_CREATE_ERROR_TEXT: Readonly<Record<string, string>> = {
  forbidden: "This account cannot create a personal dashboard. Contact support if you need one.",
  org_provisioning: "Your personal dashboard is already being set up.",
};

/** personalCreateError words a failed create. */
export function personalCreateError(code: string, message: string): string {
  return PERSONAL_CREATE_ERROR_TEXT[code] ?? `Could not create your personal dashboard: ${message || "request failed"}. Try again.`;
}

// ---------------------------------------------------------------------------
// Words per org kind (the shared org page and billing card)
// ---------------------------------------------------------------------------

/** orgNoun is how the console names an org of a kind in a sentence. */
export function orgNoun(kind: PortalOrg["kind"]): string {
  return kind === "personal" ? "personal dashboard" : "team";
}

/** PERSONAL_BILLING_TEXT words each billing state for a personal org. */
export const PERSONAL_BILLING_TEXT: Readonly<Record<BillingState, string>> = {
  subscribed: "Your personal dashboard's subscription is active.",
  trialing: "Your personal dashboard is in its Paddle trial.",
  past_due:
    "The last payment did not go through. Access continues for now; update the payment method in the Paddle billing portal.",
  ended: "Your personal subscription has ended. Subscribe again to keep the paid plan; the free plan stays either way.",
  can_subscribe: "Your personal dashboard is on the free plan. Subscribe for a paid personal plan.",
  checkout_unconfigured: "Checkout is not configured for this deployment yet.",
  owner_only: "Only you can change this subscription.",
  not_billable: "This personal dashboard cannot take a subscription right now.",
};

/** billingTextFor words a billing state for an org of the given kind. */
export function billingTextFor(state: BillingState, kind: PortalOrg["kind"]): string {
  return kind === "personal" ? PERSONAL_BILLING_TEXT[state] : BILLING_TEXT[state];
}

/** subscribeLabel is the checkout button for an org of the given kind. */
export function subscribeLabel(state: BillingState, kind: PortalOrg["kind"]): string {
  if (state === "ended") return "Subscribe again";
  return kind === "personal" ? "Subscribe" : "Subscribe to Team";
}

// ---------------------------------------------------------------------------
// The old personal portal pages while the personal plane is serving
// ---------------------------------------------------------------------------

/** personalPlaneOf reads the session's personal_plane: only an exact
 * "retired" retires it; absent or anything else is serving. */
export function personalPlaneOf(v: unknown): PersonalPlaneState {
  return v === "retired" ? "retired" : "serving";
}

/** LegacyView is what the console does with the old personal pages
 * (Overview, Sessions, SessionDetail, Community, Usage). */
export interface LegacyView {
  /** Show the one quiet "Earlier enrichment results" link on Organizations. */
  showEarlierLink: boolean;
  /** Show the "Cloud Intelligence (legacy)" section in the navigation
   * (operator ruling 2026-11-16: nothing of the old plane is retired before
   * the end-to-end sign-off, so its pages stay reachable and labelled). */
  showNavSection: boolean;
  /** "page" renders the old page; "moved" renders the moved notice. */
  routes: "page" | "moved";
}

/** LEGACY_RULES is one row per personal plane state. While serving, the old
 * pages are reachable from a clearly labelled "Cloud Intelligence (legacy)"
 * navigation section and one link on Organizations; once the operator
 * retires the plane (after E3 and the end-to-end sign-off) both go and the
 * routes render the moved notice. */
export const LEGACY_RULES: Readonly<Record<PersonalPlaneState, LegacyView>> = {
  serving: { showEarlierLink: true, showNavSection: true, routes: "page" },
  retired: { showEarlierLink: false, showNavSection: false, routes: "moved" },
};

/** legacyView reads the rule for a raw personal_plane value. */
export function legacyView(raw: unknown): LegacyView {
  return LEGACY_RULES[personalPlaneOf(raw)];
}

/** EARLIER_RESULTS_LINK is the quiet link to the old enrichment pages. */
export const EARLIER_RESULTS_LINK = {
  to: "/sessions",
  label: "Earlier AI summaries (until they move to your personal dashboard)",
} as const;

/** MOVED_NOTICE is what the old pages say once the plane is retired. */
export const MOVED_NOTICE = {
  title: "This page has moved",
  cardTitle: "Your enrichment results moved to your personal dashboard",
  body:
    "Your enrichment results now live in your personal dashboard. Open it from Home to see them.",
  toLabel: "Go to Home",
} as const;
