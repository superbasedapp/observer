// orgsModel - the pure rules of the console's team org pages (plan 07 M6.5):
// the slug's shape check while typing, a slug suggested from the team name,
// the create form's state, the team cap and the managed-capture notice, the
// provisioning stage and org status vocabulary, the billing summary, and the
// per-team links to each team's own machines page. No React, no fetch: every
// page reads these and the tests pin them (orgsModel.test.ts).
//
// The server stays authoritative. The shape check here mirrors
// store.ValidateOrgSlug's shape rows only so the form can answer before a
// request; the reserved names and "taken" come from the server's
// availability read, never from a list copied here.

import type {
  OrgBillingView,
  OrgPlan,
  OrgStatus,
  PortalOrg,
  ProvisioningStage,
  SlugAvailability,
  TeamOrgAllowance,
} from "../api.ts";
import type { Tone } from "@shared/lib/tone";

// ---------------------------------------------------------------------------
// Slug shape (a mirror of store.ValidateOrgSlug's shape rows)
// ---------------------------------------------------------------------------

export const SLUG_MIN = 3;
export const SLUG_MAX = 40;
export const TEAM_NAME_MAX = 100;
const PERSONAL_PREFIX = "u-";

/** SlugShapeProblem names the first shape rule a slug breaks. */
export type SlugShapeProblem = "empty" | "length" | "charset" | "hyphen-edges" | "personal-prefix";

interface SlugShapeRule {
  id: SlugShapeProblem;
  bad: (s: string) => boolean;
}

// The rows of store.ValidateOrgSlug that need no list, in its order.
const SLUG_SHAPE_RULES: SlugShapeRule[] = [
  { id: "empty", bad: (s) => s.length === 0 },
  { id: "length", bad: (s) => s.length < SLUG_MIN || s.length > SLUG_MAX },
  { id: "charset", bad: (s) => !/^[a-z0-9-]+$/.test(s) },
  { id: "hyphen-edges", bad: (s) => s.startsWith("-") || s.endsWith("-") || s.includes("--") },
  { id: "personal-prefix", bad: (s) => s.startsWith(PERSONAL_PREFIX) },
];

/** normalizeSlug trims and lower-cases what the user typed (the server does
 * the same). */
export function normalizeSlug(raw: string): string {
  return raw.trim().toLowerCase();
}

/** slugShapeProblem returns the first broken shape rule, or null. */
export function slugShapeProblem(slug: string): SlugShapeProblem | null {
  for (const r of SLUG_SHAPE_RULES) {
    if (r.bad(slug)) return r.id;
  }
  return null;
}

/** SLUG_PROBLEM_TEXT words each shape problem for the field's error line. */
export const SLUG_PROBLEM_TEXT: Readonly<Record<SlugShapeProblem, string>> = {
  empty: "Choose an address for your team.",
  length: `Use ${SLUG_MIN} to ${SLUG_MAX} characters.`,
  charset: "Use lowercase letters, digits and hyphens only.",
  "hyphen-edges": "No hyphen at the start or end, and no two in a row.",
  "personal-prefix": "Team addresses cannot start with u-.",
};

/** suggestSlug turns a team name into a slug candidate: lower case, every
 * run of other characters becomes one hyphen, trimmed to the maximum, no
 * hyphen at either end, never the personal prefix. */
export function suggestSlug(name: string): string {
  let s = name
    .normalize("NFKD")
    .replace(/[̀-ͯ]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  if (s.startsWith(PERSONAL_PREFIX)) s = s.slice(PERSONAL_PREFIX.length);
  s = s.slice(0, SLUG_MAX).replace(/-+$/g, "");
  return s;
}

// ---------------------------------------------------------------------------
// The create form
// ---------------------------------------------------------------------------

/** AvailabilityState is the slug check's lifecycle in the form. */
export type AvailabilityState =
  | { kind: "idle" }
  | { kind: "checking"; slug: string }
  | { kind: "answered"; answer: SlugAvailability }
  | { kind: "error"; slug: string; message: string };

export interface CreateFormInput {
  name: string;
  slug: string;
  availability: AvailabilityState;
  submitting: boolean;
}

/** CreateFormView is everything the create form renders from its input. */
export interface CreateFormView {
  slug: string;
  nameError: string | null;
  slugMessage: string | null;
  slugTone: "neutral" | "success" | "danger";
  /** host is the server's answer for this exact slug, never composed here. */
  host: string | null;
  canSubmit: boolean;
}

const REASON_TEXT: Readonly<Record<NonNullable<SlugAvailability["reason"]>, string>> = {
  invalid: "That address is not valid.",
  reserved: "That name is reserved. Choose another.",
  taken: "That address is taken.",
};

/** createFormView is the create form's one decision function. */
export function createFormView(input: CreateFormInput): CreateFormView {
  const slug = normalizeSlug(input.slug);
  const name = input.name.trim();
  const nameError =
    name.length === 0
      ? null
      : [...name].length > TEAM_NAME_MAX
        ? `Use at most ${TEAM_NAME_MAX} characters.`
        : null;
  const view: CreateFormView = {
    slug,
    nameError,
    slugMessage: null,
    slugTone: "neutral",
    host: null,
    canSubmit: false,
  };
  const shape = slugShapeProblem(slug);
  if (shape) {
    view.slugMessage = shape === "empty" ? null : SLUG_PROBLEM_TEXT[shape];
    view.slugTone = shape === "empty" ? "neutral" : "danger";
    return view;
  }
  const a = input.availability;
  if (a.kind === "checking" || (a.kind === "answered" && a.answer.slug !== slug) || a.kind === "idle") {
    view.slugMessage = "Checking the address";
    return view;
  }
  if (a.kind === "error") {
    view.slugMessage = "Could not check the address: " + a.message;
    view.slugTone = "danger";
    return view;
  }
  if (!a.answer.available) {
    view.slugMessage = REASON_TEXT[a.answer.reason ?? "taken"];
    view.slugTone = "danger";
    return view;
  }
  view.slugMessage = "Available";
  view.slugTone = "success";
  view.host = a.answer.host ?? null;
  view.canSubmit = name.length > 0 && nameError === null && !input.submitting;
  return view;
}

/** TEAM_INVITE_ONLY_TEXT words the early-access allow-list (W17;
 * portal_teamallowlist.go): team workspaces are by invitation, the personal
 * workspace is unaffected, and how to ask. */
export const TEAM_INVITE_ONLY_TEXT =
  "Teams are by invitation while superbased is in early access. " +
  "Your personal dashboard works as usual. To ask for a team, contact support and quote your account reference.";

/** CREATE_ERROR_TEXT words the create route's refusals (portal_orgs.go
 * createErrors and the team cap's 409). */
export const CREATE_ERROR_TEXT: Readonly<Record<string, string>> = {
  slug_taken: "That address was just taken. Choose another.",
  slug_reserved: "That name is reserved. Choose another.",
  slug_invalid: "That address is not valid.",
  display_name_invalid: `The team name must be 1 to ${TEAM_NAME_MAX} characters.`,
  team_org_limit:
    "You already have as many teams as one account can create. We can raise this on request: contact support and say how many you need.",
  team_create_invite_only: TEAM_INVITE_ONLY_TEXT,
};

/** PAYS_FOR_LIVE_ORG is the account deletion's refusal code when the account
 * pays for a team that is still live (C2.front-door-5 A; portal_orgs.go
 * writePaysForLiveOrg). */
export const PAYS_FOR_LIVE_ORG = "pays_for_live_org";

// ---------------------------------------------------------------------------
// What a team is (said before the create) and the team cap
// ---------------------------------------------------------------------------

/** MANAGED_TEAM_NOTICE says, before the create, that a team is a managed
 * org: the team's admins see full content (prompts, responses, file paths,
 * commands) from every member's machine (C2.front-door-2; the console
 * creates every team with managed tenancy, portal_orgs.go createTeamTenancy). */
export const MANAGED_TEAM_NOTICE = {
  title: "Full detail",
  body:
    "Every machine you connect to a team sends full detail: prompts, responses and file paths. " +
    "The team's admins can read it. Keep private work off team machines.",
} as const;

/** DEFAULT_TEAM_CAP mirrors store.DefaultMaxTeamOrgs, for copy only: the
 * server's answer (team_orgs) decides. */
export const DEFAULT_TEAM_CAP = 3;

/** TeamCapView is what the console says about the team cap. */
export interface TeamCapView {
  /** canCreate is false once the cap is reached (the server refuses too). */
  canCreate: boolean;
  /** note is one sentence, or null when there is nothing worth saying. */
  note: string | null;
}

/** teamInviteOnlyNote is the invite-only sentence, naming the account
 * reference when the server gave one. */
export function teamInviteOnlyNote(accountRef?: string): string {
  return accountRef ? `${TEAM_INVITE_ONLY_TEXT.slice(0, -1)}: ${accountRef}.` : TEAM_INVITE_ONLY_TEXT;
}

/** teamCapView words the account's team cap. Unknown (the server could not
 * read it) lets the create through; the create route enforces the cap. While
 * team creation is invitation-only and this account is not invited, the
 * create is closed and the note says why and how to ask. */
export function teamCapView(a: TeamOrgAllowance | undefined): TeamCapView {
  if (!a) return { canCreate: true, note: null };
  if (a.invite_only && a.create_allowed === false) {
    return { canCreate: false, note: teamInviteOnlyNote(a.account_ref) };
  }
  if (a.limit <= 0) {
    return { canCreate: false, note: "This account cannot create teams. Contact support if you need one." };
  }
  const teams = (n: number) => `${n} team${n === 1 ? "" : "s"}`;
  if (a.remaining <= 0) {
    return {
      canCreate: false,
      note: `You have ${teams(a.used)}, the most one account can create (${a.limit}). We can raise this on request: contact support and say how many you need.`,
    };
  }
  return {
    canCreate: true,
    note: `You can create ${a.remaining} more team${a.remaining === 1 ? "" : "s"} (up to ${a.limit} per account; we can raise this on request).`,
  };
}

// ---------------------------------------------------------------------------
// Provisioning and status vocabulary
// ---------------------------------------------------------------------------

export interface StageView {
  label: string;
  tone: Tone;
  /** One honest sentence about where the create is. */
  sentence: string;
  /** Still moving: the page polls. */
  pending: boolean;
}

/** PROVISIONING_STAGE is one row per stage of portal_orgs.go's
 * provisioningRules. */
export const PROVISIONING_STAGE: Readonly<Record<ProvisioningStage, StageView>> = {
  ready: { label: "Ready", tone: "success", sentence: "Your team is ready.", pending: false },
  closing: { label: "Closing", tone: "neutral", sentence: "This team is being closed.", pending: false },
  unknown: {
    label: "Unknown",
    tone: "neutral",
    sentence: "We could not read the progress of this team's setup. Try again in a moment.",
    pending: true,
  },
  failed: {
    label: "Needs attention",
    tone: "danger",
    sentence: "Setting up this team stopped with an error. Our team has been alerted and will finish it; nothing you set up is lost.",
    pending: false,
  },
  finishing: { label: "Finishing", tone: "info", sentence: "Your team is almost ready.", pending: true },
  waitlisted: {
    label: "Waitlisted",
    tone: "warn",
    sentence: "We are at capacity right now, so your team is on the waitlist. It is created automatically as soon as there is room; you do not need to do anything.",
    pending: true,
  },
  queued: { label: "Queued", tone: "info", sentence: "Your team is queued to be set up.", pending: true },
  retrying: {
    label: "Retrying",
    tone: "warn",
    sentence: "Setting up your team hit a temporary problem and is being retried automatically.",
    pending: true,
  },
  creating: { label: "Setting up", tone: "info", sentence: "Your team is being set up.", pending: true },
};

/** stageView reads a stage, honest about an unknown one. */
export function stageView(stage: string | undefined): StageView {
  return (stage && PROVISIONING_STAGE[stage as ProvisioningStage]) || PROVISIONING_STAGE.unknown;
}

/** ORG_STATUS is the label and tone of each org lifecycle state. */
export const ORG_STATUS: Readonly<Record<OrgStatus, { label: string; tone: Tone }>> = {
  provisioning: { label: "Setting up", tone: "info" },
  active: { label: "Active", tone: "success" },
  suspended: { label: "Suspended", tone: "warn" },
  pending_deletion: { label: "Deletion scheduled", tone: "danger" },
  purging: { label: "Deleting", tone: "danger" },
  purged: { label: "Deleted", tone: "neutral" },
};

/** orgStatusView labels an org: a provisioning org is labelled by its stage
 * (a waitlisted team reads "Waitlisted", not "Setting up"). */
export function orgStatusView(org: PortalOrg): { label: string; tone: Tone } {
  if (org.status === "provisioning" && org.provisioning) {
    const s = stageView(org.provisioning.stage);
    return { label: s.label, tone: s.tone };
  }
  return ORG_STATUS[org.status] ?? { label: org.status, tone: "neutral" };
}

/** ROLE_LABEL is the console role in words. */
export const ROLE_LABEL: Readonly<Record<PortalOrg["console_role"], string>> = {
  owner: "Owner",
  admin: "Admin",
  member: "Member",
};

// ---------------------------------------------------------------------------
// Plan and billing
// ---------------------------------------------------------------------------

/** PLAN_SOURCE_TEXT says why the org is on its plan. */
export const PLAN_SOURCE_TEXT: Readonly<Record<OrgPlan["source"], string>> = {
  subscription: "From your subscription",
  org_grant: "Granted by superbased",
  launch: "Free launch period",
  floor: "No active subscription",
};

/** BillingState is the one state the org billing card renders. */
export type BillingState =
  | "subscribed"
  | "trialing"
  | "past_due"
  | "ended"
  | "can_subscribe"
  | "checkout_unconfigured"
  | "owner_only"
  | "not_billable";

interface BillingRule {
  state: BillingState;
  match: (v: OrgBillingView) => boolean;
}

const LIVE = new Set(["active", "trialing", "past_due", "paused"]);

// The billing card's state, walked top-down, first match wins.
const BILLING_RULES: BillingRule[] = [
  { state: "trialing", match: (v) => v.subscription?.status === "trialing" },
  { state: "past_due", match: (v) => v.subscription?.status === "past_due" },
  { state: "subscribed", match: (v) => !!v.subscription && LIVE.has(v.subscription.status) },
  { state: "owner_only", match: (v) => !v.is_billing_owner },
  { state: "checkout_unconfigured", match: (v) => !v.checkout.available || v.checkout.prices.length === 0 },
  { state: "ended", match: (v) => v.has_subscription && v.can_checkout },
  { state: "can_subscribe", match: (v) => v.can_checkout },
  { state: "not_billable", match: () => true },
];

/** billingState walks BILLING_RULES. */
export function billingState(v: OrgBillingView): BillingState {
  for (const r of BILLING_RULES) {
    if (r.match(v)) return r.state;
  }
  return "not_billable"; // unreachable: the last row matches everything
}

/** BILLING_TEXT words each billing state. */
export const BILLING_TEXT: Readonly<Record<BillingState, string>> = {
  subscribed: "Your team's subscription is active.",
  trialing: "Your team is in its Paddle trial.",
  past_due: "The last payment did not go through. Access continues for now; update the payment method in the Paddle billing portal.",
  ended: "Your team's subscription has ended. Subscribe again to keep the Team plan.",
  can_subscribe: "Subscribe to keep your team on the Team plan after the launch period.",
  checkout_unconfigured: "Checkout is not configured for this deployment yet.",
  owner_only: "Only the team's billing owner can change the subscription.",
  not_billable: "This team cannot take a subscription right now.",
};
