// deletionModel - the pure rules of the console's deletion screens (plan 07
// M6.9 / M7a.1): who may see the "Delete organization" control, when the
// typed slug confirms it, the org deletion's states and refusals in words,
// and the account deletion precheck's blockers with the way out of each.
// No React, no fetch: OrgDeletionCard and Privacy's DeleteSection read these
// and deletionModel.test.ts pins them.
//
// The server stays authoritative: it re-checks ownership, the slug and every
// blocker. These rules only decide what the page offers before it asks.
//
// Honesty rules for the copy: the purge deletes the org's data from the
// tenant host and from object storage after the cooling-off window; backups
// age out within 30 days of it. Nothing here promises crypto-erasure.

import type {
  AccountDeletionBlockerCode,
  AccountDeletionPrecheck,
  AuthMode,
  OrgDeletionOrigin,
  OrgDeletionProof,
  OrgDeletionPreview,
  OrgDeletionReauth,
  OrgDeletionRefusal,
  OrgDeletionState,
  OrgDeletionStatus,
  PortalOrg,
} from "../api.ts";
import type { Tone } from "@shared/lib/tone";

// ---------------------------------------------------------------------------
// Org deletion
// ---------------------------------------------------------------------------

/** isOrgOwner: only an owner is offered the delete and cancel controls. */
export function isOrgOwner(org: Pick<PortalOrg, "console_role">): boolean {
  return org.console_role === "owner";
}

/** slugConfirmed: the typed text is exactly the org's slug (surrounding
 * spaces ignored, case kept: a slug is lowercase). */
export function slugConfirmed(typed: string, slug: string): boolean {
  return slug !== "" && typed.trim() === slug;
}

/** OPEN_STATES are the deletion states that hold the org: no new request. */
const OPEN_STATES: ReadonlySet<OrgDeletionState> = new Set(["cooling_off", "purging", "blocked"]);

/** deletionOpen: a request is still in progress (cooling off, purging, or
 * blocked mid-purge). */
export function deletionOpen(d: OrgDeletionStatus | null): boolean {
  return d !== null && OPEN_STATES.has(d.state);
}

/** OrgDeletionControl is what the owner part of the card shows. */
export type OrgDeletionControl =
  /** not an owner: no control at all (the status, if any, still shows). */
  | { kind: "none" }
  /** an owner the server refuses: the refusal in words. */
  | { kind: "refused"; sentence: string }
  /** an owner who can request it: the explanation and the slug form. */
  | { kind: "form" };

/** orgDeletionControl decides the owner part of the card, top to bottom:
 * non-owners see nothing; an open request leaves only the status panel; a
 * server refusal is worded; otherwise the form. */
export function orgDeletionControl(
  org: Pick<PortalOrg, "console_role">,
  deletion: OrgDeletionStatus | null,
  preview: OrgDeletionPreview,
): OrgDeletionControl {
  if (!isOrgOwner(org)) return { kind: "none" };
  if (deletionOpen(deletion)) return { kind: "none" };
  if (!preview.can_request) {
    return { kind: "refused", sentence: refusalText(preview.refusal) };
  }
  return { kind: "form" };
}

/** showCancel: the Cancel deletion button is an owner's, and only while the
 * server says the request can still be canceled. */
export function showCancel(org: Pick<PortalOrg, "console_role">, d: OrgDeletionStatus | null): boolean {
  return d !== null && d.can_cancel && isOrgOwner(org);
}

/** ORG_DELETION_REFUSAL_TEXT words the preview's refusal codes. */
export const ORG_DELETION_REFUSAL_TEXT: Readonly<Record<Exclude<OrgDeletionRefusal, "">, string>> = {
  not_owner: "Only an owner of this team can delete it.",
  personal_org: "A personal dashboard is deleted with your account. Delete your account from Privacy instead.",
  deletion_open: "This team already has a deletion in progress.",
  org_not_deletable: "This team cannot be deleted in its current state.",
  billing_cancel_unavailable:
    "This team has an active subscription that can't be canceled automatically right now. Cancel it from the team's billing page first, then delete the team.",
};

/** refusalText words a refusal code, honest about one this build does not
 * know. */
export function refusalText(code: string): string {
  return (
    ORG_DELETION_REFUSAL_TEXT[code as Exclude<OrgDeletionRefusal, "">] ??
    "This team cannot be deleted right now."
  );
}

/** REAUTH_UNAVAILABLE_TEXT says why the delete button is off on a
 * deployment that cannot re-authenticate. */
export const REAUTH_UNAVAILABLE_TEXT =
  "Re-authentication isn't available on this deployment, so the team can't be deleted here yet.";

/** ORG_DELETION_ERROR_TEXT words the request and cancel routes' refusals.
 * step_up_required is not here: it starts the re-authentication instead of
 * showing an error (orgDeletionRefusalNext). */
export const ORG_DELETION_ERROR_TEXT: Readonly<Record<string, string>> = {
  ...ORG_DELETION_REFUSAL_TEXT,
  confirm_mismatch: "The name you typed does not match this team's address. Type it exactly.",
  not_cancellable: "The deletion can no longer be canceled: the purge has started.",
  reauth_required: "Re-enter your developer subject to confirm deleting the team.",
  reauth_mismatch: "That developer subject is not the account you are signed in with.",
  step_up_invalid: "That re-authentication has expired or was already used. Re-authenticate again to delete the team.",
  provider_not_configured: REAUTH_UNAVAILABLE_TEXT,
};

// ---------------------------------------------------------------------------
// Org deletion: re-authentication
// ---------------------------------------------------------------------------

/** ReauthMode is the re-authentication the delete form asks for. */
export type ReauthMode = OrgDeletionReauth;

/** REAUTH_RULES decide the form's re-authentication, top to bottom: the
 * server's answer wins; an older server that does not say falls back to the
 * session's sign-in (WorkOS re-authenticates, anything else re-enters the
 * developer subject). */
const REAUTH_RULES: ReadonlyArray<{
  when: (reauth: string | undefined, authMode: AuthMode | null) => boolean;
  mode: ReauthMode;
}> = [
  { when: (r) => r === "unavailable", mode: "unavailable" },
  { when: (r) => r === "broker_token", mode: "broker_token" },
  { when: (r) => r === "step_up", mode: "step_up" },
  { when: (_r, a) => a === "workos", mode: "step_up" },
  { when: () => true, mode: "broker_token" },
];

/** orgDeletionReauthMode decides which re-authentication the form shows. */
export function orgDeletionReauthMode(
  preview: Pick<OrgDeletionPreview, "reauth">,
  authMode: AuthMode | null,
): ReauthMode {
  for (const r of REAUTH_RULES) if (r.when(preview.reauth, authMode)) return r.mode;
  return "broker_token";
}

/** orgDeletionFormReady: the delete button is on when the slug is typed
 * exactly, the developer subject is filled in when the form asks for it,
 * and this deployment can re-authenticate at all. */
export function orgDeletionFormReady(mode: ReauthMode, typed: string, slug: string, subject: string): boolean {
  if (mode === "unavailable") return false;
  if (!slugConfirmed(typed, slug)) return false;
  return mode !== "broker_token" || subject.trim() !== "";
}

/** REAUTH_NOTE is the line under the form for each re-authentication, and
 * for a WorkOS re-authentication that came back without the typed address
 * (stepped_up). broker_token has none: its field's label says it. */
const REAUTH_NOTE: Readonly<Record<ReauthMode | "stepped_up", string>> = {
  unavailable: REAUTH_UNAVAILABLE_TEXT,
  broker_token: "",
  step_up: "You'll be asked to sign in again to confirm, unless you used your passkey in the last few minutes.",
  stepped_up: "Re-authentication confirmed. Type the team's address again to finish.",
};

/** reauthNote is the line the form shows under its fields ("" for none). */
export function reauthNote(mode: ReauthMode, steppedUp: boolean): string {
  return REAUTH_NOTE[mode === "step_up" && steppedUp ? "stepped_up" : mode];
}

/** orgDeletionProof is what a request carries to prove the person is
 * present: the re-entered developer subject, or the WorkOS step-up id when
 * there is one (none first: a recent passkey use is enough, and the server
 * answers step_up_required otherwise). */
export function orgDeletionProof(mode: ReauthMode, subject: string, stepUpId: string | null): OrgDeletionProof {
  if (mode === "broker_token") return { brokerSubject: subject.trim() };
  if (mode === "step_up" && stepUpId) return { stepUpAuthorizationId: stepUpId };
  return {};
}

/** RefusalNext is what the page does with a request's refusal. */
export type RefusalNext = "start_step_up" | "drop_step_up" | "show";

/** REFUSAL_NEXT: step_up_required starts the WorkOS re-authentication;
 * step_up_invalid drops the spent authorization (and shows why); every
 * other refusal is shown. */
const REFUSAL_NEXT: Readonly<Record<string, RefusalNext>> = {
  step_up_required: "start_step_up",
  step_up_invalid: "drop_step_up",
};

/** orgDeletionRefusalNext reads what a refusal code asks of the page. */
export function orgDeletionRefusalNext(code: string): RefusalNext {
  return REFUSAL_NEXT[code] ?? "show";
}

/** ORG_DELETION_STEP_UP_KEY is the sessionStorage key the page stashes the
 * request under while the browser is away re-authenticating. */
export const ORG_DELETION_STEP_UP_KEY = "sbci_org_deletion_stepup";

/** OrgDeletionStepUpStash is what the page remembers across the WorkOS
 * re-authentication: which org, and the slug the owner typed. */
export interface OrgDeletionStepUpStash {
  orgId: string;
  slug: string;
}

/** orgDeletionStepUpURL is the full-page navigation that starts WorkOS
 * re-authentication for this org's deletion; the browser comes back to the
 * org's page with ?step_up=<id> appended. */
export function orgDeletionStepUpURL(orgId: string): string {
  return "/portal/auth/workos/start?purpose=step_up&action=deletion&return_to=/portal/orgs/" + encodeURIComponent(orgId);
}

/** parseStepUpStash reads a stashed request, null when it is missing or not
 * the expected shape. */
export function parseStepUpStash(raw: string | null): OrgDeletionStepUpStash | null {
  if (!raw) return null;
  try {
    const v = JSON.parse(raw) as Partial<OrgDeletionStepUpStash>;
    if (typeof v.orgId === "string" && typeof v.slug === "string") return { orgId: v.orgId, slug: v.slug };
  } catch {
    // fall through
  }
  return null;
}

/** stepUpConfirmSlug is the stashed slug to finish the request with after
 * re-authentication, null when the stash is missing, is for another org, or
 * no longer matches this org's slug (the owner then types it again). */
export function stepUpConfirmSlug(
  stash: OrgDeletionStepUpStash | null,
  org: Pick<PortalOrg, "org_id" | "slug">,
): string | null {
  if (!stash || stash.orgId !== org.org_id) return null;
  return slugConfirmed(stash.slug, org.slug) ? stash.slug.trim() : null;
}

/** OrgDeletionStateView is a deletion state in words. */
export interface OrgDeletionStateView {
  label: string;
  tone: Tone;
  /** One sentence; `date` is the relevant date already formatted. */
  sentence: (date: string) => string;
}

/** ORG_DELETION_STATE has one row per deletion state. */
export const ORG_DELETION_STATE: Readonly<Record<OrgDeletionState, OrgDeletionStateView>> = {
  cooling_off: {
    label: "Deletion scheduled",
    tone: "warn",
    sentence: (date) =>
      `Cooling off until ${date}. The team keeps working until then, and an owner can cancel the deletion.`,
  },
  canceled: {
    label: "Deletion canceled",
    tone: "neutral",
    sentence: (date) => (date ? `The deletion was canceled on ${date}. Nothing was deleted.` : "The deletion was canceled. Nothing was deleted."),
  },
  purging: {
    label: "Deletion in progress",
    tone: "danger",
    sentence: () => "The team's data is being deleted. Members no longer have access, and this can no longer be canceled.",
  },
  done: {
    label: "Deleted",
    tone: "neutral",
    sentence: (date) =>
      (date ? `The team was deleted on ${date}. ` : "The team was deleted. ") +
      "Copies in backups expire within 30 days.",
  },
  blocked: {
    label: "Deletion blocked",
    tone: "danger",
    sentence: () => "The deletion stopped and needs our attention. SuperBased has been alerted and will finish it.",
  },
};

/** orgDeletionStateView reads a state, honest about one this build does not
 * know. */
export function orgDeletionStateView(state: string): OrgDeletionStateView {
  return (
    ORG_DELETION_STATE[state as OrgDeletionState] ?? {
      label: state || "Unknown",
      tone: "neutral",
      sentence: () => "We could not read where this deletion stands.",
    }
  );
}

/** BLOCKED_REASON_TEXT words why a deletion is blocked. */
export const BLOCKED_REASON_TEXT: Readonly<Record<string, string>> = {
  billing_seam_unwired:
    "This deployment can't cancel the team's subscription automatically, so support will cancel it.",
  billing_cancel_refused: "The payment provider refused to cancel the team's subscription. Support will cancel it.",
  host_refused: "The team's host refused to delete its data. Support is looking into it.",
  host_purge_overdue: "The team's host has not confirmed that its data was deleted in time. Support is checking it.",
  followup_unverified:
    "The deletion could not be matched to a finished account deletion, so nothing was deleted. Support is checking it.",
};

/** blockedReasonText words a blocked reason, falling back to the raw token. */
export function blockedReasonText(reason: string): string {
  return BLOCKED_REASON_TEXT[reason] ?? reason;
}

/** stateDate picks the date the state's sentence names. */
export function stateDate(d: OrgDeletionStatus): string | undefined {
  switch (d.state) {
    case "cooling_off":
      return d.purge_after;
    case "canceled":
      return d.canceled_at;
    case "done":
      return d.done_at;
    default:
      return undefined;
  }
}

/** ORG_DELETION_ORIGIN says who started the deletion. */
export const ORG_DELETION_ORIGIN: Readonly<Record<OrgDeletionOrigin, string>> = {
  owner: "An owner of this team",
  account_deletion: "The deletion of the owner's account",
  staff: "SuperBased support",
};

/** KEPT_TEXT words what the purge keeps. */
export const KEPT_TEXT: Readonly<Record<string, string>> = {
  usage_counts: "Usage counts (numbers only, no content), kept for 10 years for billing records.",
  deletion_record: "A record that this team was deleted, and when.",
};

/** keptText words a kept item, falling back to the raw token. */
export function keptText(token: string): string {
  return KEPT_TEXT[token] ?? token;
}

// ---------------------------------------------------------------------------
// Account deletion precheck
// ---------------------------------------------------------------------------

/** AccountBlockerView is one blocker code in words, with the way out. */
export interface AccountBlockerView {
  /** Why this team blocks the deletion. */
  why: string;
  /** What to do first. */
  wayOut: string;
  /** Link the way out to the team's page in this console. */
  linkToTeam: boolean;
}

/** ACCOUNT_BLOCKER has one row per blocker code. */
export const ACCOUNT_BLOCKER: Readonly<Record<AccountDeletionBlockerCode, AccountBlockerView>> = {
  pays_for_live_org: {
    why: "Your account pays for this team's subscription.",
    wayOut: "Transfer the billing to another owner, or delete the team.",
    linkToTeam: true,
  },
  billing_owner: {
    why: "You are this team's billing owner.",
    wayOut: "Transfer the billing to another owner, or delete the team.",
    linkToTeam: true,
  },
  sole_owner_with_members: {
    why: "You are the only owner, and the team has other members.",
    wayOut: "Make another member an owner first.",
    linkToTeam: true,
  },
  sole_owner_alone: {
    why: "You are the team's only member.",
    wayOut: "Delete the team first.",
    linkToTeam: true,
  },
};

/** accountBlockerView reads a blocker code, honest about one this build does
 * not know. */
export function accountBlockerView(code: string): AccountBlockerView {
  return (
    ACCOUNT_BLOCKER[code as AccountDeletionBlockerCode] ?? {
      why: "This team blocks the deletion of your account.",
      wayOut: "Open the team to see what to change.",
      linkToTeam: true,
    }
  );
}

/** ACCOUNT_DELETION_BLOCKED is the account deletion's refusal code when an
 * org blocks it; its body carries the same `blockers` as the precheck. */
export const ACCOUNT_DELETION_BLOCKED = "account_deletion_blocked";

/** accountDeletionAllowed: the delete action is offered only when the
 * precheck has loaded and names no blocker. While it loads or after it
 * failed the action stays available: the server re-checks every blocker. */
export function accountDeletionAllowed(p: AccountDeletionPrecheck | null | undefined): boolean {
  if (!p) return true;
  return p.can_delete && p.blockers.length === 0;
}
