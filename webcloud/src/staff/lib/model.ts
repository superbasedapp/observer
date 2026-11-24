// Display rules for the staff console (managed-SaaS M6.8). Pure: the pages
// pass server data in and render what comes out, so every rule here has a
// node test (model.test.ts) and no page repeats one.

export type Tone = "neutral" | "success" | "warn" | "danger" | "info" | "accent";

/** orgStatusTone: the orgs.status vocabulary (cloud 0047) to a pill tone. */
const orgStatusTones: Record<string, Tone> = {
  provisioning: "info",
  active: "success",
  suspended: "warn",
  pending_deletion: "danger",
  purging: "danger",
  purged: "neutral",
};

export function orgStatusTone(status: string): Tone {
  return orgStatusTones[status] ?? "neutral";
}

/** isDeletionStatus reports whether an org status is part of deletion. */
export function isDeletionStatus(status: string): boolean {
  return status === "pending_deletion" || status === "purging" || status === "purged";
}

/** subscriptionTone: Paddle subscription status to a pill tone. */
export function subscriptionTone(status: string): Tone {
  switch (status) {
    case "active":
    case "trialing":
      return "success";
    case "past_due":
    case "paused":
      return "warn";
    case "canceled":
      return "neutral";
    default:
      return "neutral";
  }
}

export interface GrantState {
  action: string;
  plan_name?: string;
  plan_version?: number;
  effective_until?: string | null;
}

/** grantInForce mirrors store.OrgPlanGrant.InForce: a grant row naming a
 *  plan whose end is absent or after now. */
export function grantInForce(g: GrantState | null | undefined, now: Date): boolean {
  if (!g || g.action !== "grant" || !g.plan_name) return false;
  if (!g.effective_until) return true;
  return new Date(g.effective_until).getTime() > now.getTime();
}

export interface PlanSource {
  grant?: GrantState | null;
  subscription?: { status: string; plan_name?: string; plan_version?: number } | null;
}

const liveSubscription = ["active", "trialing", "past_due", "paused"];

/** planSummary names where the org's plan comes from, in the order the
 *  entitlements plan source reads them (entitlementwork planRules): a live
 *  subscription, then an operator grant in force, then the launch window or
 *  the floor (which only the issued document can tell apart). */
export function planSummary(o: PlanSource, now: Date): { label: string; source: string; tone: Tone } {
  const s = o.subscription;
  if (s && liveSubscription.includes(s.status) && s.plan_name) {
    return { label: `${s.plan_name} v${s.plan_version ?? "?"}`, source: `subscription (${s.status})`, tone: subscriptionTone(s.status) };
  }
  if (grantInForce(o.grant, now)) {
    return { label: `${o.grant!.plan_name} v${o.grant!.plan_version ?? "?"}`, source: "operator grant", tone: "accent" };
  }
  return { label: "launch window or floor", source: "see the issued document", tone: "neutral" };
}

// ---- passkey freshness -----------------------------------------------------

export interface Freshness {
  fresh: boolean;
  /** secondsLeft is how long the assertion stays fresh (0 when stale). */
  secondsLeft: number;
  label: string;
}

/** freshness reads the session's last assertion against the window the
 *  server enforces (staffauth.FreshAssertionWindow) for every change. */
export function freshness(freshUntil: string | null | undefined, now: Date): Freshness {
  if (!freshUntil) return { fresh: false, secondsLeft: 0, label: "Verify your passkey to make changes" };
  const left = Math.floor((new Date(freshUntil).getTime() - now.getTime()) / 1000);
  if (left <= 0) return { fresh: false, secondsLeft: 0, label: "Verify your passkey to make changes" };
  const m = Math.floor(left / 60);
  const s = left % 60;
  return { fresh: true, secondsLeft: left, label: `Changes allowed for ${m}:${String(s).padStart(2, "0")}` };
}

// ---- capabilities ----------------------------------------------------------

export interface Capability {
  action: string;
  permitted: boolean;
  fresh: boolean;
}

/** can reports whether the role may perform action at all (the gate still
 *  decides; this only hides controls a role can never use). */
export function can(caps: Capability[] | undefined, action: string): boolean {
  return !!caps?.find((c) => c.action === action)?.permitted;
}

// ---- the plan grant command ------------------------------------------------

/** shellQuote quotes one argument for a POSIX shell. */
export function shellQuote(s: string): string {
  if (/^[A-Za-z0-9_./:@=+-]+$/.test(s)) return s;
  return `'${s.replace(/'/g, `'"'"'`)}'`;
}

export interface GrantCommandInput {
  action: "grant" | "revoke";
  orgId: string;
  plan: string;
  version: string;
  until: string;
  reason: string;
}

/** grantCommand prepares the operator's `observer-cloud grant-plan org`
 *  command (cmd/observer-cloud/grantplan_org.go). Plan grants are an
 *  operator-only CLI write by W15-D13 (cloud 0095): the console never writes
 *  one, it hands the operator the exact command, with the errors the CLI
 *  would raise. */
export function grantCommand(g: GrantCommandInput): { command: string; errors: string[] } {
  const errors: string[] = [];
  const reason = g.reason.trim();
  if (reason === "") errors.push("A reason is required (it is kept with the grant).");
  if (reason.length > 1000) errors.push("The reason is longer than 1000 characters.");
  const args = ["observer-cloud", "grant-plan", "org"];
  if (g.action === "revoke") {
    args.push("revoke", "--org", shellQuote(g.orgId), "--reason", shellQuote(reason));
    return { command: args.join(" "), errors };
  }
  const plan = g.plan.trim();
  if (!/^[a-z][a-z0-9_]{0,63}$/.test(plan)) errors.push("The plan is a catalog plan name, e.g. team or business.");
  args.push("--org", shellQuote(g.orgId), "--plan", shellQuote(plan));
  const version = g.version.trim();
  if (version !== "") {
    if (!/^[1-9][0-9]*$/.test(version)) errors.push("The version is a whole number from 1, or empty for the newest.");
    args.push("--version", version);
  }
  const until = g.until.trim();
  if (until !== "") {
    const t = new Date(until);
    if (Number.isNaN(t.getTime()) || !/Z$|[+-]\d\d:\d\d$/.test(until)) errors.push("The end is an RFC 3339 time, e.g. 2027-01-01T00:00:00Z.");
    args.push("--until", shellQuote(until));
  }
  args.push("--reason", shellQuote(reason));
  return { command: args.join(" "), errors };
}

// ---- the action log ----------------------------------------------------------

/** VERB_LABELS mirrors staffauth.KnownVerbs. */
export const VERB_LABELS: Record<string, string> = {
  "staff.created": "Staff member created",
  "enrolment.minted": "Enrolment code minted",
  "credential.registered": "Passkey registered",
  "credential.revoked": "Passkey revoked",
  "session.started": "Signed in",
  "session.ended": "Signed out",
  "availability.set": "Availability input set",
  "availability.deleted": "Availability input removed",
  "action.refused": "Action refused",
  "support.signin": "Support sign-in",
  "team_allowlist.added": "Team allow-list entry added",
  "team_allowlist.removed": "Team allow-list entry removed",
  "availability.issue_requested": "Availability envelope issue requested",
  "availability.issue_cancelled": "Availability envelope issue cancelled",
};

export function verbLabel(verb: string): string {
  return VERB_LABELS[verb] ?? verb;
}

/** actorLabel shortens "staff:<uuid>" for a table cell. */
export function actorLabel(actor: string, self?: string): string {
  if (self && actor === `staff:${self}`) return "you";
  if (actor.startsWith("staff:")) return `staff ${actor.slice(6, 14)}`;
  return actor;
}

/** shortId is the first block of a UUID, for dense tables. */
export function shortId(id: string): string {
  return id.length > 8 ? id.slice(0, 8) : id;
}

/** formatTime renders an RFC 3339 time as "YYYY-MM-DD HH:MM UTC". */
export function formatTime(iso: string | null | undefined): string {
  if (!iso) return "-";
  const t = new Date(iso);
  if (Number.isNaN(t.getTime())) return iso;
  return `${t.toISOString().slice(0, 16).replace("T", " ")} UTC`;
}

/** relativeTime renders how long ago (or until) iso is from now. */
export function relativeTime(iso: string | null | undefined, now: Date): string {
  if (!iso) return "-";
  const d = Math.round((new Date(iso).getTime() - now.getTime()) / 1000);
  const abs = Math.abs(d);
  const unit = abs < 90 ? `${abs}s` : abs < 5400 ? `${Math.round(abs / 60)}m` : abs < 129600 ? `${Math.round(abs / 3600)}h` : `${Math.round(abs / 86400)}d`;
  return d < 0 ? `${unit} ago` : `in ${unit}`;
}

/** envelopeBehind reports whether a staff input changed after the issued
 *  envelope, i.e. the change is not yet in a signed document. */
export function envelopeBehind(inputUpdatedAt: string, issuedAt: string | null | undefined): boolean {
  if (!issuedAt) return true;
  return new Date(inputUpdatedAt).getTime() > new Date(issuedAt).getTime();
}

/** matchesOrgQuery is the org list's text filter: name, slug, id or host. */
export function matchesOrgQuery(o: { display_name: string; slug: string; org_id: string; host_id?: string }, q: string): boolean {
  const needle = q.trim().toLowerCase();
  if (needle === "") return true;
  return [o.display_name, o.slug, o.org_id, o.host_id ?? ""].some((v) => v.toLowerCase().includes(needle));
}

/** reasonError checks a staff reason the way staffauth.ValidateReason does:
 *  present, at most max characters, no control character but a line break or
 *  a tab. */
export function reasonError(reason: string, max = 1000): string | null {
  const r = reason.trim();
  if (r === "") return "A reason is required for every change; it is kept in the staff log.";
  if ([...r].length > max) return `The reason is longer than ${max} characters.`;
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u0008\u000b-\u001f\u007f]/.test(r)) return "The reason contains a control character.";
  return null;
}

// ---- the change dialog -------------------------------------------------------

export interface ChangeFormInput {
  reason: string;
  /** confirmed: the staff member ticked "I have checked this change". */
  confirmed: boolean;
  /** ready: a fresh passkey assertion and a CSRF token are in hand. */
  ready: boolean;
  busy: boolean;
  /** blocking: the change's own validation errors. */
  blocking: string[];
  confirmLabel: string;
  maxReason?: number;
}

/** changeFormView is the one rule every staff write's confirmation follows:
 *  the change must be valid, a reason given, the change ticked as checked;
 *  without a fresh passkey the button says it will ask for one first. */
export function changeFormView(i: ChangeFormInput): { reasonError: string | null; canSubmit: boolean; submitLabel: string } {
  const reasonErr = i.reason.trim() === "" ? null : reasonError(i.reason, i.maxReason);
  const canSubmit = !i.busy && i.blocking.length === 0 && reasonError(i.reason, i.maxReason) === null && i.confirmed;
  const submitLabel = i.busy ? "Applying..." : i.ready ? i.confirmLabel : `Verify passkey and ${i.confirmLabel.toLowerCase()}`;
  return { reasonError: reasonErr, canSubmit, submitLabel };
}
