// Issuing the availability envelope, and the per-org component switches
// (lane fix/sr-17-staff-control). Staff writes change the INPUTS only; the
// signed envelope that hosts apply changes only when staff review the
// difference (GET /staff/api/availability/preview) and issue it (POST
// /staff/api/availability/issue), which a worker then signs, stores and
// delivers to every host. These rules turn the preview into what the console
// shows: the changes as readable lines, each host's delivery state, the last
// request's outcome, when "Review and issue" may be pressed (and why not),
// how often to poll, and what a per-org component row says.
// Pure: no fetch, no React.

import { ALL_ORGS, PLATFORM_KEY, describeOrgControl, describeReach, type Section } from "./envelope.ts";
import { shortId, type Tone } from "./model.ts";

// ---- wire types (GET /staff/api/availability/preview) ----------------------

export type ChangeKind = "added" | "removed" | "changed";

/** EnvelopeChange is one section/key that differs between the newest issued
 *  body and the next one; before/after are that body row (or null). */
export interface EnvelopeChange {
  section: Section | string;
  key: string;
  kind: ChangeKind | string;
  before: unknown;
  after: unknown;
}

export type IssueState = "pending" | "issued" | "stale" | "failed";

/** IssueRequest is one staff request to issue the envelope. */
export interface IssueRequest {
  request_id: string;
  requested_by: string;
  reason: string;
  requested_at: string;
  base_version: number;
  state: IssueState | string;
  result_version?: number | null;
  error_class?: string;
  done_at?: string | null;
}

export type DeliveryState = "delivered" | "retry" | "refused";

/** HostDelivery is the newest envelope version one host acknowledged
 *  (delivered), is being sent (retry) or refused. */
export interface HostDelivery {
  host_id: string;
  version: number;
  state: DeliveryState | string;
  attempts: number;
  error_class?: string;
  updated_at: string;
}

export interface AvailabilityPreview {
  /** base_version is the newest issued envelope's version (0: none yet). */
  base_version: number;
  inputs_digest: string;
  /** body is the next envelope's body; null while problems exist. */
  body: unknown;
  problems: string[];
  changes: EnvelopeChange[];
  pending: IssueRequest | null;
  last_request: IssueRequest | null;
  deliveries: HostDelivery[];
}

/** normalizePreview fills the lists a server may send as null. */
export function normalizePreview(raw: Partial<AvailabilityPreview> | null | undefined): AvailabilityPreview {
  const r = raw ?? {};
  return {
    base_version: r.base_version ?? 0,
    inputs_digest: r.inputs_digest ?? "",
    body: r.body ?? null,
    problems: r.problems ?? [],
    changes: r.changes ?? [],
    pending: r.pending ?? null,
    last_request: r.last_request ?? null,
    deliveries: r.deliveries ?? [],
  };
}

// ---- wire types (GET /staff/api/orgs/{id}/components) ----------------------

export interface OrgComponentToggle {
  /** on is the state the button moves this org to. */
  on: boolean;
  /** value is the components input the button writes (null: row removed). */
  value: unknown;
  /** error, when not empty, is why the button cannot act. */
  error: string;
}

export interface OrgComponentRow {
  component: string;
  title: string;
  /** issued: the newest issued envelope offers it to this org. */
  issued: boolean;
  /** next: the next envelope (the inputs now) would. */
  next: boolean;
  input: unknown;
  toggle: OrgComponentToggle;
}

export interface OrgComponents {
  org_id: string;
  base_version: number;
  components: OrgComponentRow[];
}

/** normalizeOrgComponents fills the list a server may send as null. */
export function normalizeOrgComponents(raw: Partial<OrgComponents> | null | undefined): OrgComponents {
  const r = raw ?? {};
  return {
    org_id: r.org_id ?? "",
    base_version: r.base_version ?? 0,
    components: (r.components ?? []).map((c) => ({
      ...c,
      input: c.input ?? null,
      toggle: { on: !!c.toggle?.on, value: c.toggle?.value ?? null, error: c.toggle?.error ?? "" },
    })),
  };
}

// ---- error classes ------------------------------------------------------------

/** ERROR_CLASS_WORDS: an error class (or its prefix) to plain words, walked
 *  top-down; the first match wins. The class itself follows in parentheses. */
const ERROR_CLASS_WORDS: [string, string][] = [
  // An issue request's classes.
  ["inputs_changed", "the inputs changed after the review"],
  ["version_moved", "another envelope was issued after the review"],
  ["nothing_to_issue", "there was nothing to issue"],
  ["invalid_inputs", "some inputs cannot be composed"],
  ["compose", "the inputs could not be composed"],
  ["sign", "signing failed"],
  ["verify", "the signed envelope did not verify"],
  ["store", "the envelope could not be stored"],
  ["cancelled", "cancelled by staff"],
  // A host delivery's classes.
  ["transport:dial", "could not connect to the host"],
  ["transport:timeout", "the host did not answer in time"],
  ["transport:", "could not reach the host"],
  ["unverified:", "the host's answer could not be verified"],
  ["not_sent:", "not sent to the host"],
  ["refused:invalid", "the host found the envelope invalid"],
  ["refused:", "the host refused the envelope"],
  ["bad_response", "the host answered with something unexpected"],
  ["bad_intent", "the delivery request was malformed"],
];

/** errorClassText is an error class in words, the class in parentheses. */
export function errorClassText(errorClass: string | null | undefined): string {
  const ec = (errorClass ?? "").trim();
  if (ec === "") return "";
  const hit = ERROR_CLASS_WORDS.find(([prefix]) => ec.startsWith(prefix));
  return `${hit ? hit[1] : "failed"} (${ec})`;
}

// ---- the changes, as lines ------------------------------------------------------

export const SECTION_LABELS: Record<string, string> = {
  org_controls: "Org controls",
  components: "Components",
  release_flags: "Release flags",
};

const KIND_VIEW: Record<string, { label: string; tone: Tone }> = {
  added: { label: "added", tone: "accent" },
  changed: { label: "changed", tone: "info" },
  removed: { label: "removed", tone: "neutral" },
};

export interface ItemLabel {
  label: string;
  /** sub is a second, smaller line (an org id under its name). */
  sub?: string;
  mono: boolean;
}

/** itemLabel names a section/key the way the Availability tables do. */
export function itemLabel(section: string, key: string, names?: Map<string, string>): ItemLabel {
  if (section === "org_controls") {
    if (key === PLATFORM_KEY || key === ALL_ORGS) return { label: "Every org (platform-wide)", mono: false };
    const name = names?.get(key);
    return name ? { label: name, sub: key, mono: false } : { label: key, mono: true };
  }
  return { label: key, mono: true };
}

function orgsOf(v: unknown): string[] {
  const o = (v ?? {}) as { reach?: string; orgs?: unknown };
  return o.reach === "named" && Array.isArray(o.orgs) ? o.orgs.filter((x): x is string => typeof x === "string") : [];
}

/** orgDelta is which named orgs a reach row adds and drops. */
export function orgDelta(before: unknown, after: unknown): { added: string[]; removed: string[] } {
  const b = new Set(orgsOf(before));
  const a = new Set(orgsOf(after));
  return { added: [...a].filter((x) => !b.has(x)), removed: [...b].filter((x) => !a.has(x)) };
}

/** describeValue is a body row's setting in plain lines (none for null). */
export function describeValue(section: string, value: unknown): string[] {
  if (value == null) return [];
  if (section === "org_controls") return describeOrgControl(value);
  if (section === "components" || section === "release_flags") return [describeReach(value)];
  return ["Unrecognized row"];
}

function orgList(ids: string[], names?: Map<string, string>, max = 3): string {
  const shown = ids.slice(0, max).map((id) => names?.get(id) ?? shortId(id));
  return ids.length > max ? `${shown.join(", ")} and ${ids.length - max} more` : shown.join(", ");
}

function reasonOf(v: unknown): string {
  const r = (v ?? {}) as { reason?: unknown };
  return typeof r.reason === "string" ? r.reason : "";
}

export interface ChangeView {
  section: string;
  sectionLabel: string;
  item: ItemLabel;
  kindLabel: string;
  kindTone: Tone;
  /** before and after are the row's setting in the issued and the next
   *  envelope (empty: the row is not in that envelope). */
  before: string[];
  after: string[];
  /** reason is the next row's reason (empty when removed or unchanged). */
  reason: string;
  /** note says what changed when the setting reads the same. */
  note: string;
}

/** changeView turns one change into the diff table's row. */
export function changeView(c: EnvelopeChange, names?: Map<string, string>): ChangeView {
  const section = String(c.section);
  const kind = KIND_VIEW[String(c.kind)] ?? { label: String(c.kind), tone: "neutral" as Tone };
  const before = describeValue(section, c.before);
  const after = describeValue(section, c.after);
  if (section === "components" || section === "release_flags") {
    const named = orgsOf(c.after);
    if (c.before == null && named.length > 0) {
      after.push(`Orgs: ${orgList(named, names)}`);
    } else if (c.before != null && c.after != null) {
      const d = orgDelta(c.before, c.after);
      if (d.added.length > 0) after.push(`Adds ${orgList(d.added, names)}`);
      if (d.removed.length > 0) after.push(`Drops ${orgList(d.removed, names)}`);
    }
  }
  const sameSetting = c.before != null && c.after != null && before.join("\n") === after.join("\n");
  const reasonChanged = reasonOf(c.before) !== reasonOf(c.after);
  return {
    section,
    sectionLabel: SECTION_LABELS[section] ?? section,
    item: itemLabel(section, c.key, names),
    kindLabel: kind.label,
    kindTone: kind.tone,
    before,
    after,
    reason: c.after != null && (c.before == null || reasonChanged) ? reasonOf(c.after) : "",
    note: sameSetting ? (reasonChanged ? "Only the reason changed." : "Only the author or a detail changed.") : "",
  };
}

/** changeNamesOrg reports whether a change names one org: its own org
 *  control, or a reach row that lists it (before or after). */
export function changeNamesOrg(c: EnvelopeChange, orgId: string): boolean {
  if (c.section === "org_controls") {
    const org = (v: unknown) => ((v ?? {}) as { org?: unknown }).org;
    return c.key === orgId || org(c.before) === orgId || org(c.after) === orgId;
  }
  return orgsOf(c.before).includes(orgId) || orgsOf(c.after).includes(orgId);
}

/** pendingSummary is the card's headline: what is not issued yet. */
export function pendingSummary(p: AvailabilityPreview, orgId?: string): { text: string; tone: Tone } {
  const n = p.changes.length;
  if (n > 0) {
    let text = `${n} change${n === 1 ? " is" : "s are"} not issued yet`;
    if (orgId) {
      const m = p.changes.filter((c) => changeNamesOrg(c, orgId)).length;
      if (m > 0) text += `, ${m === n && n > 1 ? "all" : m} naming this org`;
    }
    return { text, tone: "warn" };
  }
  if (p.problems.length > 0) return { text: "Some inputs cannot be issued", tone: "danger" };
  if (p.base_version === 0) return { text: "No envelope issued yet, and no input to issue", tone: "neutral" };
  return { text: "Everything is issued", tone: "success" };
}

// ---- "Review and issue" -----------------------------------------------------------

/** ISSUE_RULES: why an issue cannot be sent now, walked top-down; the first
 *  match is the button's reason. The server refuses the same cases. */
const ISSUE_RULES: { when: (p: AvailabilityPreview) => boolean; reason: string }[] = [
  { when: (p) => p.problems.length > 0, reason: "Fix or remove the inputs with problems first." },
  { when: (p) => p.pending !== null, reason: "An issue is already waiting for the worker." },
  { when: (p) => p.changes.length === 0, reason: "Nothing to issue: every input is in the issued envelope." },
];

export interface IssueGate {
  /** show: this role can ever issue (support reads the card only). */
  show: boolean;
  enabled: boolean;
  /** reason is why the button is off (null when it is on or hidden). */
  reason: string | null;
}

/** issueGate decides the "Review and issue" button. */
export function issueGate(preview: AvailabilityPreview | null, mayIssue: boolean): IssueGate {
  if (!mayIssue) return { show: false, enabled: false, reason: null };
  if (!preview) return { show: true, enabled: false, reason: "Loading the changes." };
  const hit = ISSUE_RULES.find((r) => r.when(preview));
  return hit ? { show: true, enabled: false, reason: hit.reason } : { show: true, enabled: true, reason: null };
}

/** issueBlocking is every rule an issue breaks (the dialog's blocking list). */
export function issueBlocking(preview: AvailabilityPreview): string[] {
  return ISSUE_RULES.filter((r) => r.when(preview)).map((r) => r.reason);
}

/** cancelGate: ops and admin may cancel the pending request (support reads
 *  only). The server refuses a request that is no longer pending. */
export function cancelGate(pending: IssueRequest | null, mayIssue: boolean): boolean {
  return mayIssue && pending !== null && pending.state === "pending";
}

/** ISSUE_ERRORS: the issue route's refusals in words (the code follows). */
const ISSUE_ERRORS: Record<string, string> = {
  inputs_changed: "The inputs or the issued envelope changed since this review. The list now shows the current changes: check them again.",
  nothing_to_issue: "Nothing to issue: every input is already in the issued envelope.",
  issue_pending: "Another issue request is already waiting for the worker. If it has waited for minutes, withdraw it on the card.",
  invalid_inputs: "Some inputs cannot be composed: fix or remove them first.",
  reason_required: "A reason is required.",
  not_pending: "This request is no longer waiting: the worker finished it or someone cancelled it. The card now shows its outcome.",
  not_found: "That issue request does not exist.",
};

/** issueErrorText is a refusal in words, else the server's message. */
export function issueErrorText(code: string, fallback: string): string {
  return ISSUE_ERRORS[code] ?? fallback;
}

/** COMPONENT_ERRORS: the per-org switch's refusals in words. */
const COMPONENT_ERRORS: Record<string, string> = {
  no_change: "This org is already in that state. The card now shows the current state.",
  not_found: "That org or component no longer exists.",
};

/** componentErrorText is a switch refusal in words, else the server's message. */
export function componentErrorText(code: string, fallback: string): string {
  return COMPONENT_ERRORS[code] ?? fallback;
}

// ---- requests and deliveries ---------------------------------------------------------

/** CANCELLED_CLASS is the error class of a request staff cancelled while it
 *  was pending (POST /staff/api/availability/issue/{id}/cancel). */
export const CANCELLED_CLASS = "cancelled";

/** requestView is one issue request's outcome in words. */
export function requestView(r: IssueRequest): { label: string; tone: Tone; text: string } {
  if (r.state === "failed" && r.error_class === CANCELLED_CLASS) {
    return { label: "cancelled", tone: "neutral", text: "Cancelled by staff before the worker issued it. Nothing was signed or sent." };
  }
  switch (r.state) {
    case "pending":
      return { label: "waiting", tone: "info", text: "Waiting for the worker to sign and store the envelope." };
    case "issued":
      return { label: "issued", tone: "success", text: `Issued v${r.result_version ?? "?"}.` };
    case "stale":
      return {
        label: "not issued",
        tone: "warn",
        text: "Not issued: the inputs or the issued envelope changed after the review. Review again.",
      };
    case "failed":
      return { label: "failed", tone: "danger", text: `Failed: ${errorClassText(r.error_class) || "no reason recorded"}.` };
    default:
      return { label: String(r.state), tone: "neutral", text: `State ${r.state}.` };
  }
}

export type DeliveryClass = "current" | "behind" | "retrying" | "refused" | "unknown";

/** DELIVERY_RULES: a host's delivery row to its class, top-down. A host is
 *  current when it acknowledged the newest issued version. */
const DELIVERY_RULES: { when: (d: HostDelivery, base: number) => boolean; cls: DeliveryClass }[] = [
  { when: (d) => d.state === "refused", cls: "refused" },
  { when: (d) => d.state === "retry", cls: "retrying" },
  { when: (d, base) => d.state === "delivered" && d.version >= base, cls: "current" },
  { when: (d) => d.state === "delivered", cls: "behind" },
];

export function classifyDelivery(d: HostDelivery, baseVersion: number): DeliveryClass {
  return DELIVERY_RULES.find((r) => r.when(d, baseVersion))?.cls ?? "unknown";
}

const DELIVERY_TONE: Record<DeliveryClass, Tone> = {
  current: "success",
  behind: "warn",
  retrying: "warn",
  refused: "danger",
  unknown: "neutral",
};

export interface DeliveryView {
  cls: DeliveryClass;
  label: string;
  tone: Tone;
  /** version is what the host holds, is being sent or refused. */
  version: string;
  detail: string;
}

/** deliveryView is one host's row in the delivery table. */
export function deliveryView(d: HostDelivery, baseVersion: number): DeliveryView {
  const cls = classifyDelivery(d, baseVersion);
  const v = `v${d.version}`;
  const tries = d.attempts > 1 ? `, attempt ${d.attempts}` : "";
  switch (cls) {
    case "current":
      return { cls, label: "current", tone: DELIVERY_TONE[cls], version: `holds ${v}`, detail: "" };
    case "behind":
      return { cls, label: "behind", tone: DELIVERY_TONE[cls], version: `holds ${v}`, detail: `The newest is v${baseVersion}.` };
    case "retrying":
      return {
        cls,
        label: "retrying",
        tone: DELIVERY_TONE[cls],
        version: `sending ${v}`,
        detail: `${errorClassText(d.error_class) || "sending again"}${tries}`,
      };
    case "refused":
      return { cls, label: "refused", tone: DELIVERY_TONE[cls], version: `refused ${v}`, detail: errorClassText(d.error_class) || "no reason recorded" };
    default:
      return { cls, label: "unknown", tone: DELIVERY_TONE[cls], version: v, detail: `State ${d.state}.` };
  }
}

// ---- polling ---------------------------------------------------------------------------

/** ISSUE_POLL_MS is how often the preview is read while an issue is in flight. */
export const ISSUE_POLL_MS = 2000;
/** SETTLE_MS is how long after an issue the console keeps reading the
 *  preview while hosts take the new envelope. */
export const SETTLE_MS = 60_000;

/** issuePollMs: poll while a request is pending, and for a short settling
 *  window after one finished while some host is not current yet; else not. */
export function issuePollMs(p: AvailabilityPreview | null, settling: boolean): number {
  if (!p) return 0;
  if (p.pending) return ISSUE_POLL_MS;
  if (settling && (p.deliveries.length === 0 || p.deliveries.some((d) => classifyDelivery(d, p.base_version) !== "current"))) {
    return ISSUE_POLL_MS;
  }
  return 0;
}

// ---- per-org components ------------------------------------------------------------------

export interface ComponentView {
  /** headline is what the org's host has now (the issued envelope). */
  headline: string;
  headlineTone: Tone;
  issuedLabel: string;
  issuedText: string;
  nextLabel: string;
  nextText: string;
  /** differs: the inputs say otherwise than the issued envelope. */
  differs: boolean;
  buttonLabel: string;
  /** disabledReason is why the button cannot act (null when it can). */
  disabledReason: string | null;
  /** afterText says what the button leaves in the inputs. */
  afterText: string;
}

/** componentView is one per-org component row (off is the default). */
export function componentView(row: OrgComponentRow, baseVersion: number): ComponentView {
  const offered = (b: boolean) => (b ? "offered" : "not offered");
  const issuedOn = baseVersion > 0 && row.issued;
  return {
    headline: issuedOn ? "On for this org" : "Off for this org",
    headlineTone: issuedOn ? "success" : "neutral",
    issuedLabel: baseVersion > 0 ? `Issued envelope (v${baseVersion})` : "Issued envelope",
    issuedText: baseVersion > 0 ? offered(row.issued) : "none issued yet",
    nextLabel: "Next envelope (inputs)",
    nextText: offered(row.next),
    differs: issuedOn !== row.next,
    buttonLabel: row.toggle.on ? "Turn on for this org" : "Turn off for this org",
    disabledReason: row.toggle.error.trim() === "" ? null : row.toggle.error,
    afterText:
      row.toggle.value == null
        ? "The component's input row is removed, so the stage default applies."
        : `The component's input becomes: ${describeReach(row.toggle.value)}.`,
  };
}
