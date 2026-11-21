// cloudAgents.ts - the PURE half of Settings > Connected tools > Cloud agents
// (cloud-agents lane CA-B5, docs/cloud-agents.md "Dashboard API"): the wire
// types of /api/cloud-agents*, the closed vocabularies mapped to labels and
// tones (glyphs live in shared/lib/vocabIcons.ts), and the derivations the
// card renders. No React, no fetch: importable under `node --test`.
//
// HONESTY RULES this file owns:
//   - A figure the server did not send is never drawn as 0 or "never": the
//     text helpers return null and the card says what is missing.
//   - An error is shown by its class (the closed vocabulary the server
//     stores), with a plain sentence; vendor text is never kept server-side.
//   - A member-scoped account with no user chosen pulls nothing, and every
//     surface says so; there is no "everything" fallback.
//   - The member-users capability is read from the catalog (chooses_user),
//     never from a connector id.

import type { VocabEntry } from "../../../shared/lib/vocabEntry.ts";

// --- wire types ---------------------------------------------------------------

export type CloudAgentSignal = {
  signal: string;
  state: string;
  label: string;
};

export type CloudAgentParamChoice = { value: string; label: string };

export type CloudAgentParam = {
  name: string;
  label: string;
  hint: string;
  choices?: CloudAgentParamChoice[];
};

export type CloudAgentConnector = {
  id: string;
  label: string;
  provider: string;
  tool: string;
  kind: "cli" | "api" | string;
  command?: string;
  experimental: boolean;
  surface_host?: string;
  placeholder_project: string;
  placeholder_note: string;
  signals: CloudAgentSignal[];
  doc_ref: string;
  needs_key: boolean;
  key_label?: string;
  params: CloudAgentParam[] | null;
  hosts?: string[];
  grounding: string;
  grounding_label: string;
  grounding_rank: number;
  grounding_meaning: string;
  chooses_user: boolean;
  user_label?: string;
};

export type CloudAgentGap = { from: string; to: string; scope?: string };

export type CloudAgentAccount = {
  id: number;
  connector: string;
  label: string;
  provider: string;
  account_id: string;
  display?: string;
  coverage: string;
  last_error?: string;
  last_attempt?: string;
  last_success?: string;
  gaps: CloudAgentGap[] | null;
  activity_gaps: number;
  open_tasks: number;
  waiting: number;
  owed: number;
  signals: CloudAgentSignal[] | null;
  linked_at: string;
  user_state?: string;
  vendor_user?: string;
  purge_pending?: boolean;
};

export type CloudAgentsView = {
  generated_at: string;
  connectors: CloudAgentConnector[] | null;
  accounts: CloudAgentAccount[] | null;
};

export type CloudAgentsResponse = { view: CloudAgentsView; confirm_token: string };

export type CloudAgentProbe = {
  connector: string;
  ok: boolean;
  account_id?: string;
  display?: string;
  coverage: string;
  error_class?: string;
};

export type CloudAgentSync = {
  account: number;
  connector: string;
  pages: number;
  tasks: number;
  sessions_touched: number;
  actions_inserted: number;
  partial: boolean;
  coverage: string;
  error_class?: string;
  open_tasks: number;
  waiting: number;
  owed: number;
  user_state?: string;
  purged_other_member?: number;
};

export type CloudAgentProbeResponse = { probe: CloudAgentProbe };
export type CloudAgentConnectResponse = {
  probe: CloudAgentProbe;
  account: CloudAgentAccount | null;
  sync?: CloudAgentSync;
};
export type CloudAgentSyncResponse = { sync: CloudAgentSync };
export type CloudAgentSyncAllResponse = { syncs: CloudAgentSync[] | null };

export type CloudAgentUserCandidate = { user_id: string; username?: string; sessions: number };

export type CloudAgentUsers = {
  account: number;
  connector: string;
  user_label: string;
  chosen?: string;
  candidates: CloudAgentUserCandidate[] | null;
  more: boolean;
  service_user_sessions: number;
  no_user_sessions: number;
  message_reads: number;
  error_class?: string;
};

export type CloudAgentUsersResponse = { users: CloudAgentUsers };
export type CloudAgentChooseResponse = { account: CloudAgentAccount; sync?: CloudAgentSync };

// --- routes -------------------------------------------------------------------

export const CLOUD_AGENTS_PATH = "/api/cloud-agents";
export const CLOUD_AGENTS_TEST_PATH = "/api/cloud-agents/test";
export const CLOUD_AGENTS_CONNECT_PATH = "/api/cloud-agents/connect";
export const CLOUD_AGENTS_SYNC_ALL_PATH = "/api/cloud-agents/sync";

export type AccountVerb = "sync" | "disconnect" | "users" | "user";

/** accountPath is the per-account POST route for one verb. */
export function accountPath(id: number, verb: AccountVerb): string {
  return `/api/cloud-agents/accounts/${encodeURIComponent(String(id))}/${verb}`;
}

/** CLOUD_AGENTS_HREF opens Settings > Connected tools at the Cloud agents card. */
export const CLOUD_AGENTS_HREF = "/settings?section=tools&open=cloud-agents";

// --- vocabularies -------------------------------------------------------------

/** A vocabulary row with the sentence its tooltip says. */
export type CloudAgentEntry = VocabEntry & { tip: string };

/** COVERAGE: the closed coverage vocabulary (internal/cloudagents/coverage.go). */
export const COVERAGE: Readonly<Record<string, CloudAgentEntry>> = {
  verified: { tone: "success", label: "Verified", tip: "A supported feed passed a test for this account." },
  available_to_configure: {
    tone: "info",
    label: "Available to configure",
    tip: "A documented path exists; some setup remains before anything is read.",
  },
  permission_required: {
    tone: "warn",
    label: "Permission required",
    tip: "A role, plan or vendor setting blocks collection.",
  },
  partial_history: {
    tone: "warn",
    label: "Partial history",
    tip: "Some events were retrieved; a known interval or kind of detail is missing.",
  },
  delayed_reporting: {
    tone: "info",
    label: "Delayed reporting",
    tip: "The vendor reports this on its own schedule, so it arrives later.",
  },
  not_established: {
    tone: "neutral",
    label: "Not established",
    tip: "Nothing yet shows that this works for this account.",
  },
  disconnected: {
    tone: "danger",
    label: "Disconnected",
    tip: "The login, key or connection no longer allows collection.",
  },
};

/** ERROR_CLASS: the closed error-class vocabulary a failed call is stored as. */
export const ERROR_CLASS: Readonly<Record<string, CloudAgentEntry>> = {
  not_installed: { tone: "warn", label: "CLI not installed", tip: "The vendor's command line tool is not on this machine." },
  not_signed_in: {
    tone: "warn",
    label: "Not signed in",
    tip: "The vendor CLI has no usable login, or the stored key is missing. Sign in to the vendor tool, or connect again with a key.",
  },
  permission_denied: {
    tone: "danger",
    label: "Permission denied",
    tip: "The account lacks the plan, role or feature this needs, or the key was refused.",
  },
  rate_limited: { tone: "warn", label: "Rate limited", tip: "The vendor asked Observer to slow down. The next pass retries later." },
  unreachable: { tone: "warn", label: "Unreachable", tip: "The vendor could not be reached (network, DNS or TLS)." },
  server_error: { tone: "warn", label: "Vendor server error", tip: "The vendor's side failed. The next pass retries." },
  timeout: { tone: "warn", label: "Timed out", tip: "The call ran past its time limit." },
  wrong_shape: {
    tone: "danger",
    label: "Unexpected reply",
    tip: "The vendor's reply did not match the recorded format; the vendor may have changed it.",
  },
  over_cap: { tone: "warn", label: "Reply too large", tip: "The vendor's reply was larger than Observer accepts." },
  host_not_allowed: { tone: "danger", label: "Host not allowed", tip: "A link outside the connector's allowed hosts was refused." },
  invalid: { tone: "danger", label: "Invalid request", tip: "Observer refused to build the request (a bad id or value)." },
  stream_expired: {
    tone: "info",
    label: "Stream expired",
    tip: "A run's event history passed the vendor's retention window; the missing interval is shown as a gap.",
  },
  stream_resume_refused: {
    tone: "info",
    label: "Stream restarted",
    tip: "The vendor refused to resume a run's events; they are read again from the start.",
  },
  failed: { tone: "danger", label: "Failed", tip: "The call failed for a reason the vendor did not name." },
};

/** GROUNDING: how well the vendor surface a connector reads is established.
 *  The label and meaning come from the catalog; only the tone is ours. */
export const GROUNDING: Readonly<Record<string, VocabEntry>> = {
  live_verified: { tone: "success" },
  documented: { tone: "info" },
  observed_undocumented: { tone: "warn" },
};

/** USER_STATE: a member-scoped account's vendor-user state. */
export const USER_STATE: Readonly<Record<string, CloudAgentEntry>> = {
  vendor_user_not_chosen: {
    tone: "warn",
    label: "No user chosen",
    tip: "Nothing is pulled until you choose your own user from the list.",
  },
  vendor_user_chosen: { tone: "success", label: "User chosen", tip: "Only this user's sessions are pulled." },
};

/** SIGNAL_LABEL: the signals a connector reports separately, in plain words. */
export const SIGNAL_LABEL: Readonly<Record<string, string>> = {
  discovery: "Finds sessions",
  identity: "Who started it",
  activity: "Activity detail",
  tokens: "Tokens",
  usage: "Usage units",
  billing: "Billing",
  control: "Control",
};

/** errorEntry resolves an error class; an unknown class keeps its raw token as
 *  the label (unknown is never guessed into a known one). */
export function errorEntry(cls: string): CloudAgentEntry {
  return ERROR_CLASS[cls] ?? { tone: "danger", label: cls, tip: "An error this dashboard does not know yet." };
}

/** coverageEntry resolves a coverage state the same way. */
export function coverageEntry(state: string): CloudAgentEntry {
  return COVERAGE[state] ?? { tone: "neutral", label: state || "Unknown", tip: "A coverage state this dashboard does not know yet." };
}

// --- connect form -------------------------------------------------------------

/** paramControl is how a connector parameter is entered: a picker when the
 *  catalog gives its closed list of choices, else a text field (an open value
 *  such as an organization id the vendor cannot list for us). */
export function paramControl(p: CloudAgentParam): "select" | "text" {
  return p.choices && p.choices.length > 0 ? "select" : "text";
}

/** connectorParams normalises a connector's (nullable) parameter list. */
export function connectorParams(c: CloudAgentConnector | undefined): CloudAgentParam[] {
  return c?.params ?? [];
}

/** needsLabel lists what connecting a connector asks for, in plain words. */
export function needsLabel(c: CloudAgentConnector): string {
  const parts: string[] = [];
  if (c.needs_key) parts.push("an API key");
  else if (c.command) parts.push(`your signed-in ${c.command} CLI`);
  else parts.push("your signed-in vendor CLI");
  for (const p of connectorParams(c)) parts.push(p.label.toLowerCase());
  if (c.chooses_user) parts.push(`choosing your ${c.user_label || "user"}`);
  return parts.length === 1 ? parts[0] : `${parts.slice(0, -1).join(", ")} and ${parts[parts.length - 1]}`;
}

export type FormCheck = { ok: true } | { ok: false; reason: string };

/** checkConnectForm says whether the connect form can be sent, and if not,
 *  names the missing field in plain words (the button's tooltip). */
export function checkConnectForm(
  c: CloudAgentConnector | undefined,
  key: string,
  params: Readonly<Record<string, string>>,
): FormCheck {
  if (!c) return { ok: false, reason: "Choose a connector." };
  if (c.needs_key) {
    const k = key.trim();
    if (!k) return { ok: false, reason: "Paste the API key." };
    if (/\s/.test(k)) return { ok: false, reason: "The key cannot contain spaces or line breaks." };
  }
  for (const p of connectorParams(c)) {
    const v = (params[p.name] ?? "").trim();
    if (!v) return { ok: false, reason: paramControl(p) === "select" ? `Choose the ${p.label.toLowerCase()}.` : `Enter the ${p.label.toLowerCase()}.` };
    if (paramControl(p) === "select" && !p.choices!.some((ch) => ch.value === v)) {
      return { ok: false, reason: `Choose the ${p.label.toLowerCase()} from the list.` };
    }
  }
  return { ok: true };
}

/** connectBody is the POST body of the test and connect routes. The key is
 *  sent only for a connector that needs one, trimmed, and only in the body. */
export function connectBody(
  c: CloudAgentConnector,
  key: string,
  params: Readonly<Record<string, string>>,
): { connector: string; key?: string; params?: Record<string, string> } {
  const out: { connector: string; key?: string; params?: Record<string, string> } = { connector: c.id };
  if (c.needs_key) out.key = key.trim();
  const ps = connectorParams(c);
  if (ps.length > 0) {
    out.params = {};
    for (const p of ps) out.params[p.name] = (params[p.name] ?? "").trim();
  }
  return out;
}

/** probeText is one sentence for a test or connect probe. */
export function probeText(p: CloudAgentProbe): string {
  if (p.ok) {
    const who = p.display || p.account_id;
    return who ? `It works: reached ${who}.` : "It works.";
  }
  const e = errorEntry(p.error_class || "failed");
  return `Check failed: ${e.label}. ${e.tip}`;
}

// --- accounts -----------------------------------------------------------------

/** connectorFor finds an account's catalog row (undefined for a row a newer
 *  build linked: shown, never synced). */
export function connectorFor(view: CloudAgentsView | undefined, id: string): CloudAgentConnector | undefined {
  return (view?.connectors ?? []).find((c) => c.id === id);
}

/** accountName is the account's own name: the vendor's display, else its id. */
export function accountName(a: CloudAgentAccount): string {
  return a.display || a.account_id;
}

/** lastPassText says when the last pass ran and whether it succeeded; null
 *  when no pass was ever recorded (never drawn as a time or a zero). */
export function lastPassText(a: CloudAgentAccount, fmt: (iso: string) => string): string | null {
  if (!a.last_attempt) return null;
  const tried = fmt(a.last_attempt);
  if (a.last_success && Date.parse(a.last_success) >= Date.parse(a.last_attempt)) return `Last pass ${tried}, succeeded`;
  if (a.last_success) return `Last pass ${tried}, failed; last success ${fmt(a.last_success)}`;
  return `Last pass ${tried}, no success yet`;
}

/** needsUser is true when the account's connector declares member users and
 *  no user is chosen yet: nothing is pulled. */
export function needsUser(a: CloudAgentAccount, c: CloudAgentConnector | undefined): boolean {
  return !!c?.chooses_user && a.user_state === "vendor_user_not_chosen";
}

/** taskCounts is the still-open work line; null when everything is read. */
export function taskCounts(a: { open_tasks: number; waiting: number; owed: number }): string | null {
  const parts: string[] = [];
  if (a.open_tasks > 0) parts.push(`${a.open_tasks} running`);
  if (a.waiting > 0) parts.push(`${a.waiting} waiting for you`);
  if (a.owed > 0) parts.push(`${a.owed} finished with a read still owed`);
  return parts.length ? parts.join(", ") : null;
}

/** gapText names the uncovered intervals; null when there are none. */
export function gapText(a: CloudAgentAccount): string | null {
  const gaps = a.gaps ?? [];
  if (gaps.length === 0) return null;
  const discovery = gaps.filter((g) => !g.scope).length;
  const runs = gaps.length - discovery;
  const parts: string[] = [];
  if (discovery > 0) parts.push(`${discovery} discovery gap${discovery === 1 ? "" : "s"}`);
  if (runs > 0) parts.push(`${runs} run stream${runs === 1 ? "" : "s"} could not be resumed`);
  return parts.join(", ");
}

/** syncText is one sentence for a pass result. */
export function syncText(s: CloudAgentSync): string {
  if (s.user_state === "vendor_user_not_chosen") return "Nothing pulled: choose your user first.";
  if (s.error_class) {
    const e = errorEntry(s.error_class);
    return `Pass failed: ${e.label}. ${e.tip}`;
  }
  const found = `${s.tasks} session${s.tasks === 1 ? "" : "s"} seen, ${s.sessions_touched} updated`;
  const purged = s.purged_other_member ? `, ${s.purged_other_member} from other members removed` : "";
  return `Pass done: ${found}${purged}${s.partial ? " (partial)" : ""}.`;
}

// --- user picker --------------------------------------------------------------

export type UserOption = { value: string; label: string };

/** userOptions builds the picker's options: each candidate by username (its
 *  id when the username could not be read) and its session count on the
 *  first page; the current choice stays listed even when the first page did
 *  not report it, so the picker never silently drops it. */
export function userOptions(u: CloudAgentUsers): UserOption[] {
  const out: UserOption[] = (u.candidates ?? []).map((c) => ({
    value: c.user_id,
    label: `${c.username || c.user_id} (${c.sessions} session${c.sessions === 1 ? "" : "s"} on the first page)`,
  }));
  if (u.chosen && !out.some((o) => o.value === u.chosen)) {
    out.unshift({ value: u.chosen, label: `${u.chosen} (current choice, not on the first page)` });
  }
  return out;
}

/** userNotes are the picker's hints: more pages, and sessions no person
 *  started (never offered, never pulled). */
export function userNotes(u: CloudAgentUsers): string[] {
  const out: string[] = [];
  if (u.more) out.push("Only users with a session on the first page are listed. If you are not listed, start a session and list again.");
  if (u.service_user_sessions > 0) {
    out.push(
      `${u.service_user_sessions} listed session${u.service_user_sessions === 1 ? " was" : "s were"} started by a service user; those are never pulled.`,
    );
  }
  if (u.no_user_sessions > 0) {
    out.push(`${u.no_user_sessions} listed session${u.no_user_sessions === 1 ? " names" : "s name"} no user; those are never pulled.`);
  }
  return out;
}
