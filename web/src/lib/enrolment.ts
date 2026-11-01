// enrolment.ts - Settings > Enrolment management (backlog item 6): the wire
// types of /api/enrolment/{manage,grant,probe,enrol,grant-decision,idp/*,
// push-now,leave} and the pure decisions the EnrolmentSection makes on them.
//
// Every authority decision is the daemon's: it runs the same Go code paths as
// `observer enroll` / `observer org ...` / `observer unenroll`, and re-checks
// every input (internal/orgenrol). The checks here only keep the submit
// button honest and put a field-level message next to the right field before
// a round trip; the server's message always wins when it answers.

export type EnrolMethod = "code" | "link" | "idp";

export type EnrolNoteLevel = "ok" | "info" | "warn";

export type EnrolNote = { level: EnrolNoteLevel; text: string };

export type AuthorityLine = { token: string; text: string };

/** The governance-grant consent screen, rendered from the same data the CLI prompt prints. */
export type GrantDisclosure = {
  intro: string;
  /** What the screen calls the organization (the daemon's display name, never an id). */
  org_display?: string;
  org_id: string;
  server_url: string;
  expires_at?: string;
  managed: boolean;
  may: AuthorityLine[] | null;
  config_writes?: string[] | null;
  families?: string[] | null;
  config_writes_note?: string;
  may_not: string[] | null;
};

export type PendingGrant = {
  offer_id: string;
  expires_at: string;
  disclosure: GrantDisclosure;
};

export type EnrolTableCount = { table: string; historical: number; eligible: number };

export type EnrolmentOverview = {
  enrolled: boolean;
  org_id?: string;
  org_name?: string;
  org_display?: string;
  org_server_url?: string;
  user_email?: string;
  enrolled_at?: string;
  credential_store?: string;
  tenancy?: string;
  /** Set when the daemon of a managed enrolment signs no machine proof. */
  machine_proof_warning?: string;
  /** Set when a running daemon cannot read the org credential, so it does not push. */
  daemon_credential_warning?: string;
  pushing_enabled: boolean;
  push_loop_running: boolean;
  /** The configured push ceiling in seconds (`observer org push-status`). */
  push_interval_seconds?: number;
  share_mode?: string;
  share_mode_line?: string;
  target_actions?: string[] | null;
  governance_warning?: string;
  governed: boolean;
  tables?: EnrolTableCount[] | null;
  pending_resends?: Record<string, number> | null;
  pending_deletions?: number;
  pending_manifests?: number;
  eligible_reason?: string;
  last_push?: { pushed_at: string; status: string; row_count: number; bytes: number; error?: string } | null;
  push_paused?: { reason?: string; until: string } | null;
  pending_grant?: PendingGrant | null;
  /** What Leave would do with each AI tool proxy route right now. */
  leave_plan?: EnrolLeaveRoute[] | null;
  /** The structured unenrol's conferred -> retired table, in apply order (T-718). */
  leave_steps?: EnrolLeaveStep[] | null;
};

/** One row of the structured unenrol plan (`observer unenroll --plan`). */
export type EnrolLeaveStep = {
  id: string;
  phase: "fence" | "enforcement" | "notify" | "identity" | "kept";
  conferred: string;
  retired: string;
};

/**
 * One AI tool proxy route in Leave's plan: removed only when this machine's
 * enrolment wrote it and it is unchanged, kept otherwise. `message` is the
 * sentence `observer unenroll` prints for the same route.
 */
export type EnrolLeaveRoute = { tool: string; action: "remove" | "keep"; message: string };

/** ResyncReport is POST /api/enrolment/resync (`observer org resync`). */
export type ResyncReport = {
  window_days: number;
  limit: number;
  tables?: { table: string; queued: number }[] | null;
  queued: number;
  ended_at_checked: number;
  manifests: number;
  manifests_checked: number;
  manifests_too_big: number;
  not_before?: string;
  confirmed: boolean;
};

/**
 * resyncLine is the one sentence the Re-send changed rows card shows for a
 * resync report (T-642): the dry run says what a confirm would queue, a
 * confirmed run what it queued.
 */
export function resyncLine(r: ResyncReport): string {
  const rows = `${r.queued} changed row${r.queued === 1 ? "" : "s"}`;
  const man = `${r.manifests} session${r.manifests === 1 ? "" : "s"} to reconcile deletions`;
  const window = `in the last ${r.window_days} days`;
  if (r.confirmed) {
    return `Queued ${rows} and ${man} ${window}. The push loop sends them over the next pushes.`;
  }
  if (r.queued === 0 && r.manifests === 0) {
    return `Nothing to re-send ${window}: the organization already has this machine's current rows.`;
  }
  return `Re-send would queue ${rows} and ${man} ${window} (at most ${r.limit} rows).`;
}

/**
 * pushCadenceLine is `observer org push-status`'s cadence and next-attempt
 * lines as one sentence (T-642). The next attempt is only promised when this
 * daemon runs the push loop and has pushed before; otherwise it says why not.
 */
export function pushCadenceLine(
  ov: Pick<EnrolmentOverview, "pushing_enabled" | "push_loop_running" | "push_interval_seconds" | "last_push">,
  fmtTime: (iso: string) => string,
): string {
  const secs = ov.push_interval_seconds ?? 0;
  if (!ov.pushing_enabled) return "The push loop is off: [org_client] enabled = false in config.toml.";
  if (!ov.push_loop_running) return "The push loop is not running in this daemon yet; restart it, or use Push now.";
  if (secs <= 0) return "The push loop is running.";
  const every = `Pushes at least every ${secs} s, sooner when new activity arrives.`;
  const last = ov.last_push?.pushed_at ? Date.parse(ov.last_push.pushed_at) : NaN;
  if (Number.isNaN(last)) return `${every} The first push runs within ${secs} s of the daemon starting.`;
  return `${every} Next push by ${fmtTime(new Date(last + secs * 1000).toISOString())}.`;
}

/** leavePlanGroups splits Leave's route plan into what goes and what stays. */
export function leavePlanGroups(plan?: EnrolLeaveRoute[] | null): {
  remove: EnrolLeaveRoute[];
  keep: EnrolLeaveRoute[];
} {
  const rows = plan ?? [];
  return {
    remove: rows.filter((r) => r.action === "remove"),
    keep: rows.filter((r) => r.action !== "remove"),
  };
}

export type ManageResponse = { confirm_token: string; overview: EnrolmentOverview };

export type EnrolProbe = { org_url: string; ok: boolean; message: string };

export type GrantDecision = {
  status: "accepted" | "declined" | "refused" | "consented";
  message: string;
  notes?: EnrolNote[] | null;
};

export type EnrolOutcome = {
  org_id: string;
  org_name: string;
  org_display?: string;
  user_email: string;
  org_server_url: string;
  tenancy: string;
  managed: boolean;
  config_path?: string;
  block_written: boolean;
  full_content: boolean;
  share_summary?: string;
  notes?: EnrolNote[] | null;
  pending_grant?: PendingGrant | null;
  grant?: GrantDecision | null;
  restart_required: boolean;
};

export type IdPStart = {
  flow_id: string;
  user_code: string;
  verification_uri: string;
  expires_in: number;
  interval: number;
};

export type IdPPoll = {
  status: "pending" | "approved" | "denied" | "expired" | "error";
  interval: number;
  message?: string;
  outcome?: EnrolOutcome | null;
};

export type GrantReport = {
  state: "not_enrolled" | "ungoverned" | "governed";
  org_name?: string;
  org_display?: string;
  org_id?: string;
  server_url?: string;
  granted_at?: string;
  expiry_line?: string;
  consent?: string;
  receipt?: string;
  authority?: AuthorityLine[] | null;
  content_line?: string;
  families?: { family: string; accepted: boolean; preauthorized: boolean }[] | null;
  verification?: EnrolNote[] | null;
  pinned?: string[] | null;
};

export type PushNowReport = {
  empty: boolean;
  row_count: number;
  bytes: number;
  accepted: number;
  deduped: number;
  more: boolean;
  message: string;
  notes?: EnrolNote[] | null;
};

export type LeaveReport = { was_enrolled: boolean; org_name?: string; org_display?: string; notes?: EnrolNote[] | null };

export const METHOD_OPTIONS: { value: EnrolMethod; label: string; help: string }[] = [
  {
    value: "code",
    label: "Enrolment code",
    help: "Your admin gave you the server address and a one-time code (two parts joined by a dot).",
  },
  {
    value: "link",
    label: "Enrolment link",
    help: "Your admin shared a link that looks like https://host/enrol/<code>.",
  },
  {
    value: "idp",
    label: "Sign in",
    help: "Sign in with your organization account in a browser, on this or any other device. Enrols this machine as organization-managed.",
  },
];

/** checkServerUrl mirrors orgenrol.NormalizeServerURL closely enough to flag
 *  an obviously wrong value; null means "looks fine". */
export function checkServerUrl(raw: string): string | null {
  const s = raw.trim();
  if (!s) return "Enter the organization server address.";
  if (/\s/.test(s)) return "The address contains spaces.";
  let u: URL;
  try {
    u = new URL(s);
  } catch {
    return "Use a full address starting with https:// (or http:// for a local server).";
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") return "The address must start with https:// or http://.";
  if (!u.hostname) return "The address needs a host name.";
  if (u.username || u.password) return "The address must not contain a user name or password.";
  if (u.search || u.hash) return 'This looks like a link. Choose "Enrolment link" instead.';
  return null;
}

/** checkCode mirrors orgenrol.CheckTokenShape. */
export function checkCode(raw: string): string | null {
  const t = raw.trim();
  if (!t) return "Enter the enrolment code.";
  if (t.includes("://")) return 'That looks like a link. Choose "Enrolment link" instead.';
  if (/\s/.test(t)) return "The code contains spaces or line breaks. Paste it again on one line.";
  const dot = t.indexOf(".");
  if (dot <= 0 || dot === t.length - 1) return "An enrolment code has two parts joined by a dot (id.secret).";
  if (t.length > 512) return "That is too long to be an enrolment code.";
  return null;
}

/** checkLink accepts only the canonical /enrol/<code> magic link. */
export function checkLink(raw: string): string | null {
  const s = raw.trim();
  if (!s) return "Paste the enrolment link.";
  let u: URL;
  try {
    u = new URL(s);
  } catch {
    return "Paste the whole link, starting with https://.";
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") return "The link must start with https:// or http://.";
  const path = u.pathname.replace(/^\/+/, "");
  if (path === "set-password" || path === "login" || u.searchParams.has("token")) {
    return "That is a dashboard sign-in invite, not a machine enrolment link. Open it in a browser to set your password.";
  }
  if (!path.startsWith("enrol/") || path.length <= "enrol/".length) return "An enrolment link looks like https://host/enrol/<code>.";
  return null;
}

export type EnrolForm = { method: EnrolMethod; orgUrl: string; token: string; link: string };

/** formErrors returns the per-field message for the chosen method (only the
 *  fields that method uses). */
export function formErrors(f: EnrolForm): { orgUrl?: string; token?: string; link?: string } {
  switch (f.method) {
    case "link": {
      const link = checkLink(f.link);
      return link ? { link } : {};
    }
    case "idp": {
      const orgUrl = checkServerUrl(f.orgUrl);
      return orgUrl ? { orgUrl } : {};
    }
    default: {
      const out: { orgUrl?: string; token?: string } = {};
      const orgUrl = checkServerUrl(f.orgUrl);
      const token = checkCode(f.token);
      if (orgUrl) out.orgUrl = orgUrl;
      if (token) out.token = token;
      return out;
    }
  }
}

export function canSubmit(f: EnrolForm): boolean {
  return Object.keys(formErrors(f)).length === 0;
}

/** enrolBody builds the POST /api/enrolment/enrol body: only the fields the
 *  method uses ever leave the page. */
export function enrolBody(f: EnrolForm): Record<string, string> {
  if (f.method === "link") return { method: "link", link: f.link.trim() };
  return { method: "code", org_url: f.orgUrl.trim(), token: f.token.trim() };
}

/** apiErrorMessage extracts the server's sentence from a failed call: the
 *  enrolment routes answer {error, message}; anything else falls back to the
 *  raw text or the thrown message. */
export function apiErrorMessage(err: unknown): string {
  const body = (err as { body?: unknown } | null)?.body;
  if (typeof body === "string" && body.trim()) {
    try {
      const parsed = JSON.parse(body) as { message?: string; error?: string };
      if (parsed.message) return parsed.message;
      if (parsed.error) return parsed.error;
    } catch {
      return body.trim().slice(0, 300);
    }
  }
  if (err instanceof Error && err.message) return err.message;
  return String(err);
}

/** pollDelayMs is how long the page waits before the next sign-in poll: the
 *  server's interval, never faster than 2 s. */
export function pollDelayMs(intervalSeconds: number | undefined): number {
  const s = intervalSeconds && intervalSeconds > 0 ? intervalSeconds : 5;
  return Math.max(2, s) * 1000;
}

export type Tone = "success" | "info" | "warn" | "danger" | "neutral";

export const NOTE_TONE: Record<EnrolNoteLevel, Tone> = {
  ok: "success",
  info: "info",
  warn: "warn",
};

export const DECISION_TONE: Record<GrantDecision["status"], Tone> = {
  accepted: "success",
  consented: "success",
  declined: "neutral",
  refused: "warn",
};

export const IDP_STATUS_COPY: Record<IdPPoll["status"], string> = {
  pending: "Waiting for approval in the browser.",
  approved: "Approved. Completing enrolment.",
  denied: "The enrolment was refused in the browser. Nothing was granted and this machine is not enrolled.",
  expired: "The code expired before it was approved. Start again to get a fresh code.",
  error: "The organization answered with a state this version of Observer does not understand.",
};

export function tenancyLabel(tenancy: string | undefined): string {
  return tenancy === "managed" ? "Organization-managed" : "Individual";
}

/** SHARE_MODE_LABEL names the share-mode rule (cmd/observer shareModeRules). */
export const SHARE_MODE_LABEL: Record<string, { text: string; tone: Tone }> = {
  full_content: { text: "Full content (your setting)", tone: "warn" },
  admin_managed: { text: "Full content (admin-managed)", tone: "warn" },
  enterprise_grant: { text: "Full content (organization grant)", tone: "warn" },
  metadata_only: { text: "Metadata only", tone: "success" },
};

export function shareModeLabel(rule: string | undefined): { text: string; tone: Tone } {
  return SHARE_MODE_LABEL[rule ?? ""] ?? { text: "Unknown", tone: "neutral" };
}

/** pendingGrantOf picks the consent screen to show: the one an enrolment just
 *  returned, else the one the daemon still holds (survives a reload). */
export function pendingGrantOf(
  outcome: EnrolOutcome | null,
  overview: EnrolmentOverview | null | undefined,
  decidedOfferIds: ReadonlySet<string>,
): PendingGrant | null {
  for (const p of [outcome?.pending_grant, overview?.pending_grant]) {
    if (p && !decidedOfferIds.has(p.offer_id)) return p;
  }
  return null;
}
