// you.ts is the pure model of the You page (pages/You.tsx) and its top-bar
// avatar chip: wire types of the three /api/me/* routes and the small
// derivations both render. No React, no fetch: node --test imports it.
// Operator reference: docs/you-page.md.

import { PLACES } from "./settingsPlaces.ts";

export type MeToolAccount = {
  email?: string;
  name?: string;
  /** The first 8 characters of the account key, a one-way hash. */
  key?: string;
  first_seen: string;
  last_seen: string;
  sessions: number;
};

export type MeToolAccounts = {
  tool: string;
  accounts: MeToolAccount[];
  multiple_accounts: boolean;
};

export type MeToolAccountsResponse = { tools: MeToolAccounts[] };

export type MeMachine = {
  fingerprint: string;
  source: "os" | "seed" | "hostname" | "none" | string;
  org_bound: boolean;
  host?: string;
  os_user?: string;
};

export type MeCredentialRow = {
  service: string;
  purpose: string;
  owner: string;
  presence: "present" | "absent" | "unknown" | "not_checked" | string;
};

export type MeCredentialsResponse = { checked: boolean; services: MeCredentialRow[] };
/** A withdraw this page can make through an existing route. */
export type ConsentWithdraw =
  | { kind: "intel" }
  | { kind: "cloud"; purpose: string }
  | { kind: "lookup"; change: Record<string, unknown> };

/** One consent the page lists: a stable id, the plain-words title, what is
 *  known about it, and the link to the page that owns accepting it. */
export type ConsentRow = {
  id: string;
  title: string;
  /** "given" and "not_given" are read from the store; "unreadable" means the
   *  read failed; "see_page" means no route lists this consent (it is per
   *  directory or per workspace), so the page says so instead of guessing. */
  state: "given" | "not_given" | "unreadable" | "see_page";
  detail?: string;
  /** ISO time the consent was given, when the store has it. */
  since?: string;
  owner: string;
  /** Set only when an existing route can take this consent back from here. */
  withdraw?: ConsentWithdraw;
};

type LookupConsentLike = { accepted: boolean; accepted_at?: string };

/** What each consent store answered; null means that read failed or is pending. */
export type ConsentInputs = {
  intel: { class?: string; active?: { event?: string; created_at?: string; evidence_level?: string } } | null;
  cloud: { id: string; purpose: string; created_at: string; live: boolean; mode?: string }[] | null;
  lookup: {
    managed: boolean;
    download: LookupConsentLike;
    remote: LookupConsentLike;
    remote_private: LookupConsentLike;
  } | null;
  provenance: { consents: { root: string; notes: boolean; trailer: boolean; given_at?: string }[] } | null;
  grant: { state: string; granted_at?: string; org_display?: string } | null;
  /** [terminal.sandbox].sign_in_seed_tools. */
  signInSeed: string[] | null;
  /** [terminal.sandbox.oci].allow_devcontainer_image. */
  devcontainer: boolean | null;
  /** available false: this build has no community aggregate sharing. */
  aggregate: { available?: boolean; enabled: boolean; status?: string; consented_at?: string } | null;
};

/** Consents no route lists: per directory or per workspace. */
export const CONSENT_PER_SCOPE: ReadonlyArray<Pick<ConsentRow, "id" | "title" | "owner" | "detail">> = [
  { id: "repo-trust", title: "Repository trust", owner: "/code-security", detail: "Decided per directory when you open it" },
  { id: "hosted-sandbox", title: "Hosted sandbox", owner: "/terminals", detail: "Decided per provider and workspace" },
];

function unreadable(id: string, title: string, owner: string): ConsentRow {
  return { id, title, state: "unreadable", owner };
}

/** consentRows composes the one consent list from what each store answered. */
export function consentRows(i: ConsentInputs, cloudLabel: (purpose: string) => string): ConsentRow[] {
  const rows: ConsentRow[] = [];

  // Organization enrichment.
  const intelOwner = "/settings?section=intel";
  if (!i.intel) rows.push(unreadable("org-enrichment", "Organization enrichment", intelOwner));
  else if (!i.intel.class || i.intel.class === "unenrolled") {
    rows.push({ id: "org-enrichment", title: "Organization enrichment", state: "not_given", detail: "Not enrolled", owner: intelOwner });
  } else {
    const given = i.intel.active?.event === "accept";
    rows.push({
      id: "org-enrichment",
      title: "Organization enrichment",
      state: given ? "given" : "not_given",
      detail: given && i.intel.active?.evidence_level ? `Level: ${i.intel.active.evidence_level}` : undefined,
      since: given ? i.intel.active?.created_at : undefined,
      owner: intelOwner,
      withdraw: given ? { kind: "intel" } : undefined,
    });
  }

  // Cloud Intelligence purposes.
  const cloudOwner = "/settings?section=cloud";
  if (!i.cloud) rows.push(unreadable("cloud", "Cloud Intelligence", cloudOwner));
  else {
    const live = i.cloud.filter((r) => r.live);
    if (live.length === 0) rows.push({ id: "cloud", title: "Cloud Intelligence", state: "not_given", owner: cloudOwner });
    for (const r of live) {
      rows.push({
        id: `cloud:${r.purpose}`,
        title: `Cloud Intelligence: ${cloudLabel(r.purpose)}`,
        state: "given",
        detail: r.mode === "standing" ? "Standing" : "Per upload",
        since: r.created_at,
        owner: cloudOwner,
        withdraw: { kind: "cloud", purpose: r.purpose },
      });
    }
  }

  // Package checks: the superbased lookup, private names, and the database download.
  const scanOwner = "/code-security?tab=scanners";
  if (!i.lookup) {
    rows.push(unreadable("package-checks", "Online package checks", scanOwner));
    rows.push(unreadable("osv-download", "Vulnerability database download", scanOwner));
  } else {
    const l = i.lookup;
    const org = l.managed ? "Set by your organization" : undefined;
    rows.push({
      id: "package-checks",
      title: "Online package checks",
      state: l.remote.accepted ? "given" : "not_given",
      detail: org ?? (l.remote.accepted ? "Package name hash prefixes go to superbased.app" : undefined),
      since: l.remote.accepted ? l.remote.accepted_at : undefined,
      owner: scanOwner,
      withdraw:
        l.remote.accepted && !l.managed
          ? { kind: "lookup", change: { withdraw_remote: true, withdraw_private: true } }
          : undefined,
    });
    if (l.remote_private.accepted) {
      rows.push({
        id: "private-package-names",
        title: "Look up private package names",
        state: "given",
        detail: org,
        since: l.remote_private.accepted_at,
        owner: scanOwner,
        withdraw: l.managed ? undefined : { kind: "lookup", change: { withdraw_private: true, private: "withhold" } },
      });
    }
    rows.push({
      id: "osv-download",
      title: "Vulnerability database download",
      state: l.download.accepted ? "given" : "not_given",
      detail: org ?? (l.download.accepted ? "Public databases, downloaded automatically" : undefined),
      since: l.download.accepted ? l.download.accepted_at : undefined,
      owner: scanOwner,
    });
  }

  // Signed change records.
  const baseOwner = "/code-security?tab=baselines";
  if (!i.provenance) rows.push(unreadable("change-records", "Signed change records", baseOwner));
  else {
    const given = i.provenance.consents.filter((c) => c.notes || c.trailer);
    const dates = given.map((c) => c.given_at).filter((d): d is string => !!d).sort();
    rows.push({
      id: "change-records",
      title: "Signed change records",
      state: given.length > 0 ? "given" : "not_given",
      detail: given.length > 0 ? `${given.length} ${given.length === 1 ? "repository" : "repositories"}` : undefined,
      since: dates[0],
      owner: baseOwner,
    });
  }

  rows.push(...CONSENT_PER_SCOPE.map((r) => ({ ...r, state: "see_page" as const })));

  // Organization governance grant.
  const enrolOwner = "/settings?section=enrolment";
  if (!i.grant) rows.push(unreadable("org-grant", "Organization governance grant", enrolOwner));
  else {
    const governed = i.grant.state === "governed";
    rows.push({
      id: "org-grant",
      title: "Organization governance grant",
      state: governed ? "given" : "not_given",
      detail: governed ? `Held by ${i.grant.org_display || "your organization"}; ends when you leave` : undefined,
      since: governed ? i.grant.granted_at : undefined,
      owner: enrolOwner,
    });
  }

  // Sandbox sign-in seed and dev container.
  if (!i.signInSeed) rows.push(unreadable("sandbox-sign-in-seed", "Sandbox sign-in seed", "/terminals"));
  else {
    rows.push({
      id: "sandbox-sign-in-seed",
      title: "Sandbox sign-in seed",
      state: i.signInSeed.length > 0 ? "given" : "not_given",
      detail: i.signInSeed.length > 0 ? `Always copied for: ${i.signInSeed.join(", ")}` : undefined,
      owner: "/terminals",
    });
  }
  if (i.devcontainer == null) rows.push(unreadable("devcontainer", "Dev container images", "/terminals"));
  else {
    rows.push({
      id: "devcontainer",
      title: "Dev container images",
      state: i.devcontainer ? "given" : "not_given",
      detail: i.devcontainer ? "A project's dev container image may be used for sandboxed runs" : undefined,
      owner: "/terminals",
    });
  }

  // Community aggregate sharing.
  const aggOwner = "/privacy";
  if (!i.aggregate) rows.push(unreadable("community-sharing", "Community aggregate sharing", aggOwner));
  else if (i.aggregate.available === false)
    rows.push({ id: "community-sharing", title: "Community aggregate sharing", state: "not_given", detail: "Not in this build", owner: aggOwner });
  else {
    const a = i.aggregate;
    rows.push({
      id: "community-sharing",
      title: "Community aggregate sharing",
      state: a.status === "valid" ? "given" : "not_given",
      detail:
        a.status === "valid"
          ? "Coarsened monthly totals, no content"
          : a.enabled
            ? "Switched on but paused until you agree again"
            : undefined,
      since: a.status === "valid" ? a.consented_at : undefined,
      owner: aggOwner,
    });
  }
  return rows;
}

/** accountLabel is the line shown for one account: email, else name, else an
 *  honest "not named" with the short key, so two unnamed accounts of one tool
 *  stay distinguishable. */
export function accountLabel(a: Pick<MeToolAccount, "email" | "name" | "key">): string {
  if (a.email || a.name) return (a.email || a.name) as string;
  return a.key ? `Account not named · ${a.key}` : "Account not named";
}

/** multiAccountTools lists the tools that were seen with more than one account. */
export function multiAccountTools(tools: MeToolAccounts[]): string[] {
  return tools.filter((t) => t.accounts.length > 1).map((t) => t.tool);
}

/** identityLabel picks the best identity: the org email, else the OS user. */
export function identityLabel(orgEmail?: string, osUser?: string): string {
  return orgEmail?.trim() || osUser?.trim() || "";
}

/** avatarInitials: up to two letters from an email's local part or a name. */
export function avatarInitials(label: string): string {
  const base = label.includes("@") ? label.split("@")[0]! : label;
  // A Windows account may arrive as DOMAIN-slash-user.
  const bare = base.split(String.fromCharCode(92)).pop() ?? base;
  const parts = bare.split(/[\s._-]+/).filter(Boolean);
  if (parts.length === 0) return "?";
  const a = parts[0]![0] ?? "";
  const b = parts.length > 1 ? (parts[parts.length - 1]![0] ?? "") : (parts[0]![1] ?? "");
  return (a + b).toUpperCase();
}

const SOURCE_WORDS: Record<string, string> = {
  os: "the operating system's machine id",
  seed: "an id Observer created on this machine",
  hostname: "the computer name (the weakest source)",
  none: "nothing readable, so this machine cannot be told apart",
};

/** machineSourceWords says in plain words where the identity came from. */
export function machineSourceWords(source: string): string {
  return SOURCE_WORDS[source] ?? "an unknown source";
}

const PRESENCE_WORDS: Record<string, string> = {
  present: "Stored",
  absent: "Not stored",
  unknown: "Cannot tell from here",
  unavailable: "Keychain not available here",
  not_checked: "Not checked",
};

/** presenceWords is the plain word for a credential presence value. */
export function presenceWords(p: string): string {
  return PRESENCE_WORDS[p] ?? "Not checked";
}

/** shortFingerprint shows the first 16 characters; "" renders as not measured. */
export function shortFingerprint(fp: string): string {
  return fp ? fp.slice(0, 16) : "";
}

// ---------- Organization: what this machine shares ----------

/** Display table of the [org_client.share] keys (mirrors the Privacy page's
 *  table; any extra key the org reports is still listed, with its raw name). */
export const SHARE_KEY_WORDS: { key: string; field: string; label: string; list?: true }[] = [
  { key: "full_content", field: "FullContent", label: "Full file paths and command text" },
  { key: "target_action_allowlist", field: "TargetActionAllowlist", label: "Action types allowed to ship a raw target", list: true },
  { key: "routing_summary", field: "RoutingSummary", label: "Routing summary rollup" },
  { key: "policy_state", field: "PolicyState", label: "Effective-policy-state reports" },
  { key: "security", field: "Security", label: "Code security" },
];

export type ShareGov = Record<string, { effective: boolean | string[]; source: string }> | undefined;

export type ShareLine = { key: string; label: string; value: string; decidedBy: string };

function shareValue(v: unknown, list?: boolean): string {
  if (Array.isArray(v)) return v.length ? v.join(", ") : "none";
  if (typeof v === "boolean") return v ? "shared" : "not shared";
  if (v === undefined || v === null) return list ? "none" : "not shared";
  return String(v);
}

/** shareLines turns the local [org_client.share] block and the governance
 *  `share` block into plain-words lines: the value in force and who decided. */
export function shareLines(local: Record<string, unknown> | undefined, gov: ShareGov): ShareLine[] {
  const known = new Set(SHARE_KEY_WORDS.map((r) => r.key));
  const extra = Object.keys(gov ?? {}).filter((k) => !known.has(k));
  const out: ShareLine[] = [];
  for (const r of SHARE_KEY_WORDS) {
    const g = gov?.[r.key];
    out.push({
      key: r.key,
      label: r.label,
      value: shareValue(g ? g.effective : local?.[r.field], r.list),
      decidedBy: g && g.source !== "you" ? "your organization" : "you",
    });
  }
  for (const k of extra) {
    const g = gov![k]!;
    out.push({ key: k, label: k, value: shareValue(g.effective), decidedBy: g.source !== "you" ? "your organization" : "you" });
  }
  return out;
}

type GovLike = {
  active?: boolean;
  version?: number;
  hidden_sections?: string[];
  read_only_sections?: string[];
};

/** policyLine says in one sentence what the organization's policy does here. */
export function policyLine(g: GovLike | null | undefined): string {
  if (!g || !g.active) return "No organization policy is in force.";
  const bits: string[] = [`Version ${g.version ?? "?"}`];
  const hidden = g.hidden_sections?.length ?? 0;
  const locked = g.read_only_sections?.length ?? 0;
  if (hidden) bits.push(`${hidden} ${hidden === 1 ? "page" : "pages"} hidden`);
  if (locked) bits.push(`${locked} ${locked === 1 ? "page" : "pages"} read-only`);
  return bits.join(", ");
}

/** costDisplayLine says what the organization chose to show on this dashboard. */
export function costDisplayLine(c: { mode?: string; source?: string } | null | undefined): string {
  if (!c) return "";
  if (c.source === "org") return c.mode === "usd" ? "Your organization shows dollar amounts." : "Your organization shows token usage instead of dollars.";
  if (c.source === "pending") return "Not known yet; token usage is shown until it is.";
  return "No organization choice applies; dollar amounts are shown.";
}

// ---------- Plans and spend ----------

export type OrgBudgetWindowLike = {
  window: string;
  period: string;
  ratio: number;
  enforcement: string;
  level: string;
  subject?: string;
  /** What the cap does on THIS machine (internal/budgetwarn EffectOf);
   *  absent from an older daemon. */
  effect?: string;
};

/** hardRule names what a hard cap does on this machine: an org cap set to
 *  block reads as a warning on a machine that cannot block (observe mode,
 *  guard off), never as "blocks" (2026-11-18). */
function hardRule(effect: string | undefined): string {
  if (effect === undefined || effect === "blocks") return "blocks at the cap";
  if (effect === "blocks_proxied") return "blocks proxied requests at the cap";
  return "set to block, warns only on this machine";
}

/** orgBudgetLine reads one org budget window as a share of its cap. It never
 *  prints an amount: the amounts follow the organization's display choice and
 *  the share is true in either. */
export function orgBudgetLine(w: OrgBudgetWindowLike): {
  label: string;
  value: string;
  tone: "neutral" | "warn" | "danger";
  /** The Guard mode link when the cap only warns here because of this
   *  machine's guard (budget enforce consistency, 2026-11-19). */
  link?: { href: string; label: string };
} {
  const pct = Number.isFinite(w.ratio) ? `${Math.round(w.ratio * 100)}% of the cap` : "not measured";
  const rule = w.enforcement === "hard" ? hardRule(w.effect) : w.enforcement === "soft" ? "warns at the cap" : "report only";
  const who = w.subject ? ` (${w.subject.replace(":", " ")})` : "";
  const warnsHere = w.enforcement === "hard" && (w.effect === "warn_observe" || w.effect === "warn_guard_off");
  return {
    label: `${w.window || w.period}${who}`,
    value: `${pct}, ${rule}`,
    tone: w.level === "exceeded" ? "danger" : w.level === "warning" ? "warn" : "neutral",
    ...(warnsHere ? { link: { href: PLACES.security_mode.href, label: "Open Guard mode" } } : {}),
  };
}

export type GuardBudgetLike = {
  session_usd: number;
  daily_usd: number;
  hard: boolean;
  /** The guard's mode (off / observe / enforce); a hard cap blocks only in
   *  enforce mode. Absent from an older daemon. */
  guard_mode?: string;
  spend_today_usd: number;
  session_tokens?: number;
  daily_tokens?: number;
  weekly_tokens?: number;
  monthly_tokens?: number;
  usage_today_tokens?: number;
  usage_week_tokens?: number;
  usage_month_tokens?: number;
};

/** guardBudgetLines lists the enforced caps on this machine that are set, in
 *  dollars or tokens following the display choice; none set returns []. */
export function guardBudgetLines(
  g: GuardBudgetLike,
  dollars: boolean,
  fmtUSD: (n: number) => string,
  fmtTok: (n: number) => string,
): { label: string; value: string }[] {
  const out: { label: string; value: string }[] = [];
  const enforcing = g.guard_mode === undefined || g.guard_mode === "enforce";
  const rule = !g.hard ? "warns at the cap" : enforcing ? "blocks at the cap" : "set to block, warns only on this machine";
  if (dollars) {
    if (g.daily_usd > 0) out.push({ label: "Daily", value: `${fmtUSD(g.spend_today_usd)} of ${fmtUSD(g.daily_usd)}, ${rule}` });
    if (g.session_usd > 0) out.push({ label: "Per session", value: `${fmtUSD(g.session_usd)} cap, ${rule}` });
  } else {
    const t: [string, number | undefined, number | undefined][] = [
      ["Daily", g.daily_tokens, g.usage_today_tokens],
      ["Weekly", g.weekly_tokens, g.usage_week_tokens],
      ["Monthly", g.monthly_tokens, g.usage_month_tokens],
    ];
    for (const [label, cap, used] of t) {
      if (cap && cap > 0) out.push({ label, value: `${used == null ? "usage not measured" : fmtTok(used)} of ${fmtTok(cap)}, ${rule}` });
    }
    if (g.session_tokens && g.session_tokens > 0) out.push({ label: "Per session", value: `${fmtTok(g.session_tokens)} cap, ${rule}` });
  }
  return out;
}

/** planHeadlineText is the one number a plan card leads with, or "" when none. */
export function planHeadlineText(
  h: { kind?: string; unit?: string; value?: number; of?: number; used?: number } | undefined,
  fmt: (unit: string, n: number) => string,
): string {
  if (!h || !h.unit) return "";
  if (h.kind === "left" && h.value != null) return `${fmt(h.unit, h.value)} left`;
  if (h.kind === "percent_left" && h.value != null) return `${Math.round(h.value)}% left`;
  if (h.kind === "used_only" && h.used != null) return `${fmt(h.unit, h.used)} used`;
  return "";
}

// ---------- Integrations ----------

export type ProbeLike = { registered: boolean; partial?: boolean; no_hooks?: boolean; unprobed?: boolean } | null | undefined;

export type ToolRowLike = { tool: string; detected: boolean; hooks?: ProbeLike; mcp?: ProbeLike; proxy?: ProbeLike };

/** integrationSummary counts, over the tools found on this machine, how many
 *  have each integration set up. A tool with no such integration is left out
 *  of the total; when none has it the answer is "not available". */
export function integrationSummary(tools: ToolRowLike[]): { hooks: string; mcp: string; proxy: string; detected: number } {
  const found = tools.filter((t) => t.detected);
  const count = (pick: (t: ToolRowLike) => ProbeLike) => {
    const have = found.map(pick).filter((p): p is NonNullable<ProbeLike> => !!p && !p.no_hooks);
    const on = have.filter((p) => p.registered).length;
    return have.length === 0 ? "not available" : `${on} of ${have.length}`;
  };
  return { hooks: count((t) => t.hooks), mcp: count((t) => t.mcp), proxy: count((t) => t.proxy), detected: found.length };
}

/** probeWords reads one tool probe: not available for a missing probe, never "off". */
export function probeWords(p: ProbeLike): string {
  if (!p) return "not available";
  if (p.no_hooks) return "no hook surface";
  if (p.unprobed) return "not checked";
  if (p.partial) return "partly set up";
  return p.registered ? "set up" : "not set up";
}

export type MeAggregateShare = { available: boolean; enabled: boolean; status?: string; consented_at?: string; actor?: string };
