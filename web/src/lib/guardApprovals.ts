// guardApprovals.ts is the Security page's pure approvals logic (P-232):
// which active grant already covers a verdict or a grant request, the
// defensive display dedupe of the register, the subagent session id a
// session grant must name, and why a blocking verdict was NOT downgraded.
// Pure: no fetch, no React; the page passes in what it already loaded.

// ApprovalRow is the slice of a GET /api/guard/approvals row this module
// reads (the page's GuardApproval type is a superset).
export type ApprovalRow = {
  id: number;
  ts: string;
  rule_id: string;
  scope: string;
  session_id?: string;
  project_root_hash?: string;
  expires_at?: string;
  last_used_at?: string;
};

// approvalKey is the store's unique key (agent migration 218): rule, scope,
// session, project hash.
export function approvalKey(a: ApprovalRow): string {
  return [a.rule_id, a.scope, a.session_id ?? "", a.project_root_hash ?? ""].join("\u0000");
}

// laterExpiry returns the later of two expiries, "" (never) winning.
function laterExpiry(a?: string, b?: string): string {
  if (!a || !b) return "";
  return new Date(a).getTime() >= new Date(b).getTime() ? a : b;
}

// laterTime returns the later of two optional timestamps ("" = none).
function laterTime(a?: string, b?: string): string {
  if (!a) return b ?? "";
  if (!b) return a;
  return new Date(a).getTime() >= new Date(b).getTime() ? a : b;
}

// dedupeApprovals folds rows that share a key into one, the way the store
// does: the lowest id survives with the latest expiry and the latest use.
// A daemon from before migration 218 can still serve duplicates; the card
// shows one row per grant either way. Order follows the surviving ids.
export function dedupeApprovals<T extends ApprovalRow>(rows: readonly T[]): T[] {
  const byKey = new Map<string, T>();
  for (const r of [...rows].sort((a, b) => a.id - b.id)) {
    const k = approvalKey(r);
    const kept = byKey.get(k);
    if (!kept) {
      byKey.set(k, { ...r });
      continue;
    }
    byKey.set(k, {
      ...kept,
      expires_at: laterExpiry(kept.expires_at, r.expires_at) || undefined,
      last_used_at: laterTime(kept.last_used_at, r.last_used_at) || undefined,
    });
  }
  return [...byKey.values()];
}

// Target is what a grant would cover: a rule, plus the session and the
// session's project hash when known. scope narrows to what a grant FORM is
// about to create; undefined means "any grant that covers this call" (a
// verdict row).
export type Target = {
  rule: string;
  session?: string;
  projectHash?: string;
  scope?: "session" | "project" | "global";
};

// SCOPE_COVERS is the coverage table: which existing grant scopes cover a
// request of a given scope. A global grant covers everything; a project
// grant covers its project's sessions; a session grant only its session.
const SCOPE_COVERS: Record<"session" | "project" | "global" | "any", readonly string[]> = {
  any: ["global", "project", "session"],
  session: ["global", "project", "session"],
  project: ["global", "project"],
  global: ["global"],
};

// grantCovers reports whether grant a covers target t (scope semantics of
// store.ApprovalActiveFor; 'once' grants never apply).
export function grantCovers(a: ApprovalRow, t: Target): boolean {
  if (a.rule_id !== t.rule) return false;
  if (!SCOPE_COVERS[t.scope ?? "any"].includes(a.scope)) return false;
  switch (a.scope) {
    case "global":
      return true;
    case "project":
      return !!a.project_root_hash && !!t.projectHash && a.project_root_hash === t.projectHash;
    case "session":
      return !!a.session_id && !!t.session && a.session_id === t.session;
    default:
      return false;
  }
}

// coveringGrant is the first active grant (lowest id) that covers t, or
// null. "Covered by grant #N" on the approve button and the Grant form.
export function coveringGrant(approvals: readonly ApprovalRow[], t: Target): ApprovalRow | null {
  if (!t.rule) return null;
  const hits = approvals.filter((a) => grantCovers(a, t)).sort((a, b) => a.id - b.id);
  return hits[0] ?? null;
}

// SUBAGENT_SEP is the separator of a Claude Code subagent session id
// (`<parent>:agent:<agent>`, internal/adapter/claudecode/subagent.go).
const SUBAGENT_SEP = ":agent:";

// grantSession is the session id a session-scoped grant must name for a
// verdict row's session: a subagent's own id is the watcher's, while the
// tool-gate hook reports the PARENT session for a subagent's calls, so the
// grant names the parent. subagent is true when the id was rewritten.
export function grantSession(session: string): { session: string; subagent: boolean } {
  const i = session.indexOf(SUBAGENT_SEP);
  if (i <= 0) return { session, subagent: false };
  return { session: session.slice(0, i), subagent: true };
}

// DECISIONS_THAT_BLOCK are the decisions an approval can soften.
const DECISIONS_THAT_BLOCK = new Set(["ask", "deny"]);

// ruleCanBlock reports whether a rule can ever produce an ask or deny, from
// its effective definitions (observe and enforce decisions). Unknown rules
// (no definition loaded) are assumed able to, so nothing is hidden on an
// older daemon. A flag-only rule (A-610) never consults approvals.
export function ruleCanBlock(defs: readonly { observe?: string; enforce?: string }[] | undefined): boolean {
  if (!defs || defs.length === 0) return true;
  return defs.some((d) => DECISIONS_THAT_BLOCK.has(d.observe ?? "") || DECISIONS_THAT_BLOCK.has(d.enforce ?? ""));
}

// VerdictRow is the slice of a verdict row whyNotDowngraded reads.
export type VerdictRow = {
  ts: string;
  rule_id: string;
  session_id?: string;
  project_root_hash?: string;
  decision?: string;
  degraded_from?: string;
  enforced: boolean;
  reason?: string;
};

// projectCaveat is set when a PROJECT grant for the rule took part in the
// answer: this page matches it on the verdict row's SESSION project, while
// the hook matched the command's working directory (ProjectLookupRoot, not
// recorded on the row), and the two can differ (a `git -C other` command, a
// session started in another repository).
export type NotDowngraded = (
  | { kind: "lookup_error" }
  | { kind: "org_locked" }
  | { kind: "grant_not_applied"; id: number }
  | { kind: "grant_came_later"; id: number }
  | { kind: "scope_mismatch"; id: number }
  | { kind: "no_grant" }
) & { projectCaveat?: boolean };

// whyNotDowngraded explains a blocking verdict an approval did not soften,
// as an ordered table walked top down; null for a row that is not a
// blocking verdict, or one that was downgraded.
//
//	| # | condition                                            | kind              |
//	|---|------------------------------------------------------|-------------------|
//	| 1 | reason carries "[approval lookup failed"             | lookup_error      |
//	| 2 | reason carries "[org_locked"                         | org_locked        |
//	| 3 | an active grant covers it and predates the verdict   | grant_not_applied |
//	| 4 | an active grant covers it, made after the verdict    | grant_came_later  |
//	| 5 | an active grant for the rule covers another scope    | scope_mismatch    |
//	| 6 | else                                                 | no_grant          |
//
// Row 3 is what the operator saw before P-232: a project grant that the
// hook never matched. Expired grants are not listed, so "no grant" means no
// ACTIVE grant for the rule now.
export function whyNotDowngraded(ev: VerdictRow, approvals: readonly ApprovalRow[]): NotDowngraded | null {
  if (!ev.enforced || !DECISIONS_THAT_BLOCK.has(ev.decision ?? "") || ev.degraded_from) return null;
  const reason = ev.reason ?? "";
  if (reason.includes("[approval lookup failed")) return { kind: "lookup_error" };
  if (reason.includes("[org_locked")) return { kind: "org_locked" };
  const t: Target = { rule: ev.rule_id, session: ev.session_id, projectHash: ev.project_root_hash };
  const covering = approvals.filter((a) => grantCovers(a, t)).sort((a, b) => a.id - b.id);
  const evTime = new Date(ev.ts).getTime();
  const before = covering.find((a) => new Date(a.ts).getTime() <= evTime);
  const sameRule = approvals.filter((a) => a.rule_id === ev.rule_id).sort((a, b) => a.id - b.id);
  const caveat = sameRule.some((a) => a.scope === "project") ? { projectCaveat: true } : {};
  if (before) return { kind: "grant_not_applied", id: before.id, ...caveat };
  if (covering[0]) return { kind: "grant_came_later", id: covering[0].id, ...caveat };
  if (sameRule[0]) return { kind: "scope_mismatch", id: sameRule[0].id, ...caveat };
  return { kind: "no_grant" };
}

// PROJECT_CAVEAT is the note a project-grant explanation carries (P-232
// fix round 1, L2).
export const PROJECT_CAVEAT =
  " Project grants are matched here on the session's project; the hook matched the command's working directory, which can differ.";

// notDowngradedText is the one-line explanation the verdict row shows.
export function notDowngradedText(w: NotDowngraded): string {
  return notDowngradedBase(w) + (w.projectCaveat ? PROJECT_CAVEAT : "");
}

function notDowngradedBase(w: NotDowngraded): string {
  switch (w.kind) {
    case "lookup_error":
      return "Not downgraded: the approval lookup failed, so no grant was consulted.";
    case "org_locked":
      return "Not downgraded: an org policy locks this rule; local approvals are ignored.";
    case "grant_not_applied":
      return `Not downgraded although grant #${w.id} covers it: before this release a project grant never matched on the hook, and a failed lookup read as no grant.`;
    case "grant_came_later":
      return `No grant at the time; grant #${w.id} was made afterwards.`;
    case "scope_mismatch":
      return `Not downgraded: grant #${w.id} for this rule covers another session or project.`;
    case "no_grant":
      return "Not downgraded: no active grant for this rule.";
  }
}
