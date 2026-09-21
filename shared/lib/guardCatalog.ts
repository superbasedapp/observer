// guardCatalog — Guard rule-authoring vocabulary + TOML compose/parse
// (docs/plans/guard-rule-management-ui-plan-2026-09-21.md, Track B / §5, §6).
//
// PROMOTED from web2/src/pages/policyforms/vocab.ts (moved, not copied — that
// file re-exports everything here so its existing importers are unchanged).
// Promoted because BOTH dashboards need it: web2's org guard bundle form
// (escalate-only `[[override]]` rows) and web's per-node/per-project rule
// manager (`[[rule]]` + `[[override]]` + `disable`, spec §6 Track B) share the
// exact same TOML grammar (internal/guard/policyfile.go) and the same
// built-in rule catalog (internal/policy/rules_*.go). One vocabulary, one
// owner, per CLAUDE.md's shared/ discipline — never fork a copy per app.
//
// Pure data + string composition/parsing — no fetch, no React, no app
// coupling. `Decision`/`Severity` are the shared enums both the guard
// override form and the admission-criteria form (web2 vocab.ts) key off of.

// --- Decision / Severity (shared enums) ---

export type Decision = "allow" | "flag" | "ask" | "deny";
export type Severity = "info" | "warn" | "high" | "critical";

export const DECISIONS: Decision[] = ["allow", "flag", "ask", "deny"];
export const SEVERITIES: Severity[] = ["info", "warn", "high", "critical"];

// --- TOML string helpers ---

export function tomlStr(s: string): string {
  return `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

export function tomlUnquote(v: string): string | null {
  const m = /^"((?:[^"\\]|\\.)*)"$/.exec(v);
  if (!m) return null;
  try {
    return JSON.parse(`"${m[1]}"`) as string;
  } catch {
    return null;
  }
}

function parseTomlNumber(v: string): number | null {
  const t = v.trim();
  if (!/^-?\d+(\.\d+)?$/.test(t)) return null;
  return Number(t);
}

// splitTomlArrayItems splits the body of a `[...]` TOML array of
// double-quoted strings into its raw (still-quoted) elements, respecting
// escaped quotes/commas inside each element — a naive `.split(",")` breaks
// the moment a value contains a comma (a glob list, a regex alternation).
function splitTomlArrayItems(body: string): string[] | null {
  const items: string[] = [];
  let i = 0;
  const n = body.length;
  while (i < n) {
    while (i < n && /\s/.test(body[i])) i++;
    if (i >= n) break;
    if (body[i] !== '"') return null;
    let j = i + 1;
    let escaped = false;
    let closed = false;
    while (j < n) {
      const c = body[j];
      if (escaped) {
        escaped = false;
        j++;
        continue;
      }
      if (c === "\\") {
        escaped = true;
        j++;
        continue;
      }
      if (c === '"') {
        j++;
        closed = true;
        break;
      }
      j++;
    }
    if (!closed) return null;
    items.push(body.slice(i, j));
    i = j;
    while (i < n && /\s/.test(body[i])) i++;
    if (i < n) {
      if (body[i] !== ",") return null;
      i++;
    }
  }
  return items;
}

function parseTomlStringArray(v: string): string[] | null {
  const t = v.trim();
  const m = /^\[\s*([\s\S]*?)\s*\]$/.exec(t);
  if (!m) return null;
  const body = m[1].trim();
  if (body === "") return [];
  const raw = splitTomlArrayItems(body);
  if (raw === null) return null;
  const out: string[] = [];
  for (const item of raw) {
    const s = tomlUnquote(item);
    if (s === null) return null;
    out.push(s);
  }
  return out;
}

function tomlStrArray(items: string[]): string {
  return `[${items.map(tomlStr).join(", ")}]`;
}

// --- Guard override rows (Plane B — internal/guard org bundle + web's
// per-node/per-project rule manager) ---
//
// An `[[override]]` tunes a BUILT-IN rule's decision/enforce — it never
// carries a matcher (internal/guard/policyfile.go rejects `[[override]]
// match.*`; see docs/guard-policy-authoring.md "Layering rules"). The org
// layer is an ESCALATE-ONLY strictness floor (spec §4.6/§14.2): an
// `[[override]]` may only raise a built-in rule's decision, never lower it.
// internal/guard/merge.go::mergeLayers seeds the effective policy from
// policy.Catalog() before applying org overrides, then drops (as a lint
// "issue", never silently applied) any override whose decision is weaker
// than that rule's stricter-of(observe, enforce) bar. Rule ids come from a
// curated catalog of the built-in rules (internal/policy/rules_*.go); an id
// typed outside the catalog is still accepted (free text) with all four
// decisions offered, since the org/trusted-project lint is the actual
// authority — this picker is a UI hint, not enforcement.

export type GuardOverrideRow = {
  rule: string;
  decision: Decision | ""; // "" = enforce-only override, no decision change (legal TOML)
  enforce: boolean;
  // overridable grants a developer the latitude to override THIS rule's deny
  // on their own node, scoped and time-boxed (org guardrail control wave,
  // Track A item 6 / Track B). DEFAULT FALSE: silence means the rule is hard.
  // Composition across bundles is FALSE-WINS, so an org-wide "not overridable"
  // can never be loosened by a team bundle. `undefined` means the author has
  // not spoken about this rule at all, and the key is not emitted - which is
  // what keeps a fleet that never uses the flag on byte-identical bundles.
  // ONLY the org layer may grant it (internal/guard/merge.go
  // noteUngrantableOverridable): a user / trusted-project file carrying the
  // key is a lint issue, so the node rule manager never emits it.
  overridable?: boolean;
};

export type GuardRuleCatalogEntry = {
  id: string;
  category: string;
  severity: Severity;
  observe: Decision;
  enforce: Decision;
  doc: string;
};

// GUARD_RULE_CATALOG — transcribed from internal/policy/rules_*.go
// (policy.Catalog()). Where a rule id appears as multiple table rows (e.g. a
// file-access variant and a shell-command variant), the observe/enforce pair
// here is the stricter of all rows for that id — the same
// StricterOf(observe, enforce) reduction internal/guard/merge.go performs
// when it seeds the effective policy from the catalog.
export const GUARD_RULE_CATALOG: GuardRuleCatalogEntry[] = [
  // Destructive — internal/policy/rules_destructive.go
  { id: "R-101", category: "destructive", severity: "critical", observe: "flag", enforce: "deny", doc: "Recursive delete targeting a filesystem root, the home directory, a root-depth wildcard, or a path outside the project." },
  { id: "R-102", category: "destructive", severity: "high", observe: "flag", enforce: "ask", doc: "Recursive delete inside the project targeting the VCS directory or the project root itself." },
  { id: "R-103", category: "destructive", severity: "high", observe: "flag", enforce: "ask", doc: "Mass-deletion chain (find -delete / xargs rm)." },
  { id: "R-104", category: "destructive", severity: "high", observe: "flag", enforce: "ask", doc: "Git command that discards uncommitted work (reset --hard / checkout -- / clean -f)." },
  { id: "R-110", category: "destructive", severity: "critical", observe: "flag", enforce: "deny", doc: "Force push to a protected branch." },
  { id: "R-111", category: "destructive", severity: "warn", observe: "flag", enforce: "ask", doc: "Deletion of a protected branch or tag." },
  { id: "R-120", category: "destructive", severity: "critical", observe: "flag", enforce: "deny", doc: "Destructive SQL through a database CLI (DROP/TRUNCATE/DELETE without WHERE)." },
  { id: "R-130", category: "destructive", severity: "critical", observe: "flag", enforce: "ask", doc: "Cloud-infrastructure destruction command." },
  { id: "R-140", category: "destructive", severity: "high", observe: "flag", enforce: "ask", doc: "Package registry publish/yank." },
  { id: "R-141", category: "destructive", severity: "high", observe: "flag", enforce: "ask", doc: "Bulk permission/ownership change (chmod -R 777 / chown -R outside project)." },
  { id: "R-142", category: "destructive", severity: "critical", observe: "flag", enforce: "deny", doc: "Disk/device-level operation (mkfs / dd to a device / diskpart / format)." },
  // Boundary — internal/policy/rules_boundary.go
  { id: "R-150", category: "boundary", severity: "warn", observe: "flag", enforce: "ask", doc: "File read/write outside the project root." },
  { id: "R-151", category: "boundary", severity: "high", observe: "flag", enforce: "ask", doc: "Write into a different observed project's root (cross-project bleed)." },
  { id: "R-152", category: "boundary", severity: "critical", observe: "flag", enforce: "deny", doc: "Access to a sensitive credential/profile location (write denies, read asks)." },
  { id: "R-153", category: "boundary", severity: "high", observe: "flag", enforce: "ask", doc: "Read of a secret-bearing file (.env / key material / credentials)." },
  { id: "R-154", category: "boundary", severity: "critical", observe: "flag", enforce: "deny", doc: "Write to a shell rc/profile file (persistence vector)." },
  { id: "R-155", category: "boundary", severity: "critical", observe: "flag", enforce: "deny", doc: "Write to an autostart/persistence location, or a persistence-installing command (cron, systemd, LaunchAgents, Startup, schtasks, Run key)." },
  { id: "R-156", category: "boundary", severity: "high", observe: "flag", enforce: "ask", doc: "Write to .git/hooks (in-repo persistence vector)." },
  { id: "R-157", category: "boundary", severity: "high", observe: "flag", enforce: "ask", doc: "Wrapper whose inner command could not be analysed (fails closed)." },
  { id: "R-160", category: "boundary", severity: "critical", observe: "flag", enforce: "deny", doc: "Agent modifying observer/guard/hook configuration." },
  { id: "R-161", category: "boundary", severity: "high", observe: "flag", enforce: "flag", doc: "Agent modifying the project guard policy file." },
  // Exfil — internal/policy/rules_exfil.go
  { id: "R-170", category: "exfil", severity: "critical", observe: "flag", enforce: "deny", doc: "Remote content piped into an interpreter (curl|sh-class remote-code execution)." },
  { id: "R-171", category: "exfil", severity: "high", observe: "flag", enforce: "ask", doc: "Shell command uploading file contents to a remote destination." },
  { id: "R-172", category: "exfil", severity: "critical", observe: "flag", enforce: "deny", doc: "Secret-shaped value in a network command or outbound LLM API request." },
  { id: "R-173", category: "exfil", severity: "warn", observe: "flag", enforce: "flag", doc: "DNS lookup of an encoded-looking subdomain (DNS-tunnel exfil shape)." },
  // Injection — internal/policy/rules_inject.go
  { id: "R-180", category: "injection", severity: "high", observe: "flag", enforce: "flag", doc: "Inbound tool-result/web content carries injection-shaped instruction patterns." },
  // Posture — internal/policy/rules_posture.go
  { id: "R-204", category: "posture", severity: "high", observe: "flag", enforce: "flag", doc: "Compiled native guard rules drifted from the effective policy." },
  { id: "R-205", category: "posture", severity: "high", observe: "flag", enforce: "flag", doc: "Org policy bundle failed integrity verification and was rejected." },
  // MCP — internal/policy/rules_mcp.go
  { id: "R-301", category: "mcp", severity: "warn", observe: "flag", enforce: "flag", doc: "New MCP server appeared without an approved pin." },
  { id: "R-302", category: "mcp", severity: "critical", observe: "flag", enforce: "flag", doc: "Pinned MCP server's declared tools or descriptions changed (rug-pull shape)." },
  { id: "R-303", category: "mcp", severity: "high", observe: "flag", enforce: "flag", doc: "MCP tool description carries a poisoning-shaped pattern." },
  { id: "R-304", category: "mcp", severity: "critical", observe: "flag", enforce: "deny", doc: "Agent modifying an MCP server registry file." },
  { id: "R-305", category: "mcp", severity: "critical", observe: "flag", enforce: "flag", doc: "Pinned MCP server's command/binary or URL changed under the same name." },
  // Anomaly — internal/policy/rules_anomaly.go (anomaly rules never deny, §12.2/F6)
  { id: "A-610", category: "anomaly", severity: "warn", observe: "flag", enforce: "flag", doc: "Identical tool call repeated consecutively past the stuck-loop threshold." },
  // Taint — internal/policy/rules_taint.go
  { id: "T-501", category: "taint", severity: "high", observe: "flag", enforce: "ask", doc: "Shell command while the session carries untrusted content with instruction-like patterns." },
  { id: "T-502", category: "taint", severity: "high", observe: "flag", enforce: "ask", doc: "Out-of-project write while the session carries untrusted content." },
  { id: "T-503", category: "taint", severity: "warn", observe: "flag", enforce: "flag", doc: "Git push while the session carries untrusted content." },
  { id: "T-504", category: "taint", severity: "critical", observe: "flag", enforce: "deny", doc: "Network-touching command after the session read a secrets-bearing file." },
  { id: "T-505", category: "taint", severity: "warn", observe: "flag", enforce: "flag", doc: "MCP call to a different server after consuming an unpinned server's result (cross-server toxic-flow shape)." },
  // Budget — internal/policy/rules_budget.go
  { id: "B-601", category: "budget", severity: "high", observe: "flag", enforce: "flag", doc: "Session cost exceeded [guard.budget].session_usd." },
  { id: "B-602", category: "budget", severity: "high", observe: "flag", enforce: "flag", doc: "Daily cost (all sessions) exceeded [guard.budget].daily_usd." },
  { id: "B-603", category: "budget", severity: "high", observe: "flag", enforce: "flag", doc: "Calendar-month cost (all sessions) exceeded [guard.budget].monthly_usd." },
  { id: "B-604", category: "budget", severity: "high", observe: "flag", enforce: "flag", doc: "Rolling-7-day cost (all sessions) exceeded [guard.budget].weekly_usd." },
  { id: "B-610", category: "limit", severity: "warn", observe: "flag", enforce: "flag", doc: "5h usage window utilization reached [guard.budget.window].util_5h_warn." },
  { id: "B-611", category: "limit", severity: "high", observe: "flag", enforce: "deny", doc: "5h usage window utilization reached [guard.budget.window].util_5h_deny." },
  { id: "B-612", category: "limit", severity: "warn", observe: "flag", enforce: "flag", doc: "Weekly usage window utilization reached [guard.budget.window].util_weekly_warn." },
  { id: "B-613", category: "limit", severity: "high", observe: "flag", enforce: "deny", doc: "Weekly usage window utilization reached [guard.budget.window].util_weekly_deny." },
];

const DECISION_ORDER: Record<Decision, number> = { allow: 0, flag: 1, ask: 2, deny: 3 };

export function guardRuleInfo(id: string): GuardRuleCatalogEntry | undefined {
  const needle = id.trim();
  return GUARD_RULE_CATALOG.find((r) => r.id === needle);
}

// guardMinDecisionFor mirrors the escalate-only floor mergeLayers enforces
// server-side: the stricter of a catalogued rule's observe/enforce decisions.
// Returns undefined for a free-text/uncatalogued rule id — the form offers
// all four decisions in that case rather than fabricating a floor.
export function guardMinDecisionFor(id: string): Decision | undefined {
  const info = guardRuleInfo(id);
  if (!info) return undefined;
  return DECISION_ORDER[info.enforce] >= DECISION_ORDER[info.observe] ? info.enforce : info.observe;
}

// isGuardIntegrityRuleId names the guard's own INTEGRITY rules — R-160 (agent
// modifying observer/guard/hook config) and R-161 (agent modifying the project
// guard file). Mirrors internal/policy/engine.go::IsIntegrityRuleID, a closed
// set. The policy engine is a HARD BACKSTOP that refuses to disable or weaken
// these below the org floor at merge time regardless of layer, so the picker
// must never OFFER a weaken it can't apply — even in a weaken-allowed layer.
export function isGuardIntegrityRuleId(id: string): boolean {
  const needle = id.trim();
  return needle === "R-160" || needle === "R-161";
}

// guardDecisionOptionsFor returns the decisions legal for a given rule id
// (at-or-above its escalate-only floor for a catalogued rule; all four for a
// free-text one). This is a UI hint only — the org/user lint is the real
// gate. NOTE: a weaken-allowed layer (the trusted-project layer §3, or the
// user/global structured picker) offers all four decisions — EXCEPT for an
// integrity rule (R-160/R-161), which stays escalate-only even when weakening
// is allowed, matching the policy engine's hard backstop.
export function guardDecisionOptionsFor(id: string, allowWeaken = false): Decision[] {
  if (allowWeaken && !isGuardIntegrityRuleId(id)) return DECISIONS;
  const floor = guardMinDecisionFor(id);
  if (!floor) return DECISIONS;
  return DECISIONS.filter((d) => DECISION_ORDER[d] >= DECISION_ORDER[floor]);
}

export function emptyGuardOverride(): GuardOverrideRow {
  return { rule: "", decision: "", enforce: true };
}

// composeGuardToml turns override rows into the bare `[[override]]` blocks
// internal/guard/policyfile.go::tomlOverride parses — no wrapping table
// header, matching the shape of both shipped starter bundles and the
// dashboard's own GUARD_PLACEHOLDER example. `decision` is emitted only when
// set (an enforce-only override with no decision change is legal TOML).
export function composeGuardToml(rows: GuardOverrideRow[]): string {
  const lines: string[] = [
    "# Org guard-policy bundle (TOML; merged on every agent as the strictness floor)",
  ];
  for (const r of rows) {
    if (!r.rule.trim()) continue;
    lines.push("", "[[override]]", `rule = ${tomlStr(r.rule.trim())}`);
    if (r.decision) lines.push(`decision = ${tomlStr(r.decision)}`);
    lines.push(`enforce = ${r.enforce ? "true" : "false"}`);
    // Emitted ONLY when the author actually set it: an unspoken rule is
    // already hard by default, and an emitted key would change the bytes of
    // every bundle in every fleet that has no use for the flag.
    if (r.overridable !== undefined) lines.push(`overridable = ${r.overridable ? "true" : "false"}`);
  }
  return lines.join("\n") + "\n";
}

// parseGuardOverrides is the inverse of composeGuardToml for the narrow
// grammar the guard form owns: comments, blank lines, `[[override]]` blocks
// and their rule/decision/enforce assignments. Anything else (e.g. a
// `[[rule]]` definition table, multi-line values, unknown keys) returns null
// so the caller falls back to the Advanced raw-TOML editor instead of
// silently dropping constructs the form cannot represent.
export function parseGuardOverrides(toml: string): GuardOverrideRow[] | null {
  const rows: GuardOverrideRow[] = [];
  let cur: GuardOverrideRow | null = null;
  for (const rawLine of toml.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line === "" || line.startsWith("#")) continue;
    if (line === "[[override]]") {
      if (cur) rows.push(cur);
      cur = emptyGuardOverride();
      continue;
    }
    const m = /^([A-Za-z_]+)\s*=\s*(.+?)\s*(?:#.*)?$/.exec(line);
    if (!m || !cur) return null;
    const [, key, val] = m;
    if (key === "rule") {
      const s = tomlUnquote(val);
      if (s === null) return null;
      cur.rule = s;
    } else if (key === "decision") {
      const s = tomlUnquote(val);
      if (s === null || !(DECISIONS as readonly string[]).includes(s)) return null;
      cur.decision = s as Decision;
    } else if (key === "enforce") {
      if (val !== "true" && val !== "false") return null;
      cur.enforce = val === "true";
    } else if (key === "overridable") {
      if (val !== "true" && val !== "false") return null;
      cur.overridable = val === "true";
    } else {
      return null;
    }
  }
  if (cur) rows.push(cur);
  if (rows.some((r) => !r.rule.trim())) return null;
  return rows;
}

// --- [[rule]] authoring (net-new, matcher-v1 — docs/guard-policy-authoring.md) ---
//
// A rule may use only ONE matcher scope — command-scoped (evaluated per
// parsed shell command) XOR event-scoped (evaluated per event) — "the parser
// rejects mixing; split into two rules". GuardRuleRow models that as an
// explicit `scope` discriminant plus both matcher shapes always present
// (the inactive one just stays empty), which is simpler for a controlled
// form than a real union and composes/parses identically either way.

export type GuardMatchScope = "command" | "event";

export const GUARD_CATEGORIES = [
  "destructive",
  "boundary",
  "secrets",
  "exfil",
  "posture",
  "mcp",
  "taint",
  "budget",
  "anomaly",
] as const;

export const GUARD_EVENT_KINDS = [
  "tool_call",
  "file_access",
  "shell_exec",
  "mcp_call",
  "api_request",
  "api_response",
  "config_change",
  "session_meta",
] as const;

export const GUARD_TAINT_SOURCES = [
  "web_fetch",
  "mcp_unpinned",
  "external_file",
  "attachment",
  "secrets_read",
] as const;

export const GUARD_SINKS = ["shell_exec", "git_push", "out_of_project_write", "mcp_call"] as const;

// Command-scoped matcher fields (evaluated per parsed command, after the
// shellparse unwrap). Implies applies_to = ["shell_exec"].
export type GuardCommandMatch = {
  command_regex: string;
  command_base: string;
  arg_contains: string;
};

// Event-scoped matcher fields (evaluated once per event). Numeric fields are
// held as UI text ("" = unset) and converted at compose time — the same
// convention vocab.ts's node.governance pin editor uses for typed values
// behind a text input.
export type GuardEventMatch = {
  path_glob: string[];
  path_not: string[];
  path_outside_project: boolean;
  path_sensitive: boolean;
  url_domain: string;
  mcp_server: string;
  mcp_tool: string;
  event_kind: string[];
  sink: string;
  taint_source: string;
  session_cost_usd_gt: string; // float text, "" = unset
  repeat_count_gt: string; // int text, "" = unset
};

export type GuardRuleRow = {
  id: string;
  category: string;
  severity: Severity;
  decision: Decision;
  enforce: boolean;
  // Explicit applies_to override. Empty = let the matchers imply it (the
  // compiler's default); the composer only emits the key when non-empty.
  applies_to: string[];
  scope: GuardMatchScope;
  command: GuardCommandMatch;
  event: GuardEventMatch;
};

export function emptyGuardCommandMatch(): GuardCommandMatch {
  return { command_regex: "", command_base: "", arg_contains: "" };
}

export function emptyGuardEventMatch(): GuardEventMatch {
  return {
    path_glob: [],
    path_not: [],
    path_outside_project: false,
    path_sensitive: false,
    url_domain: "",
    mcp_server: "",
    mcp_tool: "",
    event_kind: [],
    sink: "",
    taint_source: "",
    session_cost_usd_gt: "",
    repeat_count_gt: "",
  };
}

export function emptyGuardRuleRow(): GuardRuleRow {
  return {
    id: "",
    category: "boundary",
    severity: "warn",
    decision: "flag",
    enforce: false,
    applies_to: [],
    scope: "event",
    command: emptyGuardCommandMatch(),
    event: emptyGuardEventMatch(),
  };
}

// guardRuleRowHasMatcher reports whether a row carries at least one matcher
// field for its active scope — a UI hint mirroring the server's "a rule
// with no matchers" reject (docs/guard-policy-authoring.md "Common rejects").
export function guardRuleRowHasMatcher(r: GuardRuleRow): boolean {
  if (r.scope === "command") {
    return !!(r.command.command_regex.trim() || r.command.command_base.trim() || r.command.arg_contains.trim());
  }
  const e = r.event;
  return !!(
    e.path_glob.length ||
    e.path_not.length ||
    e.path_outside_project ||
    e.path_sensitive ||
    e.url_domain.trim() ||
    e.mcp_server.trim() ||
    e.mcp_tool.trim() ||
    e.event_kind.length ||
    e.sink.trim() ||
    e.taint_source.trim() ||
    e.session_cost_usd_gt.trim() ||
    e.repeat_count_gt.trim()
  );
}

// guardRuleRowIsPureCondition reports whether a row's only matchers are
// "pure conditions" (taint_source / session_cost_usd_gt / repeat_count_gt),
// which imply no event kind — the parser requires an explicit applies_to (or
// event_kind) in that case (docs/guard-policy-authoring.md).
export function guardRuleRowIsPureCondition(r: GuardRuleRow): boolean {
  if (r.scope === "command") return false;
  const e = r.event;
  const hasPure = !!(e.taint_source.trim() || e.session_cost_usd_gt.trim() || e.repeat_count_gt.trim());
  const hasKindImplying = !!(
    e.path_glob.length ||
    e.path_not.length ||
    e.path_outside_project ||
    e.path_sensitive ||
    e.url_domain.trim() ||
    e.mcp_server.trim() ||
    e.mcp_tool.trim() ||
    e.event_kind.length ||
    e.sink.trim()
  );
  return hasPure && !hasKindImplying;
}

// guardRuleRowProblems is an advisory (client-side) mirror of the server's
// strict parser rejects, so the editor can point at the exact field before a
// round trip to /api/guard/policy/lint. Never the real gate.
export function guardRuleRowProblems(r: GuardRuleRow): string[] {
  const problems: string[] = [];
  if (!r.id.trim()) problems.push("Rule id is required.");
  if (!r.category.trim()) problems.push("Category is required.");
  if (!guardRuleRowHasMatcher(r)) {
    problems.push(`This rule has no ${r.scope === "command" ? "command" : "event"} matchers — it would never fire.`);
  }
  if (guardRuleRowIsPureCondition(r) && r.applies_to.length === 0 && r.event.event_kind.length === 0) {
    problems.push(
      "A pure-condition rule (taint_source / session_cost_usd_gt / repeat_count_gt) implies no event kind — set Applies to explicitly.",
    );
  }
  return problems;
}

// composeRuleToml renders the full trusted-layer/user-layer policy file: an
// optional top-level `disable = [...]` line (trusted-project layer ONLY —
// `allowDisable` gates it; the global/user layer disables through the
// separate PUT /api/config/section/guard seam per spec §5), followed by
// `[[rule]]` blocks, then `[[override]]` blocks. Rows with an empty id are
// skipped (mirrors composeGuardToml's `!r.rule.trim()` convention) so a
// half-filled draft row never reaches the wire.
export function composeRuleToml(
  rules: GuardRuleRow[],
  overrides: GuardOverrideRow[],
  disable: string[] = [],
  opts?: { allowDisable?: boolean },
): string {
  const lines: string[] = [
    "# Guard policy (TOML) - composed by the dashboard's rule manager.",
    "# Reference: docs/guard-policy-authoring.md",
  ];
  const allowDisable = opts?.allowDisable ?? false;
  const disableIds = [...new Set(disable.map((d) => d.trim()).filter(Boolean))];
  if (allowDisable && disableIds.length > 0) {
    lines.push("", `disable = ${tomlStrArray(disableIds)}`);
  }
  for (const r of rules) {
    const id = r.id.trim();
    if (!id) continue;
    lines.push("", "[[rule]]");
    lines.push(`id         = ${tomlStr(id)}`);
    if (r.category.trim()) lines.push(`category   = ${tomlStr(r.category.trim())}`);
    lines.push(`severity   = ${tomlStr(r.severity)}`);
    lines.push(`decision   = ${tomlStr(r.decision)}`);
    if (r.enforce) lines.push("enforce    = true");
    if (r.applies_to.length) lines.push(`applies_to = ${tomlStrArray(r.applies_to)}`);
    if (r.scope === "command") {
      const c = r.command;
      if (c.command_regex.trim()) lines.push(`match.command_regex = ${tomlStr(c.command_regex.trim())}`);
      if (c.command_base.trim()) lines.push(`match.command_base = ${tomlStr(c.command_base.trim())}`);
      if (c.arg_contains.trim()) lines.push(`match.arg_contains = ${tomlStr(c.arg_contains.trim())}`);
    } else {
      const e = r.event;
      if (e.path_glob.length) lines.push(`match.path_glob = ${tomlStrArray(e.path_glob)}`);
      if (e.path_not.length) lines.push(`match.path_not = ${tomlStrArray(e.path_not)}`);
      if (e.path_outside_project) lines.push("match.path_outside_project = true");
      if (e.path_sensitive) lines.push("match.path_sensitive = true");
      if (e.url_domain.trim()) lines.push(`match.url_domain = ${tomlStr(e.url_domain.trim())}`);
      if (e.mcp_server.trim()) lines.push(`match.mcp_server = ${tomlStr(e.mcp_server.trim())}`);
      if (e.mcp_tool.trim()) lines.push(`match.mcp_tool = ${tomlStr(e.mcp_tool.trim())}`);
      if (e.event_kind.length) lines.push(`match.event_kind = ${tomlStrArray(e.event_kind)}`);
      if (e.sink.trim()) lines.push(`match.sink = ${tomlStr(e.sink.trim())}`);
      if (e.taint_source.trim()) lines.push(`match.taint_source = ${tomlStr(e.taint_source.trim())}`);
      const costN = parseTomlNumber(e.session_cost_usd_gt);
      if (costN !== null) lines.push(`match.session_cost_usd_gt = ${costN}`);
      const repeatN = parseTomlNumber(e.repeat_count_gt);
      if (repeatN !== null && Number.isInteger(repeatN)) lines.push(`match.repeat_count_gt = ${repeatN}`);
    }
  }
  for (const r of overrides) {
    if (!r.rule.trim()) continue;
    lines.push("", "[[override]]", `rule = ${tomlStr(r.rule.trim())}`);
    if (r.decision) lines.push(`decision = ${tomlStr(r.decision)}`);
    lines.push(`enforce = ${r.enforce ? "true" : "false"}`);
  }
  return lines.join("\n") + "\n";
}

export type ParsedGuardPolicy = {
  rules: GuardRuleRow[];
  overrides: GuardOverrideRow[];
  disable: string[];
};

// parseRules is the inverse of composeRuleToml, extended to also recognize
// `[[rule]]` blocks and the top-level `disable` key. Like parseGuardOverrides,
// it is DELIBERATELY STRICT: comments, blank lines, a leading `disable =
// [...]`, `[[rule]]` blocks and `[[override]]` blocks with exactly the keys
// this module composes are the only things it accepts. ANY other construct
// (an unknown key, a mixed command+event rule, a multi-line value, a
// dotted-table syntax variant) returns null — the safety pattern the spec
// calls for: the caller falls back to the Advanced raw-TOML editor rather
// than silently dropping a construct this form can't represent.
export function parseRules(toml: string): ParsedGuardPolicy | null {
  const rules: GuardRuleRow[] = [];
  const overrides: GuardOverrideRow[] = [];
  let disable: string[] = [];
  let disableSeen = false;

  let mode: "none" | "rule" | "override" = "none";
  let curRule: GuardRuleRow | null = null;
  let curOverride: GuardOverrideRow | null = null;
  let curRuleScope: GuardMatchScope | null = null;

  function flushCurrent(): boolean {
    if (mode === "rule") {
      if (!curRule || !curRule.id.trim()) return false;
      rules.push(curRule);
    } else if (mode === "override") {
      if (!curOverride || !curOverride.rule.trim()) return false;
      overrides.push(curOverride);
    }
    return true;
  }

  for (const rawLine of toml.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line === "" || line.startsWith("#")) continue;

    if (line === "[[rule]]") {
      if (!flushCurrent()) return null;
      curRule = emptyGuardRuleRow();
      curOverride = null;
      curRuleScope = null;
      mode = "rule";
      continue;
    }
    if (line === "[[override]]") {
      if (!flushCurrent()) return null;
      curOverride = emptyGuardOverride();
      curRule = null;
      mode = "override";
      continue;
    }

    const m = /^([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*(.+)$/.exec(line);
    if (!m) return null;
    const key = m[1];
    const val = m[2].trim();

    if (mode === "none") {
      if (key !== "disable" || disableSeen) return null;
      const arr = parseTomlStringArray(val);
      if (arr === null) return null;
      disable = arr;
      disableSeen = true;
      continue;
    }

    if (mode === "override") {
      if (!curOverride) return null;
      if (key === "rule") {
        const s = tomlUnquote(val);
        if (s === null) return null;
        curOverride.rule = s;
      } else if (key === "decision") {
        const s = tomlUnquote(val);
        if (s === null || !(DECISIONS as readonly string[]).includes(s)) return null;
        curOverride.decision = s as Decision;
      } else if (key === "enforce") {
        if (val !== "true" && val !== "false") return null;
        curOverride.enforce = val === "true";
      } else {
        return null;
      }
      continue;
    }

    // mode === "rule"
    if (!curRule) return null;
    if (key === "id") {
      const s = tomlUnquote(val);
      if (s === null) return null;
      curRule.id = s;
    } else if (key === "category") {
      const s = tomlUnquote(val);
      if (s === null) return null;
      curRule.category = s;
    } else if (key === "severity") {
      const s = tomlUnquote(val);
      if (s === null || !(SEVERITIES as readonly string[]).includes(s)) return null;
      curRule.severity = s as Severity;
    } else if (key === "decision") {
      const s = tomlUnquote(val);
      if (s === null || !(DECISIONS as readonly string[]).includes(s)) return null;
      curRule.decision = s as Decision;
    } else if (key === "enforce") {
      if (val !== "true" && val !== "false") return null;
      curRule.enforce = val === "true";
    } else if (key === "applies_to") {
      const arr = parseTomlStringArray(val);
      if (arr === null) return null;
      curRule.applies_to = arr;
    } else if (key.startsWith("match.")) {
      const field = key.slice("match.".length);
      const commandFields = new Set(["command_regex", "command_base", "arg_contains"]);
      if (commandFields.has(field)) {
        if (curRuleScope === "event") return null;
        curRuleScope = "command";
        curRule.scope = "command";
        const s = tomlUnquote(val);
        if (s === null) return null;
        if (field === "command_regex") curRule.command.command_regex = s;
        else if (field === "command_base") curRule.command.command_base = s;
        else curRule.command.arg_contains = s;
        continue;
      }
      if (curRuleScope === "command") return null;
      curRuleScope = "event";
      curRule.scope = "event";
      const e = curRule.event;
      switch (field) {
        case "path_glob": {
          const arr = parseTomlStringArray(val);
          if (arr === null) return null;
          e.path_glob = arr;
          break;
        }
        case "path_not": {
          const arr = parseTomlStringArray(val);
          if (arr === null) return null;
          e.path_not = arr;
          break;
        }
        case "path_outside_project":
          if (val !== "true" && val !== "false") return null;
          e.path_outside_project = val === "true";
          break;
        case "path_sensitive":
          if (val !== "true" && val !== "false") return null;
          e.path_sensitive = val === "true";
          break;
        case "url_domain": {
          const s = tomlUnquote(val);
          if (s === null) return null;
          e.url_domain = s;
          break;
        }
        case "mcp_server": {
          const s = tomlUnquote(val);
          if (s === null) return null;
          e.mcp_server = s;
          break;
        }
        case "mcp_tool": {
          const s = tomlUnquote(val);
          if (s === null) return null;
          e.mcp_tool = s;
          break;
        }
        case "event_kind": {
          const arr = parseTomlStringArray(val);
          if (arr === null) return null;
          e.event_kind = arr;
          break;
        }
        case "sink": {
          const s = tomlUnquote(val);
          if (s === null) return null;
          e.sink = s;
          break;
        }
        case "taint_source": {
          const s = tomlUnquote(val);
          if (s === null) return null;
          e.taint_source = s;
          break;
        }
        case "session_cost_usd_gt": {
          const n = parseTomlNumber(val);
          if (n === null) return null;
          e.session_cost_usd_gt = String(n);
          break;
        }
        case "repeat_count_gt": {
          const n = parseTomlNumber(val);
          if (n === null || !Number.isInteger(n)) return null;
          e.repeat_count_gt = String(n);
          break;
        }
        default:
          return null;
      }
    } else {
      return null;
    }
  }
  if (!flushCurrent()) return null;
  return { rules, overrides, disable };
}
