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

import { toneOf, type Tone } from "./tone.ts";
import type { GuardCoverageLane } from "./guardToolCoverage.ts";

export type Decision = "allow" | "flag" | "ask" | "deny";
export type Severity = "info" | "warn" | "high" | "critical";

export const DECISIONS: Decision[] = ["allow", "flag", "ask", "deny"];
export const SEVERITIES: Severity[] = ["info", "warn", "high", "critical"];

// The ONE tone per guard decision / severity for every surface (web Security,
// Policies, Egress, web2 Security / GuardEvents / Sessions). Before
// 2026-09-28 the apps disagreed (allow neutral vs success, ask accent vs
// info, severity warn rendered as info). Glyphs: VOCAB_ICONS.guardDecision /
// .guardSeverity in ./vocabIcons.
export const DECISION_TONE: Readonly<Record<Decision, Tone>> = {
  allow: "success",
  flag: "warn",
  ask: "info",
  deny: "danger",
};

export const SEVERITY_TONE: Readonly<Record<Severity, Tone>> = {
  info: "info",
  warn: "warn",
  high: "danger",
  critical: "danger",
};

/** decisionTone - the tone for a guard decision, "neutral" if unknown. */
export function decisionTone(d: string | null | undefined): Tone {
  return toneOf(DECISION_TONE, d);
}

/** severityTone - the tone for a guard severity, "neutral" if unknown. */
export function severityTone(s: string | null | undefined): Tone {
  return toneOf(SEVERITY_TONE, s);
}

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
  // coverageLanes, when set, names the lanes the rule is judged on, so the
  // admin form renders the GENERATED per-tool coverage for each
  // (guardToolCoverage.ts: which tools block / ask / warn / record only for
  // the decision the row pins). Data on the row, never a UI branch on the
  // rule id; a row without it falls back to its category's lanes
  // (CATEGORY_COVERAGE_LANES, guardRuleCoverageLanes).
  coverageLanes?: GuardCoverageLane[];
  // module, when set, names the optional module whose rule pack carries the
  // row (the security pillar's S-7xx rows: "Code security"). A node
  // evaluates the rule only while that module is on there; an org override
  // on it is valid fleet policy either way.
  module?: string;
};

// Lane sets the catalog rows below name explicitly.
const CL_PROMPT: GuardCoverageLane[] = ["prompt"];
const CL_PROMPT_TOOL: GuardCoverageLane[] = ["prompt", "toolCall"];
const CL_TOOL: GuardCoverageLane[] = ["toolCall"];

// CATEGORY_COVERAGE_LANES: the categories whose rules are judged on a tool
// call (a shell command, a file access, an MCP call) at the tool gate. Taint
// rules depend on live session state that not every gate holds,
// and the posture / budget / anomaly / MCP-pin rules are not tool-gate
// judgements, so they carry no per-tool view.
const CATEGORY_COVERAGE_LANES: Readonly<Record<string, GuardCoverageLane[]>> = {
  destructive: ["toolCall"],
  boundary: ["toolCall"],
  exfil: ["toolCall"],
};

/** guardRuleCoverageLanes returns the lanes a catalog rule's per-tool coverage view shows. */
export function guardRuleCoverageLanes(entry: GuardRuleCatalogEntry | undefined): GuardCoverageLane[] {
  if (!entry) return [];
  return entry.coverageLanes ?? CATEGORY_COVERAGE_LANES[entry.category] ?? [];
}

// GUARD_RULE_CATALOG — transcribed from internal/policy/rules_*.go
// (policy.Catalog()). Where a rule id appears as multiple table rows (e.g. a
// file-access variant and a shell-command variant), the observe/enforce pair
// here is the stricter of all rows for that id — the same
// StricterOf(observe, enforce) reduction internal/guard/merge.go performs
// when it seeds the effective policy from the catalog.
export const GUARD_RULE_CATALOG: GuardRuleCatalogEntry[] = [
  // Destructive — internal/policy/rules_destructive.go
  { id: "R-101", category: "destructive", severity: "critical", observe: "flag", enforce: "deny", doc: "Recursive delete targeting a filesystem root, the home directory, a root-depth wildcard, or a path outside the project." },
  { id: "R-102", category: "destructive", severity: "high", observe: "flag", enforce: "ask", doc: "Recursive delete inside the project targeting the VCS directory or the project root itself; also asks before a recursive delete after a directory change in the same command that the guard cannot resolve, or that leaves the project only if an earlier directory change fails." },
  { id: "R-103", category: "destructive", severity: "high", observe: "flag", enforce: "ask", doc: "Mass-deletion chain (find -delete / xargs rm)." },
  { id: "R-104", category: "destructive", severity: "high", observe: "flag", enforce: "ask", doc: "Git command that discards uncommitted work (reset --hard / checkout -- / clean -f)." },
  { id: "R-110", category: "destructive", severity: "critical", observe: "flag", enforce: "deny", doc: "Force push to a protected branch." },
  { id: "R-111", category: "destructive", severity: "warn", observe: "flag", enforce: "ask", doc: "Deletion of a protected branch or tag." },
  { id: "R-120", category: "destructive", severity: "critical", observe: "flag", enforce: "deny", doc: "Destructive SQL through a database CLI (DROP/TRUNCATE/DELETE without WHERE)." },
  // Database family: internal/policy/rules_database.go ([guard.database])
  { id: "R-121", category: "destructive", severity: "high", observe: "flag", enforce: "ask", doc: "UPDATE without WHERE through a database CLI." },
  { id: "R-122", category: "destructive", severity: "high", observe: "flag", enforce: "ask", doc: "Schema destruction beyond DROP TABLE through a database CLI (DROP INDEX/VIEW/USER/ROLE, ALTER ... DROP)." },
  { id: "R-123", category: "destructive", severity: "critical", observe: "flag", enforce: "deny", doc: "NoSQL or key-value store destruction (dropDatabase, deleteMany({}), FLUSHALL/FLUSHDB, DROP KEYSPACE)." },
  { id: "R-124", category: "destructive", severity: "warn", observe: "flag", enforce: "flag", doc: "ORM or migration reset (prisma migrate reset, rails db:drop, alembic downgrade base, django flush, knex migrate:rollback --all)." },
  { id: "R-125", category: "destructive", severity: "high", observe: "flag", enforce: "ask", doc: "Database command whose host, connection string, database name or profile matches [guard.database] prod_patterns; off while the list is empty." },
  { id: "R-126", category: "destructive", severity: "critical", observe: "flag", enforce: "deny", doc: "SQL run from a file (psql -f, mysql < file.sql) that drops, truncates, or updates or deletes without WHERE." },
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
  { id: "R-157", category: "boundary", severity: "high", observe: "flag", enforce: "deny", doc: "Wrapper whose inner command could not be analysed (fails closed)." },
  { id: "R-160", category: "boundary", severity: "critical", observe: "flag", enforce: "deny", doc: "Agent modifying observer/guard/hook configuration." },
  { id: "R-161", category: "boundary", severity: "high", observe: "flag", enforce: "flag", doc: "Agent modifying the project guard policy file." },
  { id: "R-162", category: "boundary", severity: "critical", observe: "flag", enforce: "deny", doc: "Agent write, edit or shell command that turns a coding agent's hooks off (disableAllHooks and its siblings) in a hook-bearing settings file." },
  { id: "R-163", category: "boundary", severity: "high", observe: "flag", enforce: "flag", doc: "Shell command writing a hook-bearing settings file with content the guard cannot see (recorded)." },
  // Core agent-behaviour rules (D-761): internal/policy/rules_githooks.go, rules_selfapproval.go
  { id: "R-112", category: "boundary", severity: "critical", observe: "flag", enforce: "deny", doc: "Git command that skips the repository's hooks (--no-verify, -n, core.hooksPath for one command, injected git config, or an alias that does so)." },
  { id: "R-113", category: "boundary", severity: "high", observe: "flag", enforce: "deny", doc: "Git command run with a hook manager's skip switch in its environment (HUSKY=0, SKIP=, LEFTHOOK=0); an export of one alone asks." },
  { id: "R-114", category: "boundary", severity: "high", observe: "flag", enforce: "deny", doc: "Change to where or whether git hooks run: git config core.hooksPath or core.fsmonitor, writes into .git/config, refs or objects or the global git config (deny); hook-manager config and .gitattributes custom drivers (ask)." },
  { id: "R-165", category: "boundary", severity: "high", observe: "ask", enforce: "deny", doc: "Agent approving its own guard exception or loosening the guard (observer guard approve, the dashboard's approval routes, a write into guard_approvals); an exception request is recorded, and the laptop-relay opt-in (observer sandbox org-shell opt-in) asks in both modes." },
  { id: "R-166", category: "boundary", severity: "high", observe: "flag", enforce: "deny", doc: "Agent write to a protected test, CI or coverage path; off until [guard.boundary].protected_path_classes names a class (tests, ci, coverage)." },
  // Sandbox egress allow-list: internal/policy/rules_sandboxallow.go
  { id: "R-167", category: "boundary", severity: "high", observe: "flag", enforce: "deny", doc: "Agent calling the local dashboard (the refusal advisor's apply or a settings route) or running observer config set to add a host to the sandbox egress allow-list." },
  // Agent-initiated launches: internal/policy/rules_agentlaunch.go (lane cli-2)
  { id: "R-168", category: "boundary", severity: "high", observe: "ask", enforce: "ask", doc: "Agent launching another agent (observer launch, a launcher verb or a loopback launch route); asked on every launch, no approval covers it." },
  // Exfil — internal/policy/rules_exfil.go
  { id: "R-170", category: "exfil", severity: "critical", observe: "flag", enforce: "deny", doc: "Remote content piped into an interpreter (curl|sh-class remote-code execution)." },
  { id: "R-171", category: "exfil", severity: "high", observe: "flag", enforce: "ask", doc: "Shell command uploading file contents to a remote destination." },
  { id: "R-172", category: "exfil", severity: "critical", observe: "flag", enforce: "deny", doc: "Secret-shaped value in a network command, an outbound LLM API request, or the developer's own prompt.", coverageLanes: CL_PROMPT_TOOL },
  { id: "R-173", category: "exfil", severity: "warn", observe: "flag", enforce: "flag", doc: "DNS lookup of an encoded-looking subdomain (DNS-tunnel exfil shape)." },
  // Network family: internal/policy/rules_network.go ([guard.network]). The
  // rules judge the hosts a command line names; they are not a firewall.
  { id: "R-174", category: "exfil", severity: "critical", observe: "flag", enforce: "deny", doc: "Network command to a cloud metadata endpoint (169.254.169.254, metadata.google.internal) or a [guard.network] deny_hosts host." },
  { id: "R-175", category: "exfil", severity: "warn", observe: "allow", enforce: "allow", doc: "Network command to a private, link-local, CGNAT or raw-IP target; silent until a level or pack raises it." },
  { id: "R-176", category: "exfil", severity: "high", observe: "allow", enforce: "allow", doc: "Network command to a host not on [guard.network] allow_hosts (loopback always passes); silent until a level or pack raises it." },
  { id: "R-177", category: "exfil", severity: "high", observe: "flag", enforce: "deny", doc: "Reverse shell or network listener (nc -l, socat, bash -i >& /dev/tcp/...)." },
  { id: "R-178", category: "exfil", severity: "high", observe: "flag", enforce: "ask", doc: "Tunnel exposing this machine (ngrok, cloudflared tunnel, ssh -R)." },
  { id: "R-179", category: "exfil", severity: "warn", observe: "flag", enforce: "ask", doc: "Network scanner (nmap, masscan)." },
  { id: "R-190", category: "pii", severity: "warn", observe: "flag", enforce: "deny", doc: "Deterministic PII (credit card, SSN, IBAN, ...) in the developer's own prompt text.", coverageLanes: CL_PROMPT },
  // Injection — internal/policy/rules_inject.go
  { id: "R-180", category: "injection", severity: "high", observe: "flag", enforce: "flag", doc: "Inbound tool-result/web content carries injection-shaped instruction patterns." },
  // Posture — internal/policy/rules_posture.go
  { id: "R-204", category: "posture", severity: "high", observe: "flag", enforce: "flag", doc: "Compiled native guard rules drifted from the effective policy." },
  { id: "R-205", category: "posture", severity: "high", observe: "flag", enforce: "flag", doc: "Org policy bundle failed integrity verification and was rejected." },
  // MCP — internal/policy/rules_mcp.go
  { id: "R-301", category: "mcp", severity: "warn", observe: "flag", enforce: "flag", doc: "New MCP server appeared without an approved pin." },
  { id: "R-302", category: "mcp", severity: "critical", observe: "flag", enforce: "flag", doc: "Pinned MCP server's declared tools or descriptions changed (rug-pull shape)." },
  { id: "R-303", category: "mcp", severity: "high", observe: "flag", enforce: "flag", doc: "MCP tool description carries a poisoning-shaped pattern." },
  { id: "R-304", category: "mcp", severity: "critical", observe: "flag", enforce: "deny", doc: "Agent modifying an MCP server registry file.", coverageLanes: CL_TOOL },
  { id: "R-305", category: "mcp", severity: "critical", observe: "flag", enforce: "flag", doc: "Pinned MCP server's command/binary or URL changed under the same name." },
  // MCP access: internal/policy/rules_mcp.go (the tools.mcp_access table; the org sets the grants on the Agent Access pages)
  { id: "R-306", category: "mcp", severity: "high", observe: "flag", enforce: "deny", doc: "MCP tool call to a server not approved by the node's compiled tools.mcp_access table.", coverageLanes: CL_TOOL },
  { id: "R-307", category: "mcp", severity: "critical", observe: "flag", enforce: "deny", doc: "MCP tool call denied by the organization's tools.mcp_access grant.", coverageLanes: CL_TOOL },
  // Anomaly — internal/policy/rules_anomaly.go (anomaly rules never deny, §12.2/F6)
  { id: "A-610", category: "anomaly", severity: "warn", observe: "flag", enforce: "flag", doc: "Identical tool call repeated consecutively past the stuck-loop threshold." },
  { id: "A-613", category: "anomaly", severity: "high", observe: "flag", enforce: "flag", doc: "Repeated attempts at a denied action in different shapes (policy evasion); off until [guard.rules].evasion_window_seconds is set." },
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
  // Token and subject budgets: internal/policy/rules_budget.go (the org sets caps and enforcement on the Budgets page)
  { id: "B-621", category: "budget", severity: "high", observe: "flag", enforce: "flag", doc: "Session token usage exceeded [guard.budget].session_tokens." },
  { id: "B-622", category: "budget", severity: "high", observe: "flag", enforce: "flag", doc: "Daily token usage (all sessions) exceeded [guard.budget].daily_tokens." },
  { id: "B-623", category: "budget", severity: "high", observe: "flag", enforce: "flag", doc: "Calendar-month token usage (all sessions) exceeded [guard.budget].monthly_tokens." },
  { id: "B-624", category: "budget", severity: "high", observe: "flag", enforce: "flag", doc: "Rolling-7-day token usage (all sessions) exceeded [guard.budget].weekly_tokens." },
  { id: "B-625", category: "budget", severity: "high", observe: "flag", enforce: "deny", doc: "The organization requires a budget on this managed node and none has been verified." },
  { id: "B-626", category: "budget", severity: "high", observe: "flag", enforce: "deny", doc: "Per-tool spend exceeded the organization's tool budget cap." },
  { id: "B-627", category: "budget", severity: "high", observe: "flag", enforce: "deny", doc: "Per-tool token usage exceeded the organization's tool budget cap." },
  { id: "B-628", category: "budget", severity: "high", observe: "flag", enforce: "deny", doc: "Per-model spend exceeded the organization's model budget cap." },
  { id: "B-629", category: "budget", severity: "high", observe: "flag", enforce: "deny", doc: "Per-model token usage exceeded the organization's model budget cap." },
  { id: "B-610", category: "limit", severity: "warn", observe: "flag", enforce: "flag", doc: "5h usage window utilization reached [guard.budget.window].util_5h_warn." },
  { id: "B-611", category: "limit", severity: "high", observe: "flag", enforce: "deny", doc: "5h usage window utilization reached [guard.budget.window].util_5h_deny." },
  { id: "B-612", category: "limit", severity: "warn", observe: "flag", enforce: "flag", doc: "Weekly usage window utilization reached [guard.budget.window].util_weekly_warn." },
  { id: "B-613", category: "limit", severity: "high", observe: "flag", enforce: "deny", doc: "Weekly usage window utilization reached [guard.budget.window].util_weekly_deny." },
  // Code security pack: internal/secrules (trust.go, secrets.go, deps.go,
  // gates.go). The rows are composed into a node's guard only while Code
  // security (and the row's part of it) is on there; an org override on one
  // is valid fleet policy either way and applies once the module is on.
  // Repository trust: internal/secrules/trust.go
  { id: "S-701", category: "code_security", severity: "high", observe: "flag", enforce: "ask", doc: "Agent launch in an untrusted repository that makes the agent run commands, or holds config files nothing could judge, that nobody accepted yet. Needs Code security on the node.", module: "Code security" },
  { id: "S-702", category: "code_security", severity: "critical", observe: "flag", enforce: "deny", doc: "Agent launch in an untrusted repository that redirects the agent's API, its config or Observer's own binary, or injects code into its process. Needs Code security on the node.", module: "Code security" },
  { id: "S-703", category: "code_security", severity: "critical", observe: "flag", enforce: "deny", doc: "Agent launch in an untrusted repository that switches off the agent's approvals, its folder trust or its hooks. Needs Code security on the node.", module: "Code security" },
  { id: "S-704", category: "code_security", severity: "high", observe: "flag", enforce: "ask", doc: "Agent launch in an untrusted repository that hides instructions or code, links its config outside the tree, or sets git to run a program. Needs Code security on the node.", module: "Code security" },
  { id: "S-705", category: "code_security", severity: "warn", observe: "flag", enforce: "flag", doc: "Agent launch in a repository with accepted commands or warnings. Needs Code security on the node.", module: "Code security" },
  // Secrets: internal/secrules/secrets.go
  { id: "S-721", category: "secrets", severity: "high", observe: "flag", enforce: "deny", doc: "Agent write that adds a secret (asks for one in a fixture path). Needs Code security on the node.", module: "Code security", coverageLanes: CL_TOOL },
  // Package installs: internal/secrules/deps.go
  { id: "S-741", category: "code_security", severity: "critical", observe: "ask", enforce: "deny", doc: "Agent install of a package an authenticated source lists as malicious. Needs Code security on the node.", module: "Code security", coverageLanes: CL_TOOL },
  { id: "S-742", category: "code_security", severity: "high", observe: "ask", enforce: "ask", doc: "Agent install of a package one edit from a popular name (a possible typosquat). Needs Code security on the node.", module: "Code security", coverageLanes: CL_TOOL },
  { id: "S-743", category: "code_security", severity: "warn", observe: "flag", enforce: "flag", doc: "Agent install of a package published more recently than the minimum package age. Needs Code security on the node.", module: "Code security", coverageLanes: CL_TOOL },
  { id: "S-744", category: "code_security", severity: "warn", observe: "ask", enforce: "deny", doc: "Agent install of a package the registry does not know, or that no usable index could check; also the once-per-session note that package checks are not set up. Needs Code security on the node.", module: "Code security", coverageLanes: CL_TOOL },
  { id: "S-745", category: "code_security", severity: "warn", observe: "flag", enforce: "flag", doc: "Agent install that names a custom registry or package index (dependency confusion). Needs Code security on the node.", module: "Code security", coverageLanes: CL_TOOL },
  { id: "S-747", category: "code_security", severity: "warn", observe: "flag", enforce: "flag", doc: "Agent manifest edit that adds a dependency the install gate flags. Needs Code security on the node.", module: "Code security", coverageLanes: CL_TOOL },
  { id: "S-748", category: "code_security", severity: "warn", observe: "ask", enforce: "deny", doc: "Agent install the online package check could not answer in time. Needs Code security on the node.", module: "Code security", coverageLanes: CL_TOOL },
  { id: "S-749", category: "code_security", severity: "high", observe: "flag", enforce: "flag", doc: "Agent install of a package some of whose versions are listed as malicious, without a pin outside them. Needs Code security on the node.", module: "Code security", coverageLanes: CL_TOOL },
  { id: "S-757", category: "code_security", severity: "high", observe: "flag", enforce: "flag", doc: "Agent install of a version that lacks the build provenance earlier versions of the package carried (npm provenance, a PyPI attestation). Needs Code security on the node.", module: "Code security", coverageLanes: CL_TOOL },
  // Commit gate: internal/secrules/gates.go gateTable. Each id is two rows:
  // the individual gate (asks even in observe mode) and the org's commit
  // gate floor twin (denies). The pair here is the stricter of both, as for
  // every split id, because that is the reference an org override is checked
  // against.
  { id: "S-791", category: "code_security", severity: "high", observe: "deny", enforce: "deny", doc: "Agent commit while a new high-confidence finding is open in this project. Asks on an individual node; denies under the org's commit gate floor. Needs Code security on the node.", module: "Code security", coverageLanes: CL_TOOL },
  { id: "S-792", category: "code_security", severity: "high", observe: "deny", enforce: "deny", doc: "Agent push while a new high-confidence finding is open in this project, or held by a commit the push's remote does not have yet. Asks on an individual node; denies under the org's commit gate floor. Needs Code security on the node.", module: "Code security", coverageLanes: CL_TOOL },
  { id: "S-793", category: "code_security", severity: "warn", observe: "deny", enforce: "deny", doc: "Agent commit with agent changes that the quick scan did not find clean. Asks on an individual node; denies under the org's commit gate floor. Needs Code security on the node.", module: "Code security", coverageLanes: CL_TOOL },
  { id: "S-794", category: "code_security", severity: "warn", observe: "deny", enforce: "deny", doc: "Agent commit while this project's security state is unknown. Asks on an individual node; denies under the org's commit gate floor. Needs Code security on the node.", module: "Code security", coverageLanes: CL_TOOL },
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
// modifying observer/guard/hook config), R-161 (agent modifying the project
// guard file), R-162 (agent turning a coding agent's hooks off, T-910),
// R-165 (agent approving its own guard exception, D-761), R-167 (agent
// adding a host to its own sandbox egress allow-list, OB-029) and R-168
// (agent launching another agent, asked on every launch, lane cli-2).
// Mirrors internal/policy/engine.go::IsIntegrityRuleID, a closed set;
// internal/policy/integrity_ts_mirror_test.go fails when the two differ.
// The policy engine is a HARD BACKSTOP that refuses to disable or weaken
// these below the org floor at merge time regardless of layer, so the picker
// must never OFFER a weaken it can't apply — even in a weaken-allowed layer.
export function isGuardIntegrityRuleId(id: string): boolean {
  const needle = id.trim();
  return needle === "R-160" || needle === "R-161" || needle === "R-162" || needle === "R-165" || needle === "R-167" || needle === "R-168";
}

// guardDecisionOptionsFor returns the decisions legal for a given rule id
// (at-or-above its escalate-only floor for a catalogued rule; all four for a
// free-text one). This is a UI hint only — the org/user lint is the real
// gate. NOTE: a weaken-allowed layer (the trusted-project layer §3, or the
// user/global structured picker) offers all four decisions — EXCEPT for an
// integrity rule (isGuardIntegrityRuleId), which stays escalate-only even
// when weakening is allowed, matching the policy engine's hard backstop.
export function guardDecisionOptionsFor(id: string, allowWeaken = false): Decision[] {
  if (allowWeaken && !isGuardIntegrityRuleId(id)) return DECISIONS;
  const floor = guardMinDecisionFor(id);
  if (!floor) return DECISIONS;
  return DECISIONS.filter((d) => DECISION_ORDER[d] >= DECISION_ORDER[floor]);
}

export function emptyGuardOverride(): GuardOverrideRow {
  return { rule: "", decision: "", enforce: true };
}

// composeGuardToml renders an ORG guard bundle: the org's own `[[rule]]`
// definitions (custom rules, matcher-v1) and then its `[[override]]` rows
// over built-in rules — the shapes internal/guard/policyfile.go parses at
// layer "org", with no wrapping table header, matching both shipped starter
// bundles. `decision` is emitted only when set (an enforce-only override with
// no decision change is legal TOML). With no custom rules the bytes are
// exactly what the override-only composer produced, so a fleet that never
// authors one keeps byte-identical bundles.
//
// A custom rule the org marks overridable (GuardRuleRow.overridable) is
// written as its own grant row straight after the rule: an `[[override]]`
// naming the rule id that carries ONLY `overridable = true`. `overridable` is
// an [[override]] key, never a [[rule]] key (guardbundle.ClarifyProblems), and
// the row carries no `enforce` key on purpose: `enforce = false` would cap the
// rule at flag and `enforce = true` would enforce it in observe mode, neither
// of which the author asked for. parseGuardBundle folds the row back.
export function composeGuardToml(rows: GuardOverrideRow[], rules: GuardRuleRow[] = []): string {
  const lines: string[] = [
    "# Org guard-policy bundle (TOML; merged on every agent as the strictness floor)",
  ];
  for (const r of rules) {
    const id = r.id.trim();
    if (!id) continue;
    lines.push("", ...ruleBlockLines(r));
    if (r.overridable === true) lines.push("", "[[override]]", `rule = ${tomlStr(id)}`, "overridable = true");
  }
  for (const r of rows) {
    if (!r.rule.trim()) continue;
    lines.push("", ...overrideBlockLines(r, ORG_GUARD_GRAMMAR));
  }
  return lines.join("\n") + "\n";
}

// parseGuardOverrides is the override-only view of parseGuardBundle, kept for
// the callers that edit overrides alone (the setup wizard's guard step): a
// bundle that also defines `[[rule]]` entries returns null so such a caller
// falls back to its Advanced raw-TOML editor instead of dropping them.
export function parseGuardOverrides(toml: string): GuardOverrideRow[] | null {
  const b = parseGuardBundle(toml);
  if (!b || b.rules.length > 0) return null;
  return b.overrides;
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

// GUARD_FILE_ACCESS is match.access's vocabulary: a file rule narrowed to
// reads or to writes (a write or edit, or any config change), the
// classification R-150 uses. Empty (the editor's "either") matches both.
export const GUARD_FILE_ACCESS = ["read", "write"] as const;
export type GuardFileAccess = (typeof GUARD_FILE_ACCESS)[number];

// GUARD_RULE_TEXT_MAX mirrors internal/guard/policyfile.go maxRuleDocLen: a
// [[rule]]'s doc and advice are each one line of at most this many
// characters.
export const GUARD_RULE_TEXT_MAX = 300;

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
  // access narrows a file rule to reads or writes; "" matches both. It
  // implies the file_access and config_change kinds, like the path matchers.
  access: GuardFileAccess | "";
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
  // doc is the rule's one-liner, the verdict reason's prefix the agent reads
  // ("" keeps the guard's "<layer> rule <id>"); advice is the one sentence a
  // verdict carries on what to do instead ("" = none). Both optional.
  doc: string;
  advice: string;
  // overridable is the org's grant for its OWN rule (org bundles only,
  // ORG_GUARD_GRAMMAR): true lets a developer approve past the rule on their
  // own machine, scoped and logged, like GuardOverrideRow.overridable on a
  // built-in. It is composed as a separate `[[override]]` grant row, never a
  // [[rule]] key. undefined / false = the rule is hard. The node's own layers
  // cannot grant it, so composeRuleToml ignores it.
  overridable?: boolean;
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
    access: "",
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
    doc: "",
    advice: "",
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
    e.access ||
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
    e.access ||
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
    problems.push(`This rule has no ${r.scope === "command" ? "command" : "event"} matchers - it would never fire.`);
  }
  if (guardRuleRowIsPureCondition(r) && r.applies_to.length === 0 && r.event.event_kind.length === 0) {
    problems.push(
      "A pure-condition rule (taint_source / session_cost_usd_gt / repeat_count_gt) implies no event kind - set Applies to explicitly.",
    );
  }
  for (const [label, text] of [
    ["Doc", r.doc],
    ["Advice", r.advice],
  ] as const) {
    const t = text.trim();
    if (/[\r\n]/.test(t) || t.length > GUARD_RULE_TEXT_MAX) {
      problems.push(`${label} must be one line of at most ${GUARD_RULE_TEXT_MAX} characters.`);
    }
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
  // The file lands on a developer's machine, so it points at the public
  // guide, never at an internal document path.
  const lines: string[] = [
    "# Guard policy (TOML) - composed by the dashboard's rule manager.",
    "# Guide: https://superbased.app/docs/guides/security-guard",
  ];
  const allowDisable = opts?.allowDisable ?? false;
  const disableIds = [...new Set(disable.map((d) => d.trim()).filter(Boolean))];
  if (allowDisable && disableIds.length > 0) {
    lines.push("", `disable = ${tomlStrArray(disableIds)}`);
  }
  for (const r of rules) {
    if (!r.id.trim()) continue;
    lines.push("", ...ruleBlockLines(r));
  }
  for (const r of overrides) {
    if (!r.rule.trim()) continue;
    lines.push("", ...overrideBlockLines(r, LOCAL_GUARD_GRAMMAR));
  }
  return lines.join("\n") + "\n";
}

// ruleBlockLines renders one `[[rule]]` block (no leading blank line) — the
// ONE rule renderer both composers share, so a node policy file and an org
// bundle write a rule byte-for-byte the same way.
function ruleBlockLines(r: GuardRuleRow): string[] {
  const lines: string[] = [];
  const id = r.id.trim();
  lines.push("[[rule]]");
  lines.push(`id         = ${tomlStr(id)}`);
  if (r.category.trim()) lines.push(`category   = ${tomlStr(r.category.trim())}`);
  lines.push(`severity   = ${tomlStr(r.severity)}`);
  lines.push(`decision   = ${tomlStr(r.decision)}`);
  if (r.enforce) lines.push("enforce    = true");
  if (r.applies_to.length) lines.push(`applies_to = ${tomlStrArray(r.applies_to)}`);
  if (r.doc.trim()) lines.push(`doc        = ${tomlStr(r.doc.trim())}`);
  if (r.advice.trim()) lines.push(`advice     = ${tomlStr(r.advice.trim())}`);
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
    if (e.access) lines.push(`match.access = ${tomlStr(e.access)}`);
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
  return lines;
}

// overrideBlockLines renders one `[[override]]` block (no leading blank
// line). `overridable` is written only where the grammar grants it (the org
// layer) and only when the author spoke: an unspoken rule is already hard by
// default, and an emitted key would change the bytes of every bundle in every
// fleet that has no use for the flag.
function overrideBlockLines(r: GuardOverrideRow, grammar: GuardPolicyGrammar): string[] {
  const lines = ["[[override]]", `rule = ${tomlStr(r.rule.trim())}`];
  if (r.decision) lines.push(`decision = ${tomlStr(r.decision)}`);
  lines.push(`enforce = ${r.enforce ? "true" : "false"}`);
  if (grammar.overridable && r.overridable !== undefined) lines.push(`overridable = ${r.overridable ? "true" : "false"}`);
  return lines;
}

// GuardPolicyGrammar is what one policy layer's file may say beyond the
// `[[rule]]` / `[[override]]` keys every layer shares
// (internal/guard/policyfile.go::parsePolicyFile): the differences between
// the node's own files and an org bundle are this data, never a branch on
// which dashboard is asking.
export type GuardPolicyGrammar = {
  /** A top-level `disable = [...]` list (the trusted-project layer). */
  disable: boolean;
  /** `overridable` on an `[[override]]` row (only the org grants it). */
  overridable: boolean;
};

// LOCAL_GUARD_GRAMMAR is the node rule manager's: user and trusted-project
// files. `disable` parses (composeRuleToml writes it only for the
// trusted-project layer); `overridable` does not, since a node layer cannot
// grant it (merge.go noteUngrantableOverridable).
export const LOCAL_GUARD_GRAMMAR: GuardPolicyGrammar = { disable: true, overridable: false };

// ORG_GUARD_GRAMMAR is an org bundle's: `overridable` grants, and `disable`
// is not an org key (the org layer ignores it; Lint refuses it).
export const ORG_GUARD_GRAMMAR: GuardPolicyGrammar = { disable: false, overridable: true };

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
  const p = parsePolicyText(toml, LOCAL_GUARD_GRAMMAR);
  return p && { rules: p.rules, overrides: p.overrides, disable: p.disable };
}

// GuardBundleForm is what the org guard form edits: the bundle's custom
// `[[rule]]` definitions and its `[[override]]` rows over built-in rules.
export type GuardBundleForm = {
  rules: GuardRuleRow[];
  overrides: GuardOverrideRow[];
};

// parseGuardBundle is the inverse of composeGuardToml under ORG_GUARD_GRAMMAR,
// as strict as parseRules: anything the form cannot represent (a `disable`
// list, a `[fallbacks]` table, an unknown key, a multi-line value) returns
// null so the caller opens the Advanced raw-TOML editor rather than dropping
// it. An `[[override]]` row carrying ONLY `rule` and `overridable = true` for
// a custom rule the same bundle defines is the rule's grant row
// (composeGuardToml) and folds back onto GuardRuleRow.overridable.
export function parseGuardBundle(toml: string): GuardBundleForm | null {
  const p = parsePolicyText(toml, ORG_GUARD_GRAMMAR);
  if (!p) return null;
  const byId = new Map<string, GuardRuleRow>();
  for (const r of p.rules) if (!byId.has(r.id.trim())) byId.set(r.id.trim(), r);
  const overrides: GuardOverrideRow[] = [];
  p.overrides.forEach((o, i) => {
    const keys = p.overrideKeys[i];
    const rule = byId.get(o.rule.trim());
    if (rule && o.overridable === true && keys.size === 2 && keys.has("rule") && keys.has("overridable")) {
      rule.overridable = true;
      return;
    }
    overrides.push(o);
  });
  return { rules: p.rules, overrides };
}

// stripTomlComment drops a trailing `# ...` comment from one line, ignoring a
// `#` inside a quoted string (a regex or a glob may hold one). The starter
// bundles annotate each `rule = "R-101"      # ...` line this way.
function stripTomlComment(line: string): string {
  let quote: '"' | "'" | null = null;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote) {
      if (quote === '"' && c === "\\") i++;
      else if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'") quote = c;
    else if (c === "#") return line.slice(0, i);
  }
  return line;
}

type ParsedPolicyText = ParsedGuardPolicy & {
  // overrideKeys[i] is the set of keys overrides[i] actually wrote (an
  // absent `enforce` and an explicit one parse to the same row).
  overrideKeys: Set<string>[];
};

// parsePolicyText is the ONE strict parser behind parseRules and
// parseGuardBundle; the grammar says which layer-specific keys parse.
function parsePolicyText(toml: string, grammar: GuardPolicyGrammar): ParsedPolicyText | null {
  const rules: GuardRuleRow[] = [];
  const overrides: GuardOverrideRow[] = [];
  const overrideKeys: Set<string>[] = [];
  let disable: string[] = [];
  let disableSeen = false;

  let mode: "none" | "rule" | "override" = "none";
  let curRule: GuardRuleRow | null = null;
  let curOverride: GuardOverrideRow | null = null;
  let curKeys = new Set<string>();
  let curRuleScope: GuardMatchScope | null = null;

  function flushCurrent(): boolean {
    if (mode === "rule") {
      if (!curRule || !curRule.id.trim()) return false;
      rules.push(curRule);
    } else if (mode === "override") {
      if (!curOverride || !curOverride.rule.trim()) return false;
      overrides.push(curOverride);
      overrideKeys.push(curKeys);
    }
    return true;
  }

  for (const rawLine of toml.split(/\r?\n/)) {
    const line = stripTomlComment(rawLine).trim();
    if (line === "") continue;

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
      curKeys = new Set<string>();
      curRule = null;
      mode = "override";
      continue;
    }

    const m = /^([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*(.+)$/.exec(line);
    if (!m) return null;
    const key = m[1];
    const val = m[2].trim();

    if (mode === "none") {
      if (!grammar.disable || key !== "disable" || disableSeen) return null;
      const arr = parseTomlStringArray(val);
      if (arr === null) return null;
      disable = arr;
      disableSeen = true;
      continue;
    }

    if (mode === "override") {
      if (!curOverride) return null;
      if (curKeys.has(key)) return null;
      curKeys.add(key);
      if (key === "overridable" && grammar.overridable) {
        if (val !== "true" && val !== "false") return null;
        curOverride.overridable = val === "true";
      } else if (key === "rule") {
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
    } else if (key === "doc" || key === "advice") {
      const s = tomlUnquote(val);
      if (s === null) return null;
      curRule[key] = s;
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
        case "access": {
          const s = tomlUnquote(val);
          if (s === null || !(GUARD_FILE_ACCESS as readonly string[]).includes(s)) return null;
          e.access = s as GuardFileAccess;
          break;
        }
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
  return { rules, overrides, disable, overrideKeys };
}

// --- Custom rule ids (advisory; internal/guard/policyfile.go compileRule is
// the gate) ---
//
// The lint enforces only two things about a [[rule]] id: it is not a built-in
// id ("id collides with built-in rule ...") and it is unique within one file
// ("duplicate id"). No prefix is required. The org form still SUGGESTS one,
// ORG-<n>, because the built-in catalog grows release by release under R-,
// the code security rule pack owns S-7.., and an org id that a later release
// claims stops loading (the built-in collision is a parse error on the node).

// ORG_CUSTOM_RULE_ID_PREFIX is the prefix the org form suggests.
export const ORG_CUSTOM_RULE_ID_PREFIX = "ORG-";

// RESERVED_RULE_ID_PREFIXES are the namespaces Observer's own rules use; an
// author id inside one may collide with a rule a later release adds.
const RESERVED_RULE_ID_PREFIXES: readonly { prefix: string; owner: string }[] = [
  { prefix: "R-", owner: "built-in rules" },
  { prefix: "S-7", owner: "the code security rule pack" },
];

// suggestCustomRuleId returns the first `<prefix><n>` (n from 1) that no id in
// taken uses.
export function suggestCustomRuleId(prefix: string, taken: Iterable<string>): string {
  const used = new Set<string>();
  for (const t of taken) used.add(t.trim());
  for (let n = 1; ; n++) {
    const id = `${prefix}${n}`;
    if (!used.has(id)) return id;
  }
}

// guardCustomRuleIdProblems is the advisory check on one custom rule id
// against the built-in catalog, the reserved namespaces and the other custom
// rules in the same file (others: their ids, this rule's own excluded). Empty
// means nothing to say; an empty id is guardRuleRowProblems' business.
export function guardCustomRuleIdProblems(id: string, others: readonly string[]): string[] {
  const t = id.trim();
  if (!t) return [];
  if (guardRuleInfo(t)) {
    return [`${t} is a built-in rule. To change it, add it under the built-in rules instead; a custom rule needs its own id.`];
  }
  const out: string[] = [];
  if (others.some((o) => o.trim() === t)) out.push(`Another custom rule here already uses the id ${t}.`);
  const reserved = RESERVED_RULE_ID_PREFIXES.find((r) => t.startsWith(r.prefix));
  if (reserved) {
    out.push(`Ids starting with ${reserved.prefix} belong to ${reserved.owner}; a later release may add ${t} and this rule would stop loading. Use ${ORG_CUSTOM_RULE_ID_PREFIX}... instead.`);
  }
  return out;
}

// guardProblemsForRule picks the lint problems that name one custom rule: the
// parser's "rule <n> (<id>): ..." form (position = the rule's 1-based place
// among the composed [[rule]] blocks) or any problem naming the id as a whole
// token (the merge's "org override on <id> ..." form). Problems that name no
// rule stay with the bundle as a whole.
export function guardProblemsForRule(problems: readonly string[], id: string, position: number): string[] {
  const t = id.trim();
  if (!t) return [];
  const esc = t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const token = new RegExp(`(^|[^A-Za-z0-9_-])${esc}($|[^A-Za-z0-9_-])`);
  const at = `rule ${position} (`;
  return problems.filter((p) => p.startsWith(at) || token.test(p));
}

// guardRuleMatcherSummary is the one-line "what does it match" text of a
// custom rule for a rules table: its set matchers of the active scope, in
// composer order, as `key value` pairs.
export function guardRuleMatcherSummary(r: GuardRuleRow): string {
  const parts: string[] = [];
  const add = (k: string, v: string | boolean | readonly string[]) => {
    if (typeof v === "boolean") {
      if (v) parts.push(k);
    } else if (typeof v === "string") {
      if (v.trim()) parts.push(`${k} ${v.trim()}`);
    } else if (v.length) {
      parts.push(`${k} ${v.join(", ")}`);
    }
  };
  if (r.scope === "command") {
    add("command_regex", r.command.command_regex);
    add("command_base", r.command.command_base);
    add("arg_contains", r.command.arg_contains);
  } else {
    const e = r.event;
    add("path_glob", e.path_glob);
    add("path_not", e.path_not);
    add("path_outside_project", e.path_outside_project);
    add("path_sensitive", e.path_sensitive);
    add("access", e.access);
    add("url_domain", e.url_domain);
    add("mcp_server", e.mcp_server);
    add("mcp_tool", e.mcp_tool);
    add("event_kind", e.event_kind);
    add("sink", e.sink);
    add("taint_source", e.taint_source);
    add("session_cost_usd_gt", e.session_cost_usd_gt);
    add("repeat_count_gt", e.repeat_count_gt);
  }
  return parts.join("; ");
}

// blankGuardBundleForm is the org guard form with nothing in it yet: one
// empty built-in rule row to fill in, no custom rules.
export function blankGuardBundleForm(): GuardBundleForm {
  return { overrides: [emptyGuardOverride()], rules: [] };
}

// guardBundleFormIsEmpty reports a parsed bundle with no rows at all (a
// header-only or withdrawn body), which the editor opens as the blank form.
export function guardBundleFormIsEmpty(f: GuardBundleForm): boolean {
  return f.overrides.length === 0 && f.rules.length === 0;
}
