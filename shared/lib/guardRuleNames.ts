// guardRuleNames - the human name of every built-in guard rule, keyed by its
// stable catalog id (design review 2026-10-13: the rule picker and the
// Security rule-hit table showed bare ids such as "R-172 (critical)" and a
// lowercase category slug).
//
// The Go catalog (internal/policy/rules_*.go, Rule struct) carries an id, a
// category, a severity and a one-line doc, but NO display name. Each name
// below is therefore DERIVED from that rule's doc string (GUARD_RULE_CATALOG
// in ./guardCatalog.ts): a short noun phrase that says what the rule catches,
// never a claim the doc does not make. When a rule's doc changes, re-derive
// its name here. The id stays visible beside the name everywhere (muted, mono)
// because admins and the docs refer to rules by id.
//
// Pure data, no imports, so node:test can load it directly.

/** GUARD_RULE_NAMES maps a built-in rule id to its display name. */
export const GUARD_RULE_NAMES: Readonly<Record<string, string>> = {
  // Destructive
  "R-101": "Recursive delete of a root, home or outside path",
  "R-102": "Recursive delete of the repo or project root",
  "R-103": "Mass deletion chain",
  "R-104": "Git command that discards uncommitted work",
  "R-110": "Force push to a protected branch",
  "R-111": "Deleting a protected branch or tag",
  "R-120": "Destructive SQL command",
  "R-130": "Cloud infrastructure destruction",
  "R-140": "Package registry publish or yank",
  "R-141": "Bulk permission or ownership change",
  "R-142": "Disk or device level operation",
  // Boundary
  "R-150": "File access outside the project",
  "R-151": "Write into another project",
  "R-152": "Sensitive credential location access",
  "R-153": "Reading a secrets file",
  "R-154": "Write to a shell startup file",
  "R-155": "Installing an autostart or persistence entry",
  "R-156": "Write to git hooks",
  "R-157": "Command the guard cannot analyse",
  "R-160": "Agent changing Observer or guard settings",
  "R-161": "Agent changing the project guard file",
  "R-162": "Agent turning a coding tool's hooks off",
  "R-163": "Settings file written with unseen content",
  "R-112": "Git command skipping the repository's hooks",
  "R-113": "Git hook manager switched off by environment",
  "R-114": "Changing where or whether git hooks run",
  "R-165": "Agent approving its own guard exception",
  "R-166": "Agent writing a protected test or CI path",
  // Exfil and PII
  "R-170": "Remote script piped into a shell",
  "R-171": "Uploading file contents to a remote host",
  "R-172": "Secret sent over the network or in a prompt",
  "R-173": "DNS tunnelling pattern",
  "R-190": "Personal data in a prompt",
  // Injection and posture
  "R-180": "Prompt injection in tool or web content",
  "R-204": "Compiled guard rules drifted",
  "R-205": "Org rules failed integrity check",
  // MCP
  "R-301": "New MCP server not approved",
  "R-302": "Approved MCP server's tools changed",
  "R-303": "Poisoned MCP tool description",
  "R-304": "Agent changing the MCP server list",
  "R-305": "Approved MCP server's command or URL changed",
  // Anomaly
  "A-610": "Agent stuck in a loop",
  "A-613": "Agent retrying a refused action in new shapes",
  // Taint
  "T-501": "Shell command after untrusted content",
  "T-502": "Out-of-project write after untrusted content",
  "T-503": "Git push after untrusted content",
  "T-504": "Network command after reading secrets",
  "T-505": "Cross-server MCP call after unapproved content",
  // Budget and limits
  "B-601": "Session spend over budget",
  "B-602": "Daily spend over budget",
  "B-603": "Monthly spend over budget",
  "B-604": "Weekly spend over budget",
  "B-610": "5-hour usage limit warning",
  "B-611": "5-hour usage limit reached",
  "B-612": "Weekly usage limit warning",
  "B-613": "Weekly usage limit reached",
};

/** GUARD_CATEGORY_LABEL names each catalog category (the catalog spells them
 *  as lowercase slugs) for picker group headers and rule-hit tables. */
export const GUARD_CATEGORY_LABEL: Readonly<Record<string, string>> = {
  destructive: "Destructive commands",
  boundary: "Project boundary",
  exfil: "Data exfiltration",
  pii: "Personal data",
  injection: "Prompt injection",
  posture: "Guard integrity",
  mcp: "MCP servers",
  anomaly: "Anomalies",
  taint: "Untrusted content",
  budget: "Budget",
  limit: "Usage limits",
  secrets: "Secrets",
};

/** guardCategoryLabel names a category; an unknown one keeps its spelling. */
export function guardCategoryLabel(category: string): string {
  return GUARD_CATEGORY_LABEL[category] ?? category;
}

/** guardRuleName returns a rule's display name, or undefined for an id the
 *  catalog does not know (an org's own rule, or a newer agent's rule). */
export function guardRuleName(id: string): string | undefined {
  return GUARD_RULE_NAMES[id.trim()];
}

/** guardRuleOptionText is the one-line text a native <option> can carry:
 *  "Secret sent over the network or in a prompt (R-172, critical)". An
 *  uncatalogued id falls back to the id itself. */
export function guardRuleOptionText(id: string, severity?: string): string {
  const name = guardRuleName(id);
  const meta = severity ? `${id}, ${severity}` : id;
  return name ? `${name} (${meta})` : severity ? `${id} (${severity})` : id;
}

/** GUARD_DECISION_LABEL is the sentence-case word for each guard decision,
 *  for buttons and pickers (design review 2026-10-13: the decision control
 *  showed bare lowercase wire values). "" is the editor's no-change choice. */
export const GUARD_DECISION_LABEL: Readonly<Record<string, string>> = {
  "": "No change",
  allow: "Allow",
  flag: "Flag",
  ask: "Ask",
  deny: "Deny",
};

/** guardDecisionLabel returns the sentence-case word for a decision, falling
 *  back to the value itself for one this table does not know. */
export function guardDecisionLabel(decision: string): string {
  return GUARD_DECISION_LABEL[decision] ?? decision;
}
