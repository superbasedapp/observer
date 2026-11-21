import type { GuardRule } from "@/lib/types";

// ruleScope: how the Effective rules table names where a rule comes from. The
// Source pill says which layer gives the rule its decision, in words (a
// built-in rule at its catalog decision, a rule your organization sets, your
// own rules, a project's rules); an organization rule scoped to one of its
// projects (an org project section, GuardRule.project) adds "project <id>",
// and a rule several of the org's projects define names every project once.

/** ruleProjects is the org projects the rule's rows are scoped to, sorted
 *  and deduplicated ([] for a rule in force on every project). */
export function ruleProjects(defs: readonly GuardRule[] | undefined): string[] {
  const set = new Set<string>();
  for (const d of defs ?? []) if (d.project) set.add(d.project);
  return [...set].sort();
}

// RULE_SOURCE_LABEL names each policy layer a rule row can come from
// (policy.RuleInfo.Source). A prefix row ends in ":"; walked top down.
const RULE_SOURCE_LABEL: readonly { source: string; label: string }[] = [
  { source: "builtin", label: "Built-in" },
  { source: "org", label: "Your organization" },
  { source: "user", label: "Your rules" },
  { source: "trusted_project", label: "This project (your rules)" },
  { source: "project", label: "Project file" },
  { source: "pack:security", label: "Built-in, Code security" },
  { source: "pack:", label: "Built-in pack" },
];

/** ruleSourceName is the words for one layer; an unknown layer keeps its
 *  own name so nothing reads as a guess. */
export function ruleSourceName(source: string | undefined): string {
  const s = source || "builtin";
  for (const row of RULE_SOURCE_LABEL) {
    if (s === row.source || (row.source.endsWith(":") && s.startsWith(row.source))) return row.label;
  }
  return s;
}

/** ruleSourceLabel is the Source pill's text for one rule id. */
export function ruleSourceLabel(defs: readonly GuardRule[] | undefined): string {
  // A multi-row id reads as your organization's when any row is.
  const label = ruleSourceName((defs ?? []).find((d) => d.source === "org")?.source ?? defs?.[0]?.source);
  const projects = ruleProjects(defs);
  if (projects.length === 0) return label;
  return `${label} · project ${projects.join(", ")}`;
}
