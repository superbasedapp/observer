// The Effective rules table names an org rule scoped to one of the
// organization's projects with that project (round-3 finding: the node's
// effective rules left the org's project-scoped rules out).

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { EffectiveRulesTable } from "@/pages/security/RuleManager";
import { ruleProjects, ruleSourceLabel } from "@/pages/security/ruleScope";
import type { GuardRule } from "@/lib/types";

const row = (id: string, extra: Partial<GuardRule>): GuardRule => ({ id, doc: `${id} doc`, category: "exfil", ...extra });

const cases: { name: string; defs: GuardRule[]; label: string; projects: string[] }[] = [
  { name: "a built-in", defs: [row("R-101", { source: "builtin" })], label: "Built-in", projects: [] },
  { name: "an org-wide org rule", defs: [row("ORG-1", { source: "org" })], label: "Your organization", projects: [] },
  { name: "a built-in the org overrides", defs: [row("R-101", { source: "org" })], label: "Your organization", projects: [] },
  { name: "a multi-row id one org row of which the org overrides", defs: [row("R-152", { source: "builtin" }), row("R-152", { source: "org" })], label: "Your organization", projects: [] },
  { name: "a user rule", defs: [row("U-1", { source: "user" })], label: "Your rules", projects: [] },
  { name: "a trusted project rule", defs: [row("T-1", { source: "trusted_project" })], label: "This project (your rules)", projects: [] },
  { name: "an in-repo project rule", defs: [row("P-1", { source: "project" })], label: "Project file", projects: [] },
  { name: "a Code security pack rule", defs: [row("S-791", { source: "pack:security" })], label: "Built-in, Code security", projects: [] },
  { name: "another pack", defs: [row("S-1", { source: "pack:other" })], label: "Built-in pack", projects: [] },
  { name: "an unknown layer keeps its name", defs: [row("X-1", { source: "future" })], label: "future", projects: [] },
  { name: "an org rule scoped to one project", defs: [row("PRJ-X1", { source: "org", project: "X" })], label: "Your organization · project X", projects: ["X"] },
  {
    name: "an id two projects define, each once",
    defs: [row("PRJ-2", { source: "org", project: "Y" }), row("PRJ-2", { source: "org", project: "X" }), row("PRJ-2", { source: "org", project: "Y" })],
    label: "Your organization · project X, Y",
    projects: ["X", "Y"],
  },
  { name: "no rows", defs: [], label: "Built-in", projects: [] },
];

for (const c of cases) {
  test(`ruleSourceLabel: ${c.name}`, () => {
    assert.equal(ruleSourceLabel(c.defs), c.label);
    assert.deepEqual(ruleProjects(c.defs), c.projects);
  });
}

test("the Effective rules table shows a project-scoped org rule with its project", () => {
  const defs = new Map<string, GuardRule[]>([["PRJ-X1", [row("PRJ-X1", { source: "org", project: "X" })]]]);
  const html = renderToStaticMarkup(
    <EffectiveRulesTable ruleDefs={defs} ids={["PRJ-X1"]} loading={false} onOverride={() => {}} onDisable={() => {}} />,
  );
  assert.match(html, /Your organization · project X/);
});
