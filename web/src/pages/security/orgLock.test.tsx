// On a managed node the rule manager offers no Disable or Override for a rule
// the organization locks there (round-3 finding). It says "Set by your
// organization" only for a rule the organization's bundle sets itself, and
// "Locked by your organization" for a rule that runs at its built-in decision
// and is only locked (2026-11-12 operator report: every one of 81 rules read
// "Set by your organization" while the bundle named four). Any other rule
// keeps both controls.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { EffectiveRulesTable } from "@/pages/security/RuleManager";
import { orgLockNote, orgUnlockedIds, ruleLockedByOrg, ruleSetByOrg } from "@/pages/security/orgLock";
import type { GuardRule } from "@/lib/types";

const row = (id: string, extra: Partial<GuardRule>): GuardRule => ({ id, doc: `${id} doc`, category: "destructive", ...extra });

type Want = "set" | "locked" | "open";

const cases: { name: string; defs: GuardRule[]; want: Want }[] = [
  { name: "a built-in no org lock reaches", defs: [row("R-101", { source: "builtin" })], want: "open" },
  { name: "a built-in the managed lock reaches but the bundle does not name", defs: [row("R-121", { source: "builtin", org_locked: true })], want: "locked" },
  { name: "a built-in the bundle overrides", defs: [row("R-101", { source: "org", org_locked: true, org_named: true })], want: "set" },
  { name: "a built-in the bundle names, from a daemon that sends only org_named", defs: [row("R-110", { source: "builtin", org_locked: true, org_named: true })], want: "set" },
  { name: "a pack rule the managed lock reaches", defs: [row("S-793", { source: "pack:security", org_locked: true })], want: "locked" },
  { name: "an org-layer rule", defs: [row("ORG-1", { source: "org", org_locked: true, org_named: true })], want: "set" },
  { name: "an org-layer rule from a daemon that sends no org_locked", defs: [row("ORG-2", { source: "org" })], want: "set" },
  { name: "an org rule the org marked overridable", defs: [row("ORG-3", { source: "org", overridable: true })], want: "open" },
  { name: "a project-scoped org rule", defs: [row("PRJ-X1", { source: "org", project: "X", org_locked: true })], want: "set" },
  { name: "one locked row of a multi-row id locks the id", defs: [row("R-152", { source: "builtin" }), row("R-152", { source: "builtin", org_locked: true })], want: "locked" },
  { name: "a user rule", defs: [row("U-1", { source: "user" })], want: "open" },
];

for (const c of cases) {
  test(`Effective rules controls: ${c.name}`, () => {
    assert.equal(ruleLockedByOrg(c.defs), c.want !== "open");
    assert.equal(orgLockNote(c.defs) === null, c.want === "open");
    if (c.want !== "open") assert.equal(ruleSetByOrg(c.defs), c.want === "set");
    const id = c.defs[0].id;
    const html = renderToStaticMarkup(
      <EffectiveRulesTable ruleDefs={new Map([[id, c.defs]])} ids={[id]} loading={false} onOverride={() => {}} onDisable={() => {}} />,
    );
    if (c.want === "open") {
      assert.doesNotMatch(html, /by your organization</);
      assert.match(html, />Override</);
      return;
    }
    assert.doesNotMatch(html, />Override</);
    assert.doesNotMatch(html, />Disable</);
    if (c.want === "set") {
      assert.match(html, /Set by your organization/);
      assert.doesNotMatch(html, /Locked by your organization/);
    } else {
      assert.match(html, /Locked by your organization/);
      assert.doesNotMatch(html, /Set by your organization/);
    }
  });
}

test("orgUnlockedIds leaves the rules the organization locks out of the disable picker", () => {
  const defs = new Map<string, GuardRule[]>([
    ["R-101", [row("R-101", { source: "builtin" })]],
    ["R-110", [row("R-110", { source: "builtin", org_locked: true })]],
    ["ORG-1", [row("ORG-1", { source: "org" })]],
    ["ORG-3", [row("ORG-3", { source: "org", overridable: true })]],
    ["U-1", [row("U-1", { source: "user" })]],
  ]);
  assert.deepEqual(orgUnlockedIds([...defs.keys()], defs), ["R-101", "ORG-3", "U-1"]);
});
