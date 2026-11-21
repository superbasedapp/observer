// Component tests of the local rule editor's integrity lock (audit CF2-A1,
// tracker F-021), rendered with react-dom/server under node's test runner
// (scripts/test-components.mjs). For a guard integrity rule
// (isGuardIntegrityRuleId) the Enforce toggle is locked on in every layer
// and the disable chip picker never offers the id; any other rule keeps both
// controls.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { RuleEditor } from "@/pages/security/RuleEditor";
import { EffectiveRulesTable } from "@/pages/security/RuleManager";
import {
  guardDisableOptions,
  integrityDisables,
  withDisabledRule,
  withIntegrityEnforce,
  withIntegrityOverrides,
} from "@/pages/security/integrityLock";

// enforceSwitch returns the Enforce switch's opening tag; it also pins that
// the override editor renders exactly one switch, so no other control can be
// mistaken for it.
function enforceSwitch(html: string): string {
  const switches = html.match(/<button[^>]*role="switch"[^>]*>/g) ?? [];
  assert.equal(switches.length, 1, `switches: ${switches.join(" | ")}`);
  return switches[0];
}

function renderOverride(rule: string, enforce: boolean, allowWeaken: boolean): string {
  return renderToStaticMarkup(
    <RuleEditor
      kind="override"
      open
      onClose={() => {}}
      mode="edit"
      initial={{ rule, decision: "", enforce }}
      allowWeaken={allowWeaken}
      onSave={() => {}}
    />,
  );
}

// One row per case: an integrity rule saved with enforce off, the same with
// enforce on, each in a weaken-allowed and an escalate-only layer, and an
// ordinary rule, which keeps a working toggle.
const cases: { name: string; rule: string; enforce: boolean; allowWeaken: boolean; locked: boolean; on: boolean }[] = [
  { name: "R-167 enforce off, user layer", rule: "R-167", enforce: false, allowWeaken: true, locked: true, on: true },
  { name: "R-167 enforce on, user layer", rule: "R-167", enforce: true, allowWeaken: true, locked: true, on: true },
  { name: "R-160 enforce off, org layer", rule: "R-160", enforce: false, allowWeaken: false, locked: true, on: true },
  { name: "R-165 enforce off, trusted layer", rule: "R-165", enforce: false, allowWeaken: true, locked: true, on: true },
  { name: "R-101 enforce off, user layer", rule: "R-101", enforce: false, allowWeaken: true, locked: false, on: false },
  { name: "R-101 enforce on, user layer", rule: "R-101", enforce: true, allowWeaken: true, locked: false, on: true },
];

for (const c of cases) {
  test(`the Enforce toggle: ${c.name}`, () => {
    const html = renderOverride(c.rule, c.enforce, c.allowWeaken);
    const sw = enforceSwitch(html);
    assert.match(sw, new RegExp(`aria-checked="${c.on}"`));
    if (c.locked) {
      assert.match(sw, / disabled=""/);
      assert.match(html, /Locked on: this is a guard integrity rule/);
    } else {
      assert.doesNotMatch(sw, / disabled=""/);
      assert.doesNotMatch(html, /Locked on/);
    }
  });
}

test("withIntegrityEnforce forces enforce on for an integrity rule only", () => {
  assert.deepEqual(withIntegrityEnforce({ rule: "R-167", decision: "", enforce: false }), {
    rule: "R-167",
    decision: "",
    enforce: true,
  });
  assert.deepEqual(withIntegrityEnforce({ rule: " R-161 ", decision: "ask", enforce: false }).enforce, true);
  const plain = { rule: "R-101", decision: "" as const, enforce: false };
  assert.equal(withIntegrityEnforce(plain), plain);
});

test("the disable picker leaves every integrity id out and keeps the rest", () => {
  const ids = ["R-101", "R-160", "R-161", "R-162", "R-165", "R-167", "R-170", "U-100"];
  const offered = guardDisableOptions(ids).map((o) => o.id);
  assert.deepEqual(offered, ["R-101", "R-170", "U-100"]);
  // A catalogued id carries its doc; a custom id has none.
  const r101 = guardDisableOptions(["R-101"])[0];
  assert.ok(r101.sublabel && r101.sublabel.length > 0);
  assert.equal(guardDisableOptions(["U-100"])[0].sublabel, undefined);
});

test("integrityDisables names an integrity id already in a disable list", () => {
  assert.deepEqual(integrityDisables(["R-101", "R-167", "R-160"]), ["R-167", "R-160"]);
  assert.deepEqual(integrityDisables(["R-101"]), []);
});

// The Effective rules table's per-row Disable (fix round 1): one case per
// kind of row. An integrity id gets no Disable button and says why; any
// other id keeps it.
for (const c of [
  { id: "R-167", disable: false },
  { id: "R-160", disable: false },
  { id: "R-165", disable: false },
  { id: "R-101", disable: true },
  { id: "U-100", disable: true },
]) {
  test(`the Effective rules table: ${c.id} ${c.disable ? "offers" : "never offers"} Disable`, () => {
    const html = renderToStaticMarkup(
      <EffectiveRulesTable ruleDefs={new Map()} ids={[c.id]} loading={false} onOverride={() => {}} onDisable={() => {}} />,
    );
    assert.match(html, />Override</);
    if (c.disable) {
      assert.match(html, />Disable</);
      assert.doesNotMatch(html, /integrity rule/);
    } else {
      assert.doesNotMatch(html, />Disable</);
      assert.match(html, />integrity rule</);
    }
  });
}

test("withDisabledRule never adds an integrity id and never duplicates", () => {
  assert.deepEqual(withDisabledRule(["R-101"], "R-167"), ["R-101"]);
  assert.deepEqual(withDisabledRule(["R-101"], "R-101"), ["R-101"]);
  assert.deepEqual(withDisabledRule(["R-101"], "R-170"), ["R-101", "R-170"]);
});

test("withIntegrityOverrides normalizes every integrity row before the page saves", () => {
  const out = withIntegrityOverrides([
    { rule: "R-167", decision: "", enforce: false },
    { rule: "R-101", decision: "", enforce: false },
  ]);
  assert.deepEqual(
    out.map((r) => [r.rule, r.enforce]),
    [
      ["R-167", true],
      ["R-101", false],
    ],
  );
});

// The custom rule form is the shared one (shared/components/guard/
// CustomRuleEditor.tsx); the node still opens it with its own wording.
test("the node's custom rule editor renders the shared form with the local wording", () => {
  const html = renderToStaticMarkup(<RuleEditor kind="rule" open onClose={() => {}} onSave={() => {}} />);
  assert.match(html, /New custom rule/);
  assert.match(html, /placeholder="U-100"/);
  assert.match(html, /Must not collide with a built-in id\./);
  assert.match(html, /What should this rule stop\?/);
  assert.match(html, /File paths/);
});
