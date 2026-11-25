import assert from "node:assert/strict";
import test from "node:test";

import { PLAN_LABELS, labelFor, planDisplayName } from "./labels.ts";

// The paid individual plan is "Personal Pro" everywhere a customer reads its
// name (operator ruling 2026-11-24). The plan has two internal names: the
// account plan plus_beta (what the Paddle price buys) and the personal org
// plan personal_pro (what a re-keyed subscription names). "Plus", the name
// of the September beta, is never shown. One row per place the portal turns
// a plan into a name; the server's own label is pinned in Go
// (tests/invariant/personal_pro_name_test.go).

const SOURCES: { source: string; name: string }[] = [
  { source: "PLAN_LABELS.plus_beta", name: labelFor(PLAN_LABELS, "plus_beta") },
  { source: "PLAN_LABELS.personal_pro", name: labelFor(PLAN_LABELS, "personal_pro") },
  { source: "planDisplayName(plus_beta), no server label", name: planDisplayName("plus_beta") },
  { source: "planDisplayName(personal_pro), no server label", name: planDisplayName("personal_pro") },
  { source: "planDisplayName(plus_beta, the server's label)", name: planDisplayName("plus_beta", "Personal Pro") },
];

for (const { source, name } of SOURCES) {
  test(`${source} reads Personal Pro`, () => {
    assert.equal(name, "Personal Pro");
  });
}

test("no plan label the portal knows reads Plus", () => {
  for (const [token, label] of Object.entries(PLAN_LABELS)) {
    assert.doesNotMatch(label, /\bPlus\b/, `PLAN_LABELS.${token} = ${label}`);
  }
});

test("planDisplayName prefers the server's label, then the table, then the token, never undefined", () => {
  assert.equal(planDisplayName("team", "Team"), "Team");
  assert.equal(planDisplayName("business"), "Business");
  assert.equal(planDisplayName("enterprise_x"), "enterprise_x");
  assert.equal(planDisplayName(undefined), "");
  assert.equal(planDisplayName(null, null), "");
});
