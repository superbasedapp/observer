import { test } from "node:test";
import assert from "node:assert/strict";
import { securityNoticeLine } from "./securityOrgNotice.ts";

const base = { active: true, shared: ["a"], purpose: "", purpose_stated: false, not_for: "Not for evaluating individual employees' performance" };

test("the line names the stated purpose and the statement the org chose to show", () => {
  const line = securityNoticeLine({ ...base, purpose: "Audit evidence", purpose_stated: true });
  assert.ok(line.startsWith("Stated purpose: Audit evidence."));
  assert.ok(line.endsWith("Not for evaluating individual employees' performance."));
});

test("without a statement the line names only the purpose (ruling P-089)", () => {
  const line = securityNoticeLine({ ...base, purpose: "Audit evidence", purpose_stated: true, not_for: "" });
  assert.equal(line, "Stated purpose: Audit evidence.");
});

test("an unstated purpose says so, never a guess", () => {
  assert.ok(securityNoticeLine(base).startsWith("Your organization has not stated a purpose"));
});
