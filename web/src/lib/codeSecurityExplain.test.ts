import { test } from "node:test";
import assert from "node:assert/strict";
import {
  EXPLAIN_COMPONENT,
  explainAskingLabel,
  explainBody,
  explainHeading,
  explainPath,
  explainView,
  explainVisible,
} from "./codeSecurityExplain.ts";

test("the Explain button shows only while security.feedback is selected", () => {
  assert.equal(explainVisible(["security", EXPLAIN_COMPONENT]), true);
  assert.equal(explainVisible(["security", "security.secrets"]), false);
  assert.equal(explainVisible(undefined), false, "unknown selection fails closed");
  assert.equal(explainVisible(null), false);
});

test("the path escapes the id", () => {
  assert.equal(explainPath("01ABC"), "/api/security/findings/01ABC/explain");
  assert.equal(explainPath("a/../b"), "/api/security/findings/a%2F..%2Fb/explain");
});

test("an answer shows its advisory label, and a refusal its reason", () => {
  const ok = explainView({ available: true, advisory: true, text: "It looks for X.", label: "Advisory: no change.", model: "m", hosting: "local" });
  assert.deepEqual(ok, { body: "It looks for X.", note: "Advisory: no change. (m, local)" });
  const none = explainView({ available: false, advisory: false, reason: "No judge is configured, so nothing was sent." });
  assert.deepEqual(none, { body: "No judge is configured, so nothing was sent.", note: "" });
});

test("a fix suggestion is the same route with {fix: true}; an explanation sends no flag", () => {
  const cases = [
    { mode: "explain" as const, body: {}, asking: "Asking the judge...", heading: "Explanation" },
    { mode: "fix" as const, body: { fix: true }, asking: "Asking for a fix...", heading: "Suggested fix" },
  ];
  for (const c of cases) {
    assert.deepEqual(explainBody(c.mode), c.body, c.mode);
    assert.equal(explainAskingLabel(c.mode), c.asking, c.mode);
    assert.equal(explainHeading(c.mode), c.heading, c.mode);
  }
});
