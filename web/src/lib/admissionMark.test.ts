import { test } from "node:test";
import assert from "node:assert/strict";
import { admissionChip } from "./admissionMark.ts";

test("admissionChip: none", () => {
  assert.equal(admissionChip(null), null);
  assert.equal(admissionChip(undefined), null);
  assert.equal(admissionChip({ decision: "", count: 0 }), null);
});

test("admissionChip: enforce deny reads deny with the criterion", () => {
  const c = admissionChip({ decision: "deny", criterion_id: "denied_topics", mode: "enforce", count: 1 });
  assert.equal(c?.value, "deny");
  assert.match(c!.title, /denied_topics/);
});

test("admissionChip: an observe-mode deny or ask would have blocked", () => {
  assert.equal(admissionChip({ decision: "deny", mode: "observe", count: 1 })?.value, "would_block");
  assert.equal(admissionChip({ decision: "ask", mode: "observe", count: 1 })?.value, "would_block");
  assert.equal(admissionChip({ decision: "flag", mode: "observe", count: 1 })?.value, "flag");
});

test("admissionChip: several verdicts are counted in the title", () => {
  assert.match(admissionChip({ decision: "allow", mode: "enforce", count: 3 })!.title, /3 verdicts/);
});
