import { test } from "node:test";
import assert from "node:assert/strict";
import {
  GATEWAY_ALLOWANCES,
  GATEWAY_BETA_NOTE,
  GATEWAY_COMPARISON_ROWS,
  GATEWAY_COMPARISON_TITLE,
  GATEWAY_STATUS_PILL,
} from "../components/billing/gatewayRows.ts";

// The hosted AI gateway's plan rows (decision 4 of L-174): Free 10k/4,
// Personal Pro 250k/16. The numbers must match the plan versions in force.
test("the gateway allowances are decision 4's numbers", () => {
  assert.deepEqual(GATEWAY_ALLOWANCES, {
    free: { requestsMonthly: 10_000, concurrency: 4 },
    plus: { requestsMonthly: 250_000, concurrency: 16 },
  });
  assert.deepEqual(
    GATEWAY_COMPARISON_ROWS.map((r) => [r.free, r.plus]),
    [
      ["10,000", "250,000"],
      ["4", "16"],
    ],
  );
});

test("the gateway rows read as plain sentence-case words and say it is not offered yet", () => {
  for (const r of GATEWAY_COMPARISON_ROWS) {
    assert.match(r.label, /^[A-Z][a-z]/, r.label);
    assert.doesNotMatch(r.label, /[_.]|aigw/i, r.label);
  }
  assert.equal(GATEWAY_COMPARISON_TITLE, "AI gateway");
  // C-118: no hosted team is offered it yet, so the section never
  // reads as an available beta.
  assert.equal(GATEWAY_STATUS_PILL, "Not offered yet");
  assert.match(GATEWAY_BETA_NOTE, /not offered yet/i);
  assert.doesNotMatch(GATEWAY_BETA_NOTE, /\bbeta\b/i);
  assert.match(GATEWAY_BETA_NOTE, /\.$/);
});
