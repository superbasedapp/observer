import assert from "node:assert/strict";
import test from "node:test";

import { orgAppBudgetLead, orgAppCapLimit, orgAppCapWho } from "./orgAppBudget.ts";

// The machine's view of the organization's app budgets (Plane A W4-1).

test("org app caps read in plain words, never a raw end user", () => {
  assert.equal(orgAppCapWho({ scope: "end_user", end_user: "*", period: "calendar_day", enforcement: "hard" }), "each end user");
  assert.equal(orgAppCapWho({ scope: "service", service: "checkout", period: "calendar_day", enforcement: "hard" }), "service checkout");
  assert.equal(
    orgAppCapWho({ scope: "end_user_service", end_user: "*", service: "checkout", period: "calendar_day", enforcement: "soft" }),
    "each end user of service checkout",
  );
  assert.match(orgAppCapLimit({ scope: "service", service: "x", period: "calendar_month", cap_tokens: 1000, enforcement: "hard" }, String), /tokens per month$/);
});

test("the lead says whether the org's caps replace or lower the machine's own", () => {
  assert.match(orgAppBudgetLead(true, true, 2), /replace/);
  assert.match(orgAppBudgetLead(true, false, 2), /lower/);
  assert.match(orgAppBudgetLead(false, false, 0), /Settings > Account/);
  assert.doesNotMatch(orgAppBudgetLead(true, true, 2), /\bnode\b/);
});
