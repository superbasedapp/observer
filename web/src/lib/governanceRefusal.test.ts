import assert from "node:assert/strict";
import test from "node:test";

import { governanceRefusalOf, terminalsRefusalSentence } from "./governanceRefusal.ts";

// P-031 (lane SEC-E): a governance refusal reads as a sentence naming the
// organization; any other error is left to the caller's own copy.

test("governanceRefusal: a hidden Terminals route names the org", () => {
  const e = { status: 404, body: JSON.stringify({ error: "governance_hidden", section: "terminals", org_name: "Acme" }) };
  assert.deepEqual(governanceRefusalOf(e), { code: "governance_hidden", section: "terminals", orgName: "Acme" });
  assert.match(terminalsRefusalSentence(e) ?? "", /Acme has hidden Terminals/);
});

test("governanceRefusal: read-only and an unnamed org", () => {
  const e = { status: 409, body: JSON.stringify({ error: "governance_read_only", section: "terminals" }) };
  assert.match(terminalsRefusalSentence(e) ?? "", /your organization has made Terminals read-only/);
});

test("governanceRefusal: other errors are not governance", () => {
  assert.equal(governanceRefusalOf({ status: 404, body: "not found" }), null);
  assert.equal(governanceRefusalOf({ status: 500, body: JSON.stringify({ error: "governance_hidden" }) }), null);
  assert.equal(governanceRefusalOf(new Error("x")), null);
  assert.equal(terminalsRefusalSentence(null), null);
});
