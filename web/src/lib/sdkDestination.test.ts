import { test } from "node:test";
import assert from "node:assert/strict";
import {
  DESTINATION_CHOICES,
  categoryLabel,
  destinationLabel,
  pendingProposals,
  requesterLabel,
  sdkKeyNudge,
  sendsOnline,
  type SettingsProposal,
} from "./sdkDestination.ts";

test("sendsOnline matches the server's D19 predicate", () => {
  assert.equal(sendsOnline("online"), true);
  assert.equal(sendsOnline("both"), true);
  assert.equal(sendsOnline("local"), false);
  assert.equal(sendsOnline(""), false);
});

test("every choice has a label and help; the default comes first", () => {
  assert.equal(DESTINATION_CHOICES[0].value, "");
  for (const c of DESTINATION_CHOICES) {
    assert.ok(c.label && c.help);
    assert.equal(destinationLabel(c.value), c.label);
  }
});

test("pendingProposals keeps only pending rows, oldest first", () => {
  const row = (id: number, status: SettingsProposal["status"]): SettingsProposal => ({
    id, key: "k", value: "v", prev_value: "", category: "", reason: "", requested_by: "", note: "", status, created_at: "",
  });
  assert.deepEqual(pendingProposals([row(3, "pending"), row(1, "approved"), row(2, "pending")]).map((p) => p.id), [2, 3]);
  assert.deepEqual(pendingProposals(null), []);
});

test("labels never show raw ids where plain words exist", () => {
  assert.equal(categoryLabel("destination_online"), "SDK destination");
  assert.equal(categoryLabel("unknown_cat"), "unknown_cat");
  assert.equal(requesterLabel("mcp:claude-code"), "an AI agent (claude-code)");
  assert.equal(requesterLabel("mcp"), "an AI agent");
});

test("sdkKeyNudge points an enrolled machine without a key at Get my SDK key (U-26)", () => {
  assert.equal(sdkKeyNudge(null, true, "Acme"), null);
  assert.equal(sdkKeyNudge({ signed_in: true }, true, "Acme"), null);
  assert.equal(sdkKeyNudge({ signed_in: false }, false, "Acme"), null);
  assert.match(sdkKeyNudge({ signed_in: false }, true, "Acme") ?? "", /connected to Acme, but your SDK key is separate/);
  assert.match(sdkKeyNudge({ signed_in: false }, true, " ") ?? "", /your organization/);
});
