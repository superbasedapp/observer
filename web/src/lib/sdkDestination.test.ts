import { test } from "node:test";
import assert from "node:assert/strict";
import {
  DESTINATION_CHOICES,
  adminIssued,
  categoryLabel,
  installKeyBody,
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

test("installKeyBody checks the key and the address in order, never repeating the key", () => {
  const key = "ik_a.fakeFormSecret";
  const rows: { key: string; gw: string; ok?: { key: string; gateway_url: string }; err?: RegExp }[] = [
    { key, gw: "https://acme.superbased.app/", ok: { key, gateway_url: "https://acme.superbased.app" } },
    { key: `  ${key}\n`, gw: " http://127.0.0.1:4318 ", ok: { key, gateway_url: "http://127.0.0.1:4318" } },
    { key, gw: "http://localhost:4318", ok: { key, gateway_url: "http://localhost:4318" } },
    { key: "", gw: "https://gw.example.com", err: /Paste the SDK key/ },
    { key: "ik_a.fake Secret", gw: "https://gw.example.com", err: /no spaces/ },
    { key: `SUPERBASED_API_KEY=${key}`, gw: "https://gw.example.com", err: /without SUPERBASED_API_KEY=/ },
    { key: "nodotfake", gw: "https://gw.example.com", err: /not an SDK key/ },
    { key: "ik/a.fake", gw: "https://gw.example.com", err: /not an SDK key/ },
    { key, gw: "", err: /gateway address/ },
    { key, gw: "http://gw.example.com", err: /https:\/\// },
    { key, gw: "gw.example.com", err: /https:\/\// },
  ];
  for (const r of rows) {
    const got = installKeyBody(r.key, r.gw);
    if (r.ok) {
      assert.deepEqual(got, { body: r.ok }, `${r.key} ${r.gw}`);
    } else {
      assert.ok("error" in got, `${r.key} ${r.gw} accepted`);
      assert.match((got as { error: string }).error, r.err!);
      assert.doesNotMatch((got as { error: string }).error, /fakeFormSecret/);
    }
  }
});

test("adminIssued reads the held key's origin; an older daemon reads as a sign-in key", () => {
  const d = (signed_in: boolean, key_origin?: "" | "sign_in" | "admin_issued") =>
    ({ signed_in, online: { key_origin } }) as Parameters<typeof adminIssued>[0];
  assert.equal(adminIssued(d(true, "admin_issued")), true);
  assert.equal(adminIssued(d(true, "sign_in")), false);
  assert.equal(adminIssued(d(true)), false);
  assert.equal(adminIssued(d(false, "admin_issued")), false);
  assert.equal(adminIssued(null), false);
});
