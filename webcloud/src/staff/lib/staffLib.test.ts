import assert from "node:assert/strict";
import test from "node:test";

import {
  b64urlToBytes,
  bytesToB64url,
  credentialToJSON,
  passkeyErrorText,
  toCreationOptions,
  toRequestOptions,
} from "./webauthn.ts";
import {
  ALL_ORGS,
  PLATFORM_KEY,
  buildOrgControl,
  buildReach,
  describeOrgControl,
  describeReach,
  orgControlDraftFrom,
  orgControlTone,
  reachDraftFrom,
} from "./envelope.ts";
import {
  actorLabel,
  can,
  envelopeBehind,
  freshness,
  grantCommand,
  grantInForce,
  matchesOrgQuery,
  orgStatusTone,
  planSummary,
  reasonError,
  shellQuote,
} from "./model.ts";

const ORG = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const NOW = new Date("2026-11-16T12:00:00Z");

// ---- webauthn ---------------------------------------------------------------

test("base64url round-trips every byte value, unpadded", () => {
  const bytes = new Uint8Array(256).map((_, i) => i);
  const enc = bytesToB64url(bytes);
  assert.doesNotMatch(enc, /[+/=]/);
  assert.deepEqual(b64urlToBytes(enc), bytes);
  assert.deepEqual(b64urlToBytes("AQID"), new Uint8Array([1, 2, 3]));
  assert.deepEqual(b64urlToBytes("_-8"), new Uint8Array([255, 239]));
});

test("request options decode the challenge and keep the relying party", () => {
  const o = toRequestOptions({ challenge: "AQID", rpId: "staff.superbased.app", timeout: 120000, userVerification: "required", allowCredentials: [] });
  assert.deepEqual(new Uint8Array(o.challenge as Uint8Array), new Uint8Array([1, 2, 3]));
  assert.equal(o.rpId, "staff.superbased.app");
  assert.equal(o.userVerification, "required");
});

test("creation options decode the user handle and the excluded credentials", () => {
  const o = toCreationOptions({
    rp: { id: "staff.superbased.app", name: "superbased staff console" },
    user: { id: "BAU", name: "Ada", displayName: "Ada" },
    challenge: "AQID",
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    timeout: 120000,
    excludeCredentials: [{ type: "public-key", id: "CQo" }],
    authenticatorSelection: { residentKey: "required", requireResidentKey: true, userVerification: "required" },
    attestation: "none",
  });
  assert.deepEqual(new Uint8Array(o.user.id as Uint8Array), new Uint8Array([4, 5]));
  assert.deepEqual(new Uint8Array(o.excludeCredentials![0].id as Uint8Array), new Uint8Array([9, 10]));
});

test("an assertion serializes in the toJSON form the server parses", () => {
  const buf = (...b: number[]) => new Uint8Array(b).buffer;
  const json = credentialToJSON({
    id: "AQ",
    rawId: buf(1),
    type: "public-key",
    authenticatorAttachment: "platform",
    response: { clientDataJSON: buf(2), authenticatorData: buf(3), signature: buf(4), userHandle: buf(5) },
    getClientExtensionResults: () => ({}),
  });
  assert.deepEqual(json, {
    id: "AQ",
    rawId: "AQ",
    type: "public-key",
    authenticatorAttachment: "platform",
    response: { clientDataJSON: "Ag", authenticatorData: "Aw", signature: "BA", userHandle: "BQ" },
    clientExtensionResults: {},
  });
});

test("an attestation carries its object and transports", () => {
  const buf = (...b: number[]) => new Uint8Array(b).buffer;
  const json = credentialToJSON({
    id: "AQ",
    rawId: buf(1),
    type: "public-key",
    response: { clientDataJSON: buf(2), attestationObject: buf(6), getTransports: () => ["internal"] },
  });
  const r = json.response as Record<string, unknown>;
  assert.equal(r.attestationObject, "Bg");
  assert.deepEqual(r.transports, ["internal"]);
  assert.equal(r.signature, undefined);
});

test("a cancelled prompt reads as cancelled", () => {
  const e = new Error("x");
  e.name = "NotAllowedError";
  assert.match(passkeyErrorText(e), /cancelled/);
});

// ---- envelope: reach --------------------------------------------------------

test("reach follows the body's reach table", () => {
  const cases: [Parameters<typeof buildReach>[0], number][] = [
    [{ reach: "off", orgsText: "", cohort: "" }, 0],
    [{ reach: "stage-default", orgsText: "", cohort: "" }, 0],
    [{ reach: "named", orgsText: ORG, cohort: "" }, 0],
    [{ reach: "named", orgsText: "", cohort: "" }, 1],
    [{ reach: "named", orgsText: `${ORG}, ${ORG}`, cohort: "" }, 1],
    [{ reach: "named", orgsText: "acme", cohort: "" }, 1],
    [{ reach: "cohort", orgsText: "", cohort: "ring-1" }, 0],
    [{ reach: "cohort", orgsText: "", cohort: " " }, 1],
  ];
  for (const [draft, nErrors] of cases) {
    assert.equal(buildReach(draft).errors.length, nErrors, JSON.stringify(draft));
  }
  // Off never carries orgs or a cohort, even when the draft has them.
  assert.deepEqual(buildReach({ reach: "off", orgsText: ORG, cohort: "x" }).value, { reach: "off" });
  assert.deepEqual(buildReach({ reach: "cohort", orgsText: ORG, cohort: "ring-1" }).value, { reach: "cohort", cohort: "ring-1" });
});

test("a stored reach reads back into its draft", () => {
  assert.deepEqual(reachDraftFrom({ reach: "named", orgs: [ORG] }), { reach: "named", orgsText: ORG, cohort: "" });
  assert.equal(reachDraftFrom({ reach: "nonsense" }).reach, "stage-default");
  assert.equal(describeReach({ reach: "named", orgs: [ORG] }), "Only 1 named org");
  assert.equal(describeReach({ reach: "off" }), "Off everywhere");
});

// ---- envelope: org_controls ---------------------------------------------------

test("org controls follow the body's org_controls rules", () => {
  const ok = (d: Parameters<typeof buildOrgControl>[0]) => buildOrgControl(d).errors;
  const none = { route: "", admission: "on" as const, dispatch: "on" as const };
  assert.deepEqual(ok({ key: ORG, ingest: "pause", rateText: "", inference: [] }), []);
  assert.deepEqual(ok({ key: ORG, ingest: "throttle", rateText: "600", inference: [] }), []);
  assert.equal(ok({ key: ORG, ingest: "throttle", rateText: "0", inference: [] }).length, 1);
  assert.equal(ok({ key: ORG, ingest: "throttle", rateText: "1.5", inference: [] }).length, 1);
  assert.equal(ok({ key: ORG, ingest: "none", rateText: "", inference: [] }).length, 1, "a row with no control");
  assert.equal(ok({ key: PLATFORM_KEY, ingest: "pause", rateText: "", inference: [] }).length, 1, "ingest is never platform-wide");
  assert.deepEqual(ok({ key: PLATFORM_KEY, ingest: "none", rateText: "", inference: [{ ...none, admission: "paused" }] }), []);
  assert.equal(ok({ key: ORG, ingest: "none", rateText: "", inference: [none, none] }).length, 1, "two rows for every route");
  assert.equal(ok({ key: "acme", ingest: "pause", rateText: "", inference: [] }).length, 1, "not an org id");
});

test("the stored value names its org, * for the platform row", () => {
  const p = buildOrgControl({ key: PLATFORM_KEY, ingest: "none", rateText: "", inference: [{ route: "gpt", admission: "off", dispatch: "paused" }] });
  assert.deepEqual(p.value, { org: ALL_ORGS, inference: [{ route: "gpt", admission: "off", dispatch: "paused" }] });
  const o = buildOrgControl({ key: ORG, ingest: "pause", rateText: "99", inference: [] });
  assert.deepEqual(o.value, { org: ORG, ingest: { mode: "pause" } }, "pause carries no rate");
});

test("a stored org control reads back, describes and tones", () => {
  const v = { org: ORG, ingest: { mode: "throttle", rate_per_minute: 60 }, inference: [{ admission: "paused", dispatch: "on" }] };
  const d = orgControlDraftFrom(ORG, v);
  assert.equal(d.ingest, "throttle");
  assert.equal(d.rateText, "60");
  assert.deepEqual(buildOrgControl(d).value, v);
  assert.deepEqual(describeOrgControl(v), ["Ingest throttled to 60 pushes a minute", "Inference (every route): admission paused, dispatch on"]);
  assert.equal(orgControlTone(v), "warn");
  assert.equal(orgControlTone({ org: ORG, ingest: { mode: "throttle", rate_per_minute: 5 } }), "info");
  assert.equal(orgControlTone({ org: "*", inference: [{ admission: "on", dispatch: "off" }] }), "danger");
});

// ---- model ------------------------------------------------------------------

test("org status tones", () => {
  assert.equal(orgStatusTone("active"), "success");
  assert.equal(orgStatusTone("pending_deletion"), "danger");
  assert.equal(orgStatusTone("whatever"), "neutral");
});

test("a grant is in force until its end", () => {
  assert.equal(grantInForce({ action: "grant", plan_name: "team" }, NOW), true);
  assert.equal(grantInForce({ action: "grant", plan_name: "team", effective_until: "2026-11-16T11:59:59Z" }, NOW), false);
  assert.equal(grantInForce({ action: "revoke" }, NOW), false);
  assert.equal(grantInForce(null, NOW), false);
});

test("the plan source order: live subscription, then grant, then the document", () => {
  const grant = { action: "grant", plan_name: "business", plan_version: 2 };
  assert.equal(planSummary({ grant, subscription: { status: "active", plan_name: "team", plan_version: 1 } }, NOW).source, "subscription (active)");
  assert.equal(planSummary({ grant, subscription: { status: "canceled", plan_name: "team" } }, NOW).label, "business v2");
  assert.equal(planSummary({}, NOW).label, "launch window or floor");
});

test("freshness counts down the 15-minute window", () => {
  assert.equal(freshness("2026-11-16T12:05:30Z", NOW).label, "Changes allowed for 5:30");
  assert.equal(freshness("2026-11-16T11:59:00Z", NOW).fresh, false);
  assert.equal(freshness(null, NOW).fresh, false);
});

test("capabilities hide what a role can never do", () => {
  const caps = [{ action: "availability.write", permitted: false, fresh: true }];
  assert.equal(can(caps, "availability.write"), false);
  assert.equal(can(undefined, "availability.write"), false);
  assert.equal(can([{ action: "orgs.read", permitted: true, fresh: false }], "orgs.read"), true);
});

test("the grant command is the CLI's, quoted, with the CLI's refusals", () => {
  const g = grantCommand({ action: "grant", orgId: ORG, plan: "business", version: "", until: "", reason: "internal org (W15-D13)" });
  assert.deepEqual(g.errors, []);
  assert.equal(g.command, `observer-cloud grant-plan org --org ${ORG} --plan business --reason 'internal org (W15-D13)'`);
  const r = grantCommand({ action: "revoke", orgId: ORG, plan: "", version: "", until: "", reason: "done" });
  assert.equal(r.command, `observer-cloud grant-plan org revoke --org ${ORG} --reason done`);
  assert.equal(grantCommand({ action: "grant", orgId: ORG, plan: "Team!", version: "0", until: "tomorrow", reason: "" }).errors.length, 4);
  assert.equal(shellQuote("it's"), `'it'"'"'s'`);
});

test("reasons follow staffauth.ValidateReason", () => {
  assert.notEqual(reasonError("  "), null);
  assert.equal(reasonError("ticket 42\nsecond line"), null);
  assert.notEqual(reasonError("a\u0007b"), null);
  assert.notEqual(reasonError("x".repeat(1001)), null);
});

test("log and list helpers", () => {
  assert.equal(actorLabel("staff:11111111-2222", "11111111-2222"), "you");
  assert.equal(actorLabel("staff:11111111-2222"), "staff 11111111");
  assert.equal(actorLabel("operator"), "operator");
  assert.equal(envelopeBehind("2026-11-16T12:00:01Z", "2026-11-16T12:00:00Z"), true);
  assert.equal(envelopeBehind("2026-11-16T11:00:00Z", "2026-11-16T12:00:00Z"), false);
  assert.equal(envelopeBehind("2026-11-16T11:00:00Z", null), true);
  const o = { display_name: "Acme Corp", slug: "acme", org_id: ORG, host_id: "app-0" };
  assert.equal(matchesOrgQuery(o, "ACME"), true);
  assert.equal(matchesOrgQuery(o, "aaaaaaaa"), true);
  assert.equal(matchesOrgQuery(o, "zzz"), false);
});

test("the change dialog needs a valid change, a reason and the tick", async () => {
  const { changeFormView } = await import("./model.ts");
  const base = { reason: "ticket 7", confirmed: true, ready: true, busy: false, blocking: [], confirmLabel: "Apply" };
  assert.equal(changeFormView(base).canSubmit, true);
  assert.equal(changeFormView(base).submitLabel, "Apply");
  assert.equal(changeFormView({ ...base, reason: "" }).canSubmit, false);
  assert.equal(changeFormView({ ...base, reason: "" }).reasonError, null, "an untouched reason shows no error yet");
  assert.equal(changeFormView({ ...base, confirmed: false }).canSubmit, false);
  assert.equal(changeFormView({ ...base, blocking: ["bad"] }).canSubmit, false);
  assert.equal(changeFormView({ ...base, busy: true }).canSubmit, false);
  assert.equal(changeFormView({ ...base, ready: false }).submitLabel, "Verify passkey and apply");
});
