// Pins the Policies apply rule (UI review U-27: applying an admission policy
// always saves it) and the friendly error wording (U-13: no raw API text).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  ADMISSION_APPLY_PERSISTS,
  ADMISSION_STARTS_NEXT_TEXT,
  admissionCard,
  ADMISSION_OFF_TEXT,
  NO_ANSWER_TEXT,
  POLICY_ERROR_TEXT,
  policyPostUrl,
  policyStatusText,
} from "../pages/policies/applyRule.ts";

const pages = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "pages");

test("an admission apply always carries the persist flag", () => {
  assert.equal(ADMISSION_APPLY_PERSISTS, true);
  assert.equal(policyPostUrl("/api/obs/admission/policy", ADMISSION_APPLY_PERSISTS), "/api/obs/admission/policy?persist=1");
  assert.equal(policyPostUrl("/api/obs/egress/policy", false), "/api/obs/egress/policy");
});

test("no Policies source posts the admission policy except through applyAdmissionPolicy", () => {
  const files = [path.join(pages, "Policies.tsx"), ...readdirSync(path.join(pages, "policies")).map((f) => path.join(pages, "policies", f))];
  for (const f of files) {
    if (!/\.tsx?$/.test(f) || f.endsWith("types.ts")) continue;
    const src = readFileSync(f, "utf8");
    assert.ok(
      !/postPolicy\(\s*"\/api\/obs\/admission\/policy"/.test(src),
      `${path.basename(f)} posts the admission policy directly; use applyAdmissionPolicy so it is saved`,
    );
  }
});

test("policy errors are worded by status and never echo the API", () => {
  assert.equal(policyStatusText(404), ADMISSION_OFF_TEXT);
  for (const status of [400, 401, 403, 404, 409, 418, 500, 503]) {
    const text = policyStatusText(status);
    assert.ok(text.length > 0);
    assert.ok(!/\bapi\b|\/api\/|\b\d{3}\b/i.test(text), `status ${status} text echoes the API: ${text}`);
  }
  for (const row of POLICY_ERROR_TEXT) assert.ok(!/\/api\//.test(row.text));
  assert.ok(!/\/api\//.test(NO_ANSWER_TEXT));
});

test("admission waiting for the next start shows its own card, never the off card", () => {
  const rows: Array<[string, Parameters<typeof admissionCard>[0], string]> = [
    ["no read yet", undefined, "none"],
    ["running", { available: true }, "none"],
    ["an older daemon (no flag)", {}, "none"],
    ["off", { available: false }, "off"],
    ["waiting for the next start", { available: false, pending_next_start: true }, "starts_next"],
    ["waiting, flag only", { pending_next_start: true }, "starts_next"],
    ["flag false", { available: false, pending_next_start: false }, "off"],
  ];
  for (const [name, status, want] of rows) assert.equal(admissionCard(status), want, name);
  assert.match(ADMISSION_STARTS_NEXT_TEXT, /next time the daemon starts/);
});

test("the Policies page renders the waiting card from admissionCard", () => {
  const src = readFileSync(path.join(pages, "Policies.tsx"), "utf8");
  assert.match(src, /pending_next_start\?: boolean/);
  assert.match(src, /card === "starts_next" \? <AdmissionStartsNext \/>/);
});
