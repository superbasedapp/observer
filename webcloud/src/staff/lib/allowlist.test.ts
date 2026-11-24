// Unit tests of the team allow-list rules (lib/allowlist.ts): the value
// check mirrors staffauth.ValidateAllowlistEntry case by case.

import assert from "node:assert/strict";
import test from "node:test";

import {
  addBlocking,
  allowlistErrorText,
  allowlistSummary,
  isActive,
  kindLabel,
  validateAllowlistEntry,
  type AllowlistEntry,
} from "./allowlist.ts";

const ACCOUNT = "dddddddd-eeee-4fff-8000-111111111111";

function entry(extra: Partial<AllowlistEntry> = {}): AllowlistEntry {
  return {
    entry_id: "e",
    kind: "email_domain",
    value: "acme.com",
    added_by: "operator",
    added_reason: "r",
    added_at: "2026-11-23T10:00:00Z",
    ...extra,
  };
}

test("entries are checked and spelled the way the server stores them", () => {
  const cases: [string, string, string, boolean][] = [
    // kind, typed, stored, valid
    ["account", ACCOUNT, ACCOUNT, true],
    ["account", ` ${ACCOUNT.toUpperCase()} `, ACCOUNT, true],
    ["account", `{${ACCOUNT}}`, `{${ACCOUNT}}`, false],
    ["account", `urn:uuid:${ACCOUNT}`, `urn:uuid:${ACCOUNT}`, false],
    ["account", "acme", "acme", false],
    ["email_domain", "acme.com", "acme.com", true],
    ["email_domain", " @Acme.COM. ", "acme.com", true],
    ["email_domain", "eu.mail.acme.co.uk", "eu.mail.acme.co.uk", true],
    ["email_domain", "ana@acme.com", "ana@acme.com", false],
    ["email_domain", "acme", "acme", false],
    ["email_domain", "-acme.com", "-acme.com", false],
    ["email_domain", "a.b", "a.b", true],
    ["email_domain", `${"a".repeat(64)}.com`, `${"a".repeat(64)}.com`, false],
    ["team", "acme.com", "acme.com", false],
  ];
  for (const [kind, typed, stored, valid] of cases) {
    const got = validateAllowlistEntry(kind, typed);
    assert.equal(got.value, stored, `${kind} ${typed}`);
    assert.equal(got.error === null, valid, `${kind} ${typed}: ${got.error}`);
  }
});

test("refusals say what to type", () => {
  assert.equal(validateAllowlistEntry("email_domain", "ana@acme.com").error, "A domain entry is a domain, not an address: use acme.com.");
  assert.equal(validateAllowlistEntry("email_domain", "acme").error, '"acme" is not a domain name like example.com.');
  assert.equal(validateAllowlistEntry("account", "x").error, "An account entry is an account id (a UUID).");
  assert.equal(validateAllowlistEntry("", "x").error, "Choose an email domain or an account.");
});

test("an add is blocked when empty, invalid, or already on the list", () => {
  const list = [entry(), entry({ entry_id: "r", value: "old.dev", removed_at: "2026-11-23T11:00:00Z" })];
  assert.deepEqual(addBlocking(list, "email_domain", "  "), ["Enter a value."]);
  assert.match(addBlocking(list, "email_domain", "acme")[0], /not a domain name/);
  assert.deepEqual(addBlocking(list, "email_domain", "@ACME.com"), ["That entry is already on the allow-list."]);
  assert.deepEqual(addBlocking(list, "email_domain", "old.dev"), [], "a removed entry may be added again");
  assert.deepEqual(addBlocking(list, "account", "acme.com"), ["An account entry is an account id (a UUID)."]);
  assert.deepEqual(addBlocking(list, "email_domain", "acme.org"), []);
});

test("the summary counts active entries only", () => {
  assert.match(allowlistSummary([]), /^No one is on the allow-list/);
  assert.match(allowlistSummary([entry({ removed_at: "2026-11-23T11:00:00Z" })]), /^No one/);
  assert.equal(allowlistSummary([entry(), entry({ kind: "account", value: ACCOUNT })]), "1 email domain and 1 account may create a team org.");
  assert.equal(allowlistSummary([entry(), entry({ value: "b.com" })]), "2 email domains and 0 accounts may create a team org.");
});

test("labels, activity and refusals in words", () => {
  assert.equal(kindLabel("email_domain"), "Email domain");
  assert.equal(kindLabel("account"), "Account");
  assert.equal(kindLabel("other"), "other");
  assert.equal(isActive(entry()), true);
  assert.equal(isActive(entry({ removed_at: "2026-11-23T11:00:00Z" })), false);
  assert.match(allowlistErrorText("exists", "x"), /already on the allow-list/);
  assert.match(allowlistErrorText("not_found", "x"), /no longer on the allow-list/);
  assert.equal(allowlistErrorText("forbidden_role", "role refused"), "role refused");
});
