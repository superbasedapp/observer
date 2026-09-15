import { test } from "node:test";
import assert from "node:assert/strict";
import { publicHostsFor } from "../src/index.js";

test("unset SBCI_PUBLIC_HOSTS keeps the historical default set", () => {
  const set = publicHostsFor({});
  assert.deepEqual([...set].sort(), ["app.superbased.app", "cloud.superbased.app"]);
});

test("SBCI_PUBLIC_HOSTS replaces the default, trimmed and lowercased", () => {
  const set = publicHostsFor({ SBCI_PUBLIC_HOSTS: " Staging-Cloud.superbased.app , cloud.superbased.app,, " });
  assert.deepEqual([...set].sort(), ["cloud.superbased.app", "staging-cloud.superbased.app"]);
  assert.equal(set.has("app.superbased.app"), false);
});

test("a blank SBCI_PUBLIC_HOSTS falls back to the default rather than accepting nothing", () => {
  assert.equal(publicHostsFor({ SBCI_PUBLIC_HOSTS: " , " }).has("cloud.superbased.app"), true);
});
