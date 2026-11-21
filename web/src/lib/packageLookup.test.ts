import assert from "node:assert/strict";
import test from "node:test";

import {
  cacheLine,
  consentFor,
  firstRunNeeded,
  kindsChange,
  LOOKUP_MODES,
  lookupModeLine,
  modeChange,
  orgPostureLines,
  privateChange,
  privateLine,
  remoteDriverNotes,
  type PackageLookupStatus,
} from "./packageLookup.ts";

function status(over: Partial<PackageLookupStatus> = {}): PackageLookupStatus {
  return {
    mode: "",
    configured: "",
    via: "shards",
    via_choices: ["shards"],
    kinds: ["language", "actions"],
    kind_choices: ["language", "actions"],
    private: "withhold",
    private_sending: false,
    managed: false,
    download: { accepted: false, text: "download text" },
    remote: { accepted: false, text: "remote text" },
    remote_private: { accepted: false, text: "private text" },
    remote_hosts: ["superbased.app", "shards.superbased.app"],
    approx_mb: 300,
    cache_bytes: 0,
    drivers: [
      { driver: "security.scan.scalibr", remote: true },
      { driver: "security.scan.osv", remote: false, note: "remote lookup: not available for osv-scanner in this build" },
    ],
    ...over,
  };
}

test("a fresh install needs the first-run choice; a chosen or managed one does not", () => {
  assert.equal(firstRunNeeded(status()), true);
  assert.equal(firstRunNeeded(status({ mode: "local" })), false);
  assert.equal(firstRunNeeded(status({ managed: true })), false);
  assert.equal(firstRunNeeded(null), false);
});

test("each mode asks for its own consent, and only when it is not recorded", () => {
  const st = status();
  assert.equal(consentFor(st, "local"), "download");
  assert.equal(consentFor(st, "remote"), "remote");
  assert.equal(consentFor(st, "both"), "remote");
  assert.deepEqual(modeChange(st, "remote"), { mode: "remote", accept_remote: true });
  assert.deepEqual(modeChange(st, "local"), { mode: "local", accept_download: true });
  const given = status({ download: { accepted: true, text: "" }, remote: { accepted: true, text: "" } });
  assert.equal(consentFor(given, "local"), null);
  assert.deepEqual(modeChange(given, "both"), { mode: "both" });
});

test("the private-names switch records its own consent before sending", () => {
  assert.deepEqual(privateChange(status(), true), { private: "send", accept_private: true });
  assert.deepEqual(privateChange(status({ remote_private: { accepted: true, text: "" } }), true), { private: "send" });
  assert.deepEqual(privateChange(status(), false), { private: "withhold" });
  assert.match(privateLine(status()), /withheld/);
  assert.match(privateLine(status({ private: "send" })), /not recorded/);
  assert.match(privateLine(status({ private: "send", private_sending: true, remote_private: { accepted: true, accepted_at: "2026-11-04T10:00:00Z", text: "" } })), /sent too/);
});

test("kinds toggle in choice order and never empty", () => {
  assert.deepEqual(kindsChange(status(), "actions", false), { kinds: ["language"] });
  assert.equal(kindsChange(status({ kinds: ["language"] }), "language", false), null);
  assert.deepEqual(kindsChange(status({ kinds: ["actions"] }), "language", true), { kinds: ["language", "actions"] });
});

test("the posture line says what each mode does and never claims more", () => {
  assert.match(lookupModeLine(status()), /not scanned/);
  assert.match(lookupModeLine(status({ mode: "remote" })), /not recorded/);
  assert.match(lookupModeLine(status({ mode: "remote", remote: { accepted: true, accepted_at: "2026-11-04T10:00:00Z", accepted_on: "dashboard", text: "" } })), /no download/);
  assert.match(lookupModeLine(status({ managed: true, mode: "" })), /organization/);
  assert.match(lookupModeLine(status({ mode: "both" })), /only the downloaded databases/);
});

test("every mode says what it sends, and the remote ones never claim names leave", () => {
  for (const m of LOOKUP_MODES) {
    assert.ok(m.sends.length > 0, m.id);
  }
  const remote = LOOKUP_MODES.find((m) => m.id === "remote");
  assert.match(remote?.sends ?? "", /never a name, a version or code/);
});

test("driver notes and the cache line", () => {
  assert.deepEqual(remoteDriverNotes(status()), ["remote lookup: not available for osv-scanner in this build"]);
  assert.match(cacheLine(0), /No shards/);
  assert.match(cacheLine(2048), /2 KB/);
  assert.match(cacheLine(3 << 20), /3\.0 MB/);
});

test("a managed node reads its organization's decision, its server and its policy version", () => {
  const on = status({ managed: true, mode: "both", org: { on: true, private: "withhold", kinds: ["language", "actions"], org_name: "Acme", version: 12, source: "org" } });
  assert.match(lookupModeLine(on), /your organization's server \(Acme\), mirror mode/);
  const lines = orgPostureLines(on).join("\n");
  assert.match(lines, /language, actions/);
  assert.match(lines, /withheld \(your organization's rule\)/);
  assert.match(lines, /Security policy version 12 \(org state\)/);
  const off = status({ managed: true, mode: "local", org: { on: false, private: "withhold", kinds: [], version: 3, source: "org" } });
  assert.match(lookupModeLine(off), /no package lookup leaves this machine/);
  assert.match(orgPostureLines(off).join("\n"), /off by your organization's policy/);
});
