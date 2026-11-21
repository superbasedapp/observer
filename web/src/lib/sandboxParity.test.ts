// Tests of the pure models behind the sandbox controls of the dashboard CLI
// parity plan (lane L3).

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  MXC_TIER_OPTIONS,
  absPathProblem,
  credKeyProblem,
  hostedConnectReady,
  hostedFieldIsSecret,
  hostedTemplateProblem,
  importDirProblem,
  mxcTierLoosens,
  readoptCanReattach,
  wslcImageProblem,
} from "./sandboxParity.ts";

test("only a move off ProcessContainer loosens the MXC tier floor", () => {
  const cases: [string | undefined, string | undefined, boolean][] = [
    ["process_container", "appcontainer", true],
    ["process_container", "", true],
    ["process_container", undefined, true],
    ["process_container", "process_container", false],
    ["", "process_container", false],
    ["appcontainer", "", false],
    ["", "appcontainer", false],
    [undefined, undefined, false],
  ];
  for (const [saved, next, want] of cases) {
    assert.equal(mxcTierLoosens(saved, next), want, `${saved} -> ${next}`);
  }
  assert.deepEqual(
    MXC_TIER_OPTIONS.map((o) => o.value),
    ["process_container", "appcontainer", ""],
  );
});

test("a credential field is a secret unless it names an id", () => {
  assert.equal(hostedFieldIsSecret("E2B_API_KEY"), true);
  assert.equal(hostedFieldIsSecret("MODAL_TOKEN_SECRET"), true);
  assert.equal(hostedFieldIsSecret("VERCEL_TOKEN"), true);
  assert.equal(hostedFieldIsSecret("MODAL_TOKEN_ID"), false);
  assert.equal(hostedFieldIsSecret("VERCEL_TEAM_ID"), false);
});

test("connect is ready only when every field has a value", () => {
  assert.equal(hostedConnectReady(["A", "B"], { A: "x", B: " y " }), true);
  assert.equal(hostedConnectReady(["A", "B"], { A: "x", B: "  " }), false);
  assert.equal(hostedConnectReady(["A"], {}), false);
  assert.equal(hostedConnectReady([], {}), false);
});

test("a key with a space, a line break or nothing is refused without echoing it", () => {
  assert.equal(credKeyProblem("sk-FAKEVALUE"), null);
  assert.equal(credKeyProblem("  sk-FAKEVALUE \n"), null);
  for (const bad of ["", "   ", "sk FAKEVALUE", "sk-FAKE\nVALUE", "x".repeat(4097)]) {
    const why = credKeyProblem(bad);
    assert.ok(why, `refused: ${JSON.stringify(bad.slice(0, 20))}`);
    assert.doesNotMatch(why ?? "", /FAKE/);
  }
});

test("the Windows row fields: a digest-pinned image and absolute paths", () => {
  assert.equal(wslcImageProblem(""), null);
  assert.equal(wslcImageProblem("ghcr.io/acme/box@sha256:" + "a".repeat(64)), null);
  assert.ok(wslcImageProblem("ghcr.io/acme/box:latest"));
  assert.ok(wslcImageProblem("box@sha256:" + "A".repeat(64)));
  assert.equal(absPathProblem(""), null);
  assert.equal(absPathProblem("C:\\Windows\\System32\\wslc.exe"), null);
  assert.equal(absPathProblem("/opt/observer/bin/observer"), null);
  assert.equal(absPathProblem("\\\\server\\share\\uvm"), null);
  assert.ok(absPathProblem("bin/wslc.exe"));
});

test("a hosted template is a name, never a path or a command", () => {
  assert.equal(hostedTemplateProblem(""), null);
  assert.equal(hostedTemplateProblem("observer-claude-code"), null);
  assert.equal(hostedTemplateProblem("ghcr.io/acme/box:1.2@sha256:abc"), null);
  assert.ok(hostedTemplateProblem("/abs/path"));
  assert.ok(hostedTemplateProblem("a b"));
  assert.ok(hostedTemplateProblem("x;rm -rf /"));
});

test("the image set folder must be named by an absolute path", () => {
  assert.ok(importDirProblem(""));
  assert.ok(importDirProblem("sets/1.0.0"));
  assert.equal(importDirProblem("/home/u/Downloads/observer-vm-1.0.0"), null);
  assert.equal(importDirProblem("D:\\sets\\observer-vm-1.0.0"), null);
});

test("a re-attach takes an open or held offer only", () => {
  assert.equal(readoptCanReattach("offered"), true);
  assert.equal(readoptCanReattach("held"), true);
  for (const s of ["checkpointed", "readopted", "expiring", ""]) assert.equal(readoptCanReattach(s), false);
});
