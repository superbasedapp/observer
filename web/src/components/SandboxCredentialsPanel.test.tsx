// Render tests of the credential injection and re-adoption panel (lane
// GATES-SBX; dashboard CLI parity lane L3 items B-G1 and B-G3), rendered with
// react-dom/server (scripts/test-components.mjs).

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { SandboxCredentialsView, componentActive, BOUND_MINUTES } from "@/components/SandboxCredentialsPanel";

// React warns that a layout effect does nothing on the server; the chips use
// one, and the warning says nothing about these tests.
const consoleError = console.error;
console.error = (...args: unknown[]) => {
  if (typeof args[0] === "string" && args[0].includes("useLayoutEffect does nothing on the server")) return;
  consoleError(...args);
};

const base = {
  readopt: { bound_minutes: 10, checkpoint_cap_mib: 2048 },
  creds: { providers: [{ provider: "anthropic", label: "Anthropic API key", host: "api.anthropic.com", key_env: "ANTHROPIC_API_KEY", stored: true }], store: "keychain", confirm_token: "t" },
  runs: { runs: [{ run_id: "run0000000000000001", tool: "claude-code", project: "/w", state: "offered", reason: "", command: "observer sandbox readopt run0000000000000001", checkpointed: false }], confirm_token: "t" },
  pinned: new Set<string>(),
  writable: true,
  busy: "",
  err: null,
  onChange: () => {},
  post: () => {},
};

test("nothing renders while both components are off", () => {
  assert.equal(renderToStaticMarkup(<SandboxCredentialsView {...base} credOn={false} readoptOn={false} />), "");
});

test("the credential half lists providers, never a key, and offers an empty password field", () => {
  const html = renderToStaticMarkup(
    <SandboxCredentialsView {...base} credOn readoptOn={false} keyDraft={{}} onKeyDraft={() => {}} saveKey={() => {}} />,
  );
  assert.match(html, /key stored/);
  assert.match(html, /<input[^>]*type="password"/);
  assert.doesNotMatch(html, /<input[^>]*type="text"/);
  assert.match(html, /Replace key/);
  assert.doesNotMatch(html, /in your own terminal/);
  assert.doesNotMatch(html, /Re-adopting container runs/);
});

test("a typed key is refused before Save when it holds a space, and the message never repeats it", () => {
  const html = renderToStaticMarkup(
    <SandboxCredentialsView {...base} credOn readoptOn={false} keyDraft={{ anthropic: "sk FAKEVALUE" }} onKeyDraft={() => {}} saveKey={() => {}} />,
  );
  assert.match(html, /That is not a key/);
  assert.match(html, /<button[^>]*disabled=""[^>]*>Replace key/);
});

test("without the save seam there is no key field", () => {
  const html = renderToStaticMarkup(<SandboxCredentialsView {...base} credOn readoptOn={false} />);
  assert.doesNotMatch(html, /<input/);
});

test("the re-adoption half has pickers, the offered run and a re-attach button", () => {
  const html = renderToStaticMarkup(<SandboxCredentialsView {...base} credOn={false} readoptOn reattach={() => {}} />);
  assert.match(html, /Keep an unadopted run for/);
  assert.match(html, /10 minutes/);
  assert.match(html, />Re-attach in a terminal<\/button>/);
  assert.match(html, /Same as .*observer sandbox readopt run0000000000000001/);
  assert.match(html, /Checkpoint/);
  assert.ok(BOUND_MINUTES.includes(10));
});

test("a checkpointed run gets no re-attach button", () => {
  const runs = { runs: [{ ...base.runs.runs[0], state: "checkpointed", checkpointed: true }], confirm_token: "t" };
  const html = renderToStaticMarkup(<SandboxCredentialsView {...base} runs={runs} credOn={false} readoptOn reattach={() => {}} />);
  assert.doesNotMatch(html, />Re-attach in a terminal<\/button>/);
  assert.match(html, /Restore/);
});

test("the opt-in rule needs a configured block with the component active", () => {
  assert.equal(componentActive(undefined, "terminals.sandbox.credentials"), false);
  assert.equal(componentActive({ configured: false, components: [{ id: "terminals.sandbox.credentials", state: "active" }] } as never, "terminals.sandbox.credentials"), false);
  assert.equal(componentActive({ configured: true, components: [{ id: "terminals.sandbox.credentials", state: "active" }] } as never, "terminals.sandbox.credentials"), true);
});
