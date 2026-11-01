// Render tests of the credential injection and re-adoption panel (lane
// GATES-SBX), rendered with react-dom/server (scripts/test-components.mjs).

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { SandboxCredentialsView, componentActive, BOUND_MINUTES } from "@/components/SandboxCredentialsPanel";

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

test("the credential half lists providers, never a key, and says how to add one", () => {
  const html = renderToStaticMarkup(<SandboxCredentialsView {...base} credOn readoptOn={false} />);
  assert.match(html, /key stored/);
  assert.match(html, /observer sandbox credentials add/);
  assert.doesNotMatch(html, /<input[^>]*type="(text|password)"/);
  assert.doesNotMatch(html, /Re-adopting container runs/);
});

test("the re-adoption half has pickers and the offered run", () => {
  const html = renderToStaticMarkup(<SandboxCredentialsView {...base} credOn={false} readoptOn />);
  assert.match(html, /Keep an unadopted run for/);
  assert.match(html, /10 minutes/);
  assert.match(html, /observer sandbox readopt run0000000000000001/);
  assert.match(html, /Checkpoint/);
  assert.ok(BOUND_MINUTES.includes(10));
});

test("the opt-in rule needs a configured block with the component active", () => {
  assert.equal(componentActive(undefined, "terminals.sandbox.credentials"), false);
  assert.equal(componentActive({ configured: false, components: [{ id: "terminals.sandbox.credentials", state: "active" }] } as never, "terminals.sandbox.credentials"), false);
  assert.equal(componentActive({ configured: true, components: [{ id: "terminals.sandbox.credentials", state: "active" }] } as never, "terminals.sandbox.credentials"), true);
});
