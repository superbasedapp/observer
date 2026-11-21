import { test } from "node:test";
import assert from "node:assert/strict";
import { agentFromSurfaceHost, ownAgentSnippet, snippetBase, SNIPPET_LANGS, viaLabel } from "./ownAgents.ts";

const facts = {
  baseURL: "http://127.0.0.1:8820/",
  agentHeader: "X-Superbased-Agent",
  sessionHeader: "X-Session-Id",
};

test("every snippet sets the base URL and both headers", () => {
  for (const { value } of SNIPPET_LANGS) {
    const s = ownAgentSnippet(value, facts);
    assert.ok(s.includes("http://127.0.0.1:8820"), `${value}: no base URL`);
    assert.ok(!s.includes("8820//"), `${value}: doubled slash`);
    assert.ok(s.includes("X-Superbased-Agent"), `${value}: no agent header`);
    assert.ok(s.includes("X-Session-Id"), `${value}: no session header`);
  }
});

test("the OpenAI snippet uses the /v1 base and the Anthropic ones the root", () => {
  assert.ok(ownAgentSnippet("typescript", facts).includes('baseURL: "http://127.0.0.1:8820/v1"'));
  assert.ok(ownAgentSnippet("python", facts).includes('base_url="http://127.0.0.1:8820"'));
  assert.ok(ownAgentSnippet("curl", facts).includes("http://127.0.0.1:8820/v1/messages"));
});

test("a named agent replaces the example name", () => {
  assert.ok(ownAgentSnippet("curl", { ...facts, agent: "triage-bot" }).includes("X-Superbased-Agent: triage-bot"));
});

test("agentFromSurfaceHost reads only own-agent hosts", () => {
  assert.equal(agentFromSurfaceHost("agent:bot"), "bot");
  assert.equal(agentFromSurfaceHost("vscode"), "");
  assert.equal(agentFromSurfaceHost(""), "");
  assert.equal(agentFromSurfaceHost(undefined), "");
});

test("with client auth every snippet uses the /t/<token> base URL", () => {
  const auth = { ...facts, clientAuth: true };
  assert.equal(snippetBase(auth), "http://127.0.0.1:8820/t/<token>");
  assert.ok(ownAgentSnippet("typescript", auth).includes('baseURL: "http://127.0.0.1:8820/t/<token>/v1"'));
  assert.ok(ownAgentSnippet("python", auth).includes('base_url="http://127.0.0.1:8820/t/<token>"'));
  assert.ok(ownAgentSnippet("curl", auth).includes("http://127.0.0.1:8820/t/<token>/v1/messages"));
  assert.equal(snippetBase(facts), "http://127.0.0.1:8820");
});

test("the source label names the capture path, and an unknown value reads as the proxy", () => {
  assert.equal(viaLabel("proxy"), "proxy");
  assert.equal(viaLabel("otlp"), "OTLP spans");
  assert.equal(viaLabel("proxy+otlp"), "proxy + OTLP spans");
  assert.equal(viaLabel(undefined), "proxy");
  assert.equal(viaLabel("something-new"), "proxy");
});
