// The AI gateway helpers (hosted AI gateway arc, lane L8):
// sdk/contract/ai-gateway-cases.json through the pure resolver and
// parseGatewayRefusal (Python, Go and Java run the same file), and the client
// options against a stub gateway with the real OpenAI and Anthropic clients.
import { test, beforeEach, after } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { InMemorySpanExporter } from "@opentelemetry/sdk-trace-base";

import * as sb from "../dist/esm/index.js";
import { reset, startStub } from "./helpers.mjs";

const contractDir = process.env.SUPERBASED_CONTRACT_DIR || join(dirname(fileURLToPath(import.meta.url)), "..", "..", "contract");
const FILE = join(contractDir, "ai-gateway-cases.json");
const CASES = existsSync(FILE) ? JSON.parse(readFileSync(FILE, "utf8")) : null;
const skip = !CASES && "sdk/contract is not present";

beforeEach(reset);
after(reset);

test("the base_url contract cases", { skip }, () => {
  assert.ok(CASES.base_url.length >= 20);
  for (const c of CASES.base_url) {
    let asked = false;
    const r = sb.resolveGatewayEndpoint({
      provider: c.provider,
      upstream: c.upstream,
      url: c.url,
      env: c.env,
      destination: c.destination,
      orgUrl: c.org_url,
      local: () => {
        asked = true;
        return c.local;
      },
    });
    if (c.want.problem) {
      assert.equal(r.endpoint, null, c.name);
      assert.equal(r.problem, c.want.problem, c.name);
      assert.ok(r.message, c.name);
      continue;
    }
    assert.equal(r.problem, "", `${c.name}: ${r.message}`);
    assert.equal(r.endpoint.baseUrl, c.want.url, c.name);
    assert.equal(r.endpoint.source, c.want.source, c.name);
    assert.equal(r.endpoint.upstreamHeader, c.want.upstream_header ?? "", c.name);
    if (c.destination === "online") assert.equal(asked, false, `${c.name}: asked the machine under online`);
  }
});

function budget(b) {
  return { level: b.level, scopeId: b.scope_id, unit: b.unit, remaining: b.remaining, cap: b.cap, estimated: b.estimated };
}

function checkRefusal(got, want, name) {
  if (want === null) {
    assert.equal(got, null, name);
    return;
  }
  assert.ok(got instanceof sb.GatewayRefusalError, name);
  assert.ok(got instanceof Error, name);
  assert.deepEqual([got.kind, got.code, got.status], [want.kind, want.code, want.status], name);
  assert.ok(got.message, name);
  if ("message" in want) assert.equal(got.message, want.message, name);
  assert.equal(got.requestId, want.request_id ?? "", name);
  assert.equal(got.retryAfterMs, "retry_after_seconds" in want ? want.retry_after_seconds * 1000 : undefined, name);
  if ("budget" in want) assert.deepEqual(got.budget, budget(want.budget), name);
  else assert.equal(got.budget, undefined, name);
  if ("plan_refusal" in want) {
    const p = got.planRefusal;
    assert.ok(p instanceof sb.PlanRefusalError, name);
    assert.deepEqual([p.kind, p.code, p.upgradeUrl, p.capability], [want.plan_refusal.kind, want.plan_refusal.code, want.plan_refusal.upgrade_url, want.plan_refusal.capability], name);
  } else {
    assert.equal(got.planRefusal, undefined, name);
  }
}

test("the api_key contract cases", { skip }, () => {
  // The shared key rule (hosted AI gateway review L7): a provider's own key
  // never reaches a remote gateway.
  assert.ok(CASES.api_key.length >= 10);
  const saved = process.env.SUPERBASED_AI_GATEWAY_KEY;
  try {
    for (const c of CASES.api_key) {
      if (c.gateway_key === null) delete process.env.SUPERBASED_AI_GATEWAY_KEY;
      else process.env.SUPERBASED_AI_GATEWAY_KEY = c.gateway_key;
      const ep = { baseUrl: c.base_url, source: c.source, upstream: "", upstreamHeader: "" };
      if ("problem" in c.want) {
        assert.throws(() => sb.gatewayClientKey(ep), (e) => e instanceof sb.GatewayNotConfiguredError && e.problem === c.want.problem, c.name);
        continue;
      }
      assert.equal(sb.gatewayClientKey(ep) ?? null, c.want.key, c.name);
    }
  } finally {
    if (saved === undefined) delete process.env.SUPERBASED_AI_GATEWAY_KEY;
    else process.env.SUPERBASED_AI_GATEWAY_KEY = saved;
  }
});

test("the refusal contract cases, as objects, text and bytes, with Headers or a record", { skip }, () => {
  assert.ok(CASES.refusal.length >= 15);
  for (const c of CASES.refusal) {
    checkRefusal(sb.parseGatewayRefusal(c.status, c.body, c.headers), c.want, c.name);
    const text = typeof c.body === "string" ? c.body : JSON.stringify(c.body);
    checkRefusal(sb.parseGatewayRefusal(c.status, text, new Headers(c.headers)), c.want, `${c.name} (text)`);
    checkRefusal(sb.parseGatewayRefusal(c.status, new TextEncoder().encode(text), c.headers), c.want, `${c.name} (bytes)`);
  }
});

test("parseGatewayRefusal never throws", () => {
  for (const junk of [undefined, null, 0, "null", "[]", new Uint8Array([0xff, 0xfe]), { reason: 7 }]) {
    assert.equal(sb.parseGatewayRefusal(402, junk), null);
  }
  assert.equal(sb.parseGatewayRefusal("402", { reason: "budget_exceeded" }), null);
});

test("online resolves the organization's address; env and argument win", async () => {
  process.env.SUPERBASED_DESTINATION = "online";
  process.env.SUPERBASED_ORG_URL = "https://acme.superbased.app";
  process.env.SUPERBASED_API_KEY = "ik_1.secret";
  process.env.SUPERBASED_DISCOVER = "0";
  assert.equal(await sb.gatewayBaseUrl("openai"), "https://acme.superbased.app/ai/openai/v1");
  const ep = await sb.gatewayEndpoint("anthropic", { upstream: "claude" });
  assert.deepEqual(ep, { baseUrl: "https://acme.superbased.app/ai/claude", source: "org", upstream: "claude", upstreamHeader: "" });
  process.env.SUPERBASED_AI_GATEWAY_URL = "https://ai.example.com";
  assert.deepEqual(await sb.gatewayEndpoint("openai", { upstream: "openai-eu" }), {
    baseUrl: "https://ai.example.com/v1",
    source: "env",
    upstream: "openai-eu",
    upstreamHeader: "openai-eu",
  });
  assert.equal(await sb.gatewayBaseUrl("openai", { url: "https://arg.example.com" }), "https://arg.example.com/v1");
  await assert.rejects(sb.gatewayBaseUrl("cohere"), (e) => e instanceof sb.GatewayNotConfiguredError && e.problem === "unknown_provider");
});

test("the machine lane from discovery, asked once", async () => {
  const stub = await startStub();
  try {
    stub.reply({ api_version: 1, destination: "local", local: { app_lanes: [{ id: "openai", base_url: "http://127.0.0.1:8820/up/openai" }] } });
    process.env.SUPERBASED_NODE_URL = stub.url;
    assert.equal(await sb.gatewayBaseUrl("openai"), "http://127.0.0.1:8820/up/openai/v1");
    await assert.rejects(sb.gatewayBaseUrl("anthropic"), (e) => e.problem === "not_configured" && /observer apps lane add/.test(e.message));
    assert.equal(stub.requests.filter((r) => r.path === "/api/sdk/destination").length, 1);
  } finally {
    await stub.close();
  }
});

test("discovery off never asks the machine", async () => {
  const stub = await startStub();
  try {
    process.env.SUPERBASED_NODE_URL = stub.url;
    process.env.SUPERBASED_DISCOVER = "0";
    process.env.SUPERBASED_DESTINATION = "local";
    await assert.rejects(sb.gatewayBaseUrl("openai"), (e) => e.problem === "not_configured");
    assert.equal(stub.requests.length, 0);
  } finally {
    await stub.close();
  }
});

test("gatewayFetch sends the active span's traceparent", async () => {
  const stub = await startStub();
  try {
    sb.init({ serviceName: "svc", destination: "local", exporter: new InMemorySpanExporter(), discover: false });
    await sb.withSpan("call", async (sp) => {
      await sb.gatewayFetch()(stub.url + "/v1/chat/completions", { method: "POST", body: "{}" });
      const ctx = sp.spanContext();
      assert.match(stub.requests[0].headers.traceparent, new RegExp(`^00-${ctx.traceId}-${ctx.spanId}-`));
    });
  } finally {
    await stub.close();
  }
});

const { default: OpenAI } = await import("openai").catch(() => ({ default: null }));
const { default: Anthropic } = await import("@anthropic-ai/sdk").catch(() => ({ default: null }));

const completion = { id: "c1", object: "chat.completion", created: 1, model: "m", choices: [] };

test("openAIOptions: the gateway key, the identity headers and the upstream header", { skip: !OpenAI && "openai not installed" }, async () => {
  const stub = await startStub();
  try {
    stub.reply(completion, 200, { "X-SBO-Request-Id": "gw-1" });
    process.env.SUPERBASED_AI_GATEWAY_KEY = "sbo-vk-test";
    process.env.OPENAI_API_KEY = "sk-provider-must-not-leak";
    sb.init({ serviceName: "support-bot", user: "u1", destination: "local", exporter: new InMemorySpanExporter(), discover: false });
    const client = new OpenAI(await sb.openAIOptions({ upstream: "openai-eu", url: stub.url }));
    await client.chat.completions.create({ model: "m", messages: [{ role: "user", content: "hi" }] });
    const req = stub.requests.at(-1);
    assert.equal(req.path, "/v1/chat/completions");
    assert.equal(req.headers.authorization, "Bearer sbo-vk-test");
    assert.equal(req.headers["x-sbo-upstream"], "openai-eu");
    assert.equal(req.headers["x-superbased-service"], "support-bot");
    assert.equal(req.headers["x-superbased-user"], "u1");
    assert.match(req.headers["x-sbo-request-id"], /^sdk-/);
  } finally {
    delete process.env.OPENAI_API_KEY;
    await stub.close();
  }
});

test("a remote gateway without a gateway key never gets the provider key", async () => {
  process.env.OPENAI_API_KEY = "sk-provider-must-not-leak";
  try {
    await assert.rejects(sb.openAIOptions({ url: "https://ai.example.com" }), (e) => e instanceof sb.GatewayNotConfiguredError && e.problem === "no_key");
  } finally {
    delete process.env.OPENAI_API_KEY;
  }
});

test("the machine lane leaves the key to the client (the provider's own)", async () => {
  const stub = await startStub();
  try {
    stub.reply({ api_version: 1, destination: "local", local: { app_lanes: [{ id: "openai", base_url: "http://127.0.0.1:8820/up/openai" }] } });
    process.env.SUPERBASED_NODE_URL = stub.url;
    process.env.SUPERBASED_AI_GATEWAY_KEY = "sbo-vk-not-for-the-lane";
    const opts = await sb.openAIOptions();
    assert.equal(opts.baseURL, "http://127.0.0.1:8820/up/openai/v1");
    assert.equal("apiKey" in opts, false);
    assert.equal(opts.defaultHeaders, undefined);
  } finally {
    await stub.close();
  }
});

test("a refusal through the OpenAI client is read back by request id", { skip: !OpenAI && "openai not installed" }, async () => {
  const stub = await startStub();
  try {
    stub.reply(
      { error: { message: "model gpt-5 is not allowed", type: "permission_error", param: null, code: "model_not_allowed" }, reason: "model_not_allowed" },
      403,
      { "X-SBO-Request-Id": "gw-9", "x-request-id": "gw-9" },
    );
    process.env.SUPERBASED_AI_GATEWAY_KEY = "sbo-vk-test";
    const client = new OpenAI({ ...(await sb.openAIOptions({ url: stub.url })), maxRetries: 0 });
    const err = await client.chat.completions.create({ model: "gpt-5", messages: [] }).then(
      () => null,
      (e) => e,
    );
    assert.ok(err);
    const r = sb.gatewayRefusal(err);
    assert.equal(r?.kind, "model_not_allowed");
    assert.equal(r?.requestId, "gw-9");
    assert.equal(sb.gatewayRefusal(new Error("x")), null);
  } finally {
    await stub.close();
  }
});

test("no redirect is followed", { skip: !OpenAI && "openai not installed" }, async () => {
  const stub = await startStub();
  try {
    stub.reply("", 307, { Location: "https://elsewhere.example.com/v1/chat/completions" });
    process.env.SUPERBASED_AI_GATEWAY_KEY = "sbo-vk-test";
    const opts = await sb.openAIOptions({ url: stub.url });
    const resp = await opts.fetch(stub.url + "/v1/chat/completions", { method: "POST", body: "{}" });
    assert.equal(resp.status, 307);
    assert.equal(stub.requests.length, 1);
  } finally {
    await stub.close();
  }
});

test("anthropicOptions with the Anthropic client; its error keeps the whole body", { skip: !Anthropic && "@anthropic-ai/sdk not installed" }, async () => {
  const stub = await startStub();
  try {
    stub.reply(
      {
        type: "error",
        error: { type: "billing_error", message: "request denied: the service token cap was reached (estimated)", details: { error_code: "budget_exceeded" } },
        reason: "budget_exceeded",
        level: "service",
        scope_id: "checkout-api",
        unit: "tokens",
        remaining_tokens: -994,
        cap_tokens: 100,
        estimated: true,
      },
      402,
      { "X-SBO-Request-Id": "gw-2", "request-id": "gw-2" },
    );
    process.env.SUPERBASED_AI_GATEWAY_KEY = "sbo-vk-test";
    process.env.ANTHROPIC_API_KEY = "sk-ant-must-not-leak";
    const client = new Anthropic({ ...(await sb.anthropicOptions({ url: stub.url })), maxRetries: 0 });
    const err = await client.messages.create({ model: "m", max_tokens: 8, messages: [{ role: "user", content: "hi" }] }).then(
      () => null,
      (e) => e,
    );
    const req = stub.requests.at(-1);
    assert.equal(req.path, "/v1/messages");
    assert.ok(req.headers["x-api-key"] === "sbo-vk-test" || req.headers.authorization === "Bearer sbo-vk-test");
    assert.ok(!JSON.stringify(req.headers).includes("sk-ant-must-not-leak"));
    const r = sb.gatewayRefusal(err);
    assert.equal(r?.kind, "budget_exceeded");
    assert.equal(r?.budget?.remaining, -994);
  } finally {
    delete process.env.ANTHROPIC_API_KEY;
    await stub.close();
  }
});
