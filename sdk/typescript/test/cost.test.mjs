// W4-2 (lane C6): the SDK side of exact cost (contract cost-source.md, lane C2):
// getTraceCost over the org route and the machine's trace detail, the source
// vocabulary, and the gateway request-id join key.
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { InMemorySpanExporter } from "@opentelemetry/sdk-trace-base";

import * as sb from "../dist/esm/index.js";
import { reset, startStub } from "./helpers.mjs";

beforeEach(reset);

const TRACE = "4bf92f3577b34da6a3ce929d0e0e4736";
const contractDir = process.env.SUPERBASED_CONTRACT_DIR || join(dirname(fileURLToPath(import.meta.url)), "..", "..", "contract");
const RECORDED = join(contractDir, "trace-cost-response.json");

// contract cost-source.md section 6, verbatim
const BODY = {
  api_version: "v1",
  trace_id: TRACE,
  cost_usd: 0.0123,
  cost_provenance: { label: "gateway_exact", complete: true, sources: { gateway_exact: 1, proxy_exact: 0, computed: 0, reported: 0, unpriced: 0 } },
  spans: [
    {
      span_id: "00f067aa0ba902b7",
      model: "gpt-4o-mini",
      cost_usd: 0.0123,
      cost_source: "gateway_exact",
      reported_usd: 0.01,
      computed_usd: 0.0121,
      exact_usd: 0.0123,
      cost_delta_usd: 0.0023,
      gateway_request_id: "gw-3f0c",
    },
  ],
};

function quiet() {
  const warn = console.warn;
  console.warn = () => {};
  return () => (console.warn = warn);
}

test("the source vocabulary and labels match the contract", () => {
  assert.deepEqual(sb.COST_SOURCES, ["gateway_exact", "proxy_exact", "computed", "reported", ""]);
  assert.equal(sb.COST_SOURCE_LABELS[""], "Unpriced");
  assert.equal(sb.COST_SOURCE_LABELS.gateway_exact, "Gateway exact");
  assert.equal(sb.isExactCost("proxy_exact"), true);
  assert.equal(sb.isExactCost("computed"), false);
});

test("getTraceCost reads the org route under online, camelCased", async () => {
  const gw = await startStub();
  try {
    gw.reply(BODY);
    sb.init({ exporter: new InMemorySpanExporter(), destination: "online", orgUrl: gw.url, apiKey: "sk" });
    const c = await sb.getTraceCost(TRACE.toUpperCase());
    assert.equal(gw.requests[0].path, `/v1/sdk/traces/${TRACE}/cost`);
    assert.equal(gw.requests[0].headers.authorization, "Bearer sk");
    assert.deepEqual(c, {
      traceId: TRACE,
      costUsd: 0.0123,
      costProvenance: { label: "gateway_exact", complete: true, sources: { gatewayExact: 1, proxyExact: 0, computed: 0, reported: 0, unpriced: 0 } },
      spans: [
        {
          spanId: "00f067aa0ba902b7",
          model: "gpt-4o-mini",
          costUsd: 0.0123,
          costSource: "gateway_exact",
          reportedUsd: 0.01,
          computedUsd: 0.0121,
          exactUsd: 0.0123,
          costDeltaUsd: 0.0023,
          gatewayRequestId: "gw-3f0c",
        },
      ],
      destination: "online",
    });
  } finally {
    await gw.close();
  }
});

test("getTraceCost under both: the org first, then the machine's trace detail; null when neither has it", async () => {
  const gw = await startStub();
  const machine = await startStub();
  const restore = quiet();
  try {
    gw.reply({ error: "not_found" }, 404);
    machine.reply({
      trace: { trace_id: TRACE },
      cost: {
        trace_id: TRACE,
        cost_usd: null,
        cost_provenance: { label: "unpriced", complete: false, sources: { unpriced: 1 } },
        spans: [{ span_id: "00f067aa0ba902b7", model: "m", cost_usd: 0, cost_source: "", reported_usd: null }],
      },
    });
    sb.init({ exporter: new InMemorySpanExporter(), destination: "both", orgUrl: gw.url, apiKey: "sk", nodeUrl: machine.url });
    const c = await sb.getTraceCost(TRACE);
    assert.equal(machine.requests[0].path, `/api/obs/trace/${TRACE}`);
    assert.equal(machine.requests[0].headers.authorization, undefined, "the key never goes to the machine");
    assert.equal(c.destination, "local");
    assert.equal(c.costUsd, null);
    assert.equal(c.costProvenance.complete, false);
    assert.equal(c.spans[0].costSource, "");
    assert.equal(c.spans[0].costUsd, null, "an unpriced span never reads as $0");
    machine.reply({ error: "not_found" }, 404);
    assert.equal(await sb.getTraceCost(TRACE), null);
    await assert.rejects(sb.getTraceCost("nope"), RangeError);
    await assert.rejects(sb.getTraceCost("0".repeat(32)), RangeError);
  } finally {
    restore();
    await gw.close();
    await machine.close();
  }
});

test("the recorded org and machine responses (sdk/contract/trace-cost-response.json, lane C2) parse", { skip: !existsSync(RECORDED) && "C2's recorded response is not on this branch yet" }, () => {
  // The file records each answer under its side: org.body is the org's
  // GET /v1/sdk/traces/{id}/cost, machine.body.cost the machine's.
  const fx = JSON.parse(readFileSync(RECORDED, "utf8"));
  for (const [side, body] of [["online", fx.org.body], ["local", fx.machine.body.cost]]) {
    const c = sb.parseTraceCost(body, side);
    assert.ok(c, side);
    assert.equal(c.traceId, body.trace_id);
    assert.equal(c.spans.length, (body.spans ?? []).length);
    for (const [i, s] of (body.spans ?? []).entries()) assert.equal(c.spans[i].costSource, s.cost_source ?? "", `${side} span ${i}`);
  }
});

test("C1: gatewayFetch names the end user and the service for the gateway's app budgets; a caller's headers win", async () => {
  const gw = await startStub();
  try {
    sb.init({ exporter: new InMemorySpanExporter(), serviceName: "checkout", user: "init-user" });
    gw.reply({ ok: true }, 200, {});
    const f = sb.gatewayFetch();
    await f(`${gw.url}/v1/chat/completions`, { method: "POST", body: "{}" });
    assert.equal(gw.requests[0].headers["x-superbased-user"], "init-user", "init's user");
    assert.equal(gw.requests[0].headers["x-superbased-service"], "checkout");
    await sb.propagateAttributes({ user: "alice" }, () => f(`${gw.url}/v1/chat/completions`, { method: "POST", body: "{}" }));
    assert.equal(gw.requests[1].headers["x-superbased-user"], "alice", "the per-request user wins over init's");
    await f(`${gw.url}/v1/x`, { headers: { "X-Superbased-User": "set-by-app", "X-Superbased-Service": "svc-by-app" } });
    assert.equal(gw.requests[2].headers["x-superbased-user"], "set-by-app");
    assert.equal(gw.requests[2].headers["x-superbased-service"], "svc-by-app");
    // A user fetch cannot send as a header (non-Latin-1) is left out; the call still goes.
    const resp = await sb.propagateAttributes({ user: "名前" }, () => f(`${gw.url}/v1/x`, {}));
    assert.equal(resp.status, 200);
    assert.equal(gw.requests[3].headers["x-superbased-user"], undefined);
    assert.equal(gw.requests[3].headers["x-superbased-service"], "checkout");
  } finally {
    await gw.close();
  }
});

test("gatewayFetch sends a request id when none is set and stamps the gateway's id on the active span", async () => {
  const gw = await startStub();
  try {
    const mem = new InMemorySpanExporter();
    sb.init({ exporter: mem });
    gw.reply({ ok: true }, 200, { "X-SBO-Request-Id": "gw-answered" });
    const f = sb.gatewayFetch();
    await sb.withLlmSpan("chat", { model: "gpt-4o-mini" }, () => f(`${gw.url}/v1/chat/completions`, { method: "POST", body: "{}" }));
    assert.match(gw.requests[0].headers["x-sbo-request-id"], /^sdk-/);
    gw.reply({ ok: true }, 200, {});
    await sb.withLlmSpan("chat2", {}, () => f(`${gw.url}/v1/x`, { headers: { "X-SBO-Request-Id": "mine" } }));
    assert.equal(gw.requests[1].headers["x-sbo-request-id"], "mine", "a caller's id is kept");
    await sb.flush(2000);
    const spans = Object.fromEntries(mem.getFinishedSpans().map((s) => [s.name, s]));
    assert.equal(spans.chat.attributes.request_id, "gw-answered");
    assert.equal(spans.chat2.attributes.request_id, "mine", "the gateway honours the sent id");
    assert.equal(sb.gatewayRequestId({ "x-sbo-request-id": ["a"] }), "a");
    assert.equal(sb.stampGatewayRequestId({}), "");
  } finally {
    await gw.close();
  }
});

test("R-C34: getTraceCost() defaults to the current trace; no trace resolves null with no call", async () => {
  const gw = await startStub();
  try {
    gw.reply(BODY);
    sb.init({ exporter: new InMemorySpanExporter(), destination: "online", orgUrl: gw.url, apiKey: "sk" });
    assert.equal(await sb.getTraceCost(), null);
    assert.equal(gw.requests.length, 0, "no trace, no call");
    const tid = await sb.withSpan("req", async () => {
      await sb.getTraceCost();
      return sb.getCurrentTraceId();
    });
    assert.equal(gw.requests[0].path, `/v1/sdk/traces/${tid}/cost`);
  } finally {
    await gw.close();
  }
});
