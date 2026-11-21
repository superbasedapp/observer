// admit(): every failure body, status mapping, failClosed, timeouts, org
// endpoint + credential, advertised timeout, span stamping.
import { test, beforeEach, before, after } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { trace } from "@opentelemetry/api";
import { resourceFromAttributes } from "@opentelemetry/resources";
import { InMemorySpanExporter } from "@opentelemetry/sdk-trace-base";
import { NodeTracerProvider } from "@opentelemetry/sdk-trace-node";

import * as sb from "../dist/esm/index.js";
import { advertisedTimeoutMs, resetAdvertisedTimeouts } from "../dist/esm/admit.js";
import { deadUrl, reset, startStub } from "./helpers.mjs";

const GOOD = {
  allowed: false, decision: "deny", severity: "high", criterion: "c1", reason: "no",
  mode: "enforce", judge_used: true, latency_ms: 42, enforce_decision: "deny",
};

let stub;
before(async () => { stub = await startStub(); });
after(async () => { await stub.close(); });
beforeEach(async () => {
  await reset();
  resetAdvertisedTimeouts();
  stub.delayMs = 0;
  stub.requests.length = 0;
  stub.reply(GOOD);
});

test("defaults", () => {
  assert.equal(sb.DEFAULT_ADMISSION_ENDPOINT, "http://127.0.0.1:8081/api/obs/admission/check");
  assert.equal(sb.DEFAULT_ADMIT_TIMEOUT_MS, 12000);
});

test("clean verdict carries judgeUsed and latencyMs", async () => {
  const v = await sb.admit("hi", { endpoint: stub.url + "/check", user: "u", session: "s", tenant: "t", requestId: "r" });
  assert.equal(v.allowed, false);
  assert.equal(v.decision, "deny");
  assert.equal(v.judgeUsed, true);
  assert.equal(v.latencyMs, 42);
  assert.equal(v.degraded, "");
  assert.equal(v.httpStatus, 200);
  assert.deepEqual(stub.requests[0].body, { text: "hi", tenant: "t", user: "u", session: "s", service: "custom-app", trace_id: "", request_id: "r" });
});

const BAD = ["[]", "\"x\"", "null", "42", "not json", "", "{\"decision\":\"allow\"}", "{\"allowed\":\"false\"}", "{\"allowed\":1}", "{\"allowed\":null}"];
for (const body of BAD) {
  for (const failClosed of [false, true]) {
    test(`bad body ${JSON.stringify(body)} failClosed=${failClosed} is degraded, never throws`, async () => {
      stub.reply(body);
      const v = await sb.admit("hi", { endpoint: stub.url, failClosed });
      assert.equal(v.degraded, sb.Degraded.BAD_RESPONSE);
      assert.equal(v.allowed, !failClosed);
      assert.equal(v.decision, failClosed ? "deny" : "allow");
    });
  }
}

test("null fields are tolerated", async () => {
  stub.reply({ allowed: true, decision: null, latency_ms: null, judge_used: null, reason: null, severity: 3, verdict_id: 991 });
  const v = await sb.admit("hi", { endpoint: stub.url });
  assert.equal(v.allowed, true);
  assert.equal(v.decision, "allow");
  assert.equal(v.latencyMs, 0);
  assert.equal(v.judgeUsed, false);
  assert.equal(v.severity, "");
  assert.equal(v.verdictId, "991");
});

for (const status of [403, 404]) {
  test(`HTTP ${status} is admission-unavailable`, async () => {
    stub.reply("admission not enabled", status);
    let v = await sb.admit("hi", { endpoint: stub.url });
    assert.equal(v.degraded, sb.Degraded.UNAVAILABLE);
    assert.equal(v.httpStatus, status);
    assert.equal(v.allowed, true);
    v = await sb.admit("hi", { endpoint: stub.url, failClosed: true });
    assert.equal(v.allowed, false);
  });
}

for (const status of [400, 401, 500, 503]) {
  test(`HTTP ${status} is client-http-error`, async () => {
    stub.reply("oops", status);
    const v = await sb.admit("hi", { endpoint: stub.url });
    assert.equal(v.degraded, sb.Degraded.HTTP_ERROR);
    assert.equal(v.httpStatus, status);
  });
}

test("transport error", async () => {
  const url = await deadUrl();
  let v = await sb.admit("hi", { endpoint: url });
  assert.equal(v.degraded, sb.Degraded.TRANSPORT);
  assert.equal(v.allowed, true);
  assert.ok(v.error);
  process.env.SUPERBASED_ADMISSION_FAIL_CLOSED = "1";
  v = await sb.admit("hi", { endpoint: url });
  assert.equal(v.allowed, false);
  assert.equal((await sb.admit("hi", { endpoint: url, failClosed: false })).allowed, true);
});

test("timeout", async () => {
  stub.delayMs = 800;
  const t = Date.now();
  const v = await sb.admit("hi", { endpoint: stub.url, timeoutMs: 150 });
  assert.ok(Date.now() - t < 700);
  assert.equal(v.degraded, sb.Degraded.TIMEOUT);
  assert.equal(v.allowed, true);
});

test("org endpoint and credential", async () => {
  await sb.admit("hi", { orgUrl: stub.url + "/", apiKey: "sk-1" });
  let r = stub.requests.at(-1);
  assert.equal(r.path, "/v1/sdk/admit");
  assert.equal(r.headers.authorization, "Bearer sk-1");
  process.env.SUPERBASED_ORG_URL = stub.url;
  process.env.SUPERBASED_API_KEY = "sk-env";
  await sb.admit("hi", { headers: { "X-Extra": "1" } });
  r = stub.requests.at(-1);
  assert.equal(r.path, "/v1/sdk/admit");
  assert.equal(r.headers.authorization, "Bearer sk-env");
  assert.equal(r.headers["x-extra"], "1");
  process.env.SUPERBASED_ADMISSION_ENDPOINT = stub.url + "/node";
  await sb.admit("hi");
  assert.equal(stub.requests.at(-1).path, "/node");
});

test("server-advertised timeout (body) is used for later calls", async () => {
  stub.reply({ ...GOOD, recommended_timeout_ms: 200 });
  await sb.admit("hi", { endpoint: stub.url });
  stub.delayMs = 800;
  const t = Date.now();
  const v = await sb.admit("hi", { endpoint: stub.url });
  assert.equal(v.degraded, sb.Degraded.TIMEOUT);
  assert.ok(Date.now() - t < 700);
});

test("server-advertised timeout (header), garbage ignored", async () => {
  stub.reply(GOOD, 200, { "X-Superbased-Admit-Timeout-Ms": "nonsense" });
  await sb.admit("hi", { endpoint: stub.url });
  stub.reply(GOOD, 200, { "X-Superbased-Admit-Timeout-Ms": "200" });
  await sb.admit("hi", { endpoint: stub.url });
  stub.delayMs = 800;
  assert.equal((await sb.admit("hi", { endpoint: stub.url })).degraded, sb.Degraded.TIMEOUT);
});

test("canonical timeout names win and the header is case-insensitive", async () => {
  stub.reply({ ...GOOD, recommended_client_timeout_ms: 4000, recommended_timeout_ms: 9000 });
  await sb.admit("hi", { endpoint: stub.url });
  assert.equal(advertisedTimeoutMs(stub.url), 4000);
  stub.reply(GOOD, 200, { "X-SBO-Recommended-Timeout-Ms": "7000" });
  await sb.admit("hi", { endpoint: stub.url + "/h" });
  assert.equal(advertisedTimeoutMs(stub.url + "/h"), 7000);
});

// Contract test (review R-A03): replay a response recorded from the org SDK
// control API (sdk/contract, pinned to the Go code by tests/sdkcontract).
const recordedPath = fileURLToPath(new URL("../../contract/org-admit-response.json", import.meta.url));
test("contract: recorded org admit response teaches the timeout", { skip: !existsSync(recordedPath) }, async () => {
  const rec = JSON.parse(readFileSync(recordedPath, "utf8"));
  const wantMs = rec.body.recommended_client_timeout_ms;
  stub.reply(rec.body, rec.status);
  const v = await sb.admit("hi", { endpoint: stub.url });
  assert.equal(v.allowed, false);
  assert.equal(v.verdictId, rec.body.verdict_id);
  assert.equal(advertisedTimeoutMs(stub.url), wantMs);
  const { recommended_client_timeout_ms: _drop, ...bodyOnly } = rec.body;
  const headers = Object.fromEntries(
    Object.entries(rec.headers).filter(([k]) => !["content-type", "content-length"].includes(k.toLowerCase())),
  );
  stub.reply(bodyOnly, rec.status, headers);
  await sb.admit("hi", { endpoint: stub.url + "/hdr" });
  assert.equal(advertisedTimeoutMs(stub.url + "/hdr"), Number(rec.headers["X-Sbo-Recommended-Timeout-Ms"]));
});

test("non-string message never throws", async () => {
  assert.equal((await sb.admit(undefined, { endpoint: stub.url })).decision, "deny");
  assert.equal((await sb.admit({ toString() { throw new Error("x"); } }, { endpoint: stub.url })).degraded,
    sb.Degraded.BAD_RESPONSE);
});

test("C1: the service name goes to the machine and to the org (service budget caps bind on it)", async () => {
  process.env.OTEL_SERVICE_NAME = "from-env";
  await sb.admit("hi", { endpoint: stub.url + "/check" }); // no init(): the configured name
  assert.equal(stub.requests.at(-1).body.service, "from-env");

  sb.init({ exporter: new InMemorySpanExporter(), serviceName: "checkout" });
  await sb.admit("hi", { endpoint: stub.url + "/check" });
  assert.equal(stub.requests.at(-1).body.service, "checkout");
  await sb.admit("hi", { orgUrl: stub.url, apiKey: "sk-1" });
  const r = stub.requests.at(-1);
  assert.equal(r.path, "/v1/sdk/admit");
  assert.equal(r.body.service, "checkout");
});

test("C1: attached to the app's own provider, the service is that resource's", async () => {
  // OTel JS 2.x: the app hands the SDK's processor to its own provider.
  const host = new NodeTracerProvider({ resource: resourceFromAttributes({ "service.name": "host-svc" }), spanProcessors: [sb.spanProcessor()] });
  trace.setGlobalTracerProvider(host);
  sb.init({ exporter: new InMemorySpanExporter(), serviceName: "not-on-the-spans" });
  assert.equal(sb.diagnostics().mode, "attached");
  await sb.withSpan("front-door", sb.Kind.GUARDRAIL, async () => {
    await sb.admit("hi", { endpoint: stub.url + "/check" });
  });
  assert.equal(stub.requests.at(-1).body.service, "host-svc");
});

test("verdict stamped on the active span; trace id sent", async () => {
  const mem = new InMemorySpanExporter();
  sb.init({ exporter: mem });
  stub.reply({ ...GOOD, verdict_id: "v-7" });
  let tid;
  await sb.withSpan("front-door", sb.Kind.GUARDRAIL, async (span) => {
    tid = span.spanContext().traceId;
    await sb.admit("hi", { endpoint: stub.url });
  });
  assert.equal(stub.requests.at(-1).body.trace_id, tid);
  await sb.flush(5000);
  const a = mem.getFinishedSpans()[0].attributes;
  assert.equal(a["sbo.admission.decision"], "deny");
  assert.equal(a["sbo.admission.allowed"], false);
  assert.equal(a["sbo.admission.verdict_id"], "v-7");
});

test("parseVerdict rejects non-objects", () => {
  for (const b of [[], "x", null, 1, { allowed: "true" }]) assert.equal(sb.parseVerdict(b), null);
  assert.equal(sb.parseVerdict({ allowed: true }).decision, "allow");
});

test("admit fails open but says so: one warning per cause per minute, a counter, the fix (E-39)", async () => {
  const stub = await startStub();
  const dead = await deadUrl();
  const warn = console.warn;
  const lines = [];
  console.warn = (m) => lines.push(String(m));
  try {
    stub.reply({ error: "not found" }, 404);
    const v1 = await sb.admit("hi", { endpoint: `${stub.url}/check` });
    const v2 = await sb.admit("again", { endpoint: `${stub.url}/check` });
    assert.equal(v1.allowed && v2.allowed, true, "fail open is the contract");
    assert.equal(v1.degraded, "admission-unavailable");
    const admitLines = () => lines.filter((l) => l.includes("admit()"));
    assert.equal(admitLines().length, 1, "one warning per cause per minute");
    assert.match(admitLines()[0], /HTTP 404.*admitted \(fail open\)\. Fix: /);
    stub.reply({}, 401);
    await sb.admit("hi", { endpoint: `${stub.url}/check`, apiKey: "ik_secret.s" });
    await sb.admit("hi", { endpoint: `${dead}/check`, timeoutMs: 500 });
    assert.equal(admitLines().length, 3, "each cause warns once");
    assert.match(admitLines()[1], /HTTP 401.*SDK key was refused/);
    assert.match(admitLines()[2], /client-transport/);
    assert.ok(!lines.join("\n").includes("ik_secret"), "the key is never logged");
    const d = sb.diagnostics();
    assert.equal(d.admissionDegraded, 4);
    assert.match(d.admissionLastError, /client-transport/);
    stub.reply({ allowed: true, decision: "allow" });
    assert.equal((await sb.admit("ok", { endpoint: `${stub.url}/check` })).degraded, "");
    assert.equal(sb.diagnostics().admissionDegraded, 4, "a clean decision is not counted");
  } finally {
    console.warn = warn;
    await stub.close();
  }
});
