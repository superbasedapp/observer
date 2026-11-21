// sdk/contract/sdk-behaviour-cases.json: the behaviours both SDKs share
// (review R-B19, R-C34). Python runs the same file in
// sdk/python/tests/test_behaviour_cases.py. Each section maps the
// SDK-neutral (snake_case) case onto the TypeScript API.
import { test, beforeEach, after } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { trace } from "@opentelemetry/api";
import { InMemorySpanExporter } from "@opentelemetry/sdk-trace-base";

import * as sb from "../dist/esm/index.js";
import { targets } from "../dist/esm/control.js";
import { resolveSampling } from "../dist/esm/config.js";
import { literalRows } from "../dist/esm/experiments.js";
import { parsePrompt } from "../dist/esm/prompts.js";
import { deadUrl, reset, startStub } from "./helpers.mjs";

const contractDir = process.env.SUPERBASED_CONTRACT_DIR || join(dirname(fileURLToPath(import.meta.url)), "..", "..", "contract");
const FILE = join(contractDir, "sdk-behaviour-cases.json");
const CASES = existsSync(FILE) ? JSON.parse(readFileSync(FILE, "utf8")) : null;
const skip = !CASES && "sdk/contract is not present";
const section = (name) => (CASES ? CASES[name].cases : []);

// The option names the case file spells in snake_case.
const CAMEL = { org_url: "orgUrl", api_key: "apiKey", session_id: "sessionId", node_url: "nodeUrl" };
const camel = (o = {}) => Object.fromEntries(Object.entries(o).map(([k, v]) => [CAMEL[k] ?? k, v]));

beforeEach(reset);
after(reset);

test("every section of the case file has a runner here", { skip }, () => {
  const runners = [
    "compile_values", "score_target", "score_ok", "destination", "control_targets",
    "admit_identity", "admit_credential", "admit_redirect", "local_export_credential", "experiment_pass_rate",
    "literal_item_ids", "sampling_env", "pending_per_destination", "admit_degraded",
    "control_before_discovery", "experiment_snapshot_version", "llm_span_prompt",
    "experiment_create_id", "local_receiver_discovery", "vendor_self_tracing",
    "set_usage_net_input",
    // lane D3 (ruling D29)
    "admit_org_off", "experiment_strict_gate", "get_dataset_missing",
  ];
  assert.deepEqual(Object.keys(CASES).filter((k) => !k.startsWith("_")).sort(), [...runners].sort());
});

test("compile_values", { skip }, () => {
  const sec = CASES.compile_values;
  for (const c of sec.cases) assert.equal(sb.compilePrompt(sec.prompt, { v: c.value }), c.want, JSON.stringify(c.value));
});

test("score_target", { skip }, async () => {
  for (const c of section("score_target")) {
    await reset();
    const stub = await startStub();
    try {
      stub.reply({ accepted: [{ index: 0, id: "sc_1" }], rejected: [] });
      sb.init({ exporter: new InMemorySpanExporter(), nodeUrl: stub.url, destination: "local", discover: false });
      const call = async () => {
        const args = { ...c.args };
        if (args.span_id === "current") {
          delete args.span_id;
          args.spanId = sb.getCurrentSpanId();
        }
        return [await sb.score("accuracy", 1.0, args), sb.getCurrentTraceId(), sb.getCurrentSpanId()];
      };
      const [res, tid, sid] = c.in_span ? await sb.withSpan("req", call) : await call();
      if (c.want.error) {
        assert.equal(res.ok, false);
        assert.ok(res.errors.some((e) => e.includes(c.want.error)), res.errors.join("; "));
        continue;
      }
      const body = stub.requests.at(-1).body;
      assert.equal(body.trace_id, tid);
      assert.equal(body.span_id ?? "", c.want.span_id === "current" ? sid : "");
    } finally {
      await stub.close();
    }
  }
});

test("score_ok", { skip }, async () => {
  const TID = "4bf92f3577b34da6a3ce929d0e0e4736";
  for (const c of section("score_ok")) {
    await reset();
    const stubs = {};
    try {
      for (const [name, ok] of Object.entries(c.destinations)) {
        stubs[name] = await startStub();
        stubs[name].reply(ok ? { accepted: [{ index: 0, id: "sc_1" }], rejected: [] } : { accepted: [], rejected: [{ index: 0, error: "invalid", message: "no" }] });
      }
      const names = Object.keys(c.destinations);
      const destination = names.length === 2 ? "both" : names[0] ?? "online";
      sb.init({
        exporter: new InMemorySpanExporter(),
        discover: false,
        destination,
        nodeUrl: stubs.local?.url ?? (await deadUrl()),
        ...(stubs.online ? { orgUrl: stubs.online.url, apiKey: "ik_1.s" } : {}),
      });
      const res = await sb.score("accuracy", 1, { traceId: TID });
      assert.equal(res.ok, c.want, JSON.stringify(c));
    } finally {
      for (const s of Object.values(stubs)) await s.close();
    }
  }
});

test("destination", { skip }, async () => {
  for (const c of section("destination")) {
    await reset();
    const machine = await startStub();
    try {
      for (const [k, v] of Object.entries(c.env ?? {})) process.env[k] = v;
      const opts = { exporter: undefined, ...camel(c.args) };
      if (c.machine) {
        machine.handler = (r) =>
          r.path === sb.DISCOVERY_PATH
            ? { body: { api_version: 1, destination: c.machine.destination, source: "config", configured: "", signed_in: false, local: { enabled: true }, online: {}, warnings: [] } }
            : undefined;
        opts.nodeUrl = machine.url;
      } else if (!("SUPERBASED_MACHINE_URL" in (c.env ?? {}))) {
        opts.nodeUrl = await deadUrl(); // nothing answers
      } else {
        opts.discover = false; // never ask a real machine on this host
      }
      sb.init(opts);
      await sb.ready();
      const d = sb.diagnostics();
      assert.deepEqual([d.destination, d.destinationSource], [c.want.destination, c.want.source], JSON.stringify(c));
      if (c.want.node_url) {
        assert.equal(sb.settings().nodeUrl, c.want.node_url); // SUPERBASED_MACHINE_URL is not read
      }
    } finally {
      await sb.shutdown(500);
      await machine.close();
    }
  }
});

test("local_receiver_discovery", { skip }, async () => {
  // Live finding L-01: a set destination still asks the machine for its receiver.
  const sec = CASES?.local_receiver_discovery;
  for (const c of section("local_receiver_discovery")) {
    await reset();
    const machine = await startStub();
    try {
      machine.handler = (r) =>
        r.path === sb.DISCOVERY_PATH
          ? { body: { api_version: 1, destination: "local", source: "config", configured: "", signed_in: false, local: { enabled: true, otlp_traces_url: sec.machine_receiver }, online: {}, warnings: [] } }
          : undefined;
      const opts = { destination: c.destination, nodeUrl: machine.url, discover: c.discover, orgUrl: "https://gw.example.com", apiKey: "ik_1.s" };
      let named = c.endpoint ?? "";
      if (c.endpoint_from === "argument") opts.endpoint = named;
      else if (c.endpoint_from === "superbased_env") process.env.SUPERBASED_OTLP_ENDPOINT = named;
      else if (c.endpoint_from === "otel_env") {
        process.env.OTEL_EXPORTER_OTLP_ENDPOINT = named;
        named = named.replace(/\/+$/, "") + "/v1/traces";
      }
      sb.init(opts);
      await sb.ready();
      const local = sb.diagnostics().destinations.filter((d) => d.name === "local").map((d) => d.endpoint);
      const want = { machine: [sec.machine_receiver], named: [named], default: ["http://127.0.0.1:4318/v1/traces"] }[c.want.local] ?? [];
      assert.deepEqual(local, want, JSON.stringify(c));
      const asked = machine.requests.filter((r) => r.path === sb.DISCOVERY_PATH).length > 0;
      assert.equal(asked, c.want.asked, JSON.stringify(c));
    } finally {
      await sb.shutdown(500);
      await machine.close();
    }
  }
});

test("control_targets", { skip }, async () => {
  for (const c of section("control_targets")) {
    await reset();
    process.env.SUPERBASED_DISCOVER = "0";
    process.env.SUPERBASED_DESTINATION = c.destination;
    if (c.online_ready) {
      process.env.SUPERBASED_ORG_URL = "https://gw.example.com";
      process.env.SUPERBASED_API_KEY = "ik_1.s";
    }
    sb.init({ exporter: new InMemorySpanExporter() });
    assert.deepEqual(targets("write").map((t) => t.name), c.want, JSON.stringify(c));
    assert.deepEqual(targets("read").map((t) => t.name), c.want, JSON.stringify(c));
  }
});

/** Replace fetch for one call: record the request and answer a clean verdict. Nothing is dialled. */
async function captured(fn) {
  const real = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, init) => {
    calls.push({ url: String(url), headers: Object.fromEntries(Object.entries(init.headers).map(([k, v]) => [k.toLowerCase(), v])), body: JSON.parse(init.body) });
    return new Response(JSON.stringify({ allowed: true, decision: "allow" }), { status: 200, headers: { "Content-Type": "application/json" } });
  };
  try {
    await fn();
  } finally {
    globalThis.fetch = real;
  }
  return calls;
}

test("admit_identity", { skip }, async () => {
  for (const c of section("admit_identity")) {
    await reset();
    if (Object.keys(c.init).length) sb.init({ exporter: new InMemorySpanExporter(), destination: "local", discover: false, ...camel(c.init) });
    const call = () => sb.admit("hi", { endpoint: "http://127.0.0.1:9/check", ...c.args });
    const calls = await captured(() => (Object.keys(c.scope).length ? sb.propagateAttributes(camel(c.scope), call) : call()));
    const b = calls.at(-1).body;
    assert.deepEqual({ tenant: b.tenant, user: b.user, session: b.session }, c.want, JSON.stringify(c));
  }
});

const HOSTS = { loopback: "http://127.0.0.1:9", remote: "https://admit.example.com" };

test("admit_credential", { skip }, async () => {
  for (const c of section("admit_credential")) {
    await reset();
    const host = HOSTS[c.host];
    const opts = {};
    if (c.key === "argument") opts.apiKey = "ik_arg";
    else if (c.key === "init") sb.init({ exporter: new InMemorySpanExporter(), destination: "local", discover: false, apiKey: "ik_init" });
    else process.env.SUPERBASED_API_KEY = "ik_env";
    if (c.via === "endpoint") opts.endpoint = host + "/check";
    else if (c.via === "env_endpoint") process.env.SUPERBASED_ADMISSION_ENDPOINT = host + "/check";
    else if (c.via === "org_url") opts.orgUrl = host;
    else if (c.via === "env_org_url") process.env.SUPERBASED_ORG_URL = host;
    const calls = await captured(() => sb.admit("hi", opts));
    assert.equal("authorization" in calls.at(-1).headers, c.want_key, JSON.stringify(c));
  }
});

test("admit_redirect", { skip }, async () => {
  for (const c of section("admit_redirect")) {
    await reset();
    const stub = await startStub();
    const other = await startStub();
    try {
      stub.reply({}, c.status, { Location: other.url + "/stolen" });
      const v = await sb.admit("hi", { endpoint: stub.url + "/check", apiKey: "ik_1.s" });
      assert.equal(stub.requests.length, c.want.requests);
      assert.equal(other.requests.length, 0);
      assert.deepEqual([v.degraded, v.httpStatus], [c.want.degraded, c.want.http_status]);
    } finally {
      await stub.close();
      await other.close();
    }
  }
});

test("local_export_credential", { skip }, () => {
  for (const c of section("local_export_credential")) {
    const env = { SUPERBASED_API_KEY: "ik_1.s", SUPERBASED_DESTINATION: "local" };
    const opts = {};
    if (c.endpoint_from === "argument") opts.endpoint = c.endpoint;
    else if (c.endpoint_from === "superbased_env") env.SUPERBASED_OTLP_ENDPOINT = c.endpoint;
    else if (c.endpoint_from === "otel_env") env.OTEL_EXPORTER_OTLP_ENDPOINT = c.endpoint;
    const [local] = sb.destinations(sb.resolveSettings(env, opts), "local");
    assert.equal(Object.keys(local.headers).some((h) => h.toLowerCase() === "authorization"), c.want_key, JSON.stringify(c));
  }
});

test("experiment_pass_rate", { skip }, () => {
  for (const c of section("experiment_pass_rate")) {
    const items = c.items.map((it, n) => ({
      item: { id: `it_${n}`, input: "x" },
      traceId: "",
      output: undefined,
      error: it.error ?? "",
      scores: [
        ...it.scores,
        ...Array.from({ length: it.evaluator_errors ?? 0 }, () => ({ name: "threw", value: "", error: "boom" })),
      ],
      postError: "",
    }));
    const t = sb.experimentTotals(items, c.sides, c.fail_under ?? undefined);
    const msg = JSON.stringify(c);
    assert.equal(t.scored, c.want.scored, msg);
    if (c.want.pass_rate === null) assert.ok(Number.isNaN(t.passRate), msg);
    else assert.ok(Math.abs(t.passRate - c.want.pass_rate) < 1e-9, msg);
    assert.equal(t.gateFailed, c.want.gate_failed, msg);
  }
});

// --- lane E4 sections (end-to-end review E-31, E-33, E-38, E-39, E-49, E-75) ---

test("literal_item_ids", { skip }, () => {
  for (const c of section("literal_item_ids")) {
    assert.deepEqual(literalRows(c.items.map((it) => ({ ...it }))).map((r) => r.id), c.want, JSON.stringify(c.items));
  }
});

test("sampling_env", { skip }, () => {
  for (const c of section("sampling_env")) {
    if (c.want.error) {
      assert.throws(() => resolveSampling(c.explicit, c.env), RangeError);
      continue;
    }
    const got = resolveSampling(c.explicit, c.env);
    assert.deepEqual([got.rate, got.parentBased], [c.want.rate, c.want.parent_based], JSON.stringify(c));
    const named = ["SUPERBASED_SAMPLE_RATE", "OTEL_TRACES_SAMPLER_ARG"].filter((v) => got.invalid.includes(`${v}=`));
    assert.deepEqual(named, c.want.ignored, got.invalid);
  }
});

test("pending_per_destination", { skip }, async () => {
  for (const c of section("pending_per_destination")) {
    await reset();
    const local = await startStub();
    const online = await startStub();
    try {
      for (const [name, st] of [["local", local], ["online", online]]) st.delayMs = c.held.includes(name) ? 1000 : 0;
      const opts = { destination: c.destination, discover: false, endpoint: `${local.url}/v1/traces`, shutdownTimeoutMs: 5000 };
      if (c.destination === "both") Object.assign(opts, { orgUrl: online.url, apiKey: "ik_1.s" });
      sb.init(opts);
      sb.withSpan("x", () => {});
      const done = sb.flush(5000);
      const legs = c.destination === "both" ? 2 : 1;
      const answered = legs - c.held.length;
      for (let i = 0; i < 150 && sb.diagnostics().exportedSpans < answered; i++) await new Promise((r) => setTimeout(r, 20));
      if (c.held.length) assert.equal(sb.diagnostics().pendingSpans, c.want_pending, JSON.stringify(c));
      await done;
      assert.equal(sb.diagnostics().pendingSpans, 0, JSON.stringify(c));
      if (!c.held.length) assert.equal(c.want_pending, 0);
    } finally {
      await sb.shutdown(2000);
      await local.close();
      await online.close();
    }
  }
});

test("admit_degraded", { skip }, async () => {
  for (const c of section("admit_degraded")) {
    await reset();
    const stub = await startStub();
    const warn = console.warn;
    const lines = [];
    console.warn = (m) => lines.push(String(m));
    try {
      let url = `${stub.url}${c.path ?? "/check"}`;
      if (c.status === "transport") url = `${await deadUrl()}/check`;
      else stub.reply(c.status === 200 ? { allowed: true, decision: "allow" } : {}, c.status);
      const vs = [];
      for (let i = 0; i < 2; i++) vs.push(await sb.admit("hi", { endpoint: url, timeoutMs: 1000, failClosed: c.fail_closed ?? false }));
      for (const v of vs) assert.deepEqual([v.allowed, v.degraded], [c.want.allowed, c.want.degraded], JSON.stringify(c));
      const admitLines = lines.filter((l) => l.includes("admit()"));
      assert.equal(admitLines.length, c.want.warnings, JSON.stringify([c, admitLines]));
      assert.ok(admitLines.every((l) => l.includes("Fix:") && l.includes(c.want.fix ?? "")), admitLines.join("\n"));
      assert.equal(sb.diagnostics().admissionDegraded, c.want.counted);
    } finally {
      console.warn = warn;
      await stub.close();
    }
  }
});

test("control_before_discovery", { skip }, async () => {
  for (const c of section("control_before_discovery")) {
    await reset();
    const machine = await startStub();
    const gateway = await startStub();
    try {
      const accepted = { body: { accepted: [{ index: 0, id: "sc_1" }], rejected: [] } };
      machine.delayMs = c.delay_ms;
      machine.handler = (r) =>
        r.path === sb.DISCOVERY_PATH
          ? { body: { api_version: 1, destination: c.discovery, source: "config", configured: "", signed_in: true, local: { enabled: true }, online: {}, warnings: [] } }
          : accepted;
      gateway.handler = () => accepted;
      // No caller exporter: with one, TypeScript skips discovery (lane E4 notes).
      // The gateway is named by the app (review E-04: never by discovery).
      sb.init({ nodeUrl: machine.url, apiKey: "ik_1.s", orgUrl: gateway.url });
      const res = await sb.withSpan("req", () => sb.score("accuracy", 1));
      assert.equal(res.ok, true, JSON.stringify(res));
      assert.deepEqual(Object.keys(res.destinations), [c.want], JSON.stringify(c));
    } finally {
      await sb.shutdown(1000);
      await machine.close();
      await gateway.close();
    }
  }
});

test("experiment_snapshot_version", { skip }, async () => {
  for (const c of section("experiment_snapshot_version")) {
    await reset();
    const stub = await startStub();
    try {
      const created = [];
      stub.handler = (r) => {
        const path = r.path.split("?")[0];
        if (path === "/api/obs/eval/datasets") return { body: { datasets: [{ id: "7", name: "golden" }] } };
        if (path === "/api/obs/eval/experiments" && r.method === "POST") {
          created.push(r.body);
          return { status: 201, body: { id: "1", snapshot_version: r.body.snapshot_version } };
        }
        if (path === "/api/obs/eval/datasets/7/items") return { body: { items: [], next_cursor: "" } };
        return { body: {} };
      };
      sb.init({ exporter: new InMemorySpanExporter(), nodeUrl: stub.url, destination: "local", discover: false });
      const opts = { dataset: "golden", task: (x) => x };
      if (c.snapshot_version !== null) opts.snapshotVersion = c.snapshot_version;
      await sb.runExperiment(opts);
      assert.equal(created[0].snapshot_version, c.want);
    } finally {
      await stub.close();
    }
  }
});

test("experiment_create_id", { skip }, async () => {
  for (const c of section("experiment_create_id")) {
    await reset();
    const stub = await startStub();
    try {
      const created = [];
      stub.handler = (r) => {
        const path = r.path.split("?")[0];
        if (path === "/api/obs/eval/datasets") return { body: { datasets: [{ id: "7", name: "golden" }] } };
        if (path === "/api/obs/eval/experiments" && r.method === "POST") {
          created.push(r.body);
          if (created.length === 1 && c.first_status !== 201) return { status: c.first_status, body: { error: "x", message: "x" } };
          return { status: 201, body: { id: "1", snapshot_version: 1 } };
        }
        if (path === "/api/obs/eval/datasets/7/items") return { body: { items: [], next_cursor: "" } };
        return { body: {} };
      };
      sb.init({ exporter: new InMemorySpanExporter(), nodeUrl: stub.url, destination: "local", discover: false });
      const run = () => sb.runExperiment({ dataset: "golden", task: (x) => x });
      if (c.first_status === 201 || c.first_status === 429 || c.first_status >= 500) await run();
      else await assert.rejects(run(), sb.ExperimentError);
      assert.equal(created.length, c.want_creates, JSON.stringify(c));
      const ids = new Set(created.map((b) => b.id));
      assert.equal(ids.size, 1);
      const [id] = ids;
      assert.match(id, /^[A-Za-z0-9_.:-]{1,128}$/);
      if (c.first_status === 201) {
        await run();
        assert.notEqual(created.at(-1).id, id);
      }
    } finally {
      await stub.close();
    }
  }
});

test("llm_span_prompt", { skip }, async () => {
  for (const c of section("llm_span_prompt")) {
    await reset();
    const body = JSON.parse(readFileSync(join(contractDir, c.fixture), "utf8")).body;
    const prompt = parsePrompt(body, "", "online");
    const mem = new InMemorySpanExporter();
    sb.init({ exporter: mem, destination: "local", discover: false });
    sb.withLlmSpan("chat", { prompt }, () => {});
    await sb.flush(2000);
    const attrs = mem.getFinishedSpans().at(-1).attributes;
    assert.deepEqual([attrs["sbo.prompt.name"], attrs["sbo.prompt.version"]], [c.want.name, c.want.version]);
    assert.equal("input.value" in attrs || "gen_ai.input.messages" in attrs, c.want.content);
  }
});

test("vendor_self_tracing", { skip }, async () => {
  for (const c of section("vendor_self_tracing")) {
    await reset();
    Object.assign(process.env, c.env);
    const mem = new InMemorySpanExporter();
    sb.init({ exporter: mem, destination: "local", discover: false });
    const d = sb.diagnostics();
    assert.deepEqual(d.vendorTracing, c.want.status);
    for (const [k, v] of Object.entries(c.want.env_after)) assert.equal(process.env[k], v);
    const provider = trace.getTracerProvider();
    for (const scope of Object.keys(c.want.exported)) provider.getTracer(scope).startSpan(`call ${scope}`).end();
    await sb.flush(2000);
    const got = new Set(mem.getFinishedSpans().map((s) => s.instrumentationScope.name));
    const exported = Object.fromEntries(Object.keys(c.want.exported).map((scope) => [scope, got.has(scope)]));
    assert.deepEqual(exported, c.want.exported);
    const dropped = Object.values(c.want.exported).filter((v) => !v).length;
    assert.equal(sb.diagnostics().vendorSpansDropped, dropped);
  }
});

test("set_usage_net_input", { skip }, async () => {
  const camelUsage = { input_tokens: "inputTokens", output_tokens: "outputTokens", cache_read_tokens: "cacheReadTokens", cache_write_tokens: "cacheWriteTokens" };
  for (const c of section("set_usage_net_input")) {
    await reset();
    const mem = new InMemorySpanExporter();
    sb.init({ exporter: mem, destination: "local", discover: false });
    const before = sb.diagnostics().usageNetInputCorrected;
    const usage = Object.fromEntries(Object.entries(c.usage).map(([k, v]) => [camelUsage[k], v]));
    sb.withLlmSpan("chat", {}, (span) => sb.setUsage(span, usage));
    await sb.flush(2000);
    const attrs = mem.getFinishedSpans().at(-1).attributes;
    assert.equal(attrs["gen_ai.usage.input_tokens"] ?? null, c.want.input_tokens);
    assert.equal(sb.diagnostics().usageNetInputCorrected - before, c.want.corrected);
  }
});

// --- lane D3 sections (ruling D29: L-05, E-12) -------------------------------

test("admit_org_off", { skip }, async () => {
  for (const c of section("admit_org_off")) {
    await reset();
    const machine = await startStub();
    const gateway = await startStub();
    const warn = console.warn;
    console.warn = () => {};
    try {
      gateway.handler = (r) => (r.path === "/v1/sdk/admit" ? { body: c.org } : undefined);
      let nodeUrl = await deadUrl();
      if (c.machine !== "transport") {
        machine.handler = (r) => (r.path === "/api/obs/admission/check" ? { body: c.machine } : undefined);
        nodeUrl = machine.url;
      }
      sb.init({ destination: c.destination, nodeUrl, orgUrl: gateway.url, apiKey: "ik_1.s", discover: false, exporter: new InMemorySpanExporter() });
      const opts = { timeoutMs: 1000, failClosed: c.fail_closed ?? false, ...(c.via === "org_url" ? { orgUrl: gateway.url } : {}) };
      const v = await sb.admit("hi", opts);
      const label = JSON.stringify(c);
      assert.deepEqual([v.allowed, v.decision, v.degraded], [c.want.allowed, c.want.decision, c.want.degraded], label);
      const asked = machine.requests.filter((r) => r.path === "/api/obs/admission/check");
      assert.equal(asked.length > 0, c.want.asked_machine, label);
      assert.ok(asked.every((r) => r.headers.authorization === undefined), label);
      assert.equal(sb.diagnostics().admissionDegraded, c.want.counted, label);
    } finally {
      console.warn = warn;
      await sb.shutdown(500);
      await machine.close();
      await gateway.close();
    }
  }
});

test("experiment_strict_gate", { skip }, () => {
  for (const c of section("experiment_strict_gate")) {
    const items = c.items.map((it, n) => ({
      item: { id: `it_${n}`, input: "x" },
      traceId: "",
      output: undefined,
      error: it.error ?? "",
      scores: [...it.scores, ...Array.from({ length: it.evaluator_errors ?? 0 }, () => ({ name: "threw", value: "", error: "boom" }))],
      postError: "",
    }));
    const t = sb.experimentTotals(items, []);
    const g = sb.experimentGate(
      { scored: t.scored, passRate: t.passRate, skippedSides: c.skipped_sides, failedPosts: c.failed_posts },
      c.fail_under ?? undefined,
      c.strict ?? true,
    );
    const msg = JSON.stringify(c);
    assert.equal(g.reasons.length, c.want.reasons, msg);
    assert.equal(g.failed, c.want.gate_failed, msg);
  }
});

test("get_dataset_missing", { skip }, async () => {
  for (const c of section("get_dataset_missing")) {
    await reset();
    const stub = await startStub();
    const warn = console.warn;
    console.warn = () => {};
    try {
      if (c.datasets === "no_destination") {
        delete process.env.SUPERBASED_API_KEY;
        delete process.env.SUPERBASED_ORG_URL;
        sb.init({ destination: "online", discover: false, exporter: new InMemorySpanExporter() });
      } else {
        const listed = c.datasets.map((name, n) => ({ id: String(n + 7), name, item_count: 0, latest_snapshot: 1 }));
        stub.handler = (r) => (r.method === "GET" && r.path.split("?")[0] === "/api/obs/eval/datasets" ? { body: { api_version: "v1", datasets: listed } } : { body: { items: [], next_cursor: "" } });
        sb.init({ destination: "local", nodeUrl: stub.url, discover: false, exporter: new InMemorySpanExporter() });
      }
      const label = JSON.stringify(c);
      if (c.want.found) assert.equal((await sb.getDataset(c.name)).name, c.name, label);
      else await assert.rejects(sb.getDataset(c.name), (e) => e instanceof sb.ExperimentError, label);
    } finally {
      console.warn = warn;
      await sb.shutdown(500);
      await stub.close();
    }
  }
});
