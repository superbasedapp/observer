// SDK tests: init / attach / re-init, spans, observe, content, flush and
// shutdown against unreachable and failing endpoints, settings, exit hook.
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

import { SpanStatusCode, trace } from "@opentelemetry/api";
import { BasicTracerProvider, InMemorySpanExporter, SimpleSpanProcessor } from "@opentelemetry/sdk-trace-base";
import { NodeTracerProvider } from "@opentelemetry/sdk-trace-node";

import * as sb from "../dist/esm/index.js";
import { byName, deadUrl, reset, startStub } from "./helpers.mjs";

beforeEach(reset);

async function exported(mem) {
  assert.equal(await sb.flush(5000), true);
  return byName(mem.getFinishedSpans());
}

// --- init -------------------------------------------------------------------

test("init registers its own provider with the resource identity", async () => {
  const mem = new InMemorySpanExporter();
  sb.init({ exporter: mem, tenant: "t1", user: "u1", sessionId: "s1", serviceName: "svc" });
  sb.withSpan("root", sb.Kind.CHAIN, () => {});
  const sp = (await exported(mem)).root;
  const res = sp.resource.attributes;
  assert.equal(res["service.name"], "svc");
  assert.equal(res["sbo.tenant"], "t1");
  assert.equal(res["sbo.user"], "u1");
  assert.equal(res["session.id"], "s1");
  assert.equal(res["sbo.sdk"], "superbased-typescript");
  assert.equal(sb.diagnostics().mode, "owned");
  assert.equal(sp.attributes["session.id"], undefined, "identity on the resource is not stamped again");
});

test("double init with the same settings is a no-op", async () => {
  const mem = new InMemorySpanExporter();
  sb.init({ exporter: mem });
  sb.init({ exporter: mem });
  sb.withSpan("once", sb.Kind.CHAIN, () => {});
  await sb.flush(5000);
  assert.deepEqual(mem.getFinishedSpans().map((s) => s.name), ["once"]);
});

test("re-init with new settings swaps the exporter and shuts the old one down", async () => {
  const first = new InMemorySpanExporter();
  sb.init({ exporter: first });
  const second = new InMemorySpanExporter();
  sb.init({ exporter: second, sessionId: "s2" });
  sb.withSpan("after", sb.Kind.CHAIN, () => {});
  const got = await exported(second);
  assert.ok(got.after);
  assert.equal(got.after.attributes["session.id"], "s2", "new identity not on the resource is stamped");
  assert.equal(first.getFinishedSpans().length, 0);
  assert.equal(sb.diagnostics().mode, "owned");
});

test("attaches to an OTel 2.x host provider built with spanProcessor()", async () => {
  const hostMem = new InMemorySpanExporter();
  const host = new NodeTracerProvider({ spanProcessors: [sb.spanProcessor(), new SimpleSpanProcessor(hostMem)] });
  host.register();
  const mem = new InMemorySpanExporter();
  sb.init({ exporter: mem, user: "alice" });
  assert.equal(sb.diagnostics().mode, "attached");
  trace.getTracer("host").startActiveSpan("host-span", (hs) => {
    sb.withSpan("sdk-span", sb.Kind.TOOL, () => {});
    hs.end();
  });
  const got = await exported(mem);
  assert.ok(got["host-span"] && got["sdk-span"], "host and SDK spans both reach the SDK exporter");
  assert.equal(got["sdk-span"].spanContext().traceId, got["host-span"].spanContext().traceId);
  assert.equal(got["sdk-span"].attributes["sbo.user"], "alice");
  assert.equal(hostMem.getFinishedSpans().length, 2);
  assert.equal(await sb.shutdown(5000), true);
  trace.getTracer("host").startActiveSpan("later", (s) => s.end());
  assert.ok(hostMem.getFinishedSpans().some((s) => s.name === "later"), "host provider keeps running");
});

test("attaches to a 1.x-style provider that has addSpanProcessor", async () => {
  const procs = [];
  const mutable = {
    onStart: (s, c) => procs.forEach((p) => p.onStart(s, c)),
    onEnd: (s) => procs.forEach((p) => p.onEnd(s)),
    forceFlush: async () => {},
    shutdown: async () => {},
  };
  class LegacyProvider extends BasicTracerProvider {
    constructor() {
      super({ spanProcessors: [mutable] });
    }
    addSpanProcessor(p) {
      procs.push(p);
    }
  }
  const legacy = new LegacyProvider();
  trace.setGlobalTracerProvider(legacy);
  const mem = new InMemorySpanExporter();
  sb.init({ exporter: mem });
  assert.equal(sb.diagnostics().mode, "attached");
  assert.equal(procs.length, 1);
  sb.withSpan("x", sb.Kind.CHAIN, () => {});
  assert.ok((await exported(mem)).x);
  sb.init({ exporter: new InMemorySpanExporter(), user: "other" });
  assert.equal(procs.length, 1, "re-init never adds a second processor");
});

test("a host provider without our processor: standalone, spans still join the trace", async () => {
  const hostMem = new InMemorySpanExporter();
  const host = new NodeTracerProvider({ spanProcessors: [new SimpleSpanProcessor(hostMem)] });
  host.register();
  const mem = new InMemorySpanExporter();
  sb.init({ exporter: mem });
  assert.equal(sb.diagnostics().mode, "standalone");
  let hostTrace;
  trace.getTracer("host").startActiveSpan("host-span", (hs) => {
    hostTrace = hs.spanContext().traceId;
    sb.withSpan("sdk-span", sb.Kind.CHAIN, () => {});
    hs.end();
  });
  const got = await exported(mem);
  assert.equal(got["sdk-span"].spanContext().traceId, hostTrace);
});

test("explicit tracerProvider option", async () => {
  const p = new BasicTracerProvider({ spanProcessors: [sb.spanProcessor()] });
  const mem = new InMemorySpanExporter();
  sb.init({ exporter: mem, tracerProvider: p });
  sb.withSpan("x", sb.Kind.CHAIN, () => {});
  assert.ok((await exported(mem)).x);
  assert.equal(sb.diagnostics().mode, "attached");
});

test("spans before init are no-ops", async () => {
  assert.equal(sb.withSpan("nothing", sb.Kind.CHAIN, () => 5), 5);
  assert.equal(await sb.flush(), true);
  assert.equal(await sb.shutdown(), true);
});

// --- spans ------------------------------------------------------------------

test("withSpan returns sync values synchronously and promises for async", async () => {
  const mem = new InMemorySpanExporter();
  sb.init({ exporter: mem });
  const v = sb.withSpan("sync", sb.Kind.TOOL, () => 42, { a: 1 });
  assert.equal(v, 42);
  const p = sb.withSpan("async", sb.Kind.CHAIN, async () => {
    await new Promise((r) => setTimeout(r, 30));
    return "ok";
  });
  assert.ok(p instanceof Promise);
  assert.equal(await p, "ok");
  const got = await exported(mem);
  assert.equal(got.sync.attributes["openinference.span.kind"], "TOOL");
  assert.equal(got.sync.attributes.a, 1);
  assert.equal(got.sync.status.code, SpanStatusCode.OK);
  const dur = got.async.duration[0] * 1e3 + got.async.duration[1] / 1e6;
  assert.ok(dur >= 25, `async span covers the awaited work (${dur}ms)`);
});

test("errors: recorded once, ERROR status, rethrown (sync and async)", async () => {
  const mem = new InMemorySpanExporter();
  sb.init({ exporter: mem });
  assert.throws(() => sb.withSpan("boom", sb.Kind.CHAIN, () => { throw new TypeError("bad"); }), TypeError);
  await assert.rejects(sb.withSpan("aboom", sb.Kind.CHAIN, async () => { throw new RangeError("late"); }), RangeError);
  const got = await exported(mem);
  for (const n of ["boom", "aboom"]) {
    assert.equal(got[n].status.code, SpanStatusCode.ERROR);
    assert.equal(got[n].events.filter((e) => e.name === "exception").length, 1);
  }
});

test("a user-set ERROR status is not overwritten with OK", async () => {
  const mem = new InMemorySpanExporter();
  sb.init({ exporter: mem });
  sb.withSpan("handled", sb.Kind.CHAIN, (span) => span.setStatus({ code: SpanStatusCode.ERROR, message: "refused" }));
  await sb.withSpan("ahandled", sb.Kind.CHAIN, async (span) => span.setStatus({ code: SpanStatusCode.ERROR }));
  const got = await exported(mem);
  assert.equal(got.handled.status.code, SpanStatusCode.ERROR);
  assert.equal(got.handled.status.message, "refused");
  assert.equal(got.ahandled.status.code, SpanStatusCode.ERROR);
});

test("observe wraps sync and async functions, keeps this and args", async () => {
  const mem = new InMemorySpanExporter();
  sb.init({ exporter: mem });
  const add = sb.observe(function add(a, b) { return a + b; });
  const obj = { k: 3, get: sb.observe(function () { return this.k; }, { name: "getter", kind: sb.Kind.TOOL }) };
  const slow = sb.observe(async (x) => {
    await new Promise((r) => setTimeout(r, 20));
    return x * 2;
  }, { name: "slow" });
  const fails = sb.observe(async () => { throw new Error("x"); }, { name: "fails" });
  assert.equal(add(1, 2), 3);
  assert.equal(add.name, "add");
  assert.equal(obj.get(), 3);
  assert.equal(await slow(4), 8);
  await assert.rejects(fails());
  const got = await exported(mem);
  assert.ok(got.add);
  assert.equal(got.getter.attributes["openinference.span.kind"], "TOOL");
  assert.equal(got.slow.status.code, SpanStatusCode.OK);
  assert.equal(got.fails.status.code, SpanStatusCode.ERROR);
});

test("withLlmSpan + setUsage emit GenAI and OpenInference keys", async () => {
  const mem = new InMemorySpanExporter();
  sb.init({ exporter: mem });
  sb.withLlmSpan("chat", { model: "gpt-4o", provider: "openai", prompt: "hi" }, (span) =>
    sb.setUsage(span, {
      inputTokens: 12, outputTokens: 3, responseId: "chatcmpl-x", requestId: "r1",
      responseModel: "gpt-4o-2024", costUsd: 0.01, response: "yo",
    }),
  );
  sb.withLlmSpan("emb", { model: "m", operation: "embeddings" }, () => {});
  const got = await exported(mem);
  const a = got.chat.attributes;
  assert.equal(a["openinference.span.kind"], "LLM");
  assert.equal(a["gen_ai.operation.name"], "chat");
  assert.equal(a["gen_ai.provider.name"], "openai");
  assert.equal(a["gen_ai.system"], "openai");
  assert.equal(a["gen_ai.request.model"], "gpt-4o");
  assert.equal(a["llm.model_name"], "gpt-4o");
  assert.equal(a["llm.provider"], "openai");
  assert.equal(a["gen_ai.usage.input_tokens"], 12);
  assert.equal(a["gen_ai.usage.output_tokens"], 3);
  assert.equal(a["gen_ai.response.id"], "chatcmpl-x");
  assert.equal(a["gen_ai.response.model"], "gpt-4o-2024");
  assert.equal(a["request_id"], "r1");
  assert.equal(a["gen_ai.usage.cost"], 0.01);
  assert.equal(a["input.value"], "hi");
  assert.equal(a["output.value"], "yo");
  assert.equal(got.emb.attributes["gen_ai.operation.name"], "embeddings");
});

// --- content ----------------------------------------------------------------

/** Minimal duck-typed Span that records setAttribute calls. */
function fakeSpan() {
  const attrs = {};
  return { attrs, setAttribute(k, v) { attrs[k] = v; } };
}

test("content capture on by default, off switch keeps usage, truncation", () => {
  sb.init({ exporter: new InMemorySpanExporter() });
  let sp = fakeSpan();
  sb.setContent(sp, { toolArgs: "{\"q\":1}", toolResult: "ok" });
  assert.equal(sp.attrs["input.value"], "{\"q\":1}");
  assert.equal(sp.attrs["output.value"], "ok");
  sb.init({ exporter: new InMemorySpanExporter(), captureContent: false });
  sp = fakeSpan();
  sb.setUsage(sp, { inputTokens: 5, prompt: "secret", response: "secret" });
  assert.equal(sp.attrs["gen_ai.usage.input_tokens"], 5);
  assert.equal(sp.attrs["input.value"], undefined);
  sb.init({ exporter: new InMemorySpanExporter(), maxContentChars: 5 });
  sp = fakeSpan();
  sb.setContent(sp, { prompt: "abcdefghij" });
  assert.equal(sp.attrs["input.value"], "abcde…[truncated]");
});

test("capture env: SUPERBASED_CAPTURE_CONTENT, legacy OBSERVER_CAPTURE_CONTENT", () => {
  process.env.SUPERBASED_CAPTURE_CONTENT = "0";
  assert.equal(sb.init({ exporter: new InMemorySpanExporter() }).captureContent, false);
  delete process.env.SUPERBASED_CAPTURE_CONTENT;
  process.env.OBSERVER_CAPTURE_CONTENT = "off";
  assert.equal(sb.init({ exporter: new InMemorySpanExporter() }).captureContent, false);
  process.env.SUPERBASED_CAPTURE_CONTENT = "1";
  assert.equal(sb.init({ exporter: new InMemorySpanExporter() }).captureContent, true);
});

// --- flush / shutdown / diagnostics ------------------------------------------

test("unreachable endpoint: shutdown is bounded, never rejects, failure counted", async () => {
  const url = await deadUrl();
  const warn = console.warn;
  const lines = [];
  console.warn = (...a) => lines.push(a.join(" "));
  try {
    sb.init({ endpoint: url + "/v1/traces", shutdownTimeoutMs: 1000 });
    sb.withSpan("lost", sb.Kind.CHAIN, () => {});
    const t = Date.now();
    await sb.flush();
    const ok = await sb.shutdown();
    assert.ok(Date.now() - t < 3000);
    assert.equal(typeof ok, "boolean");
    const d = sb.diagnostics();
    assert.ok(d.failedExports >= 1, JSON.stringify(d));
    assert.ok(d.droppedSpans >= 1);
    assert.ok(d.lastError.length > 0);
    assert.ok(lines.length <= 1, "at most one summary line");
  } finally {
    console.warn = warn;
  }
});

for (const status of [302, 401, 500]) {
  test(`HTTP ${status} from the collector: shutdown resolves, failure counted`, async () => {
    const stub = await startStub();
    stub.reply("nope", status, status === 302 ? { Location: "http://127.0.0.1:1/" } : {});
    const warn = console.warn;
    console.warn = () => {};
    try {
      sb.init({ endpoint: stub.url + "/v1/traces", shutdownTimeoutMs: 3000, exportTimeoutMs: 1000 });
      sb.withSpan("x", sb.Kind.CHAIN, () => {});
      await sb.flush();
      assert.equal(typeof (await sb.shutdown()), "boolean");
      assert.ok(sb.diagnostics().failedExports >= 1);
      assert.ok(stub.requests.length >= 1);
    } finally {
      console.warn = warn;
      await stub.close();
    }
  });
}

test("a successful OTLP export is counted", async () => {
  const stub = await startStub();
  stub.reply("{}", 200);
  try {
    sb.init({ endpoint: stub.url + "/v1/traces", apiKey: "k1", headers: { "x-extra": "1" } });
    sb.withSpan("ok", sb.Kind.CHAIN, () => {});
    assert.equal(await sb.flush(5000), true);
    assert.equal(sb.diagnostics().exportedSpans, 1);
    const r = stub.requests[0];
    assert.equal(r.path, "/v1/traces");
    assert.equal(r.headers.authorization, undefined, "the key never goes to a loopback receiver (as Python)");
    assert.equal(r.headers["x-extra"], "1");
  } finally {
    await stub.close();
  }
});

test("an exporter that throws is counted, never escapes", async () => {
  const boom = {
    export() { throw new Error("kaput"); },
    async shutdown() { throw new Error("kaput"); },
  };
  sb.init({ exporter: boom });
  sb.withSpan("x", sb.Kind.CHAIN, () => {});
  await sb.flush(2000);
  assert.equal(await sb.shutdown(2000), true);
  const d = sb.diagnostics();
  assert.equal(d.failedExports, 1);
  assert.equal(d.droppedSpans, 1);
  assert.match(d.lastError, /kaput/);
  assert.equal(d.initialized, false);
});

test("shutdown then init exports again", async () => {
  sb.init({ exporter: new InMemorySpanExporter() });
  await sb.shutdown(2000);
  const fresh = new InMemorySpanExporter();
  sb.init({ exporter: fresh });
  sb.withSpan("again", sb.Kind.CHAIN, () => {});
  assert.ok((await exported(fresh)).again);
});

// --- settings ---------------------------------------------------------------

test("endpoint resolution order", () => {
  const r = (env, explicit) => sb.resolveSettings(env, explicit ? { endpoint: explicit } : {}).endpoint;
  assert.equal(r({}), "http://127.0.0.1:4318/v1/traces");
  assert.equal(r({ OTEL_EXPORTER_OTLP_ENDPOINT: "https://gw.example/" }), "https://gw.example/v1/traces");
  const env = { OTEL_EXPORTER_OTLP_ENDPOINT: "https://a", OTEL_EXPORTER_OTLP_TRACES_ENDPOINT: "https://b/t" };
  assert.equal(r(env), "https://b/t");
  env.SUPERBASED_OTLP_ENDPOINT = "https://c/v1/traces";
  assert.equal(r(env), "https://c/v1/traces");
  assert.equal(r(env, "https://d"), "https://d");
});

test("settings from env", () => {
  const env = {
    OTEL_SERVICE_NAME: "from-otel",
    OTEL_RESOURCE_ATTRIBUTES: "deployment.environment=prod,team=a%20b",
    OTEL_EXPORTER_OTLP_HEADERS: "x-a=1,x-b=2",
    SUPERBASED_OTLP_HEADERS: "x-b=3",
    OTEL_EXPORTER_OTLP_TIMEOUT: "1500",
    SUPERBASED_API_KEY: "k1",
    SUPERBASED_TENANT: "acme",
    SUPERBASED_SHUTDOWN_TIMEOUT_MS: "750",
    SUPERBASED_MAX_CONTENT_CHARS: "0",
    SUPERBASED_EXIT_HOOK: "0",
  };
  const s = sb.resolveSettings(env, { headers: { "x-c": "4" } });
  assert.equal(s.serviceName, "from-otel");
  assert.equal(s.resourceAttributes.team, "a b");
  assert.deepEqual(s.headers, { "x-a": "1", "x-b": "3", "x-c": "4" });
  assert.equal(s.exportTimeoutMs, 1500);
  assert.equal(s.shutdownTimeoutMs, 750);
  assert.equal(s.tenant, "acme");
  assert.equal(s.maxContentChars, 0);
  assert.equal(s.exitHook, false);
  const d = sb.destinations(s);
  assert.equal(d.length, 1);
  assert.equal(d[0].name, "local");
  assert.equal(d[0].headers.Authorization, undefined, "the built-in loopback receiver never gets the key");
  assert.equal(sb.resolveSettings({ OTEL_RESOURCE_ATTRIBUTES: "service.name=res" }).serviceName, "res");
  assert.equal(sb.resolveSettings({ ...env, SUPERBASED_SERVICE_NAME: "sb" }).serviceName, "sb");
  assert.throws(() => sb.resolveSettings({}, { nope: 1 }), TypeError);
});

test("OTEL_RESOURCE_ATTRIBUTES land on the resource", async () => {
  process.env.OTEL_RESOURCE_ATTRIBUTES = "deployment.environment=staging";
  process.env.OTEL_SERVICE_NAME = "svc-env";
  const mem = new InMemorySpanExporter();
  sb.init({ exporter: mem });
  sb.withSpan("r", sb.Kind.CHAIN, () => {});
  const res = (await exported(mem)).r.resource.attributes;
  assert.equal(res["service.name"], "svc-env");
  assert.equal(res["deployment.environment"], "staging");
});

// --- exit hook --------------------------------------------------------------

test("beforeExit flushes pending spans without an explicit shutdown", async () => {
  const stub = await startStub();
  stub.reply("{}", 200);
  try {
    const entry = fileURLToPath(new URL("../dist/esm/index.js", import.meta.url));
    const script = `
      import * as sb from ${JSON.stringify(entry)};
      sb.init({ endpoint: ${JSON.stringify(stub.url + "/v1/traces")} });
      sb.withSpan("exit-span", sb.Kind.CHAIN, () => {});
    `;
    const code = await new Promise((resolve) => {
      const child = spawn(process.execPath, ["--input-type=module", "-e", script], { stdio: "inherit" });
      child.on("exit", resolve);
    });
    assert.equal(code, 0);
    assert.ok(stub.requests.some((r) => r.path === "/v1/traces"), "the span was exported on beforeExit");
  } finally {
    await stub.close();
  }
});

test("beforeExit flushes the tail under both after an earlier flush (E-31)", async () => {
  const local = await startStub();
  const online = await startStub();
  try {
    const entry = fileURLToPath(new URL("../dist/esm/index.js", import.meta.url));
    // One span is flushed to both sides; the second one ends later and is
    // only ever exported by the exit hook.
    const script = `
      import * as sb from ${JSON.stringify(entry)};
      sb.init({ destination: "both", discover: false, endpoint: ${JSON.stringify(local.url + "/v1/traces")}, orgUrl: ${JSON.stringify(online.url)}, apiKey: "k" });
      sb.withSpan("first", sb.Kind.CHAIN, () => {});
      await sb.flush(3000);
      sb.withSpan("tail", sb.Kind.CHAIN, () => {});
    `;
    const code = await new Promise((resolve) => {
      const child = spawn(process.execPath, ["--input-type=module", "-e", script], { stdio: "inherit" });
      child.on("exit", resolve);
    });
    assert.equal(code, 0);
    for (const [name, stub] of [["local", local], ["online", online]]) {
      const n = stub.requests.filter((r) => r.path === "/v1/traces").length;
      assert.equal(n, 2, `${name} received the first span and the tail`);
    }
  } finally {
    await local.close();
    await online.close();
  }
});

const otlp = (stub) => stub.requests.filter((r) => r.path === "/v1/traces");

test("pendingSpans counts each destination under both (E-31)", async () => {
  const local = await startStub();
  const online = await startStub();
  online.delayMs = 1000;
  try {
    sb.init({ destination: "both", discover: false, endpoint: `${local.url}/v1/traces`, orgUrl: online.url, apiKey: "k", shutdownTimeoutMs: 5000 });
    sb.withSpan("x", sb.Kind.CHAIN, () => {});
    const done = sb.flush(5000);
    // Wait for the local copy to be exported (the online one is held 1 s).
    for (let i = 0; i < 100 && sb.diagnostics().exportedSpans < 1; i++) await new Promise((r) => setTimeout(r, 20));
    assert.equal(local.requests.filter((r) => r.path === "/v1/traces").length, 1, "the local copy went out");
    assert.equal(sb.diagnostics().exportedSpans, 1, JSON.stringify(sb.diagnostics()));
    assert.equal(sb.diagnostics().pendingSpans, 1, "the online copy is still pending");
    await done;
    const d = sb.diagnostics();
    assert.equal(otlp(online).length, 1, "the online copy went out too");
    assert.equal(d.pendingSpans, 0, JSON.stringify(d));
    assert.equal(d.exportedSpans, 2, JSON.stringify(d));
  } finally {
    await sb.shutdown(2000);
    await local.close();
    await online.close();
  }
});
