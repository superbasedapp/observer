// W2-2 SDK API: per-request attributes, typed span helpers, cache and
// reasoning tokens, sampling, shouldExport, masking, traceparent helpers.
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";

import { trace } from "@opentelemetry/api";
import { InMemorySpanExporter, SimpleSpanProcessor } from "@opentelemetry/sdk-trace-base";
import { NodeTracerProvider } from "@opentelemetry/sdk-trace-node";

import * as sb from "../dist/esm/index.js";
import { byName, reset } from "./helpers.mjs";

beforeEach(reset);

async function spans(mem) {
  assert.equal(await sb.flush(5000), true);
  return byName(mem.getFinishedSpans());
}

// --- per-request attributes ---------------------------------------------------

test("propagateAttributes stamps every span inside, at any async depth, including raw OTel spans", async () => {
  const mem = new InMemorySpanExporter();
  sb.init({ exporter: mem });
  await sb.propagateAttributes(
    { user: "u1", sessionId: "s1", tenant: "acme", tags: ["a"], metadata: { plan: "pro", n: 3 }, release: "r9", environment: "staging" },
    async () => {
      await new Promise((r) => setTimeout(r, 5));
      await sb.withSpan("outer", sb.Kind.CHAIN, async () => {
        await new Promise((r) => setTimeout(r, 1));
        trace.getTracer("host").startActiveSpan("raw", (s) => s.end());
      });
    },
  );
  const got = await spans(mem);
  for (const name of ["outer", "raw"]) {
    const a = got[name].attributes;
    assert.equal(a["sbo.user"], "u1", name);
    assert.equal(a["session.id"], "s1", name);
    assert.equal(a["sbo.tenant"], "acme", name);
    assert.deepEqual(a["sbo.tags"], ["a"], name);
    assert.equal(a["sbo.metadata.plan"], "pro", name);
    assert.equal(a["sbo.metadata.n"], "3", name);
    assert.equal(a["sbo.release"], "r9", name);
    assert.equal(a["sbo.environment"], "staging", name);
  }
});

test("concurrent requests keep their own attributes", async () => {
  const mem = new InMemorySpanExporter();
  sb.init({ exporter: mem });
  const one = (user) =>
    sb.propagateAttributes({ user }, async () => {
      await new Promise((r) => setTimeout(r, user === "a" ? 10 : 1));
      sb.withSpan(`req-${user}`, sb.Kind.CHAIN, () => {});
    });
  await Promise.all([one("a"), one("b")]);
  const got = await spans(mem);
  assert.equal(got["req-a"].attributes["sbo.user"], "a");
  assert.equal(got["req-b"].attributes["sbo.user"], "b");
});

test("nested scopes merge: tags union, metadata merge, scalar replace; a span's own value wins", async () => {
  const mem = new InMemorySpanExporter();
  sb.init({ exporter: mem });
  sb.propagateAttributes({ user: "outer", tags: ["x"], metadata: { a: "1" } }, () =>
    sb.propagateAttributes({ user: "inner", tags: ["y"], metadata: { b: "2" } }, () => {
      sb.withSpan("s", sb.Kind.CHAIN, () => {});
      sb.withSpan("own", sb.Kind.CHAIN, () => {}, { "sbo.user": "explicit" });
    }),
  );
  const got = await spans(mem);
  assert.equal(got.s.attributes["sbo.user"], "inner");
  assert.deepEqual(got.s.attributes["sbo.tags"], ["x", "y"]);
  assert.equal(got.s.attributes["sbo.metadata.a"], "1");
  assert.equal(got.s.attributes["sbo.metadata.b"], "2");
  assert.equal(got.own.attributes["sbo.user"], "explicit");
});

test("propagateAttributes and identify also stamp the span already active", async () => {
  const mem = new InMemorySpanExporter();
  sb.init({ exporter: mem });
  await sb.withSpan("handler", sb.Kind.CHAIN, async () => {
    sb.identify({ user: "late-user" });
    await new Promise((r) => setTimeout(r, 1));
    sb.withSpan("after", sb.Kind.TOOL, () => {});
  });
  const got = await spans(mem);
  assert.equal(got.handler.attributes["sbo.user"], "late-user");
  assert.equal(got.after.attributes["sbo.user"], "late-user", "identify persists through later awaits");
});

test("identify returns a handle whose reset() undoes it", async () => {
  const mem = new InMemorySpanExporter();
  sb.init({ exporter: mem });
  await sb.propagateAttributes({ user: "outer" }, async () => {
    const h = sb.identify({ user: "inner", tags: ["t"] });
    assert.equal(sb.getCurrentAttributes().user, "inner");
    h.reset();
    assert.deepEqual(sb.getCurrentAttributes(), { user: "outer" });
  });
  assert.deepEqual(sb.getCurrentAttributes(), {});
});

test("an empty string clears an outer value; undefined leaves it; null drops a metadata key", () => {
  sb.init({ exporter: new InMemorySpanExporter() });
  sb.propagateAttributes({ user: "u", sessionId: "s", metadata: { a: "1", b: "2" } }, () =>
    sb.propagateAttributes({ user: "", sessionId: undefined, metadata: { a: null } }, () => {
      assert.deepEqual(sb.getCurrentAttributes(), { sessionId: "s", metadata: { b: "2" } });
    }),
  );
});

test("identify does not leak to a sibling request", async () => {
  const mem = new InMemorySpanExporter();
  sb.init({ exporter: mem });
  const req = (user, delay) =>
    sb.propagateAttributes({}, async () => {
      if (user) sb.identify({ user });
      await new Promise((r) => setTimeout(r, delay));
      sb.withSpan(`r-${user || "anon"}`, sb.Kind.CHAIN, () => {});
    });
  await Promise.all([req("alice", 5), req("", 10)]);
  const got = await spans(mem);
  assert.equal(got["r-alice"].attributes["sbo.user"], "alice");
  assert.equal(got["r-anon"].attributes["sbo.user"], undefined);
});

test("init-level release, environment, tags and metadata ride on the resource", async () => {
  const mem = new InMemorySpanExporter();
  process.env.SUPERBASED_TAGS = "t2, t1";
  process.env.SUPERBASED_METADATA = "team=core";
  sb.init({ exporter: mem, release: "1.2.3", environment: "prod" });
  sb.withSpan("x", sb.Kind.CHAIN, () => {});
  const r = (await spans(mem)).x.resource.attributes;
  assert.equal(r["service.version"], "1.2.3");
  assert.equal(r["deployment.environment.name"], "prod");
  assert.deepEqual(r["sbo.tags"], ["t1", "t2"]);
  assert.equal(r["sbo.metadata.team"], "core");
});

test("identity values are clamped to the otelident bounds", async () => {
  const mem = new InMemorySpanExporter();
  sb.init({ exporter: mem });
  const meta = Object.fromEntries(Array.from({ length: 40 }, (_, i) => [`k${i}`, "v".repeat(600)]));
  sb.propagateAttributes({ user: "u".repeat(300), tags: Array.from({ length: 40 }, (_, i) => `t${i}`), metadata: meta }, () =>
    sb.withSpan("c", sb.Kind.CHAIN, () => {}),
  );
  const a = (await spans(mem)).c.attributes;
  assert.equal(a["sbo.user"].length, sb.LIMITS.valueLen);
  assert.equal(a["sbo.tags"].length, sb.LIMITS.tags);
  const mk = Object.keys(a).filter((k) => k.startsWith("sbo.metadata.")).sort();
  assert.equal(mk.length, sb.LIMITS.metadataKeys);
  assert.ok(mk.includes("sbo.metadata.k0") && !mk.includes("sbo.metadata.k9"), "the lexically smallest keys are kept");
  assert.equal(a[mk[0]].length, sb.LIMITS.metadataValueLen);
});

// --- typed helpers ------------------------------------------------------------

test("typed helpers write the GenAI and OpenInference keys", async () => {
  const mem = new InMemorySpanExporter();
  sb.init({ exporter: mem });
  await sb.withAgentSpan("planner", { agentId: "ag-1" }, async (agent) => {
    sb.setInput(agent, { goal: "g" });
    sb.withToolSpan("call-search", { toolName: "search", callId: "call_1", arguments: { q: "x" } }, (sp) =>
      sb.setToolResult(sp, ["r1"]),
    );
    sb.withRetrieverSpan("kb", { query: "what", attributes: { "gen_ai.provider.name": "pgvector" } }, (sp) =>
      sb.setDocuments(sp, ["doc one", { id: "d2", content: "doc two", score: 0.5 }]),
    );
    sb.withRetrieverSpan("kb2", {}, (sp) => sb.setOutput(sp, [{ content: "x" }]));
    sb.withEmbeddingSpan("embed", { model: "text-embedding-3-small", provider: "openai" }, (sp) =>
      sb.setUsage(sp, { inputTokens: 4 }),
    );
    sb.setOutput(agent, "done");
  });
  const g = await spans(mem);
  const ag = g.planner.attributes;
  assert.equal(ag["openinference.span.kind"], "AGENT");
  assert.equal(ag["gen_ai.operation.name"], "invoke_agent");
  assert.equal(ag["gen_ai.agent.name"], "planner");
  assert.equal(ag["agent.name"], "planner");
  assert.equal(ag["gen_ai.agent.id"], "ag-1");
  assert.equal(ag["input.value"], '{"goal":"g"}');
  assert.equal(ag["output.value"], "done");
  const tool = g["call-search"].attributes;
  assert.equal(tool["openinference.span.kind"], "TOOL");
  assert.equal(tool["gen_ai.operation.name"], "execute_tool");
  assert.equal(tool["gen_ai.tool.name"], "search");
  assert.equal(tool["tool.name"], "search");
  assert.equal(tool["gen_ai.tool.call.id"], "call_1");
  assert.equal(tool["gen_ai.tool.call.arguments"], '{"q":"x"}');
  assert.equal(tool["gen_ai.tool.call.result"], '["r1"]');
  const kb = g.kb.attributes;
  assert.equal(kb["openinference.span.kind"], "RETRIEVER");
  assert.equal(kb["gen_ai.operation.name"], "retrieval");
  assert.equal(kb["gen_ai.retrieval.query.text"], "what");
  assert.equal(kb["gen_ai.provider.name"], "pgvector");
  assert.deepEqual(JSON.parse(kb["gen_ai.retrieval.documents"]), [{ content: "doc one" }, { id: "d2", content: "doc two", score: 0.5 }]);
  assert.equal(g.kb2.attributes["gen_ai.retrieval.documents"], '[{"content":"x"}]', "setOutput on a retriever writes documents");
  const em = g.embed.attributes;
  assert.equal(em["gen_ai.system"], "openai");
  assert.equal(em["openinference.span.kind"], "EMBEDDING");
  assert.equal(em["gen_ai.operation.name"], "embeddings");
  assert.equal(em["gen_ai.request.model"], "text-embedding-3-small");
  assert.equal(em["gen_ai.usage.input_tokens"], 4);
});

test("withSpan overloads, LLM system / message-list prompt / request params, setContent by span kind", async () => {
  const mem = new InMemorySpanExporter();
  sb.init({ exporter: mem });
  assert.equal(sb.withSpan("plain", () => 7), 7);
  sb.withSpan("opts", { kind: sb.Kind.GUARDRAIL, attributes: { "sbo.tenant": "t" } }, () => {});
  sb.withLlmSpan("chat", { model: "m", system: "be brief", prompt: [{ role: "user", content: "hi" }] }, (sp) => {
    sb.setRequestParams(sp, { temperature: 0.2, maxTokens: 100, stopSequences: ["\n"], stream: true });
    sb.setContent(sp, { response: [{ role: "assistant", content: "yo" }] });
  });
  sb.withToolSpan("t", {}, (sp) => sb.setContent(sp, { toolArgs: { a: 1 }, toolResult: "r" }));
  const g = await spans(mem);
  assert.equal(g.plain.attributes["openinference.span.kind"], "CHAIN");
  assert.equal(g.opts.attributes["openinference.span.kind"], "GUARDRAIL");
  assert.equal(g.opts.attributes["sbo.tenant"], "t");
  const c = g.chat.attributes;
  assert.equal(c["gen_ai.system_instructions"], "be brief");
  assert.equal(c["gen_ai.input.messages"], '[{"role":"user","content":"hi"}]');
  assert.equal(c["gen_ai.output.messages"], '[{"role":"assistant","content":"yo"}]');
  assert.equal(c["gen_ai.request.temperature"], 0.2);
  assert.equal(c["gen_ai.request.max_tokens"], 100);
  assert.deepEqual(c["gen_ai.request.stop_sequences"], ["\n"]);
  assert.equal(c["gen_ai.request.stream"], true);
  assert.equal(g.t.attributes["gen_ai.tool.call.arguments"], '{"a":1}');
  assert.equal(g.t.attributes["gen_ai.tool.call.result"], "r");
});

test("setUsage records cache and reasoning tokens with the dotted keys", async () => {
  const mem = new InMemorySpanExporter();
  sb.init({ exporter: mem });
  sb.withLlmSpan("chat", { model: "m", provider: "anthropic" }, (sp) =>
    sb.setUsage(sp, {
      inputTokens: 1200,
      outputTokens: 300,
      cacheReadTokens: 1000,
      cacheWriteTokens: 100,
      reasoningTokens: 120,
      finishReasons: ["stop"],
      responseModel: "m-2026",
      totalTokens: 1500.7,
    }),
  );
  assert.throws(() => sb.setUsage(trace.getTracer("x").startSpan("s"), { inputTokens: -1 }), RangeError);
  const a = (await spans(mem)).chat.attributes;
  assert.equal(a["gen_ai.usage.input_tokens"], 1200);
  assert.equal(a["gen_ai.usage.output_tokens"], 300);
  assert.equal(a["gen_ai.usage.cache_read.input_tokens"], 1000);
  assert.equal(a["gen_ai.usage.cache_write.input_tokens"], 100);
  assert.equal(a["gen_ai.usage.reasoning.output_tokens"], 120);
  assert.deepEqual(a["gen_ai.response.finish_reasons"], ["stop"]);
  assert.equal(a["gen_ai.response.model"], "m-2026");
  assert.equal(a["gen_ai.usage.total_tokens"], 1500, "a fraction is truncated");
});

test("a failing span records error.type once", async () => {
  const mem = new InMemorySpanExporter();
  sb.init({ exporter: mem });
  assert.throws(() =>
    sb.withSpan("bad", sb.Kind.TOOL, () => {
      throw new RangeError("nope");
    }),
  );
  const s = (await spans(mem)).bad;
  assert.equal(s.attributes["error.type"], "RangeError");
  assert.equal(s.events.filter((e) => e.name === "exception").length, 1);
});

test("observe captureIo records arguments and the awaited result", async () => {
  const mem = new InMemorySpanExporter();
  sb.init({ exporter: mem });
  const f = sb.observe(async (q) => `answer to ${q}`, { name: "ask", captureIo: true });
  assert.equal(await f("life"), "answer to life");
  const a = (await spans(mem)).ask.attributes;
  assert.equal(a["input.value"], "life");
  assert.equal(a["output.value"], "answer to life");
});

test("getCurrentTraceId / getCurrentSpanId inside and outside a span", async () => {
  sb.init({ exporter: new InMemorySpanExporter() });
  assert.equal(sb.getCurrentTraceId(), "");
  sb.withSpan("x", sb.Kind.CHAIN, (span) => {
    assert.equal(sb.getCurrentTraceId(), span.spanContext().traceId);
    assert.equal(sb.getCurrentSpanId(), span.spanContext().spanId);
  });
});

// --- sampling and shouldExport -------------------------------------------------

test("keepTrace is deterministic on the low 64 bits and roughly proportional", () => {
  assert.equal(sb.keepTrace("0".repeat(32), 0.5), true);
  assert.equal(sb.keepTrace("f".repeat(32), 0.5), false);
  assert.equal(sb.keepTrace("ffffffffffffffff0000000000000001", 0.01), true, "high bits are ignored");
  assert.equal(sb.keepTrace("abc", 1), true);
  assert.equal(sb.keepTrace("0".repeat(32), 0), false);
  let kept = 0;
  for (let i = 0; i < 4000; i++) {
    const hex = (BigInt(i) * 0x9e3779b97f4a7c15n % (1n << 64n)).toString(16).padStart(32, "0");
    if (sb.keepTrace(hex, 0.25)) kept++;
  }
  assert.ok(kept > 800 && kept < 1200, `kept ${kept} of 4000 at 0.25`);
});

test("sampleRate 0 drops whole traces and counts them; env SUPERBASED_SAMPLE_RATE is read", async () => {
  const mem = new InMemorySpanExporter();
  process.env.SUPERBASED_SAMPLE_RATE = "0";
  sb.init({ exporter: mem });
  assert.equal(sb.settings().sampleRate, 0);
  sb.withSpan("p", sb.Kind.CHAIN, () => sb.withSpan("c", sb.Kind.TOOL, () => {}));
  await sb.flush(5000);
  assert.equal(mem.getFinishedSpans().length, 0);
  assert.equal(sb.diagnostics().sampledOutSpans, 2);
  assert.equal(sb.diagnostics().pendingSpans, 0);
});

test("OTEL_TRACES_SAMPLER supplies the rate; a rate outside 0..1 is a RangeError", () => {
  process.env.OTEL_TRACES_SAMPLER = "parentbased_traceidratio";
  process.env.OTEL_TRACES_SAMPLER_ARG = "0.3";
  assert.equal(sb.resolveSettings(process.env).sampleRate, 0.3);
  assert.equal(sb.resolveSettings(process.env).parentBased, true);
  process.env.OTEL_TRACES_SAMPLER = "always_off";
  assert.equal(sb.resolveSettings(process.env).sampleRate, 0);
  assert.throws(() => sb.resolveSettings(process.env, { sampleRate: 7 }), RangeError);
});

test("a bad sampling value in the environment is ignored and named, never thrown (E-38)", () => {
  process.env.OTEL_TRACES_SAMPLER = "traceidratio";
  process.env.OTEL_TRACES_SAMPLER_ARG = "5";
  const s = sb.resolveSettings(process.env);
  assert.equal(s.sampleRate, 1);
  assert.equal(s.parentBased, false);
  assert.match(s.samplingInvalid, /OTEL_TRACES_SAMPLER_ARG="5" is not a number in 0\.\.1; ignored/);
  process.env.SUPERBASED_SAMPLE_RATE = "abc";
  delete process.env.OTEL_TRACES_SAMPLER_ARG;
  const t = sb.resolveSettings(process.env);
  assert.equal(t.sampleRate, 1, "falls through to OTEL_TRACES_SAMPLER");
  assert.match(t.samplingInvalid, /SUPERBASED_SAMPLE_RATE="abc"/);
  // init() degrades, warns once and runs.
  process.env.OTEL_TRACES_SAMPLER_ARG = "5";
  const warn = console.warn;
  const lines = [];
  console.warn = (m) => lines.push(String(m));
  try {
    const mem = new InMemorySpanExporter();
    assert.doesNotThrow(() => sb.init({ exporter: mem, discover: false }));
    assert.ok(lines.some((l) => /SUPERBASED_SAMPLE_RATE="abc"/.test(l)), lines.join("\n"));
  } finally {
    console.warn = warn;
  }
  assert.throws(() => sb.resolveSettings(process.env, { sampleRate: 1.5 }), RangeError, "the explicit option still throws");
});

test("owned mode samples at the provider, parent-based: a sampled remote parent keeps the child", async () => {
  const mem = new InMemorySpanExporter();
  sb.init({ exporter: mem, sampleRate: 0 });
  // a sampled remote parent whose trace id the ratio would drop
  sb.continueTrace({ traceparent: `00-${"f".repeat(32)}-${"1".repeat(16)}-01` }, () => sb.withSpan("child", () => {}));
  sb.withSpan("root", () => {});
  const got = await spans(mem);
  assert.ok(got.child, "kept by the sampled parent");
  assert.equal(got.root, undefined);
});

test("attached mode applies the same ratio to what the SDK exports", async () => {
  const hostMem = new InMemorySpanExporter();
  const host = new NodeTracerProvider({ spanProcessors: [sb.spanProcessor(), new SimpleSpanProcessor(hostMem)] });
  host.register();
  const mem = new InMemorySpanExporter();
  sb.init({ exporter: mem, sampleRate: 0 });
  assert.equal(sb.diagnostics().mode, "attached");
  trace.getTracer("host").startActiveSpan("h", (s) => s.end());
  await sb.flush(2000);
  assert.equal(mem.getFinishedSpans().length, 0);
  assert.equal(hostMem.getFinishedSpans().length, 1, "the host's own processors still see it");
  assert.equal(sb.diagnostics().sampledOutSpans, 1);
});

test("shouldExport drops spans; a throwing hook keeps the span and is counted", async () => {
  const mem = new InMemorySpanExporter();
  sb.init({
    exporter: mem,
    shouldExport: (s) => {
      if (s.name === "boom") throw new Error("hook bug");
      return s.name !== "health";
    },
  });
  for (const n of ["health", "work", "boom"]) sb.withSpan(n, sb.Kind.CHAIN, () => {});
  const got = await spans(mem);
  assert.deepEqual(Object.keys(got).sort(), ["boom", "work"]);
  const d = sb.diagnostics();
  assert.equal(d.filteredSpans, 1);
  assert.equal(d.shouldExportErrors, 1);
  assert.match(d.lastHookError, /hook bug/);
});

test("a re-init with a new hook takes effect (functions are not part of the no-op key)", async () => {
  const mem = new InMemorySpanExporter();
  sb.init({ exporter: mem });
  sb.init({ exporter: mem, shouldExport: () => false });
  sb.withSpan("x", sb.Kind.CHAIN, () => {});
  await sb.flush(5000);
  assert.equal(mem.getFinishedSpans().length, 0);
});

// --- masking and content --------------------------------------------------------

test("mask rewrites content from any writer, on spans and events, before export", async () => {
  const mem = new InMemorySpanExporter();
  const seen = [];
  sb.init({
    exporter: mem,
    mask: (v, key) => {
      seen.push(key);
      return String(v).replace(/\d{3}-\d{2}-\d{4}/g, "[ssn]");
    },
  });
  sb.withLlmSpan("chat", { prompt: "my ssn is 123-45-6789" }, (sp) => sb.setUsage(sp, { response: "got 123-45-6789", inputTokens: 5 }));
  trace.getTracer("openllmetry").startActiveSpan("raw", (s) => {
    s.setAttribute("gen_ai.prompt.0.content", "call 123-45-6789");
    s.setAttribute("gen_ai.prompt.0.role", "user");
    s.setAttribute("gen_ai.input.messages", '[{"role":"user","content":"123-45-6789"}]');
    s.setAttribute("other", "123-45-6789 is not content");
    s.addEvent("gen_ai.content.prompt", { "gen_ai.prompt": "event 123-45-6789" });
    s.end();
  });
  const g = await spans(mem);
  assert.equal(g.chat.attributes["input.value"], "my ssn is [ssn]");
  assert.equal(g.chat.attributes["output.value"], "got [ssn]");
  assert.equal(g.chat.attributes["gen_ai.usage.input_tokens"], 5);
  assert.equal(g.raw.attributes["gen_ai.prompt.0.content"], "call [ssn]");
  assert.equal(g.raw.attributes["gen_ai.input.messages"], '[{"role":"user","content":"[ssn]"}]');
  assert.equal(g.raw.attributes.other, "123-45-6789 is not content", "only content keys are masked");
  assert.equal(g.raw.events[0].attributes["gen_ai.prompt"], "event [ssn]");
  assert.ok(seen.includes("gen_ai.prompt.0.content"));
  assert.ok(!seen.includes("gen_ai.prompt.0.role"), "the .role member is structure, not content");
});

test("a mask hook that throws drops that value, never the span; null drops it too", async () => {
  const mem = new InMemorySpanExporter();
  sb.init({
    exporter: mem,
    mask: (v, key) => {
      if (key === "output.value") return null;
      throw new Error("mask bug");
    },
  });
  sb.withLlmSpan("chat", { model: "m", prompt: "secret" }, (sp) => sb.setContent(sp, { response: "also secret" }));
  const a = (await spans(mem)).chat.attributes;
  assert.equal("input.value" in a, false);
  assert.equal("output.value" in a, false);
  assert.equal(a["gen_ai.request.model"], "m");
  assert.equal(sb.diagnostics().maskErrors, 1);
});

test("captureContent=false strips content an instrumentation wrote too", async () => {
  const mem = new InMemorySpanExporter();
  sb.init({ exporter: mem, captureContent: false });
  trace.getTracer("instr").startActiveSpan("raw", (s) => {
    s.setAttribute("input.value", "secret");
    s.setAttribute("llm.input_messages.0.message.content", "secret");
    s.setAttribute("gen_ai.request.model", "m");
    s.end();
  });
  const a = (await spans(mem)).raw.attributes;
  assert.equal(a["input.value"], undefined);
  assert.equal(a["llm.input_messages.0.message.content"], undefined);
  assert.equal(a["gen_ai.request.model"], "m");
});

test("maxContentChars clips instrumentation content at export", async () => {
  const mem = new InMemorySpanExporter();
  sb.init({ exporter: mem, maxContentChars: 5 });
  trace.getTracer("instr").startActiveSpan("raw", (s) => {
    s.setAttribute("output.value", "abcdefghij");
    s.end();
  });
  assert.equal((await spans(mem)).raw.attributes["output.value"], "abcde…[truncated]");
});

// --- trace context -----------------------------------------------------------

test("inject / continueTrace join a trace across a boundary", async () => {
  const mem = new InMemorySpanExporter();
  sb.init({ exporter: mem });
  let carrier;
  let parentTrace;
  sb.withSpan("producer", (span) => {
    parentTrace = span.spanContext().traceId;
    carrier = sb.inject();
    assert.equal(sb.getTraceparent(), carrier.traceparent);
  });
  assert.match(carrier.traceparent, /^00-[0-9a-f]{32}-[0-9a-f]{16}-01$/);
  assert.equal(carrier.baggage, undefined, "no baggage unless asked");
  sb.continueTrace({ TraceParent: carrier.traceparent }, () => sb.withSpan("consumer", () => {}));
  const ctx = sb.extract(new Headers({ traceparent: carrier.traceparent }));
  assert.equal(trace.getSpanContext(ctx).traceId, parentTrace);
  const g = await spans(mem);
  assert.equal(g.consumer.spanContext().traceId, parentTrace);
  assert.equal(g.consumer.parentSpanContext.spanId, g.producer.spanContext().spanId);
});

test("asBaggage carries per-request values to the next service, which restores them", async () => {
  const mem = new InMemorySpanExporter();
  sb.init({ exporter: mem });
  let carrier;
  sb.propagateAttributes({ user: "alice", tags: ["vip"], metadata: { plan: "pro" }, asBaggage: true }, () =>
    sb.withSpan("up", () => {
      carrier = sb.inject();
    }),
  );
  assert.match(carrier.baggage, /sbo\.user=alice/);
  assert.match(carrier.baggage, /sbo\.metadata\.plan=pro/);
  sb.continueTrace(carrier, () => sb.withSpan("down", () => {}));
  const d = (await spans(mem)).down.attributes;
  assert.equal(d["sbo.user"], "alice");
  assert.deepEqual(d["sbo.tags"], ["vip"]);
  assert.equal(d["sbo.metadata.plan"], "pro");
});

test("trace-context helpers are no-ops without a span or with a bad header", () => {
  sb.init({ exporter: new InMemorySpanExporter() });
  assert.deepEqual(sb.inject(), {});
  assert.equal(sb.getTraceparent(), "");
  assert.equal(trace.getSpanContext(sb.extract({ traceparent: "garbage" })), undefined);
});
