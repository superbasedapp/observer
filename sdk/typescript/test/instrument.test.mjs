// W2-3: instrument([...]) over the OpenInference JS instrumentations (and the
// AI SDK's own @ai-sdk/otel integration), offline.
//
// Each target runs a scenario against a loopback stub or an in-process mock
// (no network) and the emitted spans are checked against
// sdk/contract/fixtures/instrument/<target>-ts.json: the span names, the
// parent links and the recorded attributes. The fixtures' "want" blocks (the
// normalized genaiattr fields) are checked by go test ./tests/sdkcontract
// (lane B2's TestInstrumentFixturesNormalize globs every fixture), so the
// chain instrumentation -> wire attributes -> normalized span is pinned end to
// end for the TypeScript instrumentations too.
//
// Re-record after an instrumentation upgrade with SUPERBASED_RECORD_FIXTURES=1
// (keeps each span's "want"; review the diff).
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import http from "node:http";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { InMemorySpanExporter } from "@opentelemetry/sdk-trace-base";

import * as sb from "../dist/esm/index.js";
import { reset, startStub } from "./helpers.mjs";

const require = createRequire(import.meta.url);
const here = dirname(fileURLToPath(import.meta.url));
// The fixtures live in the repo at sdk/contract; a gate that copies the
// package elsewhere points SUPERBASED_CONTRACT_DIR at them.
const FIXTURES = join(process.env.SUPERBASED_CONTRACT_DIR || join(here, "..", "..", "contract"), "fixtures", "instrument");
const HAVE_FIXTURES = existsSync(FIXTURES);
const RECORD = process.env.SUPERBASED_RECORD_FIXTURES === "1";
const nodeMajor = Number(process.versions.node.split(".")[0]);

/** Skip reason when a framework's engines field excludes this Node (the gate runs 20 to 24). */
function needs(...pkgs) {
  for (const pkg of pkgs) {
    const file = join(here, "..", "node_modules", ...pkg.split("/"), "package.json");
    if (!existsSync(file)) return `${pkg} is not installed`;
    const m = /^>=\s*(\d+)/.exec(JSON.parse(readFileSync(file, "utf8")).engines?.node ?? "");
    if (m && nodeMajor < Number(m[1])) return `${pkg} needs Node ${m[1]}+`;
  }
  return false;
}

beforeEach(async () => {
  sb.uninstrument();
  await reset();
});

// Attributes that differ run to run (ports, LangGraph checkpoint ids, timings).
const VOLATILE = new Set(["server.port", "metadata", "gen_ai.client.operation.duration"]);
const UUID = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g;

function scrub(v) {
  if (typeof v === "string") return v.replace(UUID, "<id>");
  if (Array.isArray(v)) return v.map(scrub);
  return v;
}

// A span name that repeats (an agent's two "generation" spans) gets " #2",
// " #3" in start order, so each fixture span has a unique label the parent
// links (and the Go fixture test) can name.
function labels(spans) {
  const ordered = [...spans].sort((a, b) => a.startTime[0] - b.startTime[0] || a.startTime[1] - b.startTime[1]);
  const seen = new Map();
  const out = new Map();
  for (const s of ordered) {
    const n = (seen.get(s.name) ?? 0) + 1;
    seen.set(s.name, n);
    out.set(s.spanContext().spanId, n === 1 ? s.name : `${s.name} #${n}`);
  }
  return out;
}

function normalize(spans) {
  const byId = labels(spans);
  return spans.map((s) => {
    const attrs = {};
    for (const k of Object.keys(s.attributes).sort()) if (!VOLATILE.has(k)) attrs[k] = scrub(s.attributes[k]);
    return { name: byId.get(s.spanContext().spanId), parent: byId.get(s.parentSpanContext?.spanId) ?? null, attrs };
  });
}

function version(pkg) {
  const file = join(here, "..", "node_modules", ...pkg.split("/"), "package.json");
  return `${pkg} ${JSON.parse(readFileSync(file, "utf8")).version}`;
}

async function check(target, spans, source, gaps = []) {
  const got = normalize(spans);
  if (!RECORD && !HAVE_FIXTURES) return; // outside the repo: the scenario's own assertions still ran
  const file = join(FIXTURES, `${target}-ts.json`);
  const prev = existsSync(file) ? JSON.parse(readFileSync(file, "utf8")) : null;
  if (RECORD) {
    const wants = new Map((prev?.spans ?? []).map((s) => [s.name, s.want]));
    const out = {
      _source: { target, ...source, sdk: "@superbased/sdk (sdk/typescript)", recorded: `${new Date().toISOString().slice(0, 10)}, offline, by sdk/typescript/test/instrument.test.mjs with SUPERBASED_RECORD_FIXTURES=1` },
      target,
      ...(gaps.length ? { _gaps: gaps } : {}),
      spans: got.map((s) => ({ ...s, want: wants.get(s.name) ?? {} })),
    };
    writeFileSync(file, JSON.stringify(out, null, 2) + "\n");
    return;
  }
  assert.ok(prev, `fixture ${file} is missing; record it with SUPERBASED_RECORD_FIXTURES=1`);
  assert.deepEqual(got.map((s) => s.name).sort(), prev.spans.map((s) => s.name).sort(), "span names");
  for (const want of prev.spans) {
    const s = got.find((g) => g.name === want.name);
    assert.equal(s.parent, want.parent, `${want.name}: parent`);
    assert.deepEqual(s.attrs, want.attrs, `${want.name}: attributes`);
    assert.ok(want.want && Object.keys(want.want).length >= 0, `${want.name}: want block`);
  }
}

async function run(fn) {
  const mem = new InMemorySpanExporter();
  // These scenarios test the explicit instrument() call: init()'s own auto
  // setting stays off so it does not instrument first (auto.test.mjs covers it).
  sb.init({ exporter: mem, instrument: "off" });
  await fn();
  assert.equal(await sb.flush(5000), true);
  return mem.getFinishedSpans();
}

// --- API ------------------------------------------------------------------------

test("instrument() reports per target, is idempotent, and refuses an unknown target", { skip: needs("openai", "@langchain/core") }, () => {
  sb.init({ exporter: new InMemorySpanExporter(), instrument: "off" });
  assert.throws(() => sb.instrument(["opneai"]), TypeError);
  assert.deepEqual(sb.instrument(["openai", "langgraph"]), { openai: "instrumented", langchain: "instrumented" });
  assert.deepEqual(sb.instrument(["openai"]), { openai: "already" });
  assert.deepEqual(sb.instrumented().sort(), ["langchain", "openai"]);
  sb.uninstrument(["openai"]);
  assert.deepEqual(sb.instrumented(), ["langchain"]);
  assert.deepEqual(sb.instrument(["openai"]), { openai: "instrumented" });
});

test("a missing instrumentation package reads not-installed, never throws", { skip: needs("@anthropic-ai/sdk") }, () => {
  const preload = join(here, "fixtures", "hide-openai-instrumentation.cjs");
  const script = `import(${JSON.stringify(join(here, "..", "dist", "esm", "index.js"))}).then((sb) => { sb.init({ exporter: { export(_s, cb) { cb({ code: 0 }); }, shutdown: async () => {} } }); console.log(JSON.stringify(sb.instrument(["openai", "anthropic"]))); });`;
  const r = spawnSync(process.execPath, ["--require", preload, "--input-type=module", "-e", script], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(JSON.parse(r.stdout.trim().split("\n").at(-1)), { openai: "not-installed", anthropic: "instrumented" });
});

test("a peer the app installed is found when the SDK is a linked folder", { skip: needs("openai") }, () => {
  // npm links `npm install ./sdk/typescript`; Node resolves from the SDK's real
  // path, which may hold only the runtime dependencies (live finding L-15).
  const app = mkdtempSync(join(tmpdir(), "sbo-app-"));
  try {
    const pkg = "@arizeai/openinference-instrumentation-openai";
    const realPeer = join(here, "..", "node_modules", pkg);
    mkdirSync(join(app, "node_modules", "@arizeai"), { recursive: true });
    symlinkSync(realPeer, join(app, "node_modules", pkg), "dir");
    const entry = join(app, "app.mjs");
    writeFileSync(
      entry,
      `const sb = await import(${JSON.stringify(join(here, "..", "dist", "esm", "index.js"))});\n` +
        `sb.init({ exporter: { export(_s, cb) { cb({ code: 0 }); }, shutdown: async () => {} } });\n` +
        `const openai = await import(${JSON.stringify(createRequire(join(here, "..", "package.json")).resolve("openai"))});\n` +
        `console.log(JSON.stringify(sb.instrument(["openai"], { modules: { openai } })));\n`,
    );
    const preload = join(here, "fixtures", "hide-openai-instrumentation-from-sdk.cjs");
    const r = spawnSync(process.execPath, ["--require", preload, entry], { cwd: app, encoding: "utf8", env: { ...process.env, SBO_SDK_DIR: join(here, "..") } });
    assert.equal(r.status, 0, r.stderr);
    assert.deepEqual(JSON.parse(r.stdout.trim().split("\n").at(-1)), { openai: "instrumented" });
  } finally {
    rmSync(app, { recursive: true, force: true });
  }
});

// --- scenarios ------------------------------------------------------------------

test("openai: chat completion with cached and reasoning usage, and an embedding", { skip: needs("openai") }, async () => {
  const stub = await startStub();
  try {
    stub.handler = (r) =>
      r.path.endsWith("/embeddings")
        ? { body: { object: "list", data: [{ object: "embedding", index: 0, embedding: [0.25, 0.5] }], model: "text-embedding-3-small", usage: { prompt_tokens: 5, total_tokens: 5 } } }
        : {
            body: {
              id: "chatcmpl-fixture",
              object: "chat.completion",
              created: 1763510400,
              model: "gpt-4o-mini-2024-07-18",
              choices: [{ index: 0, finish_reason: "stop", message: { role: "assistant", content: "Paris." } }],
              usage: { prompt_tokens: 1200, completion_tokens: 40, total_tokens: 1240, prompt_tokens_details: { cached_tokens: 1024 }, completion_tokens_details: { reasoning_tokens: 16 } },
            },
          };
    const spans = await run(async () => {
      assert.deepEqual(sb.instrument(["openai"]), { openai: "instrumented" });
      const OpenAI = require("openai").default; // the CommonJS copy instrument() patched
      const client = new OpenAI({ apiKey: "sk-fixture", baseURL: `${stub.url}/v1` });
      await sb.propagateAttributes({ user: "end-user-1", sessionId: "sess-1" }, async () => {
        await client.chat.completions.create({
          model: "gpt-4o-mini",
          messages: [{ role: "system", content: "Be brief." }, { role: "user", content: "Capital of France?" }],
          temperature: 0.2,
        });
        await client.embeddings.create({ model: "text-embedding-3-small", input: "hello", encoding_format: "float" });
      });
    });
    await check(
      "openai",
      spans,
      {
        instrumentor: version("@arizeai/openinference-instrumentation-openai"),
        library: version("openai"),
        grounding: "OpenAI chat completion (system + user messages, cached and reasoning usage) and an embeddings call, against a loopback stub, inside propagateAttributes({ user, sessionId }).",
      },
      ["OpenAI Embeddings: OpenInference names the embedding model embedding.model_name, which genaiattr's model field does not read, so the model is empty (same gap as the Python fixture). Its inputs (embedding.embeddings.*) are masked as SDK extra content keys."],
    );
  } finally {
    await stub.close();
  }
});

test("anthropic: messages.create with a system prompt and cache read/write usage", { skip: needs("@anthropic-ai/sdk") }, async () => {
  const stub = await startStub();
  try {
    stub.reply({
      id: "msg_fixture",
      type: "message",
      role: "assistant",
      model: "claude-sonnet-5-5",
      content: [{ type: "text", text: "Paris." }],
      stop_reason: "end_turn",
      stop_sequence: null,
      usage: { input_tokens: 30, output_tokens: 5, cache_read_input_tokens: 2000, cache_creation_input_tokens: 100 },
    });
    const spans = await run(async () => {
      assert.deepEqual(sb.instrument(["anthropic"]), { anthropic: "instrumented" });
      const Anthropic = require("@anthropic-ai/sdk").default;
      const client = new Anthropic({ apiKey: "sk-fixture", baseURL: stub.url });
      await client.messages.create({ model: "claude-sonnet-5-5", max_tokens: 64, system: "Be brief.", messages: [{ role: "user", content: "Capital of France?" }] });
    });
    await check("anthropic", spans, {
      instrumentor: version("@arizeai/openinference-instrumentation-anthropic"),
      library: version("@anthropic-ai/sdk"),
      grounding: "Anthropic messages.create with a system prompt and cache read/write usage, against a loopback stub. The instrumentation reports GROSS prompt tokens (30 + 2000 + 100).",
    }, ["Anthropic Messages: the JS instrumentation writes the assistant text under llm.output_messages.0.message.contents.0.message_content.text (a content-block list), not .message.content, so genaiattr's output_messages has the role but no content (follow-up for the genaiattr owner)."]);
  } finally {
    await stub.close();
  }
});

test("langchain: a two-node LangGraph StateGraph with a tool and a usage-reporting chat model (ESM modules handed over)", { skip: needs("@langchain/core", "@langchain/langgraph", "zod") }, async () => {
  const manager = await import("@langchain/core/callbacks/manager");
  const { StateGraph, Annotation, START, END } = await import("@langchain/langgraph");
  const { tool } = await import("@langchain/core/tools");
  const { BaseChatModel } = await import("@langchain/core/language_models/chat_models");
  const { AIMessage, HumanMessage } = await import("@langchain/core/messages");
  const { z } = await import("zod");

  class UsageChatModel extends BaseChatModel {
    _llmType() {
      return "usage-fake";
    }
    async _generate() {
      const text = "superbased has 10 letters";
      const message = new AIMessage({ content: text, id: "msg-fixture", usage_metadata: { input_tokens: 12, output_tokens: 6, total_tokens: 18 } });
      return { generations: [{ text, message }], llmOutput: { tokenUsage: { promptTokens: 12, completionTokens: 6, totalTokens: 18 } } };
    }
  }

  const spans = await run(async () => {
    assert.deepEqual(sb.instrument(["langchain"], { modules: { langchain: manager } }), { langchain: "instrumented" });
    const wordLength = tool(async ({ word }) => String(word.length), {
      name: "word_length",
      description: "Length of a word.",
      schema: z.object({ word: z.string() }),
    });
    const llm = new UsageChatModel({});
    const State = Annotation.Root({ q: Annotation(), n: Annotation(), a: Annotation() });
    const graph = new StateGraph(State)
      .addNode("count", async (s) => ({ n: Number(await wordLength.invoke({ word: s.q })) }))
      .addNode("answer", async (s) => ({ a: (await llm.invoke([new HumanMessage(`${s.q} has ${s.n} letters?`)])).content }))
      .addEdge(START, "count")
      .addEdge("count", "answer")
      .addEdge("answer", END)
      .compile();
    assert.deepEqual(await graph.invoke({ q: "superbased" }), { q: "superbased", n: 10, a: "superbased has 10 letters" });
  });
  await check("langchain", spans, {
    instrumentor: version("@arizeai/openinference-instrumentation-langchain"),
    library: `${version("@langchain/core")}, ${version("@langchain/langgraph")}`,
    grounding: "A two-node LangGraph StateGraph: node 'count' calls a tool, node 'answer' calls a BaseChatModel that reports usage. LangGraph runs are LangChain runs, so one instrumentation covers both. 'metadata' (per-run checkpoint ids) is not recorded and UUIDs are written as <id>.",
  });
});

test("mcp: a client tool call over loopback streamable HTTP joins the server's tool span to the caller's trace", { skip: needs("@modelcontextprotocol/sdk", "zod") }, async () => {
  const { McpServer } = require("@modelcontextprotocol/sdk/server/mcp.js");
  const { StreamableHTTPServerTransport } = require("@modelcontextprotocol/sdk/server/streamableHttp.js");
  const { Client } = require("@modelcontextprotocol/sdk/client/index.js");
  const { StreamableHTTPClientTransport } = require("@modelcontextprotocol/sdk/client/streamableHttp.js");
  const { z } = require("zod");
  let httpServer;
  let spans;
  try {
    spans = await run(async () => {
      assert.deepEqual(sb.instrument(["mcp"]), { mcp: "instrumented" });
      const server = new McpServer({ name: "calc", version: "1.0.0" });
      server.registerTool("add", { description: "Add two numbers", inputSchema: { a: z.number(), b: z.number() } }, async ({ a, b }) =>
        sb.withToolSpan("server.add", { arguments: { a, b } }, (sp) => {
          sb.setToolResult(sp, String(a + b));
          return { content: [{ type: "text", text: String(a + b) }] };
        }),
      );
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: () => "sess-fixture" });
      await server.connect(transport);
      httpServer = http.createServer(async (req, res) => {
        const chunks = [];
        for await (const c of req) chunks.push(c);
        await transport.handleRequest(req, res, chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : undefined);
      });
      await new Promise((r) => httpServer.listen(0, "127.0.0.1", r));
      const client = new Client({ name: "client", version: "1.0.0" });
      await client.connect(new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${httpServer.address().port}/mcp`)));
      const out = await sb.withSpan("client.call", () => client.callTool({ name: "add", arguments: { a: 2, b: 3 } }));
      assert.deepEqual(out.content, [{ type: "text", text: "5" }]);
      await client.close();
      await server.close();
    });
  } finally {
    // In a finally, so a failed call cannot leave the server holding the
    // file's event loop open (the test file would never exit).
    httpServer?.closeAllConnections?.();
    httpServer?.close();
  }
  const call = spans.find((s) => s.name === "client.call");
  const add = spans.find((s) => s.name === "server.add");
  assert.equal(add.spanContext().traceId, call.spanContext().traceId, "the server span joined the client's trace");
  await check(
    "mcp",
    spans,
    {
      instrumentor: version("@arizeai/openinference-instrumentation-mcp"),
      library: version("@modelcontextprotocol/sdk"),
      grounding: "An MCP client calls a tool over streamable HTTP on loopback inside an SDK span 'client.call'; the server's tool handler opens withToolSpan('server.add'). The JS MCP SDK emits no spans of its own; the instrumentation carries the trace context in the request, so the handler's span joins the client's trace (without it the two are separate traces).",
    },
    ["The JS MCP SDK (unlike mcp 2.x for Python) emits no tools/call or tools/list spans; only the context propagation is the instrumentation's."],
  );
});

test("vercel-ai: generateText through the AI SDK v7 @ai-sdk/otel integration", { skip: needs("ai", "@ai-sdk/otel") }, async () => {
  const { generateText } = await import("ai");
  const { MockLanguageModelV4 } = await import("ai/test");
  const ai = await import("ai");
  const otel = await import("@ai-sdk/otel");
  const spans = await run(async () => {
    assert.deepEqual(sb.instrument(["vercel-ai"], { modules: { "vercel-ai": { ai, otel } } }), { "vercel-ai": "instrumented" });
    const model = new MockLanguageModelV4({
      provider: "openai.chat",
      modelId: "gpt-4o-mini",
      doGenerate: {
        content: [{ type: "text", text: "Paris." }],
        finishReason: { unified: "stop", raw: "stop" },
        usage: { inputTokens: { total: 1200, noCache: 176, cacheRead: 1024, cacheWrite: 0 }, outputTokens: { total: 40, text: 24, reasoning: 16 } },
        response: { id: "resp-fixture", modelId: "gpt-4o-mini-2024-07-18", timestamp: new Date(0) },
        warnings: [],
      },
    });
    await sb.propagateAttributes({ user: "end-user-1" }, () => generateText({ model, system: "Be brief.", prompt: "Capital of France?", temperature: 0.2 }));
  });
  sb.uninstrument(["vercel-ai"]);
  assert.equal((globalThis.AI_SDK_TELEMETRY_INTEGRATIONS ?? []).length, 0, "uninstrument removes the integration");
  await check(
    "vercel-ai",
    spans,
    {
      instrumentor: version("@ai-sdk/otel"),
      library: version("ai"),
      grounding: "AI SDK v7 generateText over its MockLanguageModelV4 (system + prompt, cached and reasoning usage) inside propagateAttributes({ user }). The AI SDK emits GenAI semconv spans itself (invoke_agent > step > chat); no OpenInference layer is involved.",
    },
    [
      "The AI SDK reports the cache write as gen_ai.usage.cache_creation.input_tokens (a legacy spelling genaiattr also reads) and reasoning only as ai.usage.outputTokenDetails.reasoningTokens, which genaiattr does not read, so reasoning_tokens is empty (follow-up for the genaiattr owner).",
      "The structured gen_ai.input.messages / output.messages use the semconv parts shape ({role, parts: [{type, content}]}).",
    ],
  );
});

// --- W5-1 (lane C6): Gemini, Bedrock, LlamaIndex.TS, OpenAI Agents JS -----------

test("crewai and pydantic-ai are Python-only: a TypeError that says so", () => {
  sb.init({ exporter: new InMemorySpanExporter() });
  assert.throws(() => sb.instrument(["crewai"]), (e) => e instanceof TypeError && /Python/.test(e.message));
  assert.throws(() => sb.instrument(["pydantic-ai"]), (e) => e instanceof TypeError && /Python/.test(e.message));
});

test("gemini: generateContent through OpenLLMetry's @google/genai instrumentation (ESM copy handed over)", { skip: needs("@google/genai", "@traceloop/instrumentation-google-generativeai") }, async () => {
  const stub = await startStub();
  try {
    stub.reply({
      candidates: [{ content: { role: "model", parts: [{ text: "Paris." }] }, finishReason: "STOP", index: 0 }],
      usageMetadata: { promptTokenCount: 1200, candidatesTokenCount: 24, thoughtsTokenCount: 16, cachedContentTokenCount: 1024, totalTokenCount: 1240 },
      modelVersion: "gemini-2.5-flash-001",
      responseId: "resp-fixture",
    });
    const ns = await import("@google/genai");
    const spans = await run(async () => {
      // A module namespace is sealed (the instrumentation replaces the GoogleGenAI export): refused with the fix.
      assert.match(sb.instrument(["gemini"], { modules: { gemini: ns } }).gemini, /^error: .*ESM module namespace.*\.\.\.\(await import/);
      const genai = { ...ns };
      assert.deepEqual(sb.instrument(["gemini"], { modules: { gemini: genai } }), { gemini: "instrumented" });
      const client = new genai.GoogleGenAI({ apiKey: "fixture", httpOptions: { baseUrl: stub.url } });
      const r = await sb.propagateAttributes({ user: "end-user-1" }, () =>
        client.models.generateContent({ model: "gemini-2.5-flash", contents: "Capital of France?", config: { systemInstruction: "Be brief.", temperature: 0.2, maxOutputTokens: 64 } }),
      );
      assert.equal(r.text, "Paris.");
    });
    assert.equal(stub.requests[0].path, "/v1/models/gemini-2.5-flash:generateContent");
    await check(
      "gemini",
      spans,
      {
        instrumentor: version("@traceloop/instrumentation-google-generativeai"),
        library: version("@google/genai"),
        grounding: "Google Gen AI SDK generateContent (system instruction + user text, cached and thinking usage) against a loopback stub via httpOptions.baseUrl, inside propagateAttributes({ user }). OpenLLMetry's instrumentation writes GenAI semconv keys (gen_ai.*), not traceloop.* or llm.*.",
      },
      [
        "The instrumentation writes the thinking tokens as gen_ai.usage.reasoning_tokens; genaiattr reads gen_ai.usage.reasoning.output_tokens (and the OpenInference spelling), so reasoning_tokens is empty (follow-up for the genaiattr owner).",
        "Gemini's candidatesTokenCount excludes thinking tokens, and the instrumentation copies it to gen_ai.usage.output_tokens as is, so output_tokens is NET of reasoning here while genaiattr's contract is output including reasoning (24 + 16 = 40); total_tokens (1240) is Gemini's own total, which counts them.",
        "gen_ai.provider.name is gcp.gen_ai (the semconv value for the Gemini API).",
      ],
    );
  } finally {
    await stub.close();
  }
});

test("bedrock: Converse and InvokeModel (Anthropic body) through the OpenInference Bedrock instrumentation", { skip: needs("@aws-sdk/client-bedrock-runtime", "@arizeai/openinference-instrumentation-bedrock") }, async () => {
  const stub = await startStub();
  try {
    stub.handler = (r) =>
      r.path.endsWith("/converse")
        ? {
            body: {
              output: { message: { role: "assistant", content: [{ text: "Paris." }] } },
              stopReason: "end_turn",
              usage: { inputTokens: 30, outputTokens: 5, totalTokens: 2135, cacheReadInputTokens: 2000, cacheWriteInputTokens: 100 },
              metrics: { latencyMs: 12 },
            },
          }
        : {
            body: {
              id: "msg_fixture",
              type: "message",
              role: "assistant",
              model: "claude-sonnet-5-5",
              content: [{ type: "text", text: "Paris." }],
              stop_reason: "end_turn",
              usage: { input_tokens: 30, output_tokens: 5, cache_read_input_tokens: 2000, cache_creation_input_tokens: 100 },
            },
          };
    const spans = await run(async () => {
      assert.deepEqual(sb.instrument(["bedrock"]), { bedrock: "instrumented" });
      const br = require("@aws-sdk/client-bedrock-runtime");
      const { NodeHttpHandler } = require("@smithy/node-http-handler");
      // HTTP/1.1 handler: the default client speaks HTTP/2, which the loopback stub does not.
      const client = new br.BedrockRuntimeClient({ region: "us-east-1", endpoint: stub.url, requestHandler: new NodeHttpHandler(), credentials: { accessKeyId: "AKIDFIXTURE", secretAccessKey: "fixture" } });
      const modelId = "anthropic.claude-sonnet-5-5-v1:0";
      const c = await client.send(
        new br.ConverseCommand({ modelId, system: [{ text: "Be brief." }], messages: [{ role: "user", content: [{ text: "Capital of France?" }] }], inferenceConfig: { maxTokens: 64, temperature: 0.2 } }),
      );
      assert.equal(c.output.message.content[0].text, "Paris.");
      const body = JSON.stringify({ anthropic_version: "bedrock-2023-05-31", max_tokens: 64, system: "Be brief.", messages: [{ role: "user", content: "Capital of France?" }] });
      const i = await client.send(new br.InvokeModelCommand({ modelId, contentType: "application/json", accept: "application/json", body }));
      assert.equal(JSON.parse(new TextDecoder().decode(i.body)).content[0].text, "Paris.");
    });
    await check(
      "bedrock",
      spans,
      {
        instrumentor: version("@arizeai/openinference-instrumentation-bedrock"),
        library: version("@aws-sdk/client-bedrock-runtime"),
        grounding: "Bedrock Runtime ConverseCommand and InvokeModelCommand (an Anthropic messages body) for one Claude model id, against a loopback stub (endpoint override, HTTP/1.1 handler, fixed fake credentials). Bedrock's own usage is NET of the cache (inputTokens 30, cache read 2000, cache write 100).",
      },
      [
        "bedrock.converse: the instrumentation does not record Converse's cacheReadInputTokens / cacheWriteInputTokens, and llm.token_count.prompt is Bedrock's NET inputTokens (30), so input_tokens is net (genaiattr's contract is gross: 2130) and the cache fields are empty; total_tokens is Bedrock's 2135.",
        "bedrock.invoke_model: the cache read/write are recorded, but llm.token_count.prompt is the Anthropic body's NET input_tokens (30), not gross, and no total is written (derived 35, should be 2135).",
        "Neither span carries a response id or the full model id (llm.model_name drops the anthropic. prefix and the -v1:0 version suffix).",
      ],
    );
  } finally {
    await stub.close();
  }
});

test("llama-index: a ContextChatEngine and a RetrieverQueryEngine through OpenLLMetry's LlamaIndex.TS instrumentation", { skip: needs("llamaindex", "@traceloop/instrumentation-llamaindex") }, async () => {
  const li = require("llamaindex");
  // The instrumentation wraps the LLM classes the handed-over module exports;
  // a provider package's class (@llamaindex/openai) is handed over the same way.
  class FixtureLLM extends li.BaseLLM {
    metadata = { model: "fixture-llm-1", temperature: 0.2, topP: 1, contextWindow: 8192, tokenizer: undefined };
    async chat() {
      return { message: { role: "assistant", content: "Paris." }, raw: { usage: { prompt_tokens: 42, completion_tokens: 3, total_tokens: 45 } } };
    }
    async complete() {
      return { text: "Paris.", raw: null };
    }
  }
  class FixtureRetriever extends li.BaseRetriever {
    async _retrieve() {
      return [{ node: new li.TextNode({ text: "Paris is the capital of France.", id_: "node-1" }), score: 0.9 }];
    }
  }
  const spans = await run(async () => {
    assert.deepEqual(sb.instrument(["llamaindex"], { modules: { "llama-index": { llamaindex: { ...li, FixtureLLM, FixtureRetriever } } } }), { "llama-index": "instrumented" });
    const llm = new FixtureLLM();
    const chat = new li.ContextChatEngine({ retriever: new FixtureRetriever(), chatModel: llm });
    assert.equal((await chat.chat({ message: "Capital of France?" })).message.content, "Paris.");
    const query = new li.RetrieverQueryEngine(new FixtureRetriever(), li.getResponseSynthesizer("compact", { llm }));
    assert.equal(String(await query.query({ query: "Capital of France?" })), "Paris.");
  });
  sb.uninstrument(["llama-index"]);
  await check(
    "llama-index",
    spans,
    {
      instrumentor: version("@traceloop/instrumentation-llamaindex"),
      library: version("llamaindex"),
      grounding: "LlamaIndex.TS ContextChatEngine.chat and RetrieverQueryEngine.query over an in-process retriever and a BaseLLM subclass reporting usage (no network). The workflow and task spans use the traceloop.* dialect; the LLM chat span uses GenAI semconv.",
    },
    [
      "The workflow and task spans (traceloop.span.kind workflow / task) have no OpenInference span kind, so span_kind is empty; genaiattr reads their input and output through traceloop.entity.input / traceloop.entity.output, and also returns those two as tool_arguments / tool_result on these non-tool spans (the fixture does not pin that).",
      "The compact synthesizer calls llm.complete, which the instrumentation does not wrap, so the query engine's LLM call has no span (only chat is instrumented).",
      "gen_ai.provider.name is the LLM class name lowercased (fixturellm), not a provider.",
    ],
  );
});

test("openai-agents: a tool-calling agent run through the OpenInference OpenAI Agents processor", { skip: needs("@openai/agents", "@arizeai/openinference-instrumentation-openai-agents", "openai", "zod") }, async () => {
  const stub = await startStub();
  try {
    stub.queue.push(
      {
        body: {
          id: "chatcmpl-1",
          object: "chat.completion",
          created: 1763510400,
          model: "gpt-4o-mini-2024-07-18",
          choices: [{ index: 0, finish_reason: "tool_calls", message: { role: "assistant", content: null, tool_calls: [{ id: "call_fixture", type: "function", function: { name: "word_length", arguments: '{"word":"superbased"}' } }] } }],
          usage: { prompt_tokens: 80, completion_tokens: 12, total_tokens: 92 },
        },
      },
      {
        body: {
          id: "chatcmpl-2",
          object: "chat.completion",
          created: 1763510401,
          model: "gpt-4o-mini-2024-07-18",
          choices: [{ index: 0, finish_reason: "stop", message: { role: "assistant", content: "superbased has 10 letters." } }],
          usage: { prompt_tokens: 110, completion_tokens: 8, total_tokens: 118, prompt_tokens_details: { cached_tokens: 64 } },
        },
      },
    );
    const agents = require("@openai/agents");
    const OpenAI = require("openai").default;
    const { z } = require("zod");
    agents.setTraceProcessors([]); // no OpenAI trace export from the test (the app's own processors are kept by instrument())
    const spans = await run(async () => {
      assert.deepEqual(sb.instrument(["agents"]), { "openai-agents": "instrumented" });
      agents.setDefaultOpenAIClient(new OpenAI({ apiKey: "sk-fixture", baseURL: `${stub.url}/v1` }));
      agents.setOpenAIAPI("chat_completions");
      const wordLength = agents.tool({ name: "word_length", description: "Length of a word.", parameters: z.object({ word: z.string() }), execute: async ({ word }) => String(word.length) });
      const agent = new agents.Agent({ name: "Counter", instructions: "Count letters.", model: "gpt-4o-mini", tools: [wordLength] });
      const res = await sb.propagateAttributes({ user: "end-user-1" }, () => sb.withSpan("app.request", () => agents.run(agent, "How many letters in superbased?")));
      assert.equal(res.finalOutput, "superbased has 10 letters.");
    });
    sb.uninstrument(["openai-agents"]);
    assert.equal(stub.requests.length, 2);
    const app = spans.find((s) => s.name === "app.request");
    assert.ok(spans.every((s) => s.spanContext().traceId === app.spanContext().traceId), "the agent's spans join the caller's trace");
    await check(
      "openai-agents",
      spans,
      {
        instrumentor: version("@arizeai/openinference-instrumentation-openai-agents"),
        library: version("@openai/agents"),
        grounding: "An @openai/agents Agent with one function tool, run over the chat-completions API against a loopback stub (first reply a tool call, second the answer), inside propagateAttributes({ user }) and an SDK span 'app.request' (the agent's root span joins it). The instrumentation is a trace processor ADDED beside the app's own (exclusiveProcessor false); the test clears the default OpenAI exporter first so nothing leaves the machine.",
      },
      [
        "generation spans: llm.model_name is the REQUESTED model (gpt-4o-mini), not the response's gpt-4o-mini-2024-07-18, and no response id is written, so model and response_id do not reflect the response.",
        "The turn and Agent workflow #2 spans are CHAIN spans with no input or output; only the root Agent workflow span carries the run's input and final output.",
      ],
    );
  } finally {
    await stub.close();
  }
});
