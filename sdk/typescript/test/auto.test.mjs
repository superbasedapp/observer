// Plan 3.1: init() instruments by itself. One test per row of the rule
// table (off / a list / auto with the app's provider / auto with the SDK's),
// plus the env and argument precedence, the auto-excluded Agents SDK, a host
// that instrumented first, and a CommonJS framework required after init().
// The contract's auto_instrument section (L0) is run by behaviour.test.mjs
// when present; these pin the TypeScript half without it.
import { test, beforeEach, after } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { trace } from "@opentelemetry/api";
import { InMemorySpanExporter } from "@opentelemetry/sdk-trace-base";
import { NodeTracerProvider } from "@opentelemetry/sdk-trace-node";

import * as sb from "../dist/esm/index.js";
import { esmMatch } from "../dist/esm/instrument.js";
import { reset } from "./helpers.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const have = (pkg) => existsSync(join(here, "..", "node_modules", ...pkg.split("/"), "package.json"));
const nodeMajor = Number(process.versions.node.split(".")[0]);

beforeEach(async () => {
  sb.uninstrument();
  await reset();
});
after(async () => {
  sb.uninstrument();
  await reset();
});

const opts = (extra = {}) => ({ exporter: new InMemorySpanExporter(), discover: false, destination: "local", ...extra });

test("row 1: off instruments nothing (argument, env, false)", () => {
  for (const [o, env] of [[{ instrument: "off" }, {}], [{ instrument: false }, {}], [{}, { SUPERBASED_INSTRUMENT: "off" }], [{}, { SUPERBASED_INSTRUMENT: "0" }]]) {
    Object.assign(process.env, env);
    sb.init(opts(o));
    const d = sb.diagnostics();
    assert.deepEqual(d.instrumented, {}, JSON.stringify([o, env]));
    assert.equal(d.instrument, "off");
    assert.deepEqual(sb.instrumented(), []);
    delete process.env.SUPERBASED_INSTRUMENT;
  }
});

test("row 2: a list instruments exactly those, aliases folded, even with the app's provider", { skip: !have("openai") && "openai is not installed" }, () => {
  const provider = new NodeTracerProvider({ spanProcessors: [sb.spanProcessor()] });
  provider.register();
  sb.init(opts({ instrument: ["openai", "langgraph"] }));
  const d = sb.diagnostics();
  assert.equal(d.mode, "attached");
  assert.deepEqual(Object.keys(d.instrumented).sort(), ["langchain", "openai"]);
  assert.equal(d.instrumented.openai, "instrumented");
  assert.deepEqual(d.instrument, ["openai", "langchain"]);
});

test("row 2: a named openai-agents is honoured", { skip: !have("@openai/agents") && "@openai/agents is not installed" }, () => {
  sb.init(opts({ instrument: "openai-agents" }));
  assert.deepEqual(Object.keys(sb.diagnostics().instrumented), ["openai-agents"]);
  assert.equal(sb.diagnostics().instrumented["openai-agents"], "instrumented");
});

test("row 3: auto with a provider the app registered instruments nothing and says why", () => {
  // Standalone: a provider the SDK cannot add to.
  new NodeTracerProvider().register();
  sb.init(opts());
  let d = sb.diagnostics();
  assert.equal(d.mode, "standalone");
  assert.ok(Object.values(d.instrumented).every((v) => v === sb.SKIPPED_HOST_PROVIDER), JSON.stringify(d.instrumented));
  assert.ok(d.notes.includes(sb.AUTO_SKIPPED_NOTE), d.notes.join("; "));
  assert.deepEqual(sb.instrumented(), []);
});

test("row 3: auto in attached mode instruments nothing", async () => {
  new NodeTracerProvider({ spanProcessors: [sb.spanProcessor()] }).register();
  sb.init(opts());
  const d = sb.diagnostics();
  assert.equal(d.mode, "attached");
  assert.ok(Object.values(d.instrumented).every((v) => v === "skipped: host_provider"));
  assert.ok(d.notes.includes(sb.AUTO_SKIPPED_NOTE));
});

test("row 4: auto with the SDK's own provider: every installed auto target, openai-agents excluded", () => {
  sb.init(opts());
  const d = sb.diagnostics();
  assert.equal(d.mode, "owned");
  assert.equal(d.instrument, "auto");
  assert.deepEqual(Object.keys(d.instrumented).sort(), sb.TARGETS.map((t) => t.name).sort());
  for (const t of sb.TARGETS) {
    const st = d.instrumented[t.name];
    if (!t.auto) assert.equal(st, have(t.package) && have(t.library.split("/").slice(0, t.library.startsWith("@") ? 2 : 1).join("/")) ? "skipped: auto_excluded" : "skipped: not_installed", t.name);
    else assert.ok(["pending", "instrumented", "skipped: not_installed"].includes(st), `${t.name}: ${st}`);
  }
  if (have("@openai/agents")) assert.equal(d.instrumented["openai-agents"], sb.AUTO_EXCLUDED);
  assert.ok(!sb.instrumented().includes("openai-agents"));
});

test("the argument beats the env; an unknown name in the env list is ignored with a warning", () => {
  process.env.SUPERBASED_INSTRUMENT = "off";
  sb.init(opts({ instrument: "auto" }));
  assert.equal(sb.diagnostics().instrument, "auto");
  process.env.SUPERBASED_INSTRUMENT = "openai, nosuchlib, crewai";
  const warned = [];
  const orig = console.warn;
  console.warn = (m) => warned.push(String(m));
  try {
    sb.init(opts());
  } finally {
    console.warn = orig;
  }
  const d = sb.diagnostics();
  assert.deepEqual(d.instrument, ["openai"]);
  assert.ok(warned.some((w) => w.includes("nosuchlib")), warned.join("\n"));
  assert.ok(warned.some((w) => w.includes("CrewAI")), warned.join("\n"));
  assert.ok(d.destinationProblems.some((p) => p.includes("nosuchlib")));
});

test("an unknown name in the argument is a TypeError, as in instrument()", () => {
  assert.throws(() => sb.init(opts({ instrument: ["opneai"] })), TypeError);
  assert.throws(() => sb.init(opts({ instrument: 7 })), TypeError);
});

test("resolveInstrumentSetting: the words and the list forms", () => {
  const r = (x, env = {}) => sb.resolveInstrumentSetting(x, env);
  assert.equal(r(undefined).mode, "auto");
  assert.equal(r(true).mode, "auto");
  assert.equal(r("AUTO").mode, "auto");
  assert.equal(r("false").mode, "off");
  assert.deepEqual(r("ai, google").names, ["vercel-ai", "gemini"]);
  assert.deepEqual(r(undefined, { SUPERBASED_INSTRUMENT: "llamaindex,agents" }).names, ["llama-index", "openai-agents"]);
  assert.equal(r(undefined, { SUPERBASED_INSTRUMENT: "" }).source, "default");
});

test("a framework required after init() is instrumented on that require (CommonJS)", { skip: (!have("openai") && "openai is not installed") || (nodeMajor < 20 && "node 20+") }, () => {
  sb.init(opts());
  const before = sb.diagnostics().instrumented.openai;
  // openai may already be loaded in this process: then init() instrumented it at once.
  if (before === "pending") {
    require("openai");
    assert.equal(sb.diagnostics().instrumented.openai, "instrumented");
  } else {
    assert.equal(before, "instrumented");
  }
  assert.ok(sb.instrumented().includes("openai"));
});

test("the CommonJS fixture app: one init line, spans from a library required later", { skip: !have("openai") && "openai is not installed" }, () => {
  const r = spawnSync(process.execPath, [join(here, "fixtures", "cjs-app", "app.cjs")], { encoding: "utf8", env: { ...process.env, SUPERBASED_INSTRUMENT: "" } });
  assert.equal(r.status, 0, r.stderr);
  const out = JSON.parse(r.stdout.trim().split("\n").at(-1));
  assert.equal(out.before.openai, "pending");
  assert.equal(out.before["openai-agents"], have("@openai/agents") ? "skipped: auto_excluded" : "skipped: not_installed");
  assert.equal(out.after.openai, "instrumented");
  assert.deepEqual(out.instrumented, ["openai"]);
  assert.ok(out.spans.includes("OpenAI Chat Completions"), out.spans.join(","));
});

test("a library loaded before init() is instrumented at init", { skip: !have("openai") && "openai is not installed" }, () => {
  const script = `const OpenAI = require("openai"); const sb = require("@superbased/sdk"); sb.init({ exporter: { export(_s, cb) { cb({ code: 0 }); }, shutdown: async () => {} }, discover: false }); console.log(JSON.stringify(sb.diagnostics().instrumented.openai));`;
  const r = spawnSync(process.execPath, ["-e", script], { encoding: "utf8", cwd: join(here, "..") });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(JSON.parse(r.stdout.trim()), "instrumented");
});

test("a host that instrumented first reads already", { skip: !have("openai") && "openai is not installed" }, () => {
  const script = [
    `const openai = require("openai");`,
    `const { OpenAIInstrumentation } = require("@arizeai/openinference-instrumentation-openai");`,
    `new OpenAIInstrumentation().manuallyInstrument(openai);`,
    `const sb = require("@superbased/sdk");`,
    `sb.init({ exporter: { export(_s, cb) { cb({ code: 0 }); }, shutdown: async () => {} }, discover: false });`,
    `console.log(JSON.stringify(sb.diagnostics().instrumented.openai));`,
  ].join("\n");
  const r = spawnSync(process.execPath, ["-e", script], { encoding: "utf8", cwd: join(here, "..") });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(JSON.parse(r.stdout.trim()), "already");
});

test("uninstrument() stops waiting; a later init(off) undoes what init() turned on", { skip: !have("openai") && "openai is not installed" }, () => {
  const script = [
    `const sb = require("@superbased/sdk");`,
    `const x = { exporter: { export(_s, cb) { cb({ code: 0 }); }, shutdown: async () => {} }, discover: false };`,
    `sb.init(x);`,
    `sb.uninstrument(["anthropic"]);`,
    `require("@anthropic-ai/sdk");`,
    `const a = sb.instrumented();`,
    `require("openai");`,
    `const b = sb.instrumented();`,
    `sb.init({ ...x, instrument: "off" });`,
    `console.log(JSON.stringify([a, b, sb.instrumented()]));`,
  ].join("\n");
  const r = spawnSync(process.execPath, ["-e", script], { encoding: "utf8", cwd: join(here, "..") });
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(JSON.parse(r.stdout.trim()), [[], ["openai"], []]);
});

test("an explicit instrument() after init() still reports already for an auto-instrumented target", { skip: !have("openai") && "openai is not installed" }, () => {
  sb.init(opts());
  require("openai");
  assert.deepEqual(sb.instrument(["openai"]), { openai: "already" });
});

test("esmMatch: the package from the last node_modules segment; a sub-path when one package carries several", () => {
  const watch = [
    { target: "openai", spec: "openai", part: "" },
    { target: "langchain", spec: "@langchain/core/callbacks/manager", part: "" },
    { target: "mcp", spec: "@modelcontextprotocol/sdk/client/stdio.js", part: "clientStdioModule" },
    { target: "mcp", spec: "@modelcontextprotocol/sdk/server/streamableHttp.js", part: "serverStreamableHTTPModule" },
  ];
  assert.equal(esmMatch("/app/node_modules/openai/index.mjs", watch)?.target, "openai");
  assert.equal(esmMatch("/app/node_modules/.pnpm/openai@5/node_modules/openai/index.mjs", watch)?.target, "openai");
  assert.equal(esmMatch("/app/node_modules/@langchain/core/dist/callbacks/manager.js", watch)?.target, "langchain");
  assert.equal(esmMatch("/app/node_modules/@modelcontextprotocol/sdk/dist/esm/server/streamableHttp.js", watch)?.part, "serverStreamableHTTPModule");
  assert.equal(esmMatch("/app/node_modules/@modelcontextprotocol/sdk/dist/esm/client/stdio.js", watch)?.part, "clientStdioModule");
  assert.equal(esmMatch("/app/node_modules/@modelcontextprotocol/sdk/dist/esm/client/sse.js", watch), null);
  assert.equal(esmMatch("/app/src/openai.js", watch), null);
});

test("TARGETS rows carry the detect packages and the auto column (one owner for setup and init)", () => {
  for (const t of sb.TARGETS) {
    assert.ok(Array.isArray(t.detect) && t.detect.length > 0, t.name);
    assert.equal(typeof t.auto, "boolean", t.name);
  }
  assert.deepEqual(sb.TARGETS.filter((t) => !t.auto).map((t) => t.name), ["openai-agents"]);
  void trace;
});
