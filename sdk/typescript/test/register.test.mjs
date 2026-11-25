// Plan 3.3: `@superbased/sdk/register`. An ESM app with no superbased code,
// started with `node --import @superbased/sdk/register`, gets its statically
// imported model library instrumented (openai; and @google/genai, whose
// instrumentation replaces a class export, so the loader hook's writable
// namespace is exercised). A Next.js-style app loads the entry from its
// instrumentation hook on the nodejs runtime only. Each run is a child
// process against one loopback stub that is both the model API and the
// OTLP collector.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { startStub } from "./helpers.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const pkgRoot = join(here, "..");
const nodeMajor = Number(process.versions.node.split(".")[0]);

function needs(...pkgs) {
  for (const pkg of pkgs) {
    const file = join(pkgRoot, "node_modules", ...pkg.split("/"), "package.json");
    if (!existsSync(file)) return `${pkg} is not installed`;
    const m = /^>=\s*(\d+)/.exec(JSON.parse(readFileSync(file, "utf8")).engines?.node ?? "");
    if (m && nodeMajor < Number(m[1])) return `${pkg} needs Node ${m[1]}+`;
  }
  return false;
}

const COMPLETION = {
  id: "chatcmpl-fixture",
  object: "chat.completion",
  created: 1763510400,
  model: "gpt-4o-mini",
  choices: [{ index: 0, finish_reason: "stop", message: { role: "assistant", content: "Paris." } }],
  usage: { prompt_tokens: 10, completion_tokens: 2, total_tokens: 12 },
};
const GEMINI = {
  candidates: [{ content: { role: "model", parts: [{ text: "Paris." }] }, finishReason: "STOP", index: 0 }],
  usageMetadata: { promptTokenCount: 10, candidatesTokenCount: 2, totalTokenCount: 12 },
  modelVersion: "gemini-2.5-flash-001",
  responseId: "resp-fixture",
};

async function stubBoth() {
  const stub = await startStub();
  stub.handler = (r) => {
    if (r.path === "/v1/traces") return { body: {} };
    if (r.path.includes(":generateContent")) return { body: GEMINI };
    return { body: COMPLETION };
  };
  return stub;
}

/** Span names the collector received. */
function spanNames(stub) {
  const out = [];
  for (const r of stub.requests.filter((x) => x.path === "/v1/traces")) {
    for (const rs of r.body.resourceSpans ?? []) for (const ss of rs.scopeSpans ?? []) for (const s of ss.spans ?? []) out.push(s.name);
  }
  return out;
}

function sdkEnv(stub, extra = {}) {
  const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^(SUPERBASED_|OTEL_)/.test(k)));
  return {
    ...env,
    STUB_URL: stub.url,
    SUPERBASED_DESTINATION: "local",
    SUPERBASED_OTLP_ENDPOINT: `${stub.url}/v1/traces`,
    SUPERBASED_DISCOVER: "0",
    SUPERBASED_CREDENTIAL_FILE: join(tmpdir(), "sbo-no-sdk-credential", "x"),
    ...extra,
  };
}

function run(args, opts) {
  return new Promise((resolve) => {
    const cp = spawn(process.execPath, args, { ...opts, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    cp.stdout.on("data", (c) => (stdout += c));
    cp.stderr.on("data", (c) => (stderr += c));
    cp.on("exit", (status) => resolve({ status, stdout, stderr }));
  });
}

const last = (r) => JSON.parse(r.stdout.trim().split("\n").at(-1));

test("an ESM app started with --import @superbased/sdk/register: openai imported statically is instrumented", { skip: needs("openai") }, async () => {
  const stub = await stubBoth();
  try {
    const r = await run(["--import", "@superbased/sdk/register", join(here, "fixtures", "esm-app", "app.mjs")], { cwd: pkgRoot, env: sdkEnv(stub) });
    assert.equal(r.status, 0, r.stderr);
    const out = last(r);
    assert.equal(out.registered.hooked, true);
    assert.ok(out.registered.modules.includes("openai"));
    assert.ok(!out.registered.modules.includes("@openai/agents"), "openai-agents only when named");
    assert.deepEqual(out.instrumented, ["openai"]);
    assert.equal(out.openai, "instrumented");
    assert.equal(out.mode, "owned");
    assert.ok(spanNames(stub).includes("OpenAI Chat Completions"), spanNames(stub).join(","));
  } finally {
    await stub.close();
  }
});

test("register + @google/genai: the class export is replaced through the loader hook's namespace", { skip: needs("@google/genai", "@traceloop/instrumentation-google-generativeai") }, async () => {
  const stub = await stubBoth();
  try {
    const r = await run(["--import", "@superbased/sdk/register", join(here, "fixtures", "esm-app", "gemini.mjs")], { cwd: pkgRoot, env: sdkEnv(stub) });
    assert.equal(r.status, 0, r.stderr);
    const out = last(r);
    assert.equal(out.text, "Paris.");
    assert.equal(out.gemini, "instrumented");
    assert.ok(spanNames(stub).some((n) => n.startsWith("generate_content")), spanNames(stub).join(","));
  } finally {
    await stub.close();
  }
});

test("register with SUPERBASED_INSTRUMENT=off wraps nothing and the app still runs", { skip: needs("openai") }, async () => {
  const stub = await stubBoth();
  try {
    const r = await run(["--import", "@superbased/sdk/register", join(here, "fixtures", "esm-app", "app.mjs")], { cwd: pkgRoot, env: sdkEnv(stub, { SUPERBASED_INSTRUMENT: "off" }) });
    assert.equal(r.status, 0, r.stderr);
    const out = last(r);
    assert.deepEqual(out.registered, { hooked: false, modules: [], reason: "instrument is off" });
    assert.deepEqual(out.instrumented, []);
    assert.ok(!spanNames(stub).includes("OpenAI Chat Completions"));
  } finally {
    await stub.close();
  }
});

test("register with a named list waits for those (openai-agents included when named)", { skip: needs("openai", "@openai/agents") }, async () => {
  const stub = await stubBoth();
  try {
    const r = await run(["--import", "@superbased/sdk/register", join(here, "fixtures", "esm-app", "app.mjs")], { cwd: pkgRoot, env: sdkEnv(stub, { SUPERBASED_INSTRUMENT: "openai,agents" }) });
    assert.equal(r.status, 0, r.stderr);
    const out = last(r);
    assert.deepEqual(out.registered.modules.sort(), ["@openai/agents", "openai"]);
    assert.deepEqual(out.instrumented, ["openai"]);
  } finally {
    await stub.close();
  }
});

/** The Next.js fixture in a temp folder with node_modules links to this SDK and openai. */
function nextApp() {
  const dir = mkdtempSync(join(tmpdir(), "sbo-next-"));
  cpSync(join(here, "fixtures", "next-app"), dir, { recursive: true });
  mkdirSync(join(dir, "node_modules", "@superbased"), { recursive: true });
  symlinkSync(realpathSync(pkgRoot), join(dir, "node_modules", "@superbased", "sdk"), "dir");
  symlinkSync(realpathSync(join(pkgRoot, "node_modules", "openai")), join(dir, "node_modules", "openai"), "dir");
  return dir;
}

test("Next.js: instrumentation.register() on the nodejs runtime instruments the route's openai", { skip: needs("openai") }, async () => {
  const stub = await stubBoth();
  const dir = nextApp();
  try {
    const r = await run([join(dir, "server.mjs")], { cwd: dir, env: sdkEnv(stub, { NEXT_RUNTIME: "nodejs" }) });
    assert.equal(r.status, 0, r.stderr);
    const out = last(r);
    assert.deepEqual(out.answer, { answer: "Paris." });
    assert.equal(out.initialized, true);
    assert.deepEqual(out.instrumented, ["openai"]);
    assert.equal(out.service, "next-shop", "the service name comes from the app's package.json");
    assert.ok(spanNames(stub).includes("OpenAI Chat Completions"), spanNames(stub).join(","));
  } finally {
    await stub.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Next.js: the edge runtime does not load the register entry", { skip: needs("openai") }, async () => {
  const stub = await stubBoth();
  const dir = nextApp();
  try {
    const r = await run([join(dir, "server.mjs")], { cwd: dir, env: sdkEnv(stub, { NEXT_RUNTIME: "edge" }) });
    assert.equal(r.status, 0, r.stderr);
    const out = last(r);
    assert.equal(out.initialized, false);
    assert.deepEqual(out.instrumented, []);
    assert.deepEqual(spanNames(stub), []);
  } finally {
    await stub.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the register entry is ESM only: the CommonJS build has none, the exports map names it", () => {
  const pkg = JSON.parse(readFileSync(join(pkgRoot, "package.json"), "utf8"));
  assert.deepEqual(Object.keys(pkg.exports["./register"]).sort(), ["default", "import", "types"]);
  assert.equal(existsSync(join(pkgRoot, "dist", "esm", "register.js")), true);
  assert.equal(existsSync(join(pkgRoot, "dist", "cjs", "register.js")), false);
});
