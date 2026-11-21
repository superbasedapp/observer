// W3-1 scores/feedback (contracts/scores.md), W3-3 getPrompt (prompts.md),
// W3-2 runExperiment (experiments.md), over the SDK control API.
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { InMemorySpanExporter } from "@opentelemetry/sdk-trace-base";

import * as sb from "../dist/esm/index.js";
import { literalItemId } from "../dist/esm/experiments.js";
import { byName, deadUrl, reset, startStub } from "./helpers.mjs";

beforeEach(reset);

const TRACE = "0af7651916cd43dd8448eb211c80319c";
const contractDir = process.env.SUPERBASED_CONTRACT_DIR || join(dirname(fileURLToPath(import.meta.url)), "..", "..", "contract");
const contract = (f) => (existsSync(join(contractDir, f)) ? JSON.parse(readFileSync(join(contractDir, f), "utf8")) : null);

function quiet() {
  const warn = console.warn;
  console.warn = () => {};
  return () => (console.warn = warn);
}

const accepted = (id = "sc_1") => ({ api_version: "v1", accepted: [{ index: 0, id, client_id: "x" }], rejected: [] });

function online(gw, extra = {}) {
  sb.init({ exporter: new InMemorySpanExporter(), orgUrl: gw.url, apiKey: "sk", destination: "online", ...extra });
}

// --- scores ---------------------------------------------------------------------

test("score() posts the contract body to the gateway with the SDK key and API version", async () => {
  const gw = await startStub();
  try {
    gw.reply(accepted("sc_abc"));
    online(gw);
    const r = await sb.score("Helpfulness", 0.8, { traceId: TRACE.toUpperCase(), comment: "ok", scorer: "judge", scorerVersion: "3", runId: "run_1" });
    assert.equal(r.ok, true);
    assert.equal(r.id, "sc_abc");
    assert.match(r.clientId, /^sdk_[0-9a-f]{32}$/);
    assert.deepEqual(r.destinations, { online: { ok: true, status: 200, id: "sc_abc", error: "" } });
    const req = gw.requests[0];
    assert.equal(req.path, "/v1/sdk/scores");
    assert.equal(req.headers.authorization, "Bearer sk");
    assert.equal(req.headers["x-sbo-sdk-api-version"], "1");
    assert.deepEqual(req.body, {
      id: r.clientId,
      trace_id: TRACE,
      name: "helpfulness",
      value: 0.8,
      kind: "numeric",
      source: "sdk",
      comment: "ok",
      scorer: { name: "judge", version: "3" },
      run_id: "run_1",
    });
    await sb.score("pass", true, { traceId: TRACE, kind: "boolean", scorer: "rule" });
    assert.equal(gw.requests[1].body.kind, "boolean");
    assert.deepEqual(gw.requests[1].body.scorer, { name: "rule", version: "1" }, "scorerVersion defaults to 1");
  } finally {
    await gw.close();
  }
});

test("score() inside a span defaults to that trace, trace-level (no span id), as Python", async () => {
  const gw = await startStub();
  try {
    gw.reply(accepted());
    online(gw);
    let ids;
    await sb.withSpan("answer", async (span) => {
      ids = span.spanContext();
      await sb.score("relevance", 1);
      await sb.score("relevance", 1, { spanId: ids.spanId });
    });
    assert.equal(gw.requests[0].body.trace_id, ids.traceId);
    assert.equal(gw.requests[0].body.span_id, undefined);
    assert.equal(gw.requests[1].body.span_id, ids.spanId);
  } finally {
    await gw.close();
  }
});

test("score() never throws: rule refusals name the contract code; network failures resolve ok:false", async () => {
  online({ url: await deadUrl() });
  const restore = quiet();
  try {
    const cases = [
      [() => sb.score("x", 1), "invalid_trace_id"],
      [() => sb.score("", 1, { traceId: TRACE }), "invalid_name"],
      [() => sb.score("x", NaN, { traceId: TRACE }), "invalid_value"],
      [() => sb.score("x", "two\nlines", { traceId: TRACE }), "invalid_value"],
      [() => sb.score("x", 1, { traceId: TRACE, kind: "boolean" }), "kind_mismatch"],
      [() => sb.score("x", 1, { traceId: TRACE, spanId: "nothex" }), "invalid_span_id"],
      [() => sb.score("x", 1, { traceId: TRACE, comment: "c".repeat(2001) }), "comment_too_long"],
      [() => sb.score("x", 1, { traceId: TRACE, scoreId: "has space" }), "invalid_id"],
      [() => sb.score("x", 1, { traceId: "0".repeat(32) }), "invalid_trace_id"],
    ];
    for (const [fn, code] of cases) {
      const r = await fn();
      assert.equal(r.ok, false, code);
      assert.match(r.errors[0], new RegExp(`^${code}: `));
    }
    const r = await sb.score("x", 1, { traceId: TRACE, timeoutMs: 500 });
    assert.equal(r.ok, false);
    assert.match(r.destinations.online.error, /transport/);
    assert.match(r.errors[0], /^online: transport/);
    assert.ok(sb.diagnostics().controlFailures >= 2, "the attempt and its one retry are counted");
  } finally {
    restore();
  }
});

test("a rejected score is reported, and a 5xx is retried once with the same id", async () => {
  const gw = await startStub();
  const restore = quiet();
  try {
    online(gw);
    gw.reply({ api_version: "v1", accepted: [], rejected: [{ index: 0, error: "invalid_value", message: "too long" }] }, 400);
    const bad = await sb.score("x", "y", { traceId: TRACE });
    assert.equal(bad.ok, false);
    assert.equal(bad.destinations.online.error, "invalid_value: too long");
    gw.queue.push({ status: 503, body: { error: "busy" } });
    gw.reply(accepted());
    const r = await sb.score("x", 1, { traceId: TRACE });
    assert.equal(r.ok, true);
    const [a, b] = gw.requests.slice(-2);
    assert.equal(a.body.id, b.body.id);
  } finally {
    restore();
    await gw.close();
  }
});

test("both: one score goes to the machine (no key) and the gateway (key) with the same id; ok needs every side", async () => {
  const machine = await startStub();
  const gw = await startStub();
  const restore = quiet();
  try {
    machine.reply(accepted("sc_m"));
    gw.reply(accepted("sc_g"));
    sb.init({ exporter: new InMemorySpanExporter(), destination: "both", nodeUrl: machine.url, orgUrl: gw.url, apiKey: "k" });
    const r = await sb.score("x", 2, { traceId: TRACE });
    assert.deepEqual(Object.fromEntries(Object.entries(r.destinations).map(([k, v]) => [k, v.ok])), { local: true, online: true });
    assert.equal(r.ok, true);
    assert.equal(r.id, "sc_g", "the first accepting destination's id, online first (as Python)");
    assert.equal(machine.requests[0].path, "/api/obs/scores");
    assert.equal(machine.requests[0].headers.authorization, undefined);
    assert.equal(gw.requests[0].headers.authorization, "Bearer k");
    assert.equal(machine.requests[0].body.id, gw.requests[0].body.id);
    gw.reply({ error: "forbidden" }, 403);
    const half = await sb.score("x", 3, { traceId: TRACE });
    assert.equal(half.ok, false, "one side refused: not ok (Python's all-destinations rule)");
    assert.equal(half.destinations.local.ok, true);
    assert.equal(half.id, "sc_m");
  } finally {
    restore();
    await machine.close();
    await gw.close();
  }
});

test("feedback() is a score with source feedback; flush() waits for pending writes", async () => {
  const gw = await startStub();
  try {
    gw.delayMs = 100;
    gw.reply(accepted());
    online(gw);
    void sb.feedback(false, { traceId: TRACE, comment: "wrong" });
    assert.equal(await sb.flush(3000), true);
    const b = gw.requests[0].body;
    assert.equal(b.name, "user_feedback");
    assert.equal(b.source, "feedback");
    assert.equal(b.value, false);
    assert.equal(b.comment, "wrong");
  } finally {
    await gw.close();
  }
});

// --- prompts --------------------------------------------------------------------

const PROMPT_BODY = {
  api_version: "v1",
  name: "support-reply",
  version: 3,
  type: "text",
  prompt: "Hello {{customer}}, thanks for writing about {{topic}}.",
  config: { model: "gpt-5.1-mini", temperature: 0.2 },
  labels: ["production"],
  resolved_by: "label:production",
  variables: ["customer", "topic"],
  digest: "sha256:x",
};

test("getPrompt parses the recorded org response, caches it and stamps the span on compile", async () => {
  const gw = await startStub();
  const mem = new InMemorySpanExporter();
  try {
    const recorded = contract("prompt-fetch-response.json");
    gw.reply(recorded?.body ?? PROMPT_BODY, 200, { ETag: recorded?.headers?.Etag ?? '"e3"' });
    sb.init({ exporter: mem, orgUrl: gw.url, apiKey: "k", destination: "online" });
    const p = await sb.getPrompt("support-reply");
    assert.equal(gw.requests[0].path, "/v1/sdk/prompts/support-reply?label=production");
    assert.equal(p.version, 3);
    assert.equal(p.label, "production");
    assert.equal(p.text, "Hello {{customer}}, thanks for writing about {{topic}}.");
    assert.deepEqual(p.variables, ["customer", "topic"]);
    assert.deepEqual(p.config, { model: "gpt-5.1-mini", temperature: 0.2 });
    if (recorded) {
      // R-C34: the four fields Python's Prompt carries.
      assert.equal(p.resolvedBy, "label:production");
      assert.equal(p.commitMessage, "tone fix");
      assert.equal(p.createdAt, "2026-11-19T10:00:00Z");
    }
    assert.equal(p.source, "online");
    await sb.getPrompt("support-reply");
    assert.equal(gw.requests.length, 1, "a fresh entry is served without a request");
    sb.withLlmSpan("chat", {}, () => assert.equal(p.compile({ customer: "Ada", topic: "billing" }), "Hello Ada, thanks for writing about billing."));
    sb.withLlmSpan("ref", { promptRef: p }, () => {});
    // The contract name: the Prompt itself as `prompt` (E-49): a stamp, no content.
    sb.withLlmSpan("asPrompt", { prompt: p }, () => {});
    await sb.flush(3000);
    const g = byName(mem.getFinishedSpans());
    assert.equal(g.asPrompt.attributes["input.value"], undefined, "a registry prompt is not request content");
    assert.equal(g.asPrompt.attributes["gen_ai.input.messages"], undefined);
    for (const n of ["chat", "ref", "asPrompt"]) {
      assert.equal(g[n].attributes["sbo.prompt.name"], "support-reply", n);
      assert.equal(g[n].attributes["sbo.prompt.version"], 3, n);
      assert.equal(g[n].attributes["sbo.prompt.label"], "production", n);
    }
  } finally {
    await gw.close();
  }
});

test("compile follows the shared cases (contract prompt-compile-cases.json)", { skip: !contract("prompt-compile-cases.json") && "contract file not present" }, () => {
  for (const c of contract("prompt-compile-cases.json").cases) {
    assert.deepEqual(sb.promptVariables(c.prompt), c.variables, c.name);
    if (c.missing) {
      assert.throws(() => sb.compilePrompt(c.prompt, c.values), (e) => e instanceof sb.PromptCompileError && JSON.stringify(e.missing) === JSON.stringify(c.missing), c.name);
    } else {
      assert.deepEqual(sb.compilePrompt(c.prompt, c.values), c.want, c.name);
    }
  }
});

test("compile: one pass, missing names sorted, numbers JSON-encoded", () => {
  assert.equal(sb.compilePrompt("{{a}} {{b}}", { a: "{{b}}", b: 2 }), "{{b}} 2");
  // R-B19: null renders as JSON null, as Python's json.dumps(None). (JS has no 1.0: a float that is whole renders "1"; Python "1.0".)
  assert.equal(sb.compilePrompt("{{a}}|{{b}}|{{c}}", { a: null, b: { x: "é" }, c: [1] }), 'null|{"x":"é"}|[1]');
  assert.throws(() => sb.compilePrompt("{{b}} {{a}} {{c}}", { c: "3" }), (e) => e instanceof sb.PromptCompileError && e.missing.join() === "a,b");
});

test("a stale prompt is returned at once and revalidated with If-None-Match; 304 renews, 404 drops", async () => {
  const gw = await startStub();
  try {
    gw.reply({ ...PROMPT_BODY, name: "p", version: 1, prompt: "one" }, 200, { ETag: '"e1"' });
    online(gw);
    await sb.getPrompt("p", { cacheTtlMs: 1 });
    await new Promise((r) => setTimeout(r, 5));
    gw.reply("", 304, { ETag: '"e1"' });
    assert.equal((await sb.getPrompt("p", { cacheTtlMs: 1 })).text, "one");
    await sb.flush(2000);
    assert.equal(gw.requests[1].headers["if-none-match"], '"e1"');
    gw.reply({ ...PROMPT_BODY, name: "p", version: 2, prompt: "two" }, 200, { ETag: '"e2"' });
    await new Promise((r) => setTimeout(r, 5));
    await sb.getPrompt("p", { cacheTtlMs: 1 }); // the old copy; the refresh is in flight
    await sb.flush(2000);
    assert.equal((await sb.getPrompt("p", { cacheTtlMs: 60_000 })).text, "two");
    gw.reply({ error: "prompt_not_found", message: "gone" }, 404);
    await sb.getPrompt("p", { cacheTtlMs: 0 }).catch(() => undefined);
    await assert.rejects(sb.getPrompt("p", { cacheTtlMs: 60_000 }), sb.PromptNotFound, "the 404 dropped the entry");
  } finally {
    await gw.close();
  }
});

test("getPrompt: version selector, chat, cached copy on failure, fallback, 501 and errors", async () => {
  const gw = await startStub();
  const restore = quiet();
  try {
    gw.reply({ ...PROMPT_BODY, name: "c", version: 7, type: "chat", prompt: [{ role: "system", content: "You help {{who}}" }], resolved_by: "version:7" });
    online(gw);
    const chat = await sb.getPrompt("c", { version: 7, cacheTtlMs: 0 });
    assert.equal(gw.requests[0].path, "/v1/sdk/prompts/c?version=7");
    assert.equal(chat.label, "", "a version fetch has no label");
    assert.deepEqual(chat.compile({ who: "devs" }), [{ role: "system", content: "You help devs" }]);
    gw.reply({ error: "unavailable" }, 503);
    assert.equal((await sb.getPrompt("c", { version: 7, cacheTtlMs: 0 })).version, 7, "a cached copy survives a failed refresh");
    gw.reply({ error: "not_implemented" }, 501);
    const fb = await sb.getPrompt("missing", { fallback: "Default {{x}}" });
    assert.equal(fb.isFallback, true);
    assert.equal(fb.compile({ x: 1 }), "Default 1");
    await assert.rejects(sb.getPrompt("missing"), (e) => e instanceof sb.PromptNotFound && /no prompt registry/.test(e.message));
    await assert.rejects(sb.getPrompt("x", { label: "staging", version: 2 }), TypeError);
  } finally {
    restore();
    await gw.close();
  }
});

test("getPrompt on a local destination reads this machine's registry", async () => {
  const machine = await startStub();
  try {
    machine.reply({ ...PROMPT_BODY, name: "n", version: 1, prompt: "local" });
    sb.init({ exporter: new InMemorySpanExporter(), destination: "local", nodeUrl: machine.url });
    assert.equal((await sb.getPrompt("n")).text, "local");
    assert.equal(machine.requests[0].path, "/api/obs/sdk/prompts/n?label=production");
    assert.equal(machine.requests[0].headers.authorization, undefined);
  } finally {
    await machine.close();
  }
});

test("R-B08: under both, a gateway blip plus a machine 404 during revalidation keeps the cached prompt", async () => {
  const gw = await startStub();
  const machine = await startStub();
  const restore = quiet();
  try {
    gw.reply({ ...PROMPT_BODY, name: "org", version: 4, prompt: "from the org" }, 200, { ETag: '"o4"' });
    machine.reply({ error: "prompt_not_found", message: "no such prompt" }, 404);
    sb.init({ exporter: new InMemorySpanExporter(), orgUrl: gw.url, apiKey: "sk", destination: "both", nodeUrl: machine.url, discover: false });
    assert.equal((await sb.getPrompt("org", { cacheTtlMs: 1 })).text, "from the org");
    assert.equal(machine.requests.length, 0, "the gateway answered; the machine was not asked");
    // The gateway fails on revalidation; the machine (which never served it) says 404.
    gw.reply({ error: "unavailable" }, 503);
    await new Promise((r) => setTimeout(r, 5));
    assert.equal((await sb.getPrompt("org", { cacheTtlMs: 1 })).text, "from the org");
    await sb.flush(2000);
    assert.equal(machine.requests.length, 0, "revalidation asks only the destination that served the entry");
    assert.equal((await sb.getPrompt("org", { cacheTtlMs: 60_000 })).text, "from the org", "still cached");
    // ttl 0 revalidates inline: a 503 keeps it, too.
    assert.equal((await sb.getPrompt("org", { cacheTtlMs: 0 })).version, 4);
    // The gateway's OWN 404 drops its entry; the next call asks the machine.
    gw.reply({ error: "prompt_not_found", message: "gone" }, 404);
    machine.reply({ ...PROMPT_BODY, name: "org", version: 1, prompt: "from the machine" });
    assert.equal((await sb.getPrompt("org", { cacheTtlMs: 0 })).text, "from the machine");
  } finally {
    restore();
    await gw.close();
    await machine.close();
  }
});

test("getPrompt: a transport failure everywhere is PromptFetchError; not found everywhere is PromptNotFound; a bad name is a TypeError", async () => {
  const gw = await startStub();
  const restore = quiet();
  try {
    gw.reply({ error: "unavailable" }, 503);
    online(gw);
    await assert.rejects(sb.getPrompt("p"), (e) => e instanceof sb.PromptFetchError && e instanceof sb.PromptError && e.status === 503);
    gw.reply({ error: "label_not_set" }, 404);
    await assert.rejects(sb.getPrompt("p"), (e) => e instanceof sb.PromptNotFound && e instanceof sb.PromptError);
    await assert.rejects(sb.getPrompt("../etc"), TypeError);
    assert.ok(new sb.PromptCompileError(["a"]) instanceof sb.PromptError);
  } finally {
    restore();
    await gw.close();
  }
});

// --- prompts v2: staged rollout on the fetch (prompts.md section 9, lane C8) ---------

test("rollout bucketing follows the shared cases (contract prompt-rollout-cases.json)", { skip: !contract("prompt-rollout-cases.json") && "C8's case file is not on this branch yet" }, () => {
  for (const c of contract("prompt-rollout-cases.json").cases) {
    const h = sb.cohortHash(c.id);
    assert.equal(h, c.hash, c.id);
    assert.equal(sb.rolloutBucket(c.salt, `${c.key}:${h}`), c.bucket, `${c.id} ${c.salt}`);
    assert.equal(sb.rolloutBucket(c.salt, c.subject) < c.percent, c.candidate);
  }
});

test("prompts v2: the cohort key is hashed, each side is cached once, and a changed rollout re-buckets", async () => {
  const gw = await startStub();
  const salt = "prompt|support-reply|production|4";
  // From the shared cases: alice buckets 74, bob 42.
  assert.equal(sb.rolloutBucket(salt, `user:${sb.cohortHash("alice@example.com")}`), 74);
  assert.equal(sb.rolloutBucket(salt, `user:${sb.cohortHash("bob")}`), 42);
  let percent = 50;
  gw.handler = (r) => {
    const q = new URL(r.path, "http://x").searchParams;
    const key = q.get("user_hash") ? "user" : q.get("session_hash") ? "session" : "";
    const subject = key ? `${key}:${q.get(`${key}_hash`)}` : "";
    const cohort = !subject ? "unkeyed" : sb.rolloutBucket(salt, subject) < percent ? "candidate" : "base";
    const version = cohort === "candidate" ? 4 : 3;
    return {
      body: { ...PROMPT_BODY, name: "support-reply", version, prompt: `v${version}`, rollout: { base_version: 3, candidate_version: 4, percent, cohort, key, salt } },
      headers: { ETag: `"${version}-${percent}"` },
    };
  };
  try {
    const mem = new InMemorySpanExporter();
    online(gw, { exporter: mem });
    const alice = await sb.getPrompt("support-reply", { user: "alice@example.com", cacheTtlMs: 60_000 });
    assert.equal(alice.version, 3);
    assert.equal(alice.cohort, "base");
    const q0 = new URL(gw.requests[0].path, "http://x").searchParams;
    assert.equal(q0.get("user_hash"), sb.cohortHash("alice@example.com"), "only the hash leaves the SDK");
    assert.ok(!gw.requests[0].path.includes("alice"));
    // bob: the cached rollout buckets him to the candidate, which is not cached yet: one fetch.
    const bob = await sb.propagateAttributes({ user: "bob" }, () => sb.getPrompt("support-reply", { cacheTtlMs: 60_000 }));
    assert.equal(bob.version, 4);
    assert.equal(bob.cohort, "candidate");
    assert.equal(gw.requests.length, 2);
    // Any other user is served from the cache: no fetch (three entries at most).
    for (const u of ["carol", "dave", "erin", "frank"]) await sb.getPrompt("support-reply", { user: u, cacheTtlMs: 60_000 });
    assert.equal(gw.requests.length, 2);
    // A session is the key when there is no user; unkeyed is its own side (the base).
    await sb.getPrompt("support-reply", { sessionId: "s-1", cacheTtlMs: 60_000 });
    const un = await sb.getPrompt("support-reply", { cacheTtlMs: 60_000 });
    assert.equal(un.cohort, "unkeyed");
    assert.equal(un.version, 3);
    assert.equal(new URL(gw.requests.at(-1).path, "http://x").searchParams.get("user_hash"), null);
    assert.equal(sb.promptCacheSize(), 3);
    // The stamp carries the SERVED version and the cohort.
    sb.withLlmSpan("chat", { promptRef: bob }, () => {});
    await sb.flush(2000);
    const chat = mem.getFinishedSpans().find((x) => x.name === "chat");
    assert.equal(chat.attributes["sbo.prompt.version"], 4);
    assert.equal(chat.attributes["sbo.prompt.cohort"], "candidate");
    // A version fetch ignores the cohort key.
    await sb.getPrompt("support-reply", { version: 3, user: "bob" });
    assert.equal(new URL(gw.requests.at(-1).path, "http://x").searchParams.get("user_hash"), null);
    // The rollout drops to 1%: a revalidation that sees it drops the other sides; bob re-buckets to base.
    percent = 1;
    await new Promise((r) => setTimeout(r, 5));
    const again = await sb.getPrompt("support-reply", { user: "bob", cacheTtlMs: 0 });
    assert.equal(gw.requests.at(-1).headers["if-none-match"], '"4-50"', "revalidated with the key and ETag that filled it");
    assert.equal(again.version, 3, "bob's side changed: he is served the base now");
    assert.equal(again.cohort, "base");
  } finally {
    await gw.close();
  }
});

test("prompts v2 against a v1 server: no rollout object, one side per key", async () => {
  const gw = await startStub();
  try {
    gw.reply({ ...PROMPT_BODY, name: "p", version: 2, prompt: "two" });
    online(gw);
    const a = await sb.getPrompt("p", { user: "alice", cacheTtlMs: 60_000 });
    const b = await sb.getPrompt("p", { user: "bob", cacheTtlMs: 60_000 });
    assert.equal(a.cohort, "");
    assert.equal(b.rollout, null);
    assert.equal(gw.requests.length, 1, "side all: one entry serves every key");
  } finally {
    await gw.close();
  }
});

// --- experiments ----------------------------------------------------------------

function experimentServer(gw, { items, passRate = 0.5, total, prefix = "/v1/sdk", side = "online" } = {}) {
  const posted = { results: [], created: null, finished: null, snapshot: null, datasetCreated: null };
  const P = (p) => prefix + p;
  const L = side === "local";
  gw.handler = (r) => {
    const [path] = r.path.split("?");
    if (r.method === "GET" && path === P(L ? "/eval/datasets" : "/datasets")) return { body: { api_version: "v1", datasets: [{ id: "ds_1", name: "golden" }] } };
    if (r.method === "POST" && path === P(L ? "/eval/datasets" : "/datasets")) {
      posted.datasetCreated = r.body;
      return { status: 201, body: { dataset: { id: "ds_1", name: r.body.name } } };
    }
    if (r.method === "POST" && path === P(L ? "/eval/datasets/ds_1/items" : "/datasets/ds_1/snapshots")) {
      posted.snapshot = r.body;
      items = r.body.items.map((it, i) => ({ item_id: `it_${i + 1}`, client_id: it.id, input: it.input, expected: it.expected, has_content: true }));
      return { status: 201, body: { version: 5, item_count: items.length } };
    }
    if (r.method === "POST" && path === P(L ? "/eval/experiments" : "/experiments")) {
      posted.created = r.body;
      return { status: 201, body: { id: "run_9", dataset_id: "ds_1", snapshot_version: r.body.snapshot_version || 4, item_count: items.length, status: "running" } };
    }
    if (r.method === "GET" && (path === P("/datasets/ds_1/snapshots/4/items") || path === P("/datasets/ds_1/snapshots/5/items") || (L && path === P("/eval/datasets/ds_1/items")))) {
      return { body: { api_version: "v1", items, next_cursor: "" } };
    }
    if (r.method === "POST" && path === P(L ? "/eval/experiments/run_9/results" : "/experiments/run_9/results")) {
      posted.results.push(...r.body.results);
      return { body: { accepted: r.body.results.length, rejected: [] } };
    }
    if (r.method === "POST" && path === P(L ? "/eval/experiments/run_9/finish" : "/experiments/run_9/finish")) {
      posted.finished = r.body;
      return { body: { status: "done" } };
    }
    if (r.method === "GET" && path === P(L ? "/eval/experiments/run_9" : "/experiments/run_9")) return { body: { api_version: "v1", id: "run_9", status: "done", pass_rate: passRate, ...(total === undefined ? {} : { total }) } };
    return { status: 404, body: { error: "not_found" } };
  };
  return posted;
}

test("runExperiment: dataset by name, create run, snapshot items, one trace per item, results, finish, totals", async () => {
  const gw = await startStub();
  const mem = new InMemorySpanExporter();
  try {
    const posted = experimentServer(gw, {
      items: [
        { item_id: "it_1", input: "2+2", expected: "4", has_content: true },
        { item_id: "it_2", input: "3+3", expected: "7", has_content: true },
        { item_id: "it_3", input: "boom", expected: "", has_content: true },
        { item_id: "it_4", has_content: false },
      ],
    });
    sb.init({ exporter: mem, orgUrl: gw.url, apiKey: "k", destination: "online" });
    const res = await sb.withSpan("outer", () =>
      sb.runExperiment({
        name: "prompt-v7",
        dataset: "golden",
        metadata: { git_sha: "abc" },
        task: async (input) => {
          if (input === "boom") throw new Error("task failed");
          return String(eval(String(input)));
        },
        evaluators: [
          function exact_match({ output, expectedOutput }) {
            return output === expectedOutput;
          },
          { name: "multi", version: "2", evaluate: () => [{ name: "len", value: 1 }, 0.5] },
          function broken() {
            throw new Error("evaluator bug");
          },
        ],
      }),
    );
    assert.equal(res.runId, "run_9");
    assert.deepEqual(res.runs, { online: "run_9" });
    assert.equal(res.snapshotVersion, 4);
    assert.equal(res.skippedNoContent, 1);
    assert.equal(res.items.length, 3);
    assert.equal(res.items[2].error, "Error: task failed");
    assert.deepEqual(res.summary.exact_match, { mean: 0.5, count: 2 });
    assert.ok(res.items[0].scores.some((s) => s.name === "broken" && s.error === "evaluator bug"));
    assert.equal(res.recorded, true);
    assert.equal(res.passRate, 0.5);
    // The create carries one idempotency id per call (E-79).
    assert.match(posted.created.id, /^[A-Za-z0-9_.:-]{1,128}$/);
    assert.deepEqual(posted.created, {
      id: posted.created.id,
      name: "prompt-v7",
      dataset_id: "ds_1",
      snapshot_version: 0,
      metadata: { git_sha: "abc" },
      scorers: [{ name: "exact_match", version: "1" }, { name: "multi", version: "2" }, { name: "broken", version: "1" }],
    });
    assert.equal(posted.results.length, 3);
    const r1 = posted.results.find((r) => r.item_id === "it_1");
    assert.equal(r1.output, "4");
    assert.equal(r1.trace_id, res.items[0].traceId);
    assert.deepEqual(r1.scores[0], { name: "exact_match", value: true, scorer: { name: "exact_match", version: "1" } });
    assert.deepEqual(r1.scores[1], { name: "len", value: 1, scorer: { name: "multi", version: "2" } });
    assert.equal(posted.results.find((r) => r.item_id === "it_3").error, "Error: task failed");
    assert.deepEqual(posted.finished, {});
    await sb.flush(3000);
    const runs = mem.getFinishedSpans().filter((s) => s.name === "experiment prompt-v7");
    const outer = mem.getFinishedSpans().find((s) => s.name === "outer");
    assert.equal(runs.length, 3);
    assert.equal(new Set(runs.map((s) => s.spanContext().traceId)).size, 3, "one trace per item");
    assert.ok(runs.every((s) => s.spanContext().traceId !== outer.spanContext().traceId && !s.parentSpanContext));
    assert.equal(runs[0].attributes["sbo.experiment.run_id"], "run_9");
    assert.ok(runs.every((s) => String(s.attributes["sbo.experiment.item_id"]).startsWith("it_")));
    assert.equal(runs.find((s) => s.attributes["sbo.experiment.item_id"] === "it_3").status.code, 2, "a failed task marks its span ERROR");
    assert.equal(gw.requests.filter((r) => r.path === "/v1/sdk/scores").length, 0, "scores ride in the results, not as separate writes");
  } finally {
    await gw.close();
  }
});

test("runExperiment failUnder rejects with ExperimentGateFailed and sets process.exitCode", async () => {
  const gw = await startStub();
  const prev = process.exitCode;
  try {
    experimentServer(gw, { items: [{ item_id: "it_1", input: "x", expected: "y" }], passRate: 0.4 });
    online(gw);
    await assert.rejects(sb.runExperiment({ dataset: "golden", task: (i) => i, evaluators: [() => false], failUnder: 0.9 }), (e) => {
      assert.ok(e instanceof sb.ExperimentGateFailed);
      assert.equal(e.result.passRate, 0.4);
      return true;
    });
    assert.equal(process.exitCode, 1);
  } finally {
    process.exitCode = prev;
    await gw.close();
  }
});

test("R-C31: with strict: false, failUnder is not applied to a run that scored nothing (no evaluators)", async () => {
  const gw = await startStub();
  const prev = process.exitCode;
  const warn = console.warn;
  console.warn = () => {};
  try {
    // An older server answers pass_rate 0 with total 0 for "nothing scored".
    experimentServer(gw, { items: [{ item_id: "it_1", input: "x", expected: "y" }], passRate: 0, total: 0 });
    online(gw);
    const res = await sb.runExperiment({ dataset: "golden", task: (i) => i, evaluators: [], failUnder: 0.9, strict: false });
    assert.equal(res.scored, 0);
    assert.ok(Number.isNaN(res.passRate));
    assert.ok(res.errors.some((e) => e.startsWith("no scores")));
    assert.equal(process.exitCode, prev);
  } finally {
    console.warn = warn;
    process.exitCode = prev;
    await gw.close();
  }
});

test("runExperiment: inline items with datasetName become a literal snapshot; without it nothing is posted", async () => {
  const machine = await startStub();
  try {
    const posted = experimentServer(machine, { items: [], prefix: "/api/obs", side: "local" });
    sb.init({ exporter: new InMemorySpanExporter(), destination: "local", nodeUrl: machine.url });
    const items = [{ id: "a", input: "x", expectedOutput: "x" }, { input: "y", expected: "z" }];
    const same = function same({ output, expected }) {
      return output === expected;
    };
    const res = await sb.runExperiment({ dataset: items, datasetName: "adhoc", task: (i) => i, evaluators: [same] });
    assert.deepEqual(posted.datasetCreated, { name: "adhoc" });
    assert.deepEqual(posted.snapshot.items, [{ id: "a", input: "x", expected: "x" }, { id: literalItemId("y", "z"), input: "y", expected: "z" }]);
    assert.deepEqual(posted.results.map((r) => r.item_id).sort(), ["it_1", "it_2"]);
    assert.equal(res.recorded, true);
    const before = machine.requests.length;
    const local = await sb.runExperiment({ dataset: items, task: (i) => i, evaluators: [same] });
    assert.equal(machine.requests.length, before, "in-process only");
    assert.equal(local.recorded, false);
    assert.equal(local.passRate, 0.5);
  } finally {
    await machine.close();
  }
});

test("runExperiment under both: the task runs once, results go to each side by matched item id", async () => {
  const machine = await startStub();
  const gw = await startStub();
  try {
    const onl = experimentServer(gw, { items: [{ item_id: "it_on", client_id: "q1", input: "a", expected: "a" }] });
    const loc = experimentServer(machine, { items: [{ item_id: "it_lo", input: "a", expected: "a" }], prefix: "/api/obs", side: "local" });
    sb.init({ exporter: new InMemorySpanExporter(), destination: "both", nodeUrl: machine.url, orgUrl: gw.url, apiKey: "k" });
    let calls = 0;
    const res = await sb.runExperiment({ dataset: "golden", task: (i) => (calls++, i), evaluators: [() => true] });
    assert.equal(calls, 1);
    assert.deepEqual(res.runs, { online: "run_9", local: "run_9" });
    assert.deepEqual(onl.results.map((r) => r.item_id), ["it_on"]);
    assert.deepEqual(loc.results.map((r) => r.item_id), ["it_lo"], "matched by input");
    assert.equal(onl.results[0].trace_id, loc.results[0].trace_id);
  } finally {
    await machine.close();
    await gw.close();
  }
});

const SCOPE_REFUSED = { error: "insufficient_scope", message: "this credential lacks the sdk:eval scope" };

// Review E-12 (ruling D29): with failUnder set the gate is strict by default.
for (const kind of ["nothing scored", "every evaluator throws", "a skipped side", "a failed post"]) {
  test(`E-12: a strict failUnder gate fails on ${kind}; strict: false does not`, async () => {
    const machine = await startStub();
    const gw = await startStub();
    const restore = quiet();
    const prev = process.exitCode;
    try {
      const items = [{ item_id: "it_lo", client_id: "q1", input: "a", expected: "a" }];
      let evaluators = [() => true];
      if (kind === "a skipped side") {
        gw.reply(SCOPE_REFUSED, 403);
        experimentServer(machine, { items, prefix: "/api/obs", side: "local", passRate: 1, total: 1 });
        sb.init({ exporter: new InMemorySpanExporter(), destination: "both", nodeUrl: machine.url, orgUrl: gw.url, apiKey: "member-key" });
      } else {
        experimentServer(gw, { items, passRate: 1, total: kind === "a failed post" ? 1 : 0 });
        online(gw);
        if (kind === "nothing scored") evaluators = [];
        if (kind === "every evaluator throws")
          evaluators = [
            () => {
              throw new Error("judge API down");
            },
          ];
        if (kind === "a failed post") {
          const inner = gw.handler;
          gw.handler = (r) => (r.path.endsWith("/results") ? { status: 500, body: { error: "boom" } } : inner(r));
        }
      }
      const opts = { dataset: "golden", task: (i) => i, evaluators, failUnder: 0.9 };
      await assert.rejects(sb.runExperiment(opts), (e) => {
        assert.ok(e instanceof sb.ExperimentGateFailed, String(e));
        assert.ok(e.reasons.length >= 1, e.message);
        assert.match(e.message, /cannot pass/);
        return true;
      });
      assert.equal(process.exitCode, 1);
      process.exitCode = prev;
      const res = await sb.runExperiment({ ...opts, strict: false });
      assert.equal(process.exitCode, prev, `${kind}: strict false gates on the rate alone`);
      if (kind === "a skipped side") assert.deepEqual(res.skippedSides, ["online"]);
      if (kind === "a failed post") assert.equal(res.failedPosts, 1);
    } finally {
      restore();
      process.exitCode = prev;
      await machine.close();
      await gw.close();
    }
  });
}

for (const shape of ["by name", "literal"]) {
  test(`R-B10 (${shape}): the org's 403 insufficient_scope skips the org with an error; the machine side runs`, async () => {
    const machine = await startStub();
    const gw = await startStub();
    const restore = quiet();
    try {
      gw.reply(SCOPE_REFUSED, 403); // a member key: every org dataset and experiment route refuses
      const loc = experimentServer(machine, { items: [{ item_id: "it_lo", client_id: "q1", input: "a", expected: "a" }], prefix: "/api/obs", side: "local" });
      sb.init({ exporter: new InMemorySpanExporter(), destination: "both", nodeUrl: machine.url, orgUrl: gw.url, apiKey: "member-key" });
      const res = await sb.runExperiment(
        shape === "by name"
          ? { dataset: "golden", task: (i) => i, evaluators: [() => true] }
          : { dataset: [{ id: "q1", input: "a", expected: "a" }], datasetName: "golden", task: (i) => i, evaluators: [() => true] },
      );
      assert.deepEqual(res.runs, { local: "run_9" });
      assert.equal(res.items.length, 1);
      // A literal upload re-numbers the items on the machine (it_1, ...).
      assert.deepEqual(loc.results.map((r) => r.item_id), [shape === "by name" ? "it_lo" : "it_1"]);
      assert.ok(loc.finished, "the machine run is finished");
      const skips = res.errors.filter((e) => e.startsWith("online: skipped"));
      assert.equal(skips.length, 1, res.errors.join(" | "));
      assert.match(skips[0], /insufficient_scope/);
      assert.match(skips[0], /sdk:eval/);
      assert.ok(!gw.requests.some((r) => r.path.startsWith("/v1/sdk/experiments")), "no run is created on the org");
    } finally {
      restore();
      await machine.close();
      await gw.close();
    }
  });
}

test("R-B10: online only, a scope refusal resolves with an empty run and the reason (never rejects)", async () => {
  const gw = await startStub();
  const restore = quiet();
  try {
    gw.reply(SCOPE_REFUSED, 403);
    online(gw);
    const res = await sb.runExperiment({ dataset: "golden", task: (i) => i, evaluators: [() => true] });
    assert.deepEqual(res.runs, {});
    assert.equal(res.items.length, 0);
    assert.equal(res.recorded, false);
    assert.equal(res.errors.length, 1);
    assert.match(res.errors[0], /^online: skipped, dataset list refused: .*insufficient_scope/);
  } finally {
    restore();
    await gw.close();
  }
});

test("R-B10: the org lists the dataset but refuses the run: skipped, the machine still runs", async () => {
  const machine = await startStub();
  const gw = await startStub();
  const restore = quiet();
  try {
    experimentServer(gw, { items: [{ item_id: "it_on", client_id: "q1", input: "a", expected: "a" }] });
    const inner = gw.handler;
    gw.handler = (r) => (r.method === "POST" && r.path.split("?")[0] === "/v1/sdk/experiments" ? { status: 403, body: SCOPE_REFUSED } : inner(r));
    const loc = experimentServer(machine, { items: [{ item_id: "it_lo", input: "a", expected: "a" }], prefix: "/api/obs", side: "local" });
    sb.init({ exporter: new InMemorySpanExporter(), destination: "both", nodeUrl: machine.url, orgUrl: gw.url, apiKey: "member-key" });
    const res = await sb.runExperiment({ dataset: "golden", task: (i) => i, evaluators: [() => true] });
    assert.deepEqual(res.runs, { local: "run_9" });
    assert.deepEqual(loc.results.map((r) => r.item_id), ["it_lo"]);
    assert.ok(res.errors.some((e) => e.startsWith("online: skipped, experiment create refused")), res.errors.join(" | "));
  } finally {
    restore();
    await machine.close();
    await gw.close();
  }
});

test("runExperiment rejects when the dataset is nowhere; getDataset reads a snapshot", async () => {
  const gw = await startStub();
  const restore = quiet();
  try {
    experimentServer(gw, { items: [{ item_id: "it_1", input: "q", expected: "a", metadata: { tag: "x" } }] });
    online(gw);
    await assert.rejects(sb.runExperiment({ dataset: "nope", task: (i) => i }), (e) => e instanceof sb.ExperimentError && /not found on any destination/.test(e.message));
    const ds = await sb.getDataset("golden", { version: 4 });
    assert.equal(ds.id, "ds_1");
    assert.deepEqual(ds.items, [{ id: "it_1", input: "q", expectedOutput: "a", metadata: { tag: "x" } }]);
    // R-C34 (ruling D29): a dataset that is nowhere rejects, as in Python.
    await assert.rejects(sb.getDataset("nope"), (e) => e instanceof sb.ExperimentError && /dataset "nope" not found/.test(e.message));
  } finally {
    restore();
    await gw.close();
  }
});

test("R-C34: getPrompt refuses an unknown label; a degraded online is a PromptFetchError, not PromptNotFound", async () => {
  process.env.SUPERBASED_DISCOVER = "0";
  sb.init({ exporter: new InMemorySpanExporter(), destination: "online" });
  await assert.rejects(sb.getPrompt("p", { label: "prod" }), RangeError);
  await assert.rejects(sb.getPrompt("p"), (e) => {
    assert.ok(e instanceof sb.PromptFetchError && !(e instanceof sb.PromptNotFound), e.name);
    assert.match(e.message, /no destination for this call/);
    return true;
  });
  const fb = await sb.getPrompt("p", { fallback: "hi" });
  assert.equal(fb.isFallback, true);
  assert.equal(fb.source, "fallback");
});

test("R-C34: a degraded online keeps a literal run in-process and refuses a dataset by name, as Python", async () => {
  process.env.SUPERBASED_DISCOVER = "0";
  sb.init({ exporter: new InMemorySpanExporter(), destination: "online" });
  const res = await sb.runExperiment({ dataset: [{ input: 1 }, { input: 2 }], datasetName: "adhoc", task: (i) => i * 2, evaluators: [({ output }) => output > 2] });
  assert.equal(res.runId, "");
  assert.deepEqual(res.items.map((i) => i.output).sort(), [2, 4]);
  assert.ok(res.errors.some((e) => e.includes("in-process only") && e.includes("no destination for this call")), res.errors.join("; "));
  await assert.rejects(sb.runExperiment({ dataset: "golden", task: (i) => i }), (e) => e instanceof sb.ExperimentError && /no destination for this call/.test(e.message));
});

// A machine that answers as the Go server: a literal upload is deduplicated by
// client id (a duplicate answers its EXISTING item), the upload answers
// item_ids, a run created with item_ids is pinned to them, and
// GET .../items?run= reads a run's own items.
function fakeMachine(stub) {
  const m = { items: [], runs: {}, results: {} };
  stub.handler = (r) => {
    const [path, qs] = r.path.split("?");
    const q = Object.fromEntries(new URLSearchParams(qs ?? ""));
    const p = "/api/obs/eval";
    if (path === `${p}/datasets` && r.method === "GET") return { body: { datasets: [{ id: "9", name: "adhoc" }] } };
    if (path === `${p}/datasets` && r.method === "POST") return { body: { id: "9", name: "adhoc" } };
    if (path === `${p}/datasets/9/items` && r.method === "POST") {
      const ids = r.body.items.map((it) => {
        let hit = m.items.find((x) => x.client_id === it.id);
        if (!hit) {
          hit = { item_id: String(m.items.length + 1), client_id: it.id, input: it.input, expected: it.expected, has_content: true };
          m.items.push(hit);
        }
        return hit.item_id;
      });
      return { body: { version: m.items.length, item_ids: ids } };
    }
    if (path === `${p}/datasets/9/items` && r.method === "GET") {
      const pinned = m.runs[q.run]?.item_ids;
      return { body: { items: m.items.filter((x) => !pinned || pinned.includes(x.item_id)), next_cursor: "" } };
    }
    if (path === `${p}/experiments` && r.method === "POST") {
      const rid = String(100 + Object.keys(m.runs).length);
      m.runs[rid] = r.body;
      m.results[rid] = [];
      return { status: 201, body: { id: rid, snapshot_version: m.items.length } };
    }
    const res = path.match(/^\/api\/obs\/eval\/experiments\/(\d+)\/results$/);
    if (res) {
      m.results[res[1]].push(...r.body.results);
      return { body: { accepted: r.body.results.length, rejected: [] } };
    }
    if (path.startsWith(`${p}/experiments/`)) return { body: { id: "x", total: 0 } };
    return undefined;
  };
  return m;
}

test("a literal re-run with changed inputs runs and records the new inputs (E-75)", async () => {
  const stub = await startStub();
  try {
    const m = fakeMachine(stub);
    sb.init({ exporter: new InMemorySpanExporter(), nodeUrl: stub.url, destination: "local", discover: false });
    const seen = [];
    const task = (input) => {
      seen.push(input);
      return input;
    };
    await sb.runExperiment({ dataset: [{ input: "old-a" }, { input: "old-b" }], datasetName: "adhoc", task });
    seen.length = 0;
    const res = await sb.runExperiment({ dataset: [{ input: "new-a" }, { input: "new-b" }], datasetName: "adhoc", task });
    assert.deepEqual(seen.sort(), ["new-a", "new-b"]);
    const create = m.runs[res.runId];
    assert.equal(create.item_ids.length, 2, "the run is pinned to this upload's items");
    const posted = new Set(m.results[res.runId].map((r) => r.item_id));
    assert.deepEqual([...posted].sort(), [...create.item_ids].sort(), "results go to the new items, not the old ids");
    const byId = Object.fromEntries(m.items.map((x) => [x.item_id, x.input]));
    assert.deepEqual(create.item_ids.map((i) => byId[i]).sort(), ["new-a", "new-b"]);
  } finally {
    await stub.close();
  }
});

test("runExperiment reads the contract's snapshotVersion, and still datasetVersion (E-49)", async () => {
  const stub = await startStub();
  try {
    const created = [];
    stub.handler = (r) => {
      const path = r.path.split("?")[0];
      if (path === "/api/obs/eval/datasets") return { body: { datasets: [{ id: "7", name: "golden" }] } };
      if (path === "/api/obs/eval/experiments" && r.method === "POST") {
        created.push(r.body);
        return { status: 201, body: { id: String(created.length), snapshot_version: r.body.snapshot_version } };
      }
      if (path === "/api/obs/eval/datasets/7/items") return { body: { items: [], next_cursor: "" } };
      return { body: {} };
    };
    sb.init({ exporter: new InMemorySpanExporter(), nodeUrl: stub.url, destination: "local", discover: false });
    await sb.runExperiment({ dataset: "golden", task: (x) => x, snapshotVersion: 4 });
    await sb.runExperiment({ dataset: "golden", task: (x) => x, datasetVersion: 5 });
    assert.deepEqual(created.map((b) => b.snapshot_version), [4, 5]);
  } finally {
    await stub.close();
  }
});
