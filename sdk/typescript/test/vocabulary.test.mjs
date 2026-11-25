// Principle 2: the SDK writes no attribute key outside the Observer
// vocabulary (contract sdk-api-surface.md section 9).
// - Every key in attrs.ts is a string literal in internal/genaiattr or
//   internal/otelident, or an SDK-owned sbo.* key.
// - Every key the SDK actually emits is listed in
//   sdk/contract/sdk-attribute-keys.json (B2's machine-readable list).
// - The content keys equal that file's content keys.
// Skipped where the Go sources or the contract file are absent (an
// installed package, a gate's copy); SUPERBASED_REPO_ROOT and
// SUPERBASED_CONTRACT_DIR point at the repo and sdk/contract.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { trace } from "@opentelemetry/api";
import { InMemorySpanExporter } from "@opentelemetry/sdk-trace-base";

import * as sb from "../dist/esm/index.js";
import { CONTENT_KEYS, CONTENT_PREFIXES, CONTENT_PREFIX_EXEMPT_SUFFIXES, EXTRA_CONTENT_PREFIXES, isContentKey } from "../dist/esm/attrs.js";
import { reset } from "./helpers.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const repo = process.env.SUPERBASED_REPO_ROOT || join(here, "..", "..", "..");
const dirs = ["internal/genaiattr", "internal/otelident"].map((d) => join(repo, d));
const goPresent = dirs.every((d) => existsSync(d));
const keysFile = join(process.env.SUPERBASED_CONTRACT_DIR || join(here, "..", "..", "contract"), "sdk-attribute-keys.json");
const contract = existsSync(keysFile) ? JSON.parse(readFileSync(keysFile, "utf8")) : null;

const SDK_OWNED = new Set([
  "sbo.sdk",
  "sbo.admission.allowed",
  "sbo.admission.decision",
  "sbo.admission.verdict_id",
  "sbo.admission.degraded",
  "sbo.experiment.run_id",
  "sbo.experiment.item_id",
  // The setup hello span (sdk-api-surface.md section 17).
  "sbo.setup.hello",
]);

// The prompt stamp keys, all in the Go vocabulary now (review R-C34: the
// cohort key left "pending_vocabulary").
const PROMPT_KEYS = ["sbo.prompt.name", "sbo.prompt.version", "sbo.prompt.label", "sbo.prompt.cohort"];

function goLiterals() {
  const out = new Set();
  for (const d of dirs) {
    for (const f of readdirSync(d)) {
      if (!f.endsWith(".go") || f.endsWith("_test.go")) continue;
      for (const m of readFileSync(join(d, f), "utf8").matchAll(/"([^"\n]+)"/g)) out.add(m[1]);
    }
  }
  return out;
}

test("every key in attrs.ts is in internal/genaiattr or internal/otelident, or SDK-owned", { skip: !goPresent && "Go sources not present" }, () => {
  const lit = goLiterals();
  const keys = [...Object.values(sb.Attr), ...Object.values(sb.REQUEST_PARAMS)];
  const missing = keys.filter((k) => !SDK_OWNED.has(k) && !lit.has(k) && !lit.has(k.replace(/\.$/, "")));
  for (const k of CONTENT_KEYS) if (!lit.has(k)) missing.push(`content:${k}`);
  for (const p of CONTENT_PREFIXES) if (![...lit].some((l) => l === p.replace(/\.$/, "") || l.startsWith(p))) missing.push(`prefix:${p}`);
  assert.deepEqual(missing, []);
  assert.ok(lit.has(sb.SEMCONV_COMMIT) && lit.has(sb.SEMCONV_SCHEMA_URL), "semconv pin matches genaiattr");
});

test("the content keys equal sdk-attribute-keys.json's", { skip: !contract && "contract file not present" }, () => {
  assert.deepEqual([...CONTENT_KEYS].sort(), [...contract.content_keys].sort());
  assert.deepEqual([...CONTENT_PREFIXES].sort(), [...contract.content_prefixes].sort());
  assert.deepEqual([...CONTENT_PREFIX_EXEMPT_SUFFIXES].sort(), [...contract.content_prefix_exempt_suffixes].sort());
  // R-C32: the mask-only list is the contract's, so no instrumentation content leaks.
  assert.deepEqual([...EXTRA_CONTENT_PREFIXES].sort(), [...contract.extra_content_prefixes].sort());
  assert.deepEqual([...SDK_OWNED].sort(), [...contract.sdk_owned].sort());
  for (const k of PROMPT_KEYS) assert.ok(contract.vocabulary.includes(k), k);
  assert.deepEqual(contract.pending_vocabulary ?? [], []);
  assert.equal(sb.SEMCONV_COMMIT, contract.semconv_commit);
  assert.deepEqual(
    [sb.LIMITS.valueLen, sb.LIMITS.tags, sb.LIMITS.tagLen, sb.LIMITS.metadataKeys, sb.LIMITS.metadataKeyLen, sb.LIMITS.metadataValueLen],
    [contract.limits.max_value_len, contract.limits.max_tags, contract.limits.max_tag_len, contract.limits.max_metadata_keys, contract.limits.max_metadata_key_len, contract.limits.max_metadata_value_len],
  );
});

test("every key the SDK emits is listed in sdk-attribute-keys.json", { skip: !contract && "contract file not present" }, async () => {
  await reset();
  const listed = new Set([...contract.vocabulary, ...contract.sdk_owned, ...(contract.pending_vocabulary ?? [])]);
  const prefixes = [...contract.vocabulary_prefixes, ...contract.sdk_owned_prefixes];
  const mem = new InMemorySpanExporter();
  sb.init({ exporter: mem, user: "u", sessionId: "s", tenant: "t", tags: ["a"], metadata: { k: "v" }, release: "r", environment: "e" });
  const prompt = new sb.Prompt("p", 1, "production", "text", "x");
  await sb.propagateAttributes({ user: "u2", sessionId: "s2", tenant: "t2", tags: ["b"], metadata: { m: 1 }, release: "r2", environment: "e2" }, async () => {
    await sb.withAgentSpan("agent", { agentId: "id" }, async (agent) => {
      sb.setInput(agent, "in");
      sb.setOutput(agent, "out");
      sb.withLlmSpan("llm", { model: "m", provider: "p", prompt: "hi", system: "s", promptRef: prompt }, (sp) => {
        sb.setUsage(sp, { inputTokens: 1, outputTokens: 1, totalTokens: 2, cacheReadTokens: 1, cacheWriteTokens: 0, reasoningTokens: 0, responseId: "r", requestId: "q", responseModel: "m2", finishReasons: ["stop"], costUsd: 0.1, response: "ok" });
        sb.setRequestParams(sp, { maxTokens: 1, temperature: 0, topP: 1, topK: 1, stopSequences: ["x"], frequencyPenalty: 0, presencePenalty: 0, seed: 1, stream: false, reasoningLevel: "low" });
        sb.setContent(sp, { prompt: [{ role: "user", content: "x" }], response: [{ role: "assistant", content: "y" }] });
      });
      sb.withToolSpan("tool", { toolName: "t", callId: "c", arguments: { a: 1 } }, (sp) => sb.setToolResult(sp, "r"));
      sb.withRetrieverSpan("ret", { query: "q" }, (sp) => sb.setDocuments(sp, ["d"]));
      sb.withEmbeddingSpan("emb", { model: "m", provider: "p" }, () => {});
      try {
        sb.withSpan("bad", () => {
          throw new Error("x");
        });
      } catch {
        // expected
      }
    });
  });
  // the runExperiment root stamp
  sb.withSpan("exp", { attributes: { [sb.Attr.experimentRunId]: "r", [sb.Attr.experimentItemId]: "i" } }, () => {});
  assert.equal(await sb.flush(3000), true);
  const unlisted = new Set();
  for (const s of mem.getFinishedSpans()) {
    for (const k of [...Object.keys(s.attributes), ...Object.keys(s.resource.attributes)]) {
      if (k.startsWith("telemetry.sdk.") || k === "service.name" || k.startsWith("process.") || k.startsWith("host.")) continue;
      if (!listed.has(k) && !prefixes.some((p) => k.startsWith(p))) unlisted.add(k);
    }
  }
  assert.deepEqual([...unlisted], []);
  void trace;
});

test("R-C32: every extra content prefix is masked, exact keys and nested keys alike", { skip: !contract && "contract file not present" }, () => {
  for (const p of contract.extra_content_prefixes) {
    const keys = p.endsWith(".") ? [`${p}0`, `${p}0.text`, `${p}0.role`] : [p, `${p}.0`, `${p}.0.role`];
    for (const key of keys) assert.ok(isContentKey(key), key);
  }
  assert.ok(!isContentKey("gen_ai.prompt.0.role"), "a structural member of a vocabulary prefix stays");
  assert.ok(!isContentKey("llm.model_name"));
});
