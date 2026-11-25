import { test } from "node:test";
import assert from "node:assert/strict";
import {
  JUDGE_SOURCE_WORDS,
  LANE_PROVIDERS,
  clientBaseUrl,
  clientFamily,
  cleanModels,
  judgeLine,
  judgeOffersOrg,
  judgeSourceOf,
  keyEnvFor,
  laneCli,
  laneIdError,
  laneInput,
  laneSnippet,
  laneWriteError,
  lanesOf,
  modelsText,
  providerForLane,
  serviceError,
  type AppLane,
} from "./modelCalls.ts";

const OPENAI: AppLane = { id: "openai", upstream: "https://api.openai.com", base_url: "http://127.0.0.1:8820/up/openai" };
const ANTHROPIC: AppLane = { id: "anthropic", upstream: "https://api.anthropic.com", base_url: "http://127.0.0.1:8820/up/anthropic/" };

test("lane ids follow the path-segment rule and are unique", () => {
  const cases: [string, string[], boolean][] = [
    ["openai", [], true],
    ["a", [], true],
    ["my-lane-2", [], true],
    ["", [], false],
    ["-lead", [], false],
    ["Upper", [], false],
    ["has space", [], false],
    ["x".repeat(32), [], true],
    ["x".repeat(33), [], false],
    ["openai", ["openai"], false],
  ];
  for (const [id, existing, ok] of cases) assert.equal(laneIdError(id, existing) === "", ok, id);
});

test("an optional service follows the app key rule", () => {
  assert.equal(serviceError(""), "");
  assert.equal(serviceError("Support-Bot"), "");
  assert.equal(serviceError("billing/api:v2"), "");
  assert.notEqual(serviceError("*"), "");
  assert.notEqual(serviceError("sa:svc"), "");
  assert.notEqual(serviceError("has space"), "");
  assert.notEqual(serviceError("x".repeat(129)), "");
});

test("providers are known public hosts with distinct ids", () => {
  const ids = LANE_PROVIDERS.map((p) => p.id);
  assert.equal(new Set(ids).size, ids.length);
  for (const p of LANE_PROVIDERS) {
    assert.match(p.upstream, /^https:\/\//, p.id);
    assert.equal(new URL(p.upstream).host, p.host, p.id);
    assert.equal(laneIdError(p.id), "", `${p.id} is a valid suggested lane id`);
  }
});

test("the client base URL: the daemon's when given, else the lane plus the client path", () => {
  assert.equal(clientBaseUrl(OPENAI), "http://127.0.0.1:8820/up/openai/v1");
  assert.equal(clientBaseUrl(ANTHROPIC), "http://127.0.0.1:8820/up/anthropic");
  assert.equal(clientBaseUrl({ ...OPENAI, client_base_url: "http://x/y" }), "http://x/y");
  assert.equal(clientFamily({ upstream: "https://example.com", client: "anthropic" }), "anthropic");
  assert.equal(clientFamily({ upstream: "https://example.com" }), "openai");
  assert.equal(providerForLane({ upstream: "https://openrouter.ai/api" })?.id, "openrouter");
});

test("the add body carries only what was set", () => {
  assert.deepEqual(laneInput({ id: " openai ", provider: "openai", models: [], service: "" }), {
    id: "openai",
    upstream: "https://api.openai.com",
  });
  assert.deepEqual(laneInput({ id: "a", provider: "anthropic", models: [" m1", "m1", ""], service: " Bot " }), {
    id: "a",
    upstream: "https://api.anthropic.com",
    models: ["m1"],
    service: "bot",
  });
  assert.equal(laneInput({ id: "a", provider: "nope", models: [], service: "" }), null);
  assert.deepEqual(cleanModels(["b", " a", "b"]), ["b", "a"]);
});

test("models text: any model, one name, or a count", () => {
  assert.equal(modelsText({}), "Any model");
  assert.equal(modelsText({ models: null }), "Any model");
  assert.equal(modelsText({ models: ["gpt-5-nano"] }), "gpt-5-nano");
  assert.equal(modelsText({ models: ["a", "b"] }), "2 models");
});

test("snippets point the client at the lane and read the app's own provider key", () => {
  for (const lane of [OPENAI, ANTHROPIC, { ...OPENAI, service: "Support-Bot", models: ["gpt-5-mini"] }]) {
    for (const lang of ["python", "typescript", "curl"] as const) {
      const s = laneSnippet(lane, lang);
      assert.ok(s.includes(clientBaseUrl(lane)), `${lane.id} ${lang}: base URL`);
      assert.ok(s.includes(keyEnvFor(lane)), `${lane.id} ${lang}: key env`);
      assert.ok(!/sbo-vk-|sk-[a-z0-9]/i.test(s), `${lane.id} ${lang}: no literal key`);
      if (lane.service) assert.ok(s.includes("support-bot") && s.includes("X-Superbased-Service"), `${lang}: service header`);
      else assert.ok(!s.includes("X-Superbased-Service"), `${lang}: no service header`);
    }
  }
  assert.ok(laneSnippet(ANTHROPIC, "curl").includes("/v1/messages"));
  assert.ok(laneSnippet(OPENAI, "curl").includes("/v1/chat/completions"));
  assert.ok(laneSnippet({ ...OPENAI, models: ["gpt-5-mini"] }, "curl").includes("gpt-5-mini"));
  assert.ok(laneSnippet(ANTHROPIC, "python").includes("from anthropic import Anthropic"));
  assert.ok(laneSnippet(OPENAI, "typescript").includes('import OpenAI from "openai"'));
});

test("lanesOf sorts and tolerates an older daemon's null", () => {
  assert.deepEqual(lanesOf(null), []);
  assert.deepEqual(lanesOf({ lanes: null }), []);
  assert.deepEqual(lanesOf({ lanes: [OPENAI, ANTHROPIC] }).map((l) => l.id), ["anthropic", "openai"]);
});

test("the CLI twin of the add form", () => {
  assert.equal(laneCli(null), "observer apps lane add <id> --upstream <url>");
  assert.equal(
    laneCli({ id: "openai", upstream: "https://api.openai.com", models: ["a"], service: "bot" }),
    "observer apps lane add openai --upstream https://api.openai.com --model a --service bot",
  );
});

test("a refused write shows the daemon's sentence", () => {
  assert.equal(laneWriteError('{"error":"lane exists"}'), "lane exists");
  assert.equal(laneWriteError('{"error":"bad","message":"The id is taken."}'), "The id is taken.");
  assert.equal(laneWriteError("plain text\n"), "plain text");
});

test("the judge in effect: source words, sentence and the org offer", () => {
  for (const s of ["machine", "org_relay", "none"] as const) {
    const w = JUDGE_SOURCE_WORDS[s];
    assert.ok(w.label && !/_/.test(w.label), s);
  }
  assert.equal(judgeSourceOf(null), "none");
  assert.equal(judgeSourceOf({ judge: { source: "weird" } }), "none");
  assert.equal(judgeSourceOf({ judge: { source: "org_relay" } }), "org_relay");
  assert.match(judgeLine({ judge: { source: "machine", model: "qwen", base_url_host: "127.0.0.1:11434" } }), /qwen at 127\.0\.0\.1:11434/);
  assert.match(judgeLine({ judge: { source: "org_relay" } }), /organization/);
  assert.match(judgeLine({ judge: null }), /not judged/);
  assert.equal(judgeOffersOrg({ judge: { source: "machine", enrolled: true, org_judge_available: true } }), true);
  assert.equal(judgeOffersOrg({ judge: { source: "org_relay", enrolled: true, org_judge_available: true } }), false);
  assert.equal(judgeOffersOrg({ judge: { source: "none", enrolled: false, org_judge_available: true } }), false);
});
