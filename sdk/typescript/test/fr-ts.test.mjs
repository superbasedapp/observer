// Final-review fixes (FR-S01, S04, S10, S11, S12, S15).
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { trace } from "@opentelemetry/api";
import { InMemorySpanExporter, SimpleSpanProcessor } from "@opentelemetry/sdk-trace-base";
import { NodeTracerProvider } from "@opentelemetry/sdk-trace-node";

import * as sb from "../dist/esm/index.js";
import { byName, reset } from "./helpers.mjs";

beforeEach(reset);

test("FR-S01: the file credential never rides to a remote local collector", () => {
  const s = sb.resolveSettings({ SUPERBASED_OTLP_ENDPOINT: "https://vendor.example/v1/traces", SUPERBASED_DESTINATION: "both" });
  const filed = { ...s, apiKey: "ik_1.secret", credentialSource: "file", orgUrl: "https://gw.example" };
  const [local, online] = sb.destinations(filed, "both");
  assert.equal(local.endpoint, "https://vendor.example/v1/traces");
  assert.equal(local.headers.Authorization, undefined);
  assert.equal(online.headers.Authorization, "Bearer ik_1.secret");
  // An explicit env key still goes to a collector the app named (as Python/Go/Java).
  const env = sb.resolveSettings({ SUPERBASED_OTLP_ENDPOINT: "https://vendor.example/v1/traces", SUPERBASED_API_KEY: "k" });
  assert.equal(sb.destinations(env, "local")[0].headers.Authorization, "Bearer k");
});

test("FR-S04: the SDK key replaces any Authorization header on the online exporter; a header alone is not a credential", () => {
  const s = sb.resolveSettings({ SUPERBASED_HEADERS: "x" }, { apiKey: "k", orgUrl: "https://gw.example", headers: { authorization: "Bearer foreign", "X-A": "1" } });
  const [online] = sb.destinations({ ...s, onlineHeaders: { authorization: "Bearer foreign", AUTHORIZATION: "z", "X-A": "1" } }, "online");
  assert.deepEqual(Object.keys(online.headers).filter((k) => k.toLowerCase() === "authorization"), ["Authorization"]);
  assert.equal(online.headers.Authorization, "Bearer k");
  const noKey = { ...s, apiKey: "", onlineHeaders: { Authorization: "Bearer foreign" } };
  assert.equal(sb.onlineUsable(noKey), false);
  assert.deepEqual(sb.destinations(noKey, "online"), []);
  assert.match(sb.destinationProblems(noKey, "online").join(" "), /an SDK credential/);
});

test("FR-S10: an unknown discovered destination warns and falls back to local, keeping the receiver", () => {
  const d = sb.parseDiscovery({
    api_version: 1,
    destination: "mirror",
    local: { enabled: true, otlp_traces_url: "http://127.0.0.1:8081/v1/traces", admission_url: "http://127.0.0.1:8081/api/obs/admit" },
    online: {},
    warnings: ["w1"],
  });
  assert.ok(d);
  assert.equal(d.destination, "local");
  assert.equal(d.localTracesUrl, "http://127.0.0.1:8081/v1/traces");
  assert.equal(d.admissionUrl, "http://127.0.0.1:8081/api/obs/admit");
  assert.equal(d.warnings[0], "w1");
  assert.match(d.warnings.join(" "), /unknown destination "mirror"/);
});

test("FR-S11: attached mode unions init tags with scope tags", async () => {
  const host = new NodeTracerProvider({ spanProcessors: [sb.spanProcessor(), new SimpleSpanProcessor(new InMemorySpanExporter())] });
  host.register();
  const mem = new InMemorySpanExporter();
  sb.init({ exporter: mem, tags: ["init-b", "init-a"] });
  assert.equal(sb.diagnostics().mode, "attached");
  await sb.propagateAttributes({ tags: ["scope", "init-a"] }, async () => {
    sb.withSpan("s", sb.Kind.CHAIN, () => {});
  });
  assert.equal(await sb.flush(5000), true);
  const got = byName(mem.getFinishedSpans());
  assert.deepEqual(got.s.attributes["sbo.tags"], ["init-a", "init-b", "scope"]);
  trace.disable();
});

test("FR-S12: setContent only treats an all-object list as messages and prefers prompt over toolArgs", async () => {
  const mem = new InMemorySpanExporter();
  sb.init({ exporter: mem });
  sb.withLlmSpan("mixed", { model: "m" }, (sp) => sb.setContent(sp, { prompt: ["a", { role: "user" }], response: ["x", "y"] }));
  sb.withLlmSpan("msgs", { model: "m" }, (sp) => sb.setContent(sp, { prompt: [{ role: "user", content: "hi" }] }));
  sb.withLlmSpan("both", { model: "m" }, (sp) => sb.setContent(sp, { prompt: "P", toolArgs: "T" }));
  assert.equal(await sb.flush(5000), true);
  const g = byName(mem.getFinishedSpans());
  assert.equal(g.mixed.attributes["gen_ai.input.messages"], undefined);
  assert.ok(g.mixed.attributes["input.value"]);
  assert.ok(g.mixed.attributes["output.value"]);
  assert.equal(g.mixed.attributes["gen_ai.output.messages"], undefined);
  assert.ok(g.msgs.attributes["gen_ai.input.messages"]);
  assert.equal(g.both.attributes["input.value"], "P");
});

test("FR-S15: the credential file is refused when non-ASCII", { skip: process.platform === "win32" }, () => {
  const dir = mkdtempSync(join(tmpdir(), "sbo-cred-"));
  const f = join(dir, "c");
  writeFileSync(f, "ik_9a.s3crét\n");
  chmodSync(f, 0o600);
  assert.match(sb.readCredentialFile(f).error, /non-ASCII/);
  const ok = join(dir, "ok");
  writeFileSync(ok, "ik_9a.s3cr3t\ngateway_url=https://gw.example\n");
  chmodSync(ok, 0o600);
  assert.equal(sb.readCredentialFile(ok).key, "ik_9a.s3cr3t");
  const link = join(dir, "l");
  symlinkSync(ok, link);
  assert.match(sb.readCredentialFile(link).error, /symlink/);
});
