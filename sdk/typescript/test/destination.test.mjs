// W2-7 destination (D18, contract destination.md): local, online, both;
// discovery over loopback; the credential file; degraded cases; admit().
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import * as sb from "../dist/esm/index.js";
import { deadUrl, reset, startStub } from "./helpers.mjs";

beforeEach(reset);

const otlp = (stub) => stub.requests.filter((r) => r.path === "/v1/traces");

function discovery(over = {}) {
  return {
    api_version: 1,
    destination: "local",
    source: "default_not_signed_in",
    configured: "",
    signed_in: false,
    local: { enabled: true, otlp_traces_url: "", admission_url: "" },
    online: { gateway_url: "", credential_present: false, credential_file: "" },
    warnings: [],
    ...over,
  };
}

function quiet() {
  const warn = console.warn;
  const lines = [];
  console.warn = (m) => lines.push(String(m));
  return { lines, restore: () => (console.warn = warn) };
}

test("an invalid destination is refused loudly and the next source is used", () => {
  const s = sb.resolveSettings({ SUPERBASED_DESTINATION: "both" }, { destination: "bothh" });
  assert.equal(s.destination, "both");
  assert.match(s.destinationInvalid, /"bothh" \(argument\) is not local, online or both/);
  assert.equal(sb.resolveSettings({ SUPERBASED_DESTINATION: " Online " }).destination, "online");
});

test("destinations(): local never carries the key; OTEL env reaches only a local destination; both has one each", () => {
  const env = { OTEL_EXPORTER_OTLP_HEADERS: "x-other-vendor=secret", OTEL_EXPORTER_OTLP_ENDPOINT: "https://other-vendor.example", SUPERBASED_OTLP_HEADERS: "x-sb=1" };
  const s = sb.resolveSettings(env, { apiKey: "k", orgUrl: "https://gw.example/" });
  const [local] = sb.destinations(s, "local");
  assert.equal(local.endpoint, "https://other-vendor.example/v1/traces", "destination local honours the app's OTEL endpoint");
  assert.equal(local.headers.Authorization, undefined, "R-B26: the key never rides to an OTEL_* endpoint");
  assert.equal(local.headers["x-other-vendor"], "secret");
  const [online] = sb.destinations(s, "online");
  assert.equal(online.endpoint, "https://gw.example/v1/traces");
  assert.equal(online.headers.Authorization, "Bearer k");
  assert.equal(online.headers["x-sb"], "1");
  assert.equal(online.headers["x-other-vendor"], undefined, "an app's OTEL headers never ride to the gateway");
  const both = sb.destinations(s, "both");
  assert.deepEqual(both.map((d) => d.name), ["local", "online"]);
  assert.equal(both[0].endpoint, sb.DEFAULT_ENDPOINT, "under both, OTEL_* never replaces the machine");
  assert.equal(both[0].headers["x-other-vendor"], undefined);
  // An endpoint the app named itself (option or SUPERBASED_OTLP_ENDPOINT), remote: the key rides (A7's custom collector).
  const named = sb.destinations(sb.resolveSettings({}, { endpoint: "https://collector.example/v1/traces", apiKey: "k" }), "local");
  assert.deepEqual(named.map((d) => [d.name, d.endpoint, d.headers.Authorization]), [["local", "https://collector.example/v1/traces", "Bearer k"]]);
  const viaEnv = sb.resolveSettings({ SUPERBASED_OTLP_ENDPOINT: "https://collector.example/v1/traces", SUPERBASED_API_KEY: "k" });
  assert.equal(sb.destinations(viaEnv, "local")[0].headers.Authorization, "Bearer k");
  const loop = sb.resolveSettings({}, { endpoint: "http://127.0.0.1:9999/v1/traces", apiKey: "k" });
  assert.equal(sb.destinations(loop, "local")[0].headers.Authorization, undefined, "never to a loopback receiver");
  assert.throws(() => sb.resolveSettings({}, { localEndpoint: "x" }), TypeError, "one spelling per setting (R-B19)");
  assert.throws(() => sb.resolveSettings({}, { machineUrl: "x" }), TypeError);
  assert.equal(sb.resolveSettings({ SUPERBASED_MACHINE_URL: "http://127.0.0.1:1" }).nodeUrl, sb.DEFAULT_NODE_URL, "only SUPERBASED_NODE_URL");
  assert.equal(sb.resolveSettings({ SUPERBASED_NODE_URL: "http://127.0.0.1:1/" }).nodeUrl, "http://127.0.0.1:1");
});

test("both: each destination gets every span; a dead one never blocks the other", async () => {
  const online = await startStub();
  const dead = await deadUrl();
  const q = quiet();
  try {
    // The dead side retries for longer than the whole flush budget, so the
    // online copy arrives only if the two are flushed at the same time.
    sb.init({ destination: "both", endpoint: `${dead}/v1/traces`, orgUrl: online.url, apiKey: "sdk-key", exportTimeoutMs: 2500 });
    const d0 = sb.diagnostics();
    assert.equal(d0.destination, "both");
    assert.equal(d0.destinationSource, "argument");
    sb.withSpan("one", () => {});
    sb.withSpan("two", () => {});
    await sb.flush(1000);
    const got = otlp(online);
    assert.ok(got.length >= 1, "the gateway received the batch despite the dead local side");
    assert.equal(got[0].headers.authorization, "Bearer sdk-key");
    const d = sb.diagnostics();
    assert.deepEqual(d.destinations, [
      { name: "local", endpoint: `${dead}/v1/traces` },
      { name: "online", endpoint: `${online.url}/v1/traces` },
    ]);
    assert.ok(d.failedExports >= 1, "the dead side's failure is counted");
  } finally {
    q.restore();
    // Long enough for the dead side to give up (exportTimeoutMs), so its
    // retries never run on into the next test.
    await sb.shutdown(5000);
    await online.close();
  }
});

test("both: two live destinations each receive the spans, local without the key", async () => {
  const local = await startStub();
  const online = await startStub();
  try {
    sb.init({ destination: "both", endpoint: `${local.url}/v1/traces`, orgUrl: online.url, apiKey: "k" });
    sb.withSpan("x", () => {});
    assert.equal(await sb.flush(3000), true);
    assert.equal(otlp(local).length, 1);
    assert.equal(otlp(online).length, 1);
    assert.equal(otlp(local)[0].headers.authorization, undefined);
    assert.equal(otlp(online)[0].headers.authorization, "Bearer k");
  } finally {
    await sb.shutdown(1000);
    await local.close();
    await online.close();
  }
});

test("online with no gateway or no credential exports nothing and says why; both keeps the machine", async () => {
  process.env.SUPERBASED_DESTINATION = "online";
  process.env.SUPERBASED_DISCOVER = "0";
  const q = quiet();
  try {
    sb.init({});
    sb.withSpan("lost", () => {});
    await sb.flush(1000);
    let d = sb.diagnostics();
    assert.equal(d.destinationSource, "env");
    assert.deepEqual(d.destinations, []);
    assert.match(d.destinationProblems[0], /missing a gateway URL and an SDK credential; nothing is exported.*run `observer sdk sign-in`/);
    assert.equal(d.droppedSpans, 1);
    assert.ok(q.lines.some((l) => l.includes("missing a gateway URL")));
    await sb._resetForTests();
    sb.init({ destination: "both", orgUrl: "https://gw.example" });
    d = sb.diagnostics();
    assert.match(d.degraded, /exporting to this machine only/);
    assert.deepEqual(d.destinations.map((x) => x.name), ["local"]);
    assert.match(d.destinationProblems[0], /missing an SDK credential; exporting to this machine only/);
  } finally {
    q.restore();
  }
});

test("discovery: the machine's default decides and fills the endpoints; spans before the answer are held", async () => {
  const machine = await startStub();
  const online = await startStub();
  machine.delayMs = 50;
  try {
    machine.handler = (r) =>
      r.path === sb.DISCOVERY_PATH
        ? { body: discovery({ destination: "both", signed_in: true, local: { enabled: true, otlp_traces_url: `${machine.url}/v1/traces` }, online: { gateway_url: online.url } }) }
        : undefined;
    // The gateway is named by the app or the key file, never by discovery (E-04).
    sb.init({ nodeUrl: machine.url, apiKey: "k", orgUrl: online.url });
    assert.equal(sb.diagnostics().destinationSource, "discovering");
    sb.withSpan("early", () => {}); // ends before discovery answers
    assert.equal(await sb.ready(), "both");
    const d = sb.diagnostics();
    assert.equal(d.destinationSource, "machine");
    assert.deepEqual(d.destinations.map((x) => x.endpoint), [`${machine.url}/v1/traces`, `${online.url}/v1/traces`]);
    assert.equal(await sb.flush(3000), true);
    assert.equal(machine.requests[0].path, "/api/sdk/destination");
    assert.equal(otlp(machine).length, 1, "the held span went to the machine");
    assert.equal(otlp(online).length, 1, "and to the gateway");
    assert.equal(otlp(machine)[0].headers.authorization, undefined);
  } finally {
    await sb.shutdown(1000);
    await machine.close();
    await online.close();
  }
});

test("discovery reads the credential file only when it is owner-only and one line", { skip: process.platform === "win32" }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "sbo-cred-"));
  const good = join(dir, "good");
  writeFileSync(good, "ik_9a.s3cr3t\n");
  chmodSync(good, 0o600);
  const open = join(dir, "open");
  writeFileSync(open, "ik_9a.s3cr3t\n");
  chmodSync(open, 0o644);
  const link = join(dir, "link");
  symlinkSync(good, link);
  const two = join(dir, "two");
  writeFileSync(two, "a.b\nc.d\n");
  chmodSync(two, 0o600);
  assert.deepEqual(sb.readCredentialFile(good), { key: "ik_9a.s3cr3t", gateway: "", error: "" });
  assert.match(sb.readCredentialFile(open).error, /readable by others/);
  assert.match(sb.readCredentialFile(link).error, /symlink/);
  assert.match(sb.readCredentialFile(two).error, /not one <key_id>.<secret> line/);

  const machine = await startStub();
  const gw = await startStub();
  writeFileSync(good, `ik_9a.s3cr3t\ngateway_url=${gw.url}\n`);
  const q = quiet();
  try {
    let file = good;
    machine.handler = (r) =>
      r.path === sb.DISCOVERY_PATH
        ? { body: discovery({ destination: "online", signed_in: true, online: { gateway_url: gw.url, credential_present: true, credential_file: file } }) }
        : undefined;
    sb.init({ nodeUrl: machine.url });
    assert.equal(await sb.ready(), "online");
    sb.withSpan("x", () => {});
    await sb.flush(3000);
    assert.equal(otlp(gw)[0].headers.authorization, "Bearer ik_9a.s3cr3t");
    await sb._resetForTests();
    file = open;
    sb.init({ nodeUrl: machine.url });
    await sb.ready();
    const d = sb.diagnostics();
    assert.deepEqual(d.destinations, []);
    assert.ok(d.destinationProblems.some((p) => /readable by others/.test(p)));
  } finally {
    q.restore();
    await sb.shutdown(500);
    await machine.close();
    await gw.close();
  }
});

test("discovery failures fall through to local with one diagnostic", async () => {
  const q = quiet();
  const machine = await startStub();
  try {
    sb.init({ nodeUrl: await deadUrl() });
    assert.equal(await sb.ready(), "local");
    assert.equal(sb.diagnostics().destinationSource, "default");
    assert.deepEqual(sb.diagnostics().destinationProblems, [], "a machine that does not answer is a note, not a warning");
    assert.match(sb.diagnostics().notes[0], /^discovery: /);
    assert.equal(q.lines.length, 0, "notes are not logged without debug");
    for (const body of [discovery({ api_version: 2 }), "not json"]) {
      await sb._resetForTests();
      machine.reply(body);
      sb.init({ nodeUrl: machine.url });
      assert.equal(await sb.ready(), "local", JSON.stringify(body));
      await sb._resetForTests();
      // No machine answer, but the app was given a gateway and a credential: online, "inferred" (as Python).
      sb.init({ nodeUrl: machine.url, orgUrl: "https://gw.example", apiKey: "k" });
      assert.equal(await sb.ready(), "online", JSON.stringify(body));
      assert.equal(sb.diagnostics().destinationSource, "inferred");
    }
    // FR-S10: an unknown destination in an api_version 1 answer is a warning and local, not a dropped answer.
    await sb._resetForTests();
    machine.reply({ destination: "everywhere", api_version: 1 });
    sb.init({ nodeUrl: machine.url });
    assert.equal(await sb.ready(), "local");
    assert.equal(sb.diagnostics().destinationSource, "machine");
    await sb._resetForTests();
    sb.init({ nodeUrl: "http://192.0.2.10:8081" });
    assert.equal(await sb.ready(), "local");
    assert.match(sb.diagnostics().notes[0], /not a loopback address/);
    await sb._resetForTests();
    // An explicit endpoint no longer skips discovery (Python): it only sets the local destination's URL.
    machine.reply(discovery({ destination: "local" }));
    sb.init({ nodeUrl: machine.url, endpoint: "http://127.0.0.1:9/v1/traces" });
    assert.equal(await sb.ready(), "local");
    assert.equal(sb.diagnostics().destinationSource, "machine");
    assert.deepEqual(sb.diagnostics().destinations, [{ name: "local", endpoint: "http://127.0.0.1:9/v1/traces" }]);
    await sb._resetForTests();
    const before = machine.requests.length;
    sb.init({ nodeUrl: machine.url, discover: false });
    assert.equal(sb.diagnostics().destinationSource, "default");
    assert.equal(machine.requests.length, before, "no discovery request");
  } finally {
    q.restore();
    await sb.shutdown(500);
    await machine.close();
  }
});

test("the machine's warnings and local.enabled=false are reported", async () => {
  const machine = await startStub();
  const q = quiet();
  try {
    machine.reply(discovery({ local: { enabled: false }, warnings: ["signed in but this organization published no gateway address"] }));
    sb.init({ nodeUrl: machine.url });
    await sb.ready();
    const p = sb.diagnostics().destinationProblems.join(" | ");
    assert.match(p, /machine: signed in but/);
    assert.match(p, /\[observability\] off/);
  } finally {
    q.restore();
    await sb.shutdown(500);
    await machine.close();
  }
});

test("admit() follows the destination: machine for local, the org (with the key) for online", async () => {
  const machine = await startStub();
  const gw = await startStub();
  const allow = { allowed: true, decision: "allow" };
  machine.reply(allow);
  gw.reply(allow);
  try {
    process.env.SUPERBASED_API_KEY = "k";
    sb.init({ destination: "local", nodeUrl: machine.url, orgUrl: gw.url });
    await sb.admit("hi");
    assert.equal(machine.requests.at(-1).path, "/api/obs/admission/check");
    assert.equal(machine.requests.at(-1).headers.authorization, undefined, "the key never goes to the machine");
    sb.init({ destination: "online", nodeUrl: machine.url, orgUrl: gw.url });
    await sb.admit("hi");
    assert.equal(gw.requests.at(-1).path, "/v1/sdk/admit");
    assert.equal(gw.requests.at(-1).headers.authorization, "Bearer k");
    delete process.env.SUPERBASED_API_KEY;
    sb.init({ destination: "both", nodeUrl: machine.url, orgUrl: gw.url, apiKey: "" });
    await sb.ready(); // R-B09: both without a key asks the machine first
    const before = machine.requests.length;
    await sb.admit("hi");
    assert.equal(machine.requests.length, before + 1, "degraded online goes to the machine");
  } finally {
    await sb.shutdown(500);
    await machine.close();
    await gw.close();
  }
});

test("R-B09: an explicit both still takes the gateway URL and the key from the machine's key file", { skip: process.platform === "win32" }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "sbo-cred-"));
  const file = join(dir, "cred");
  const machine = await startStub();
  const gw = await startStub();
  writeFileSync(file, `ik_9a.s3cr3t\ngateway_url=${gw.url}\n`);
  chmodSync(file, 0o600);
  const q = quiet();
  try {
    machine.handler = (r) =>
      r.path === sb.DISCOVERY_PATH
        ? {
            body: discovery({
              destination: "local", // the machine's default is NOT what the app chose
              signed_in: true,
              local: { enabled: true, otlp_traces_url: `${machine.url}/v1/traces` },
              online: { gateway_url: gw.url, credential_present: true, credential_file: file },
            }),
          }
        : undefined;
    process.env.SUPERBASED_DESTINATION = "both";
    sb.init({ nodeUrl: machine.url });
    assert.equal(await sb.ready(), "both");
    const d = sb.diagnostics();
    assert.equal(d.destinationSource, "env", "the explicit choice wins over the machine's default");
    assert.deepEqual(d.destinations.map((x) => x.name), ["local", "online"]);
    assert.deepEqual(d.destinationProblems, []);
    assert.equal(d.gatewayUrl, gw.url);
    assert.equal(d.credentialSource, "file");
    assert.equal(d.signedIn, true);
    sb.withSpan("x", () => {});
    await sb.flush(3000);
    assert.equal(otlp(gw)[0].headers.authorization, "Bearer ik_9a.s3cr3t");
    assert.equal(otlp(machine)[0].headers.authorization, undefined);
    // Explicit online with no machine answering: stays online, degraded, with the fix named.
    await sb._resetForTests();
    process.env.SUPERBASED_DESTINATION = "online";
    sb.init({ nodeUrl: await deadUrl() });
    assert.equal(await sb.ready(), "online");
    assert.match(sb.diagnostics().degraded, /nothing is exported.*observer sdk sign-in/);
    // An explicit both WITH a gateway, a key and a named local endpoint does not ask the machine.
    await sb._resetForTests();
    process.env.SUPERBASED_DESTINATION = "both";
    const before = machine.requests.length;
    sb.init({ nodeUrl: machine.url, orgUrl: gw.url, apiKey: "k", endpoint: `${machine.url}/v1/traces` });
    assert.equal(sb.diagnostics().destination, "both", "known at once");
    assert.equal(machine.requests.length, before);
    // Without a named endpoint it asks, for the machine's receiver (live finding L-01).
    await sb._resetForTests();
    process.env.SUPERBASED_DESTINATION = "both";
    sb.init({ nodeUrl: machine.url, orgUrl: gw.url, apiKey: "k" });
    assert.equal(await sb.ready(), "both");
    assert.equal(machine.requests.length, before + 1);
    assert.equal(sb.diagnostics().destinations[0].endpoint, `${machine.url}/v1/traces`);
  } finally {
    q.restore();
    await sb.shutdown(500);
    await machine.close();
    await gw.close();
  }
});

test("R-B26: control calls follow no redirect, so the key never reaches the redirect's host", async () => {
  const other = await startStub();
  const gw = await startStub();
  const q = quiet();
  try {
    other.reply({ api_version: "v1", accepted: [{ index: 0, id: "sc_x" }], rejected: [] });
    gw.reply("", 307, { Location: `${other.url}/v1/sdk/scores` });
    sb.init({ exporter: { export: (_s, cb) => cb({ code: 0 }), shutdown: async () => {} }, destination: "online", orgUrl: gw.url, apiKey: "secret-key" });
    const r = await sb.score("x", 1, { traceId: "0af7651916cd43dd8448eb211c80319c" });
    assert.equal(r.ok, false);
    assert.match(r.destinations.online.error, /redirect_refused/);
    assert.equal(other.requests.length, 0, "the redirect was not followed");
    gw.reply("", 302, { Location: `${other.url}/x` });
    await assert.rejects(sb.getPrompt("p"), sb.PromptFetchError);
    assert.equal(other.requests.length, 0);
  } finally {
    q.restore();
    await other.close();
    await gw.close();
  }
});

test("R-C33: init() and settings() never print the key; the values stay readable", async () => {
  process.env.SUPERBASED_DISCOVER = "0";
  const s = sb.init({ exporter: undefined, apiKey: "ik_1.secret", headers: { Authorization: "Bearer ik_1.secret" }, destination: "local" });
  for (const view of [s, sb.settings()]) {
    assert.equal(view.apiKey, "ik_1.secret");
    assert.equal(view.headers.Authorization, "Bearer ik_1.secret");
    assert.ok(!JSON.stringify(view).includes("secret"), "JSON");
    assert.ok(!(await import("node:util")).inspect(view, { depth: 5 }).includes("secret"), "console.log");
    assert.ok(!Object.keys({ ...view }).includes("apiKey"), "spread");
  }
  await sb.shutdown(500);
});

test("E-04: discovery never decides where the key goes; local URLs must be loopback", { skip: process.platform === "win32" }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "sbo-cred-"));
  const machine = await startStub();
  const gw = await startStub();
  const attacker = "https://attacker.example";
  const file = join(dir, "cred");
  writeFileSync(file, `ik_9a.s3cr3t\ngateway_url=${gw.url}\n`);
  chmodSync(file, 0o600);
  const bare = join(dir, "bare");
  writeFileSync(bare, "ik_9a.s3cr3t\n");
  chmodSync(bare, 0o600);
  let cred = file;
  const q = quiet();
  try {
    machine.handler = (r) =>
      r.path === sb.DISCOVERY_PATH
        ? {
            body: discovery({
              destination: "both",
              signed_in: true,
              local: { enabled: true, otlp_traces_url: `${attacker}/v1/traces`, admission_url: `${attacker}/check` },
              online: { gateway_url: attacker, credential_present: true, credential_file: cred },
            }),
          }
        : undefined;
    sb.init({ nodeUrl: machine.url });
    assert.equal(await sb.ready(), "both");
    let d = sb.diagnostics();
    assert.deepEqual(d.destinations.map((x) => x.endpoint), ["http://127.0.0.1:4318/v1/traces", `${gw.url}/v1/traces`]);
    assert.equal(d.gatewayUrl, gw.url);
    assert.ok(d.destinationProblems.some((p) => /non-loopback otlp_traces_url/.test(p)));
    assert.ok(d.destinationProblems.some((p) => /non-loopback admission_url/.test(p)));

    // A key file with no gateway line: no online leg, discovery's address unused.
    await sb._resetForTests();
    cred = bare;
    sb.init({ nodeUrl: machine.url });
    await sb.ready();
    d = sb.diagnostics();
    assert.deepEqual(d.destinations.map((x) => x.name), ["local"]);
    assert.equal(d.gatewayUrl, "");
    assert.match(d.degraded, /gateway URL/);
  } finally {
    q.restore();
    await sb.shutdown(500);
    await machine.close();
    await gw.close();
  }
});

test("E-04: the key file's gateway line must be https or loopback http", { skip: process.platform === "win32" }, () => {
  const dir = mkdtempSync(join(tmpdir(), "sbo-cred-"));
  const cases = [
    ["ik_1.s\ngateway_url=https://gw.example\n", "https://gw.example", ""],
    ["ik_1.s\nlater_field=x\ngateway_url=https://gw.example/\n", "https://gw.example", ""],
    ["ik_1.s\ngateway_url=http://127.0.0.1:4318\n", "http://127.0.0.1:4318", ""],
    ["ik_1.s\ngateway_url=http://gw.example\n", "", "plain http"],
    ["ik_1.s\ngateway_url=https://u:p@gw.example\n", "", "user name"],
    ["ik_1.s\ngateway_url=https://gw.example/v1/traces\n", "", "base address"],
  ];
  cases.forEach(([content, gateway, warn], i) => {
    const f = join(dir, `c${i}`);
    writeFileSync(f, content);
    chmodSync(f, 0o600);
    const got = sb.readCredentialFile(f);
    assert.equal(got.key, "ik_1.s", content);
    assert.equal(got.gateway, gateway, content);
    assert.ok(got.error.includes(warn), `${content}: ${got.error}`);
  });
});

test("R-C33: the credential file is never read on Windows (no owner check to make)", () => {
  const dir = mkdtempSync(join(tmpdir(), "sbcred-"));
  const file = join(dir, "key");
  writeFileSync(file, "ik_1.s\n", { mode: 0o600 });
  const real = Object.getOwnPropertyDescriptor(process, "platform");
  Object.defineProperty(process, "platform", { value: "win32" });
  try {
    const got = sb.readCredentialFile(file);
    assert.equal(got.key, "");
    assert.match(got.error, /not read on Windows; set SUPERBASED_API_KEY/);
  } finally {
    Object.defineProperty(process, "platform", real);
  }
  if (process.platform !== "win32") assert.equal(sb.readCredentialFile(file).key, "ik_1.s");
});

test("control calls made before discovery answers wait for it (E-33)", async () => {
  const machine = await startStub();
  const online = await startStub();
  machine.delayMs = 300;
  try {
    machine.handler = (r) =>
      r.path === sb.DISCOVERY_PATH
        ? { body: discovery({ destination: "online", signed_in: true, online: {} }) }
        : undefined;
    online.handler = (r) => (r.path.endsWith("/scores") ? { body: { accepted: [{ index: 0, id: "sc_1" }], rejected: [] } } : { body: { allowed: true, decision: "allow" } });
    sb.init({ nodeUrl: machine.url, apiKey: "k", orgUrl: online.url });
    // Called at once, in the first few ms: before the machine answered.
    const [res, verdict] = await sb.withSpan("req", () =>
      Promise.all([sb.score("accuracy", 1), sb.admit("hello")]),
    );
    assert.equal(res.ok, true, JSON.stringify(res));
    assert.deepEqual(Object.keys(res.destinations), ["online"]);
    assert.equal(verdict.degraded, "");
    const machinePaths = machine.requests.map((r) => r.path);
    assert.deepEqual(machinePaths, [sb.DISCOVERY_PATH], "nothing but discovery went to the machine");
    assert.ok(online.requests.some((r) => r.path.endsWith("/scores")), "the score went to the gateway");
    assert.ok(online.requests.some((r) => r.path.endsWith("/admit")), "admit asked the org");
  } finally {
    await sb.shutdown(1000);
    await machine.close();
    await online.close();
  }
});

test("discovery survives an app that blocks the event loop right after init (live finding L-01)", async () => {
  // init() returns at once; an app that then loads a framework synchronously
  // for longer than the discovery timeout must still get the machine's answer.
  const machine = await startStub();
  try {
    machine.handler = (r) =>
      r.path === sb.DISCOVERY_PATH
        ? { body: discovery({ destination: "local", local: { enabled: true, otlp_traces_url: "http://127.0.0.1:14318/v1/traces" } }) }
        : undefined;
    process.env.SUPERBASED_DESTINATION = "local";
    sb.init({ nodeUrl: machine.url, discoverTimeoutMs: 300 });
    const until = Date.now() + 700;
    while (Date.now() < until) {
      // a synchronous require of a large framework
    }
    assert.equal(await sb.ready(), "local");
    const d = sb.diagnostics();
    assert.deepEqual(d.destinations.map((x) => x.endpoint), ["http://127.0.0.1:14318/v1/traces"]);
    assert.deepEqual(d.notes, []);
    // A machine that is really slow still times out, within twice the budget.
    await sb._resetForTests();
    process.env.SUPERBASED_DESTINATION = "local";
    machine.delayMs = 2000;
    const t0 = Date.now();
    sb.init({ nodeUrl: machine.url, discoverTimeoutMs: 300 });
    await sb.ready();
    assert.ok(Date.now() - t0 < 1000, `gave up after ${Date.now() - t0}ms`);
    assert.match(sb.diagnostics().notes.join(" "), /timed out after 300ms/);
  } finally {
    await sb.shutdown(500);
    await machine.close();
  }
});

// Discovery on a busy event loop (live e2e, 2026-11-21): an app that loads a
// heavy framework right after init() keeps the loop busy past the 500 ms
// window, so the timer fires late with the machine's answer waiting behind
// it. Each late firing re-arms the window, up to the wall cap; a window that
// passes on time with no answer gives up.
test("discovery timer: re-arm while the loop is busy, give up on an idle window or the cap", async () => {
  const { discoveryTimerStep, DISCOVERY_WALL_CAP_MS } = await import("../dist/esm/destination.js");
  const t0 = 1_000_000;
  const cap = t0 + DISCOVERY_WALL_CAP_MS;
  const rows = [
    // [name, now, due, giveUpAt, timeoutMs, want]
    ["on time: the machine did not answer", t0 + 500, t0 + 500, cap, 500, "abort"],
    ["a little late, within the slack", t0 + 590, t0 + 500, cap, 500, "abort"],
    ["late: the loop was busy", t0 + 1400, t0 + 500, cap, 500, "rearm"],
    ["late again on a later window", t0 + 3900, t0 + 2900, cap, 500, "rearm"],
    ["late but past the wall cap", cap + 10, cap - 600, cap, 500, "abort"],
    ["short window: the 50 ms slack floor", t0 + 140, t0 + 100, cap, 100, "abort"],
    ["short window, late past the floor", t0 + 160, t0 + 100, cap, 100, "rearm"],
  ];
  for (const [name, now, due, giveUpAt, ms, want] of rows) {
    assert.equal(discoveryTimerStep(now, due, giveUpAt, ms), want, name);
  }
});
