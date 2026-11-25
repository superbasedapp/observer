// The SDK quickstart's contract cases for TypeScript: sdk-behaviour-cases.json
// auto_instrument, service_name_default, destination_sdk_file and
// first_trace_link (the sections that carry `sdks`; behaviour.test.mjs runs
// the rest) and credential-file-cases.json.
// setup-cases.json runs in setup.test.mjs. Each runner maps the SDK-neutral
// case onto the TypeScript API; where a contract word differs from the
// TypeScript one (unknown_target raises TypeError, as instrument() always
// has), the mapping says so.
import { test, beforeEach, after } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join, sep } from "node:path";
import { fileURLToPath } from "node:url";

import { trace } from "@opentelemetry/api";
import { InMemorySpanExporter } from "@opentelemetry/sdk-trace-base";
import { NodeTracerProvider } from "@opentelemetry/sdk-trace-node";

import * as sb from "../dist/esm/index.js";
import { _setInstalledForTests } from "../dist/esm/instrument.js";
import { readCredentialRecord, sdkCredentialPath } from "../dist/esm/credfile.js";
import { _setFirstTraceSinkForTests, noteExported, noteRefused } from "../dist/esm/firsttrace.js";
import { runtime } from "../dist/esm/runtime.js";
import { deadUrl, reset, startStub } from "./helpers.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const contractDir = process.env.SUPERBASED_CONTRACT_DIR || join(here, "..", "..", "contract");
const load = (f) => (existsSync(join(contractDir, f)) ? JSON.parse(readFileSync(join(contractDir, f), "utf8")) : null);
const BEHAVIOUR = load("sdk-behaviour-cases.json");
const QUICKSTART = BEHAVIOUR?.auto_instrument ? BEHAVIOUR : null;
const CREDFILE = load("credential-file-cases.json");
const REFUSALS = load("plan-refusal-cases.json");
const skip = !QUICKSTART && "sdk/contract (the quickstart cases) is not present";
const forTs = (c, sec) => (c.sdks ?? sec.sdks ?? []).includes("typescript");
const cases = (name) => (QUICKSTART ? QUICKSTART[name].cases.filter((c) => forTs(c, QUICKSTART[name])) : []);

beforeEach(async () => {
  sb.uninstrument();
  await reset();
});
after(async () => {
  sb.uninstrument();
  _setFirstTraceSinkForTests(null);
  await reset();
});

const RUNNERS = ["auto_instrument", "service_name_default", "destination_sdk_file", "first_trace_link"];

test("every section that names typescript in its sdks has a runner here", { skip }, () => {
  const mine = Object.entries(QUICKSTART)
    .filter(([k, v]) => !k.startsWith("_") && (v.sdks ?? []).includes("typescript"))
    .map(([k]) => k)
    .sort();
  assert.deepEqual(mine, [...RUNNERS].sort());
});

// --- auto_instrument ----------------------------------------------------------

/** The framework module each target's library resolves to (CommonJS), so a case can import it before or after init(). */
const LIBRARY = Object.fromEntries(sb.TARGETS.map((t) => [t.name, t.library]));

function importFramework(name) {
  try {
    require(LIBRARY[name]);
  } catch {
    // an ESM-only framework, or not loadable here: the case's installed seam still decides
  }
}

test("auto_instrument", { skip }, async () => {
  assert.ok(cases("auto_instrument").length > 0, "no typescript cases");
  for (const c of cases("auto_instrument")) {
    sb.uninstrument();
    await reset();
    const undo = [];
    try {
      if (c.env !== null && c.env !== undefined) process.env.SUPERBASED_INSTRUMENT = c.env;
      if (c.mode === "attached") new NodeTracerProvider({ spanProcessors: [sb.spanProcessor()] }).register();
      if (c.mode === "standalone") new NodeTracerProvider().register();
      _setInstalledForTests(c.installed);
      for (const name of c.host_instrumented ?? []) {
        // The host instrumented it first, through the instrumentation itself.
        const mod = require("@arizeai/openinference-instrumentation-openai");
        const inst = new mod.OpenAIInstrumentation();
        const target = require(LIBRARY[name]);
        inst.manuallyInstrument(target);
        undo.push(() => {
          inst.disable();
          if (mod.isPatched()) inst.unpatch?.(target);
        });
      }
      const importAfter = c.import === "after_init";
      if (!importAfter) for (const n of c.installed) importFramework(n);
      const opts = { exporter: new InMemorySpanExporter(), discover: false, destination: "local" };
      if (c.arg !== null && c.arg !== undefined) opts.instrument = c.arg;
      if (c.want.raises) {
        // instrument() raises TypeError for an unknown target in TypeScript (the contract's RangeError is not what instrument() throws).
        assert.equal(c.want.raises, "unknown_target");
        assert.throws(() => sb.init(opts), TypeError, c.name);
        continue;
      }
      const warned = [];
      const orig = console.warn;
      console.warn = (m) => warned.push(String(m));
      try {
        sb.init(opts);
      } finally {
        console.warn = orig;
      }
      if (importAfter) for (const n of c.installed) importFramework(n);
      const d = sb.diagnostics();
      const instrumented = Object.entries(d.instrumented)
        .filter(([, v]) => v === "instrumented")
        .map(([k]) => k)
        .sort();
      assert.deepEqual(instrumented, [...c.want.instrumented].sort(), `${c.name}: ${JSON.stringify(d.instrumented)}`);
      for (const [k, v] of Object.entries(c.want.statuses ?? {})) assert.equal(d.instrumented[k], v, `${c.name}: ${k}`);
      if (c.want.note_contains) assert.ok(d.notes.some((n) => n.includes(c.want.note_contains)), `${c.name}: ${d.notes.join("; ")}`);
      if (c.want.warning_contains) assert.ok(warned.some((w) => w.includes(c.want.warning_contains)), `${c.name}: ${warned.join("; ")}`);
      if (c.then_instrument) assert.deepEqual(sb.instrument(c.then_instrument), c.want.then_instrument, c.name);
    } finally {
      _setInstalledForTests(null);
      sb.uninstrument();
      for (const u of undo) u();
      trace.disable();
    }
  }
});

// --- service_name_default -----------------------------------------------------

test("service_name_default", { skip }, () => {
  const sdk = join(here, "..", "dist", "cjs", "index.js");
  assert.ok(cases("service_name_default").length > 0, "no typescript cases");
  for (const c of cases("service_name_default")) {
    const root = mkdtempSync(join(tmpdir(), "sbo-svc-"));
    try {
      const p = c.project;
      const home = join(root, ...(p.home ?? "home/me").split("/"));
      mkdirSync(home, { recursive: true });
      for (const m of p.manifests ?? []) {
        mkdirSync(join(root, ...m.dir.split("/")), { recursive: true });
        writeFileSync(join(root, ...m.dir.split("/"), "package.json"), JSON.stringify(m.name === null ? { private: true } : { name: m.name }));
      }
      const args = c.args?.service_name !== undefined ? { serviceName: c.args.service_name } : {};
      const body =
        `const sb = require(${JSON.stringify(sdk)});\n` +
        `sb.init({ exporter: { export(_s, cb) { cb({ code: 0 }); }, shutdown: async () => {} }, discover: false, instrument: "off", ...${JSON.stringify(args)} });\n` +
        `const d = sb.diagnostics();\nconsole.log(JSON.stringify([d.serviceName, d.serviceNameSource]));\n`;
      const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^(SUPERBASED_|OTEL_)/.test(k)));
      Object.assign(env, c.env ?? {}, { HOME: home, USERPROFILE: home });
      let r;
      if (p.entry) {
        const file = join(root, ...p.entry.split("/")) + ".js";
        mkdirSync(dirname(file), { recursive: true });
        writeFileSync(file, body);
        r = spawnSync(process.execPath, [file], { encoding: "utf8", env, cwd: root });
      } else {
        const cwd = join(root, ...(p.cwd ?? "").split("/"));
        mkdirSync(cwd, { recursive: true });
        r = spawnSync(process.execPath, ["-e", body], { encoding: "utf8", env, cwd });
      }
      assert.equal(r.status, 0, `${c.name}: ${r.stderr}`);
      assert.deepEqual(JSON.parse(r.stdout.trim().split("\n").at(-1)), [c.want.service_name, c.want.source], c.name);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }
});

// --- destination_sdk_file -----------------------------------------------------

const unix = process.platform !== "win32";

test("destination_sdk_file", { skip: skip || (!unix && "the refused case uses unix file rules") }, async () => {
  assert.ok(cases("destination_sdk_file").length > 0, "no typescript cases");
  for (const c of cases("destination_sdk_file")) {
    await reset();
    const dir = mkdtempSync(join(tmpdir(), "sbo-sdkf-"));
    const machine = await startStub();
    try {
      for (const [k, v] of Object.entries(c.env ?? {})) process.env[k] = v;
      if (c.sdk_file) {
        const f = join(dir, "sdk-credential");
        const exp = c.sdk_file.state === "expired" ? new Date(Date.now() - 3600_000) : new Date(Date.now() + 365 * 86_400_000);
        const lines = ["00000000000000000000000000000002.fake-sdk-file-secret", "gateway_url=https://u-k7x2.superbased.app"];
        if (c.sdk_file.destination !== null) lines.push(`destination=${c.sdk_file.destination}`);
        lines.push(`expires_at=${exp.toISOString().replace(/\.\d+Z$/, "Z")}`);
        writeFileSync(f, lines.join("\n") + "\n");
        chmodSync(f, c.sdk_file.state === "refused" ? 0o644 : 0o600);
        process.env.SUPERBASED_CREDENTIAL_FILE = f;
      }
      const opts = { exporter: new InMemorySpanExporter(), instrument: "off", ...(c.args?.destination ? { destination: c.args.destination } : {}) };
      if (c.machine) {
        let credFile = "";
        if (c.machine.credential_present) {
          credFile = join(dir, "machine-credential");
          writeFileSync(credFile, "00000000000000000000000000000003.fake-machine-secret\ngateway_url=https://gw.machine.example\n");
          chmodSync(credFile, 0o600);
        }
        machine.handler = (r) =>
          r.path === sb.DISCOVERY_PATH
            ? {
                body: {
                  api_version: 1,
                  destination: c.machine.destination,
                  source: "config",
                  configured: "",
                  signed_in: c.machine.signed_in,
                  local: { enabled: c.machine.local_enabled, otlp_traces_url: `${machine.url}/v1/traces` },
                  online: c.machine.credential_present ? { gateway_url: "https://gw.machine.example", credential_present: true, credential_file: credFile } : {},
                  warnings: [],
                },
              }
            : undefined;
        opts.nodeUrl = machine.url;
      } else {
        opts.nodeUrl = await deadUrl();
      }
      // A caller-supplied exporter would short-cut discovery: run without one so the ladder is the real one.
      delete opts.exporter;
      const warned = [];
      const orig = console.warn;
      console.warn = (m) => warned.push(String(m));
      try {
        sb.init(opts);
        await sb.ready();
      } finally {
        console.warn = orig;
      }
      const d = sb.diagnostics();
      const got = { destination: d.destination, source: d.destinationSource, credential_source: d.credentialSource, sdk_file: d.sdkFile.state };
      const want = { destination: c.want.destination, source: c.want.source, credential_source: c.want.credential_source, sdk_file: c.want.sdk_file };
      assert.deepEqual(got, want, `${c.name}: ${JSON.stringify(d.destinationProblems)}`);
      if (c.want.warning_contains) assert.ok([...warned, ...d.destinationProblems].some((w) => w.includes(c.want.warning_contains)), `${c.name}: ${warned.join(" | ")}`);
      if (c.want.degraded) assert.notEqual(d.degraded, "", c.name);
      assert.equal(JSON.stringify(d).includes("fake-sdk-file-secret") || JSON.stringify(d).includes("fake-machine-secret"), false, `${c.name}: never the key`);
    } finally {
      await sb.shutdown(300);
      await machine.close();
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

// --- first_trace_link ---------------------------------------------------------

function fakeRoot(traceId) {
  return { spanContext: () => ({ traceId, spanId: "00f067aa0ba902b7" }) };
}

test("first_trace_link", { skip }, async () => {
  const refusalCases = Object.fromEntries((REFUSALS?.cases ?? []).map((r) => [r.name, r]));
  assert.ok(cases("first_trace_link").length > 0, "no typescript cases");
  for (const c of cases("first_trace_link")) {
    await reset();
    const lines = [];
    _setFirstTraceSinkForTests({ isTTY: () => c.tty, env: () => c.env, write: (l) => lines.push(l) });
    runtime.settings = sb.resolveSettings({}, { nodeUrl: c.node_url });
    runtime.destination = c.destination;
    // The record in use decides the base (destination.md 6a, section 16): the
    // SDK-held file's or discovery's dashboard_url; none under record 1.
    runtime.dashboardUrl = c.record === "sdk_file" || c.record === "machine" ? (c.dashboard_url ?? "") : "";
    for (const e of c.exports) {
      const span = [fakeRoot(e.trace_id)];
      if (e.local) noteExported(span, "local", e.local === "ok");
      if (e.online === "ok" || e.online === "failed") noteExported(span, "online", e.online === "ok");
      else if (e.online) {
        const r = refusalCases[e.online];
        assert.ok(r, `${c.name}: plan-refusal case ${e.online}`);
        noteRefused(span, sb.parsePlanRefusal(r.status, r.body, r.headers));
      }
    }
    assert.deepEqual(lines, c.want.lines, c.name);
    if (lines.length) assert.notEqual(sb.diagnostics().firstTraceLink, "", c.name);
  }
  _setFirstTraceSinkForTests(null);
});

// --- credential-file-cases.json -------------------------------------------------

const OS = { linux: "linux", darwin: "darwin", windows: "win32" };

test("credential-file-cases.json path_cases", { skip: !CREDFILE && "credential-file-cases.json is not present" }, () => {
  assert.ok(CREDFILE.sdks.includes("typescript"));
  for (const c of CREDFILE.path_cases) {
    assert.equal(sdkCredentialPath({ platform: OS[c.os], env: c.env, home: c.home }), c.want.path ?? "", c.name);
  }
});

test("credential-file-cases.json reader_cases", { skip: !CREDFILE && "credential-file-cases.json is not present" }, () => {
  assert.ok(CREDFILE.reader_cases.length > 0);
  let ran = 0;
  for (const c of CREDFILE.reader_cases) {
    if (c.os === "unix" && !unix) continue;
    const root = mkdtempSync(join(tmpdir(), "sbo-cfc-"));
    try {
      const windows = c.os === "windows";
      // Windows rules run on any host through the reader's platform option, with
      // %LOCALAPPDATA% at a folder of the temporary root.
      const localAppData = join(root, "AppData", "Local");
      const base = windows && c.location !== "outside" ? join(localAppData, "superbased") : join(root, "elsewhere");
      mkdirSync(base, { recursive: true });
      const path = join(base, "sdk-credential");
      if (c.kind === "directory") mkdirSync(path);
      else if (c.text !== null) {
        const real = c.symlink || c.reparse_point ? join(root, "real-credential") : path;
        writeFileSync(real, c.text);
        chmodSync(real, Number.parseInt(c.mode ?? "0600", 8));
        if (c.symlink || c.reparse_point) symlinkSync(real, path);
      }
      const opts = windows
        ? { platform: "win32", windowsRoot: localAppData, ownerIsSelf: () => c.owner_sid !== "other" }
        : { uid: c.owner === "other" ? (process.getuid?.() ?? 0) + 1 : undefined };
      const r = readCredentialRecord(path, opts);
      const state = r.record ? "ok" : r.reason ? "refused" : "absent";
      assert.equal(state, c.want.state, `${c.name}: ${r.error}`);
      if (state === "refused") assert.equal(r.reason, c.want.reason, c.name);
      if (state === "ok") {
        const nul = (v) => (v === "" ? null : v);
        assert.deepEqual(
          { key_id: r.record.keyId, gateway_url: nul(r.record.gateway), destination: nul(r.record.destination), dashboard_url: nul(r.record.dashboardUrl), expires_at: nul(r.record.expiresAt), ignored: r.ignored },
          { key_id: c.want.key_id, gateway_url: c.want.gateway_url, destination: c.want.destination, dashboard_url: c.want.dashboard_url, expires_at: c.want.expires_at, ignored: c.want.ignored },
          c.name,
        );
      }
      assert.ok(!JSON.stringify({ ...r, record: r.record && { ...r.record, key: "" } }).includes("fake-sdk-file-secret"), `${c.name}: the secret is never in a message`);
      ran += 1;
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }
  assert.ok(ran >= CREDFILE.reader_cases.filter((c) => c.os !== "unix" || unix).length);
  void sep;
});
