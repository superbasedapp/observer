// Plan 3.2: the service name from the project. One case per rung of the
// ladder, the scope strip, the generic-folder walk, normalisation, and the
// disk half (projectFacts) against throwaway folders.
import { test, beforeEach, after } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { InMemorySpanExporter } from "@opentelemetry/sdk-trace-base";

import * as sb from "../dist/esm/index.js";
import { entryDirName } from "../dist/esm/project.js";
import { reset } from "./helpers.mjs";

const here = dirname(fileURLToPath(import.meta.url));

beforeEach(reset);
after(reset);

const P = (manifestName, entryDir = "") => ({ manifestName, entryDir });

test("ladder: each rung, first set wins", () => {
  const rows = [
    ["argument", "explicit", {}, P("bot"), "explicit", "argument"],
    ["SUPERBASED_SERVICE_NAME", undefined, { SUPERBASED_SERVICE_NAME: "sb-env", OTEL_SERVICE_NAME: "otel" }, P("bot"), "sb-env", "env"],
    ["OTEL_SERVICE_NAME", undefined, { OTEL_SERVICE_NAME: "otel" }, P("bot"), "otel", "env"],
    ["OTEL_RESOURCE_ATTRIBUTES", undefined, { OTEL_RESOURCE_ATTRIBUTES: "a=b,service.name=from%20attrs" }, P("bot"), "from attrs", "env"],
    ["package.json name", undefined, {}, P("support-bot", "/home/me/support-bot/src"), "support-bot", "manifest"],
    ["scoped npm name stripped", undefined, {}, P("@acme/bot"), "bot", "manifest"],
    ["entry folder", undefined, {}, P("", "/home/me/chat-service"), "chat-service", "entry_dir"],
    ["generic folder walked up", undefined, {}, P("", "/home/me/chat-service/src"), "chat-service", "entry_dir"],
    ["two generic folders walked up", undefined, {}, P("", "/home/me/chat-service/dist/lib"), "chat-service", "entry_dir"],
    ["no project", undefined, {}, null, "custom-app", "default"],
    ["nothing usable", undefined, {}, P("", "/src"), "custom-app", "default"],
  ];
  for (const [what, explicit, env, project, name, source] of rows) {
    assert.deepEqual(sb.serviceNameLadder(explicit, env, project), { name, source }, what);
  }
});

test("normalisation of project names: lowercase, [a-z0-9._-], 64 at most", () => {
  assert.equal(sb.normaliseServiceName("My Support Bot!"), "my-support-bot");
  assert.equal(sb.normaliseServiceName("bot_v2.1"), "bot_v2.1");
  assert.equal(sb.normaliseServiceName("--weird--"), "weird");
  assert.equal(sb.normaliseServiceName("x".repeat(80)).length, 64);
  assert.equal(sb.normaliseServiceName("日本"), "");
  assert.deepEqual(sb.serviceNameLadder(undefined, {}, P("Ünïcode Bot")), { name: "n-code-bot", source: "manifest" });
  assert.equal(sb.normaliseServiceName("__bot__"), "bot");
  // An explicit or env value is used as given.
  assert.equal(sb.serviceNameLadder("My Bot", {}).name, "My Bot");
});

test("entryDirName walks Windows paths and stops at a drive", () => {
  assert.equal(entryDirName("C:\\work\\agent\\src"), "agent");
  assert.equal(entryDirName("C:\\src"), "");
});

function tree(files) {
  const root = mkdtempSync(join(tmpdir(), "sbo-proj-"));
  for (const [rel, body] of Object.entries(files)) {
    mkdirSync(dirname(join(root, rel)), { recursive: true });
    writeFileSync(join(root, rel), body);
  }
  return root;
}

test("projectFacts: the nearest package.json decides; a nameless one skips to the folder (no further search)", () => {
  const root = tree({
    "package.json": JSON.stringify({ name: "@acme/support-bot" }),
    "src/package.json": JSON.stringify({ type: "module" }),
    "src/server.js": "",
    "lib/server.js": "",
  });
  try {
    const f = sb.projectFacts(join(root, "src", "server.js"), "/nowhere", undefined, "");
    assert.equal(f.manifestName, "");
    assert.equal(f.entryDir, join(root, "src"));
    const g = sb.projectFacts(join(root, "lib", "server.js"), "/nowhere", undefined, "");
    assert.equal(g.manifestName, "@acme/support-bot");
    assert.deepEqual(sb.serviceNameLadder(undefined, {}, g), { name: "support-bot", source: "manifest" });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("projectFacts: an entry inside node_modules (next start, tsx) starts from the working directory", () => {
  const root = tree({
    "package.json": JSON.stringify({ name: "web-shop" }),
    "node_modules/next/package.json": JSON.stringify({ name: "next" }),
    "node_modules/next/dist/bin/next": "",
  });
  try {
    const f = sb.projectFacts(join(root, "node_modules", "next", "dist", "bin", "next"), root, undefined, "");
    assert.equal(f.manifestName, "web-shop");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("projectFacts: at most 8 folders, one read each, and never throws", () => {
  const root = tree({ "package.json": JSON.stringify({ name: "too-far" }), "a/b/c/d/e/f/g/h/i/app.js": "" });
  try {
    const reads = [];
    const f = sb.projectFacts(join(root, "a/b/c/d/e/f/g/h/i/app.js"), "/", (p) => {
      reads.push(p);
      throw Object.assign(new Error("no"), { code: "ENOENT" });
    }, "");
    assert.equal(reads.length, 8);
    assert.equal(new Set(reads.map((p) => dirname(p))).size, 8);
    assert.equal(f.manifestName, "");
    assert.equal(sb.projectFacts(join(root, "a/b/c/d/e/f/g/h/i/app.js"), "/", undefined, "").manifestName, "");
    assert.deepEqual(sb.projectFacts("", "", undefined, ""), { manifestName: "", entryDir: "", home: "" });
    assert.doesNotThrow(() => sb.projectFacts("\u0000bad", "/", () => "{not json"));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("init() names the service from the project and reports the rung", () => {
  const root = tree({ "package.json": JSON.stringify({ name: "@acme/order-agent" }), "src/main.mjs": "" });
  const sdk = join(here, "..", "dist", "esm", "index.js");
  writeFileSync(
    join(root, "src", "main.mjs"),
    `const sb = await import(${JSON.stringify(sdk)});\n` +
      `sb.init({ exporter: { export(_s, cb) { cb({ code: 0 }); }, shutdown: async () => {} }, discover: false, instrument: "off" });\n` +
      `const d = sb.diagnostics();\nconsole.log(JSON.stringify([d.serviceName, d.serviceNameSource]));\n`,
  );
  try {
    const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^(SUPERBASED_|OTEL_)/.test(k)));
    const r = spawnSync(process.execPath, [join(root, "src", "main.mjs")], { encoding: "utf8", env });
    assert.equal(r.status, 0, r.stderr);
    assert.deepEqual(JSON.parse(r.stdout.trim()), ["order-agent", "manifest"]);
    const r2 = spawnSync(process.execPath, [join(root, "src", "main.mjs")], { encoding: "utf8", env: { ...env, OTEL_SERVICE_NAME: "from-env" } });
    assert.deepEqual(JSON.parse(r2.stdout.trim()), ["from-env", "env"]);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("the explicit option is reported as argument", () => {
  sb.init({ exporter: new InMemorySpanExporter(), discover: false, serviceName: "billing", instrument: "off" });
  const d = sb.diagnostics();
  assert.deepEqual([d.serviceName, d.serviceNameSource], ["billing", "argument"]);
});
