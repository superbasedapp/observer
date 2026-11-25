// The setup command (plan 3.5 to 3.8; sdk-api-surface.md section 17) against
// L0's sdk/contract/setup-cases.json, with three loopback stubs that serve
// the bodies of sdk/contract/fixtures/setup: the cloud (create and poll), the
// organization's host (redeem, the ingest gateway, the trace cost read,
// revoke) and this machine's Observer (discovery, the AI Apps status and
// enable, the trace read, the local receiver). setup runs in-process
// (runSetup with injected dependencies and a fast clock); one test runs the
// real bin.
import { test, beforeEach, after } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import * as sb from "../dist/esm/index.js";
import { runSetup } from "../dist/esm/setup/run.js";
import { httpFetch } from "../dist/esm/setup/net.js";
import { defaultWriteDeps, credentialText, icaclsArgs, ownerDecision, OWNER_ROWS, setOwnerArgs, writeCredentialFile } from "../dist/esm/setup/credwrite.js";
import { detect, heldFact, installArgv, installPackages, nextSteps, planDestination, DESTINATION_ROWS } from "../dist/esm/setup/plan.js";
import { parseArgs } from "../dist/esm/setup/args.js";
import { machineName, newRedeemSecret, pollOutcome, redeemHash } from "../dist/esm/setup/device.js";
import { deadUrl, reset, startStub } from "./helpers.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const pkgRoot = join(here, "..");
const contractDir = process.env.SUPERBASED_CONTRACT_DIR || join(here, "..", "..", "contract");
const load = (f) => (existsSync(join(contractDir, f)) ? JSON.parse(readFileSync(join(contractDir, f), "utf8")) : null);
const CASES = load("setup-cases.json");
const FX = CASES
  ? {
      create: load("fixtures/setup/connect-create.json"),
      poll: load("fixtures/setup/connect-poll.json"),
      redeem: load("fixtures/setup/grant-redeem.json"),
      revoke: load("fixtures/setup/key-revoke.json"),
      file: load("fixtures/setup/sdk-credential-file.json"),
      fakes: load("fixtures/setup/secrecy-fakes.json"),
    }
  : null;
const REFUSALS = load("plan-refusal-cases.json");
const skip = !CASES && "sdk/contract/setup-cases.json is not present";
const unix = process.platform !== "win32";
const forTs = (c) => !c.sdks || c.sdks.includes("typescript");

beforeEach(reset);
after(reset);

// --- the harness --------------------------------------------------------------

function fastClock() {
  let t = Date.UTC(2027, 0, 15, 8, 0, 0);
  return {
    now: () => t,
    sleep: async (ms) => {
      t += ms;
      await new Promise((r) => setImmediate(r));
    },
  };
}

const capture = () => {
  const lines = [];
  return { lines, write: (s) => lines.push(s), text: () => lines.join("") };
};

/** A fixture response as a stub reply ({status, body, headers}). */
const reply = (fx, name, patch) => {
  const r = fx.responses[name];
  assert.ok(r, `fixture response ${name}`);
  const body = patch ? patch(structuredClone(r.body)) : r.body;
  return { status: r.status, body, headers: Object.fromEntries(Object.entries(r.headers ?? {}).filter(([k]) => k !== "Content-Type")) };
};

/**
 * Run setup through the stubs. scenario: create, polls, redeem (name or
 * list), hello (arrived | not_seen | a plan-refusal case name), machine (null
 * or {signed_in, local_enabled}), flags, tty, answers, observerOnPath,
 * sdkFile ("valid"), files (project), openBrowser (true), write ("fails"),
 * revoke.
 */
async function runScenario(sc) {
  const root = mkdtempSync(join(tmpdir(), "sbo-setup-"));
  const project = join(root, "app");
  mkdirSync(project, { recursive: true });
  for (const [rel, body] of Object.entries(sc.files ?? { "package.json": JSON.stringify({ name: "support-bot", dependencies: { openai: "^5" } }), "server.js": "" })) {
    mkdirSync(dirname(join(project, rel)), { recursive: true });
    writeFileSync(join(project, rel), body);
  }
  const credDir = join(root, "home", ".config", "superbased");
  const credPath = join(credDir, "sdk-credential");
  const cloud = await startStub();
  const tenant = await startStub();
  const machine = sc.machine ? await startStub() : null;
  const polls = [...(sc.polls ?? ["approved_with_grant"])];
  const redeems = Array.isArray(sc.redeem) ? [...sc.redeem] : [sc.redeem ?? "minted"];
  const tenantBase = tenant.url;
  let redeemBodies = [];
  cloud.handler = (r) => {
    if (r.method === "POST" && r.path === "/v1/connect/requests") return reply(FX.create, sc.create ?? "created");
    if (r.method === "GET" && r.path.startsWith("/v1/connect/requests/")) {
      const name = polls.length > 1 ? polls.shift() : polls[0];
      return reply(FX.poll, name, (b) => {
        if (b?.target?.server_url) b.target.server_url = tenantBase;
        return b;
      });
    }
    return { status: 404, body: {} };
  };
  const refusal = sc.hello && sc.hello !== "arrived" && sc.hello !== "not_seen" ? REFUSALS.cases.find((c) => c.name === sc.hello) : null;
  tenant.handler = (r) => {
    if (r.method === "POST" && r.path === "/api/agent/sdk-credential/grant") {
      redeemBodies.push(r.body);
      const name = redeems.length > 1 ? redeems.shift() : redeems[0];
      return reply(FX.redeem, name, (b) => {
        if (b?.gateway_url) b.gateway_url = tenantBase;
        return b;
      });
    }
    if (r.method === "POST" && r.path === "/v1/traces") {
      if (refusal) return { status: refusal.status, body: refusal.body, headers: refusal.headers ?? {} };
      return { status: 200, body: {} };
    }
    if (r.method === "GET" && /^\/v1\/sdk\/traces\/[0-9a-f]{32}\/cost$/.test(r.path)) {
      return sc.hello === "not_seen" ? { status: 404, body: { error: "not_found", message: "no such trace" } } : { status: 200, body: { api_version: "1", trace_id: r.path.split("/")[4] } };
    }
    if (r.method === "POST" && r.path === "/v1/sdk/credential/revoke") return reply(FX.revoke, sc.revoke ?? "revoked");
    return { status: 404, body: {} };
  };
  const enableState = { on: !!sc.machine?.local_enabled, statusReads: 0, enableBodies: [], enableHeaders: [] };
  let machineKeyFile = "";
  if (machine) {
    if (sc.machine.signed_in) {
      machineKeyFile = join(root, "machine-key");
      writeFileSync(machineKeyFile, `00000000000000000000000000000003.fake-machine-secret\ngateway_url=${tenantBase}\n`);
      chmodSync(machineKeyFile, 0o600);
    }
    machine.handler = (r) => {
      if (r.path === "/api/sdk/destination") {
        return {
          body: {
            api_version: 1,
            destination: "local",
            source: "config",
            configured: "",
            signed_in: !!sc.machine.signed_in,
            local: { enabled: enableState.on, otlp_traces_url: `${machine.url}/v1/traces` },
            online: sc.machine.signed_in ? { gateway_url: tenantBase, credential_present: true, credential_file: machineKeyFile, dashboard_url: "https://acme.superbased.app" } : {},
            warnings: [],
          },
        };
      }
      if (r.path === "/api/apps/status") {
        enableState.statusReads += 1;
        // With no terminal, the person clicks Turn on in the page setup opened.
        if (enableState.browserOpened && enableState.statusReads > 2) enableState.on = true;
        return {
          body: { on: enableState.on, consent: { sentence: "Stays on this machine." }, receiver: { http_addr: "127.0.0.1:4318" }, confirm_token: "c".repeat(64) },
          headers: { "Set-Cookie": `sb_remote_confirm=${"c".repeat(64)}; Path=/` },
        };
      }
      if (r.path === "/api/apps/enable") {
        enableState.enableBodies.push(r.body);
        enableState.enableHeaders.push(r.headers);
        enableState.on = true;
        return { body: { ok: true, outcome: "on" } };
      }
      if (r.path === "/v1/traces") return { body: {} };
      if (r.path.startsWith("/api/obs/trace/")) return { body: { trace_id: r.path.split("/").at(-1) } };
      return { status: 404, body: {} };
    };
  }
  if (sc.sdkFile === "valid" || sc.sdkFile === "expired" || sc.sdkFile === "refused") {
    // The harness clock starts 2027-01-15; "expired" is a year before it.
    const expires = sc.sdkFile === "expired" ? "2026-01-01T00:00:00Z" : "2099-01-01T00:00:00Z";
    mkdirSync(credDir, { recursive: true, mode: 0o700 });
    writeFileSync(credPath, `00000000000000000000000000000002.fake-sdk-file-secret\ngateway_url=${tenantBase}\ndestination=online\ndashboard_url=https://u-k7x2.superbased.app\nexpires_at=${expires}\n`);
    chmodSync(credPath, sc.sdkFile === "refused" ? 0o644 : 0o600);
  }
  const before = existsSync(credPath) ? readFileSync(credPath, "utf8") : null;
  if (sc.write === "fails") {
    // A folder that cannot be written (as root too): the folder's path is a file.
    mkdirSync(dirname(credDir), { recursive: true });
    writeFileSync(credDir, "");
  }
  const nodeUrl = machine ? machine.url : await deadUrl();
  process.env.SUPERBASED_CREDENTIAL_FILE = credPath;
  process.env.SUPERBASED_CLOUD_URL = cloud.url;
  process.env.SUPERBASED_NODE_URL = nodeUrl;
  process.env.SUPERBASED_DISCOVER_TIMEOUT_MS = "500";
  const out = capture();
  const err = capture();
  const asks = [];
  const opened = [];
  const installs = [];
  const logs = [];
  const answers = [...(sc.answers ?? [])];
  const consoleOrig = { log: console.log, warn: console.warn, info: console.info, error: console.error, debug: console.debug };
  for (const k of Object.keys(consoleOrig)) console[k] = (...a) => logs.push(a.map(String).join(" "));
  let exit;
  let thrown = "";
  try {
    exit = await runSetup(["setup", ...(sc.flags ?? [])], {
      env: process.env,
      cwd: project,
      home: join(root, "home"),
      platform: process.platform,
      hostname: "studio-mac",
      arch: "x64",
      tty: !!sc.tty,
      stdout: out,
      stderr: err,
      http: httpFetch,
      clock: fastClock(),
      ask: async (q) => {
        asks.push(q);
        return answers.length ? answers.shift() : false;
      },
      openBrowser: async (url) => {
        opened.push(url);
        if (url.includes("/apps?enable=1")) enableState.browserOpened = sc.openBrowser !== false;
        return sc.openBrowser !== false;
      },
      install: async (argv) => {
        installs.push([...argv]);
        return sc.installExit ?? 0;
      },
      onPath: () => !!sc.observerOnPath,
      write: defaultWriteDeps,
      version: "0.2.0",
    });
  } catch (e) {
    thrown = `${e}\n${e?.stack ?? ""}`;
  } finally {
    Object.assign(console, consoleOrig);
  }
  const after = existsSync(credPath) && statSync(credPath).isFile() ? readFileSync(credPath, "utf8") : null;
  const result = {
    exit,
    thrown,
    stdout: out.text(),
    stderr: err.text(),
    json: (sc.flags ?? []).includes("--json") ? out.text().split("\n").filter(Boolean).map((l) => JSON.parse(l)) : [],
    logs,
    asks,
    opened,
    installs,
    fileText: after,
    fileMode: after !== null ? statSync(credPath).mode & 0o777 : 0,
    fileWritten: after !== null && after !== before,
    credPath,
    pollRequests: cloud.requests.filter((r) => r.method === "GET").length,
    createBodies: cloud.requests.filter((r) => r.method === "POST").map((r) => r.body),
    pollHeaders: cloud.requests.filter((r) => r.method === "GET").map((r) => r.headers),
    redeemBodies,
    tenantRequests: tenant.requests,
    machineRequests: machine?.requests ?? [],
    enableState,
    helloSent: tenant.requests.some((r) => r.path === "/v1/traces") || (machine?.requests ?? []).some((r) => r.path === "/v1/traces"),
  };
  await sb.shutdown(300);
  await cloud.close();
  await tenant.close();
  if (machine) await machine.close();
  rmSync(root, { recursive: true, force: true });
  return result;
}

const allText = (r) => [r.stdout, r.stderr, ...r.logs, r.thrown].join("\n");

// --- detection ----------------------------------------------------------------

test("detection (setup-cases.json)", { skip }, () => {
  let ran = 0;
  for (const c of CASES.detection.cases) {
    if (c.want.language === "python") continue;
    const input = { files: Object.keys(c.files), packageJson: c.files["package.json"] ? JSON.parse(c.files["package.json"]) : null, installed: [] };
    const d = detect(input);
    if (c.want.language === null) {
      assert.equal(d.language, "", c.name);
      assert.equal(c.want.exit, 4);
      ran++;
      continue;
    }
    assert.equal(d.language, c.want.language, c.name);
    assert.equal(d.packageManager, c.want.package_manager, c.name);
    assert.deepEqual([...d.targets].sort(), c.want.targets, c.name);
    assert.deepEqual(installArgv(d.packageManager, installPackages(d, input, c.setup_version)), c.want.install, c.name);
    assert.equal(d.moduleType === "esm", c.want.esm, c.name);
    assert.equal(d.next, c.want.nextjs, c.name);
    ran++;
  }
  assert.ok(ran >= 8, `ran ${ran}`);
});

test("detection: no supported language exits 4 with the advice (Go points at --key-only)", { skip: !unix && "unix" }, async () => {
  const r = await runScenario({ files: { "go.mod": "module example.com/x\n" }, machine: null });
  assert.equal(r.exit, 4);
  assert.match(r.stdout, /--key-only/);
});

// --- next steps ---------------------------------------------------------------

test("next_steps (setup-cases.json)", { skip }, () => {
  let ran = 0;
  for (const c of CASES.next_steps.cases) {
    if (c.language !== "typescript") continue;
    const d = { language: "typescript", other: "", packageManager: "npm", packageManagerSource: "default", moduleType: c.esm ? "esm" : "cjs", next: c.nextjs, targets: [], entries: c.entry ? [c.entry] : [], startScript: "" };
    const n = nextSteps(d);
    if (c.want.init_line === null) assert.equal(n.initLine, "", c.name);
    else assert.equal(n.initLine, c.want.init_line, c.name);
    const placement = [n.where, n.file?.path ?? ""].join(" ");
    assert.ok(placement.includes(c.want.where), `${c.name}: ${placement}`);
    if (c.want.start_script) assert.ok(n.startScript.includes(c.want.start_script), `${c.name}: ${n.startScript}`);
    if (c.want.instrumentation_file) {
      assert.equal(n.file.path, c.want.instrumentation_file.path, c.name);
      assert.ok(n.file.content.includes(c.want.instrumentation_file.contains), c.name);
    }
    ran++;
  }
  assert.equal(ran, 3);
});

test("next steps: the app's own start script gets the flag; Next.js names its external packages", () => {
  const base = { language: "typescript", other: "", packageManager: "npm", packageManagerSource: "default", moduleType: "esm", next: false, targets: ["openai"], entries: ["server.js"], startScript: "node --env-file=.env server.js" };
  assert.equal(nextSteps(base).startScript, "node --import @superbased/sdk/register --env-file=.env server.js");
  assert.equal(nextSteps({ ...base, next: true }).externalPackages.join(","), "@superbased/sdk,openai");
  assert.equal(nextSteps({ ...base, startScript: "tsx watch src/index.ts" }).startScript, "node --import @superbased/sdk/register server.js");
});

// --- the destination plan -----------------------------------------------------

/** What the person answers each question, from the case's `answer`. */
function answersFor(c) {
  switch (c.answer) {
    case "both":
    case "online":
    case "y":
      return [true];
    case "local":
    case "n":
      return [false];
    default:
      return [];
  }
}

function approvalOf(r) {
  const phases = r.json.map((e) => e.phase);
  const approve = phases.includes("approve");
  const enable = r.json.find((e) => e.phase === "enable");
  const enablePrompt = enable?.asked === "terminal";
  const enableBrowser = enable?.asked === "dashboard";
  const asked = r.asks.some((q) => !/Turn on AI Apps/.test(q));
  if (approve && (enablePrompt || enableBrowser)) return "enable_and_browser";
  if (approve) return "browser";
  if (enablePrompt) return "enable_prompt";
  if (enableBrowser) return "enable_browser";
  if (asked) return "ask";
  return "none";
}

const CREDENTIAL = { device: "device_flow", held: "sdk_file", machine: "machine", none: "none" };

test("destination_plan (setup-cases.json), each case end to end", { skip: skip || (!unix && "unix file rules") }, async () => {
  let ran = 0;
  for (const c of CASES.destination_plan.cases.filter(forTs)) {
    await reset();
    const r = await runScenario({
      flags: [...c.flags, "--json"],
      machine: c.machine,
      observerOnPath: c.observer_on_path,
      tty: c.tty,
      answers: answersFor(c),
      sdkFile: c.sdk_file,
    });
    const dest = r.json.find((e) => e.phase === "destination");
    const name = `${c.name}: ${r.stdout}${r.stderr}`;
    if (c.want.exit) {
      assert.equal(r.exit, c.want.exit, name);
      const last = r.json.at(-1);
      if (last) assert.equal(last.phase, "error", name);
    } else {
      assert.equal(r.exit, 0, name);
      assert.equal(r.json.at(-1).phase, "done", name);
    }
    if (c.want.plan !== null) {
      assert.equal(dest?.destination, c.want.plan, name);
      assert.equal(CREDENTIAL[dest.credential], c.want.credential, name);
    } else if (dest) {
      // setup stopped at or after the plan (a declined enable stops later).
      assert.ok(dest.destination === null || r.exit === c.want.exit, name);
    }
    assert.equal(approvalOf(r), c.want.approval, name);
    assert.equal(r.fileWritten, c.want.writes_file, name);
    if (c.want.message_contains) assert.ok(allText(r).includes(c.want.message_contains), name);
    if (c.want.replaces_key_id) assert.equal(r.redeemBodies[0]?.replaces_key_id, "00000000000000000000000000000002", name);
    if (c.want.phases) {
      // --key-only: L0 lists destination, approve, credential, done; the lead
      // ruled that it still sends the hello, so `hello` sits between them.
      const phases = r.json.map((e) => e.phase);
      let i = 0;
      for (const p of phases) if (p === c.want.phases[i]) i++;
      assert.equal(i, c.want.phases.length, `${name}: ${phases.join(",")}`);
      assert.ok(!phases.includes("detect") && !phases.includes("install") && !phases.includes("next"), name);
    }
    ran++;
  }
  assert.ok(ran >= 20);
});

test("the plan table: one row per id, the pure planner alone", () => {
  const ids = DESTINATION_ROWS.map((r) => r.id);
  assert.equal(new Set(ids).size, ids.length);
  const f = (o) => ({ flag: "", replace: false, machine: { answers: false, signedIn: false, appsOn: false }, observerOnPath: false, held: "", tty: false, ...o });
  assert.equal(planDestination(f({})).row, "no_observer");
  assert.equal(planDestination(f({ held: "both" })).destination, "both");
  assert.equal(planDestination(f({ flag: "online", replace: true, held: "online", machine: { answers: true, signedIn: true, appsOn: true } })).credential, "machine", "R10: never a file beside Observer's key");
  assert.equal(planDestination(f({ flag: "local", observerOnPath: true })).exit, 4);
});

// --- the device flow ----------------------------------------------------------

test("device_flow (setup-cases.json)", { skip: skip || (!unix && "unix file rules") }, async () => {
  let ran = 0;
  for (const c of CASES.device_flow.cases.filter(forTs)) {
    await reset();
    const r = await runScenario({ flags: ["--online", "--no-install"], machine: null, create: c.create, polls: c.polls, redeem: c.redeem ?? "minted", hello: "arrived" });
    const name = `${c.name}: exit ${r.exit} ${r.stdout}${r.stderr}`;
    if (c.want.outcome === "continue") {
      assert.equal(r.exit, 0, name);
      assert.ok(r.helloSent, name);
    } else {
      assert.equal(r.exit, c.want.exit, name);
    }
    assert.equal(r.fileWritten, c.want.file_written, name);
    if (c.want.message_contains) assert.ok(allText(r).includes(c.want.message_contains), name);
    if (c.want.requests !== undefined) assert.equal(r.pollRequests, c.want.requests, name);
    ran++;
  }
  assert.ok(ran >= 21);
});

test("the wire: the create body, the poll bearer, the redeem body and the file's bytes and mode", { skip: skip || (!unix && "unix file rules") }, async () => {
  const r = await runScenario({ flags: ["--online", "--json"], machine: null });
  assert.equal(r.exit, 0, r.stderr);
  const create = r.createBodies[0];
  const rules = FX.create.request.body;
  assert.deepEqual(Object.keys(create).sort(), Object.keys(rules).sort());
  assert.equal(create.purpose, "sdk_key");
  assert.equal(create.client, "superbased-sdk-typescript");
  assert.equal(create.client_version, "0.2.0");
  assert.equal(create.project_name, "support-bot");
  assert.equal(create.machine_name, "studio-mac");
  assert.match(create.redeem_hash, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(r.pollHeaders[0].authorization, `Bearer ${FX.create.responses.created.body.device_code}`);
  const redeem = r.redeemBodies[0];
  assert.deepEqual(Object.keys(redeem).sort(), Object.keys(FX.redeem.request.body).sort());
  assert.equal(redeem.key_grant, FX.poll.responses.approved_with_grant.body.key_grant);
  assert.match(redeem.redeem_secret, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(redeemHash(redeem.redeem_secret), create.redeem_hash, "the create carries the secret's hash");
  assert.equal(redeem.replaces_key_id, "");
  // The file: the fixture's lines, with the gateway the stub stands in for.
  const lines = FX.file.lines.map((l) => (l.startsWith("gateway_url=") ? `gateway_url=${r.json.find((e) => e.phase === "credential").gateway_url}` : l));
  assert.equal(r.fileText, lines.join("\n") + "\n");
  assert.equal(r.fileMode, 0o600);
  const phases = r.json.map((e) => e.phase);
  assert.deepEqual(phases, ["detect", "destination", "install", "approve", "credential", "hello", "next", "done"]);
  const approve = r.json.find((e) => e.phase === "approve");
  assert.equal(approve.user_code, "KTRW-4821");
  assert.equal(approve.expires_in, 900);
  assert.equal(r.json.find((e) => e.phase === "credential").written, true);
  const done = r.json.at(-1);
  assert.equal(done.exit, 0);
  assert.match(done.trace_url, /^https:\/\/u-k7x2\.superbased\.app\/trajectories\?trace=[0-9a-f]{32}$/);
  assert.deepEqual(r.installs, [["npm", "install", "@superbased/sdk@^0.2.0", "@arizeai/openinference-instrumentation-openai"]]);
  assert.deepEqual(r.opened, [FX.create.responses.created.body.approve_url]);
  // The hello span: its name, the SDK-owned key, and no content.
  const hello = r.tenantRequests.find((x) => x.path === "/v1/traces");
  const span = hello.body.resourceSpans[0].scopeSpans[0].spans[0];
  assert.equal(span.name, "superbased setup: hello from support-bot");
  const attrs = Object.fromEntries(span.attributes.map((a) => [a.key, a.value]));
  assert.deepEqual(attrs["sbo.setup.hello"], { boolValue: true });
  assert.ok(!Object.keys(attrs).some((k) => /input|output|content|prompt/.test(k)), Object.keys(attrs).join(","));
  assert.equal(hello.headers.authorization, `Bearer ${FX.redeem.responses.minted.body.credential}`);
});

test("pollOutcome: every connect-poll.json response maps to a state", { skip }, () => {
  const want = { pending: "wait", approved_not_ready: "wait", approved_with_grant: "grant", declined: 2, expired: 2, window_closed: 2, already_delivered: 2, rate_limited: "wait", unauthorized: 2, not_found: 2 };
  for (const [name, w] of Object.entries(want)) {
    const r = FX.poll.responses[name];
    const o = pollOutcome(r.status, r.body, r.headers?.["Retry-After"] ?? "", 3);
    assert.equal(typeof w === "number" ? o.exit : o.kind, w, name);
  }
  assert.equal(pollOutcome(429, {}, "5", 3).delayMs, 5000, "Retry-After");
});

// --- first-run refusals -------------------------------------------------------

test("first_run_refusals (setup-cases.json)", { skip: skip || (!unix && "unix file rules") }, async () => {
  let ran = 0;
  for (const c of CASES.first_run_refusals.cases.filter(forTs)) {
    await reset();
    const r = await runScenario(c.stage === "redeem" ? { flags: ["--online", "--no-install"], machine: null, redeem: c.fixture } : { flags: ["--online", "--no-install"], machine: null, hello: c.plan_refusal_case });
    const name = `${c.name}: exit ${r.exit} ${r.stdout}${r.stderr}`;
    assert.equal(r.exit, c.want.exit, name);
    assert.equal(r.fileWritten, c.want.file_written, name);
    assert.equal(r.helloSent, c.want.hello_sent, name);
    const printed = r.stdout.split("\n");
    let at = 0;
    for (const want of c.want.lines) {
      const i = printed.findIndex((l, k) => k >= at && l.includes(want));
      assert.ok(i >= 0, `${name}: missing, in order, ${JSON.stringify(want)}`);
      at = i + 1;
    }
    for (const no of c.want.no_line_contains ?? []) assert.ok(!r.stdout.includes(no), `${name}: ${no}`);
    ran++;
  }
  assert.equal(ran, 5);
});

// --- local: the enable --------------------------------------------------------

test("local enable on a terminal: the consent, y, the confirm token and source sdk-setup, then the local link", { skip: !unix && "unix" }, async () => {
  const r = await runScenario({ flags: ["--json"], machine: { signed_in: false, local_enabled: false }, observerOnPath: true, tty: true, answers: [true] });
  assert.equal(r.exit, 0, r.stderr);
  assert.match(r.asks[0], /Turn on AI Apps on this computer\? It listens on 127\.0\.0\.1:4318 only\. Stays on this machine\. \[y\/N\]/);
  assert.deepEqual(r.enableState.enableBodies, [{ source: "sdk-setup" }]);
  assert.equal(r.enableState.enableHeaders[0]["x-observer-confirm"], "c".repeat(64));
  assert.match(r.enableState.enableHeaders[0].cookie, /sb_remote_confirm=c{64}/);
  assert.match(r.json.at(-1).trace_url, /^http:\/\/127\.0\.0\.1:\d+\/apps\/traces\?trace=[0-9a-f]{32}$/);
  assert.ok(r.machineRequests.some((x) => x.path.startsWith("/api/obs/trace/")), "the arrival check reads the machine");
});

test("local enable with no terminal and no browser: the page and observer apps on, exit 2", { skip: !unix && "unix" }, async () => {
  const r = await runScenario({ flags: [], machine: { signed_in: false, local_enabled: false }, observerOnPath: true, tty: false, openBrowser: false });
  assert.equal(r.exit, 2);
  assert.match(r.stdout, /\/apps\?enable=1&from=setup/);
  assert.match(r.stdout, /observer apps on/);
});

// --- hello, idempotence, forget, status ---------------------------------------

test("sent but not seen in 60 s: exit 5, the link still printed", { skip: !unix && "unix" }, async () => {
  const r = await runScenario({ flags: ["--online", "--no-install", "--json"], machine: null, hello: "not_seen" });
  assert.equal(r.exit, 5, r.stderr);
  const done = r.json.at(-1);
  assert.deepEqual([done.phase, done.exit, done.arrived], ["done", 5, false]);
  assert.match(r.stderr, /Sent, not seen yet .*trajectories\?trace=/);
});

test("a second run with the held file: no sign-in again", { skip: !unix && "unix" }, async () => {
  const r = await runScenario({ flags: ["--json", "--no-install"], machine: null, sdkFile: "valid" });
  assert.equal(r.exit, 0, r.stderr);
  assert.equal(r.createBodies.length, 0);
  assert.equal(r.fileWritten, false);
});

test("--forget revokes the key with itself and removes the file; --status never prints the key", { skip: !unix && "unix" }, async () => {
  const st = await runScenario({ flags: ["--status", "--json"], machine: null, sdkFile: "valid" });
  assert.equal(st.exit, 0);
  const status = st.json.find((e) => e.phase === "status");
  assert.equal(status.valid, true);
  assert.equal(status.key_id, "00000000000000000000000000000002");
  assert.ok(!allText(st).includes("fake-sdk-file-secret"));
  const f = await runScenario({ flags: ["--forget", "--json"], machine: null, sdkFile: "valid" });
  assert.equal(f.exit, 0);
  const rv = f.tenantRequests.find((x) => x.path === "/v1/sdk/credential/revoke");
  assert.equal(rv.headers.authorization, "Bearer 00000000000000000000000000000002.fake-sdk-file-secret");
  assert.equal(f.fileText, null, "the file is gone");
  assert.deepEqual(f.json.find((e) => e.phase === "forget"), { phase: "forget", credential_file: f.credPath, removed: true, revoked: true });
  const g = await runScenario({ flags: ["--forget"], machine: null, sdkFile: "valid", revoke: "unauthorized" });
  assert.equal(g.fileText, null, "the file goes even when the revoke fails");
  assert.match(g.stdout, /not revoked/);
});

// --- secrecy (SDKQS-4) --------------------------------------------------------

test("secrecy (setup-cases.json): no channel carries the key, its secret, the device code, the redeem secret or the grant", { skip: skip || (!unix && "unix file rules") }, async () => {
  const fakes = FX.fakes;
  let ran = 0;
  for (const c of CASES.secrecy.cases.filter(forTs)) {
    for (const json of [false, true]) {
      await reset();
      const s = c.scenario;
      const flags = s.flags ? [...s.flags] : ["--online"];
      if (json) flags.push("--json");
      const r = await runScenario({ flags, machine: null, create: s.create, polls: s.polls, redeem: s.redeem ?? "minted", hello: s.hello ?? "arrived", sdkFile: s.sdk_file, revoke: s.revoke, write: s.write });
      const secrets = [fakes.sdk_key, fakes.sdk_key_secret, fakes.device_code, fakes.redeem_secret, fakes.key_grant, ...r.redeemBodies.map((b) => b.redeem_secret), "fake-sdk-file-secret"];
      const channels = {
        stdout: r.stdout,
        stderr: r.stderr,
        json: r.json.map((e) => JSON.stringify(e)).join("\n"),
        log: r.logs.join("\n"),
        exception: r.thrown,
        argv: JSON.stringify(r.installs),
      };
      for (const ch of c.want.channels) {
        for (const sec of secrets) assert.ok(!channels[ch].includes(sec), `${c.name} (json ${json}): ${ch} carries a secret`);
      }
      // The reporter never had to take a secret out: the phases never wrote one.
      assert.ok(!allText(r).includes("[redacted]"), `${c.name}: a phase tried to print a secret`);
      if (s.write === "fails") assert.equal(r.exit, 4, `${c.name}: ${r.stderr}`);
      ran++;
    }
  }
  assert.ok(ran >= 14);
});

test("the redactor: a registered secret and its secret half never pass", async () => {
  const { Reporter } = await import("../dist/esm/setup/output.js");
  const out = capture();
  const rep = new Reporter(true, out, out);
  rep.secret("00000000000000000000000000000001.FAKE-sdk-key-secret");
  rep.say("x 00000000000000000000000000000001.FAKE-sdk-key-secret y");
  rep.event("e", { v: "FAKE-sdk-key-secret" });
  assert.ok(!out.text().includes("FAKE-sdk-key-secret"));
  assert.equal(rep.redactions, 2);
});

// --- no AI gateway (SDKQS-10), no R-165 (SDKQS-8) -----------------------------

test("no_ai_gateway: no output, --json line or next-steps text names it", { skip: skip || (!unix && "unix file rules") }, async () => {
  const forbidden = CASES.no_ai_gateway.forbidden.map((f) => f.toLowerCase());
  const texts = [];
  for (const sc of [
    { flags: ["--online", "--json"], machine: null },
    { flags: ["--both"], machine: { signed_in: false, local_enabled: true } },
    { flags: ["--key-only", "--json"], machine: null },
    { flags: [], machine: { signed_in: true, local_enabled: true } },
    { flags: ["--status"], machine: null, sdkFile: "valid" },
  ]) {
    await reset();
    texts.push(allText(await runScenario(sc)));
  }
  for (const c of CASES.detection.cases) {
    if (!c.files["package.json"]) continue;
    const input = { files: Object.keys(c.files), packageJson: JSON.parse(c.files["package.json"]), installed: [] };
    texts.push(JSON.stringify(nextSteps(detect(input))));
  }
  const { USAGE } = await import("../dist/esm/setup/args.js");
  texts.push(USAGE);
  for (const t of texts) for (const f of forbidden) assert.ok(!t.toLowerCase().includes(f), `names ${f}: ${t.slice(0, 200)}`);
});

test("no_r165: the setup sources never name the machine's credential routes or the sign-in verbs", { skip }, () => {
  const dir = join(pkgRoot, "src", "setup");
  for (const f of readdirSync(dir)) {
    const src = readFileSync(join(dir, f), "utf8");
    for (const s of CASES.no_r165.forbidden_in_source) assert.ok(!src.includes(s), `${f} names ${s}`);
  }
});

test("setup imports Node built-ins and the pure SDK modules only; the runtime never imports setup", () => {
  const dir = join(pkgRoot, "src", "setup");
  const allowed = new Set(["../targets.js", "../credfile.js", "../project.js", "../config.js"]);
  for (const f of readdirSync(dir)) {
    const src = readFileSync(join(dir, f), "utf8");
    for (const m of src.matchAll(/^import\s+(type\s+)?[^;]*?from\s+"([^"]+)"/gms)) {
      const [, typeOnly, spec] = m;
      if (spec.startsWith("node:") || spec.startsWith("./") || typeOnly) continue;
      assert.ok(allowed.has(spec), `${f} imports ${spec}`);
    }
  }
  // The pure modules setup reads import nothing but Node built-ins and each other.
  for (const f of ["targets.ts", "credfile.ts", "project.ts", "config.ts"]) {
    const src = readFileSync(join(pkgRoot, "src", f), "utf8");
    for (const m of src.matchAll(/^import\s+(type\s+)?[^;]*?from\s+"([^"]+)"/gms)) assert.ok(m[2].startsWith("node:") || m[2].startsWith("./"), `${f} imports ${m[2]}`);
  }
  for (const f of readdirSync(join(pkgRoot, "src")).filter((x) => x.endsWith(".ts"))) {
    assert.ok(!/from\s+"\.\/setup\//.test(readFileSync(join(pkgRoot, "src", f), "utf8")), `${f} imports setup`);
  }
});

// --- the owner table and the held-file fact (lead rulings) ----------------------

test("the Windows owner table: one case per row", () => {
  const rows = [
    [{ platform: "linux", daclSet: false, ownerSet: false }, "unix", "write"],
    [{ platform: "darwin", daclSet: true, ownerSet: true }, "unix", "write"],
    [{ platform: "win32", daclSet: true, ownerSet: false }, "owner_not_set", "refuse"],
    [{ platform: "win32", daclSet: false, ownerSet: false }, "owner_not_set", "refuse"],
    [{ platform: "win32", daclSet: false, ownerSet: true }, "dacl_not_set", "warn"],
    [{ platform: "win32", daclSet: true, ownerSet: true }, "both_set", "write"],
  ];
  for (const [facts, row, kind] of rows) {
    const d = ownerDecision(facts, "p");
    assert.deepEqual([d.row, d.kind], [row, kind], JSON.stringify(facts));
  }
  assert.deepEqual(OWNER_ROWS.map((r) => r.id), ["unix", "owner_not_set", "dacl_not_set", "both_set"]);
});

test("heldFact: an expired or refused file counts as missing; a valid one is held", () => {
  const now = Date.parse("2027-04-01T00:00:00Z");
  const rec = (o) => ({ record: { gateway: "https://gw", destination: "online", expiresAt: "2027-06-01T00:00:00Z", ...o } });
  assert.equal(heldFact(rec({}), now), "online");
  assert.equal(heldFact(rec({ destination: "both" }), now), "both");
  assert.equal(heldFact(rec({ expiresAt: "" }), now), "online", "no expiry known: held");
  assert.equal(heldFact(rec({ expiresAt: "2027-03-01T00:00:00Z" }), now), "", "expired");
  assert.equal(heldFact(rec({ gateway: "" }), now), "", "no usable gateway");
  assert.equal(heldFact({ record: null }, now), "", "refused or absent");
  const f = { flag: "", replace: false, machine: { answers: false, signedIn: false, appsOn: false }, observerOnPath: false, tty: false };
  assert.equal(planDestination({ ...f, held: heldFact(rec({ expiresAt: "2027-03-01T00:00:00Z" }), now) }).credential, "device", "expired: the device flow, no --replace");
  assert.equal(planDestination({ ...f, held: heldFact({ record: null }, now) }).credential, "device", "refused: the device flow");
  assert.equal(planDestination({ ...f, held: heldFact(rec({}), now) }).credential, "held", "valid: no sign-in");
});

test("a rerun with an expired or a refused file runs the device flow without --replace (with and without --key-only)", { skip: !unix && "unix" }, async () => {
  for (const [what, prep, flags] of [
    ["expired", "expired", []],
    ["expired, --key-only", "expired", ["--key-only"]],
    ["refused (mode 0644)", "refused", []],
  ]) {
    await reset();
    const r = await runScenario({ flags: [...flags, "--json", "--no-install"], machine: null, sdkFile: prep });
    assert.equal(r.exit, 0, `${what}: ${r.stderr}`);
    assert.equal(r.createBodies.length, 1, `${what}: the device flow ran`);
    assert.equal(r.redeemBodies[0].replaces_key_id, "", what);
    assert.equal(r.fileWritten, true, what);
    assert.equal(r.fileMode, 0o600, what);
    assert.match(r.stderr, /setup will set up a new key/, what);
  }
});

// --- small pure pieces --------------------------------------------------------

test("args: flags, values, and the refusals", () => {
  assert.equal(parseArgs([]).command, "help");
  assert.equal(parseArgs(["setup", "--online", "--team", "acme"]).team, "acme");
  assert.equal(parseArgs(["setup", "--team=acme"]).team, "acme");
  assert.throws(() => parseArgs(["setup", "--local", "--online"]), /choose one/);
  assert.throws(() => parseArgs(["setup", "--replace", "--local"]), /--replace/);
  assert.throws(() => parseArgs(["setup", "--team", "../x"]), /slug/);
  assert.throws(() => parseArgs(["setup", "--bogus"]), /unknown option/);
  assert.equal(parseArgs(["setup"], { SUPERBASED_CLOUD_URL: "http://127.0.0.1:9" }).cloudUrl, "http://127.0.0.1:9");
});

test("redeem secret and hash: 43 base64url characters each (L0's vector)", () => {
  assert.match(newRedeemSecret(), /^[A-Za-z0-9_-]{43}$/);
  assert.equal(redeemHash("fake-redeem-secret-for-tests-only-000000000"), "4gCLlovTgfGzwK4urGu0ushPtJ7SF1a3E6QVBfFb1Ks");
  assert.equal(machineName("  my‮box\u0007 "), "mybox");
});

test("the writer: owner-only, atomic, icacls once on Windows, never the key in argv", { skip: !unix && "unix" }, () => {
  const dir = mkdtempSync(join(tmpdir(), "sbo-w-"));
  try {
    const p = join(dir, "sub", "sdk-credential");
    const rec = { key: "k1.secretsecret", gatewayUrl: "https://gw.example", destination: "online", dashboardUrl: "", expiresAt: "" };
    assert.equal(writeCredentialFile(p, rec), "");
    assert.equal(statSync(p).mode & 0o777, 0o600);
    assert.equal(statSync(dirname(p)).mode & 0o777, 0o700);
    assert.equal(readFileSync(p, "utf8"), credentialText(rec));
    assert.deepEqual(readdirSync(dirname(p)), ["sdk-credential"], "no temporary file left");
    // Windows: the DACL, then this user as the owner, both on the still-empty temporary file.
    const calls = [];
    const p2 = join(dir, "win", "sdk-credential");
    const win = (icacls) => ({ platform: "win32", windowsUser: () => "DOM\\me", icacls });
    assert.equal(writeCredentialFile(p2, rec, win((a) => calls.push([...a, readFileSync(a[0], "utf8")]))), "");
    assert.equal(calls.length, 2);
    for (const c of calls) {
      assert.equal(c.at(-1), "", "set while the temporary file is still empty");
      assert.match(c[0], /sdk-credential\.tmp-/);
      c.pop();
    }
    assert.deepEqual(calls[0].slice(1), icaclsArgs("x", "DOM\\me").slice(1));
    assert.deepEqual(calls[1].slice(1), setOwnerArgs("x", "DOM\\me").slice(1));
    assert.ok(!JSON.stringify(calls).includes("secretsecret"));
    // The DACL failed, the owner was set: written, with a warning.
    assert.match(writeCredentialFile(join(dir, "win2", "c"), rec, win((a) => { if (a[1] !== "/setowner") throw new Error("no"); })), /icacls/);
    // The owner could not be set (an elevated terminal): nothing is written.
    const p3 = join(dir, "win3", "c");
    assert.throws(() => writeCredentialFile(p3, rec, win((a) => { if (a[1] === "/setowner") throw new Error("no"); })), /non-elevated terminal/);
    assert.deepEqual(readdirSync(dirname(p3)), [], "no file and no temporary file left");
    assert.throws(() => credentialText({ ...rec, gatewayUrl: "https://x\ninjected=1" }), /printable ASCII/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the bin: superbased-sdk setup --status runs from dist/setup/cli.js", { skip: !unix && "unix" }, () => {
  const dir = mkdtempSync(join(tmpdir(), "sbo-bin-"));
  try {
    const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^(SUPERBASED_|OTEL_)/.test(k)));
    env.SUPERBASED_CREDENTIAL_FILE = join(dir, "none");
    env.SUPERBASED_NODE_URL = "http://127.0.0.1:9";
    const r = spawnSync(join(pkgRoot, "dist", "setup", "cli.js"), ["setup", "--status", "--json"], { encoding: "utf8", env, cwd: dir });
    assert.equal(r.status, 0, r.stderr);
    const lines = r.stdout.trim().split("\n").map((l) => JSON.parse(l));
    assert.deepEqual(lines.map((l) => l.phase), ["status", "done"]);
    assert.equal(lines[0].present, false);
    const pkg = JSON.parse(readFileSync(join(pkgRoot, "package.json"), "utf8"));
    assert.deepEqual(pkg.bin, { "superbased-sdk": "dist/setup/cli.js" });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
