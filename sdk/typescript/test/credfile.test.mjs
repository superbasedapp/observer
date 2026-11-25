// Plan 3.4: the SDK-held credential file. The path ladder per OS, the reader
// rules (unix and Windows, ruling R4), and its two rungs: the destination
// ladder's `sdk_file` and the credential ladder's third record (ruling R10).
// L0's credential-file-cases.json runs in behaviour.test.mjs when present;
// these pin the TypeScript half on their own.
import { test, beforeEach, after } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import * as sb from "../dist/esm/index.js";
import { expiryNote, readCredentialRecord, sdkCredentialPath } from "../dist/esm/credfile.js";
import { deadUrl, reset, startStub } from "./helpers.mjs";

beforeEach(reset);
after(reset);

const KEY = "00000000000000000000000000000001.FAKE-sdk-key-secret-for-contract-tests-only";
const unix = process.platform !== "win32";

function scratch() {
  return mkdtempSync(join(tmpdir(), "sbo-cred-"));
}

/** Write an SDK-held file (mode 0600) and point SUPERBASED_CREDENTIAL_FILE at it. */
function heldFile(dir, lines, mode = 0o600) {
  const f = join(dir, "sdk-credential");
  writeFileSync(f, lines.join("\n") + "\n");
  chmodSync(f, mode);
  process.env.SUPERBASED_CREDENTIAL_FILE = f;
  return f;
}

test("path ladder: the override, XDG, ~/.config, %LOCALAPPDATA%", () => {
  const rows = [
    ["override wins", { platform: "linux", env: { SUPERBASED_CREDENTIAL_FILE: "/tmp/other", XDG_CONFIG_HOME: "/x" }, home: "/home/me" }, "/tmp/other"],
    ["XDG_CONFIG_HOME", { platform: "linux", env: { XDG_CONFIG_HOME: "/home/me/.cfg" }, home: "/home/me" }, "/home/me/.cfg/superbased/sdk-credential"],
    ["relative XDG ignored", { platform: "linux", env: { XDG_CONFIG_HOME: "cfg" }, home: "/home/me" }, "/home/me/.config/superbased/sdk-credential"],
    ["~/.config", { platform: "darwin", env: {}, home: "/Users/me" }, "/Users/me/.config/superbased/sdk-credential"],
    ["%LOCALAPPDATA%", { platform: "win32", env: { LOCALAPPDATA: "C:\\Users\\me\\AppData\\Local" }, home: "C:\\Users\\me" }, "C:\\Users\\me\\AppData\\Local\\superbased\\sdk-credential"],
    ["no %LOCALAPPDATA%: no default path", { platform: "win32", env: {}, home: "C:\\Users\\me" }, ""],
    ["override on Windows", { platform: "win32", env: { SUPERBASED_CREDENTIAL_FILE: "D:\\k" }, home: "C:\\Users\\me" }, "D:\\k"],
    ["nothing known", { platform: "linux", env: {}, home: "" }, ""],
  ];
  for (const [what, facts, want] of rows) assert.equal(sdkCredentialPath(facts), want, what);
});

test("format: the file setup writes parses whole (the L0 fixture's lines)", () => {
  const r = sb.parseCredentialText(
    [KEY, "gateway_url=https://u-k7x2.superbased.app", "destination=online", "dashboard_url=https://u-k7x2.superbased.app", "expires_at=2027-04-15T08:00:30Z"].join("\n") + "\n",
    "f",
  );
  assert.equal(r.error, "");
  assert.deepEqual(r.warnings, []);
  assert.deepEqual(r.record, {
    key: KEY,
    keyId: "00000000000000000000000000000001",
    gateway: "https://u-k7x2.superbased.app",
    destination: "online",
    dashboardUrl: "https://u-k7x2.superbased.app",
    expiresAt: "2027-04-15T08:00:30Z",
  });
});

test("format: what refuses the file, and what only drops one name", () => {
  const refused = [
    ["missing dot", "abc\n", /not one <key_id>.<secret> line/],
    ["whitespace in key", "ab c.d\n", /not one <key_id>.<secret> line/],
    ["bad name line", "a.b\nno-equals-sign\n", /not one <key_id>.<secret> line/],
    ["empty name", "a.b\n=x\n", /not one <key_id>.<secret> line/],
    ["non-ASCII", "a.b\nx=é\n", /non-ASCII/],
    ["over 4096 bytes", "a.b\nx=" + "y".repeat(4100) + "\n", /too large/],
    ["empty", "", /empty/],
  ];
  for (const [what, raw, err] of refused) {
    const r = sb.parseCredentialText(raw, "f");
    assert.equal(r.record, null, what);
    assert.match(r.error, err, what);
  }
  const dropped = [
    ["unknown name ignored", "a.b\nfuture=1\n", {}, 0],
    ["http to a remote gateway", "a.b\ngateway_url=http://gw.example\n", { gateway: "" }, 1],
    ["gateway with a path", "a.b\ngateway_url=https://gw.example/v1\n", { gateway: "" }, 1],
    ["gateway with user info", "a.b\ngateway_url=https://u:p@gw.example\n", { gateway: "" }, 1],
    ["loopback http gateway is fine", "a.b\ngateway_url=http://127.0.0.1:9\n", { gateway: "http://127.0.0.1:9" }, 0],
    ["destination local ignored", "a.b\ndestination=local\n", { destination: "" }, 1],
    ["destination nonsense ignored", "a.b\ndestination=moon\n", { destination: "" }, 1],
    ["destination both", "a.b\ndestination=BOTH\n", { destination: "both" }, 0],
    ["dashboard not https", "a.b\ndashboard_url=http://dash.example\n", { dashboardUrl: "" }, 1],
    ["dashboard on loopback http is not https either", "a.b\ndashboard_url=http://127.0.0.1:8081\n", { dashboardUrl: "" }, 1],
    ["dashboard with a path", "a.b\ndashboard_url=https://dash.example/trajectories\n", { dashboardUrl: "" }, 1],
    ["expires_at not RFC 3339", "a.b\nexpires_at=tomorrow\n", { expiresAt: "" }, 1],
    ["CRLF line ends", "a.b\r\ndestination=online\r\n", { destination: "online" }, 0],
  ];
  for (const [what, raw, want, nWarn] of dropped) {
    const r = sb.parseCredentialText(raw, "f");
    assert.equal(r.error, "", what);
    assert.equal(r.record.key, "a.b", what);
    for (const [k, v] of Object.entries(want)) assert.equal(r.record[k], v, what);
    assert.equal(r.warnings.length, nWarn, `${what}: ${r.warnings.join("; ")}`);
  }
});

test("reader (unix): symlink, group/other bits, foreign owner, a directory, a missing file", { skip: !unix && "unix rules" }, () => {
  const dir = scratch();
  try {
    const good = join(dir, "good");
    writeFileSync(good, "a.b\n", { mode: 0o600 });
    chmodSync(good, 0o600);
    assert.equal(readCredentialRecord(good).record.key, "a.b");
    const link = join(dir, "link");
    symlinkSync(good, link);
    assert.match(readCredentialRecord(link).error, /symlink/);
    const open = join(dir, "open");
    writeFileSync(open, "a.b\n");
    chmodSync(open, 0o640);
    assert.match(readCredentialRecord(open).error, /readable by others/);
    assert.match(readCredentialRecord(good, { uid: process.getuid() + 1 }).error, /not owned by this user/);
    mkdirSync(join(dir, "adir"));
    assert.match(readCredentialRecord(join(dir, "adir")).error, /not a regular file/);
    const big = join(dir, "big");
    writeFileSync(big, "a.b\nx=" + "y".repeat(5000) + "\n", { mode: 0o600 });
    chmodSync(big, 0o600);
    assert.match(readCredentialRecord(big).error, /too large/);
    assert.deepEqual(readCredentialRecord(join(dir, "missing")), { record: null, error: "", reason: "", warnings: [], ignored: [] });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("reader (Windows rules, R4): a reparse point and a file outside %LOCALAPPDATA% are refused; mode bits are not checked", () => {
  const dir = scratch();
  try {
    const root = join(dir, "AppData", "Local");
    mkdirSync(join(root, "superbased"), { recursive: true });
    const inRoot = join(root, "superbased", "sdk-credential");
    writeFileSync(inRoot, "a.b\n");
    chmodSync(inRoot, 0o644); // the DACL is setup's job; the reader does not check it
    assert.equal(readCredentialRecord(inRoot, { platform: "win32", windowsRoot: root }).record.key, "a.b");
    const outside = join(dir, "elsewhere");
    writeFileSync(outside, "a.b\n");
    assert.match(readCredentialRecord(outside, { platform: "win32", windowsRoot: root }).error, /not under this user's %LOCALAPPDATA%/);
    assert.match(readCredentialRecord(inRoot, { platform: "win32", windowsRoot: "" }).error, /not under/);
    if (unix) {
      const link = join(root, "superbased", "link");
      symlinkSync(outside, link);
      assert.match(readCredentialRecord(link, { platform: "win32", windowsRoot: root }).error, /reparse point/);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("expiry: a note inside 14 days and after, none before", () => {
  const now = Date.parse("2027-04-01T00:00:00Z");
  assert.equal(expiryNote("2027-06-01T00:00:00Z", "f", now), "");
  assert.match(expiryNote("2027-04-10T00:00:00Z", "f", now), /expires on 2027-04-10T00:00:00Z, in 9 days; run setup again/);
  assert.match(expiryNote("2027-03-01T00:00:00Z", "f", now), /expired on 2027-03-01T00:00:00Z/);
  assert.equal(expiryNote("", "f", now), "");
});

// --- the ladders -------------------------------------------------------------

function discovery(machine, over = {}) {
  return {
    api_version: 1,
    destination: "local",
    source: "config",
    configured: "",
    signed_in: false,
    local: { enabled: true, otlp_traces_url: `${machine.url}/v1/traces` },
    online: {},
    warnings: [],
    ...over,
  };
}

const otlp = (stub) => stub.requests.filter((r) => r.path === "/v1/traces");

async function withStubs(fn) {
  const dir = scratch();
  const machine = await startStub();
  const gw = await startStub();
  try {
    await fn({ dir, machine, gw });
  } finally {
    await sb.shutdown(500);
    await machine.close();
    await gw.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

const lines = (gw, dest = "online", extra = []) => [KEY, `gateway_url=${gw.url}`, `destination=${dest}`, "dashboard_url=https://u-k7x2.superbased.app", "expires_at=2099-01-01T00:00:00Z", ...extra];

test("SDK file + no machine: online from sdk_file, the file's key to the file's gateway only", { skip: !unix && "unix file rules" }, async () => {
  await withStubs(async ({ dir, gw }) => {
    heldFile(dir, lines(gw));
    sb.init({ nodeUrl: await deadUrl(), instrument: "off" });
    assert.equal(await sb.ready(), "online");
    const d = sb.diagnostics();
    assert.deepEqual([d.destination, d.destinationSource, d.credentialSource], ["online", "sdk_file", "sdk_file"]);
    assert.deepEqual(d.sdkFile, { path: process.env.SUPERBASED_CREDENTIAL_FILE, state: "used", reason: "" });
    assert.equal(d.gatewayUrl, gw.url);
    assert.equal(d.dashboardUrl, "https://u-k7x2.superbased.app");
    assert.deepEqual(d.destinationProblems, []);
    assert.equal(JSON.stringify(sb.settings()).includes("FAKE-sdk-key"), false, "the key never prints");
    sb.withSpan("x", () => {});
    assert.equal(await sb.flush(3000), true);
    assert.equal(otlp(gw)[0].headers.authorization, `Bearer ${KEY}`);
  });
});

test("SDK file + machine `local`, not signed in: online from sdk_file", { skip: !unix && "unix file rules" }, async () => {
  await withStubs(async ({ dir, machine, gw }) => {
    heldFile(dir, lines(gw));
    machine.handler = (r) => (r.path === sb.DISCOVERY_PATH ? { body: discovery(machine) } : undefined);
    sb.init({ nodeUrl: machine.url, instrument: "off" });
    assert.equal(await sb.ready(), "online");
    const d = sb.diagnostics();
    assert.deepEqual([d.destinationSource, d.credentialSource], ["sdk_file", "sdk_file"]);
  });
});

test("SDK file `both` + machine local.enabled: both, the key only to the gateway", { skip: !unix && "unix file rules" }, async () => {
  await withStubs(async ({ dir, machine, gw }) => {
    heldFile(dir, lines(gw, "both"));
    machine.handler = (r) => (r.path === sb.DISCOVERY_PATH ? { body: discovery(machine) } : undefined);
    sb.init({ nodeUrl: machine.url, instrument: "off" });
    assert.equal(await sb.ready(), "both");
    const d = sb.diagnostics();
    assert.deepEqual(d.destinations.map((x) => x.name), ["local", "online"]);
    assert.equal(d.destinationSource, "sdk_file");
    sb.withSpan("x", () => {});
    await sb.flush(3000);
    assert.equal(otlp(gw)[0].headers.authorization, `Bearer ${KEY}`);
    assert.equal(otlp(machine)[0].headers.authorization, undefined, "never to the machine");
  });
});

test("explicit local + SDK file: local, and the file is never read", { skip: !unix && "unix file rules" }, async () => {
  await withStubs(async ({ dir, gw }) => {
    heldFile(dir, lines(gw));
    sb.init({ destination: "local", discover: false, instrument: "off" });
    await sb.ready();
    const d = sb.diagnostics();
    assert.deepEqual([d.destination, d.destinationSource, d.credentialSource, d.sdkFile.state], ["local", "argument", "", "not_read"]);
  });
});

test("env destination + SDK file: the env wins, the file's record is the key", { skip: !unix && "unix file rules" }, async () => {
  await withStubs(async ({ dir, gw }) => {
    heldFile(dir, lines(gw, "both"));
    process.env.SUPERBASED_DESTINATION = "online";
    sb.init({ nodeUrl: await deadUrl(), instrument: "off" });
    assert.equal(await sb.ready(), "online");
    const d = sb.diagnostics();
    assert.deepEqual([d.destinationSource, d.credentialSource, d.gatewayUrl], ["env", "sdk_file", gw.url]);
  });
});

test("SDK file refused: the next rung decides, with a warning", { skip: !unix && "unix file rules" }, async () => {
  await withStubs(async ({ dir, machine, gw }) => {
    heldFile(dir, lines(gw), 0o644);
    machine.handler = (r) => (r.path === sb.DISCOVERY_PATH ? { body: discovery(machine) } : undefined);
    const warned = [];
    const orig = console.warn;
    console.warn = (m) => warned.push(String(m));
    try {
      sb.init({ nodeUrl: machine.url, instrument: "off" });
      assert.equal(await sb.ready(), "local");
    } finally {
      console.warn = orig;
    }
    const d = sb.diagnostics();
    assert.deepEqual([d.destinationSource, d.credentialSource, d.sdkFile.state === "used"], ["machine", "", false]);
    assert.ok(d.destinationProblems.some((p) => /readable by others/.test(p)), d.destinationProblems.join("; "));
    assert.ok(warned.some((w) => /readable by others/.test(w)));
  });
});

test("machine signed in + SDK file: the machine's record is the key, and the unused file is named", { skip: !unix && "unix file rules" }, async () => {
  await withStubs(async ({ dir, machine, gw }) => {
    const machineKey = join(dir, "machine-key");
    writeFileSync(machineKey, `ik_m.machine-secret\ngateway_url=${gw.url}\n`, { mode: 0o600 });
    chmodSync(machineKey, 0o600);
    const held = heldFile(dir, lines(gw));
    machine.handler = (r) =>
      r.path === sb.DISCOVERY_PATH
        ? { body: discovery(machine, { signed_in: true, online: { gateway_url: gw.url, credential_present: true, credential_file: machineKey, dashboard_url: "https://acme.superbased.app" } }) }
        : undefined;
    sb.init({ nodeUrl: machine.url, instrument: "off" });
    assert.equal(await sb.ready(), "online", "the file's destination still beats the machine default");
    const d = sb.diagnostics();
    assert.deepEqual([d.destinationSource, d.credentialSource, d.sdkFile.state === "used"], ["sdk_file", "file", false]);
    assert.equal(d.dashboardUrl, "https://acme.superbased.app", "links follow the record in use");
    assert.ok(d.destinationProblems.some((p) => p.includes(held) && p.includes("present but unused")), d.destinationProblems.join("; "));
    sb.withSpan("x", () => {});
    await sb.flush(3000);
    assert.equal(otlp(gw)[0].headers.authorization, "Bearer ik_m.machine-secret");
  });
});

test("an org URL the app set that is not the file's gateway: the file's key is not sent there", { skip: !unix && "unix file rules" }, async () => {
  await withStubs(async ({ dir, gw }) => {
    heldFile(dir, lines(gw));
    process.env.SUPERBASED_ORG_URL = "https://other.example";
    sb.init({ nodeUrl: await deadUrl(), instrument: "off" });
    await sb.ready();
    const d = sb.diagnostics();
    assert.equal(d.credentialSource, "");
    assert.ok(d.destinationProblems.some((p) => /not the one the key in .* belongs to/.test(p)));
  });
});

test("a key the app gave takes the file's gateway line when it gave none (rung 1)", { skip: !unix && "unix file rules" }, async () => {
  await withStubs(async ({ dir, gw }) => {
    heldFile(dir, lines(gw));
    process.env.SUPERBASED_API_KEY = "ik_env.own-secret";
    sb.init({ nodeUrl: await deadUrl(), instrument: "off" });
    await sb.ready();
    const d = sb.diagnostics();
    assert.deepEqual([d.credentialSource, d.gatewayUrl, d.sdkFile.state === "used"], ["env", gw.url, false]);
  });
});

test("a key close to expiry is named once with the fix", { skip: !unix && "unix file rules" }, async () => {
  await withStubs(async ({ dir, gw }) => {
    const soon = new Date(Date.now() + 3 * 86_400_000).toISOString().replace(/\.\d+Z$/, "Z");
    heldFile(dir, [KEY, `gateway_url=${gw.url}`, "destination=online", `expires_at=${soon}`]);
    const warned = [];
    const orig = console.warn;
    console.warn = (m) => warned.push(String(m));
    try {
      sb.init({ nodeUrl: await deadUrl(), instrument: "off" });
      await sb.ready();
    } finally {
      console.warn = orig;
    }
    assert.ok(warned.some((w) => /in 3 days/.test(w)), warned.join("\n"));
    assert.equal(warned.some((w) => w.includes("FAKE-sdk-key")), false);
  });
});

test("the local exporter never carries a file key, even to a collector the app named", { skip: !unix && "unix file rules" }, async () => {
  await withStubs(async ({ dir, machine, gw }) => {
    heldFile(dir, lines(gw, "both"));
    process.env.SUPERBASED_OTLP_ENDPOINT = "https://collector.example/v1/traces";
    sb.init({ nodeUrl: machine.url, discover: false, instrument: "off" });
    await sb.ready();
    const [local] = sb.diagnostics().destinations.filter((x) => x.name === "local");
    assert.ok(local);
    const s = sb.settings();
    assert.equal(s.credentialSource, "sdk_file");
    // destinations() is the one place headers are built.
    const built = sb.destinations({ ...s, apiKey: s.apiKey, headers: s.headers, onlineHeaders: s.onlineHeaders }, "both");
    assert.equal(built.find((x) => x.name === "local").headers.Authorization, undefined);
  });
});
