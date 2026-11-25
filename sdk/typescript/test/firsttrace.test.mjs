// Plan 3.8 and ruling R12: the app's first-trace line. The gate (terminal,
// CI, opt-out), the local and online link shapes, once per process, no line
// without a base, and the refusal said in place of the link. L0's
// first_trace_link section runs in behaviour.test.mjs when present.
import { test, beforeEach, after } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { InMemorySpanExporter } from "@opentelemetry/sdk-trace-base";

import * as sb from "../dist/esm/index.js";
import { _setFirstTraceSinkForTests, refusalLine, rootTraceId } from "../dist/esm/firsttrace.js";
import { deadUrl, reset, startStub } from "./helpers.mjs";

let lines = [];
function terminal(env = {}) {
  lines = [];
  _setFirstTraceSinkForTests({ isTTY: () => true, env: () => env, write: (l) => lines.push(l) });
}

beforeEach(async () => {
  await reset();
  terminal();
});
after(async () => {
  _setFirstTraceSinkForTests(null);
  await reset();
});

test("the gate: a terminal, CI unset, the opt-out not set", () => {
  const rows = [
    [true, {}, true],
    [false, {}, false],
    [true, { CI: "true" }, false],
    [true, { CI: "1" }, false],
    [true, { CI: "" }, true],
    [true, { CI: "false" }, true],
    [true, { CI: "0" }, true],
    [true, { SUPERBASED_FIRST_TRACE_LINK: "0" }, false],
    [true, { SUPERBASED_FIRST_TRACE_LINK: "off" }, false],
    [true, { SUPERBASED_FIRST_TRACE_LINK: "1" }, true],
  ];
  for (const [tty, env, want] of rows) assert.equal(sb.linkAllowed(tty, env), want, JSON.stringify([tty, env]));
});

test("link shapes: local and online, nothing without a base", () => {
  assert.equal(sb.traceLink("local", "abc", "http://127.0.0.1:8081", ""), "http://127.0.0.1:8081/apps/traces?trace=abc");
  assert.equal(sb.traceLink("online", "abc", "", "https://u-k7x2.superbased.app/"), "https://u-k7x2.superbased.app/trajectories?trace=abc");
  assert.equal(sb.traceLink("online", "abc", "http://127.0.0.1:8081", ""), "");
  assert.equal(sb.traceLink("local", "abc", "", "https://x"), "");
});

test("local: one line with the machine's link, once per process", async () => {
  const mem = new InMemorySpanExporter();
  sb.init({ exporter: mem, destination: "local", discover: false, nodeUrl: "http://127.0.0.1:8081", instrument: "off" });
  await sb.withSpan("root", async () => sb.withSpan("child", () => {}));
  await sb.flush(2000);
  const root = mem.getFinishedSpans().find((s) => s.name === "root");
  assert.deepEqual(lines, [`superbased: first trace from this process: http://127.0.0.1:8081/apps/traces?trace=${root.spanContext().traceId}`]);
  await sb.withSpan("second", () => {});
  await sb.flush(2000);
  assert.equal(lines.length, 1, "once per process");
});

test("no terminal, CI, or the opt-out: no line", async () => {
  for (const [tty, env] of [[false, {}], [true, { CI: "1" }], [true, { SUPERBASED_FIRST_TRACE_LINK: "0" }]]) {
    await reset();
    lines = [];
    _setFirstTraceSinkForTests({ isTTY: () => tty, env: () => env, write: (l) => lines.push(l) });
    sb.init({ exporter: new InMemorySpanExporter(), destination: "local", discover: false, instrument: "off" });
    await sb.withSpan("root", () => {});
    await sb.flush(2000);
    assert.deepEqual(lines, [], JSON.stringify([tty, env]));
  }
});

test("a collector the app named is not the machine's dashboard: no local link", async () => {
  sb.init({ exporter: new InMemorySpanExporter(), destination: "local", discover: false, endpoint: "https://collector.example/v1/traces", instrument: "off" });
  await sb.withSpan("root", () => {});
  await sb.flush(2000);
  assert.deepEqual(lines, []);
});

test("online with no dashboard base known: no line", async () => {
  const gw = await startStub();
  try {
    sb.init({ destination: "online", orgUrl: gw.url, apiKey: "ik_1.s", discover: false, instrument: "off" });
    await sb.withSpan("root", () => {});
    await sb.flush(3000);
    assert.equal(gw.requests.length, 1);
    assert.deepEqual(lines, []);
  } finally {
    await gw.close();
  }
});

test("online through the SDK-held file: the dashboard's trajectories link", { skip: process.platform === "win32" && "unix file rules" }, async () => {
  const gw = await startStub();
  const dir = mkdtempSync(join(tmpdir(), "sbo-ft-"));
  try {
    const f = join(dir, "sdk-credential");
    writeFileSync(f, `ik_1.s\ngateway_url=${gw.url}\ndestination=online\ndashboard_url=https://u-k7x2.superbased.app\n`);
    chmodSync(f, 0o600);
    process.env.SUPERBASED_CREDENTIAL_FILE = f;
    sb.init({ nodeUrl: await deadUrl(), instrument: "off" });
    await sb.ready();
    let tid = "";
    await sb.withSpan("root", () => {
      tid = sb.getCurrentTraceId();
    });
    await sb.flush(3000);
    assert.deepEqual(lines, [`superbased: first trace from this process: https://u-k7x2.superbased.app/trajectories?trace=${tid}`]);
  } finally {
    await gw.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a refused export says the refusal in place of the link", async () => {
  const gw = await startStub();
  const warn = console.warn;
  console.warn = () => {};
  try {
    gw.reply(
      {
        error: "plan_required",
        message: "AI Apps ingest is not part of this organization's plan (Team).",
        capability: "org.planea.gateway",
        plan: { name: "team", version: 1, label: "Team" },
        upgrade_url: "https://cloud.superbased.app/portal/orgs/org_1",
      },
      403,
    );
    sb.init({ destination: "online", orgUrl: gw.url, apiKey: "ik_1.s", discover: false, instrument: "off" });
    await sb.withSpan("root", () => {});
    await sb.flush(3000);
    assert.deepEqual(lines, [
      "superbased: traces from this process were refused: AI Apps ingest is not part of this organization's plan (Team). https://cloud.superbased.app/portal/orgs/org_1",
    ]);
  } finally {
    console.warn = warn;
    await gw.close();
  }
});

test("refusalLine: no link when the refusal names none; rootTraceId skips children", () => {
  assert.equal(refusalLine({ message: "Over the cap.", upgradeUrl: "" }), "superbased: traces from this process were refused: Over the cap.");
  const child = { parentSpanContext: { spanId: "p" }, spanContext: () => ({ traceId: "c" }) };
  const root = { spanContext: () => ({ traceId: "r" }) };
  assert.equal(rootTraceId([child, root]), "r");
  assert.equal(rootTraceId([child]), "");
});
