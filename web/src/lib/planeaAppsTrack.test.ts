// The AI apps column of the getting-started surface (first-run plan
// revision 2, 3.6 c to e, 7.1): one case per APPS_TRACK_RULES row, the
// prompt built from the daemon's live addresses, the tab order by coding
// history, and the 2-minute help.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  APPS_TRACK_RULES,
  agentPrompt,
  appsSteps,
  snippetForReceiver,
  appsTrackPhase,
  consentChanges,
  consentLines,
  enableResult,
  hotEnabledPending,
  pendingLine,
  receiverAddress,
  receiverURL,
  sendTabs,
  showWaitingHelp,
  waitingHelp,
  WAITING_HELP_MS,
  type AppsTrackFacts,
  type AppsTrackPhase,
} from "./planeaFirstRun.ts";
import type { FirstRunApps } from "./firstRun.ts";
import { readFileSync } from "node:fs";
import { sdkAgentPrompt } from "../../../shared/lib/sdkPrompt.ts";
import { SDK_CATALOG } from "../../../shared/lib/sdkCatalog.ts";

function apps(over: Partial<FirstRunApps>): FirstRunApps {
  return {
    in_build: true,
    component: "available",
    available: { available: true },
    on: false,
    configured_on: false,
    hot_enable: true,
    receiver: { state: "not_running" },
    latest_trace: null,
    consent: { row: "not enrolled", sentence: "Stays on this machine.", shared: false, loopback_only: true, receiver_note: "(this machine only)" },
    ...over,
  };
}

const trace = { trace_id: "t1", name: "answer", service: "my-app", started_at: "2026-11-20T10:00:00Z" };
const listening = { state: "listening", http_addr: "127.0.0.1:4318", grpc_addr: "127.0.0.1:4317" };

// One case per row, in table order.
const CASES: { rule: string; f: AppsTrackFacts; want: AppsTrackPhase }[] = [
  { rule: "the first-run read has not answered", f: { loaded: false, apps: null, openedTrace: null }, want: "loading" },
  { rule: "a daemon without the apps block", f: { loaded: true, apps: undefined, openedTrace: null }, want: "legacy" },
  { rule: "a trace arrived and was opened here", f: { loaded: true, apps: apps({ on: true, receiver: listening, latest_trace: trace }), openedTrace: "t1" }, want: "glance" },
  { rule: "a trace arrived", f: { loaded: true, apps: apps({ on: true, receiver: listening, latest_trace: trace }), openedTrace: null }, want: "first_trace" },
  {
    rule: "the receiver could not bind",
    f: { loaded: true, apps: apps({ configured_on: true, receiver: { state: "bind_failed", http_addr: "127.0.0.1:4318", error: "address in use" } }), openedTrace: null },
    want: "bind_failed",
  },
  { rule: "on, waiting for a trace", f: { loaded: true, apps: apps({ on: true, receiver: listening }), openedTrace: null }, want: "waiting" },
  {
    rule: "not available here",
    f: { loaded: true, apps: apps({ component: "absent", in_build: false, available: { available: false, reason: "not_in_build", text: "x" } }), openedTrace: null },
    want: "unavailable",
  },
  { rule: "this process cannot turn it on in place", f: { loaded: true, apps: apps({ hot_enable: false, component: "unknown" }), openedTrace: null }, want: "legacy" },
  { rule: "off: one consent", f: { loaded: true, apps: apps({}), openedTrace: null }, want: "consent" },
];

test("every APPS_TRACK_RULES row has a case, in order", () => {
  assert.deepEqual(CASES.map((c) => c.rule), APPS_TRACK_RULES.map((r) => r.name));
});

for (const c of CASES) {
  test(`appsTrackPhase: ${c.rule}`, () => {
    assert.equal(appsTrackPhase(c.f), c.want);
  });
}

test("appsSteps tick by phase", () => {
  const done = (p: AppsTrackPhase) => appsSteps(p).map((s) => s.done);
  assert.deepEqual(done("consent"), [false, false, false]);
  assert.deepEqual(done("waiting"), [true, false, false]);
  assert.deepEqual(done("first_trace"), [true, true, false]);
  assert.deepEqual(done("glance"), [true, true, true]);
  assert.equal(appsSteps("consent")[0].title, "Turn on AI Apps");
});

test("receiverURL reaches wildcard hosts on loopback", () => {
  assert.equal(receiverURL("127.0.0.1:4318"), "http://127.0.0.1:4318");
  assert.equal(receiverURL("0.0.0.0:14318"), "http://127.0.0.1:14318");
  assert.equal(receiverURL(":4319"), "http://127.0.0.1:4319");
  assert.equal(receiverURL("[::]:4318"), "http://127.0.0.1:4318");
  assert.equal(receiverURL("10.0.0.5:4318"), "http://10.0.0.5:4318");
  assert.equal(receiverURL(""), "http://127.0.0.1:4318");
});

test("receiverAddress: the daemon's report, then the configured address", () => {
  assert.equal(receiverAddress(apps({ receiver: { state: "listening", http_addr: "127.0.0.1:24318" } }), "127.0.0.1:4318"), "127.0.0.1:24318");
  assert.equal(receiverAddress(apps({}), "127.0.0.1:5318"), "127.0.0.1:5318");
  assert.equal(receiverAddress(null, ""), "127.0.0.1:4318");
});

test("agentPrompt is the one four-line SDK prompt, the catalog's setup commands", () => {
  const p = agentPrompt({ dashboard: "http://127.0.0.1:8081" });
  assert.equal(p, sdkAgentPrompt());
  const lines = p.split("\n");
  assert.equal(lines.length, 4);
  for (const s of SDK_CATALOG) if (s.setup) assert.ok(lines[0].includes(s.setup), `${s.label}: ${s.setup}`);
  assert.match(lines[1], /approve in the browser or to answer y\/N, tell me and wait/);
  assert.match(lines[1], /Never read, print, copy or move the SDK key or the file it is stored in\./);
  assert.match(lines[3], /^For more detail later .*https:\/\/superbased\.app\/docs\/sdk\/overview$/);
  assert.doesNotMatch(p, /gateway/i, "the prompt never names a gateway");
  assert.doesNotMatch(p, /SUPERBASED_NODE_URL/, "the default dashboard needs no hint");
});

test("agentPrompt names a dashboard that is not at the default address, never a hard-coded port", () => {
  const p = agentPrompt({ dashboard: "http://127.0.0.1:28081/" });
  assert.match(p.split("\n")[0], /SUPERBASED_NODE_URL=http:\/\/127\.0\.0\.1:28081 set/);
  assert.doesNotMatch(p, /:8081\b/);
  assert.equal(p.split("\n").length, 4);
});

// The website shows the same prompt from its own partial (tokens from the
// same catalog): one text on every surface (plan 3.9).
test("the website's SDK prompt is the dashboards' prompt", () => {
  const raw = readFileSync(new URL("../../../website/pages-src/partials/prompt-sdk.html", import.meta.url), "utf8");
  const text = raw
    .replace(/@@sdk\.([a-z][a-z0-9-]*)\.([a-z_]+)@@/g, (tok, id: string, field: string) => {
      const row = SDK_CATALOG.find((s) => s.id === id) as unknown as Record<string, string> | undefined;
      const value = row?.[field];
      assert.ok(typeof value === "string" && value, `unknown token ${tok}`);
      return value;
    })
    .replace(/&amp;/g, "&")
    .replace(/\n+$/, "");
  assert.equal(text, sdkAgentPrompt());
});

test("snippetForReceiver: unchanged on the default, the live address elsewhere (U-04)", () => {
  const code = 'sb.init(service_name="my-app")  # sends to this machine at 127.0.0.1:4318';
  assert.equal(snippetForReceiver(code, "127.0.0.1:4318"), code);
  assert.equal(snippetForReceiver(code, undefined), code);
  const live = snippetForReceiver(code, "0.0.0.0:14318");
  assert.match(live, /at 127\.0\.0\.1:14318 \(set OTEL_EXPORTER_OTLP_ENDPOINT=http:\/\/127\.0\.0\.1:14318\)/);
  assert.doesNotMatch(live, /:4318\b/);
  for (const s of SDK_CATALOG) assert.doesNotMatch(snippetForReceiver(s.code, "127.0.0.1:14318"), /:4318\b/, `${s.label}`);
});

test("sendTabs: the agent tab leads only with coding history", () => {
  assert.deepEqual(sendTabs(true), ["agent", "code"]);
  assert.deepEqual(sendTabs(false), ["code", "agent"]);
});

test("showWaitingHelp: after two minutes, or at once on a receiver refusal", () => {
  const on = apps({ on: true, receiver: listening });
  assert.equal(showWaitingHelp(0, WAITING_HELP_MS - 1, on), false);
  assert.equal(showWaitingHelp(0, WAITING_HELP_MS, on), true);
  assert.equal(showWaitingHelp(0, 1, apps({ receiver: { state: "bind_failed" } })), true);
  assert.equal(showWaitingHelp(0, 1, apps({ on: true, receiver: { state: "no_answer" } })), true);
});

test("waitingHelp names a bind failure first, with its error and address", () => {
  const lines = waitingHelp(apps({ receiver: { state: "bind_failed", http_addr: "127.0.0.1:4318", error: "address already in use" } }), "127.0.0.1:4318");
  assert.equal(lines[0].tone, "danger");
  assert.match(lines[0].text, /address already in use/);
  assert.match(lines[0].text, /Settings > AI Apps/);
  assert.equal(waitingHelp(apps({ on: true, receiver: listening }), "x")[0].tone, "neutral");
});

test("consentLines: the receiver, the daemon's one sentence, the off note", () => {
  const l = consentLines(apps({}), "127.0.0.1:4318");
  assert.equal(l[0], "Listens for your app's traces on 127.0.0.1:4318 (this machine only).");
  assert.equal(l[1], "Stays on this machine.");
  const shared = consentLines(
    apps({ consent: { row: "enrolled", sentence: "Also sent to Acme (summary).", shared: true, org: "Acme", loopback_only: false } }),
    "0.0.0.0:4318",
  );
  assert.equal(shared[0], "Listens for your app's traces on 0.0.0.0:4318.");
  assert.equal(shared[1], "Also sent to Acme (summary).");
  assert.match(l[2], /next start/);
});

test("enableResult: message and fix", () => {
  assert.equal(enableResult(null), null);
  assert.deepEqual(enableResult({ ok: false, message: "Port taken.", fix: "Set another port." }), { tone: "danger", text: "Port taken. Set another port." });
  assert.equal(enableResult({ ok: true, message: "" })?.tone, "success");
});

// Review FR-M01: the features a hot enable could not start are named where
// AI Apps was turned on, never said to take effect at once.
test("pendingLine and enableResult name what waits for the next start", () => {
  assert.equal(pendingLine(undefined), null);
  assert.equal(pendingLine([]), null);
  assert.equal(pendingLine([" ", ""]), null);
  assert.equal(
    pendingLine(["admission", "proxy turn traces"]),
    "These start at the next daemon start: admission, proxy turn traces.",
  );
  assert.deepEqual(
    enableResult({ ok: true, message: "AI Apps is on. Receiver: listening on 127.0.0.1:4318.", pending_next_start: ["alerts"] }),
    { tone: "success", text: "AI Apps is on. Receiver: listening on 127.0.0.1:4318. These start at the next daemon start: alerts." },
  );
  // A refusal names only why it failed.
  assert.deepEqual(enableResult({ ok: false, message: "Port taken.", pending_next_start: ["alerts"] }), { tone: "danger", text: "Port taken." });
  // The consent card's "What changes" says these wait, before the click.
  assert.ok(consentChanges(apps({})).some((l) => /next start/.test(l) && /proxy turn traces/.test(l)));
});

// Review FR-M12: "off" outranks a receiver that could not bind when AI Apps
// was never turned on (the receiver may be bound for [ingest.otel] alone).
test("a bind failure shows the consent card while AI Apps was never turned on", () => {
  const failed = { state: "bind_failed", http_addr: "127.0.0.1:4318", error: "address in use" };
  const rows: [Partial<FirstRunApps>, AppsTrackPhase][] = [
    [{ receiver: failed }, "consent"],
    [{ receiver: failed, configured_on: true }, "bind_failed"],
    [{ receiver: failed, on: true, configured_on: true }, "bind_failed"],
    [{ receiver: failed, on: true }, "bind_failed"],
  ];
  for (const [over, want] of rows) {
    assert.equal(appsTrackPhase({ loaded: true, apps: apps(over), openedTrace: null }), want, JSON.stringify(over));
  }
});

test("hotEnabledPending: only the obs activation, only while AI Apps is on", () => {
  assert.equal(hotEnabledPending({ id: "obs", change: "activate" }, true), true);
  assert.equal(hotEnabledPending({ id: "obs", change: "activate" }, false), false);
  assert.equal(hotEnabledPending({ id: "obs", change: "deactivate" }, true), false);
  assert.equal(hotEnabledPending({ id: "guard", change: "activate" }, true), false);
});

test("configuredReceiver reads the saved receiver address", async () => {
  const { configuredReceiver } = await import("./planeaFirstRun.ts");
  assert.equal(configuredReceiver({ Ingest: { OTel: { HTTPAddr: "127.0.0.1:5318" } } }), "127.0.0.1:5318");
  assert.equal(configuredReceiver({ Ingest: { OTel: { HTTPAddr: "" } } }), null);
  assert.equal(configuredReceiver(null), null);
});
