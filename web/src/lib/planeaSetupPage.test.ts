// The /apps page opened by the SDK's setup (SDK quickstart plan 3.7, 3.8):
// one case per APPS_START_MODE_RULES row, when the page forwards, which
// trace counts as setup's hello, and the trace link.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  APPS_HOME_PATH,
  APPS_START_MODE_RULES,
  SETUP_COPY,
  SETUP_TRACE_WINDOW_MS,
  appsStartForwards,
  appsStartMode,
  appsTrackPhase,
  setupApps,
  setupArrivedTrace,
  traceHref,
  type AppsStartMode,
} from "./planeaFirstRun.ts";
import type { FirstRunApps } from "./firstRun.ts";

// One case per row, in table order.
const MODE_CASES: { rule: string; search: string; want: AppsStartMode }[] = [
  { rule: "opened by the SDK's setup", search: "?enable=1&from=setup", want: "setup" },
  { rule: "opened to turn it on", search: "?enable=1", want: "enable" },
  { rule: "the nav item", search: "", want: "default" },
];

test("every APPS_START_MODE_RULES row has a case, in order", () => {
  assert.deepEqual(
    MODE_CASES.map((c) => c.rule),
    APPS_START_MODE_RULES.map((r) => r.name),
  );
  for (const c of MODE_CASES) assert.equal(appsStartMode(c.search), c.want, c.rule);
});

test("appsStartMode: other values never put the button first", () => {
  assert.equal(appsStartMode("?from=setup"), "default");
  assert.equal(appsStartMode("?enable=true&from=setup"), "default");
  assert.equal(appsStartMode("?enable=0"), "default");
  assert.equal(appsStartMode("?from=setup&enable=1&x=y"), "setup");
  assert.equal(appsStartMode("?enable=1&from=cli"), "enable");
});

test("appsStartForwards: only the nav item's page forwards to Traces", () => {
  assert.equal(appsStartForwards("default", true, true), true);
  assert.equal(appsStartForwards("default", true, false), false);
  assert.equal(appsStartForwards("default", null, true), false);
  assert.equal(appsStartForwards("enable", true, true), false);
  assert.equal(appsStartForwards("setup", true, true), false);
});

test("traceHref opens the Traces page on the trace", () => {
  assert.equal(traceHref("abc123"), `${APPS_HOME_PATH}?trace=abc123`);
  assert.equal(traceHref("a b&c"), "/apps/traces?trace=a%20b%26c");
});

const opened = Date.parse("2026-11-25T10:00:00Z");

function apps(over: Partial<FirstRunApps>): FirstRunApps {
  return {
    in_build: true,
    component: "active",
    available: { available: true },
    on: true,
    configured_on: true,
    hot_enable: true,
    receiver: { state: "listening", http_addr: "127.0.0.1:4318" },
    latest_trace: null,
    consent: { row: "not enrolled", sentence: "Stays on this machine.", shared: false, loopback_only: true },
    ...over,
  };
}

test("setupArrivedTrace: a trace since the page opened, never an older or undated one", () => {
  const at = (iso: string) => ({ trace_id: "t1", name: "superbased setup: hello from bot", started_at: iso });
  const cases: { name: string; latest: FirstRunApps["latest_trace"] | undefined; want: string | null }[] = [
    { name: "none", latest: null, want: null },
    { name: "absent", latest: undefined, want: null },
    { name: "after the page opened", latest: at("2026-11-25T10:00:05Z"), want: "t1" },
    { name: "a little before (clock and batching slack)", latest: at("2026-11-25T09:59:00Z"), want: "t1" },
    { name: "at the window's edge", latest: at(new Date(opened - SETUP_TRACE_WINDOW_MS).toISOString()), want: "t1" },
    { name: "older than the window", latest: at(new Date(opened - SETUP_TRACE_WINDOW_MS - 1000).toISOString()), want: null },
    { name: "undated", latest: { trace_id: "t1" }, want: null },
    { name: "unparseable date", latest: at("yesterday"), want: null },
    { name: "no id", latest: { trace_id: "", started_at: "2026-11-25T10:00:05Z" }, want: null },
  ];
  for (const c of cases) assert.equal(setupArrivedTrace(c.latest, opened)?.trace_id ?? null, c.want, c.name);
});

test("setupApps: the track waits for setup's hello, then shows its link", () => {
  const old = { trace_id: "old", started_at: "2026-11-20T10:00:00Z" };
  const hello = { trace_id: "hello", started_at: "2026-11-25T10:00:03Z" };
  const waiting = setupApps(apps({ latest_trace: old }), opened);
  assert.equal(waiting?.latest_trace, null);
  assert.equal(appsTrackPhase({ loaded: true, apps: waiting, openedTrace: null }), "waiting");
  const arrived = setupApps(apps({ latest_trace: hello }), opened);
  assert.equal(appsTrackPhase({ loaded: true, apps: arrived, openedTrace: null }), "first_trace");
  assert.equal(setupApps(undefined, opened), undefined);
  assert.equal(appsTrackPhase({ loaded: true, apps: setupApps(apps({ on: false, configured_on: false }), opened), openedTrace: null }), "consent");
});

test("the setup lines name no internal vocabulary and never the AI gateway", () => {
  for (const line of Object.values(SETUP_COPY)) {
    assert.doesNotMatch(line, /\b[a-z]+_[a-z]+\b/, line);
    assert.doesNotMatch(line, /gateway/i, line);
    assert.doesNotMatch(line, /\bnode\b/, line);
  }
});
