// The /apps page opened to turn AI Apps on (SDK quickstart plan 3.7, 3.8),
// rendered with react-dom/server under node's test runner
// (scripts/test-components.mjs): opened by the SDK's setup, the Turn on
// button and the one consent sentence come first, one click; the wait names
// setup's hello trace; an arrived trace is linked; and the nav item's page
// is unchanged.

import { before, test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import { AppsTrackBody, type AppsTrackBodyProps } from "@/components/apps/AppsTrack";
import { AppsStart } from "@/components/apps/AppsStart";
import type { FirstRunApps } from "@/lib/firstRun";
import { APPS_STATUS_PATH } from "@/lib/firstRun";
import { SETUP_COPY } from "@/lib/planeaFirstRun";
import { buildUrl } from "@/lib/api";
import { apiCache } from "@/lib/useApi";

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

// The trace links go through the visibility gate (GatedLink): answer the
// governance read as an ungoverned machine's, and the status read as a
// machine with AI Apps off.
before(async () => {
  await apiCache.fetch(buildUrl("/api/governance"), async () => ({
    active: false,
    state: "no_grant",
    version: 0,
    notice: {},
    hidden_sections: [],
    read_only_sections: [],
    hidden_settings: [],
    read_only_settings: [],
  }));
  await apiCache.fetch(buildUrl(APPS_STATUS_PATH), async () => ({ ...apps({}), confirm_token: "t" }));
});

function render(node: React.ReactNode, at = "/"): string {
  return renderToStaticMarkup(<MemoryRouter initialEntries={[at]}>{node}</MemoryRouter>);
}

const noop = () => undefined;

function body(over: Partial<AppsTrackBodyProps>): AppsTrackBodyProps {
  return {
    mode: "setup",
    phase: "consent",
    apps: apps({}),
    receiver: "127.0.0.1:24318",
    dashboard: "http://127.0.0.1:28081",
    codingHistory: true,
    busy: false,
    report: null,
    onEnable: noop,
    onOpened: noop,
    ...over,
  };
}

test("opened by setup: the consent sentence and Turn on come first, one click", () => {
  const html = render(<AppsTrackBody {...body({})} />);
  assert.match(html, /data-testid="apps-consent-first"/);
  const sentence = html.indexOf("Stays on this machine.");
  const button = html.indexOf("Turn on AI Apps</button>");
  const why = html.indexOf(SETUP_COPY.consentWhy.replaceAll("'", "&#x27;"));
  const changes = html.indexOf("What changes");
  assert.ok(sentence > 0 && button > 0 && why > 0 && changes > 0, html);
  assert.ok(sentence < why && button < why && button < changes, "the sentence and the button lead");
  assert.match(html, /127\.0\.0\.1:24318 \(this machine only\)/);
  assert.doesNotMatch(html, /Turn on\?/, "one click: no arm-then-confirm step");
  assert.match(html, /close this page: nothing changes/);
  assert.doesNotMatch(html, /See your own AI apps here/);
});

test("opened with enable=1 alone: the button first, without the setup lines", () => {
  const html = render(<AppsTrackBody {...body({ mode: "enable" })} />);
  assert.match(html, /data-testid="apps-consent-first"/);
  assert.doesNotMatch(html, /setup/i);
});

test("the getting-started surface keeps its consent card", () => {
  const html = render(<AppsTrackBody {...body({ mode: undefined })} />);
  assert.match(html, /data-testid="apps-consent"/);
  assert.doesNotMatch(html, /apps-consent-first/);
  assert.match(html, /See your own AI apps here/);
});

test("opened by setup, waiting: setup's hello, not the prompt or the snippet", () => {
  const a = apps({ on: true, receiver: { state: "listening", http_addr: "127.0.0.1:24318" } });
  const html = render(<AppsTrackBody {...body({ phase: "waiting", apps: a })} />);
  assert.match(html, /data-testid="apps-setup-waiting"/);
  assert.ok(html.includes(SETUP_COPY.waitingTitle.replaceAll("'", "&#x27;")));
  assert.match(html, /waiting for a trace/);
  assert.doesNotMatch(html, /apps-agent-prompt|apps-sdk-snippet/);
});

test("opened by setup, a refused receiver: the help at once and Try again", () => {
  const a = apps({ configured_on: true, receiver: { state: "bind_failed", http_addr: "127.0.0.1:4318", error: "address already in use" } });
  const html = render(<AppsTrackBody {...body({ phase: "bind_failed", apps: a })} />);
  assert.match(html, /receiver not listening/);
  assert.match(html, /address already in use/);
  assert.match(html, /Try again/);
});

test("opened by setup, the trace arrived: the card links it", () => {
  const a = apps({ on: true, latest_trace: { trace_id: "hello1", name: "superbased setup: hello from bot", service: "bot", started_at: new Date().toISOString() } });
  const html = render(<AppsTrackBody {...body({ phase: "first_trace", apps: a })} />);
  assert.match(html, /Your first trace/);
  assert.match(html, /href="\/apps\/traces\?trace=hello1"/);
});

test("the /apps page: the nav item shows the first-run card, setup's link the track", () => {
  const nav = render(<AppsStart />, "/apps");
  assert.match(nav, /data-mode="default"/);
  assert.doesNotMatch(nav, /apps-consent-first/);
  const setup = render(<AppsStart />, "/apps?enable=1&from=setup");
  assert.match(setup, /data-mode="setup"/);
  assert.match(setup, /data-testid="apps-consent-first"/);
  assert.match(setup, /Stays on this machine\./);
});
