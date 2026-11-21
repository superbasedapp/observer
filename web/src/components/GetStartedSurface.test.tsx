// Component tests of the one getting-started surface (first-run plan
// revision 2, 3.6 and 7.1; lane POLISH-F3), rendered with react-dom/server
// under node's test runner (scripts/test-components.mjs): the row-4 switch
// (and its disabled form), the row-3 quiet line, the folded strip, each AI
// apps card (consent, waiting with the tab order by coding history, the
// receiver refusal, unavailable, first trace, glance), the Settings focus
// control and the AI Apps switch.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import { FoldedStrip, OfferLine, SurfaceHeader, SwitchBackLine } from "@/components/firstrun/GetStartedSurface";
import { AppsTrackBody, AppsTrackHeader, FirstTraceView, GlanceView, type AppsTrackBodyProps } from "@/components/apps/AppsTrack";
import { FocusControl, FOCUS_HELP } from "@/pages/settings/FocusSection";
import { APPS_SWITCH_RULES, AppsSwitchView, appsSwitchButtons, appsSwitchState } from "@/pages/settings/AppsSwitchCard";
import { refreshAfterAppsChange } from "@/lib/useComponents";
import { surfaceLayout } from "@/lib/getStarted";
import type { FirstRunApps, FirstRunPlane } from "@/lib/firstRun";

function render(node: React.ReactNode): string {
  return renderToStaticMarkup(<MemoryRouter>{node}</MemoryRouter>);
}

const noop = () => undefined;

function plane(over: Partial<FirstRunPlane>): FirstRunPlane {
  return {
    row: 4,
    rule: "no signal",
    track: "coding",
    ask: true,
    offer_apps: false,
    facts: { coding: false, coding_by: "", apps: false, apps_by: "" },
    focus: "",
    intent: "",
    coding_history: false,
    apps_available: { available: true },
    ...over,
  };
}

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

function body(over: Partial<AppsTrackBodyProps>): AppsTrackBodyProps {
  return {
    phase: "consent",
    apps: apps({}),
    receiver: "127.0.0.1:24318",
    dashboard: "http://127.0.0.1:28081",
    codingHistory: false,
    busy: false,
    report: null,
    onEnable: noop,
    onOpened: noop,
    ...over,
  };
}

test("row 4: the header carries the one-line switch and Hide, no Continue", () => {
  const html = render(<SurfaceHeader layout={surfaceLayout(plane({}))} busy={false} onChoose={noop} onHide={noop} />);
  assert.match(html, /Here for AI apps you build instead\?/);
  assert.match(html, />Switch</);
  assert.match(html, />Both</);
  assert.match(html, />Hide</);
  assert.doesNotMatch(html, /Continue/);
});

test("row 4 without AI Apps: the switch is disabled and says why", () => {
  const text = "This edition does not include AI Apps.";
  const html = render(
    <SurfaceHeader
      layout={surfaceLayout(plane({ apps_available: { available: false, reason: "not_in_build", text } }))}
      busy={false}
      onChoose={noop}
      onHide={noop}
    />,
  );
  assert.match(html, /disabled/);
  assert.ok(html.includes(text));
});

test("rows 1 to 3: no switch in the header", () => {
  for (const p of [plane({ row: 1, track: "both", ask: false }), plane({ row: 2, track: "apps", ask: false }), plane({ row: 3, ask: false, offer_apps: true })]) {
    const html = render(<SurfaceHeader layout={surfaceLayout(p)} busy={false} onChoose={noop} onHide={noop} />);
    assert.doesNotMatch(html, /surface-switch/);
  }
});

test("AI apps track: the way back to AI coding agents or Both (U-02)", () => {
  const html = render(<SwitchBackLine busy={false} onChoose={noop} />);
  assert.match(html, /data-testid="surface-switch-back"/);
  assert.match(html, />Switch to AI coding agents</);
  assert.match(html, />Both</);
});

test("row 3: the quiet line offers AI Apps", () => {
  const html = render(<OfferLine busy={false} onAdd={noop} />);
  assert.match(html, /Building an AI app too\?/);
  assert.match(html, /Add AI Apps/);
});

test("Hide folds the surface to one line with Show", () => {
  const html = render(<FoldedStrip layout={surfaceLayout(plane({ track: "apps", ask: false }))} onShow={noop} />);
  assert.match(html, /data-testid="get-started-folded"/);
  assert.match(html, /send your first trace/);
  assert.match(html, />Show</);
});

test("AI apps steps: 1 Turn on, 2 Send your first trace, 3 Look at it", () => {
  const html = render(<AppsTrackHeader phase="waiting" />);
  assert.match(html, /Turn on AI Apps/);
  assert.match(html, /Send your first trace/);
  assert.match(html, /Look at it/);
  assert.match(html, /\(done\)/, "step 1 is ticked once on");
});

test("consent: one click, the daemon's one sentence, the live receiver, What changes", () => {
  const html = render(<AppsTrackBody {...body({})} />);
  assert.match(html, /Turn on AI Apps/);
  assert.match(html, /127\.0\.0\.1:24318 \(this machine only\)/);
  assert.match(html, /Stays on this machine\./);
  assert.match(html, /What changes/);
  assert.match(html, /next start/);
  assert.doesNotMatch(html, /observability\.enabled|\[components\]/, "no config keys in the consent");
});

test("consent on an enrolled machine names the organization", () => {
  const a = apps({ consent: { row: "enrolled", sentence: "Also sent to Acme (summary).", shared: true, org: "Acme", loopback_only: true } });
  const html = render(<AppsTrackBody {...body({ apps: a })} />);
  assert.match(html, /Also sent to Acme \(summary\)\./);
  assert.doesNotMatch(html, /Stays on this machine/);
});

test("waiting with coding history: the agent tab leads, prompt from live addresses", () => {
  const a = apps({ on: true, receiver: { state: "listening", http_addr: "127.0.0.1:24318" } });
  const html = render(<AppsTrackBody {...body({ phase: "waiting", apps: a, codingHistory: true })} />);
  assert.match(html, /waiting for a trace/);
  assert.match(html, /data-testid="apps-agent-prompt"/);
  assert.match(html, /http:\/\/127\.0\.0\.1:24318/);
  assert.match(html, /http:\/\/127\.0\.0\.1:28081\/api\/obs\/traces/);
  assert.doesNotMatch(html, /data-testid="apps-waiting-help"/, "no help before two minutes");
  assert.ok(html.indexOf("Let your coding agent do it") < html.indexOf("Do it yourself"));
});

test("waiting without coding history: the code tab leads", () => {
  const a = apps({ on: true, receiver: { state: "listening", http_addr: "127.0.0.1:24318" } });
  const html = render(<AppsTrackBody {...body({ phase: "waiting", apps: a, codingHistory: false })} />);
  assert.match(html, /data-testid="apps-sdk-snippet"/);
  assert.ok(html.indexOf("Do it yourself") < html.indexOf("Let your coding agent do it"));
});

test("bind failure: the help shows at once with the error, and Try again", () => {
  const a = apps({ configured_on: true, receiver: { state: "bind_failed", http_addr: "127.0.0.1:4318", error: "address already in use" } });
  const html = render(<AppsTrackBody {...body({ phase: "bind_failed", apps: a })} />);
  assert.match(html, /receiver not listening/);
  assert.match(html, /data-testid="apps-waiting-help"/);
  assert.match(html, /address already in use/);
  assert.match(html, /Try again/);
});

test("unavailable: the edition text and the editions that have it", () => {
  const a = apps({ in_build: false, component: "absent", available: { available: false, reason: "not_in_build", text: "This edition does not include AI Apps." } });
  const html = render(<AppsTrackBody {...body({ phase: "unavailable", apps: a })} />);
  assert.match(html, /Not in this edition/);
  assert.match(html, /developer, full/);
  assert.doesNotMatch(html, /Turn on AI Apps/);
});

test("first trace: real numbers and Open the trace", () => {
  const html = render(
    <FirstTraceView
      row={{
        trace_id: "abc",
        root_name: "answer",
        source: "sdk",
        session_id: "",
        status: "ok",
        started_at: "2026-11-20T10:00:00Z",
        ended_at: "2026-11-20T10:00:01Z",
        duration_ms: 1000,
        span_count: 4,
        cost_usd: 0.004,
        input_tokens: 1000,
        output_tokens: 200,
        cache_read_tokens: 0,
        cache_write_tokens: 0,
        reasoning_tokens: 0,
        total_tokens: 1200,
        model: "gpt-4o",
        service: "my-app",
      }}
      latest={{ trace_id: "abc", name: "answer", service: "my-app" }}
      provenance="priced"
      onOpened={noop}
    />,
  );
  assert.match(html, /Your first trace/);
  assert.match(html, /answer · my-app · 4 spans · gpt-4o · 1\.2K tokens/);
  assert.match(html, /\(priced\)/);
  assert.match(html, /href="\/apps\/traces\?trace=abc"/);
  assert.match(html, /Open the trace/);
});

test("first trace: a sub-cent cost is never $0.0000 (U-08)", () => {
  const html = render(
    <FirstTraceView
      row={{
        trace_id: "c",
        root_name: "turn",
        source: "sdk",
        session_id: "",
        status: "ok",
        started_at: "2026-11-20T10:00:00Z",
        ended_at: "2026-11-20T10:00:01Z",
        duration_ms: 1000,
        span_count: 2,
        cost_usd: 0.0000202,
        input_tokens: 80,
        output_tokens: 20,
        cache_read_tokens: 0,
        cache_write_tokens: 0,
        reasoning_tokens: 0,
        total_tokens: 100,
        model: "gpt-5-nano",
        service: "my-app",
      }}
      latest={{ trace_id: "c", name: "turn", service: "my-app" }}
      provenance="computed"
      onOpened={noop}
    />,
  );
  assert.doesNotMatch(html, /\$0\.0000/);
  assert.match(html, /&lt;\$0\.0001 \(computed\)/);
});

test("first trace without a price never reads as zero", () => {
  const html = render(
    <FirstTraceView
      row={{
        trace_id: "x",
        root_name: "run",
        source: "sdk",
        session_id: "",
        status: "ok",
        started_at: "",
        ended_at: "",
        duration_ms: 0,
        span_count: 1,
        cost_usd: null,
        input_tokens: 0,
        output_tokens: 0,
        cache_read_tokens: 0,
        cache_write_tokens: 0,
        reasoning_tokens: 0,
        total_tokens: 0,
      }}
      latest={null}
      onOpened={noop}
    />,
  );
  assert.match(html, /cost not priced/);
  assert.match(html, /1 span\b/);
});

test("glance: one line with traces today and a link", () => {
  const html = render(<GlanceView latest={{ trace_id: "t", name: "answer" }} today={12} errors={1} />);
  assert.match(html, /AI apps at a glance/);
  assert.match(html, /12 traces today/);
  assert.match(html, /1 with errors/);
  assert.match(html, /See the traces/);
});

test("Settings focus control: the three options, the help line (F1-1) and Show again", () => {
  const html = render(
    <FocusControl plane={plane({ focus: "apps", track: "apps" })} busy={false} readOnly={false} loaded err="" shown={false} onChoose={noop} onShowAgain={noop} />,
  );
  assert.match(html, /What you use superbased for/);
  for (const l of ["AI coding agents", "AI apps and agents you build", "Both"]) assert.ok(html.includes(l), l);
  assert.ok(html.includes(FOCUS_HELP.slice(0, 40)));
  assert.match(FOCUS_HELP, /always takes effect/);
  assert.match(html, /Let superbased work it out again/);
  assert.match(html, /Show the getting-started steps again/);
});

test("Settings focus control: an inferred track says it was not chosen", () => {
  const html = render(<FocusControl plane={plane({ track: "coding" })} busy={false} readOnly={false} loaded err="" shown={false} onChoose={noop} onShowAgain={noop} />);
  assert.match(html, /Not chosen yet/);
});

test("Settings AI Apps switch: state by the daemon's facts", () => {
  assert.equal(appsSwitchState(null), "unknown");
  assert.equal(appsSwitchState(apps({})), "off");
  assert.equal(appsSwitchState(apps({ on: true, configured_on: true, receiver: { state: "listening" } })), "on");
  assert.equal(appsSwitchState(apps({ on: true, configured_on: false })), "off_next_start");
  assert.equal(appsSwitchState(apps({ configured_on: true, receiver: { state: "bind_failed" } })), "bind_failed");
  assert.equal(appsSwitchState(apps({ available: { available: false } })), "unavailable");
  const on = render(<AppsSwitchView apps={apps({ on: true, configured_on: true, receiver: { state: "listening", http_addr: "127.0.0.1:4318" } })} busy={false} readOnly={false} line={null} onEnable={noop} onDisable={noop} />);
  assert.match(on, /Turn off/);
  assert.match(on, /next start/);
  const off = render(<AppsSwitchView apps={apps({})} busy={false} readOnly={false} line={null} onEnable={noop} onDisable={noop} />);
  assert.match(off, /Turn on/);
});

// Review FR-M12: one case per APPS_SWITCH_RULES row, in order. "Off"
// outranks a receiver bind failure while AI Apps was never turned on.
test("Settings AI Apps switch: one case per rule row, in order", () => {
  const failed = { state: "bind_failed", http_addr: "127.0.0.1:4318", error: "address in use" };
  const cases: { rule: string; a: FirstRunApps; want: string }[] = [
    { rule: "not available here", a: apps({ available: { available: false } }), want: "unavailable" },
    { rule: "turned on, the receiver could not bind", a: apps({ configured_on: true, receiver: failed }), want: "bind_failed" },
    { rule: "serving, saved off", a: apps({ on: true, configured_on: false }), want: "off_next_start" },
    { rule: "on", a: apps({ on: true, configured_on: true, receiver: { state: "listening" } }), want: "on" },
    { rule: "off", a: apps({ receiver: failed }), want: "off" },
  ];
  assert.deepEqual(cases.map((c) => c.rule), APPS_SWITCH_RULES.map((r) => r.name));
  for (const c of cases) assert.equal(appsSwitchState(c.a), c.want, c.rule);
});

test("Settings AI Apps switch: AI Apps on with its port taken offers Try again and Turn off (FR-M12)", () => {
  const failed = { state: "bind_failed", http_addr: "127.0.0.1:4318", error: "address in use" };
  const html = render(
    <AppsSwitchView apps={apps({ configured_on: true, receiver: failed })} busy={false} readOnly={false} line={null} onEnable={noop} onDisable={noop} />,
  );
  assert.match(html, /data-state="bind_failed"/);
  assert.match(html, />Try again</);
  assert.match(html, />Turn off</);
  // Never turned on, the receiver bound for something else: the plain off.
  const off = render(<AppsSwitchView apps={apps({ receiver: failed })} busy={false} readOnly={false} line={null} onEnable={noop} onDisable={noop} />);
  assert.match(off, /data-state="off"/);
  assert.match(off, />Turn on</);
  assert.doesNotMatch(off, />Turn off</);
  assert.deepEqual(appsSwitchButtons("bind_failed", apps({ on: true, configured_on: false, receiver: failed })), { enable: "Try again", disable: false });
});

// Review FR-M01: what a hot enable could not start is named where AI Apps
// was turned on (the waiting card and Settings), never "takes effect at once".
test("what waits for the next start is named on the waiting card and in Settings", () => {
  const a = apps({
    on: true,
    configured_on: true,
    receiver: { state: "listening", http_addr: "127.0.0.1:24318" },
    pending_next_start: ["admission", "proxy turn traces"],
  });
  const waiting = render(<AppsTrackBody {...body({ phase: "waiting", apps: a })} />);
  assert.match(waiting, /These start at the next daemon start: admission, proxy turn traces\./);
  const settings = render(<AppsSwitchView apps={a} busy={false} readOnly={false} line={null} onEnable={noop} onDisable={noop} />);
  assert.match(settings, /These start at the next daemon start: admission, proxy turn traces\./);
  assert.doesNotMatch(settings, /Turning on takes effect at once/);
  // Nothing pending: no line.
  const quiet = render(<AppsTrackBody {...body({ phase: "waiting", apps: { ...a, pending_next_start: undefined } })} />);
  assert.doesNotMatch(quiet, /next daemon start/);
});

// Review FR-M10: a hot enable or disable re-reads the component state and
// the AI Apps routes probe at once, not on the next 30 s poll.
test("refreshAfterAppsChange re-reads the component state and the routes probe", () => {
  const keys: string[] = [];
  refreshAfterAppsChange((k) => keys.push(k));
  assert.deepEqual(keys, ["/api/components/state", "/api/obs/enabled"]);
});
