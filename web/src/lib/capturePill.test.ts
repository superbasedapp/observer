import assert from "node:assert/strict";
import test from "node:test";

import { capturePillView, type CapturePillInput } from "./capturePill.ts";
import { CAPTURE_DOT } from "./liveSignals.ts";
import type { ObservedSurface } from "./types.ts";

function surface(kind: string, sessions: number, proxied: number, extra: Partial<ObservedSurface> = {}): ObservedSurface {
  const routable = extra.routable ?? true;
  const state =
    extra.state ?? (sessions === 0 ? "unobserved" : proxied === 0 ? "bypass_suspect" : proxied < sessions ? "partial" : "attested");
  return {
    kind,
    state,
    sessions,
    proxied_sessions: proxied,
    routable,
    bypass: extra.bypass ?? (routable && (state === "bypass_suspect" || state === "partial")),
    reason: "",
    ...extra,
  };
}

function setup(status: string, routed: boolean, surfaces?: ObservedSurface[]): CapturePillInput {
  return {
    status,
    routed_to_observer: routed,
    observed_route: surfaces ? { window_days: 7, surfaces } : undefined,
  };
}

test("capturePillView: one row per verdict, from the file verdict and the observed verdict", () => {
  const rows: [string, CapturePillInput | null | undefined, string, string][] = [
    ["proxied sessions read Active", setup("oauth_ready", true, [surface("cli", 3, 3)]), "Active", "active"],
    ["a routed file with no proxied session is Routed (file only)", setup("api_key_ready", true, [surface("cli", 0, 0)]), "Routed (file only)", "absent"],
    ["a routed file with no observed data is Routed (file only)", setup("oauth_ready", true), "Routed (file only)", "absent"],
    [
      "CLI proxied, desktop bypassing is Partly bypassed",
      setup("oauth_ready", true, [surface("cli", 5, 5), surface("desktop", 3, 0)]),
      "Partly bypassed: desktop",
      "paused",
    ],
    ["a partly proxied CLI is Partly bypassed", setup("oauth_ready", true, [surface("cli", 2, 1)]), "Partly bypassed: cli", "paused"],
    ["nothing proxied on a routed file is Bypassed", setup("oauth_ready", true, [surface("cli", 4, 0)]), "Bypassed: cli", "paused"],
    ["an installed, unrouted, unobserved tool is Not routed", setup("oauth_ready", false, []), "Not routed", "paused"],
    // Node 1, 2026-10-06: Claude Code is not installed there; the pill read
    // "Paused" while every other tool was being captured.
    ["no Claude Code here", setup("claude_not_installed", false), "No Claude Code here", "absent"],
    ["an unknown status", setup("something_new", false), "Not routed", "paused"],
    ["no snapshot yet", undefined, "Checking", "absent"],
    ["null snapshot", null, "Checking", "absent"],
  ];
  for (const [name, input, label, state] of rows) {
    const v = capturePillView(input);
    assert.equal(v.label, label, name);
    assert.equal(v.state, state, name);
    assert.notEqual(v.label, "Paused", name);
    assert.ok(v.tooltip.length > 0, name);
    assert.doesNotMatch(v.label + v.tooltip, /[\u2013\u2014]/, name);
    assert.ok(CAPTURE_DOT[v.state], `CAPTURE_DOT has a "${v.state}" state`);
  }
  assert.match(capturePillView(setup("something_new", false)).tooltip, /something_new/);
});

test("capturePillView: the install status alone never renders Active (OBS-1)", () => {
  // The pill used to read Active for oauth_ready / api_key_ready whatever the
  // settings file said. With no proxied session it is never Active now.
  for (const status of ["oauth_ready", "api_key_ready"]) {
    for (const routed of [false, true]) {
      for (const surfaces of [undefined, [], [surface("cli", 0, 0)], [surface("desktop", 2, 0, { state: "unknown_measurability", routable: false })]]) {
        const v = capturePillView(setup(status, routed, surfaces));
        assert.notEqual(v.label, "Active", `${status} routed=${routed} ${JSON.stringify(surfaces)}`);
      }
    }
  }
});

test("capturePillView: a surface that cannot be judged is named, never called a bypass", () => {
  const v = capturePillView(
    setup("oauth_ready", true, [
      surface("cli", 2, 2),
      surface("desktop", 3, 0, { host: "claude-desktop", state: "unknown_measurability", routable: true, bypass: false }),
    ]),
  );
  assert.equal(v.label, "Active");
  assert.match(v.tooltip, /Not judged: desktop \(claude-desktop\)/);
});

test("capturePillView: the bypass tooltip counts sessions per surface", () => {
  const v = capturePillView(setup("oauth_ready", true, [surface("cli", 5, 5), surface("desktop", 3, 0)]));
  assert.match(v.tooltip, /5 of 8 Claude Code sessions/);
  assert.match(v.tooltip, /desktop: 3 of 3 sessions did not reach the proxy/);
});

test("capturePillView: an invalid row is ignored, not counted", () => {
  const v = capturePillView(setup("oauth_ready", true, [surface("cli", 1, 5, { state: "invalid_input", bypass: false })]));
  assert.equal(v.label, "Routed (file only)");
});

test("capturePillView: no pill at all when Claude Code is not on this machine", () => {
  // T-803: the pill read "No Claude Code" beside a dashboard full of Claude
  // Code sessions captured from another OS. Nothing to report here: hidden.
  assert.equal(capturePillView(setup("claude_not_installed", false)).hidden, true);
  for (const s of [setup("oauth_ready", true), setup("api_key_ready", false), setup("something_new", false), undefined]) {
    assert.ok(!capturePillView(s).hidden, JSON.stringify(s));
  }
});

// WINNODE2 16b: Claude Code installed as the VS Code extension only (no
// `claude` on PATH) is not "No Claude Code": the pill reports its route.
test("an extension-only Claude Code reports its route, not absence", () => {
  const routed = capturePillView(setup("extension_ready", true));
  assert.equal(routed.hidden, undefined);
  assert.equal(routed.label, "Routed (file only)");
  const proxied = capturePillView(setup("extension_ready", true, [surface("ide", 3, 3)]));
  assert.equal(proxied.label, "Active");
  const unrouted = capturePillView(setup("extension_ready", false));
  assert.equal(unrouted.label, "Not routed");
});
