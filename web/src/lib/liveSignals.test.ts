// Pins the live-signal tables (WS8 motion and live signals): unknown states
// render an honest still grey dot, `still` rows keep their tone without the
// halo, the agent-status motion table, the utilisation bands, the cache-life
// ratio's unknown cases, and the row-arrival rule (no arrivals on the first
// render, a new key arrives once and stays arrived while present).
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  ACTIVITY_DOT,
  AGENT_STATUS_MOTION,
  CAPTURE_DOT,
  CLOUD_SIGN_IN_DOT,
  INSTANCE_DOT,
  LIVE_TAIL_DOT,
  PROCESS_DOT,
  TRANSPORT_DOT,
  UTIL_BANDS,
  advanceArrivals,
  agentStatusMotion,
  bandTone,
  cacheLifeRatio,
  isArrival,
  liveDotProps,
} from "./liveSignals.ts";

test("liveDotProps: known rows keep tone, still rows drop the halo, unknown is still grey", () => {
  assert.deepEqual(liveDotProps(TRANSPORT_DOT, "open"), { tone: "success" });
  assert.deepEqual(liveDotProps(TRANSPORT_DOT, "error"), { tone: "danger", still: true });
  assert.deepEqual(liveDotProps(TRANSPORT_DOT, "nope"), { tone: "idle" });
  assert.deepEqual(liveDotProps(TRANSPORT_DOT, undefined), { tone: "idle" });
  assert.deepEqual(liveDotProps(LIVE_TAIL_DOT, "paused"), { tone: "warn", still: true });
});

test("every dot table row uses a LiveDot tone", () => {
  const tones = new Set(["success", "warn", "danger", "info", "idle"]);
  for (const table of [TRANSPORT_DOT, CAPTURE_DOT, ACTIVITY_DOT, LIVE_TAIL_DOT, CLOUD_SIGN_IN_DOT, INSTANCE_DOT, PROCESS_DOT]) {
    for (const [k, v] of Object.entries(table)) assert.ok(tones.has(v.tone), `${k}: ${v.tone}`);
  }
});

test("agent status motion: working spins, waiting blinks, blocked and unknown are still", () => {
  assert.equal(agentStatusMotion("working"), "spin");
  assert.equal(agentStatusMotion("waiting-for-input"), "blink");
  assert.equal(agentStatusMotion("blocked"), "still");
  assert.equal(agentStatusMotion("something-new"), "still");
  assert.equal(agentStatusMotion(null), "still");
  assert.equal(Object.keys(AGENT_STATUS_MOTION).length, 6);
});

test("utilisation bands walk top-down", () => {
  const cases: [number, string][] = [
    [95, "danger"],
    [90, "warn"],
    [71, "warn"],
    [70, "accent"],
    [0, "accent"],
    [Number.NaN, "neutral"],
  ];
  for (const [v, want] of cases) assert.equal(bandTone(UTIL_BANDS, v), want, String(v));
});

test("cacheLifeRatio: share of life left, null when unknown", () => {
  const w = { last_refresh: "2026-09-28T10:00:00Z", expires_at: "2026-09-28T10:05:00Z" };
  const at = (iso: string) => Date.parse(iso);
  assert.equal(cacheLifeRatio(w, at("2026-09-28T10:00:00Z")), 1);
  assert.equal(cacheLifeRatio(w, at("2026-09-28T10:02:30Z")), 0.5);
  assert.equal(cacheLifeRatio(w, at("2026-09-28T10:09:00Z")), 0);
  assert.equal(cacheLifeRatio({ ...w, last_refresh: "" }, 0), null);
  assert.equal(cacheLifeRatio({ ...w, expires_at: "garbage" }, 0), null);
  assert.equal(cacheLifeRatio({ last_refresh: w.expires_at, expires_at: w.last_refresh }, 0), null);
});

test("arrivals: baseline first, a new key arrives and stays arrived while present", () => {
  let s = advanceArrivals(null, ["a", "b"]);
  assert.equal(isArrival(s, "a"), false);
  assert.equal(isArrival(null, "a"), false);
  // Render before the commit that includes "c": c is new.
  assert.equal(isArrival(s, "c"), true);
  s = advanceArrivals(s, ["c", "a", "b"]);
  assert.equal(isArrival(s, "c"), true);
  assert.equal(isArrival(s, "a"), false);
  // Next poll, c still present: still arrived (class is never pulled mid-animation).
  s = advanceArrivals(s, ["c", "a", "b"]);
  assert.equal(isArrival(s, "c"), true);
  // c leaves: forgotten.
  s = advanceArrivals(s, ["a", "b"]);
  assert.equal(s.arrived.has("c"), false);
});
