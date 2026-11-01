// Pins shared/lib/obsFlight.ts (D-665..D-669): the take-off and landing
// step tables, reduced motion skipping to the end pose, the job rider never
// running ahead of the real ratio, and the scenery CSS keeping all motion
// behind the reduced-motion gate with token colours only.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  CELEBRATE_TWICE_MS,
  FLIGHT_STEPS,
  cloudSpecs,
  flightSceneCss,
  flightSceneMarkup,
  flightSteps,
  flyingState,
  jobRiderPlacement,
  stepAt,
  streakSpecs,
} from "../../../shared/lib/obsFlight.ts";

const AT: Array<[kind: "takeoff" | "landing", ms: number, state: string, move: string | null]> = [
  ["takeoff", 0, "idle", "crouch"],
  ["takeoff", 279, "idle", "crouch"],
  ["takeoff", 280, "dash", "spring"],
  ["takeoff", 5000, "dash", null],
  ["landing", 0, "dash", "landing"],
  ["landing", 549, "dash", "landing"],
  ["landing", 550, "celebrate", "spring"],
  ["landing", 550 + CELEBRATE_TWICE_MS - 1, "celebrate", "spring"],
  ["landing", 550 + CELEBRATE_TWICE_MS, "idle", null],
];
for (const [kind, ms, state, move] of AT) {
  test(`${kind} at ${ms} ms: ${state} ${move ?? "(rest)"}`, () => {
    const s = stepAt(flightSteps(kind, false), ms);
    assert.equal(s.state, state);
    assert.equal(s.move, move);
  });
}

test("landing celebrates twice (two 0.9 s cycles) before resting", () => {
  assert.equal(CELEBRATE_TWICE_MS, 2 * 900);
  const l = FLIGHT_STEPS.landing;
  assert.equal(l.at(-1)!.at - l[1]!.at, CELEBRATE_TWICE_MS);
});

test("reduced motion: both sequences are the static idle end pose", () => {
  for (const kind of ["takeoff", "landing"] as const) {
    assert.deepEqual(flightSteps(kind, true), [{ at: 0, state: "idle", move: null }]);
  }
  assert.equal(flyingState(true), "idle");
  assert.equal(flyingState(false), "dash");
});

const JOB: Array<[ratio: number | null | undefined, pct: number, landed: boolean]> = [
  [0, 0, false],
  [0.4567, 45.6, false], // floored: never ahead
  [0.999, 99.9, false],
  [1, 100, true],
  [1.4, 100, true],
  [-0.2, 0, false],
  [Number.NaN, 0, false],
  [null, 0, false],
  [undefined, 0, false],
];
for (const [ratio, pct, landed] of JOB) {
  test(`job rider at ratio ${ratio}: ${pct}%${landed ? ", landed" : ""}`, () => {
    assert.deepEqual(jobRiderPlacement(ratio), { pct, landed });
  });
}

test("scenery: three cloud layers, twelve streaks, near clouds fastest", () => {
  const clouds = cloudSpecs();
  assert.equal(new Set(clouds.map((c) => c.dur)).size, 3);
  const near = clouds.filter((c) => c.layer === "near").map((c) => c.dur);
  const far = clouds.filter((c) => c.layer === "far").map((c) => c.dur);
  assert.ok(Math.max(...near) < Math.min(...far));
  assert.ok(clouds.every((c) => c.dur >= 1.6 && c.dur <= 5.5));
  assert.equal(streakSpecs().length, 12);
  assert.ok(clouds.every((c) => c.delay <= 0));
});

test("scenery CSS: motion only inside the reduced-motion gate, colours are tokens", () => {
  const css = flightSceneCss("sb-flight");
  const gate = css.indexOf("@media (prefers-reduced-motion: no-preference){");
  assert.ok(gate > 0);
  assert.doesNotMatch(css.slice(0, gate), /animation|@keyframes|transition/);
  assert.ok(css.endsWith("}}"));
  assert.doesNotMatch(css.replace(/var\(--[a-z0-9-]+\)/g, ""), /#[0-9a-f]{3,6}\b|rgba?\(/i, "no literal colours");
  // Only transform and opacity animate.
  for (const kf of css.matchAll(/@keyframes [^{]+\{(.*?\})\}/g)) {
    assert.doesNotMatch(kf[1], /(width|height|left|top|margin)\s*:/, kf[0]);
  }
  // Every class is prefixed with the root.
  assert.match(css, /^\.sb-flight-sky\{/);
  assert.match(flightSceneMarkup("sbo"), /class="sbo-cloud sbo-far"/);
});
