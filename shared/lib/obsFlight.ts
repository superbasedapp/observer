// Obs takes flight: the pure data behind the flying loaders (D-665..D-669,
// 2026-10-15). One owner for everything around the Hero dash pose that is
// not the character itself (that is shared/lib/mascot.ts):
//
//   - the take-off and landing sequences, as ordered step tables;
//   - the scenery (sky, three cloud layers, speed streaks) as specs plus ONE
//     CSS string, shared by the React stage (shared/primitives/ObsFlight.tsx)
//     and the generated pre-mount boot screen (shared/lib/bootScreen.ts), so
//     the two cannot drift;
//   - the job rider's placement (Obs flies at the real percentage, never
//     ahead).
//
// Pure: no React, no DOM, no timers. Colours are tokens only: the --flight-*
// set in shared/styles/tokens.css, plus --line-2 / --fg-1 / --fg-3.
// One look on every app (operator ruling): clouds and speed lines included,
// no calmer register for the org dashboard or the portal.

import type { MascotState } from "./mascot.ts";

/** A one-shot move played on the host wrapper around the pose. */
export type FlightMove = "crouch" | "spring" | "landing" | null;

/** One row of a sequence: from `at` ms, show `state` and play `move`. */
export type FlightStep = { at: number; state: MascotState; move: FlightMove };

/** The two scripted moments. */
export type FlightSequence = "takeoff" | "landing";

/** How long the celebrate pose plays on landing: two 0.9 s cycles. */
export const CELEBRATE_TWICE_MS = 1800;

/**
 * FLIGHT_STEPS: take-off is idle, a crouch squash (0.28 s), then a spring
 * into the dash; landing is a descent with a squash (0.55 s), celebrate
 * twice, then rest on idle. Walked top-down by stepAt.
 */
export const FLIGHT_STEPS: Record<FlightSequence, readonly FlightStep[]> = {
  takeoff: [
    { at: 0, state: "idle", move: "crouch" },
    { at: 280, state: "dash", move: "spring" },
    { at: 730, state: "dash", move: null },
  ],
  landing: [
    { at: 0, state: "dash", move: "landing" },
    { at: 550, state: "celebrate", move: "spring" },
    { at: 550 + CELEBRATE_TWICE_MS, state: "idle", move: null },
  ],
};

/**
 * flightSteps is the sequence a viewer actually sees. Under reduced motion
 * both sequences skip straight to their end pose, and the end pose of a
 * take-off is the static idle (a reduced-motion viewer never gets the
 * flying pose).
 */
export function flightSteps(kind: FlightSequence, reduced: boolean): readonly FlightStep[] {
  if (!reduced) return FLIGHT_STEPS[kind];
  return [{ at: 0, state: "idle", move: null }];
}

/** stepAt returns the row in force `elapsed` ms into a sequence. */
export function stepAt(steps: readonly FlightStep[], elapsed: number): FlightStep {
  let cur = steps[0]!;
  for (const s of steps) if (s.at <= elapsed) cur = s;
  return cur;
}

/** The pose a flying loader shows: the dash, or the static idle pose for a
 *  reduced-motion viewer. */
export function flyingState(reduced: boolean): MascotState {
  return reduced ? "idle" : "dash";
}

/**
 * jobRiderPlacement places Obs on a determinate job track: exactly at the
 * reported ratio (clamped to 0..1, a missing or broken ratio is 0), never
 * ahead of it, and `landed` once the job reports 100%.
 */
export function jobRiderPlacement(ratio: number | null | undefined): { pct: number; landed: boolean } {
  const r = typeof ratio === "number" && Number.isFinite(ratio) ? Math.min(1, Math.max(0, ratio)) : 0;
  return { pct: Math.floor(r * 1000) / 10, landed: r >= 1 };
}

// ---------------------------------------------------------------- scenery

/** The cloud silhouette, drawn in a 100 x 42 box. */
export const CLOUD_PATH =
  "M14 40 C2 40 0 26 12 24 C12 12 28 8 36 16 C40 4 62 2 68 16 C78 10 92 16 88 28 C100 30 98 40 88 40 Z";

/** Stage size the specs are laid out for (CSS px). */
export const STAGE_W = 360;
export const STAGE_H = 200;

/** One cloud: layer (far clouds use the paler token), width, top, drift
 *  period and its negative start offset so the sky is full from frame one. */
export type CloudSpec = { layer: "far" | "near"; w: number; top: number; dur: number; delay: number; x: number };

// Three layers, near faster than far (1.6 to 5.5 s per crossing).
const CLOUD_LAYERS: readonly { layer: "far" | "near"; w: number; dur: number; tops: readonly number[] }[] = [
  { layer: "far", w: 54, dur: 5.5, tops: [10, 84, 150] },
  { layer: "far", w: 84, dur: 3.4, tops: [44, 122] },
  { layer: "near", w: 120, dur: 1.6, tops: [16, 152] },
];

/** cloudSpecs lays the cloud layers out for the stage. `x` is the resting
 *  position a reduced-motion viewer sees (the clouds stand still). */
export function cloudSpecs(): CloudSpec[] {
  const out: CloudSpec[] = [];
  for (const L of CLOUD_LAYERS) {
    L.tops.forEach((top, i) => {
      const frac = (i + 1) / (L.tops.length + 1);
      out.push({
        layer: L.layer,
        w: L.w,
        top,
        dur: L.dur,
        delay: -Number((L.dur * frac).toFixed(2)),
        x: Math.round(STAGE_W * (1 - frac) - L.w / 2),
      });
    });
  }
  return out;
}

/** One speed streak: top, length and period (CSS px / s). */
export type StreakSpec = { top: number; w: number; dur: number; delay: number };

/** streakSpecs spreads `n` speed streaks over the stage height. */
export function streakSpecs(n = 12, height = STAGE_H): StreakSpec[] {
  const out: StreakSpec[] = [];
  for (let i = 0; i < n; i++) {
    out.push({
      top: Math.round(((i + 0.5) * height) / n + ((i * 37) % 13) - 6),
      w: 30 + ((i * 53) % 70),
      dur: Number((0.45 + ((i * 29) % 40) / 100).toFixed(2)),
      delay: -Number(((i * 0.17) % 1).toFixed(2)),
    });
  }
  return out;
}

/** cloudSvgMarkup is one cloud as inline SVG markup. */
export function cloudSvgMarkup(w: number): string {
  return `<svg width="${w}" height="${Math.round(w * 0.42)}" viewBox="0 0 100 42" aria-hidden="true" focusable="false"><path d="${CLOUD_PATH}"/></svg>`;
}

/**
 * flightSceneCss is the scenery and one-shot move CSS, every class prefixed
 * with `root` (the React stage uses "sb-flight", the boot screen "sbo").
 * Motion sits inside prefers-reduced-motion: no-preference: a reduced-motion
 * viewer gets still clouds, no streaks, no moves. Transform and opacity only.
 */
export function flightSceneCss(root: string): string {
  const r = `.${root}`;
  const k = (n: string) => `${root}-${n}`;
  return (
    `${r}-sky{position:relative;overflow:hidden;width:min(${STAGE_W}px,100%);height:${STAGE_H}px;border-radius:12px;border:1px solid var(--line-2);background:linear-gradient(180deg,var(--flight-sky-top),var(--flight-sky-bottom))}` +
    `${r}-cloud{position:absolute;left:0;line-height:0;transform:translateX(var(--x,0px))}` +
    `${r}-cloud svg{display:block;transform:scaleX(1.35);transform-origin:left center}` +
    `${r}-cloud path{fill:var(--flight-cloud)}` +
    `${r}-far path{fill:var(--flight-cloud-far)}` +
    `${r}-streaks{position:absolute;inset:0;pointer-events:none;display:none}` +
    `${r}-streaks span{position:absolute;left:0;height:2px;border-radius:2px;background:var(--flight-speed)}` +
    `${r}-flyer{position:absolute;left:50%;top:44%;transform:translate(-50%,-50%);line-height:0}` +
    `${r}-caption{position:absolute;left:0;right:0;bottom:12px;padding:0 12px;text-align:center;font-size:13px;line-height:1.4;color:var(--fg-1)}` +
    `${r}-caption small{display:block;min-height:1.3em;margin-top:2px;font-size:11.5px;color:var(--fg-3)}` +
    `${r}-move{display:inline-block;line-height:0}` +
    // The small rider: Obs with a short speed trail behind it.
    `${r}-inline{position:relative;display:inline-flex;align-items:center;margin-right:4px;line-height:0}` +
    `${r}-trail{position:absolute;left:-10px;top:22%;bottom:22%;width:55%;overflow:hidden;pointer-events:none;display:none}` +
    `${r}-trail span{position:absolute;right:0;width:12px;height:2px;border-radius:2px;background:var(--flight-speed)}` +
    // A job track: Obs rides at the real ratio (the run box is the track
    // minus Obs's own width, so it never overflows the track).
    `${r}-job{position:relative;width:100%}` +
    `${r}-job-run{position:absolute;left:0;bottom:0}` +
    `${r}-job-at{position:absolute;left:0;bottom:0;line-height:0}` +
    "@media (prefers-reduced-motion: no-preference){" +
    `${r}-trail{display:block}` +
    `${r}-trail span{animation:${k("trail")} .6s linear infinite}` +
    `@keyframes ${k("trail")}{0%{transform:translateX(0);opacity:0}30%{opacity:1}100%{transform:translateX(-26px);opacity:0}}` +
    `${r}-job-run{transition:transform .4s linear}` +
    `${r}-cloud{will-change:transform;animation:${k("drift")} var(--dur,4s) linear infinite}` +
    `@keyframes ${k("drift")}{from{transform:translateX(${STAGE_W + 60}px)}to{transform:translateX(-220px)}}` +
    `${r}-streaks{display:block}` +
    `${r}-streaks span{will-change:transform;animation:${k("streak")} var(--d,.7s) linear infinite}` +
    `@keyframes ${k("streak")}{from{transform:translateX(${STAGE_W + 40}px)}to{transform:translateX(-160px)}}` +
    `${r}-crouch{animation:${k("crouch")} .28s ease-out both}@keyframes ${k("crouch")}{0%{transform:none}100%{transform:translate(0,5%) scale(1.1,.86)}}` +
    `${r}-spring{animation:${k("spring")} .45s cubic-bezier(.2,.8,.3,1.2) both}@keyframes ${k("spring")}{0%{transform:translate(0,5%) scale(.9,1.1)}100%{transform:none}}` +
    `${r}-landing{animation:${k("landing")} .55s cubic-bezier(.3,.7,.4,1) both}@keyframes ${k("landing")}{0%{transform:translate(-10%,-14%)}75%{transform:translate(0,4%) scale(1.1,.9)}100%{transform:none}}` +
    "}"
  );
}

/**
 * flightSceneMarkup is the static sky (clouds and streaks) as HTML for the
 * boot screen; the React stage renders the same specs as elements.
 */
export function flightSceneMarkup(root: string): string {
  const clouds = cloudSpecs()
    .map(
      (c) =>
        `<div class="${root}-cloud${c.layer === "far" ? ` ${root}-far` : ""}" style="top:${c.top}px;--x:${c.x}px;--dur:${c.dur}s;animation-delay:${c.delay}s">${cloudSvgMarkup(c.w)}</div>`,
    )
    .join("");
  const streaks = streakSpecs()
    .map((s) => `<span style="top:${s.top}px;width:${s.w}px;--d:${s.dur}s;animation-delay:${s.delay}s"></span>`)
    .join("");
  return `${clouds}<div class="${root}-streaks">${streaks}</div>`;
}
