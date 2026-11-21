// ObsFlight: the flying mascot loaders and finish lines (D-665..D-669,
// "Obs takes flight", 2026-10-15). Every piece draws the Hero dash pose from
// shared/lib/mascot.ts through <Obs>, and the scenery from
// shared/lib/obsFlight.ts (the same specs and CSS the generated boot screens
// in each index.html use), so there is one look on every app: clouds and
// speed lines included.
//
//   ObsFlight     the stage: sky, three cloud layers, speed streaks, Obs
//                 taking off and flying centred, a caption (the live region).
//   ObsLoader     ObsFlight behind the timing rules (useDeferredShow: 300 ms
//                 delay, 600 ms minimum, an honest line after 8 s, stops on
//                 failure).
//   ObsInline     the small rider: a flying Obs with a short speed trail,
//                 for an inline wait such as the org Assistant's turn.
//   ObsMoment     a scripted take-off or landing (idle, crouch, spring into
//                 the dash; or descend, celebrate twice, rest on idle).
//   ObsLanding    ObsMoment kind="landing", for finish lines.
//   ObsJobRider   Obs on a determinate job track, at the real ratio, never
//                 ahead; lands into celebrate at 100%.
//
// Pure presentation: no fetch, no router, no app state (docs/app-design-
// system.md). Reduced motion: the static idle pose, still clouds, no
// streaks, sequences jump to their end pose, riders jump without travel.
// Where Obs must NOT fly: see the Obs.tsx contract header.

import clsx from "clsx";
import { useEffect, useState, type CSSProperties, type ReactNode } from "react";
import { Obs } from "./Obs";
import {
  cloudSpecs,
  CLOUD_PATH,
  flightSceneCss,
  flightSteps,
  flyingState,
  jobRiderPlacement,
  streakSpecs,
  type FlightSequence,
} from "../lib/obsFlight";
import { useDeferredShow } from "../lib/useDeferredShow";
import { useReducedMotion } from "../lib/useReducedMotion";
import type { DeferredShowOptions } from "../lib/deferredShow";

const ROOT = "sb-flight";
const SCENE_CSS = flightSceneCss(ROOT);
const CLOUDS = cloudSpecs();
const STREAKS = streakSpecs();

/** The scenery CSS, injected next to each flying element (scoped classes). */
function SceneStyle() {
  return <style>{SCENE_CSS}</style>;
}

function Scenery() {
  return (
    <>
      {CLOUDS.map((c, i) => (
        <div
          key={i}
          className={clsx(`${ROOT}-cloud`, c.layer === "far" && `${ROOT}-far`)}
          style={{ top: c.top, "--x": `${c.x}px`, "--dur": `${c.dur}s`, animationDelay: `${c.delay}s` } as CSSProperties}
        >
          <svg width={c.w} height={Math.round(c.w * 0.42)} viewBox="0 0 100 42" aria-hidden focusable="false">
            <path d={CLOUD_PATH} />
          </svg>
        </div>
      ))}
      <div className={`${ROOT}-streaks`}>
        {STREAKS.map((s, i) => (
          <span key={i} style={{ top: s.top, width: s.w, "--d": `${s.dur}s`, animationDelay: `${s.delay}s` } as CSSProperties} />
        ))}
      </div>
    </>
  );
}

/**
 * ObsMoment plays a scripted take-off or landing once (again whenever
 * `playKey` changes), then holds the end pose: the dash after a take-off,
 * idle after a landing. Under reduced motion it shows the end pose at once
 * (idle in both cases). Always the wide frame, so pose changes never shift
 * layout.
 */
export function ObsMoment({
  kind,
  size = 40,
  playKey,
  decorative = false,
  className,
}: {
  kind: FlightSequence;
  size?: number;
  playKey?: string | number;
  decorative?: boolean;
  className?: string;
}) {
  const reduced = useReducedMotion();
  const steps = flightSteps(kind, reduced);
  const [i, setI] = useState(0);
  useEffect(() => {
    setI(0);
    const timers = steps.slice(1).map((s, idx) => setTimeout(() => setI(idx + 1), s.at));
    return () => timers.forEach(clearTimeout);
    // steps is derived from kind + reduced
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [kind, reduced, playKey]);
  const step = steps[Math.min(i, steps.length - 1)]!;
  return (
    <span key={i} className={clsx(`${ROOT}-move`, step.move && `${ROOT}-${step.move}`, className)}>
      <SceneStyle />
      <Obs state={step.state} size={size} wide decorative={decorative} />
    </span>
  );
}

/** ObsLanding: fly in, land, celebrate twice, rest on idle (finish lines). */
export function ObsLanding(props: { size?: number; playKey?: string | number; className?: string }) {
  return <ObsMoment kind="landing" {...props} />;
}

/**
 * ObsFlight is the stage: the world rushes past while Obs takes off and
 * flies roughly centred. The caption is the live region; the stage is
 * aria-busy. `sub` is the honest slow line (empty until there is one).
 */
export function ObsFlight({
  label,
  sub,
  size = 96,
  className,
}: {
  label: ReactNode;
  sub?: ReactNode;
  size?: number;
  className?: string;
}) {
  return (
    <div className={clsx(`${ROOT}-sky`, className)} aria-busy="true">
      <SceneStyle />
      <Scenery />
      <div className={`${ROOT}-flyer`}>
        <ObsMoment kind="takeoff" size={size} decorative />
      </div>
      <div className={`${ROOT}-caption`} role="status" aria-live="polite">
        {label}
        <small>{sub}</small>
      </div>
    </div>
  );
}

/**
 * ObsLoader shows the stage for a full-page wait with no layout to promise,
 * under the timing rules: nothing for 300 ms, at least 600 ms once shown,
 * `slowLine` after 8 s, and nothing at all once `failed` (the caller shows
 * the real state, a retry or `lost`).
 */
export function ObsLoader({
  active,
  failed,
  label,
  slowLine,
  size,
  timing,
  className,
}: {
  active: boolean;
  failed?: boolean;
  label: ReactNode;
  slowLine?: ReactNode;
  size?: number;
  timing?: DeferredShowOptions;
  className?: string;
}) {
  const { show, slow } = useDeferredShow(active, { ...timing, failed });
  if (!show) return null;
  return <ObsFlight label={label} sub={slow ? slowLine : undefined} size={size} className={className} />;
}

/**
 * ObsInline is the small flying rider with a short speed trail, for an
 * inline wait (40 px and below: the small cape, one afterimage, no loop).
 * It carries the status label; put the visible progress text beside it.
 */
export function ObsInline({ size = 28, label, className }: { size?: number; label: string; className?: string }) {
  const reduced = useReducedMotion();
  return (
    <span role="status" aria-label={label} className={clsx(`${ROOT}-inline`, className)}>
      <SceneStyle />
      <span className={`${ROOT}-trail`} aria-hidden>
        <span style={{ top: "10%" }} />
        <span style={{ top: "48%", animationDelay: "-.2s" }} />
        <span style={{ top: "86%", animationDelay: "-.4s" }} />
      </span>
      <Obs state={flyingState(reduced)} size={size} wide decorative />
    </span>
  );
}

/**
 * ObsJobRider puts Obs on a determinate job's track: at the reported ratio,
 * never ahead of it (no easing past the real number), and it lands into
 * celebrate at 100%, then rests on idle. Pair it with the job's own Meter
 * and text; the rider is decorative.
 */
export function ObsJobRider({ ratio, size = 28, className }: { ratio: number | null | undefined; size?: number; className?: string }) {
  const reduced = useReducedMotion();
  const { pct, landed } = jobRiderPlacement(ratio);
  const w = Math.round(size * 1.8 * 10) / 10;
  const h = Math.round(size * 1.24 * 10) / 10;
  return (
    // The run box slides by its own width, so at a high ratio it sits past
    // the track's right edge: clip x (only x, so Obs and its cape stay
    // whole) or it adds scrollable overflow to the page (the progress-line
    // rider's 2026-11-06 scrollbar flicker, shared/styles/motion.css).
    <div className={clsx(`${ROOT}-job`, className)} style={{ height: h, overflowX: "clip", overflowY: "visible" }} aria-hidden>
      <SceneStyle />
      <div className={`${ROOT}-job-run`} style={{ width: `calc(100% - ${w}px)`, transform: `translateX(${pct}%)` }}>
        <span className={`${ROOT}-job-at`}>
          {landed ? (
            <ObsMoment kind="landing" size={size} decorative />
          ) : (
            <Obs state={flyingState(reduced)} size={size} wide decorative />
          )}
        </span>
      </div>
    </div>
  );
}
