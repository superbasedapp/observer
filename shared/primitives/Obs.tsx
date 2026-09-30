// Obs - the SuperBased mascot (the website arcade's player sprite,
// PLAYER_ART in website/arcade/main.js) as a tiny inline-SVG React
// component. The delight-layer enabler (usability arc P4.9 / review
// §9.2): build the sprite once, and every earned moment after this is
// a cheap cameo.
//
// Design contract (§9.1/§9.4, binding):
//   - states: idle (slow blink) · jump (teal→gold pulse, the brand's
//     celebration) · lost (greyed, x-eyes — error pages only)
//   - prefers-reduced-motion → every animation collapses to a static
//     frame (CSS media query, no JS)
//   - no image assets, no new deps, no sound, no confetti
//   - appears ONLY in earned/transitional moments — never inside
//     working surfaces (tables, charts, forms)
//
// Lives in shared/ (operator decision D6) so the org dashboard's 404,
// crash and onboarding states use the same sprite as the node dashboard;
// web's @/components/Obs is a re-export shim.

import { useId } from "react";

// The arcade's 8×8-grid humanoid: [x, y, w, h] cell segments.
// Head (0-2) + neck (3) + chest (4) + torso/arms (5) + legs/feet (6-7).
const SEGMENTS: [number, number, number, number][] = [
  [2, 0, 4, 1], // head crown
  [1, 1, 6, 1], // head full
  [1, 2, 6, 1], // head row (eyes overlay)
  [2, 3, 4, 1], // neck
  [1, 4, 6, 1], // chest (emblem overlay)
  [0, 5, 8, 1], // torso + arms
  [1, 6, 2, 1], // left leg
  [5, 6, 2, 1], // right leg
  [1, 7, 2, 1], // left foot
  [5, 7, 2, 1], // right foot
];

// The 'S' chest emblem as pixels (3×3 sub-grid on the chest row, the
// glyph reduced to its minimum legible pixel form).
const EMBLEM: [number, number][] = [
  [3, 3.7],
  [2.6, 4.1],
  [3.4, 4.4],
];

export type ObsState = "idle" | "jump" | "lost";

// Obs renders the mascot at `size` CSS pixels (default 32). Colors
// ride the dashboard theme through currentColor-independent vars with
// arcade fallbacks (teal #2EC4B6, gold #F4A024).
export function Obs({
  state = "idle",
  size = 32,
  className,
}: {
  state?: ObsState;
  size?: number;
  className?: string;
}) {
  const uid = useId().replace(/[^a-zA-Z0-9]/g, "");
  const body = state === "lost" ? "var(--fg-3, #8a8a93)" : "#2EC4B6";
  const cells = SEGMENTS.map(([x, y, w, h], i) => (
    <rect key={i} x={x * 4} y={y * 4 + 4} width={w * 4} height={h * 4} />
  ));
  return (
    <svg
      width={size}
      height={size * 1.125}
      viewBox="0 0 32 36"
      role="img"
      aria-label="Obs, the observer mascot"
      className={className}
      style={{ imageRendering: "pixelated" }}
    >
      <style>{`
        .obs-body-${uid} { fill: ${body}; }
        .obs-eye-${uid} { fill: #0E0C18; }
        .obs-emblem-${uid} { fill: #0E0C18; opacity: 0.75; }
        @media (prefers-reduced-motion: no-preference) {
          ${
            state === "idle"
              ? `.obs-eye-${uid} { animation: obs-blink-${uid} 4.2s step-end infinite; }
                 @keyframes obs-blink-${uid} { 0%, 92%, 100% { opacity: 1; } 93%, 97% { opacity: 0; } }`
              : ""
          }
          ${
            state === "jump"
              ? `.obs-body-${uid} { animation: obs-pulse-${uid} 1.1s ease-in-out infinite; }
                 .obs-root-${uid} { animation: obs-hop-${uid} 1.1s ease-in-out infinite; }
                 @keyframes obs-pulse-${uid} { 0%, 100% { fill: #2EC4B6; } 50% { fill: #F4A024; } }
                 @keyframes obs-hop-${uid} { 0%, 100% { transform: translateY(0); } 50% { transform: translateY(-2px); } }`
              : ""
          }
        }
      `}</style>
      <g className={`obs-root-${uid}`}>
        <g className={`obs-body-${uid}`}>{cells}</g>
        {state === "lost" ? (
          // x-eyes: two tiny crosses, reads "lost" at a glance.
          <g className={`obs-eye-${uid}`}>
            <rect x={9} y={13} width={2} height={2} />
            <rect x={11} y={15} width={2} height={2} />
            <rect x={21} y={13} width={2} height={2} />
            <rect x={19} y={15} width={2} height={2} />
          </g>
        ) : (
          <g className={`obs-eye-${uid}`}>
            <rect x={10} y={13} width={3} height={3} />
            <rect x={19} y={13} width={3} height={3} />
          </g>
        )}
        <g className={`obs-emblem-${uid}`}>
          {EMBLEM.map(([x, y], i) => (
            <rect key={i} x={x * 4} y={y * 4 + 4} width={4} height={1.6} />
          ))}
        </g>
      </g>
    </svg>
  );
}
