// Obs - the SuperBased mascot as a tiny inline-SVG React component:
// "Prompt in a cape" (B4C-1, chosen 2026-10-02 to replace the arcade's
// pixel player sprite on the dashboards). A squishy terminal buddy whose
// face IS the prompt - a ">" winking eye and a blinking "_" cursor - in a
// streaming shoulder cape, with the logo mark as a belly badge. Blueprint
// body + amber cape in the light theme, amber body + periwinkle cape in
// the dark theme. The delight-layer enabler (usability arc P4.9 / review
// §9.2): build it once, and every earned moment after this is a cheap
// cameo.
//
// Design contract (§9.1/§9.4, binding; flight added by D-665..D-669):
//   - states: idle (cursor blinks, cape ripples) · jump = celebrate (a
//     burst, the cape flares, a fist pump and a dash-hop - the brand's
//     celebration) · lost (the cape hangs, the cursor waits, thinking dots:
//     puzzled, never sad - error pages only) · dash (Hero dash, the flying
//     pose: face toward the viewer, 22 degree lean, squash and stretch, cape
//     straight back at shipped size, three afterimages, a loop about every
//     5 s; drawn in the wide frame)
//   - prefers-reduced-motion → every animation collapses to a static frame
//     (CSS media query, no JS), and the dash shows the static IDLE pose
//   - at <= 40 px the cape is the simplified silhouette (SMALL_CAPE_MAX_PX);
//     the dash also keeps one afterimage and skips the loop
//   - colours come only from the --mascot-* tokens (shared/styles/tokens.css)
//   - the celebrate burst, the cape and the dash afterimages draw outside
//     the box (overflow visible): never put it in a clipping container
//   - no image assets, no new deps, no sound, no confetti
//   - appears ONLY in earned/transitional moments: onboarding, first
//     capture, setup steps, 404, crash, and (D-665) the loaders and finish
//     lines in shared/primitives/ObsFlight.tsx (boot screen, the TopProgress
//     rider on slow route loads, the org Assistant's working turn, jobs with
//     real progress, landing on finish lines). Never inside working surfaces
//     (tables, charts, forms, drawers), never for loads under 300 ms,
//     refetches or polling, never over a security or denial moment, and
//     errors keep `lost`.
//
// The artwork is data in shared/lib/mascot.ts (pure; pinned by
// web/src/lib/mascot.test.ts); this file only maps it to elements. Lives
// in shared/ (operator decision D6) so the org dashboard's 404, crash and
// setup states use the same mascot as the node dashboard; web's
// @/components/Obs is a re-export shim.

import { createElement, useId, type ReactNode } from "react";
import { mascotCss, mascotFrame, mascotNodes, type MascotNode, type MascotState } from "../lib/mascot";
import { useReducedMotion } from "../lib/useReducedMotion";

/** Legacy state names; "jump" is the celebrate state. */
export type ObsState = "idle" | "jump" | "lost";
export type { MascotState };

/** Maps the legacy "jump" onto "celebrate"; the new names pass through. */
export function toMascotState(state: ObsState | MascotState): MascotState {
  return state === "jump" ? "celebrate" : state;
}

function render(node: MascotNode, key: number): ReactNode {
  return createElement(node.tag, { ...node.attrs, key }, node.children?.map(render));
}

// Obs renders the mascot at `size` CSS pixels (default 32): square, or the
// wide frame (1.8 x 1.24 of size) for the dash and for any pose that shares
// a host with it (`wide`), so a pose change never shifts layout.
export function Obs({
  state = "idle",
  size = 32,
  wide = false,
  decorative = false,
  className,
}: {
  state?: ObsState | MascotState;
  size?: number;
  /** Draw in the wide frame even when the pose is not the dash. */
  wide?: boolean;
  /** Inside a labelled status: hide from assistive tech instead of role="img". */
  decorative?: boolean;
  className?: string;
}) {
  const scope = `sb-mascot-${useId().replace(/[^a-zA-Z0-9]/g, "")}`;
  const reduced = useReducedMotion();
  const asked = toMascotState(state);
  // Reduced motion: the flying pose is never shown, the static idle is.
  const s = asked === "dash" && reduced ? "idle" : asked;
  const f = mascotFrame(asked, size, wide);
  const a11y = decorative
    ? { "aria-hidden": true as const, focusable: "false" as const }
    : { role: "img", "aria-label": "Obs, the SuperBased mascot" };
  return (
    <svg
      width={f.width}
      height={f.height}
      viewBox={f.viewBox}
      {...a11y}
      data-state={s}
      className={className ? `${scope} ${className}` : scope}
      style={{ overflow: "visible" }}
    >
      <style>{mascotCss(scope, s, size)}</style>
      {mascotNodes(s, size).map(render)}
    </svg>
  );
}

/** Alias for new code; `Obs` stays the canonical export. */
export const Mascot = Obs;
