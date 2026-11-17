// confirmButtonModel: the pure half of ConfirmButton (docs/app-design-system.md
// "ConfirmButton"). No React, no DOM: how the armed step ends, what a click
// does in each state, and where the armed note goes.
//
// The placement rule this file owns: the armed note is NEVER laid out in the
// button's own flow. It floats (position: fixed, portalled, anchored under the
// button), so arming cannot move the button. Before 2026-11-04 the note was an
// inline sibling of the button: arming widened the control, a right-aligned
// or narrow container pushed the button sideways, and a quick second click
// landed where the button used to be and missed (seen on web2 Integrations >
// Identities "Link").

/** ArmedBehaviour is how an armed ConfirmButton ends. */
export type ArmedBehaviour = {
  /** Auto-disarm delay, or null when the armed step waits for the operator. */
  autoDisarmMs: number | null;
  /** A Cancel button is shown beside the armed button. */
  showCancel: boolean;
  /** A click outside the control disarms it. */
  disarmOnOutsideClick: boolean;
};

/** armedBehaviour is the one rule for how the armed step ends, by the
 *  control's own shape, walked top-down:
 *   - a reason field waits for the operator (Cancel, Escape);
 *   - holdArmed waits, with a Cancel button;
 *   - an explicit timeoutMs is a deliberate timed arm (a caller that asked for
 *     it, e.g. the node dashboard's 8 s confirms), disarming itself;
 *   - otherwise (the default) the armed step WAITS: it never disarms on its
 *     own, because a silent revert after a couple of seconds made a slow
 *     second click re-arm and do nothing (demo issue 24). A click elsewhere or
 *     Escape cancels, and no Cancel button is added so the button cannot move
 *     in a right-aligned cell. */
export function armedBehaviour(p: { withReason: boolean; holdArmed: boolean; timeoutMs?: number }): ArmedBehaviour {
  if (p.withReason) return { autoDisarmMs: null, showCancel: true, disarmOnOutsideClick: false };
  if (p.holdArmed) return { autoDisarmMs: null, showCancel: true, disarmOnOutsideClick: true };
  if (p.timeoutMs !== undefined && p.timeoutMs > 0) return { autoDisarmMs: p.timeoutMs, showCancel: false, disarmOnOutsideClick: false };
  return { autoDisarmMs: null, showCancel: false, disarmOnOutsideClick: true };
}

/** ARMED_DEFAULT_NOTE is what the floating note says when the caller gave no
 *  note of its own and the armed step waits (no timeout), so the way out is
 *  always visible. */
export const ARMED_DEFAULT_NOTE = "Click again to confirm. Click elsewhere or press Escape to cancel.";

/** ARMED_CLASSES marks the armed button so it reads as armed even where the
 *  idle and armed variants are the same (danger -> danger). */
export const ARMED_CLASSES = "ring-2 ring-warn ring-offset-1 ring-offset-bg-1";

/** ConfirmClick is what one click on the button does. */
export type ConfirmClick = "fire" | "arm" | "hold";

/** confirmClick is the click rule, walked top-down: a control that needs no
 *  confirm fires at once; an idle one arms; an armed one fires (the second
 *  click), unless its required reason is still empty, when it holds. */
export function confirmClick(p: { requireConfirm: boolean; armed: boolean; reasonMissing: boolean }): ConfirmClick {
  if (!p.requireConfirm) return "fire";
  if (!p.armed) return "arm";
  if (p.reasonMissing) return "hold";
  return "fire";
}

/** ArmedFlowPart is one element laid out in the control's own inline row. */
export type ArmedFlowPart = "reason" | "button" | "cancel";

/** armedFlow lists the control's in-flow parts, in order. The armed note is
 *  deliberately absent from every row: it floats (ARMED_NOTE_FLOAT). */
export function armedFlow(p: { armed: boolean; withReason: boolean; showCancel: boolean }): ArmedFlowPart[] {
  const parts: ArmedFlowPart[] = [];
  if (p.armed && p.withReason) parts.push("reason");
  parts.push("button");
  if (p.armed && p.showCancel) parts.push("cancel");
  return parts;
}

/** ArmedNoteSide is which side of the button the armed note floats on. */
export type ArmedNoteSide = "bottom" | "top";

/** armedNotePlacement is the floating-ui placement for a side: start-aligned
 *  with the button. "top" is for a note that points at content right under
 *  the control ("the entries listed below"), which a bottom note would cover. */
export function armedNotePlacement(side: ArmedNoteSide = "bottom"): "bottom-start" | "top-start" {
  return side === "top" ? "top-start" : "bottom-start";
}

/** ARMED_NOTE_FLOAT is how the armed note is placed: fixed and portalled so
 *  neither a narrow container, a table cell nor an overflow-x-auto wrapper
 *  clips it or reflows around it; on its side of the button (armedNotePlacement),
 *  flipping when there is no room there and shifting to stay inside the
 *  viewport. */
export const ARMED_NOTE_FLOAT = {
  strategy: "fixed",
  offsetPx: 6,
  viewportPaddingPx: 8,
  maxWidthPx: 320,
  // Above the terminal workspace's overlay band (backdrop z-80, floating
  // panels [90,110], a slide-over opened there at 112/114) so a terminal
  // header's Close confirm shows its note, and below the guided tour
  // (z-120/130) and the terminal context menu (z-200).
  zIndex: 115,
} as const;
