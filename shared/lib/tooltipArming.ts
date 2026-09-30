// Pure decision logic for the lazy Tooltip (shared/primitives/Tooltip.tsx).
//
// A table renders one Tooltip per cell, and mounting the full @floating-ui
// stack (useFloating + hover/focus/dismiss/role interactions + transition
// styles) for every one of them was a top self-time item on every table
// page. The Tooltip therefore starts "unarmed": it renders only its child,
// plus a few native listeners, and mounts the floating machinery the first
// time the pointer enters or focus lands inside the trigger (or the caller
// forces it open). Because the machinery attaches its listeners AFTER the
// event that armed it, the arming intent is replayed once the machinery is
// live, so the observable behaviour matches an eagerly mounted tooltip:
// the hover still opens after the rest delay, and a keyboard focus still
// opens it (subject to the same :focus-visible test).
//
// No React, no DOM: the component feeds plain facts in and gets plain
// decisions out. Tests: web/src/lib/tooltipArming.test.ts.

/** Why the tooltip was (or would be) armed. */
export type ArmEvent = "pointerenter" | "focusin" | "controlled-open";

export type ArmInput = {
  /** The floating machinery is already mounted. */
  armed: boolean;
  /** The caller passes `open` (hover/focus listeners are bypassed). */
  controlled: boolean;
  /** The caller's `open` value (meaningful only when controlled). */
  controlledOpen: boolean;
  /** `disabled`, or no content to show: the child renders bare. */
  inert: boolean;
};

/**
 * shouldArm decides whether `event` mounts the floating machinery.
 * Hover and focus arm only an uncontrolled tooltip (a controlled one has its
 * hover/focus listeners disabled, exactly as the eager version did); a
 * controlled open arms regardless of how it got there.
 */
export function shouldArm(input: ArmInput, event: ArmEvent): boolean {
  if (input.armed || input.inert) return false;
  if (event === "controlled-open") return input.controlled && input.controlledOpen;
  return !input.controlled;
}

/**
 * stillInsideAfterLeave: a pointerleave clears the "pointer inside" intent,
 * except for a touch pointer. A tap fires pointerleave right after
 * pointerup, yet the browser's compatibility mouse events (mouseenter +
 * mousemove, no mouseleave until the next tap elsewhere) are what an eager
 * tooltip opened on, so a tap must still count as inside for the replay.
 */
export function stillInsideAfterLeave(pointerType: string | undefined): boolean {
  return pointerType === "touch";
}

/** Live facts about the trigger at the moment the machinery went live. */
export type ReplayInput = {
  /** The pointer is still inside the trigger (enter seen, no leave since). */
  pointerInside: boolean;
  /** Focus is still inside the trigger (the focused element is it or a descendant). */
  focusInside: boolean;
  /** The event that armed the tooltip. */
  armedBy: ArmEvent | null;
  /** The caller controls `open`. */
  controlled: boolean;
  inert: boolean;
};

export type ReplayPlan = {
  /** Re-deliver the pointer entry so the hover rest delay starts now. */
  hover: boolean;
  /** Re-deliver the focus so the focus interaction can open it. */
  focus: boolean;
};

/**
 * replayPlan says which arming intents to re-deliver once the machinery is
 * listening. An intent is replayed only while it still holds: a pointer
 * that left before the machinery went live must not open the tooltip, and
 * neither may a focus that has already moved away. A controlled or inert
 * tooltip replays nothing (its hover/focus interactions are disabled).
 * Focus is replayed whenever it is inside, even when hover armed the
 * tooltip: an eager tooltip would have seen that focus too.
 */
export function replayPlan(input: ReplayInput): ReplayPlan {
  if (input.controlled || input.inert || input.armedBy == null) {
    return { hover: false, focus: false };
  }
  return { hover: input.pointerInside, focus: input.focusInside };
}
