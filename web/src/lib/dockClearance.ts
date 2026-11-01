// The bottom clearance the floating "New terminal" dock (LaunchDock) needs
// (T-855). The dock is fixed bottom-right over every page, so the shell's
// scrolling page area reserves this much space at its bottom while the dock
// is visible: a full-height page (Messages) then ends above the dock, and the
// last row of a long page scrolls clear of it. The shell reads it as the CSS
// variable DOCK_CLEARANCE_VAR on <html>; it is 0 when no dock is on screen.

/** The CSS variable the shell's page area pads its bottom with. */
export const DOCK_CLEARANCE_VAR = "--sb-dock-clearance";

/** The gap kept between page content and the top of the dock, px. */
export const DOCK_GAP = 12;

/** A dock dragged higher than this many px above the bottom edge no longer
 *  sits over the bottom of the page, so it reserves nothing. */
export const DOCK_BOTTOM_BAND = 200;

/**
 * dockClearance is the space, in whole px, the page must keep free at its
 * bottom for a dock whose box is `rect` in a viewport `viewportHeight` tall.
 * A hidden dock (zero size) and a dock the developer dragged up out of the
 * bottom band reserve nothing.
 */
export function dockClearance(rect: { top: number; bottom: number; height: number }, viewportHeight: number): number {
  if (rect.height <= 0 || viewportHeight <= 0) return 0;
  if (rect.bottom < viewportHeight - DOCK_BOTTOM_BAND) return 0;
  return Math.max(0, Math.ceil(viewportHeight - rect.top + DOCK_GAP));
}
