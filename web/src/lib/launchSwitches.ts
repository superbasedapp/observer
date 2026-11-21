// launchSwitches.ts: the one sentence the New terminal surfaces show while
// both launch switches are off (D-12). With [terminal.launch].allow_fresh_agent
// and allow_shell both off nothing can start from the dialog, yet the button
// stays (the dialog also holds the sandbox setup line), so it says why and
// where to turn them on instead of doing nothing.

/** LAUNCH_SWITCHES_OFF names both switches and where they live. */
export const LAUNCH_SWITCHES_OFF =
  "Fresh launch and plain shell terminals are both off, so nothing can start here. Turn either on in Terminals > Settings > Fresh-agent launch policy.";

/**
 * launchSwitchesOff reports whether both switches are known to be off. An
 * unknown switch (an older daemon that does not report it, or a reply not in
 * yet) is never read as off.
 */
export function launchSwitchesOff(fresh: boolean | null | undefined, shell: boolean | null | undefined): boolean {
  return fresh === false && shell === false;
}
