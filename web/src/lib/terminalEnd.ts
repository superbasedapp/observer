// terminalEnd: the named line for why a terminal run ended (Windows 11 Pro
// run 4, N3). The daemon sends the reason on the terminal's exit frame
// ({"t":"exit","code":N,"end_reason":"..."}, recorded on terminal_run.end_reason);
// the dashboard shows this line in the terminal and as the exited pill's
// title. The lines are the same as the CLI's (internal/termrun/endreason.go
// endLines). No imports, so node:test pins it directly.

/** One line per end reason the daemon records. */
export const TERMINAL_END_LINES: Readonly<Record<string, string>> = {
  child_exit: "the tool exited",
  console_closed: "the console window was closed",
  dashboard_stop: "stopped from the dashboard (Stop & close)",
  cli_stop: "stopped with observer terminals stop",
  launch_refused: "the launch was refused before the tool started",
  stopped_outside: "stopped from outside (for example Stop-Process, taskkill /F or a kill signal)",
  process_gone: "the run's process is gone (ended outside Observer); its exit code is not known",
  daemon_shutdown: "the Observer daemon stopped",
  resumed: "resumed in a newer run",
  org_floor_require_full_capture_hooks_drifted:
    "ended by the organization's full-capture floor (the run's hooks drifted)",
};

/**
 * terminalEndLine is "the run ended: <reason's line> (exit code N)"; an
 * unknown or missing reason says only that the run ended, and a null code
 * leaves the code out.
 */
export function terminalEndLine(reason: string | undefined, code: number | null): string {
  let s = "the run ended";
  const line = reason ? TERMINAL_END_LINES[reason] : undefined;
  if (line) s += ": " + line;
  if (code !== null) s += ` (exit code ${code})`;
  return s;
}
