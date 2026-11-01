// npmUpdateCommand is the npm update command the operator types on the
// daemon's host. hostOS is the daemon's runtime.GOOS (useHostOS), since the
// command runs where the daemon runs, not in this browser. On Windows it
// names npm.cmd: PowerShell's default execution policy refuses the npm.ps1
// shim a bare `npm` resolves to, and npm.cmd also runs in Command Prompt
// (T-921). Unknown (null) keeps the bare form. Same rule as the Go side's
// internal/platform/winshim.
export function npmUpdateCommand(hostOS: string | null | undefined): string {
  const npm = hostOS === "windows" ? "npm.cmd" : "npm";
  return `${npm} i -g @superbased/observer`;
}
