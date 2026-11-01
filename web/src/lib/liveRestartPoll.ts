import type { RestartStatus } from "./useDaemonRestart";

// LIVE_RESTART_POLL_MS is how often the restart banner re-reads the restart
// report while something live or pending shows in it.
export const LIVE_RESTART_POLL_MS = 30000;

// liveRestartPollMs is the banner's poll interval for a restart report
// (SBX-UPD audit finding 5): every LIVE_RESTART_POLL_MS while a sandboxed run
// is live or a restart or update waits, and 0 (no polling) otherwise. Before
// lane SBX-UPD the banner never read the route, so with nothing live it now
// reads it once per page load and does not poll.
export function liveRestartPollMs(s: RestartStatus | null | undefined): number {
  if (!s) return 0;
  const busy =
    (s.live_sandboxed_runs?.length ?? 0) > 0 ||
    s.restart_pending === true ||
    s.update_pending === true ||
    s.update_deferred_live_sandbox === true;
  return busy ? LIVE_RESTART_POLL_MS : 0;
}
