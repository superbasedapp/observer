import type { RestartStatus } from "./useDaemonRestart";

// restartConfirm: the copy of the daemon-restart question (useDaemonRestart
// asks it through the shared confirmDialog). Pure, so the wording for each
// probe outcome is unit-tested.
//
// The daemon IS the proxy on its port, so the dialog says what a restart
// does to a coding session routed through it, with the live count from GET
// /api/admin/restart. It does not automate the route OFF/ON dance (lane L5
// B-R2: that needs the route writers to run before the self re-exec and
// again in the new process once its proxy serves, which lives in the start
// path, not here). The dialog says so, gives the practical way to avoid a
// dropped request (restart between turns), and names the shipped
// `observer service restart` (lane sr-restart) together with why it runs from
// a terminal the daemon did not start.

/** RestartConfirm is what a caller says about its own restart: the dialog's
 *  question and the one line on why (pending config, a new binary). */
export type RestartConfirm = { title: string; lead: string };

/** UNSAVED_LIVE_PROBES are the live changes a restart drops when they never
 *  reached config, one row each: the status route to read and the line the
 *  dialog shows when the route says the live state is unsaved (UI review
 *  U-27: a policy applied live was lost on the next restart, from any page,
 *  with no warning). Table-driven so another live-only surface is one row. */
export const UNSAVED_LIVE_PROBES: ReadonlyArray<{ path: string; unsaved: (body: unknown) => boolean; line: string }> = [
  {
    path: "/api/obs/admission/status",
    unsaved: (b) => typeof b === "object" && b != null && (b as { live_unsaved?: unknown }).live_unsaved === true,
    line: "The admission policy applied on Policies was not saved, so this restart drops it and the saved policy comes back.",
  },
];

/** probeUnsavedLive reads every UNSAVED_LIVE_PROBES route through get and
 *  returns the lines for the ones that report unsaved live state. A route
 *  that fails (AI Apps off, an older daemon) contributes nothing. */
export async function probeUnsavedLive(get: (path: string) => Promise<unknown>): Promise<string[]> {
  const out: string[] = [];
  for (const p of UNSAVED_LIVE_PROBES) {
    try {
      if (p.unsaved(await get(p.path))) out.push(p.line);
    } catch {
      // Not answering: nothing to warn about from this route.
    }
  }
  return out;
}

/** restartConfirmBody returns the dialog's paragraphs: the caller's lead,
 *  any unsaved live change the restart drops, what a restart does, then the
 *  proxy line for the probe outcome (null when the probe was unavailable:
 *  older daemon, read-only surface). */
export function restartConfirmBody(lead: string, status: RestartStatus | null, unsaved: readonly string[] = []): string[] {
  const out = [
    lead,
    ...unsaved,
    "The daemon shuts down gracefully and starts again in place; this page reconnects on its own when the new process answers, typically within a second.",
  ];
  if (status == null) {
    out.push("An active coding session routed through the observer proxy may drop one in-flight request.");
    return out;
  }
  const n = status.proxy_recent_requests ?? 0;
  if (n > 0) {
    out.push(
      `A coding session is routing through this daemon right now (${n} request${n === 1 ? "" : "s"} in the last minute). ` +
        "Restarting drops its in-flight proxy requests.",
    );
    out.push(
      "To avoid that, restart between turns: the new process answers in about a second. " +
        "This restart does not take the proxy route off first. `observer service restart` does " +
        "(route off, restart, route on); run it in a terminal the daemon did not start, because it restarts the daemon from outside it.",
    );
  } else {
    out.push("No proxied requests in the last minute, so no coding session should notice.");
  }
  return out;
}
