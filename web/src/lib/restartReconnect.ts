// restartReconnect: the reconnect wait after a daemon restart (UI review
// U-22). useDaemonRestart used to wait on the shared /api/status poller,
// which arms its next poll only when the previous request settles: a request
// left hanging on the dying process, or a run of connection-refused errors,
// could leave the "Restarting the daemon" overlay up after the new process
// already answered other calls. This loop owns its own requests instead:
// each attempt has its own timeout, every failure is retried, and the gap
// between attempts grows along a bounded ladder, until the new process's
// started_at appears.

/** RECONNECT_BACKOFF_MS is the gap before each attempt; the last value
 *  repeats, so the wait never grows past it. */
export const RECONNECT_BACKOFF_MS: readonly number[] = [300, 500, 1000, 1500, 2000, 3000];

/** RECONNECT_ATTEMPT_TIMEOUT_MS abandons one status request that does not
 *  answer, so a connection held by the old process cannot stall the loop. */
export const RECONNECT_ATTEMPT_TIMEOUT_MS = 2500;

/** StatusProbe reads the daemon's start time; it rejects or returns null
 *  while the daemon is not answering. */
export type StatusProbe = (signal: AbortSignal) => Promise<{ started_at?: string } | null>;

export type ReconnectDeps = {
  probe: StatusProbe;
  sleep: (ms: number) => Promise<void>;
  /** The loop stops (and resolves false) once this is aborted. */
  signal?: AbortSignal;
  attemptTimeoutMs?: number;
  backoffMs?: readonly number[];
};

/** isNewProcess reports whether a status started_at belongs to the process
 *  that replaced the one restarted. With the old process's own started_at
 *  known, any other value is new (no clock comparison, so a daemon whose
 *  clock differs from the browser's still counts); otherwise the start must
 *  be later than the moment the restart was asked for. */
export function isNewProcess(startedAt: string | undefined, before: string | null, restartAtMs: number): boolean {
  if (!startedAt) return false;
  if (before) return startedAt !== before;
  const t = new Date(startedAt).getTime();
  return Number.isFinite(t) && t > restartAtMs;
}

/** backoffFor returns the gap before attempt n (0-based). */
export function backoffFor(n: number, ladder: readonly number[] = RECONNECT_BACKOFF_MS): number {
  return ladder[Math.min(n, ladder.length - 1)];
}

/** waitForNewProcess retries the probe until isNew accepts a started_at,
 *  then resolves true. Every error, null answer, timeout or old started_at
 *  is retried after the next backoff step. Resolves false only when
 *  deps.signal is aborted (the caller went away). */
export async function waitForNewProcess(isNew: (startedAt: string | undefined) => boolean, deps: ReconnectDeps): Promise<boolean> {
  const timeoutMs = deps.attemptTimeoutMs ?? RECONNECT_ATTEMPT_TIMEOUT_MS;
  const ladder = deps.backoffMs ?? RECONNECT_BACKOFF_MS;
  for (let n = 0; ; n++) {
    if (deps.signal?.aborted) return false;
    await deps.sleep(backoffFor(n, ladder));
    if (deps.signal?.aborted) return false;
    const ac = new AbortController();
    const onAbort = () => ac.abort();
    deps.signal?.addEventListener("abort", onAbort);
    const timer = setTimeout(() => ac.abort(), timeoutMs);
    try {
      const st = await Promise.race([
        deps.probe(ac.signal),
        new Promise<null>((resolve) => ac.signal.addEventListener("abort", () => resolve(null))),
      ]);
      if (st && isNew(st.started_at)) return true;
    } catch {
      // Connection refused, a proxy error, an HTML page from a half-started
      // server: all mean "not back yet".
    } finally {
      clearTimeout(timer);
      deps.signal?.removeEventListener("abort", onAbort);
    }
  }
}
