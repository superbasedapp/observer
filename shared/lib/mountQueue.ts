// mountQueue: hand out first-mount "turns" one at a time, one per macrotask
// (perf re-measure 2026-09-30, lane PERF2).
//
// Why: with the dashboard's stale-while-revalidate response cache, a page's
// panels resolve together, and every chart's FIRST mount (recharts computes
// its axes, measures tick text with getBBox, creates every <rect>/<path>) ran
// in one synchronous React render + commit. Analysis mounted ~10 charts in one
// 0.4-1.2 s task, freezing input. Each first mount is cheap on its own; the
// queue makes them take turns so the browser can handle input (and paint)
// between charts. Updates to an already-mounted chart never queue.
//
// Protocol, per consumer:
//   const cancel = q.request(onTurn)   // wait for a turn (FIFO)
//   ...onTurn() fires in its own macrotask; the consumer renders its content
//   q.done(token)                      // after that render committed
// The next turn is handed out in a LATER macrotask than the done() call, so
// two turns never share a task. A turn whose holder never reports done (its
// render was discarded, it unmounted mid-turn) is reclaimed after
// `watchdogMs`, so the queue can never wedge.
//
// Pure: no React, no DOM. The macrotask scheduler and timers are injected so
// the ordering rules are unit-tested (web/src/lib/mountQueue.test.ts).

/** Injected timer seam (setTimeout / clearTimeout in the browser). */
export type MountQueueTimers = {
  setTimeout: (fn: () => void, ms: number) => unknown;
  clearTimeout: (handle: unknown) => void;
};

export type MountQueue = {
  /**
   * Ask for a turn. `onTurn` is called (from a macrotask, never
   * synchronously) when this consumer may render. Returns a cancel function:
   * call it on unmount; it drops a pending request, or releases the turn if
   * this consumer holds it and has not called done().
   */
  request: (onTurn: (token: number) => void) => () => void;
  /** Report that the turn `token` rendered and committed. Idempotent. */
  done: (token: number) => void;
  /** Pending requests (not counting the one holding the turn). Tests only. */
  pending: () => number;
};

/** A turn not reported done within this many ms is reclaimed. */
export const MOUNT_TURN_WATCHDOG_MS = 250;

export function createMountQueue(
  timers: MountQueueTimers,
  watchdogMs: number = MOUNT_TURN_WATCHDOG_MS,
): MountQueue {
  type Req = { token: number; onTurn: (token: number) => void };
  const waiting: Req[] = [];
  let seq = 0;
  // The token holding the turn (0 = none), its watchdog, and whether a pump
  // macrotask is already scheduled.
  let holder = 0;
  let watchdog: unknown = null;
  let pumpScheduled = false;

  const schedulePump = () => {
    if (pumpScheduled) return;
    pumpScheduled = true;
    timers.setTimeout(pump, 0);
  };

  const release = (token: number) => {
    if (holder !== token || token === 0) return;
    holder = 0;
    if (watchdog != null) {
      timers.clearTimeout(watchdog);
      watchdog = null;
    }
    if (waiting.length > 0) schedulePump();
  };

  function pump() {
    pumpScheduled = false;
    if (holder !== 0) return;
    const next = waiting.shift();
    if (!next) return;
    holder = next.token;
    const token = next.token;
    watchdog = timers.setTimeout(() => {
      watchdog = null;
      release(token);
    }, watchdogMs);
    next.onTurn(token);
  }

  return {
    request(onTurn) {
      const token = ++seq;
      waiting.push({ token, onTurn });
      if (holder === 0) schedulePump();
      return () => {
        const i = waiting.findIndex((r) => r.token === token);
        if (i >= 0) waiting.splice(i, 1);
        else release(token);
      };
    },
    done(token) {
      release(token);
    },
    pending: () => waiting.length,
  };
}
