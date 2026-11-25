// The SDK's one bounded HTTP request (internal: not exported from index.ts).
//
// admit.ts and control.ts used to each build an AbortController, a timer
// that marks the request timed out and aborts it, a fetch that never
// follows a redirect, and the same reading of a thrown fetch error. They
// share it here. The timer is a separate object because it bounds the body
// read too: a caller keeps it armed until the body is read, asks
// timedOut() when a read fails, and clears it in its own finally.
//
// Discovery (destination.ts) keeps its own re-arming timer and its own
// error text: its window re-arms while the event loop runs late, which this
// fixed timer does not do.

/** One request's abort timer. */
export interface RequestTimer {
  /** The signal to pass to fetch: aborted when the timer fires. */
  readonly signal: AbortSignal;
  /** Whether the timer has fired (the request or its body read was aborted by it). */
  timedOut(): boolean;
  /** Stop the timer (call once the response body has been read). */
  clear(): void;
}

/**
 * Arm a timer that aborts the request after `timeoutMs`. With `unref` the
 * timer does not keep the process alive on its own.
 */
export function startTimer(timeoutMs: number, unref: boolean): RequestTimer {
  const controller = new AbortController();
  let fired = false;
  const timer = setTimeout(() => {
    fired = true;
    controller.abort();
  }, timeoutMs);
  if (unref) timer.unref?.();
  return {
    signal: controller.signal,
    timedOut: () => fired,
    clear: () => clearTimeout(timer),
  };
}

/** What a bounded fetch returned: a response, or the error fetch threw. */
export type BoundedFetch = { resp: Response } | { failed: unknown };

/**
 * fetch `url` under `timer`. A redirect is never followed: the key must not
 * ride to a host it was not sent to (R-B26), so a 3xx comes back as the
 * response. A thrown error is returned (as `failed`), never rethrown; the
 * caller reads `timer.timedOut()` to tell a timeout from a transport error.
 */
export async function fetchBounded(
  url: string,
  init: { method: string; headers: Record<string, string>; body?: string },
  timer: RequestTimer,
): Promise<BoundedFetch> {
  try {
    return { resp: await fetch(url, { method: init.method, headers: init.headers, body: init.body, signal: timer.signal, redirect: "manual" }) };
  } catch (err) {
    return { failed: err };
  }
}

/** The text a transport failure reports: the error's cause code, else its cause message, else the error. */
export function transportDetail(err: unknown): string {
  const cause = (err as { cause?: { code?: string; message?: string } }).cause;
  return cause?.code ?? cause?.message ?? String(err);
}
