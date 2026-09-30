// Shared client data layer: a tiny keyed query cache.
//
// One instance per app (web/, web2/, webcloud/ each create their own). It
// owns every in-flight GET and every last-known response, keyed by a string
// the app derives from the request (path + params). What it gives the apps:
//
//   - request dedup: N components asking for the same key while a request is
//     in flight share ONE request (was 3-4 identical /api/status per tick);
//   - one poll timer per key at the fastest interval any subscriber asked
//     for, instead of one timer per component; the next poll is armed when
//     the previous one settles, so a slow endpoint is never permanently in
//     flight, and a resumed poll revalidates overdue data at once;
//   - structural sharing: a response keeps the previous response's objects
//     for every subtree that did not change (replaceEqualDeep), so an
//     unchanged row keeps its identity and memoized readers skip it;
//   - stale-while-revalidate across mounts: navigating back to a page paints
//     the last response immediately and revalidates in the background;
//   - an activity count of FOREGROUND fetches (a key with nothing to show, or
//     a revalidation the user is waiting on) that drives the global
//     "updating" bar - background polls never flash it.
//
// Pure TypeScript: no React, no fetch, no DOM at import time. The fetcher is
// injected per call, so the cache knows nothing about any API. The React
// binding is shared/lib/useQuery.ts. Tests: web/src/lib/queryCache.test.ts.

/** A fetcher performs the request; it must honour the abort signal. */
export type Fetcher<T> = (signal: AbortSignal) => Promise<T>;

/**
 * keyBoundFetcher builds the fetcher a cache entry keeps for `key`.
 *
 * The cache stores one fetcher per entry and re-runs it for polls, refetches
 * and other readers of the same key - long after the component that supplied
 * it may have moved on to another key. A hook that simply read "my latest
 * fetcher" through a ref would then answer key K's poll with the request for
 * its NEW key: the new URL's response cached under K, or a literal "/null"
 * request once the hook's key became null (seen on the node Sessions page).
 *
 * `live` is the hook's mutable current {key, fetcher}. While the hook still
 * reads `key`, its latest fetcher is used (fresh closures for the same key);
 * once it has moved on, the fetcher captured for `key` is used instead.
 */
export function keyBoundFetcher<T>(
  key: string,
  fetcher: Fetcher<T>,
  live: { key: string | null; fetcher: Fetcher<T> },
): Fetcher<T> {
  return (signal) => (live.key === key ? live.fetcher : fetcher)(signal);
}

/** Immutable per-key snapshot. A new object on every change, else the same. */
export type QuerySnapshot<T = unknown> = {
  /** Last successful response (undefined until one lands). */
  data: T | undefined;
  hasData: boolean;
  /** Last failure; cleared by the next success. */
  error: unknown;
  /** Epoch ms of the last successful response (0 = never). */
  updatedAt: number;
  /** A request for this key is in flight. */
  fetching: boolean;
};

export type SubscribeOptions = {
  /** Poll every N ms while subscribed (<=0: no polling). */
  refreshMs?: number;
  /** Keep polling while the document is hidden (default false). */
  refreshWhenHidden?: boolean;
};

export type FetchOptions = {
  /** Refetch even when a fresh response exists. */
  force?: boolean;
  /** Skip the request when the cached response is younger than this. */
  maxAgeMs?: number;
  /** Count this request in the foreground activity (the global bar). */
  foreground?: boolean;
};

export type QueryCacheOptions = {
  /** Keep an unsubscribed entry this long before dropping it (default 5 min). */
  gcMs?: number;
  /** Upper bound on retained entries (default 300). */
  maxEntries?: number;
  /** Clock + timer + visibility seams for tests. */
  now?: () => number;
  setTimer?: (fn: () => void, ms: number) => unknown;
  clearTimer?: (id: unknown) => void;
  isHidden?: () => boolean;
};

type Sub = {
  listener: () => void;
  refreshMs: number;
  refreshWhenHidden: boolean;
};

type Entry = {
  snap: QuerySnapshot;
  subs: Set<Sub>;
  fetcher: Fetcher<unknown> | null;
  inflight: { promise: Promise<void>; ac: AbortController; foreground: boolean } | null;
  pollTimer: unknown;
  /** The poll request the next timer waits on (see armPoll), or null. */
  pollWait: Promise<void> | null;
  pollMs: number;
  gcTimer: unknown;
  lastUsed: number;
};

const EMPTY: QuerySnapshot = Object.freeze({
  data: undefined,
  hasData: false,
  error: null,
  updatedAt: 0,
  fetching: false,
}) as QuerySnapshot;

/** The snapshot of a key nobody has asked for yet. Stable identity. */
export const EMPTY_SNAPSHOT = EMPTY;

function isAbort(err: unknown): boolean {
  return (
    typeof err === "object" &&
    err !== null &&
    "name" in err &&
    (err as { name?: unknown }).name === "AbortError"
  );
}

// replaceEqualDeep is structural sharing: it returns `next`, except that every
// subtree deep-equal to the matching subtree of `prev` is replaced by the
// `prev` object itself. A poll with no change therefore keeps the previous
// response object (so it re-renders nothing), and a poll where ONE row
// changed keeps every other row's identity, so memoized rows, cells and
// selectors below the page skip their work. The API payloads are plain JSON
// (objects, arrays, primitives; no cycles). Key order is ignored: two objects
// with the same keys and equal values are equal.
export function replaceEqualDeep<T>(prev: unknown, next: T): T {
  if (prev === next) return prev as T;
  if (Array.isArray(prev) && Array.isArray(next)) {
    let equal = prev.length === next.length;
    const out: unknown[] = new Array(next.length);
    for (let i = 0; i < next.length; i++) {
      const v = i < prev.length ? replaceEqualDeep(prev[i], next[i]) : next[i];
      out[i] = v;
      if (v !== prev[i]) equal = false;
    }
    return (equal ? prev : out) as T;
  }
  if (isPlainObject(prev) && isPlainObject(next)) {
    const nextKeys = Object.keys(next);
    let equal = nextKeys.length === Object.keys(prev).length;
    const out: Record<string, unknown> = {};
    for (const k of nextKeys) {
      const had = Object.prototype.hasOwnProperty.call(prev, k);
      const v = had ? replaceEqualDeep(prev[k], next[k]) : next[k];
      // defineProperty, not assignment: a JSON key named "__proto__" must
      // stay an own data property, never become the prototype.
      Object.defineProperty(out, k, { value: v, enumerable: true, writable: true, configurable: true });
      if (!had || v !== prev[k]) equal = false;
    }
    return (equal ? prev : out) as T;
  }
  return next;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  if (typeof v !== "object" || v === null) return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

/** sameValue: deep equality over plain JSON values (see replaceEqualDeep). */
export function sameValue(a: unknown, b: unknown): boolean {
  return replaceEqualDeep(a, b) === a;
}

/**
 * firstPollDelay is how long to wait before the first poll of a (re)armed
 * timer: the time until the cached response is `pollMs` old, so a poll that
 * resumes after a pause (a reader re-mounts, a hidden panel closes, a slower
 * interval speeds up) revalidates data that is already overdue at once
 * instead of showing it for another full interval. Without data, or with a
 * clock that went backwards, it is the plain interval.
 */
export function firstPollDelay(pollMs: number, hasData: boolean, updatedAt: number, now: number): number {
  if (!hasData) return pollMs;
  const age = now - updatedAt;
  if (!(age >= 0)) return pollMs;
  return Math.max(0, Math.min(pollMs, pollMs - age));
}

/**
 * selectionChanged decides whether a cache change is visible to a reader that
 * passed `select`: whether there is data, the error, the fetching flag while
 * an error is on screen, and the selected slice by value. Pure; exported for
 * tests.
 */
export function selectionChanged<T, S>(
  rendered: QuerySnapshot,
  next: QuerySnapshot,
  select: (data: T) => S,
  selected: { has: boolean; value: unknown },
): boolean {
  if (rendered === next) return false;
  if (rendered.hasData !== next.hasData || !next.hasData) return true;
  if (rendered.error !== next.error) return true;
  if (next.error != null && rendered.fetching !== next.fetching) return true;
  if (rendered.data === next.data) return false;
  if (!selected.has) return true;
  return !sameValue(selected.value, select(next.data as T));
}

export type QueryCache = ReturnType<typeof createQueryCache>;

export function createQueryCache(opts: QueryCacheOptions = {}) {
  const gcMs = opts.gcMs ?? 5 * 60_000;
  const maxEntries = opts.maxEntries ?? 300;
  const now = opts.now ?? (() => Date.now());
  const setTimer =
    opts.setTimer ?? ((fn: () => void, ms: number) => setTimeout(fn, ms) as unknown);
  const clearTimer =
    opts.clearTimer ?? ((id: unknown) => clearTimeout(id as ReturnType<typeof setTimeout>));
  const isHidden =
    opts.isHidden ??
    (() => typeof document !== "undefined" && document.visibilityState === "hidden");

  const entries = new Map<string, Entry>();
  const activityListeners = new Set<() => void>();
  let foregroundInflight = 0;

  function entry(key: string): Entry {
    let e = entries.get(key);
    if (!e) {
      e = {
        snap: EMPTY,
        subs: new Set(),
        fetcher: null,
        inflight: null,
        pollTimer: null,
        pollWait: null,
        pollMs: 0,
        gcTimer: null,
        lastUsed: now(),
      };
      entries.set(key, e);
      evictOverflow();
    }
    return e;
  }

  function setSnap(e: Entry, patch: Partial<QuerySnapshot>) {
    e.snap = { ...e.snap, ...patch };
    for (const s of Array.from(e.subs)) s.listener();
  }

  // Listeners hear only the idle <-> busy TRANSITIONS, not every request:
  // the progress bar needs a boolean, and a notification per fetch start and
  // end re-rendered its host once per request (measured: +1.3 s to the node
  // Overview's first data under 4x CPU throttling).
  function setForeground(delta: number) {
    const wasBusy = foregroundInflight > 0;
    foregroundInflight = Math.max(0, foregroundInflight + delta);
    if (wasBusy === foregroundInflight > 0) return;
    for (const l of Array.from(activityListeners)) l();
  }

  function evictOverflow() {
    if (entries.size <= maxEntries) return;
    // Drop the least-recently-used entries nobody is subscribed to.
    const idle = Array.from(entries.entries())
      .filter(([, e]) => e.subs.size === 0 && !e.inflight)
      .sort((a, b) => a[1].lastUsed - b[1].lastUsed);
    for (const [k, e] of idle) {
      if (entries.size <= maxEntries) break;
      if (e.gcTimer != null) clearTimer(e.gcTimer);
      entries.delete(k);
    }
  }

  function reschedulePoll(e: Entry) {
    let ms = 0;
    for (const s of e.subs) {
      if (s.refreshMs > 0 && (ms === 0 || s.refreshMs < ms)) ms = s.refreshMs;
    }
    if (ms === e.pollMs && (ms === 0 || e.pollTimer != null || e.pollWait != null)) return;
    if (e.pollTimer != null) clearTimer(e.pollTimer);
    e.pollTimer = null;
    e.pollWait = null;
    e.pollMs = ms;
    if (ms > 0) armPoll(e, firstPollDelay(ms, e.snap.hasData, e.snap.updatedAt, now()));
  }

  // The next poll is armed when the previous poll's request SETTLES, not on
  // a fixed clock: an endpoint that takes longer than its interval (the node
  // /api/sessions on a large database) used to be permanently in flight,
  // each tick joining the request still running. Now there is always a
  // full, quiet interval between the end of one poll and the next.
  function armPoll(e: Entry, delay: number = e.pollMs) {
    e.pollTimer = setTimer(() => {
      e.pollTimer = null;
      if (e.pollMs <= 0 || e.subs.size === 0) return;
      const wantsHidden = Array.from(e.subs).some((s) => s.refreshWhenHidden);
      if (e.fetcher && (wantsHidden || !isHidden())) {
        const wait = run(e, e.fetcher, false);
        e.pollWait = wait;
        void wait.then(() => {
          // Superseded by a reschedule (interval change, last reader left).
          if (e.pollWait !== wait) return;
          e.pollWait = null;
          if (e.pollMs > 0 && e.subs.size > 0 && e.pollTimer == null) armPoll(e);
        });
        return;
      }
      armPoll(e);
    }, delay);
  }

  function run(e: Entry, fetcher: Fetcher<unknown>, foreground: boolean): Promise<void> {
    if (e.inflight) {
      // Upgrade a background request the user is now waiting on.
      if (foreground && !e.inflight.foreground) {
        e.inflight.foreground = true;
        setForeground(1);
      }
      return e.inflight.promise;
    }
    const ac = new AbortController();
    const flight = { promise: Promise.resolve(), ac, foreground };
    e.inflight = flight;
    if (foreground) setForeground(1);
    if (e.snap.hasData || e.snap.error != null) {
      setSnap(e, { fetching: true });
    } else {
      // Nothing on screen yet: the reader already renders "loading", so the
      // flag flip changes nothing visible. Update the snapshot silently and
      // spare every reader a re-render per request start.
      e.snap = { ...e.snap, fetching: true };
    }
    flight.promise = fetcher(ac.signal).then(
      (value) => {
        if (e.inflight !== flight) return;
        e.inflight = null;
        if (flight.foreground) setForeground(-1);
        const data = e.snap.hasData ? replaceEqualDeep(e.snap.data, value) : value;
        setSnap(e, { data, hasData: true, error: null, updatedAt: now(), fetching: false });
      },
      (err: unknown) => {
        if (e.inflight !== flight) return;
        e.inflight = null;
        if (flight.foreground) setForeground(-1);
        if (isAbort(err) || ac.signal.aborted) {
          setSnap(e, { fetching: false });
          return;
        }
        setSnap(e, { error: err, fetching: false });
      },
    );
    return flight.promise;
  }

  return {
    /** Current snapshot for `key` (EMPTY_SNAPSHOT when unknown). */
    getSnapshot(key: string): QuerySnapshot {
      return entries.get(key)?.snap ?? EMPTY;
    },

    /**
     * fetch requests `key` through `fetcher`, joining an in-flight request
     * for the same key. With maxAgeMs, a younger cached response is kept and
     * no request is made (unless force).
     */
    fetch<T>(key: string, fetcher: Fetcher<T>, o: FetchOptions = {}): Promise<void> {
      const e = entry(key);
      e.lastUsed = now();
      e.fetcher = fetcher as Fetcher<unknown>;
      if (
        !o.force &&
        o.maxAgeMs != null &&
        e.snap.hasData &&
        now() - e.snap.updatedAt < o.maxAgeMs
      ) {
        return e.inflight?.promise ?? Promise.resolve();
      }
      return run(e, e.fetcher, o.foreground ?? false);
    },

    /**
     * subscribe registers interest in `key`: the listener fires on every
     * snapshot change, and the key polls at the fastest refreshMs of its
     * subscribers. Returns the unsubscribe. When the last subscriber leaves,
     * an in-flight request is aborted (on the next tick, so a same-render
     * re-subscribe keeps it) and the entry is dropped after gcMs.
     */
    subscribe(key: string, listener: () => void, o: SubscribeOptions = {}): () => void {
      const e = entry(key);
      e.lastUsed = now();
      if (e.gcTimer != null) {
        clearTimer(e.gcTimer);
        e.gcTimer = null;
      }
      const sub: Sub = {
        listener,
        refreshMs: o.refreshMs ?? 0,
        refreshWhenHidden: o.refreshWhenHidden ?? false,
      };
      e.subs.add(sub);
      reschedulePoll(e);
      return () => {
        e.subs.delete(sub);
        e.lastUsed = now();
        reschedulePoll(e);
        if (e.subs.size > 0) return;
        setTimer(() => {
          if (e.subs.size > 0) return;
          if (e.inflight) e.inflight.ac.abort();
        }, 0);
        e.gcTimer = setTimer(() => {
          if (e.subs.size === 0 && entries.get(key) === e) entries.delete(key);
        }, gcMs);
      };
    },

    /** Refetch every key that currently has subscribers (a Refresh button). */
    refetchActive(): void {
      for (const e of entries.values()) {
        if (e.subs.size > 0 && e.fetcher) void run(e, e.fetcher, true);
      }
    },

    /** Drop a key's cached response (e.g. after a mutation). */
    invalidate(key: string): void {
      const e = entries.get(key);
      if (!e) return;
      if (e.subs.size > 0 && e.fetcher) {
        void run(e, e.fetcher, true);
      } else {
        entries.delete(key);
      }
    },

    /** Number of foreground requests in flight (drives the updating bar).
     *  Activity listeners fire only when this crosses zero. */
    getActivity(): number {
      return foregroundInflight;
    },

    subscribeActivity(listener: () => void): () => void {
      activityListeners.add(listener);
      return () => {
        activityListeners.delete(listener);
      };
    },

    /** Test/diagnostic view of how many keys are retained. */
    size(): number {
      return entries.size;
    },
  };
}
