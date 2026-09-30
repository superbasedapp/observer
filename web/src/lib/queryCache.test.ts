import assert from "node:assert/strict";
import test from "node:test";

import {
  createQueryCache,
  EMPTY_SNAPSHOT,
  firstPollDelay,
  keyBoundFetcher,
  replaceEqualDeep,
  sameValue,
  selectionChanged,
  type QuerySnapshot,
} from "../../../shared/lib/queryCache.ts";
import {
  formatNumeric,
  parseNumeric,
  sameShape,
} from "../../../shared/lib/motion.ts";

// The shared query cache is the client half of the stale-data fix (backlog
// item 1; server half = item 6). These pin the behaviours the dashboards rely
// on: dedup of concurrent requests, one poll timer per key, keep-previous
// payload identity, abort when the last subscriber leaves, and the foreground
// activity count that drives the "updating" bar.

type Deferred<T> = { promise: Promise<T>; resolve: (v: T) => void; reject: (e: unknown) => void };
function deferred<T>(): Deferred<T> {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

// A manual timer queue so polling and deferred aborts are deterministic.
function fakeTimers() {
  let t = 1_000;
  let seq = 0;
  const timers = new Map<number, { at: number; fn: () => void }>();
  return {
    now: () => t,
    setTimer: (fn: () => void, ms: number) => {
      const id = ++seq;
      timers.set(id, { at: t + ms, fn });
      return id;
    },
    clearTimer: (id: unknown) => {
      timers.delete(id as number);
    },
    advance(ms: number) {
      const end = t + ms;
      for (;;) {
        const due = [...timers.entries()]
          .filter(([, v]) => v.at <= end)
          .sort((a, b) => a[1].at - b[1].at)[0];
        if (!due) break;
        timers.delete(due[0]);
        t = due[1].at;
        due[1].fn();
      }
      t = end;
    },
    pending: () => timers.size,
  };
}

const flush = () => new Promise((r) => setTimeout(r, 0));

test("concurrent fetches of one key share a single request", async () => {
  const clock = fakeTimers();
  const cache = createQueryCache({ ...clock, isHidden: () => false });
  let calls = 0;
  const d = deferred<{ n: number }>();
  const fetcher = () => {
    calls++;
    return d.promise;
  };
  const a = cache.fetch("/api/status", fetcher);
  const b = cache.fetch("/api/status", fetcher);
  const c = cache.fetch("/api/status", fetcher, { force: true });
  assert.equal(calls, 1);
  assert.equal(cache.getSnapshot("/api/status").fetching, true);
  d.resolve({ n: 1 });
  await Promise.all([a, b, c]);
  const snap = cache.getSnapshot("/api/status");
  assert.equal(snap.hasData, true);
  assert.deepEqual(snap.data, { n: 1 });
  assert.equal(snap.fetching, false);
});

test("maxAgeMs serves a fresh cached response without a request", async () => {
  const clock = fakeTimers();
  const cache = createQueryCache({ ...clock, isHidden: () => false });
  let calls = 0;
  const fetcher = async () => ({ n: ++calls });
  await cache.fetch("k", fetcher);
  clock.advance(500);
  await cache.fetch("k", fetcher, { maxAgeMs: 1500 });
  assert.equal(calls, 1, "fresh: no refetch");
  clock.advance(2000);
  await cache.fetch("k", fetcher, { maxAgeMs: 1500 });
  assert.equal(calls, 2, "aged out: refetched");
});

test("an identical refetch keeps the previous object (no re-render churn)", async () => {
  const cache = createQueryCache({ ...fakeTimers(), isHidden: () => false });
  await cache.fetch("k", async () => ({ rows: [1, 2] }));
  const first = cache.getSnapshot("k").data;
  await cache.fetch("k", async () => ({ rows: [1, 2] }), { force: true });
  assert.equal(cache.getSnapshot("k").data, first);
  await cache.fetch("k", async () => ({ rows: [1, 2, 3] }), { force: true });
  assert.notEqual(cache.getSnapshot("k").data, first);
});

test("one poll timer per key at the fastest subscriber interval", async () => {
  const clock = fakeTimers();
  const cache = createQueryCache({ ...clock, isHidden: () => false });
  let calls = 0;
  const fetcher = async () => ({ n: ++calls });
  await cache.fetch("k", fetcher);
  const u1 = cache.subscribe("k", () => {}, { refreshMs: 5000 });
  const u2 = cache.subscribe("k", () => {}, { refreshMs: 10000 });
  const u3 = cache.subscribe("k", () => {}, { refreshMs: 5000 });
  assert.equal(clock.pending(), 1, "a single timer for three pollers");
  clock.advance(5000);
  await flush();
  assert.equal(calls, 2, "one request per tick, not three");
  u1();
  u3();
  clock.advance(5000);
  await flush();
  assert.equal(calls, 2, "remaining subscriber polls every 10 s");
  clock.advance(5000);
  await flush();
  assert.equal(calls, 3);
  u2();
});

test("polling pauses while hidden unless a subscriber opts in", async () => {
  const clock = fakeTimers();
  let hidden = true;
  const cache = createQueryCache({ ...clock, isHidden: () => hidden });
  let calls = 0;
  const fetcher = async () => ({ n: ++calls });
  await cache.fetch("k", fetcher);
  const u = cache.subscribe("k", () => {}, { refreshMs: 1000 });
  clock.advance(3000);
  await flush();
  assert.equal(calls, 1);
  hidden = false;
  clock.advance(1000);
  await flush();
  assert.equal(calls, 2);
  u();
});

test("the last unsubscribe aborts an in-flight request and GC drops the key", async () => {
  const clock = fakeTimers();
  const cache = createQueryCache({ ...clock, gcMs: 60_000, isHidden: () => false });
  let aborted = false;
  const fetcher = (signal: AbortSignal) =>
    new Promise<never>((_, reject) => {
      signal.addEventListener("abort", () => {
        aborted = true;
        const e = new Error("aborted");
        e.name = "AbortError";
        reject(e);
      });
    });
  const u = cache.subscribe("k", () => {});
  const p = cache.fetch("k", fetcher);
  u();
  clock.advance(0);
  await p;
  assert.equal(aborted, true);
  const snap = cache.getSnapshot("k");
  assert.equal(snap.fetching, false);
  assert.equal(snap.error, null, "an abort is not an error");
  clock.advance(60_000);
  assert.equal(cache.getSnapshot("k"), EMPTY_SNAPSHOT);
  assert.equal(cache.size(), 0);
});

test("a same-tick re-subscribe keeps the request alive", async () => {
  const clock = fakeTimers();
  const cache = createQueryCache({ ...clock, isHidden: () => false });
  const d = deferred<number>();
  let aborted = false;
  const fetcher = (signal: AbortSignal) => {
    signal.addEventListener("abort", () => (aborted = true));
    return d.promise;
  };
  const u = cache.subscribe("k", () => {});
  void cache.fetch("k", fetcher);
  u();
  const u2 = cache.subscribe("k", () => {});
  clock.advance(0);
  d.resolve(7);
  await flush();
  assert.equal(aborted, false);
  assert.equal(cache.getSnapshot("k").data, 7);
  u2();
});

test("errors are kept with the last data and cleared by the next success", async () => {
  const cache = createQueryCache({ ...fakeTimers(), isHidden: () => false });
  await cache.fetch("k", async () => "ok");
  await cache.fetch("k", async () => Promise.reject(new Error("boom")), { force: true });
  let snap = cache.getSnapshot("k");
  assert.equal(snap.data, "ok");
  assert.ok(snap.error instanceof Error);
  await cache.fetch("k", async () => "ok2", { force: true });
  snap = cache.getSnapshot("k");
  assert.equal(snap.data, "ok2");
  assert.equal(snap.error, null);
});

test("foreground activity counts only foreground requests, upgrade included", async () => {
  const cache = createQueryCache({ ...fakeTimers(), isHidden: () => false });
  const seen: number[] = [];
  cache.subscribeActivity(() => seen.push(cache.getActivity()));
  const d = deferred<number>();
  void cache.fetch("bg", () => d.promise);
  assert.equal(cache.getActivity(), 0, "background poll does not count");
  void cache.fetch("bg", () => d.promise, { foreground: true });
  assert.equal(cache.getActivity(), 1, "joining request upgraded to foreground");
  d.resolve(1);
  await flush();
  assert.equal(cache.getActivity(), 0);
  assert.deepEqual(seen, [1, 0]);
});

test("refetchActive refetches only subscribed keys", async () => {
  const cache = createQueryCache({ ...fakeTimers(), isHidden: () => false });
  let a = 0;
  let b = 0;
  await cache.fetch("a", async () => ++a);
  await cache.fetch("b", async () => ++b);
  const u = cache.subscribe("a", () => {});
  cache.refetchActive();
  await flush();
  assert.equal(a, 2);
  assert.equal(b, 1);
  u();
});

test("a key's stored fetcher keeps requesting that key after its hook moves on", async () => {
  // Mirrors useQuery: one mutable {key, fetcher} per hook, one bound fetcher
  // per key. Another reader keeps key "a" subscribed after the hook moved to
  // "b" and then to null; a refetch of "a" must still request "a" (it used
  // to request the hook's CURRENT key - "/null" once the key was null).
  const cache = createQueryCache({ ...fakeTimers(), isHidden: () => false });
  const requested: string[] = [];
  const fetcherFor = (k: string | null) => async () => {
    requested.push(String(k));
    return `data:${k}`;
  };
  const live = { key: "a" as string | null, fetcher: fetcherFor("a") };
  await cache.fetch("a", keyBoundFetcher("a", fetcherFor("a"), live));
  const other = cache.subscribe("a", () => {});

  live.key = "b";
  live.fetcher = fetcherFor("b");
  await cache.fetch("b", keyBoundFetcher("b", fetcherFor("b"), live));
  live.key = null;
  live.fetcher = fetcherFor(null);

  cache.refetchActive();
  await flush();
  assert.deepEqual(requested, ["a", "b", "a"]);
  assert.equal(cache.getSnapshot("a").data, "data:a");

  // While the hook still reads the key, its LATEST fetcher is used.
  live.key = "a";
  live.fetcher = async () => {
    requested.push("a-fresh");
    return "data:a-fresh";
  };
  cache.refetchActive();
  await flush();
  assert.equal(requested.at(-1), "a-fresh");
  other();
});

test("replaceEqualDeep keeps every unchanged subtree's identity", () => {
  const prev = {
    total: 3,
    rows: [
      { id: "a", n: 1, tags: ["x"] },
      { id: "b", n: 2, tags: [] },
      { id: "c", n: 3, tags: ["y", "z"] },
    ],
    meta: { page: 1 },
  };
  // Identical payload: the whole previous object comes back.
  const same = JSON.parse(JSON.stringify(prev));
  assert.equal(replaceEqualDeep(prev, same), prev);
  // Key order does not matter.
  assert.equal(replaceEqualDeep(prev.meta, { page: 1 }), prev.meta);
  // One row changed: new root and rows array, but the other rows, the
  // unchanged nested array and the untouched sibling keep identity.
  const next = JSON.parse(JSON.stringify(prev));
  next.rows[1].n = 20;
  const out = replaceEqualDeep(prev, next);
  assert.notEqual(out, prev);
  assert.deepEqual(out, next);
  assert.notEqual(out.rows, prev.rows);
  assert.equal(out.rows[0], prev.rows[0]);
  assert.notEqual(out.rows[1], prev.rows[1]);
  assert.equal(out.rows[1].tags, prev.rows[1].tags);
  assert.equal(out.rows[2], prev.rows[2]);
  assert.equal(out.meta, prev.meta);
  // Added / removed keys and array length changes are changes.
  assert.notEqual(replaceEqualDeep({ a: 1 }, { a: 1, b: 2 }), undefined);
  const grown = replaceEqualDeep([1, 2], [1, 2, 3]);
  assert.deepEqual(grown, [1, 2, 3]);
  const shrunk = { a: 1, b: 2 };
  assert.deepEqual(replaceEqualDeep(shrunk, { a: 1 }), { a: 1 });
  assert.notEqual(replaceEqualDeep(shrunk, { a: 1 }), shrunk);
  // Type changes and primitives.
  assert.deepEqual(replaceEqualDeep([1], { 0: 1 }), { 0: 1 });
  assert.equal(replaceEqualDeep("x", "x"), "x");
  assert.equal(replaceEqualDeep(null, null), null);
  assert.deepEqual(replaceEqualDeep(null, { a: 1 }), { a: 1 });
  // A JSON "__proto__" key stays an own data property.
  const hostile = JSON.parse('{"__proto__": {"polluted": true}, "k": 1}');
  const merged = replaceEqualDeep({ k: 2 }, hostile) as Record<string, unknown>;
  assert.equal(Object.getPrototypeOf(merged), Object.prototype);
  assert.ok(Object.prototype.hasOwnProperty.call(merged, "__proto__"));
  assert.equal(({} as Record<string, unknown>).polluted, undefined);
});

test("sameValue is deep equality over JSON values", () => {
  assert.equal(sameValue({ a: [1, { b: 2 }] }, { a: [1, { b: 2 }] }), true);
  assert.equal(sameValue({ a: [1, { b: 2 }] }, { a: [1, { b: 3 }] }), false);
  assert.equal(sameValue([1, 2], [2, 1]), false);
  assert.equal(sameValue(null, undefined), false);
  assert.equal(sameValue(0, 0), true);
});

test("a changed poll keeps unchanged rows' identity in the cache", async () => {
  const cache = createQueryCache({ ...fakeTimers(), isHidden: () => false });
  await cache.fetch("k", async () => ({ rows: [{ id: 1 }, { id: 2 }] }));
  const first = cache.getSnapshot("k").data as { rows: { id: number }[] };
  await cache.fetch("k", async () => ({ rows: [{ id: 1 }, { id: 2, x: 1 }] }), { force: true });
  const second = cache.getSnapshot("k").data as { rows: { id: number }[] };
  assert.notEqual(second, first);
  assert.equal(second.rows[0], first.rows[0]);
  assert.notEqual(second.rows[1], first.rows[1]);
});

test("firstPollDelay: a resumed poll revalidates overdue data at once", () => {
  assert.equal(firstPollDelay(5000, false, 0, 10_000), 5000, "no data: plain interval");
  assert.equal(firstPollDelay(5000, true, 10_000, 10_000), 5000, "fresh data: full interval");
  assert.equal(firstPollDelay(5000, true, 8_000, 10_000), 3000, "partly aged: the remainder");
  assert.equal(firstPollDelay(30_000, true, 0, 120_000), 0, "overdue: now");
  assert.equal(firstPollDelay(5000, true, 20_000, 10_000), 5000, "clock went back: plain interval");
});

test("the next poll is armed when the previous poll settles", async () => {
  const clock = fakeTimers();
  const cache = createQueryCache({ ...clock, isHidden: () => false });
  let calls = 0;
  let pending: Deferred<number> | null = null;
  const fetcher = () => {
    calls++;
    pending = deferred<number>();
    return pending.promise;
  };
  const first = deferred<number>();
  void cache.fetch("k", () => first.promise);
  first.resolve(0);
  await flush();
  const u = cache.subscribe("k", () => {}, { refreshMs: 5000 });
  // Store the poll fetcher (a mount fetch would do this in useQuery).
  cache.getSnapshot("k");
  void cache.fetch("k", fetcher, { force: true });
  pending!.resolve(1);
  await flush();
  assert.equal(calls, 1);
  clock.advance(5000);
  await flush();
  assert.equal(calls, 2, "first poll");
  // The poll takes 12 s: no timer runs meanwhile, so no tick joins it.
  assert.equal(clock.pending(), 0, "no timer while the poll is in flight");
  clock.advance(12_000);
  await flush();
  assert.equal(calls, 2);
  pending!.resolve(2);
  await flush();
  assert.equal(clock.pending(), 1, "re-armed once the poll settled");
  clock.advance(4999);
  await flush();
  assert.equal(calls, 2, "a full quiet interval after it settled");
  clock.advance(1);
  await flush();
  assert.equal(calls, 3);
  u();
});

test("pausing and resuming a poll does not stack timers and revalidates overdue data", async () => {
  const clock = fakeTimers();
  const cache = createQueryCache({ ...clock, isHidden: () => false });
  let calls = 0;
  const fetcher = async () => ++calls;
  await cache.fetch("k", fetcher);
  let u = cache.subscribe("k", () => {}, { refreshMs: 30_000 });
  assert.equal(clock.pending(), 1);
  // Pause (a covering panel opens): the reader re-subscribes with no poll.
  u();
  u = cache.subscribe("k", () => {}, { refreshMs: 0 });
  clock.advance(0); // the deferred abort check
  assert.equal(clock.pending(), 0, "no poll timer while paused");
  clock.advance(120_000);
  await flush();
  assert.equal(calls, 1);
  // Resume: the data is two minutes old, so the first poll is immediate.
  u();
  u = cache.subscribe("k", () => {}, { refreshMs: 30_000 });
  clock.advance(0);
  await flush();
  assert.equal(calls, 2, "overdue data revalidated on resume");
  assert.equal(clock.pending(), 1, "exactly one timer afterwards");
  u();
});

test("selectionChanged: only a visible change re-renders a selecting reader", () => {
  const base: QuerySnapshot = {
    data: { uptime: 1, counts: { projects: 4 } },
    hasData: true,
    error: null,
    updatedAt: 1,
    fetching: false,
  };
  const select = (d: { uptime: number; counts: { projects: number } }) => d.counts.projects;
  const shown = { has: true, value: 4 };
  // The poll starts (fetching flips): invisible.
  assert.equal(selectionChanged(base, { ...base, fetching: true }, select, shown), false);
  // The poll lands with a new uptime but the same count: invisible.
  const moved = { ...base, data: { uptime: 2, counts: { projects: 4 } }, updatedAt: 2 };
  assert.equal(selectionChanged(base, moved, select, shown), false);
  // The count changed: visible.
  const grew = { ...base, data: { uptime: 3, counts: { projects: 5 } } };
  assert.equal(selectionChanged(base, grew, select, shown), true);
  // An error appears or clears: visible.
  const failed = { ...base, error: new Error("x") };
  assert.equal(selectionChanged(base, failed, select, shown), true);
  assert.equal(selectionChanged(failed, base, select, shown), true);
  // While an error is on screen, a retry starting is visible (callers hide
  // the error during a retry).
  assert.equal(selectionChanged(failed, { ...failed, fetching: true }, select, shown), true);
  // No data yet / data arriving: visible.
  assert.equal(selectionChanged(EMPTY_SNAPSHOT, base, select, { has: false, value: undefined }), true);
  // Same snapshot: nothing.
  assert.equal(selectionChanged(base, base, select, shown), false);
  // Structured slices compare by value.
  const pick = (d: { uptime: number; counts: { projects: number } }) => ({ p: d.counts.projects });
  assert.equal(selectionChanged(base, moved, pick, { has: true, value: { p: 4 } }), false);
});

test("parseNumeric / formatNumeric round-trip display strings", () => {
  const cases: [string, string | null][] = [
    ["$6,073.08", "$6,073.08"],
    ["1.2M", "1.2M"],
    ["42%", "42%"],
    ["+12.5%", "+12.5%"],
    ["1,204", "1,204"],
    ["0", "0"],
    ["3h 12m", null],
    ["2026-09-27", null],
    ["abc", null],
    ["v1.33.0", null],
  ];
  for (const [input, want] of cases) {
    const p = parseNumeric(input);
    if (want === null) {
      assert.equal(p, null, input);
      continue;
    }
    assert.ok(p, input);
    assert.equal(formatNumeric(p!, p!.value), want, input);
  }
  const a = parseNumeric("$999.00")!;
  const b = parseNumeric("$1,000.00")!;
  assert.equal(sameShape(a, b), true, "grouping may differ");
  assert.equal(formatNumeric(b, 999.5), "$999.50");
  assert.equal(sameShape(parseNumeric("12 KB")!, parseNumeric("1.2 MB")!), false);
});
