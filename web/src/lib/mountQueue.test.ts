import { test } from "node:test";
import assert from "node:assert/strict";
import { createMountQueue, MOUNT_TURN_WATCHDOG_MS } from "../../../shared/lib/mountQueue.ts";

// A manual macrotask clock: tasks run only when the test drains them, so the
// "never two turns in one task" rule is observable.
function fakeTimers() {
  type T = { id: number; at: number; fn: () => void };
  let now = 0;
  let id = 0;
  let q: T[] = [];
  return {
    timers: {
      setTimeout: (fn: () => void, ms: number) => {
        const t = { id: ++id, at: now + ms, fn };
        q.push(t);
        return t.id;
      },
      clearTimeout: (h: unknown) => {
        q = q.filter((t) => t.id !== h);
      },
    },
    /** Run the next due task (the earliest `at`, FIFO within it). */
    step(): boolean {
      if (q.length === 0) return false;
      q.sort((a, b) => a.at - b.at || a.id - b.id);
      const t = q.shift()!;
      now = Math.max(now, t.at);
      t.fn();
      return true;
    },
    advance(ms: number) {
      now += ms;
    },
    size: () => q.length,
  };
}

test("turns are handed out FIFO, one per macrotask, never synchronously", () => {
  const clk = fakeTimers();
  const q = createMountQueue(clk.timers);
  const got: number[] = [];
  const tokens: number[] = [];
  for (let i = 0; i < 3; i++) q.request((t) => (got.push(i), tokens.push(t)));
  assert.deepEqual(got, [], "no turn inside request()");
  clk.step(); // pump
  assert.deepEqual(got, [0]);
  // Holder has not reported done: nothing else is handed out, even if the
  // pump were to run again.
  assert.equal(q.pending(), 2);
  q.done(tokens[0]);
  assert.deepEqual(got, [0], "done() never hands the next turn out synchronously");
  clk.step();
  assert.deepEqual(got, [0, 1]);
  q.done(tokens[1]);
  clk.step();
  assert.deepEqual(got, [0, 1, 2]);
});

test("cancel drops a pending request and releases a held turn", () => {
  const clk = fakeTimers();
  const q = createMountQueue(clk.timers);
  const got: string[] = [];
  const cancelA = q.request(() => got.push("a"));
  const cancelB = q.request(() => got.push("b"));
  q.request(() => got.push("c"));
  cancelB(); // pending: dropped
  clk.step();
  assert.deepEqual(got, ["a"]);
  cancelA(); // holder unmounted before done(): the turn moves on
  clk.step();
  assert.deepEqual(got, ["a", "c"]);
  assert.equal(q.pending(), 0);
});

test("a holder that never reports done is reclaimed by the watchdog", () => {
  const clk = fakeTimers();
  const q = createMountQueue(clk.timers);
  const got: string[] = [];
  q.request(() => got.push("stuck"));
  q.request(() => got.push("next"));
  clk.step(); // pump -> stuck holds the turn
  assert.deepEqual(got, ["stuck"]);
  clk.step(); // watchdog (due at MOUNT_TURN_WATCHDOG_MS)
  clk.step(); // pump
  assert.deepEqual(got, ["stuck", "next"]);
  assert.ok(MOUNT_TURN_WATCHDOG_MS > 0);
});

test("done is idempotent and a stale token cannot release a newer holder", () => {
  const clk = fakeTimers();
  const q = createMountQueue(clk.timers);
  const tokens: number[] = [];
  const got: string[] = [];
  q.request((t) => (tokens.push(t), got.push("a")));
  q.request((t) => (tokens.push(t), got.push("b")));
  q.request((t) => (tokens.push(t), got.push("c")));
  clk.step();
  q.done(tokens[0]);
  q.done(tokens[0]);
  clk.step();
  assert.deepEqual(got, ["a", "b"]);
  q.done(tokens[0]); // stale: b still holds the turn
  assert.equal(clk.size() > 0, true); // b's watchdog only
  clk.advance(1);
  // Only the watchdog is queued; no pump was scheduled by the stale done().
  assert.equal(q.pending(), 1);
  q.done(tokens[1]);
  clk.step();
  assert.deepEqual(got, ["a", "b", "c"]);
});

test("a request made while idle starts a turn on the next task", () => {
  const clk = fakeTimers();
  const q = createMountQueue(clk.timers);
  let tok = 0;
  q.request((t) => (tok = t));
  clk.step();
  q.done(tok);
  // Queue idle; a late request (a panel that resolved later) still waits one task.
  let late = false;
  q.request(() => (late = true));
  assert.equal(late, false);
  while (clk.step()) {
    /* drain */
  }
  assert.equal(late, true);
});
