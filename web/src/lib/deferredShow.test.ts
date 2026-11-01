// Pins shared/lib/deferredShow.ts, the timing rules behind useDeferredShow
// (D-665..D-669): 300 ms delay, 600 ms minimum once shown, the honest slow
// line after 8 s, and a failure stops the loader. Driven by a fake clock.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createDeferredShow, type DeferredShowView } from "../../../shared/lib/deferredShow.ts";

function harness() {
  let now = 0;
  let seq = 0;
  const timers = new Map<number, { at: number; fn: () => void }>();
  const clock = {
    now: () => now,
    setTimeout: (fn: () => void, ms: number) => {
      const id = ++seq;
      timers.set(id, { at: now + ms, fn });
      return id;
    },
    clearTimeout: (h: unknown) => {
      timers.delete(h as number);
    },
  };
  const views: DeferredShowView[] = [];
  const ctl = createDeferredShow({}, (v) => views.push(v), clock);
  const advance = (to: number) => {
    for (;;) {
      const due = [...timers.entries()].filter(([, t]) => t.at <= to).sort((a, b) => a[1].at - b[1].at)[0];
      if (!due) break;
      timers.delete(due[0]);
      now = due[1].at;
      due[1].fn();
    }
    now = to;
  };
  return { ctl, views, advance, pending: () => timers.size };
}

test("a wait under 300 ms never shows (no flash)", () => {
  const h = harness();
  h.ctl.update(true);
  h.advance(150);
  h.ctl.update(false);
  h.advance(5000);
  assert.deepEqual(h.views, []);
  assert.equal(h.pending(), 0);
});

test("shown after 300 ms, held at least 600 ms once shown", () => {
  const h = harness();
  h.ctl.update(true);
  h.advance(299);
  assert.equal(h.ctl.view().show, false);
  h.advance(300);
  assert.equal(h.ctl.view().show, true);
  h.advance(400); // data lands 100 ms after the loader appeared
  h.ctl.update(false);
  h.advance(899);
  assert.equal(h.ctl.view().show, true, "still holding");
  h.advance(900); // 300 + 600
  assert.deepEqual(h.ctl.view(), { show: false, slow: false });
});

test("a wait longer than the minimum hides at once when it ends", () => {
  const h = harness();
  h.ctl.update(true);
  h.advance(2000);
  h.ctl.update(false);
  assert.deepEqual(h.ctl.view(), { show: false, slow: false });
});

test("the honest slow line turns on at 8 s and clears with the wait", () => {
  const h = harness();
  h.ctl.update(true);
  h.advance(7999);
  assert.equal(h.ctl.view().slow, false);
  h.advance(8000);
  assert.deepEqual(h.ctl.view(), { show: true, slow: true });
  h.ctl.update(false);
  assert.deepEqual(h.ctl.view(), { show: false, slow: false });
});

test("a failure stops it at once and stays stopped until a new wait", () => {
  const h = harness();
  h.ctl.update(true);
  h.advance(500);
  h.ctl.update(true, true);
  assert.deepEqual(h.ctl.view(), { show: false, slow: false });
  h.advance(20000);
  assert.deepEqual(h.ctl.view(), { show: false, slow: false }, "no slow line over a failure");
  h.ctl.update(true); // still the failed wait (no end seen): stay stopped
  h.advance(21000);
  assert.equal(h.ctl.view().show, false);
  h.ctl.update(false);
  h.ctl.update(true); // a fresh wait
  h.advance(21300);
  assert.equal(h.ctl.view().show, true);
});

test("a new wait inside the minimum hold keeps showing (no blink)", () => {
  const h = harness();
  h.ctl.update(true);
  h.advance(300);
  h.ctl.update(false);
  h.advance(500);
  h.ctl.update(true);
  h.advance(5000);
  assert.equal(h.ctl.view().show, true);
  const hides = h.views.filter((v) => !v.show).length;
  assert.equal(hides, 0, "never hid between the two waits");
});

test("dispose cancels every timer", () => {
  const h = harness();
  h.ctl.update(true);
  h.ctl.dispose();
  assert.equal(h.pending(), 0);
});
