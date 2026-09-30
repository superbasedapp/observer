import assert from "node:assert/strict";
import test from "node:test";

import { barsAnimate, chartUpdateAnimates, MAX_ANIMATED_BARS } from "../../../shared/lib/motion.ts";

// chartUpdateAnimates (perf audit 2026-09-29) decides whether a shared chart
// re-plays its series animation for a new rows array. One case per rule.

const rows = (vals: number[], start = 1) =>
  vals.map((v, i) => ({ bucket: `2026-05-${String(start + i).padStart(2, "0")}`, a: v, b: v * 2 }));

const cases: { name: string; prev: object[] | null; next: object[]; want: boolean }[] = [
  { name: "first data animates", prev: null, next: rows([1, 2, 3]), want: true },
  { name: "first data (empty) animates", prev: null, next: [], want: true },
  { name: "empty -> data animates (count changed)", prev: [], next: rows([1, 2]), want: true },
  { name: "identical values, new array: no replay", prev: rows([1, 2, 3]), next: rows([1, 2, 3]), want: false },
  { name: "only the newest bucket moved (live refresh): no replay", prev: rows([1, 2, 3]), next: rows([1, 2, 9]), want: false },
  { name: "an older bucket changed (filter): replay", prev: rows([1, 2, 3]), next: rows([1, 5, 3]), want: true },
  { name: "a bucket was added (window grew): replay", prev: rows([1, 2, 3]), next: rows([1, 2, 3, 4]), want: true },
  { name: "the window slid (same count, new range): replay", prev: rows([1, 2, 3]), next: rows([2, 3, 4], 2), want: true },
  {
    name: "a series appeared in the newest bucket: replay",
    prev: rows([1, 2, 3]),
    next: [...rows([1, 2]), { ...rows([1, 2, 3])[2], c: 1 }],
    want: true,
  },
  {
    name: "an older row gained a key: replay",
    prev: rows([1, 2, 3]),
    next: [{ ...rows([1])[0], c: 0 }, ...rows([2, 3], 2)],
    want: true,
  },
  { name: "empty -> empty: no replay", prev: [], next: [], want: false },
];

for (const c of cases) {
  test(`chartUpdateAnimates: ${c.name}`, () => {
    assert.equal(chartUpdateAnimates(c.prev, c.next, "bucket"), c.want);
  });
}

test("chartUpdateAnimates: the same array is never a replay", () => {
  const r = rows([1, 2, 3]);
  assert.equal(chartUpdateAnimates(r, r, "bucket"), false);
});

test("chartUpdateAnimates: honours the x key it is given", () => {
  const a = [{ day: "2026-05-01", v: 1 }, { day: "2026-05-02", v: 2 }];
  const b = [{ day: "2026-05-02", v: 1 }, { day: "2026-05-03", v: 2 }];
  assert.equal(chartUpdateAnimates(a, b, "day"), true);
  assert.equal(chartUpdateAnimates(a, [a[0], { day: "2026-05-02", v: 7 }], "day"), false);
});

test("chartUpdateAnimates: NaN values compare equal (Object.is)", () => {
  const a = [{ bucket: "x", v: NaN }, { bucket: "y", v: 1 }];
  const b = [{ bucket: "x", v: NaN }, { bucket: "y", v: 2 }];
  assert.equal(chartUpdateAnimates(a, b, "bucket"), false);
});

// barsAnimate (perf re-measure 2026-09-30): a bar chart animates only while
// buckets x series stays at or under the cap; a non-bar chart never hits it.
for (const c of [
  { name: "not a bar chart", bars: undefined, want: true },
  { name: "30 daily buckets x 7 series", bars: 31 * 7, want: true },
  { name: "exactly the cap", bars: MAX_ANIMATED_BARS, want: true },
  { name: "one over the cap", bars: MAX_ANIMATED_BARS + 1, want: false },
  { name: "7 days hourly x 7 series", bars: 169 * 7, want: false },
  { name: "empty chart", bars: 0, want: true },
]) {
  test(`barsAnimate: ${c.name}`, () => {
    assert.equal(barsAnimate(c.bars), c.want);
  });
}
