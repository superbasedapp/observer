import { test } from "node:test";
import assert from "node:assert/strict";
import {
  DATE_RANGE_PRESETS,
  END_OF_HOUR_MINUTE,
  atTime,
  fmtSpan,
  monthGrid,
  nearestMinuteChoice,
  startOfWeek,
} from "../../../shared/lib/dateRange.ts";

// Wednesday 2026-09-30 14:37 local.
const NOW = new Date(2026, 8, 30, 14, 37, 12);

function preset(key: string) {
  const p = DATE_RANGE_PRESETS.find((x) => x.key === key);
  assert.ok(p, key);
  return p.resolve(NOW);
}

test("monthGrid: 42 Monday-first days covering the month", () => {
  const g = monthGrid(2026, 8); // September 2026 starts on a Tuesday
  assert.equal(g.length, 42);
  assert.equal(g[0].getDay(), 1);
  assert.deepEqual([g[0].getMonth(), g[0].getDate()], [7, 31]);
  assert.deepEqual([g[1].getMonth(), g[1].getDate()], [8, 1]);
});

test("startOfWeek: Monday at local midnight", () => {
  const w = startOfWeek(NOW);
  assert.deepEqual([w.getMonth(), w.getDate(), w.getHours(), w.getDay()], [8, 28, 0, 1]);
  const sunday = startOfWeek(new Date(2026, 9, 4, 9));
  assert.deepEqual([sunday.getMonth(), sunday.getDate()], [8, 28]);
});

test("presets resolve to calendar-aligned local ranges", () => {
  const cases: [string, [number, number], [number, number] | null][] = [
    ["today", [8, 30], null],
    ["yesterday", [8, 29], [8, 30]],
    ["this-week", [8, 28], null],
    ["last-week", [8, 21], [8, 28]],
    ["this-month", [8, 1], null],
    ["last-month", [7, 1], [8, 1]],
  ];
  for (const [key, since, until] of cases) {
    const r = preset(key);
    assert.deepEqual([r.since.getMonth(), r.since.getDate(), r.since.getHours()], [...since, 0], key);
    if (until === null) assert.equal(r.until, null, key);
    else assert.deepEqual([r.until!.getMonth(), r.until!.getDate(), r.until!.getHours()], [...until, 0], key);
  }
});

test("open-ended presets are exactly the ones that end now", () => {
  for (const p of DATE_RANGE_PRESETS) assert.equal(p.openEnded, p.resolve(NOW).until === null, p.key);
});

test("atTime: an end at minute 59 runs through the end of that minute", () => {
  const day = new Date(2026, 8, 29);
  assert.equal(atTime(day, 23, END_OF_HOUR_MINUTE, true).getTime(), new Date(2026, 8, 30).getTime() - 1);
  assert.equal(atTime(day, 23, END_OF_HOUR_MINUTE).getSeconds(), 0);
  assert.equal(atTime(day, 9, 15, true).getSeconds(), 0);
});

test("nearestMinuteChoice snaps down to an offered minute", () => {
  assert.equal(nearestMinuteChoice(0), 0);
  assert.equal(nearestMinuteChoice(37), 35);
  assert.equal(nearestMinuteChoice(58), 55);
  assert.equal(nearestMinuteChoice(59), 59);
});

test("fmtSpan", () => {
  assert.equal(fmtSpan(45 * 60_000), "45m");
  assert.equal(fmtSpan(5 * 3_600_000 + 10 * 60_000), "5h 10m");
  assert.equal(fmtSpan(3 * 86_400_000 + 4 * 3_600_000), "3d 4h");
  assert.equal(fmtSpan(0), "");
});
