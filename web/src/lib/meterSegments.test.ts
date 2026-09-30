// Pins shared/lib/meterSegments.ts: the stacked-Meter layout (left to right,
// zero / invalid segments omitted, the running total clamped to the track)
// and the accessible summary (each segment's own share, never the clipped
// drawn width).
import { test } from "node:test";
import assert from "node:assert/strict";
import { layoutMeterSegments, meterSegmentsSummary } from "../../../shared/lib/meterSegments.ts";

const cases: Array<[string, Array<{ value: number; label: string }>, Array<{ index: number; start: number; share: number }>]> = [
  ["two segments laid left to right", [{ value: 0.4, label: "A" }, { value: 0.25, label: "B" }], [
    { index: 0, start: 0, share: 0.4 },
    { index: 1, start: 0.4, share: 0.25 },
  ]],
  ["a zero segment is omitted, the next keeps its index", [{ value: 0, label: "A" }, { value: 0.5, label: "B" }], [
    { index: 1, start: 0, share: 0.5 },
  ]],
  ["non-finite and negative draw nothing", [{ value: Number.NaN, label: "A" }, { value: -1, label: "B" }], []],
  ["an over-full stack is truncated at the right edge", [{ value: 0.75, label: "A" }, { value: 0.5, label: "B" }, { value: 0.1, label: "C" }], [
    { index: 0, start: 0, share: 0.75 },
    { index: 1, start: 0.75, share: 0.25 },
  ]],
  ["a single value above 1 is clamped to the track", [{ value: 3, label: "A" }], [{ index: 0, start: 0, share: 1 }]],
  ["no segments", [], []],
];

for (const [name, input, want] of cases) {
  test(`layoutMeterSegments: ${name}`, () => {
    assert.deepEqual(layoutMeterSegments(input), want);
  });
}

test("summary names each segment's own share, with the label", () => {
  assert.equal(
    meterSegmentsSummary([{ value: 0.4, label: "Input" }, { value: 0.25, label: "Output" }], "Token mix"),
    "Token mix: Input 40%, Output 25%",
  );
});

test("summary reports the given share even when the drawing clips", () => {
  assert.equal(
    meterSegmentsSummary([{ value: 0.75, label: "A" }, { value: 0.5, label: "B" }]),
    "A 75%, B 50%",
  );
});

test("summary of nothing says empty, never a blank name", () => {
  assert.equal(meterSegmentsSummary([], "Mix"), "Mix: empty");
  assert.equal(meterSegmentsSummary([]), "empty");
});
