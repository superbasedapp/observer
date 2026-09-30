// Pins shared/lib/liveDotSize.ts: one case per LIVE_DOT_SIZE_CLASS row, and
// the default (no size) adding no class so an existing LiveDot is unchanged.
import { test } from "node:test";
import assert from "node:assert/strict";
import { LIVE_DOT_SIZE_CLASS, liveDotSizeClass } from "../../../shared/lib/liveDotSize.ts";

const rows: Array<["sm" | "md" | "lg", string]> = [
  ["sm", "h-1.5 w-1.5"],
  ["md", ""],
  ["lg", "h-2.5 w-2.5"],
];

test("the table has exactly the three sizes", () => {
  assert.deepEqual(Object.keys(LIVE_DOT_SIZE_CLASS).sort(), ["lg", "md", "sm"]);
});

for (const [size, want] of rows) {
  test(`liveDotSizeClass(${size})`, () => {
    assert.equal(liveDotSizeClass(size), want);
  });
}

test("no size adds no class", () => {
  assert.equal(liveDotSizeClass(undefined), "");
});
