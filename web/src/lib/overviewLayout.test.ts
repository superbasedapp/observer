import assert from "node:assert/strict";
import test from "node:test";

import {
  DEFAULT_OVERVIEW_LAYOUT,
  moveSection,
  normalizeLayout,
  toggleSection,
} from "./overviewLayout.ts";

// The Overview "Customize" panel persists section order + visibility per
// browser. A stored layout from an older release (or garbage) must never
// lose a section or crash the page.

test("garbage and empty input fall back to the default layout", () => {
  for (const raw of [null, undefined, 42, "x", {}, { order: "nope" }]) {
    assert.deepEqual(normalizeLayout(raw), DEFAULT_OVERVIEW_LAYOUT);
  }
});

test("unknown ids and duplicates are dropped; missing sections are re-inserted", () => {
  const got = normalizeLayout({
    order: ["recent", "bogus", "kpis", "recent"],
    hidden: ["community", "bogus", "community"],
  });
  assert.deepEqual(got.hidden, ["community"]);
  assert.equal(new Set(got.order).size, DEFAULT_OVERVIEW_LAYOUT.order.length);
  // Each missing section lands after its nearest default predecessor that
  // is present: "trends" / "top" after "kpis", "community" after "recent".
  assert.deepEqual(got.order, ["recent", "community", "kpis", "trends", "top"]);
});

test("move and toggle", () => {
  let l = DEFAULT_OVERVIEW_LAYOUT;
  l = moveSection(l, "recent", -1);
  assert.deepEqual(l.order, ["kpis", "trends", "recent", "top", "community"]);
  assert.equal(moveSection(l, "kpis", -1), l, "top edge is a no-op");
  l = toggleSection(l, "trends");
  assert.deepEqual(l.hidden, ["trends"]);
  l = toggleSection(l, "trends");
  assert.deepEqual(l.hidden, []);
});
