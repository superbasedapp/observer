// Pins the SlideOver focus-trap rule table (shared/lib/focusTrap.ts):
// one case per row of trapTarget's ordered rules.
import { test } from "node:test";
import assert from "node:assert/strict";
import { trapTarget } from "../../../shared/lib/focusTrap.ts";

const items = ["close", "tab-a", "tab-b", "save"];

const cases: Array<{
  name: string;
  items: string[];
  active: string | null;
  shift: boolean;
  want: string | null;
}> = [
  { name: "nothing focusable", items: [], active: "panel", shift: false, want: null },
  { name: "panel itself focused, Tab -> first", items, active: "panel", shift: false, want: "close" },
  { name: "panel itself focused, Shift+Tab -> last", items, active: "panel", shift: true, want: "save" },
  { name: "no active element -> first", items, active: null, shift: false, want: "close" },
  { name: "Tab on last wraps to first", items, active: "save", shift: false, want: "close" },
  { name: "Shift+Tab on first wraps to last", items, active: "close", shift: true, want: "save" },
  { name: "Tab in the middle is left to the browser", items, active: "tab-a", shift: false, want: null },
  { name: "Shift+Tab in the middle is left to the browser", items, active: "tab-b", shift: true, want: null },
  { name: "Tab on first (not last) is left to the browser", items, active: "close", shift: false, want: null },
  { name: "single item wraps onto itself", items: ["only"], active: "only", shift: false, want: "only" },
];

for (const c of cases) {
  test(`trapTarget: ${c.name}`, () => {
    assert.equal(trapTarget(c.items, c.active, c.shift), c.want);
  });
}
