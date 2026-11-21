// The one getting-started surface (first-run plan revision 2, 3.6 and 7.1):
// the layout follows the daemon's plane block row by row; nothing here
// decides the track (that is internal/planechoice, served on /api/firstrun).

import { test } from "node:test";
import assert from "node:assert/strict";
import { focusSelected, surfaceFold, surfaceLayout } from "./getStarted.ts";
import type { FirstRunPlane } from "./firstRun.ts";

function plane(over: Partial<FirstRunPlane>): FirstRunPlane {
  return {
    row: 3,
    rule: "coding only",
    track: "coding",
    ask: false,
    offer_apps: true,
    facts: { coding: true, coding_by: "AI coding history found", apps: false, apps_by: "no apps signal" },
    focus: "",
    intent: "",
    coding_history: true,
    apps_available: { available: true },
    ...over,
  };
}

const ROWS: { name: string; p: FirstRunPlane; columns: string[]; showSwitch: boolean; offerApps: boolean }[] = [
  { name: "row 1: both", p: plane({ row: 1, track: "both", offer_apps: false }), columns: ["coding", "apps"], showSwitch: false, offerApps: false },
  { name: "row 2: AI apps", p: plane({ row: 2, track: "apps", offer_apps: false, coding_history: false }), columns: ["apps"], showSwitch: false, offerApps: false },
  { name: "row 3: coding with the quiet line", p: plane({ row: 3 }), columns: ["coding"], showSwitch: false, offerApps: true },
  { name: "row 4: coding with the switch", p: plane({ row: 4, ask: true, offer_apps: false, coding_history: false }), columns: ["coding"], showSwitch: true, offerApps: false },
];

for (const r of ROWS) {
  test(`surfaceLayout ${r.name}`, () => {
    const l = surfaceLayout(r.p);
    assert.deepEqual(l.columns, r.columns);
    assert.equal(l.showSwitch, r.showSwitch);
    assert.equal(l.offerApps, r.offerApps);
    assert.equal(l.switchDisabled, "");
  });
}

test("surfaceLayout: AI Apps unavailable disables the switch with the reason and drops the quiet line", () => {
  const text = "This edition does not include AI Apps.";
  const row4 = surfaceLayout(plane({ row: 4, ask: true, apps_available: { available: false, reason: "not_in_build", text } }));
  assert.equal(row4.showSwitch, true);
  assert.equal(row4.switchDisabled, text);
  const row3 = surfaceLayout(plane({ offer_apps: true, apps_available: { available: false, reason: "blocked" } }));
  assert.equal(row3.offerApps, false);
  assert.ok(row3.switchDisabled.length > 0);
});

test("surfaceLayout: only the AI apps track offers the way back (U-02)", () => {
  assert.equal(surfaceLayout(plane({ row: 2, track: "apps", offer_apps: false })).switchBack, true);
  assert.equal(surfaceLayout(plane({ row: 1, track: "both" })).switchBack, false);
  assert.equal(surfaceLayout(plane({ row: 4, ask: true })).switchBack, false);
  assert.equal(surfaceLayout(undefined).switchBack, false);
});

test("surfaceLayout: an older daemon (no plane block) shows the coding track only", () => {
  const l = surfaceLayout(undefined);
  assert.deepEqual(l.columns, ["coding"]);
  assert.equal(l.showSwitch, false);
  assert.equal(l.offerApps, false);
});

test("focusSelected: the stored choice, else the inferred track", () => {
  assert.equal(focusSelected(plane({ focus: "apps", track: "apps" })), "apps");
  assert.equal(focusSelected(plane({ focus: "", track: "both" })), "both");
  assert.equal(focusSelected(null), "coding");
});

test("surfaceFold: Hide folds until shown again", () => {
  assert.equal(surfaceFold(null, null), "open");
  assert.equal(surfaceFold("2026-11-20T10:00:00Z", null), "folded");
  assert.equal(surfaceFold("2026-11-20T10:00:00Z", "2026-11-20T09:00:00Z"), "folded");
  assert.equal(surfaceFold("2026-11-20T10:00:00Z", "2026-11-20T11:00:00Z"), "open");
  assert.equal(surfaceFold("garbage", null), "open");
});
