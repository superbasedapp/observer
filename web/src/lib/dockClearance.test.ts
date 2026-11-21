import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { DOCK_BOTTOM_BAND, DOCK_CLEARANCE_VAR, DOCK_GAP, dockClearance } from "./dockClearance.ts";

// One row per dock position (T-855: the dock covered Send / Reply on
// Messages and the bottom-right card on Plans & limits).
const rows: { name: string; rect: { top: number; bottom: number; height: number }; vh: number; want: number }[] = [
  { name: "default spot, button only", rect: { top: 846, bottom: 884, height: 38 }, vh: 900, want: 900 - 846 + DOCK_GAP },
  { name: "default spot with two minimized pills", rect: { top: 760, bottom: 884, height: 124 }, vh: 900, want: 900 - 760 + DOCK_GAP },
  { name: "phone", rect: { top: 790, bottom: 828, height: 38 }, vh: 844, want: 844 - 790 + DOCK_GAP },
  { name: "fractional box rounds up", rect: { top: 845.4, bottom: 884, height: 38.6 }, vh: 900, want: Math.ceil(900 - 845.4 + DOCK_GAP) },
  { name: "hidden under an overlay", rect: { top: 0, bottom: 0, height: 0 }, vh: 900, want: 0 },
  { name: "dragged to the top of the screen", rect: { top: 60, bottom: 98, height: 38 }, vh: 900, want: 0 },
  { name: "dragged just inside the bottom band", rect: { top: 662, bottom: 900 - DOCK_BOTTOM_BAND, height: 38 }, vh: 900, want: 900 - 662 + DOCK_GAP },
];
for (const r of rows) {
  test(`dockClearance: ${r.name}`, () => {
    assert.equal(dockClearance(r.rect, r.vh), r.want);
  });
}

test("the page box reserves the dock's variable, not a fixed gutter", () => {
  const app = readFileSync(new URL("../App.tsx", import.meta.url), "utf8");
  assert.ok(app.includes(`h-[calc(100%-var(${DOCK_CLEARANCE_VAR},0px))]`), "the page box must leave the dock clearance free");
  assert.ok(app.includes(`after:h-[var(${DOCK_CLEARANCE_VAR},0px)]`), "a spacer after the page content must keep its last row clear of the dock");
  assert.ok(!app.includes("overflow-y-auto pb-24"), "the fixed pb-24 gutter is replaced by the dock clearance");
  const dock = readFileSync(new URL("../components/LaunchDock.tsx", import.meta.url), "utf8");
  assert.match(dock, /useDockClearance\(drag\.ref\)/);
});

// The coordinator's phone finding: the dock's grip and button sat on Send
// (Ask my admin at 390). Below lg the floating dock is not rendered at all and
// a compact top-bar button replaces it; the grip is inline beside the button,
// never a row of its own above it.
test("the floating dock is desktop-only and its phone replacement lives in the top bar", () => {
  const dock = readFileSync(new URL("../components/LaunchDock.tsx", import.meta.url), "utf8");
  assert.match(dock, /className="sb-launch-dock fixed bottom-4 right-4 z-\[25\] hidden [^"]*lg:flex"/);
  assert.match(dock, /<div className="flex items-center gap-1\.5">\s*\{\/\* Drag grip, inline/);
  assert.match(dock, /export function PhoneTerminalButton\(/);
  const top = readFileSync(new URL("../components/TopBar.tsx", import.meta.url), "utf8");
  assert.match(top, /<span className="inline-flex lg:hidden">\s*<PhoneTerminalButton \/>/);
});

// Phone top bar room: the display preferences leave the bar below sm (the
// page title had shrunk to "M.") and are reachable from the nav drawer.
test("below sm the display controls leave the top bar for the drawer; below xl the density does too", () => {
  // Below sm the top bar has no room for either control; from sm to xl it
  // keeps the theme but not the density (its status chips need the room,
  // 2026-11-06), so the sidebar's Display row shows below xl, except on the
  // collapsed rail.
  const top = readFileSync(new URL("../components/TopBar.tsx", import.meta.url), "utf8");
  assert.match(
    top,
    /<span className="hidden items-center gap-2 sm:flex">\s*<span className="hidden xl:inline-flex">\s*<TopBarDensity \/>\s*<\/span>\s*<ThemeToggle dataTour="topbar-theme" \/>/,
  );
  const side = readFileSync(new URL("../components/Sidebar.tsx", import.meta.url), "utf8");
  assert.match(side, /px-3 py-2 xl:hidden",[\s\S]{0,160}collapsed && "lg:hidden",[\s\S]{0,40}>\s*<span className="text-\[11px\] text-fg-3">Display<\/span>\s*<DisplayControls \/>/);
});
