import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { NAV_GROUPS, NAV_ITEMS, navIcon } from "./nav.ts";
import { DollarSign } from "lucide-react";
import { setCostDisplayMode } from "../../../shared/lib/format.ts";

// Every nav item carries its own glyph: two pages sharing an icon was the
// pre-WS4 defect (Live vs Actions both lightning, Security vs Privacy both
// shield). Compared by component identity, so a lucide alias of an icon
// already in use (AlertTriangle vs TriangleAlert) still counts as a clash.
test("every nav item has a distinct icon", () => {
  const seen = new Map<unknown, string>();
  for (const it of NAV_ITEMS) {
    assert.ok(it.icon, `${it.id} has no icon`);
    const prev = seen.get(it.icon);
    assert.equal(prev, undefined, `${it.id} reuses the icon of ${prev}`);
    seen.set(it.icon, it.id);
  }
});

test("nav ids and paths are unique", () => {
  const cases: { name: string; values: string[] }[] = [
    { name: "id", values: NAV_ITEMS.map((i) => i.id) },
    { name: "path", values: NAV_ITEMS.map((i) => i.path) },
    { name: "group id", values: NAV_GROUPS.map((g) => g.id) },
  ];
  for (const c of cases) {
    assert.equal(new Set(c.values).size, c.values.length, `duplicate ${c.name}`);
  }
});

test("navIcon resolves every nav item and nothing else", () => {
  for (const it of NAV_ITEMS) assert.equal(navIcon(it.id), it.icon, it.id);
  assert.equal(navIcon("no-such-page"), undefined);
});

// Every routed page's PageHeader takes its icon from the nav table (never a
// hand-copied glyph), and every nav item's page does so: read as text because
// the page modules are .tsx the node runner cannot import.
test("every page header resolves its icon through navIcon", () => {
  const dir = new URL("../pages/", import.meta.url);
  const used = new Map<string, string>();
  for (const f of readdirSync(dir).filter((n) => n.endsWith(".tsx"))) {
    const src = readFileSync(new URL(f, dir), "utf8");
    const headers = src.match(/<PageHeader\b/g)?.length ?? 0;
    if (headers === 0) continue;
    const ids = [...src.matchAll(/icon=\{navIcon\("([^"]+)"\)\}/g)].map((m) => m[1]);
    assert.equal(ids.length, headers, `${f}: every PageHeader needs icon={navIcon("<id>")}`);
    for (const id of ids) {
      assert.ok(navIcon(id), `${f}: navIcon("${id}") is not a nav item`);
      used.set(id, f);
    }
  }
  for (const it of NAV_ITEMS) assert.ok(used.has(it.id), `no page header uses navIcon("${it.id}")`);
});

// The cost page's entry follows the org's developer cost display: "Usage"
// with a non-dollar glyph in token-usage mode, the same route, and the glyph
// stays distinct from every other page's in both modes.
test("the cost entry reads Usage with a distinct glyph in token-usage mode", () => {
  const cases = [
    { mode: "usd" as const, label: "Cost" },
    { mode: "tokens" as const, label: "Usage" },
  ];
  try {
    for (const c of cases) {
      setCostDisplayMode(c.mode);
      const cost = NAV_ITEMS.find((i) => i.id === "cost");
      assert.ok(cost, "cost nav item");
      assert.equal(cost.label, c.label, c.mode);
      assert.equal(cost.path, "/cost", c.mode);
      assert.equal(navIcon("cost"), cost.icon, c.mode);
      const clash = NAV_ITEMS.find((i) => i.id !== "cost" && i.icon === cost.icon);
      assert.equal(clash, undefined, `${c.mode}: cost reuses the icon of ${clash?.id}`);
    }
    setCostDisplayMode("tokens");
    assert.notEqual(navIcon("cost"), DollarSign, "no dollar glyph in token-usage mode");
  } finally {
    setCostDisplayMode("usd");
  }
});

// First-run plan revision 2, 2.4 / decision 4: the AI Apps group moves to
// the top for the apps and both tracks, and nothing else changes.
test("navGroupsForTrack: apps first for apps and both, unchanged otherwise", async () => {
  const { navGroupsForTrack } = await import("./nav.ts");
  const ids = (t: string | null) => navGroupsForTrack(NAV_GROUPS, t).map((g) => g.id);
  const base = NAV_GROUPS.map((g) => g.id);
  assert.deepEqual(ids("coding"), base);
  assert.deepEqual(ids(null), base);
  for (const t of ["apps", "both"]) {
    const got = ids(t);
    assert.equal(got[0], "apps");
    assert.deepEqual([...got].sort(), [...base].sort(), "no group hidden or added");
    assert.deepEqual(got.slice(1), base.filter((id) => id !== "apps"), "the rest keep their order");
  }
  // A filtered nav without the group is left alone.
  const noApps = NAV_GROUPS.filter((g) => g.id !== "apps");
  assert.deepEqual(navGroupsForTrack(noApps, "apps").map((g) => g.id), noApps.map((g) => g.id));
});
