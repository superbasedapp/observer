import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

// The Settings SECTIONS table lives in a .tsx page module the node test runner
// cannot import, so it is read as text: every `id: "<section>"` row must carry
// an `icon: <LucideName>,` and no two sections may share one (pre-WS4, 31
// sections shared 14 icons).
const src = readFileSync(new URL("../pages/Settings.tsx", import.meta.url), "utf8");
const start = src.indexOf("const SECTIONS: SectionDef[] = [");
const end = src.indexOf("\n];\n", start);
const table = src.slice(start, end);
const rows = [...table.matchAll(/\n {2}\{\n {4}id: "([^"]+)"[\s\S]*?\n {4}icon: ([A-Za-z0-9]+),/g)].map(
  (m) => ({ id: m[1], icon: m[2] }),
);

test("settings SECTIONS table parsed", () => {
  assert.ok(start >= 0 && end > start, "SECTIONS table not found");
  const ids = [...table.matchAll(/\n {2}\{\n {4}id: "([^"]+)"/g)].map((m) => m[1]);
  assert.ok(ids.length >= 30, `only ${ids.length} sections found`);
  assert.deepEqual(
    rows.map((r) => r.id),
    ids,
    "every section row must carry an `icon: <LucideName>,` entry",
  );
});

test("every settings section has a distinct icon", () => {
  const seen = new Map<string, string>();
  for (const r of rows) {
    const prev = seen.get(r.icon);
    assert.equal(prev, undefined, `${r.id} reuses ${r.icon} (already on ${prev})`);
    seen.set(r.icon, r.id);
  }
});
