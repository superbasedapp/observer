import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

// DataTable has ONE owner (shared/primitives/DataTable.tsx). These rows pin
// the promotion: each app's old path is a one-line re-export shim (so no
// second implementation can grow back there), the dependency is hoisted to
// the workspace root, and the lockfile holds exactly one install of it.

const ROOT = new URL("../../../", import.meta.url);
const read = (rel: string) => readFileSync(new URL(rel, ROOT), "utf8");

const SHIM = 'export * from "@shared/primitives/DataTable";\n';

const SHIMS = ["web/src/components/DataTable.tsx", "web2/src/components/DataTable.tsx"];

for (const path of SHIMS) {
  test(`DataTable shim: ${path} is the one-line re-export`, () => {
    assert.equal(read(path), SHIM);
  });
}

test("DataTable: the shared barrel exports it", () => {
  assert.match(read("shared/primitives/index.ts"), /export \{ DataTable, Pagination, type DataTableProps \} from "\.\/DataTable";/);
});

test("DataTable: @tanstack/react-table is a root workspace dependency", () => {
  const pkg = JSON.parse(read("package.json")) as { dependencies?: Record<string, string> };
  assert.ok(pkg.dependencies?.["@tanstack/react-table"], "root package.json must declare @tanstack/react-table");
});

test("DataTable: the lockfile holds one hoisted @tanstack install and no nested copy", () => {
  const lock = JSON.parse(read("package-lock.json")) as { packages: Record<string, unknown> };
  const tanstack = Object.keys(lock.packages).filter((k) => k.includes("node_modules/@tanstack/"));
  assert.deepEqual(tanstack.sort(), ["node_modules/@tanstack/react-table", "node_modules/@tanstack/table-core"]);
});

test("DataTable: its scrollbar rule is owned by the shared stylesheet, imported by every app", () => {
  assert.match(read("shared/styles/components.css"), /\.table-scroll-x \{/);
  for (const entry of ["web/src/index.css", "web2/src/index.css", "webcloud/src/styles.css"]) {
    assert.match(read(entry), /@import "\.\.\/\.\.\/shared\/styles\/components\.css";/, entry);
  }
  assert.doesNotMatch(read("web/src/index.css"), /\.table-scroll-x/);
});
