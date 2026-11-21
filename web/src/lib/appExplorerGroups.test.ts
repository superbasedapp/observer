// Pins the explorer group types and the AppTraces group view (FR-M06): a group
// with no priced span has a null cost, the response carries the attribution
// fields, and the page hands the server's note to the shared GroupTable so
// the overlap sentence shows.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const src = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = (p: string) => readFileSync(path.join(src, p), "utf8");

test("the explorer group types allow a null cost and carry the attribution fields", () => {
  const api = read("lib/planeaApi.ts");
  assert.match(api, /total_cost_usd: number \| null;/);
  assert.match(api, /avg_cost_per_trace: number \| null;/);
  assert.match(api, /attribution\?: "span" \| "trace";/);
  assert.match(api, /totals_may_overlap\?: boolean;/);
  assert.match(api, /note\?: string;/);
});

test("AppTraces passes the server's note to the group table", () => {
  const page = read("pages/AppTraces.tsx");
  assert.match(page, /note=\{q\.data\?\.note\}/);
  assert.match(page, /costUsd: g\.total_cost_usd,/);
});
