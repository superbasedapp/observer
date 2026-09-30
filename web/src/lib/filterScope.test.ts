import assert from "node:assert/strict";
import test from "node:test";
import { filterScopeFor, ignoredFilters } from "./filterScope.ts";

const cases: Array<[string, string]> = [
  ["/", "window,tool,project"],
  ["", "window,tool,project"],
  ["/cost", "window,tool,project"],
  ["/sessions", "window,tool,project"],
  ["/sessions/extra", "window,tool,project"],
  ["/patterns", "tool,project"],
  ["/routing", "window"],
  ["/settings", ""],
  ["/terminals", ""],
  ["/remote", ""],
  ["/no-such-page", ""],
];
for (const [path, want] of cases) {
  test(`filterScopeFor(${JSON.stringify(path)}) = [${want}]`, () => {
    const s = filterScopeFor(path);
    const got = (["window", "tool", "project"] as const).filter((k) => s[k]).join(",");
    assert.equal(got, want);
  });
}

test("ignoredFilters names only set filters the page does not read", () => {
  assert.deepEqual(ignoredFilters(filterScopeFor("/settings"), { tool: "codex", project: "" }), ["tool"]);
  assert.deepEqual(ignoredFilters(filterScopeFor("/routing"), { tool: "codex", project: "p1" }), ["tool", "project"]);
  assert.deepEqual(ignoredFilters(filterScopeFor("/cost"), { tool: "codex", project: "p1" }), []);
  assert.deepEqual(ignoredFilters(filterScopeFor("/settings"), { tool: "", project: "" }), []);
  // "all" is the FilterProvider's unfiltered default, not a set filter.
  assert.deepEqual(ignoredFilters(filterScopeFor("/settings"), { tool: "all", project: "all" }), []);
});
