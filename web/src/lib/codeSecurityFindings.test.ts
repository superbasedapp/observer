// Tests of the Findings tab's filter model in codeSecurity.ts (redesign
// lane 2b): the URL's filters become the API's query, a facet click and a
// group row click become URL changes, and the bar lists only options that
// count something. The tab's handlers are exactly these functions
// (FindingsTab: onChange = updateFindingsSearch, onDrill =
// findingsDrillDown), so a click is tested here; the component tests render
// with react-dom/server and cannot click.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  activeFindingsFilters,
  clearFindingsFilters,
  findingGroupsKey,
  findingGroupsQueryParams,
  findingGroupsSortParams,
  findingsDrillDown,
  findingsFilterKey,
  findingsListReducer,
  findingsQueryParams,
  INITIAL_FINDINGS_LIST,
  INITIAL_GROUPS_LIST,
  setFindingsFilter,
  toggleFindingsFilter,
  updateFindingsSearch,
  visibleFacetOptions,
} from "./codeSecurity.ts";
import { EMPTY_FINDINGS_FILTERS, parseFindingsFilters, type FindingGroup } from "./codeSecurityApi.ts";

test("URL filters become the list, group and facet API params", () => {
  const url = new URLSearchParams("tab=findings&sev=high,critical&type=vulnerable_dependency&eco=npm&lang=go&project=h1&st=all&base=new&q=lodash&group=none&finding=f9");
  const f = parseFindingsFilters(url);
  assert.deepEqual(findingsQueryParams(f, INITIAL_FINDINGS_LIST), {
    severity: "high,critical",
    category: "vulnerable_dependency",
    ecosystem: "npm",
    language: "go",
    project: "h1",
    baseline: "new",
    status: "",
    q: "lodash",
    page: 1,
    limit: 50,
    sort: "rank",
    dir: "desc",
  });
  // The groups read carries the grouping, its own sort and page.
  assert.deepEqual(findingGroupsQueryParams("package", f, INITIAL_GROUPS_LIST), {
    by: "package",
    severity: "high,critical",
    category: "vulnerable_dependency",
    ecosystem: "npm",
    language: "go",
    project: "h1",
    baseline: "new",
    status: "",
    q: "lodash",
    page: 1,
    limit: 50,
    sort: "severity",
    dir: "desc",
  });
  // A drill-down's exact filters reach the API under their API names.
  const drilled = parseFindingsFilters(new URLSearchParams("rule=GHSA-1&pkg=lodash@4.17.20&path=src/a.ts"));
  const q = findingsQueryParams(drilled, INITIAL_FINDINGS_LIST);
  assert.equal(q.rule, "GHSA-1");
  assert.equal(q.package, "lodash@4.17.20");
  assert.equal(q.path, "src/a.ts");
  assert.equal(q.status, "open");
});

test("a facet click updates the URL and keeps the tab and the open finding", () => {
  const prev = new URLSearchParams("tab=findings&finding=f9");
  let next = updateFindingsSearch(prev, (f) => toggleFindingsFilter(f, "severity", "high"));
  assert.equal(next.get("sev"), "high");
  assert.equal(next.get("tab"), "findings");
  assert.equal(next.get("finding"), "f9");
  next = updateFindingsSearch(next, (f) => toggleFindingsFilter(f, "severity", "critical"));
  assert.equal(next.get("sev"), "high,critical");
  // A second click on a chosen value removes it; the last one leaves no param.
  next = updateFindingsSearch(next, (f) => toggleFindingsFilter(f, "severity", "high"));
  assert.equal(next.get("sev"), "critical");
  next = updateFindingsSearch(next, (f) => toggleFindingsFilter(f, "severity", "critical"));
  assert.equal(next.has("sev"), false);
  // A picker replaces its list; duplicates collapse.
  next = updateFindingsSearch(next, (f) => setFindingsFilter(f, "driver", ["scalibr", "osv", "scalibr"]));
  assert.equal(next.get("scanner"), "scalibr,osv");
  // The status and the grouping write their own params; defaults write none.
  next = updateFindingsSearch(next, (f) => ({ ...f, status: "" }));
  assert.equal(next.get("st"), "all");
  next = updateFindingsSearch(next, (f) => ({ ...f, group: "none" }));
  assert.equal(next.get("group"), "none");
  next = updateFindingsSearch(next, (f) => ({ ...f, status: "open", group: "issue" }));
  assert.equal(next.has("st"), false);
  assert.equal(next.has("group"), false);
});

test("a group row click drills down to that group's findings, ungrouped", () => {
  const prev = new URLSearchParams("tab=findings&sev=high");
  const dep: FindingGroup = {
    key: "k1",
    rule_id: "GHSA-35jh-r3h4-6jhm",
    category: "vulnerable_dependency",
    ecosystem: "npm",
    package: "lodash@4.17.20",
    count: 20,
    projects: 20,
    max_severity: "high",
    first_seen: "2026-11-01T00:00:00Z",
    last_seen: "2026-11-06T00:00:00Z",
  };
  const issue = findingsDrillDown(prev, "issue", dep);
  assert.equal(issue.get("group"), "none");
  assert.equal(issue.get("rule"), "GHSA-35jh-r3h4-6jhm");
  assert.equal(issue.get("pkg"), "lodash@4.17.20");
  assert.equal(issue.get("eco"), "npm");
  // The filters already in force stay.
  assert.equal(issue.get("sev"), "high");
  assert.equal(issue.get("tab"), "findings");
  const pkg = findingsDrillDown(prev, "package", dep);
  assert.equal(pkg.get("pkg"), "lodash@4.17.20");
  assert.equal(pkg.has("rule"), false);
  const code: FindingGroup = { ...dep, key: "k2", package: undefined, ecosystem: undefined, rule_id: "secret.x", rel_path: "src/a.ts" };
  const path = findingsDrillDown(prev, "issue", code);
  assert.equal(path.get("rule"), "secret.x");
  assert.equal(path.get("path"), "src/a.ts");
  assert.equal(path.has("pkg"), false);
  const proj = findingsDrillDown(prev, "project", { ...dep, project_root_hash: "h7" });
  assert.equal(proj.get("project"), "h7");
  assert.equal(proj.get("group"), "none");
});

test("active filters list each value with the filters it leaves; clearing keeps the grouping", () => {
  const f = {
    ...EMPTY_FINDINGS_FILTERS,
    severity: ["high", "low"],
    category: ["secret"],
    status: "",
    rule: "secret.x",
    q: "token",
    group: "rule" as const,
  };
  const active = activeFindingsFilters(f);
  assert.deepEqual(
    active.map((a) => a.id),
    ["severity:high", "severity:low", "category:secret", "status", "rule", "q"],
  );
  assert.deepEqual(active[0].without.severity, ["low"]);
  assert.equal(active[3].without.status, "open");
  assert.equal(active[4].without.rule, "");
  // Open is the default status: not an active filter.
  assert.equal(activeFindingsFilters(EMPTY_FINDINGS_FILTERS).length, 0);
  const cleared = clearFindingsFilters(f);
  assert.deepEqual(cleared, { ...EMPTY_FINDINGS_FILTERS, group: "rule" });
});

test("visibleFacetOptions hides zero counts unless chosen, and lists the vocabulary before the counts", () => {
  const values = [
    { value: "npm", count: 300 },
    { value: "Go", count: 0 },
    { value: "PyPI", count: 12 },
  ];
  assert.deepEqual(visibleFacetOptions(values, []), [
    { value: "npm", count: 300 },
    { value: "PyPI", count: 12 },
  ]);
  // A chosen value with nothing to show stays listed, at zero, so it can be removed.
  assert.deepEqual(visibleFacetOptions(values, ["Go", "crates.io"]), [
    { value: "npm", count: 300 },
    { value: "PyPI", count: 12 },
    { value: "crates.io", count: 0 },
    { value: "Go", count: 0 },
  ]);
  // Before the facets answer: the known vocabulary plus the selection, uncounted.
  assert.deepEqual(visibleFacetOptions(null, ["x"], ["secret", "iac"]), [
    { value: "iac", count: null },
    { value: "secret", count: null },
    { value: "x", count: null },
  ]);
});

test("the grouped read's sort and page key", () => {
  assert.deepEqual(findingGroupsSortParams([]), { sort: "severity", dir: "desc" });
  assert.deepEqual(findingGroupsSortParams([{ id: "count", desc: true }]), { sort: "count", dir: "desc" });
  assert.deepEqual(findingGroupsSortParams([{ id: "last_seen", desc: false }]), { sort: "last_seen", dir: "asc" });
  assert.deepEqual(findingGroupsSortParams([{ id: "group", desc: false }]), { sort: "severity", dir: "desc" });
  // The same filters under another grouping are another page key.
  const f = { ...EMPTY_FINDINGS_FILTERS };
  assert.notEqual(findingGroupsKey("issue", f), findingGroupsKey("package", f));
  const s = findingsListReducer(INITIAL_GROUPS_LIST, { type: "page", page: 3, filterKey: findingGroupsKey("issue", f) });
  assert.equal(findingGroupsQueryParams("issue", f, s).page, 3);
  assert.equal(findingGroupsQueryParams("package", f, s).page, 1);
  // The list's page key ignores the grouping.
  assert.equal(findingsFilterKey({ ...f, group: "none" }), findingsFilterKey({ ...f, group: "rule" }));
});
