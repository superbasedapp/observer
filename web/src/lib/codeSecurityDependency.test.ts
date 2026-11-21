// Tests of the dependency-finding text helpers and the findings / projects
// paging model in codeSecurity.ts.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  advisoryDetailsCollapsible,
  advisoryRangeWords,
  advisorySourceNote,
  dependencyFixedIn,
  dependencyKindWords,
  dependencyPackage,
  findingsFilterKey,
  findingsListReducer,
  findingsQueryParams,
  findingsSortParams,
  findingSignalLabels,
  normalizeFindingSort,
  reachWords,
  findingWhereDetail,
  INITIAL_FINDINGS_LIST,
  lastPage,
  lockfileLocationLabel,
  locationNotFoundWords,
  pageSlice,
  safeReference,
  sortProjectsBy,
  type FindingsListState,
  type SecurityProject,
  type SecurityFinding,
} from "./codeSecurity.ts";
import { EMPTY_FINDINGS_FILTERS, type FindingsFilters } from "./codeSecurityApi.ts";

function finding(over: Partial<SecurityFinding> = {}): SecurityFinding {
  return {
    id: "f1",
    project_root_hash: "h",
    rule_id: "dep.osv",
    driver: "osv",
    category: "vulnerable_dependency",
    severity: "high",
    confidence: "high",
    scope: "scheduled",
    baseline: "new",
    status: "open",
    rel_path: "package-lock.json",
    start_line: 0,
    message: "m",
    first_seen: "",
    last_seen: "",
    ...over,
  };
}

test("dependencyKindWords joins relationship and scope in plain words", () => {
  assert.equal(dependencyKindWords({ relationship: "transitive", scope: "dev" }), "transitive, dev only");
  assert.equal(dependencyKindWords({ relationship: "direct", scope: "runtime" }), "direct, runtime");
  assert.equal(dependencyKindWords({ relationship: "direct", scope: "" }), "direct");
  assert.equal(dependencyKindWords({ relationship: "", scope: "" }), "");
  assert.equal(dependencyKindWords({}), "");
});

test("dependencyPackage and dependencyFixedIn", () => {
  assert.equal(dependencyPackage({ name: "lodash", version: "4.17.20" }), "lodash@4.17.20");
  assert.equal(dependencyPackage({ name: "lodash", version: "" }), "lodash");
  assert.equal(dependencyFixedIn({ fixed_versions: ["4.17.21", "5.0.1"] }), "4.17.21, 5.0.1");
  assert.equal(dependencyFixedIn({}), "");
});

test("lockfileLocationLabel and findingWhereDetail show the line when one exists", () => {
  assert.equal(lockfileLocationLabel({ rel_path: "go.sum", start_line: 12 }), "go.sum:12");
  assert.equal(lockfileLocationLabel({ rel_path: "go.sum" }), "go.sum");
  const dep = {
    ecosystem: "npm",
    name: "lodash",
    version: "4.17.20",
    advisory_source: "local_database" as const,
    location: { rel_path: "package-lock.json", found: true, start_line: 88 },
  };
  assert.equal(findingWhereDetail({ finding: finding(), dependency: dep }), "package-lock.json:88");
  // The finding row's own line wins; no dependency block changes nothing.
  assert.equal(findingWhereDetail({ finding: finding({ start_line: 5 }), dependency: dep }), "package-lock.json:5");
  assert.equal(findingWhereDetail({ finding: finding() }), "package-lock.json");
});

test("locationNotFoundWords has plain words per reason and a fallback", () => {
  for (const r of ["not_found", "file_too_large", "unsupported_format", "unreadable", "outside_project"]) {
    assert.ok(locationNotFoundWords(r).endsWith("."), r);
    assert.ok(!locationNotFoundWords(r).includes("_"), r);
  }
  assert.match(locationNotFoundWords(""), /could not be located/);
});

test("advisoryRangeWords", () => {
  assert.equal(advisoryRangeWords({ introduced: "4.0.0", fixed: "4.17.21" }), "introduced 4.0.0, fixed 4.17.21");
  assert.equal(advisoryRangeWords({ introduced: "0", fixed: "1.2.3" }), "affected from the first release, fixed 1.2.3");
  assert.equal(advisoryRangeWords({ introduced: "1.0.0", last_affected: "1.4.0" }), "introduced 1.0.0, last affected 1.4.0");
  assert.equal(advisoryRangeWords({}), "");
});

test("advisoryDetailsCollapsible collapses long text only", () => {
  assert.equal(advisoryDetailsCollapsible("short"), false);
  assert.equal(advisoryDetailsCollapsible("a\nb\nc\nd\ne\nf"), false);
  assert.equal(advisoryDetailsCollapsible("a\nb\nc\nd\ne\nf\ng"), true);
  assert.equal(advisoryDetailsCollapsible("x".repeat(601)), true);
});

test("safeReference allows http(s) only", () => {
  assert.deepEqual(safeReference({ type: "ADVISORY", url: "https://github.com/advisories/GHSA-1" }), {
    href: "https://github.com/advisories/GHSA-1",
    host: "github.com",
    type: "advisory",
  });
  assert.equal(safeReference({ url: "http://example.org/x" })?.host, "example.org");
  assert.equal(safeReference({ url: "javascript:alert(1)" }), null);
  assert.equal(safeReference({ url: "data:text/html,hi" }), null);
  assert.equal(safeReference({ url: "ftp://example.org/x" }), null);
  assert.equal(safeReference({ url: "not a url" }), null);
});

test("advisorySourceNote is honest per source and empty when advisories exist", () => {
  assert.equal(advisorySourceNote("local_database"), "");
  assert.match(advisorySourceNote("not_in_local_database"), /not in the local OSV database/);
  assert.match(advisorySourceNote("database_not_installed"), /not installed.*Scanners card/);
});

test("findingsSortParams maps the table sort onto the API and falls back to the rank", () => {
  assert.deepEqual(findingsSortParams([]), { sort: "rank", dir: "desc" });
  // The rank has one direction.
  assert.deepEqual(findingsSortParams([{ id: "rank", desc: false }]), { sort: "rank", dir: "desc" });
  assert.deepEqual(findingsSortParams([{ id: "severity", desc: false }]), { sort: "severity", dir: "asc" });
  assert.deepEqual(findingsSortParams([{ id: "last_seen", desc: true }]), { sort: "last_seen", dir: "desc" });
  assert.deepEqual(findingsSortParams([{ id: "first_seen", desc: false }]), { sort: "first_seen", dir: "asc" });
  // A column the API cannot sort on never reaches it.
  assert.deepEqual(findingsSortParams([{ id: "where", desc: true }]), { sort: "rank", dir: "desc" });
});

test("findings list: page moves request that page, filters and sort reset to page 1", () => {
  // The filters live in the URL; the state holds the page and sort and the
  // filters its page number belongs to.
  const open: FindingsFilters = { ...EMPTY_FINDINGS_FILTERS, group: "none" };
  const keyOpen = findingsFilterKey(open);
  let s: FindingsListState = INITIAL_FINDINGS_LIST;
  assert.deepEqual(findingsQueryParams(open, s), {
    status: "open",
    page: 1,
    limit: 50,
    sort: "rank",
    dir: "desc",
  });
  s = findingsListReducer(s, { type: "page", page: 2, filterKey: keyOpen });
  assert.equal(findingsQueryParams(open, s).page, 2);
  // A filter change reads page 1 at once, without a reducer step.
  const proj: FindingsFilters = { ...open, project: ["abc"] };
  assert.equal(findingsQueryParams(proj, s).page, 1);
  assert.equal(findingsQueryParams(proj, s).project, "abc");
  // Back to the filters the page belonged to: that page again.
  assert.equal(findingsQueryParams(open, s).page, 2);
  // The grouping is not a filter: the page stays.
  assert.equal(findingsQueryParams({ ...open, group: "issue" }, s).page, 2);
  const every: FindingsFilters = { ...open, status: "" };
  s = findingsListReducer(s, { type: "page", page: 3, filterKey: findingsFilterKey(every) });
  assert.equal(findingsQueryParams(every, s).page, 3);
  // Every status sends no status (buildUrl drops the empty value).
  assert.equal(findingsQueryParams(every, s).status, "");
  s = findingsListReducer(s, { type: "sort", sorting: [{ id: "last_seen", desc: true }], filterKey: findingsFilterKey(every) });
  assert.equal(s.page, 1);
  assert.equal(findingsQueryParams(every, s).sort, "last_seen");
  // The sort is kept across a filter change.
  assert.equal(findingsQueryParams(open, s).sort, "last_seen");
  // A nonsense page is clamped to 1.
  assert.equal(findingsListReducer(s, { type: "page", page: 0, filterKey: keyOpen }).page, 1);
});

test("lastPage and pageSlice page a loaded list", () => {
  const rows = Array.from({ length: 60 }, (_, i) => i);
  assert.equal(lastPage(0, 25), 1);
  assert.equal(lastPage(60, 25), 3);
  assert.equal(pageSlice(rows, 1, 25).length, 25);
  assert.equal(pageSlice(rows, 3, 25).length, 10);
  assert.equal(pageSlice(rows, 3, 25)[0], 50);
  // Out-of-range pages clamp rather than render empty.
  assert.equal(pageSlice(rows, 9, 25)[0], 50);
  assert.equal(pageSlice(rows, 0, 25)[0], 0);
});

test("sortProjectsBy orders ALL rows by the chosen column, default attention-first", () => {
  const mk = (name: string, over: Partial<SecurityProject>): SecurityProject => ({
    project_root_hash: name,
    name,
    active: true,
    state: "clean",
    reason: "",
    blocking: 0,
    open: 0,
    counts: [],
    runs: [],
    ...over,
  });
  const rows = [
    mk("b", { open: 1, state: "dirty", last_scan_at: "2026-11-01T00:00:00Z" }),
    mk("a", { open: 5, state: "dirty", last_scan_at: "2026-11-03T00:00:00Z" }),
    mk("c", { state: "blocking", blocking: 1, open: 2 }),
    mk("d", { state: "clean" }),
  ];
  const names = (r: SecurityProject[]) => r.map((p) => p.name).join("");
  assert.equal(names(sortProjectsBy(rows, [])), "cabd");
  assert.equal(names(sortProjectsBy(rows, [{ id: "project", desc: false }])), "abcd");
  assert.equal(names(sortProjectsBy(rows, [{ id: "project", desc: true }])), "dcba");
  assert.equal(names(sortProjectsBy(rows, [{ id: "open", desc: true }])), "acbd");
  assert.equal(names(sortProjectsBy(rows, [{ id: "last_scan", desc: true }])), "abcd");
  // Input is never mutated.
  assert.equal(names(rows), "bacd");
});

test("findingSignalLabels: KEV and EPSS badges first, then the reach tier; unavailable is neutral and never 'not exploited'", () => {
  const labels = findingSignalLabels({
    reach: { level: "imported", tests_only: true, label: "imported, tests only (go imports)" },
    exploit: {
      kev_available: true,
      epss_available: true,
      kev: { cve: "CVE-2021-44228", date_added: "2021-12-10", ransomware: true },
      epss: { cve: "CVE-2021-44228", score: 0.944, percentile: 1 },
      badges: ["Exploited in the wild (CISA KEV, added 2021-12-10)", "Known ransomware campaign use (CISA KEV)", "EPSS 0.944, top 1 percent"],
      epss_citation: "EPSS scores: FIRST",
    },
  });
  assert.deepEqual(labels, [
    { text: "Exploited in the wild (CISA KEV, added 2021-12-10)", tone: "danger" },
    { text: "Known ransomware campaign use (CISA KEV)", tone: "danger" },
    { text: "EPSS 0.944, top 1 percent", tone: "warn" },
    { text: "imported, tests only", tone: "warn", title: "imported, tests only (go imports)" },
  ]);
  const none = findingSignalLabels({
    reach: { level: "unknown", reason: "no_import_mapping", label: "unknown (no import mapping for this ecosystem)" },
    exploit: { kev_available: false, epss_available: false, badges: ["Exploit data unavailable"] },
  });
  assert.deepEqual(none, [
    { text: "Exploit data unavailable", tone: "neutral" },
    { text: "reach unknown", tone: "neutral", title: "unknown (no import mapping for this ecosystem)" },
  ]);
  assert.ok(!none.some((l) => /not exploited/i.test(l.text)));
  assert.deepEqual(findingSignalLabels({}), []);
  assert.equal(reachWords({ level: "not_imported_directly", label: "" }), "not imported directly");
  assert.equal(reachWords({ level: "potentially_affected", source: "go-buildinfo", label: "potentially affected (go-buildinfo)" }), "potentially affected");
  assert.deepEqual(
    findingSignalLabels({ reach: { level: "potentially_affected", source: "go-buildinfo", label: "potentially affected (go-buildinfo)" } }),
    [{ text: "potentially affected", tone: "warn", title: "potentially affected (go-buildinfo)" }],
  );
  assert.equal(reachWords({ level: "called", approximate: true, label: "" }), "called, approximate");
  assert.equal(reachWords({ level: "called", approximate: true, tests_only: true, label: "" }), "called, tests only, approximate");
  assert.equal(reachWords({ level: "imported", approximate: true, label: "" }), "imported, approximate");
  const called = findingSignalLabels({
    reach: { level: "called", approximate: true, label: "called, approximate (codeintel-rust-callsite)" },
  });
  assert.deepEqual(called, [{ text: "called, approximate", tone: "warn", title: "called, approximate (codeintel-rust-callsite)" }]);
  assert.ok(!called.some((l) => /not called/i.test(l.text)));
  assert.equal(reachWords({ level: "called", label: "" }), "called");
  assert.equal(reachWords({ level: "not_called", label: "" }), "not called");
});

test("normalizeFindingSort keeps the rank descending", () => {
  assert.deepEqual(normalizeFindingSort([{ id: "rank", desc: false }]), [{ id: "rank", desc: true }]);
  assert.deepEqual(normalizeFindingSort([{ id: "severity", desc: false }]), [{ id: "severity", desc: false }]);
});

test("findingSignalLabels: the Go symbol check's tiers; called is danger, not called stays neutral", () => {
  const called = findingSignalLabels({
    reach: { level: "called", source: "govulncheck-binary", target: "bin/app", symbol: "jwt.Parse", label: "called: jwt.Parse (govulncheck-binary, bin/app)" },
  });
  assert.deepEqual(called, [{ text: "called", tone: "danger", title: "called: jwt.Parse (govulncheck-binary, bin/app)" }]);
  const notCalled = findingSignalLabels({
    reach: { level: "not_called", source: "govulncheck-binary", target: "bin/app", label: "not called (govulncheck-binary, bin/app)" },
  });
  assert.deepEqual(notCalled, [{ text: "not called", tone: "neutral", title: "not called (govulncheck-binary, bin/app)" }]);
});
