import { test } from "node:test";
import assert from "node:assert/strict";
import {
  EMPTY_FINDINGS_FILTERS,
  findingsApiParams,
  findingsHref,
  FINDINGS_URL_PARAMS,
  groupDrillDown,
  parseFindingsFilters,
  writeFindingsFilters,
  type FindingGroup,
  type FindingsFilters,
} from "./codeSecurityApi.ts";
import { FILTER_PARAM_NAMES } from "./filterUrl.ts";

const group: FindingGroup = {
  key: "k",
  rule_id: "GHSA-1",
  ecosystem: "npm",
  package: "vite@5.0.2",
  project_root_hash: "h1",
  rel_path: "web/package-lock.json",
  count: 20,
  projects: 20,
  max_severity: "critical",
  first_seen: "2026-11-01T00:00:00Z",
  last_seen: "2026-11-06T00:00:00Z",
};

test("an empty URL is the default view: open findings, grouped by issue", () => {
  assert.deepEqual(parseFindingsFilters(new URLSearchParams()), EMPTY_FINDINGS_FILTERS);
});

test("the filters round-trip through the URL", () => {
  const f: FindingsFilters = {
    ...EMPTY_FINDINGS_FILTERS,
    severity: ["critical", "high"],
    category: ["vulnerable_dependency"],
    ecosystem: ["npm"],
    project: ["h1", "h2"],
    status: "",
    rule: "GHSA-1",
    pkg: "vite@5.0.2",
    q: "vite",
    group: "none",
  };
  const params = writeFindingsFilters(new URLSearchParams({ tab: "findings", finding: "x" }), f);
  assert.equal(params.get("tab"), "findings");
  assert.equal(params.get("finding"), "x", "parameters the filters do not own are kept");
  assert.equal(params.get("st"), "all");
  assert.equal(params.get("group"), "none");
  assert.deepEqual(parseFindingsFilters(params), f);
});

test("defaults leave the URL clean", () => {
  const params = writeFindingsFilters(new URLSearchParams({ sev: "low", st: "all", group: "rule" }), EMPTY_FINDINGS_FILTERS);
  assert.equal(params.toString(), "");
});

test("a list parameter drops blanks and duplicates; an unknown group falls back", () => {
  const f = parseFindingsFilters(new URLSearchParams({ sev: "high,,high, low ", group: "bogus" }));
  assert.deepEqual(f.severity, ["high", "low"]);
  assert.equal(f.group, "issue");
});

test("findingsHref links to the Findings tab with the filters", () => {
  assert.equal(findingsHref({ project: ["h1"] }), "/code-security?tab=findings&project=h1");
});

// The global filter bar reads and writes its own names on every page
// (lib/filterUrl.ts). A Findings filter under one of them leaks both ways:
// the bar's project (a root path) became a Findings chip nobody chose and
// could not remove, and a Findings project (a root hash) became the bar's
// project on the Projects page.
test("no Findings filter parameter is a name the global filter bar owns", () => {
  const shared = FINDINGS_URL_PARAMS.filter((p) => FILTER_PARAM_NAMES.includes(p));
  assert.deepEqual(shared, []);
});

test("the global project selection never reaches the Findings filters", () => {
  // What the bar writes on its way into the page: proj=<root path>.
  const f = parseFindingsFilters(new URLSearchParams({ tab: "findings", proj: "/mnt/d/programsx/superbased-observer" }));
  assert.deepEqual(f, EMPTY_FINDINGS_FILTERS);
  // Removing the Findings project leaves the bar's own parameter alone.
  const next = writeFindingsFilters(new URLSearchParams({ tab: "findings", proj: "/mnt/d/p", project: "h1" }), EMPTY_FINDINGS_FILTERS);
  assert.equal(next.get("project"), null);
  assert.equal(next.get("proj"), "/mnt/d/p");
});

test("findingsApiParams sends lists comma-joined and always sends the status", () => {
  assert.deepEqual(findingsApiParams(EMPTY_FINDINGS_FILTERS), { status: "open" });
  assert.deepEqual(
    findingsApiParams({ ...EMPTY_FINDINGS_FILTERS, severity: ["high", "low"], status: "", pkg: "a@1", path: "x/y", q: "z" }),
    { severity: "high,low", status: "", package: "a@1", path: "x/y", q: "z" },
  );
});

test("groupDrillDown lists one group's findings, ungrouped", () => {
  const base = { ...EMPTY_FINDINGS_FILTERS, severity: ["critical"] };
  const cases: { by: "issue" | "package" | "rule" | "project"; g: FindingGroup; want: Partial<FindingsFilters> }[] = [
    { by: "issue", g: group, want: { rule: "GHSA-1", pkg: "vite@5.0.2", ecosystem: ["npm"], path: "" } },
    {
      by: "issue",
      g: { ...group, package: undefined, ecosystem: undefined, rule_id: "secret.aws" },
      want: { rule: "secret.aws", pkg: "", path: "web/package-lock.json" },
    },
    { by: "package", g: group, want: { pkg: "vite@5.0.2", ecosystem: ["npm"], rule: "" } },
    { by: "rule", g: group, want: { rule: "GHSA-1", pkg: "" } },
    { by: "project", g: group, want: { project: ["h1"], rule: "" } },
  ];
  for (const tc of cases) {
    const got = groupDrillDown(tc.by, tc.g, base);
    assert.equal(got.group, "none", tc.by);
    assert.deepEqual(got.severity, ["critical"], `${tc.by} keeps the other filters`);
    for (const [k, v] of Object.entries(tc.want)) {
      assert.deepEqual(got[k as keyof FindingsFilters], v, `${tc.by}: ${k}`);
    }
  }
});
