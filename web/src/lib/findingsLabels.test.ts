// Tests of the Findings tab's words (findingsLabels.ts): every vocabulary
// value reads as words, an unknown id falls back to a readable form of
// itself and never to a blank, and the tab's computed lines (loading,
// count, empty) say what they should.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  baselineLabel,
  categoryLabel,
  driverLabel,
  ecosystemLabel,
  facetValueLabel,
  FINDING_STATUS_OPTIONS,
  findingsCountLine,
  findingsEmptyHint,
  findingsLoadCounts,
  findingsLoadingLabel,
  groupColumnLabel,
  groupNoun,
  LANGUAGE_LABEL,
  languageLabel,
  readableId,
  severityLabel,
  shortenChipValue,
  statusLabel,
  CHIP_VALUE_MAX,
} from "./findingsLabels.ts";
import { EMPTY_FINDINGS_FILTERS, type FindingsFacets, type FindingsFilters } from "./codeSecurityApi.ts";

function filters(over: Partial<FindingsFilters> = {}): FindingsFilters {
  return { ...EMPTY_FINDINGS_FILTERS, ...over };
}

test("readableId turns an unknown id into words, never a blank", () => {
  const cases: [string | undefined | null, string][] = [
    ["security_regression", "Security regression"],
    ["some-new.driver:id", "Some new driver id"],
    ["x", "X"],
    ["", "None"],
    [undefined, "None"],
    [null, "None"],
    ["  __  ", "None"],
  ];
  for (const [id, want] of cases) assert.equal(readableId(id), want, String(id));
  assert.equal(readableId("", "Unknown"), "Unknown");
});

test("categoryLabel covers the closed category vocabulary", () => {
  // internal/policy FindingCategories(), every one named.
  const cases: [string, string][] = [
    ["vulnerable_dependency", "Dependency"],
    ["secret", "Secret"],
    ["code_vuln", "Code rule"],
    ["iac", "IaC"],
    ["ci_config", "Workflow"],
    ["agent_config", "Agent config"],
    ["test_tampering", "Test tampering"],
    ["repo_trust", "Repository trust"],
    ["malicious_package", "Malicious package"],
    ["hallucinated_package", "Hallucinated package"],
    ["security_regression", "Security regression"],
    ["scope_drift", "Scope drift"],
    ["git_bypass", "Git hook bypass"],
    ["provenance", "Provenance"],
    ["license", "Licence"],
    // An id the table does not know yet still reads as words.
    ["license_issue", "License issue"],
    ["", "Unknown type"],
  ];
  for (const [id, want] of cases) assert.equal(categoryLabel(id), want, id);
});

test("driverLabel names every scanner, by exact id then by prefix", () => {
  const cases: [string, string][] = [
    ["native", "Built-in rules"],
    ["scalibr", "OSV-SCALIBR"],
    ["osv", "osv-scanner"],
    ["opengrep", "Opengrep"],
    ["trivy", "Trivy"],
    ["trivy-config", "Trivy"],
    ["trivy-image", "Trivy image scan"],
    ["kics", "KICS"],
    ["actionlint", "actionlint"],
    ["sarif-import", "SARIF import"],
    ["gitleaks", "Gitleaks"],
    ["observer-dast", "Passive DAST"],
    ["sbom-import", "From an SBOM"],
    ["security.scan.custom", "Custom scanner"],
    ["license", "Licence check"],
    ["custom:semgrep-local", "Custom: semgrep-local"],
    ["custom:", "Custom: unnamed"],
    ["observer-verify/agent_config", "Built-in checks (agent config)"],
    ["observer-verify/ci_workflow", "Built-in checks (workflows)"],
    ["observer-verify/new_detector", "Built-in checks (new detector)"],
    ["baseline:scalibr", "OSV-SCALIBR, baseline rescan"],
    ["diff:deps.s-747", "Deps s 747, changed files only"],
    ["brand_new", "Brand new"],
    ["", "Unknown scanner"],
  ];
  for (const [id, want] of cases) assert.equal(driverLabel(id), want, id);
});

test("the language table is internal/seclang's, id for id and label for label", () => {
  const go = readFileSync(new URL("../../../internal/seclang/seclang.go", import.meta.url), "utf8");
  const rows = [...go.matchAll(/\{ID: "([^"]+)", Label: "([^"]+)"/g)].map((m) => [m[1], m[2]] as const);
  assert.ok(rows.length > 40, "seclang rows read");
  assert.deepEqual(Object.fromEntries(rows), LANGUAGE_LABEL);
});

test("languageLabel, ecosystemLabel, baselineLabel, severityLabel, statusLabel", () => {
  const lang: [string, string][] = [
    ["go", "Go"],
    ["typescript", "TypeScript"],
    ["csharp", "C#"],
    ["cpp", "C++"],
    ["terraform", "Terraform / HCL"],
    ["", "No language"],
    ["brainfuck", "Brainfuck"],
  ];
  for (const [id, want] of lang) assert.equal(languageLabel(id), want, id);
  assert.equal(ecosystemLabel("PyPI"), "PyPI");
  assert.equal(ecosystemLabel("crates.io"), "crates.io");
  assert.equal(ecosystemLabel(""), "No ecosystem");
  const base: [string, string][] = [
    ["new", "New"],
    ["pre_existing", "Pre-existing"],
    ["untrusted_baseline", "No trusted baseline yet"],
    ["unknown", "Not judged"],
    ["", "Not judged"],
    ["later_value", "Later value"],
  ];
  for (const [id, want] of base) assert.equal(baselineLabel(id), want, id);
  assert.equal(severityLabel("critical"), "Critical");
  assert.equal(severityLabel("info"), "Info");
  assert.equal(severityLabel(""), "Unknown severity");
  for (const o of FINDING_STATUS_OPTIONS) assert.equal(statusLabel(o.value), o.label);
  assert.equal(statusLabel("fixed_verified"), "Fixed");
  assert.equal(statusLabel(""), "Every status");
});

test("facetValueLabel dispatches on the facet and names a project through the caller", () => {
  const name = (hash: string) => (hash === "h1" ? "superbased-observer" : `Unknown project (${hash})`);
  assert.equal(facetValueLabel("category", "secret", name), "Secret");
  assert.equal(facetValueLabel("driver", "scalibr", name), "OSV-SCALIBR");
  assert.equal(facetValueLabel("project", "h1", name), "superbased-observer");
  assert.equal(facetValueLabel("project", "zz", name), "Unknown project (zz)");
  assert.equal(facetValueLabel("status", "", name), "Every status");
  assert.equal(facetValueLabel("severity", "high", name), "High");
});

test("shortenChipValue keeps a chip inside a phone-width row", () => {
  assert.equal(shortenChipValue("lodash@4.17.20"), "lodash@4.17.20");
  const path = "web2/src/components/very/deep/folder/structure/linkToken.ts";
  const short = shortenChipValue(path, true);
  assert.equal(short.length, CHIP_VALUE_MAX);
  assert.ok(short.startsWith("…") && short.endsWith("linkToken.ts"), short);
  const rule = shortenChipValue("x".repeat(80));
  assert.equal(rule.length, CHIP_VALUE_MAX);
  assert.ok(rule.endsWith("…"));
});

test("group nouns and column labels", () => {
  assert.equal(groupNoun("issue", 1), "issue");
  assert.equal(groupNoun("issue", 399), "issues");
  assert.equal(groupNoun("package", 111), "packages");
  assert.equal(groupColumnLabel("rule"), "Rule");
  assert.equal(groupColumnLabel("project"), "Project");
});

const facets: FindingsFacets = {
  total: 5230,
  facets: {
    severity: [],
    category: [],
    driver: [],
    ecosystem: [],
    language: [],
    project: [
      { value: "a", count: 5000 },
      { value: "b", count: 230 },
      { value: "c", count: 0 },
    ],
    status: [],
    baseline: [],
  },
};

test("findingsLoadCounts prefers the facets, falls back to the status read only where it is exact", () => {
  assert.deepEqual(findingsLoadCounts(filters(), facets, null), { findings: 5230, projects: 2 });
  // A project filter counts the chosen projects (the project facet ignores its own filter).
  assert.deepEqual(findingsLoadCounts(filters({ project: ["b", "c"] }), facets, null), { findings: 5230, projects: 1 });
  const projects = [
    { project_root_hash: "a", open: 10 },
    { project_root_hash: "b", open: 5 },
    { project_root_hash: "c", open: 0 },
  ];
  assert.deepEqual(findingsLoadCounts(filters(), null, projects), { findings: 15, projects: 2 });
  assert.deepEqual(findingsLoadCounts(filters({ project: ["b"] }), null, projects), { findings: 5, projects: 1 });
  // The status read counts open findings only, unfiltered: anything else is unknown.
  assert.equal(findingsLoadCounts(filters({ severity: ["high"] }), null, projects), null);
  assert.equal(findingsLoadCounts(filters({ status: "" }), null, projects), null);
  assert.equal(findingsLoadCounts(filters({ q: "lodash" }), null, projects), null);
  assert.equal(findingsLoadCounts(filters(), null, null), null);
});

test("findingsLoadingLabel says what loads", () => {
  const counts = { findings: 5230, projects: 27 };
  assert.equal(findingsLoadingLabel(filters({ group: "none" }), counts), "Loading findings: 5,230 open across 27 projects");
  assert.equal(findingsLoadingLabel(filters({ group: "none", status: "" }), counts), "Loading findings: 5,230 across 27 projects");
  assert.equal(findingsLoadingLabel(filters({ group: "issue" }), counts), "Loading issues: 5,230 open findings across 27 projects");
  assert.equal(
    findingsLoadingLabel(filters({ group: "package" }), { findings: 1, projects: 1 }),
    "Loading packages: 1 open finding across 1 project",
  );
  assert.equal(findingsLoadingLabel(filters({ group: "none" }), null), "Loading findings");
  assert.equal(findingsLoadingLabel(filters({ group: "rule" }), null), "Loading rules");
});

test("findingsCountLine counts groups and findings", () => {
  assert.equal(findingsCountLine("issue", 399, 5137), "399 issues (5,137 findings)");
  assert.equal(findingsCountLine("package", 1, 1), "1 package (1 finding)");
  assert.equal(findingsCountLine("issue", 399, null), "399 issues");
  assert.equal(findingsCountLine("issue", null, 5137), null);
  assert.equal(findingsCountLine("none", null, 5137), "5,137 findings");
  assert.equal(findingsCountLine("none", null, null), null);
});

test("findingsEmptyHint tells a narrowed view from an empty one", () => {
  assert.equal(findingsEmptyHint(filters()), "No open findings. Run a scan to check again.");
  assert.equal(findingsEmptyHint(filters({ status: "suppressed" })), "No findings with this status.");
  assert.equal(findingsEmptyHint(filters({ language: ["go"] })), "No findings match these filters.");
  assert.equal(findingsEmptyHint(filters({ rule: "dep.osv" })), "No findings match these filters.");
  assert.equal(findingsEmptyHint(filters({ group: "package" })), "No dependency findings in this view.");
});
