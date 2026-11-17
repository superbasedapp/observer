// findingsLabels is the Findings tab's words: the label of every value the
// findings filters and facets carry (finding category, scanner driver,
// language, ecosystem, baseline, severity, status, grouping), and the tab's
// few computed lines (the loading line, the count line, the empty hint).
// Redesign plan docs/plans/code-security-page-redesign-plan-2026-11-06.md
// section 4.4. Pure: no React, no fetch, unit-tested directly
// (findingsLabels.test.ts).
//
// Every label is a table lookup, and an id no table knows falls back to a
// readable form of the id itself (readableId), never to a blank: a new
// category, driver or language the daemon starts reporting still reads as
// words until it gets its row here.

import type {
  FindingsFacets,
  FindingsFacetKey,
  FindingsFilters,
  FindingsGroupBy,
} from "./codeSecurityApi.ts";

/** readableId is an unknown id in words: "security_regression" reads
 *  "Security regression". An empty id is `empty`, never a blank. */
export function readableId(id: string | undefined | null, empty = "None"): string {
  const words = (id ?? "").replace(/[_\-.:/]+/g, " ").replace(/\s+/g, " ").trim();
  if (!words) return empty;
  return words.charAt(0).toUpperCase() + words.slice(1);
}

function lookup(table: Readonly<Record<string, string>>, id: string | undefined | null, empty = "None"): string {
  const v = id ?? "";
  return Object.prototype.hasOwnProperty.call(table, v) ? table[v] : readableId(v, empty);
}

// The finding category vocabulary (internal/policy FindingCategory, the
// closed set of section 4.5): the "Type" filter.
const CATEGORY_LABEL: Readonly<Record<string, string>> = {
  vulnerable_dependency: "Dependency",
  secret: "Secret",
  code_vuln: "Code rule",
  iac: "IaC",
  ci_config: "Workflow",
  agent_config: "Agent config",
  test_tampering: "Test tampering",
  repo_trust: "Repository trust",
  malicious_package: "Malicious package",
  hallucinated_package: "Hallucinated package",
  security_regression: "Security regression",
  scope_drift: "Scope drift",
  git_bypass: "Git hook bypass",
  provenance: "Provenance",
  license: "Licence",
};

/** categoryLabel is a finding category in words ("Dependency"). */
export function categoryLabel(id: string | undefined | null): string {
  return lookup(CATEGORY_LABEL, id, "Unknown type");
}

// The driver ids a finding carries (secfinding Engine.Driver): the built-in
// detectors' "native", the dependency drivers (internal/secscan/depscan
// ScalibrID / OSVID), the engines' DriverID constants and the secscan
// adapter rows.
const DRIVER_LABEL: Readonly<Record<string, string>> = {
  native: "Built-in rules",
  scalibr: "OSV-SCALIBR",
  osv: "osv-scanner",
  opengrep: "Opengrep",
  trivy: "Trivy",
  "trivy-config": "Trivy",
  "trivy-image": "Trivy image scan",
  kics: "KICS",
  actionlint: "actionlint",
  "sarif-import": "SARIF import",
  gitleaks: "Gitleaks",
  "observer-dast": "Passive DAST",
  "sbom-import": "From an SBOM",
  "security.scan.custom": "Custom scanner",
  license: "Licence check",
};

// The built-in verifier's detectors (internal/secverify Coverage.Detector):
// its findings carry "observer-verify/<detector>".
const VERIFY_DETECTOR_LABEL: Readonly<Record<string, string>> = {
  agent_config: "agent config",
  ci_workflow: "workflows",
  container_config: "containers",
  install_index: "package index",
  repo_trust: "repository trust",
  secrets: "secrets",
  test_tampering: "test tampering",
};

// Driver ids that are a prefix and a rest, walked top-down; the first
// matching row wins.
const DRIVER_PREFIX: readonly { prefix: string; label: (rest: string) => string }[] = [
  { prefix: "custom:", label: (rest) => `Custom: ${rest || "unnamed"}` },
  {
    prefix: "observer-verify/",
    label: (rest) => `Built-in checks (${VERIFY_DETECTOR_LABEL[rest] ?? readableId(rest).toLowerCase()})`,
  },
  // A baseline rescan's and a diff-only run's drivers (internal/store
  // SecBaselineDriverPrefix, SecDiffDriverPrefix).
  { prefix: "baseline:", label: (rest) => `${driverLabel(rest)}, baseline rescan` },
  { prefix: "diff:", label: (rest) => `${driverLabel(rest)}, changed files only` },
];

/** driverLabel is a scanner driver id in words ("OSV-SCALIBR"). */
export function driverLabel(id: string | undefined | null): string {
  const v = id ?? "";
  if (Object.prototype.hasOwnProperty.call(DRIVER_LABEL, v)) return DRIVER_LABEL[v];
  for (const row of DRIVER_PREFIX) {
    if (v.startsWith(row.prefix)) return row.label(v.slice(row.prefix.length));
  }
  return readableId(v, "Unknown scanner");
}

// The language ids of internal/seclang (one table, from the file name),
// with its labels: seclang.go owns them, and findingsLabels.test.ts fails
// when this copy drifts from it. An id with no row (a newer daemon's)
// reads as its own readable form.
export const LANGUAGE_LABEL: Readonly<Record<string, string>> = {
  go: "Go",
  typescript: "TypeScript",
  javascript: "JavaScript",
  python: "Python",
  jupyter: "Jupyter notebook",
  java: "Java",
  kotlin: "Kotlin",
  scala: "Scala",
  groovy: "Groovy",
  csharp: "C#",
  fsharp: "F#",
  visualbasic: "Visual Basic",
  c: "C",
  cpp: "C++",
  objectivec: "Objective-C",
  swift: "Swift",
  rust: "Rust",
  ruby: "Ruby",
  php: "PHP",
  dart: "Dart",
  elixir: "Elixir",
  erlang: "Erlang",
  haskell: "Haskell",
  ocaml: "OCaml",
  clojure: "Clojure",
  lua: "Lua",
  perl: "Perl",
  r: "R",
  julia: "Julia",
  zig: "Zig",
  solidity: "Solidity",
  sql: "SQL",
  html: "HTML",
  css: "CSS",
  vue: "Vue",
  svelte: "Svelte",
  shell: "Shell",
  powershell: "PowerShell",
  batch: "Batch",
  yaml: "YAML",
  json: "JSON",
  toml: "TOML",
  xml: "XML",
  ini: "INI",
  properties: "Java properties",
  dotenv: "Environment file",
  terraform: "Terraform / HCL",
  bicep: "Bicep",
  dockerfile: "Dockerfile",
  makefile: "Makefile",
  cmake: "CMake",
  starlark: "Starlark (Bazel)",
  nix: "Nix",
  protobuf: "Protocol Buffers",
  graphql: "GraphQL",
  markdown: "Markdown",
};

/** languageLabel is a language id in words ("TypeScript"); "" is a finding
 *  with no source language (a lockfile, the project itself). */
export function languageLabel(id: string | undefined | null): string {
  return lookup(LANGUAGE_LABEL, id, "No language");
}

/** ecosystemLabel is a dependency ecosystem as shown: OSV's own names
 *  ("npm", "PyPI", "crates.io") are already the names people know. */
export function ecosystemLabel(id: string | undefined | null): string {
  return (id ?? "").trim() || "No ecosystem";
}

// The baseline judgement (internal/policy FindingBaseline).
const BASELINE_LABEL: Readonly<Record<string, string>> = {
  new: "New",
  pre_existing: "Pre-existing",
  untrusted_baseline: "No trusted baseline yet",
  unknown: "Not judged",
  "": "Not judged",
};

/** baselineLabel is a baseline value in words ("Pre-existing"). */
export function baselineLabel(id: string | undefined | null): string {
  return lookup(BASELINE_LABEL, id, "Not judged");
}

// The severities, worst first (internal/policy FindingSeverity).
const SEVERITY_LABEL: Readonly<Record<string, string>> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

/** severityLabel is a severity in words ("High"). */
export function severityLabel(id: string | undefined | null): string {
  return lookup(SEVERITY_LABEL, id, "Unknown severity");
}

/** FINDING_STATUS_OPTIONS is the Status filter, in order: Open (the
 *  default), the three exception kinds, Not reproduced, and every status
 *  (the value ""). */
export const FINDING_STATUS_OPTIONS: readonly { value: string; label: string }[] = [
  { value: "open", label: "Open" },
  { value: "suppressed", label: "Excepted: test fixture" },
  { value: "false_positive", label: "Excepted: false positive" },
  { value: "accepted_risk", label: "Excepted: risk accepted" },
  { value: "not_reproduced", label: "Not reproduced" },
  { value: "", label: "Every status" },
];

const STATUS_LABEL: Readonly<Record<string, string>> = {
  ...Object.fromEntries(FINDING_STATUS_OPTIONS.map((o) => [o.value, o.label])),
  fixed_verified: "Fixed",
};

/** statusLabel is a finding status in words; "" is every status. */
export function statusLabel(id: string | undefined | null): string {
  return lookup(STATUS_LABEL, id, "Every status");
}

/** The "Group by" choices, in the order the control shows them. */
export const GROUP_BY_OPTIONS: readonly { value: FindingsGroupBy; label: string }[] = [
  { value: "issue", label: "Issue" },
  { value: "package", label: "Package" },
  { value: "rule", label: "Rule" },
  { value: "project", label: "Project" },
  { value: "none", label: "None" },
];

const GROUP_NOUN: Readonly<Record<Exclude<FindingsGroupBy, "none">, [string, string]>> = {
  issue: ["issue", "issues"],
  package: ["package", "packages"],
  rule: ["rule", "rules"],
  project: ["project", "projects"],
};

/** groupNoun is what one group row is, singular or plural for n. */
export function groupNoun(by: Exclude<FindingsGroupBy, "none">, n: number): string {
  const [one, many] = GROUP_NOUN[by] ?? ["group", "groups"];
  return n === 1 ? one : many;
}

/** groupColumnLabel is the grouped table's first column header. */
export function groupColumnLabel(by: Exclude<FindingsGroupBy, "none">): string {
  return GROUP_BY_OPTIONS.find((o) => o.value === by)?.label ?? "Group";
}

/** FACET_TITLE names each filter in the bar and in the active chips. */
export const FACET_TITLE: Readonly<Record<FindingsFacetKey, string>> = {
  severity: "Severity",
  category: "Type",
  driver: "Scanner",
  ecosystem: "Ecosystem",
  language: "Language",
  project: "Project",
  status: "Status",
  baseline: "Baseline",
};

/** facetValueLabel is one facet value in words. A project is named by the
 *  caller (projectName: lib/codeSecurity.ts projectLabel over the status
 *  read), never shown as its hash. */
export function facetValueLabel(key: FindingsFacetKey, value: string, projectName: (hash: string) => string): string {
  switch (key) {
    case "severity":
      return severityLabel(value);
    case "category":
      return categoryLabel(value);
    case "driver":
      return driverLabel(value);
    case "ecosystem":
      return ecosystemLabel(value);
    case "language":
      return languageLabel(value);
    case "project":
      return projectName(value);
    case "status":
      return statusLabel(value);
    case "baseline":
      return baselineLabel(value);
  }
}

/** CHIP_VALUE_MAX is the most characters an active-filter chip shows of a
 *  typed or drilled-down value; the chip's tooltip has the whole value. */
export const CHIP_VALUE_MAX = 36;

/** shortenChipValue keeps a long value inside a chip at phone width: a path
 *  keeps its end (the file name), anything else its start. */
export function shortenChipValue(value: string, keepEnd = false, max = CHIP_VALUE_MAX): string {
  if (value.length <= max) return value;
  return keepEnd ? `…${value.slice(value.length - (max - 1))}` : `${value.slice(0, max - 1)}…`;
}

/** countWords is a number with thousands separators ("5,230"). */
export function countWords(n: number): string {
  return Math.round(n).toLocaleString("en-US");
}

function plural(n: number, one: string, many: string): string {
  return `${countWords(n)} ${n === 1 ? one : many}`;
}

/** The counts the loading line names: how many findings, across how many
 *  projects. */
export type FindingsLoadCounts = { findings: number; projects: number };

/** findingsLoadCounts is what the loading line can honestly say before the
 *  list answers. The facets read counts the filtered set exactly; before it
 *  answers, the status read's per-project open counts stand in, but only
 *  for a view they describe (open findings, filtered by project at most).
 *  Null when neither can say. */
export function findingsLoadCounts(
  f: FindingsFilters,
  facets: FindingsFacets | null | undefined,
  projects: readonly { project_root_hash: string; open: number }[] | null | undefined,
): FindingsLoadCounts | null {
  if (facets) {
    const rows = (facets.facets?.project ?? []).filter((p) => p.count > 0);
    const inView = f.project.length > 0 ? rows.filter((p) => f.project.includes(p.value)) : rows;
    return { findings: facets.total, projects: inView.length };
  }
  if (!projects) return null;
  const onlyProject =
    f.status === "open" &&
    f.severity.length === 0 &&
    f.category.length === 0 &&
    f.driver.length === 0 &&
    f.ecosystem.length === 0 &&
    f.language.length === 0 &&
    f.baseline.length === 0 &&
    !f.rule &&
    !f.pkg &&
    !f.path &&
    !f.q;
  if (!onlyProject) return null;
  const rows = projects.filter((p) => p.open > 0 && (f.project.length === 0 || f.project.includes(p.project_root_hash)));
  return { findings: rows.reduce((n, p) => n + p.open, 0), projects: rows.length };
}

/** findingsLoadingLabel is the named loading line: "Loading findings:
 *  5,230 open across 27 projects", or for a grouped view "Loading issues:
 *  5,230 open findings across 27 projects"; just "Loading findings" when
 *  nothing is known yet. */
export function findingsLoadingLabel(f: FindingsFilters, counts: FindingsLoadCounts | null): string {
  const what = f.group === "none" ? "findings" : groupNoun(f.group, 2);
  if (!counts) return `Loading ${what}`;
  const open = f.status === "open" ? " open" : "";
  const across = `across ${plural(counts.projects, "project", "projects")}`;
  if (f.group === "none") return `Loading findings: ${countWords(counts.findings)}${open} ${across}`;
  const noun = counts.findings === 1 ? "finding" : "findings";
  return `Loading ${what}: ${countWords(counts.findings)}${open} ${noun} ${across}`;
}

/** The slow line under the loading line. */
export const FINDINGS_SLOW_LINE = "Still working: dependency rows are being checked for reachability";

/** The note shown while a page answers reach_pending. */
export const REACH_PENDING_NOTE = "Reachability is still being checked, so the order may change";

/** findingsCountLine is the line over the results: "399 issues (5,137
 *  findings)" for a grouped view, "5,137 findings" ungrouped. Null until
 *  the read it counts has answered. */
export function findingsCountLine(
  group: FindingsGroupBy,
  groupsTotal: number | null | undefined,
  findingsTotal: number | null | undefined,
): string | null {
  if (group === "none") return findingsTotal == null ? null : plural(findingsTotal, "finding", "findings");
  if (groupsTotal == null) return null;
  const head = `${countWords(groupsTotal)} ${groupNoun(group, groupsTotal)}`;
  return findingsTotal == null ? head : `${head} (${plural(findingsTotal, "finding", "findings")})`;
}

/** findingsEmptyHint is the empty state's line for a view with no rows.
 *  Grouping by package lists dependency findings only. */
export function findingsEmptyHint(f: FindingsFilters): string {
  if (f.group === "package") return "No dependency findings in this view.";
  const narrowed =
    f.severity.length > 0 ||
    f.category.length > 0 ||
    f.driver.length > 0 ||
    f.ecosystem.length > 0 ||
    f.language.length > 0 ||
    f.project.length > 0 ||
    f.baseline.length > 0 ||
    Boolean(f.rule || f.pkg || f.path || f.q);
  if (narrowed) return "No findings match these filters.";
  if (f.status === "open") return "No open findings. Run a scan to check again.";
  return "No findings with this status.";
}
