// scannerProblems is the Code security page's one rule table for scanner
// problems (redesign plan docs/plans/code-security-page-redesign-plan-
// 2026-11-06.md, sections 3.3, 3.4 and 5, "one message per fact"): which
// reasons mean a scanner is not set up (a setup notice shown ONCE, never a
// failing scan on every project), which mean it is off by choice, and which
// mean its scans are failing, with the words and the one next step for each.
//
// Built from two reads the page already holds: each project's newest run per
// driver (GET /api/security/status `runs`) and the scanners a manual scan
// cannot start (GET /api/security/scan `steps`, ready false). Rows group by
// (scanner, reason), so a missing tool is one row that names how many
// projects it left unchecked, not one pill per project.
//
// The reason vocabularies this reads (grounded 2026-11-06):
//   - run reasons: internal/secscan/depscan/types.go (the closed EcoResult /
//     run reasons), depscan/rules.go (no_packages, no_ecosystem_scanned,
//     partial_coverage), depdriver.failReason (budget_exceeded,
//     driver_unverified, canceled);
//   - step reasons (free text): cmd/observer/security_scan_now_*.go
//     ("not selected (<component>)", "Opengrep is not installed",
//     "<engine> is not installed", "not in this build", "no database in
//     this process"), and the job's "not in this process".
//
// Pure: no fetch, no React (scannerProblems.test.ts runs under node --test).

import { failingRuns, reasonWords, type ScanStep, type SecurityProject } from "./codeSecurity.ts";

/** How a scanner problem reads: its scans fail, it needs setting up, or it
 *  is off (by choice, or not available on this build or platform). Setup and
 *  off are both setup facts (`setup` true); only setup and failing need the
 *  person's attention. */
export type ScannerProblemKind = "failing" | "setup" | "off";

/** The page tab a problem's next step opens. */
export type ScannerProblemTab = "scanners" | "projects" | "findings" | "coverage";

export type ScannerProblemAction = { label: string; tab: ScannerProblemTab };

export type ScannerProblem = {
  /** A run's driver id (scalibr, osv, opengrep, ...), or a not-ready scan
   *  step's id (code, deps, iac.trivy, ...). */
  driver: string;
  reason: string;
  /** The problem in words, naming the scanner ("osv-scanner is not installed"). */
  words: string;
  /** A setup fact (not set up, or off), never a failing scan. */
  setup: boolean;
  kind: ScannerProblemKind;
  /** Root hashes of the projects it left unchecked; empty for a scanner
   *  that is off or not set up for every project alike. */
  projects: string[];
  action: ScannerProblemAction | null;
};

// ---- the rule table (walked top-down, first match wins) ----

type RuleKind = ScannerProblemKind | "none";

type ReasonRule = {
  /** Exact reason ids. */
  reasons: readonly string[];
  /** A free-text scan step reason the row also covers. */
  pattern?: RegExp;
  /** "none": not a scanner problem (nothing to scan, the person cancelled,
   *  or a coverage gap the Coverage tab shows). */
  kind: RuleKind;
  /** What the scanner is or did, after its name. */
  phrase: string;
  action: ScannerProblemAction | null;
};

const TO_SCANNERS = (label: string): ScannerProblemAction => ({ label, tab: "scanners" });
const TO_PROJECTS: ScannerProblemAction = { label: "See the projects", tab: "projects" };
const TO_COVERAGE: ScannerProblemAction = { label: "See coverage", tab: "coverage" };

/** REASON_RULES maps each reason to its kind, words and next step. Exported
 *  for the table test (one case per row). */
export const REASON_RULES: readonly ReasonRule[] = [
  // Off by choice: the component is not selected.
  {
    reasons: ["not_selected", "disabled", "not_enabled"],
    pattern: /^not selected\b/i,
    kind: "off",
    phrase: "is turned off",
    action: TO_SCANNERS("Turn it on"),
  },
  // Not available here: nothing to set up.
  {
    reasons: ["not_compiled", "not_in_build", "not in this build", "not in this process"],
    kind: "off",
    phrase: "is not in this build",
    action: null,
  },
  { reasons: ["unsupported_platform"], kind: "off", phrase: "does not run on this platform", action: null },
  { reasons: ["no database in this process"], kind: "off", phrase: "cannot run from this dashboard", action: null },
  // Needs setting up: one step the person takes once.
  {
    reasons: ["not_installed"],
    pattern: / is not installed$/i,
    kind: "setup",
    phrase: "is not installed",
    action: TO_SCANNERS("Install it or turn it off"),
  },
  {
    reasons: ["database_missing", "no_database"],
    kind: "setup",
    phrase: "has no vulnerability database yet",
    action: TO_SCANNERS("Get the database"),
  },
  {
    reasons: ["database_not_accepted"],
    kind: "setup",
    phrase: "is waiting for you to accept its database download",
    action: TO_SCANNERS("Review the download"),
  },
  {
    reasons: ["lookup_not_chosen"],
    kind: "setup",
    phrase: "has no package data source chosen",
    action: TO_SCANNERS("Choose a source"),
  },
  {
    reasons: ["remote_not_accepted"],
    kind: "setup",
    phrase: "is waiting for your consent to online checks",
    action: TO_SCANNERS("Review online checks"),
  },
  // Failing: the scan ran or tried to, and the projects were not checked.
  {
    reasons: ["isolation_refused"],
    kind: "failing",
    phrase: "could not start its isolated scan, so nothing was checked",
    action: TO_PROJECTS,
  },
  {
    reasons: ["driver_unverified"],
    kind: "failing",
    phrase: "could not be verified, so it did not run",
    action: TO_SCANNERS("Check the install"),
  },
  {
    reasons: ["self_test_failed", "no_self_test_for_ecosystem"],
    kind: "failing",
    phrase: "failed its self-test, so its results were not used",
    action: TO_COVERAGE,
  },
  {
    reasons: ["remote_unavailable", "remote_lookup_failed"],
    kind: "failing",
    phrase: "could not reach the online package data",
    action: TO_COVERAGE,
  },
  {
    reasons: ["no_ecosystem_scanned"],
    kind: "failing",
    phrase: "found dependency files but could not check any of them",
    action: TO_COVERAGE,
  },
  { reasons: ["budget_exceeded"], kind: "failing", phrase: "ran past its time or output limit", action: TO_PROJECTS },
  { reasons: ["engine_failed", "match_failed"], kind: "failing", phrase: "failed while scanning", action: TO_PROJECTS },
  // Not a scanner problem: nothing to scan, a cancelled run, or a partial
  // run whose gaps the Coverage tab lists file by file.
  { reasons: ["", "no_packages", "canceled", "partial_coverage"], kind: "none", phrase: "", action: null },
];

function ruleFor(reason: string): ReasonRule | undefined {
  const r = reason.trim();
  return REASON_RULES.find((x) => x.reasons.includes(r) || (x.pattern?.test(r) ?? false));
}

function isSetupKind(k: RuleKind | undefined): k is "setup" | "off" {
  return k === "setup" || k === "off";
}

/** SETUP_REASONS are the reason ids that mean a scanner is not set up (or
 *  is off): a setup notice shown once, never a failing scan. The free-text
 *  scan step forms ("not selected (...)", "X is not installed") are matched
 *  by isSetupReason too. */
export const SETUP_REASONS: readonly string[] = REASON_RULES.filter((r) => isSetupKind(r.kind)).flatMap((r) =>
  r.reasons.filter(Boolean),
);

/** isSetupReason reports whether a run or step reason is a setup fact (the
 *  scanner is not installed, not turned on, has no database, ...), which is
 *  shown once as a notice and never counted as a failing scan. */
export function isSetupReason(reason?: string): boolean {
  if (!reason) return false;
  return isSetupKind(ruleFor(reason)?.kind);
}

// ---- names ----

/** The name a run's driver goes by in a sentence. */
const DRIVER_NAMES: Readonly<Record<string, string>> = {
  native: "The built-in scanner",
  scalibr: "SCALIBR",
  osv: "osv-scanner",
  opengrep: "Opengrep",
  gitleaks: "Gitleaks",
  trivy: "Trivy",
  "trivy-config": "Trivy",
  "trivy-image": "The Trivy image scan",
  kics: "KICS",
  actionlint: "actionlint",
  "sarif-import": "SARIF import",
  custom: "A custom scanner",
};

/** The name a scan step goes by in a sentence (the step's own label otherwise). */
const STEP_NAMES: Readonly<Record<string, string>> = {
  history: "The commit history scan",
  deps: "Dependency scanning",
  code: "Opengrep",
  actionlint: "actionlint",
  "iac.trivy": "Trivy",
  "iac.kics": "KICS",
};

/** The run drivers each scan step stands for: a not-ready step's notice
 *  absorbs those drivers' setup facts, so one fact shows once. */
const STEP_DRIVERS: Readonly<Record<string, readonly string[]>> = {
  deps: ["scalibr", "osv"],
  code: ["opengrep"],
  actionlint: ["actionlint"],
  "iac.trivy": ["trivy", "trivy-config"],
  "iac.kics": ["kics"],
};

/** scannerName is a run driver's name in a sentence. */
export function scannerName(driver: string): string {
  return DRIVER_NAMES[driver] ?? driver;
}

function stepName(s: ScanStep): string {
  return STEP_NAMES[s.id] ?? (s.label || s.id);
}

// ---- building the rows ----

const KIND_ORDER: Readonly<Record<ScannerProblemKind, number>> = { failing: 0, setup: 1, off: 2 };

function runProblem(driver: string, outcome: string, reason: string): Omit<ScannerProblem, "projects"> | null {
  const key = reason || (outcome === "failed" ? "engine_failed" : "");
  const rule = ruleFor(key);
  const name = scannerName(driver);
  if (rule) {
    if (rule.kind === "none") return null;
    return { driver, reason: key, words: `${name} ${rule.phrase}`, setup: isSetupKind(rule.kind), kind: rule.kind, action: rule.action };
  }
  // A reason no row knows: a failing scan, in the reason's own words.
  const what = outcome === "failed" ? "failed" : "did not scan";
  return { driver, reason: key, words: `${name} ${what}: ${reasonWords(key)}`, setup: false, kind: "failing", action: TO_PROJECTS };
}

function stepProblem(s: ScanStep): Omit<ScannerProblem, "projects"> {
  const reason = (s.reason ?? "").trim();
  const rule = ruleFor(reason);
  const name = stepName(s);
  // Every not-ready step is a setup fact: it never ran, so nothing failed.
  if (rule && isSetupKind(rule.kind)) {
    return { driver: s.id, reason, words: `${name} ${rule.phrase}`, setup: true, kind: rule.kind, action: rule.action };
  }
  return {
    driver: s.id,
    reason,
    words: reason ? `${name} cannot run: ${reason}` : `${name} cannot run here`,
    setup: true,
    kind: "setup",
    action: TO_SCANNERS("Open Scanners"),
  };
}

/**
 * scannerProblems lists every scanner problem once, grouped by (scanner,
 * reason): one row per driver and reason across the projects' newest runs,
 * plus one row per scan step that cannot start. A not-ready step's row takes
 * in its drivers' setup rows (with their projects), so "Opengrep is not
 * installed" never shows twice. Failing rows come first, then setup, then
 * off; within a kind, the most projects first.
 */
export function scannerProblems(projects: SecurityProject[], steps: ScanStep[]): ScannerProblem[] {
  const rows = new Map<string, ScannerProblem>();
  for (const p of projects) {
    for (const r of failingRuns(p.runs ?? [])) {
      const base = runProblem(r.driver, r.outcome, r.reason ?? "");
      if (!base) continue;
      const k = `run|${base.driver}|${base.reason}`;
      const row = rows.get(k) ?? { ...base, projects: [] };
      if (!row.projects.includes(p.project_root_hash)) row.projects.push(p.project_root_hash);
      rows.set(k, row);
    }
  }
  for (const s of steps) {
    if (s.ready) continue;
    const row: ScannerProblem = { ...stepProblem(s), projects: [] };
    const drivers = STEP_DRIVERS[s.id] ?? [];
    for (const [k, r] of rows) {
      if (!k.startsWith("run|") || !r.setup || !drivers.includes(r.driver)) continue;
      for (const h of r.projects) if (!row.projects.includes(h)) row.projects.push(h);
      rows.delete(k);
    }
    rows.set(`step|${s.id}`, row);
  }
  return [...rows.values()].sort(
    (a, b) =>
      KIND_ORDER[a.kind] - KIND_ORDER[b.kind] ||
      b.projects.length - a.projects.length ||
      a.words.localeCompare(b.words),
  );
}

/** problemCounts counts the distinct scanners per kind (a scanner with two
 *  failing reasons counts once): what the posture line and the Overview
 *  tile say. */
export function problemCounts(problems: readonly ScannerProblem[]): { failing: number; setup: number; off: number; attention: number } {
  const by: Record<ScannerProblemKind, Set<string>> = { failing: new Set(), setup: new Set(), off: new Set() };
  for (const p of problems) by[p.kind].add(p.driver);
  const attention = new Set([...by.failing, ...by.setup]);
  return { failing: by.failing.size, setup: by.setup.size, off: by.off.size, attention: attention.size };
}
