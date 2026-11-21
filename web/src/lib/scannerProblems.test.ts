// Pins the Code security page's scanner problem rules
// (src/lib/scannerProblems.ts): one case per rule row (the reason's kind,
// whether it is a setup fact, its words and its next step), then the
// grouping rules: one row per (scanner, reason) across projects, a not-ready
// scan step absorbing its drivers' setup facts, the order, and the counts.
// The regression it guards: a scanner that is not installed read
// "osv: not scanned" on every project and counted as 96 failing scans.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  REASON_RULES,
  SETUP_REASONS,
  isSetupReason,
  problemCounts,
  scannerName,
  scannerProblems,
  type ScannerProblemKind,
  type ScannerProblemTab,
} from "./scannerProblems.ts";
import type { ScanStep, SecurityProject, SecurityRun } from "./codeSecurity.ts";

function run(driver: string, outcome: string, reason?: string): SecurityRun {
  return { driver, scope: "scheduled", outcome, reason, findings: 0, started_at: "2026-11-06T10:00:00Z", duration_ms: 10 };
}

function project(hash: string, runs: SecurityRun[]): SecurityProject {
  return { project_root_hash: hash, name: hash, active: true, state: "clean", reason: "clean", blocking: 0, open: 0, counts: [], runs };
}

function step(id: string, ready: boolean, reason?: string, label = id): ScanStep {
  return { id, label, ready, reason };
}

// One case per rule row, in table order: a representative reason, the
// outcome it arrives with, and what the row must say.
const RULE_CASES: {
  reason: string;
  outcome: string;
  kind: ScannerProblemKind | "none";
  words?: RegExp;
  tab?: ScannerProblemTab | null;
}[] = [
  { reason: "not_selected", outcome: "not_scanned", kind: "off", words: /^osv-scanner is turned off$/, tab: "scanners" },
  { reason: "not_compiled", outcome: "not_scanned", kind: "off", words: /is not in this build$/, tab: null },
  { reason: "unsupported_platform", outcome: "not_scanned", kind: "off", words: /does not run on this platform$/, tab: null },
  { reason: "no database in this process", outcome: "not_scanned", kind: "off", words: /cannot run from this dashboard$/, tab: null },
  { reason: "not_installed", outcome: "not_scanned", kind: "setup", words: /^osv-scanner is not installed$/, tab: "scanners" },
  { reason: "database_missing", outcome: "not_scanned", kind: "setup", words: /no vulnerability database/, tab: "scanners" },
  { reason: "database_not_accepted", outcome: "not_scanned", kind: "setup", words: /accept its database download/, tab: "scanners" },
  { reason: "lookup_not_chosen", outcome: "not_scanned", kind: "setup", words: /no package data source/, tab: "scanners" },
  { reason: "remote_not_accepted", outcome: "not_scanned", kind: "setup", words: /consent to online checks/, tab: "scanners" },
  { reason: "isolation_refused", outcome: "failed", kind: "failing", words: /could not start its isolated scan/, tab: "projects" },
  { reason: "driver_unverified", outcome: "failed", kind: "failing", words: /could not be verified/, tab: "scanners" },
  { reason: "self_test_failed", outcome: "not_scanned", kind: "failing", words: /self-test/, tab: "coverage" },
  { reason: "remote_unavailable", outcome: "not_scanned", kind: "failing", words: /online package data/, tab: "coverage" },
  { reason: "no_ecosystem_scanned", outcome: "not_scanned", kind: "failing", words: /could not check any/, tab: "coverage" },
  { reason: "budget_exceeded", outcome: "failed", kind: "failing", words: /time or output limit/, tab: "projects" },
  { reason: "engine_failed", outcome: "failed", kind: "failing", words: /failed while scanning/, tab: "projects" },
  { reason: "no_packages", outcome: "not_scanned", kind: "none" },
];

test("every rule row has a case, in table order", () => {
  assert.equal(RULE_CASES.length, REASON_RULES.length);
  RULE_CASES.forEach((c, i) => {
    const row = REASON_RULES[i];
    assert.ok(row.reasons.includes(c.reason), `row ${i} (${row.reasons.join(",")}) has no case`);
    assert.equal(row.kind, c.kind, c.reason);
  });
});

for (const c of RULE_CASES) {
  test(`reason ${c.reason}: ${c.kind}`, () => {
    const out = scannerProblems([project("h1", [run("osv", c.outcome, c.reason)])], []);
    if (c.kind === "none") {
      assert.deepEqual(out, []);
      assert.equal(isSetupReason(c.reason), false);
      return;
    }
    assert.equal(out.length, 1);
    const p = out[0];
    assert.equal(p.kind, c.kind);
    assert.equal(p.setup, c.kind === "setup" || c.kind === "off");
    assert.equal(isSetupReason(c.reason), p.setup);
    assert.match(p.words, c.words!);
    assert.equal(p.action?.tab ?? null, c.tab);
    assert.deepEqual(p.projects, ["h1"]);
    // Never a config key or a raw snake_case reason in the words.
    assert.doesNotMatch(p.words, /[a-z]+_[a-z]+/);
  });
}

test("isSetupReason: the free-text scan step reasons and the edges", () => {
  const cases: [string | undefined, boolean][] = [
    ["not selected (security.scan.opengrep)", true],
    ["not selected (security.scan.scalibr or security.scan.osv)", true],
    ["Opengrep is not installed", true],
    ["trivy is not installed", true],
    ["not in this build", true],
    ["not in this process", true],
    ["no database in this process", true],
    ["disabled", true],
    ["no_database", true],
    ["isolation_refused", false],
    ["engine_failed", false],
    ["partial_coverage", false],
    ["no_packages", false],
    ["some error the config loader printed", false],
    ["", false],
    [undefined, false],
  ];
  for (const [reason, want] of cases) assert.equal(isSetupReason(reason), want, String(reason));
});

test("SETUP_REASONS lists exactly the setup and off ids of the table", () => {
  for (const r of SETUP_REASONS) assert.equal(isSetupReason(r), true, r);
  for (const r of ["not_installed", "not_compiled", "unsupported_platform", "database_missing", "database_not_accepted"]) {
    assert.ok(SETUP_REASONS.includes(r), r);
  }
  for (const r of ["isolation_refused", "engine_failed", "", "no_packages"]) assert.ok(!SETUP_REASONS.includes(r), r);
});

test("a missing tool is ONE row naming every project it left unchecked", () => {
  const projects = ["a", "b", "c"].map((h) => project(h, [run("osv", "not_scanned", "not_installed"), run("scalibr", "clean")]));
  const out = scannerProblems(projects, [step("deps", true)]);
  assert.equal(out.length, 1);
  assert.equal(out[0].words, "osv-scanner is not installed");
  assert.deepEqual(out[0].projects, ["a", "b", "c"]);
  assert.equal(problemCounts(out).failing, 0, "a setup fact is never a failing scan");
  assert.equal(problemCounts(out).setup, 1);
});

test("rows group by scanner AND reason; a clean or findings run is no problem", () => {
  const out = scannerProblems(
    [
      project("a", [run("scalibr", "failed", "isolation_refused"), run("native", "findings")]),
      project("b", [run("scalibr", "failed", "isolation_refused"), run("osv", "not_scanned", "not_installed")]),
      project("c", [run("scalibr", "failed", "engine_failed"), run("native", "clean")]),
    ],
    [],
  );
  assert.deepEqual(
    out.map((p) => [p.driver, p.reason, p.projects.length]),
    [
      ["scalibr", "isolation_refused", 2],
      ["scalibr", "engine_failed", 1],
      ["osv", "not_installed", 1],
    ],
  );
  const c = problemCounts(out);
  assert.equal(c.failing, 1, "scalibr counts once with two failing reasons");
  assert.equal(c.setup, 1);
  assert.equal(c.attention, 2);
});

test("a failed run with no reason reads as an engine failure; an unknown reason keeps its words", () => {
  const out = scannerProblems([project("a", [run("opengrep", "failed"), run("kics", "not_scanned", "weird_state")])], []);
  const byDriver = Object.fromEntries(out.map((p) => [p.driver, p]));
  assert.equal(byDriver.opengrep.reason, "engine_failed");
  assert.equal(byDriver.opengrep.words, "Opengrep failed while scanning");
  assert.equal(byDriver.kics.kind, "failing");
  assert.equal(byDriver.kics.words, "KICS did not scan: weird state");
  assert.equal(byDriver.kics.action?.tab, "projects");
});

test("a not-ready step is a setup fact that absorbs its drivers' setup rows", () => {
  const projects = [
    project("a", [run("opengrep", "not_scanned", "not_installed")]),
    project("b", [run("opengrep", "not_scanned", "not_installed"), run("opengrep", "failed", "engine_failed")]),
  ];
  const out = scannerProblems(projects, [
    step("code", false, "Opengrep is not installed", "Code rules (Opengrep)"),
    step("history", true),
  ]);
  const setup = out.filter((p) => p.setup);
  assert.equal(setup.length, 1, "Opengrep is not installed shows once");
  assert.equal(setup[0].driver, "code");
  assert.equal(setup[0].words, "Opengrep is not installed");
  assert.deepEqual(setup[0].projects, ["a", "b"]);
  // A failing row of the same driver stays its own row.
  assert.ok(out.some((p) => p.driver === "opengrep" && p.reason === "engine_failed"));
});

test("a step that is not selected is off, never counted as needing setup, and its words name no config key", () => {
  const out = scannerProblems([], [
    step("code", false, "not selected (security.scan.opengrep)", "Code rules (Opengrep)"),
    step("iac.kics", false, "not in this build", "IaC misconfigurations (KICS)"),
  ]);
  assert.deepEqual(
    out.map((p) => [p.kind, p.words]),
    [
      ["off", "KICS is not in this build"],
      ["off", "Opengrep is turned off"],
    ],
  );
  for (const p of out) assert.doesNotMatch(p.words, /security\.scan/);
  assert.deepEqual(problemCounts(out), { failing: 0, setup: 0, off: 2, attention: 0 });
});

test("a step that cannot start for an unlisted reason is setup with its reason", () => {
  const out = scannerProblems([], [step("deps", false, "config: read failed", "Dependencies (OSV)")]);
  assert.equal(out.length, 1);
  assert.equal(out[0].kind, "setup");
  assert.equal(out[0].setup, true);
  assert.equal(out[0].words, "Dependency scanning cannot run: config: read failed");
  assert.equal(out[0].action?.tab, "scanners");
});

test("order: failing, then setup, then off; the most projects first within a kind", () => {
  const out = scannerProblems(
    [
      project("a", [run("osv", "not_scanned", "not_installed"), run("scalibr", "failed", "isolation_refused")]),
      project("b", [run("osv", "not_scanned", "not_installed"), run("kics", "failed", "budget_exceeded")]),
      project("c", [run("osv", "not_scanned", "not_installed"), run("kics", "failed", "budget_exceeded")]),
    ],
    [step("code", false, "not selected (security.scan.opengrep)")],
  );
  assert.deepEqual(
    out.map((p) => `${p.kind}:${p.driver}`),
    ["failing:kics", "failing:scalibr", "setup:osv", "off:code"],
  );
});

test("scannerName names known drivers and keeps an unknown id", () => {
  assert.equal(scannerName("osv"), "osv-scanner");
  assert.equal(scannerName("scalibr"), "SCALIBR");
  assert.equal(scannerName("something-new"), "something-new");
});
