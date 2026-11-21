// Component tests of the Code security Overview's lists
// (web/src/pages/codesecurity/OverviewTab.tsx), rendered with
// react-dom/server under node's test runner (scripts/test-components.mjs).
// What they pin: a "Needs attention" row names the issue (a dependency by
// its package, anything else by its message) with its worst severity and
// how many projects have it, and links to exactly that issue's findings; the
// scanner problems list says each problem once with its next step, keeps the
// scanners that are off as quiet lines, and says so plainly when nothing is
// wrong.

import { test } from "node:test";
import assert from "node:assert/strict";
import type { ReactElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import { IssueList, ProblemList, issueLines } from "@/pages/codesecurity/OverviewTab";
import { EMPTY_FINDINGS_FILTERS, findingsHref, groupDrillDown, type FindingGroup } from "@/lib/codeSecurityApi";
import { scannerProblems } from "@/lib/scannerProblems";
import type { ScanStep, SecurityProject } from "@/lib/codeSecurity";

const DEP: FindingGroup = {
  key: "dep-1",
  rule_id: "GHSA-p6mc-m468-83gw",
  category: "vulnerable_dependency",
  ecosystem: "npm",
  package: "lodash@4.17.20",
  message: "Prototype pollution in lodash",
  count: 20,
  projects: 20,
  max_severity: "high",
  first_seen: "2026-11-01T00:00:00Z",
  last_seen: "2026-11-06T00:00:00Z",
};

const SECRET: FindingGroup = {
  key: "sec-1",
  rule_id: "generic-api-key",
  category: "secret",
  rel_path: "config/dev.env",
  message: "Generic API key",
  count: 1,
  projects: 1,
  max_severity: "critical",
  first_seen: "2026-11-01T00:00:00Z",
  last_seen: "2026-11-06T00:00:00Z",
};

function html(node: ReactElement): string {
  return renderToStaticMarkup(<MemoryRouter>{node}</MemoryRouter>);
}

test("issueLines: a dependency by its package, anything else by its message", () => {
  assert.deepEqual(issueLines(DEP), { title: "lodash@4.17.20", detail: "npm · Prototype pollution in lodash" });
  assert.deepEqual(issueLines(SECRET), { title: "Generic API key", detail: "generic-api-key · config/dev.env" });
  assert.deepEqual(issueLines({ ...SECRET, message: undefined }), { title: "generic-api-key", detail: "config/dev.env" });
});

test("a Needs attention row shows severity, the issue and its project count, and links to its findings", () => {
  const out = html(<IssueList groups={[SECRET, DEP]} />);
  assert.match(out, /critical/);
  assert.match(out, /Generic API key/);
  assert.match(out, /1 project</);
  assert.match(out, /lodash@4\.17\.20/);
  assert.match(out, /20 projects</);
  for (const g of [SECRET, DEP]) {
    const href = findingsHref(groupDrillDown("issue", g, EMPTY_FINDINGS_FILTERS)).replaceAll("&", "&amp;");
    assert.ok(out.includes(`href="${href}"`), `missing link ${href}`);
  }
  // The drill-down is the ungrouped list of that one issue.
  assert.match(findingsHref(groupDrillDown("issue", DEP, EMPTY_FINDINGS_FILTERS)), /tab=findings.*group=none/);
});

function project(hash: string, runs: SecurityProject["runs"]): SecurityProject {
  return { project_root_hash: hash, name: hash, active: true, state: "clean", reason: "clean", blocking: 0, open: 0, counts: [], runs };
}

test("scanner problems: each once with its next step; scanners that are off stay quiet", () => {
  const projects = ["a", "b"].map((h) =>
    project(h, [{ driver: "osv", scope: "scheduled", outcome: "not_scanned", reason: "not_installed", findings: 0, started_at: "", duration_ms: 0 }]),
  );
  const steps: ScanStep[] = [{ id: "code", label: "Code rules (Opengrep)", ready: false, reason: "not selected (security.scan.opengrep)" }];
  const out = html(<ProblemList problems={scannerProblems(projects, steps)} onOpenTab={() => {}} />);
  assert.equal(out.match(/osv-scanner is not installed/g)?.length, 1, "one row, not one per project");
  assert.match(out, /2 projects not checked with it/);
  assert.match(out, /Install it or turn it off/);
  assert.match(out, /Off on this machine/);
  assert.match(out, /Opengrep is turned off/);
  assert.doesNotMatch(out, /security\.scan/, "no config key on screen");
  assert.doesNotMatch(out, /ran without a problem/);
});

test("scanner problems: nothing wrong says so", () => {
  const out = html(<ProblemList problems={[]} onOpenTab={() => {}} />);
  assert.match(out, /Every scanner that is on ran without a problem\./);
  assert.doesNotMatch(out, /Off on this machine/);
});
