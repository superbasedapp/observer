import { test } from "node:test";
import assert from "node:assert/strict";
import {
  commitHref,
  failingRuns,
  findingWhere,
  heldApproveHref,
  projectFilterLabel,
  projectHref,
  projectLabel,
  projectScanState,
  scanJobLine,
  scanProgress,
  scanSummary,
  scanToast,
  sessionHref,
  sortProjects,
  worstSeverity,
  type ScanJob,
  type SecurityProject,
} from "./codeSecurity.ts";

const HASH = "9afe4a86fa816d7b0a3fd01f80c25cbc449770305d468251aa8f1ed1c6d0b018";

function row(over: Partial<SecurityProject>): SecurityProject {
  return {
    project_root_hash: HASH,
    name: "",
    active: true,
    state: "clean",
    reason: "clean",
    blocking: 0,
    open: 0,
    counts: [],
    runs: [],
    ...over,
  };
}

// The regression: a project row never renders as its root hash (whose
// 12-character prefix read as a git commit id).
test("projectLabel names a project, never its hash", () => {
  assert.equal(projectLabel(row({ name: "superbased-observer" })), "superbased-observer");
  assert.equal(projectLabel(row({ root_path: "/mnt/d/programsx/test-project" })), "test-project");
  assert.equal(projectLabel(row({ root_path: "D:\\code\\app\\" })), "app");
  const unknown = projectLabel(row({}));
  assert.match(unknown, /^Unknown project \(9afe4a86\)$/);
  for (const r of [row({ name: "x" }), row({ root_path: "/a/b" }), row({})]) {
    assert.notEqual(projectLabel(r), HASH.slice(0, 12));
  }
});

// A Findings project filter the status read cannot resolve (a stale link)
// says so; before the read answers it is the short-hash form; never the
// bare value.
test("projectFilterLabel names a filter value honestly", () => {
  const index = new Map([[HASH, row({ name: "superbased-observer" })]]);
  const other = "f0291b30a69afb1097ff664423afc98c27da82659e501bd7bf1a974d98611ae3";
  assert.equal(projectFilterLabel(HASH, index), "superbased-observer");
  assert.equal(projectFilterLabel(other, index), "Project no longer tracked (f0291b30)");
  assert.equal(projectFilterLabel(other, new Map()), "Project no longer tracked (f0291b30)");
  assert.equal(projectFilterLabel(other, null), "Unknown project (f0291b30)");
  for (const label of [projectFilterLabel(other, index), projectFilterLabel(other, null)]) {
    assert.notEqual(label, other);
  }
});

test("links resolve to the existing detail views, or null", () => {
  assert.equal(projectHref(5), "/projects?project=5");
  assert.equal(projectHref(undefined), null);
  assert.equal(projectHref(0), null);
  assert.equal(commitHref(5, "abc123"), "/projects?project=5&dtab=commits&sha=abc123");
  assert.equal(commitHref(undefined, "abc123"), null);
  assert.equal(sessionHref("s A"), "/sessions?session=s%20A");
  assert.equal(sessionHref(""), null);
});

test("findingWhere", () => {
  assert.equal(findingWhere({ rel_path: "a.go", start_line: 3 }), "a.go:3");
  assert.equal(findingWhere({ rel_path: "a.go", start_line: 0 }), "a.go");
  assert.equal(findingWhere({ rel_path: "", start_line: 0 }), "the project");
});

test("sortProjects puts what needs attention first", () => {
  const got = sortProjects([
    row({ name: "c", state: "clean" }),
    row({ name: "idle", state: "clean", active: false, open: 0 }),
    row({ name: "b", state: "dirty", open: 1 }),
    row({ name: "a", state: "blocking", open: 1 }),
    row({ name: "many", state: "clean", open: 9 }),
  ]).map((r) => r.name);
  assert.deepEqual(got, ["a", "b", "many", "c", "idle"]);
});

test("worstSeverity and failingRuns", () => {
  assert.equal(worstSeverity([{ category: "x", severity: "low", n: 1 }, { category: "x", severity: "high", n: 2 }]), "high");
  assert.equal(worstSeverity([]), "");
  const runs = [
    { driver: "native", scope: "commit", outcome: "clean", findings: 0, started_at: "", duration_ms: 0 },
    { driver: "scalibr", scope: "scheduled", outcome: "failed", findings: 0, started_at: "", duration_ms: 0 },
  ];
  assert.deepEqual(failingRuns(runs).map((r) => r.driver), ["scalibr"]);
});

test("scanSummary", () => {
  const s = scanSummary([
    row({ state: "blocking", open: 2, last_scan_at: "2026-11-02T10:00:00Z" }),
    row({ open: 1, last_scan_at: "2026-11-02T12:00:00Z", runs: [{ driver: "osv", scope: "s", outcome: "not_scanned", findings: 0, started_at: "", duration_ms: 0 }] }),
  ]);
  assert.deepEqual(s, { projects: 2, blocking: 1, open: 3, failing: 1, lastScanAt: "2026-11-02T12:00:00Z" });
});

function job(over: Partial<ScanJob>): ScanJob {
  return { id: "j", state: "running", scope: "all", started_at: "", total: 4, done: 1, projects: [], ...over };
}

test("scan job lines, progress and toast", () => {
  const running = job({ current: { project_root_hash: HASH, name: "app", step: "Code rules" } });
  assert.equal(scanJobLine(running), "Scanning 1 of 4 projects: Code rules on app");
  assert.equal(scanProgress(running), 0.25);
  assert.equal(projectScanState(running, HASH), "scanning");
  assert.equal(projectScanState(running, "other"), "blocked");
  assert.equal(projectScanState(null, HASH), "idle");
  const done = job({
    state: "done",
    scope: "project",
    total: 1,
    done: 1,
    projects: [{ project_root_hash: HASH, name: "app", steps: [{ id: "code", label: "Code", outcome: "findings", findings: 2, new: 1 }] }],
  });
  assert.equal(scanJobLine(done), "Scanned app: 2 finding(s), 1 new");
  assert.equal(scanToast(done).variant, "warn");
  const failed = job({
    state: "done",
    total: 1,
    done: 1,
    projects: [{ project_root_hash: HASH, name: "app", steps: [{ id: "deps", label: "Deps", outcome: "failed", findings: 0, new: 0 }] }],
  });
  assert.equal(scanToast(failed).variant, "danger");
  assert.match(scanJobLine(failed), /1 step\(s\) failed/);
});

// The finding drawer's approve pointer (dashboard CLI parity plan B-CS7): an
// open finding that holds a commit links to its verdict on Security >
// Verdicts, where the commit gate's approve lives; any other finding links
// nowhere.
test("heldApproveHref points at Security > Verdicts for an open finding holding a commit", () => {
  const cases: { name: string; status: string; commits: unknown[]; want: string | null }[] = [
    { name: "open, held", status: "open", commits: [{ sha: "a" }], want: "/security?tab=verdicts" },
    { name: "open, holds nothing", status: "open", commits: [], want: null },
    { name: "closed, held", status: "fixed", commits: [{ sha: "a" }], want: null },
  ];
  for (const c of cases) assert.equal(heldApproveHref({ status: c.status }, c.commits), c.want, c.name);
});
