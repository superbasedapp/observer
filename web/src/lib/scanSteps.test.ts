import assert from "node:assert/strict";
import test from "node:test";

import {
  cellOf,
  clockLabel,
  defaultSteps,
  elapsedLabel,
  failedResults,
  jobOnlineSuffix,
  jobResultLine,
  jobStepIds,
  onlineFix,
  onlineFixLabel,
  onlineOption,
  onlineReasonWords,
  onlineResultNote,
  onlineSends,
  parseRemembered,
  parseRememberedOnline,
  runningParts,
  scanChoiceProblem,
  scanStartBody,
  startLabel,
  stepInfo,
  type TimedJob,
} from "./scanSteps.ts";
import type { ScanOnline, ScanStep } from "./codeSecurity.ts";
import { scanStepReasonWords } from "./scanSteps.ts";

test("scanStepReasonWords: a switched-off scanner reads turned off, never its component key", () => {
  assert.equal(scanStepReasonWords("not selected (security.scan.opengrep)"), "turned off");
  assert.equal(scanStepReasonWords("not selected (security.scan.scalibr or security.scan.osv)"), "turned off");
  assert.equal(scanStepReasonWords("not_installed"), "not installed");
  assert.equal(scanStepReasonWords(undefined), "");
});

const STEPS: ScanStep[] = [
  { id: "history", label: "Secrets", ready: true },
  { id: "deps", label: "Dependencies (OSV)", ready: true },
  { id: "code", label: "Code rules", ready: false, reason: "not_installed" },
];

function job(over: Partial<TimedJob> = {}): TimedJob {
  return {
    id: "j1",
    state: "done",
    scope: "all",
    started_at: "2026-11-06T10:00:00Z",
    finished_at: "2026-11-06T10:03:41Z",
    total: 2,
    done: 2,
    projects: [
      {
        project_root_hash: "a",
        name: "alpha",
        steps: [
          { id: "history", label: "Secrets", outcome: "findings", findings: 3, new: 2 },
          { id: "deps", label: "Dependencies", outcome: "failed", reason: "database_missing", findings: 0, new: 0 },
        ],
      },
      { project_root_hash: "b", name: "beta", steps: [{ id: "history", label: "Secrets", outcome: "clean", findings: 0, new: 0 }] },
    ],
    ...over,
  };
}

test("stepInfo knows the shipped steps and treats others generically", () => {
  const cases = [
    { id: "history", label: "", short: "Secrets", desc: /recent git history/ },
    { id: "iac.kics", label: "", short: "IaC (KICS)", desc: /Terraform/ },
    { id: "sbom.new", label: "SBOM check", short: "SBOM check", desc: /scanner/ },
    { id: "sbom.new", label: "", short: "sbom new", desc: /scanner/ },
  ];
  for (const c of cases) {
    const i = stepInfo(c.id, c.label);
    assert.equal(i.short, c.short, c.id);
    assert.match(i.description, c.desc, c.id);
  }
});

test("parseRemembered and defaultSteps", () => {
  assert.equal(parseRemembered(null), null);
  assert.equal(parseRemembered("{"), null);
  assert.equal(parseRemembered('{"a":1}'), null);
  assert.deepEqual(parseRemembered('["deps",3]'), ["deps"]);
  const cases = [
    { name: "nothing remembered", rem: null, want: ["history", "deps"] },
    { name: "remembered subset", rem: ["deps"], want: ["deps"] },
    { name: "remembered not ready is dropped", rem: ["code"], want: ["history", "deps"] },
    { name: "empty remembered", rem: [], want: ["history", "deps"] },
  ];
  for (const c of cases) assert.deepEqual(defaultSteps(STEPS, c.rem), c.want, c.name);
});

test("scanStartBody sends steps only when narrower than every ready step", () => {
  const ready = ["history", "deps"];
  assert.deepEqual(scanStartBody({ all: true, projects: [], chosen: ["deps", "history"], ready }), { all: true });
  assert.deepEqual(scanStartBody({ all: true, projects: [], chosen: ["deps"], ready }), { all: true, steps: ["deps"] });
  assert.deepEqual(scanStartBody({ all: false, projects: ["h1"], chosen: ready, ready }), { projects: ["h1"] });
  assert.deepEqual(scanStartBody({ all: false, projects: ["h1", "h2"], chosen: ["history"], ready }), {
    projects: ["h1", "h2"],
    steps: ["history"],
  });
});

test("scanStartBody sends online only when asked", () => {
  const ready = ["history", "deps"];
  assert.deepEqual(scanStartBody({ all: true, projects: [], chosen: ready, ready, online: true }), { all: true, online: true });
  assert.deepEqual(scanStartBody({ all: false, projects: ["h1"], chosen: ["deps"], ready, online: true }), {
    projects: ["h1"],
    steps: ["deps"],
    online: true,
  });
  assert.deepEqual(scanStartBody({ all: true, projects: [], chosen: ready, ready, online: false }), { all: true });
});

// The online dependency check (dashboard CLI parity plan, decision P-1).

test("parseRememberedOnline is on only for a stored true", () => {
  const cases: [string | null | undefined, boolean][] = [
    ["true", true],
    ["false", false],
    [null, false],
    [undefined, false],
    ["", false],
    ["1", false],
  ];
  for (const [raw, want] of cases) assert.equal(parseRememberedOnline(raw), want, String(raw));
});

test("online reasons: words, where each is fixed, and the fix's link text", () => {
  const cases: { reason: string | undefined; words: RegExp; fix: string; label: RegExp }[] = [
    { reason: "online_checks_off", words: /Online package checks are off/, fix: "package-checks", label: /Scanners > Package checks/ },
    { reason: "disclosure_not_shown", words: /disclosure has not been accepted/, fix: "package-checks", label: /Scanners > Package checks/ },
    { reason: "online_needs_scalibr", words: /SCALIBR/, fix: "scanners", label: /SCALIBR driver in Scanners/ },
    { reason: "online_unavailable", words: /No online check could be set up/, fix: "none", label: /^$/ },
    { reason: "something_new", words: /something new/, fix: "none", label: /^$/ },
    { reason: undefined, words: /^$/, fix: "none", label: /^$/ },
  ];
  for (const c of cases) {
    assert.match(onlineReasonWords(c.reason), c.words, String(c.reason));
    assert.equal(onlineFix(c.reason), c.fix, String(c.reason));
    assert.match(onlineFixLabel(onlineFix(c.reason)), c.label, String(c.reason));
  }
});

test("onlineSends names what leaves the machine, per node kind", () => {
  const individual = onlineSends(false);
  assert.match(individual, /api\.osv\.dev/);
  assert.match(individual, /submodule's pinned commit id/);
  assert.match(individual, /Private package names are withheld/);
  const relay = onlineSends(true);
  assert.match(relay, /organization's relay/);
  assert.doesNotMatch(relay, /api\.osv\.dev/);
  assert.match(relay, /not checked online on a managed node/);
});

test("onlineOption: shown with its step, ticked only while open and wanted", () => {
  const open: ScanOnline = { step: "deps", open: true };
  const off: ScanOnline = { step: "deps", open: false, reason: "online_checks_off" };
  const cases: { name: string; online?: ScanOnline; chosen: string[]; wanted: boolean; show: boolean; enabled: boolean; checked: boolean; fix: string }[] = [
    { name: "no online check on this node", chosen: ["deps"], wanted: true, show: false, enabled: false, checked: false, fix: "none" },
    { name: "its step not chosen", online: open, chosen: ["history"], wanted: true, show: false, enabled: false, checked: false, fix: "none" },
    { name: "open, not wanted", online: open, chosen: ["history", "deps"], wanted: false, show: true, enabled: true, checked: false, fix: "none" },
    { name: "open, wanted", online: open, chosen: ["deps"], wanted: true, show: true, enabled: true, checked: true, fix: "none" },
    { name: "closed, wanted: never ticked", online: off, chosen: ["deps"], wanted: true, show: true, enabled: false, checked: false, fix: "package-checks" },
  ];
  for (const c of cases) {
    const o = onlineOption({ online: c.online, chosen: c.chosen, wanted: c.wanted });
    assert.equal(o.show, c.show, c.name);
    assert.equal(o.enabled, c.enabled, c.name);
    assert.equal(o.checked, c.checked, c.name);
    assert.equal(o.fix, c.fix, c.name);
    if (c.show && !c.enabled) assert.match(o.blocked, /Online package checks are off/, c.name);
    if (c.show) assert.notEqual(o.sends, "", c.name);
  }
});

test("onlineResultNote and jobOnlineSuffix", () => {
  assert.equal(onlineResultNote({}), "");
  assert.equal(onlineResultNote({ online: "checked" }), "checked online");
  assert.equal(onlineResultNote({ online: "online_checks_off" }), "not checked online: online package checks are off");
  assert.match(onlineResultNote({ online: "online_needs_scalibr" }), /^not checked online: only the SCALIBR/);
  assert.equal(jobOnlineSuffix({ online: true }), " with online checks");
  assert.equal(jobOnlineSuffix({}), "");
});

test("scanChoiceProblem and startLabel", () => {
  assert.match(scanChoiceProblem({ projectCount: 1, stepCount: 1, readyCount: 0 }), /No scanner is ready/);
  assert.match(scanChoiceProblem({ projectCount: 0, stepCount: 1, readyCount: 2 }), /at least one project/);
  assert.match(scanChoiceProblem({ projectCount: 2, stepCount: 0, readyCount: 2 }), /at least one scanner/);
  assert.equal(scanChoiceProblem({ projectCount: 2, stepCount: 1, readyCount: 2 }), "");
  assert.equal(startLabel(1, 1), "Scan 1 project with 1 scanner");
  assert.equal(startLabel(12, 3), "Scan 12 projects with 3 scanners");
});

test("clockLabel and elapsedLabel", () => {
  assert.equal(clockLabel(0), "0:00");
  assert.equal(clockLabel(14_000), "0:14");
  assert.equal(clockLabel(221_000), "3:41");
  assert.equal(clockLabel(3_725_000), "1:02:05");
  assert.equal(clockLabel(-5), "0:00");
  const t = Date.parse("2026-11-06T10:00:00Z");
  assert.equal(elapsedLabel("2026-11-06T10:00:00Z", t + 14_000), "0:14");
  assert.equal(elapsedLabel(undefined, t), "");
  assert.equal(elapsedLabel("nonsense", t), "");
});

test("jobResultLine", () => {
  assert.equal(jobResultLine(job()), "Scanned 2 projects in 3:41: 2 new findings, 1 scanner failed");
  const clean = job({ projects: [{ project_root_hash: "b", name: "beta", steps: [{ id: "history", label: "S", outcome: "clean", findings: 0, new: 0 }] }] });
  assert.equal(jobResultLine(clean), "Scanned 2 projects in 3:41: no findings");
  const old = job({
    projects: [{ project_root_hash: "b", name: "beta", steps: [{ id: "history", label: "S", outcome: "findings", findings: 4, new: 0 }] }],
  });
  assert.equal(jobResultLine(old), "Scanned 2 projects in 3:41: 4 findings, none new");
  const one = job({ scope: "project", total: 1, done: 1, projects: [job().projects[1]] });
  assert.equal(jobResultLine(one), "Scanned beta in 3:41: no findings");
  assert.match(jobResultLine(job({ state: "cancelled", done: 1 })), /^Cancelled after 1 of 2 projects in 3:41: /);
  assert.match(jobResultLine(job({ finished_at: undefined })), /^Scanned 2 projects: /);
});

test("runningParts", () => {
  const j = job({
    state: "running",
    done: 2,
    total: 12,
    finished_at: undefined,
    current: { project_root_hash: "a", name: "design-options", step: "deps", step_id: "deps" },
  });
  assert.deepEqual(runningParts(j, STEPS), ["Scanning 3 of 12 projects", "design-options", "Dependencies (OSV)"]);
  const single = job({
    state: "running",
    scope: "project",
    total: 1,
    done: 0,
    current: { project_root_hash: "a", name: "alpha", step: "Secrets" },
  });
  assert.deepEqual(runningParts(single, STEPS), ["Scanning", "alpha", "Secrets"]);
  assert.deepEqual(runningParts(job({ state: "running", done: 0, current: undefined }), STEPS), ["Scanning 1 of 2 projects"]);
});

test("jobStepIds prefers the job's list, else the results'", () => {
  assert.deepEqual(jobStepIds(job({ steps: ["deps", "code"] })), ["deps", "code"]);
  assert.deepEqual(jobStepIds(job()), ["history", "deps"]);
});

test("cellOf covers every outcome", () => {
  const r = (outcome: string, extra: object = {}) => ({ id: "x", label: "X", outcome, findings: 0, new: 0, ...extra });
  const cases = [
    { name: "clean", opts: { result: r("clean", { duration_ms: 1500 }), running: false, jobRunning: false }, kind: "clean", label: "Clean", ms: 1500 },
    { name: "findings new", opts: { result: r("findings", { findings: 5, new: 2 }), running: false, jobRunning: false }, kind: "findings", label: "5 findings, 2 new" },
    { name: "findings old", opts: { result: r("findings", { findings: 1 }), running: false, jobRunning: false }, kind: "findings", label: "1 finding" },
    { name: "failed", opts: { result: r("failed", { reason: "timed_out" }), running: false, jobRunning: false }, kind: "failed", label: "Failed: timed out" },
    { name: "busy", opts: { result: r("busy"), running: false, jobRunning: false }, kind: "failed", label: "Busy" },
    { name: "skipped", opts: { result: r("skipped", { reason: "not_ready" }), running: false, jobRunning: false }, kind: "skipped", label: "Skipped: not ready" },
    { name: "not scanned", opts: { result: r("not_scanned"), running: false, jobRunning: false }, kind: "skipped", label: "Not scanned" },
    { name: "unknown id", opts: { result: r("weird_thing"), running: false, jobRunning: false }, kind: "other", label: "weird thing" },
    { name: "running", opts: { running: true, jobRunning: true }, kind: "running", label: "Running" },
    { name: "waiting", opts: { running: false, jobRunning: true }, kind: "waiting", label: "Waiting" },
    { name: "not run", opts: { running: false, jobRunning: false }, kind: "skipped", label: "Not run" },
  ];
  for (const c of cases) {
    const cell = cellOf(c.opts);
    assert.equal(cell.kind, c.kind, c.name);
    assert.equal(cell.label, c.label, c.name);
    if ("ms" in c) assert.equal(cell.durationMs, c.ms, c.name);
  }
});

test("failedResults names project, scanner and reason", () => {
  assert.deepEqual(failedResults(job(), STEPS), [{ project: "alpha", step: "Dependencies (OSV)", reason: "database missing" }]);
  assert.deepEqual(failedResults(job({ projects: [] }), STEPS), []);
});
