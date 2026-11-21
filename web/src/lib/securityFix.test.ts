import { test } from "node:test";
import assert from "node:assert/strict";
import {
  FIX_LAUNCH_PATH,
  fixAttemptBreakdown,
  fixAttemptStatus,
  fixAttemptSummary,
  fixAttemptsPolling,
  fixLaunchBody,
  fixPlanHeadline,
  fixPlanPath,
  fixPlanQuery,
  fixProjectNote,
  fixSeedLabel,
  fixSelectionFilters,
  fixTaskFor,
  type FixPlanProject,
} from "./securityFix.ts";
import { EMPTY_FINDINGS_FILTERS, findingsApiParams, groupDrillDown, type FindingGroup, type FindingsFilters } from "./codeSecurityApi.ts";
import { taskLaunchBody, taskLaunchRequest, taskPasteText, taskPickerItems, taskSeeded, taskSeedLabel } from "./terminalTask.ts";
import { buildToolPickerItems } from "./toolPicker.ts";

const group: FindingGroup = {
  key: "k",
  rule_id: "GHSA-1",
  ecosystem: "npm",
  package: "vite@5.0.2",
  count: 4,
  projects: 2,
  max_severity: "high",
  first_seen: "2026-11-01T00:00:00Z",
  last_seen: "2026-11-02T00:00:00Z",
};

const filtered: FindingsFilters = { ...EMPTY_FINDINGS_FILTERS, severity: ["high", "critical"], q: "lodash", group: "issue" };

const project: FixPlanProject = {
  project_root_hash: "h1",
  name: "api",
  root_path: "/home/u/api",
  on_disk: true,
  findings: 3,
  listed: 3,
  prompt: "Fix these",
};

test("one finding is finding=<id> and nothing else", () => {
  assert.equal(fixPlanQuery({ kind: "finding", id: "01ABC" }), "finding=01ABC");
  assert.equal(fixPlanPath({ kind: "finding", id: "a b" }), "/api/security/fix/plan?finding=a+b");
  assert.equal(fixSelectionFilters({ kind: "finding", id: "x" }), null);
});

test("the current filter is exactly the findings list's API params", () => {
  const q = new URLSearchParams(fixPlanQuery({ kind: "filters", filters: filtered }));
  const want = findingsApiParams(filtered);
  assert.deepEqual(Object.fromEntries(q), want);
  assert.equal(q.get("finding"), null);
});

test("empty filter values are left out (status all)", () => {
  const q = new URLSearchParams(fixPlanQuery({ kind: "filters", filters: { ...EMPTY_FINDINGS_FILTERS, status: "" } }));
  assert.equal(q.has("status"), false);
  assert.equal([...q.keys()].length, 0);
  assert.equal(fixPlanPath({ kind: "filters", filters: { ...EMPTY_FINDINGS_FILTERS, status: "" } }), "/api/security/fix/plan");
});

test("a group row is its drill-down's params", () => {
  const sel = { kind: "group" as const, by: "issue" as const, group, filters: filtered };
  const q = new URLSearchParams(fixPlanQuery(sel));
  assert.deepEqual(Object.fromEntries(q), findingsApiParams(groupDrillDown("issue", group, filtered)));
  assert.equal(q.get("rule"), "GHSA-1");
  assert.equal(q.get("package"), "vite@5.0.2");
  assert.equal(q.get("ecosystem"), "npm");
  assert.equal(q.get("q"), "lodash");
});

test("a project group drills down to its project hash", () => {
  const q = new URLSearchParams(
    fixPlanQuery({ kind: "group", by: "project", group: { ...group, project_root_hash: "ph" }, filters: EMPTY_FINDINGS_FILTERS }),
  );
  assert.equal(q.get("project"), "ph");
});

test("the launch body carries the plan's query or the finding, and the project hash", () => {
  assert.deepEqual(fixLaunchBody({ kind: "finding", id: "f1" }, project), { query: "", finding: "f1", project_root_hash: "h1" });
  const sel = { kind: "filters" as const, filters: filtered };
  assert.deepEqual(fixLaunchBody(sel, project), { query: fixPlanQuery(sel), finding: "", project_root_hash: "h1" });
});

test("the task posts to the fix route in the project's own folder", () => {
  const seeds = { "claude-code": "leading_positional", hermes: "none" };
  const t = fixTaskFor({ kind: "finding", id: "f1" }, { seeds, confirm_token: "tok" }, project);
  assert.equal(t.launchPath, FIX_LAUNCH_PATH);
  assert.equal(t.projectRoot, "/home/u/api");
  assert.equal(t.confirmToken, "tok");
  assert.deepEqual(t.launchBody, { query: "", finding: "f1", project_root_hash: "h1" });
  assert.equal(t.title, "Fix 3 Code security findings");
  assert.match(fixTaskFor({ kind: "finding", id: "f" }, { seeds, confirm_token: "" }, { ...project, findings: 40, listed: 30 }).summary, /lists 30/);
});

test("seed labels: any kind but none starts on the task; none and unknown tools paste", () => {
  const seeds = { claude: "leading_positional", codex: "trailing_positional", devin: "trailing_after_dashdash", gemini: "flag", hermes: "none", odd: "something_new" };
  for (const t of ["claude", "codex", "devin", "gemini"]) {
    assert.equal(taskSeeded(seeds, t), true, t);
    assert.equal(taskSeedLabel(seeds, t), "Starts on the task");
  }
  for (const t of ["hermes", "odd", "absent"]) {
    assert.equal(taskSeeded(seeds, t), false, t);
    assert.equal(fixSeedLabel(seeds, t), "Paste the task");
  }
});

test("the task launch body merges the agent choice and never sends project_root", () => {
  const body = taskLaunchBody(
    { launchBody: { query: "q=1", finding: "", project_root_hash: "h1", project_root: "/x" } },
    { tool: "codex", model: undefined, project_root: "/evil", sandbox: true, backend: "bwrap" },
  );
  assert.deepEqual(body, { query: "q=1", finding: "", project_root_hash: "h1", tool: "codex", sandbox: true, backend: "bwrap" });
});

test("the paste text is kept only when the agent was not started on the task", () => {
  assert.equal(taskPasteText({ seeded: true }), null);
  assert.equal(taskPasteText({}), null);
  assert.equal(taskPasteText({ seeded: false, prompt: "  " }), null);
  assert.equal(taskPasteText({ seeded: false, prompt: "Fix" }), "Fix");
});

test("plan headline and project notes", () => {
  assert.equal(fixPlanHeadline({ total: 0, truncated: false, projects: [] }), "No open findings match this selection.");
  assert.equal(fixPlanHeadline({ total: 1, truncated: false, projects: [project] }), "1 open finding in 1 project. One agent works on one project at a time.");
  assert.match(fixPlanHeadline({ total: 1000, truncated: true, projects: [project, project] }), /^At least 1000 open findings in 2 projects/);
  assert.equal(fixProjectNote(project), "");
  assert.match(fixProjectNote({ ...project, on_disk: false }), /Not on this machine/);
  assert.match(fixProjectNote({ ...project, findings: 45, listed: 30 }), /lists the 30 most severe/);
});

test("every attempt status has words and a tone; unknown reads as itself", () => {
  const rows: [string, string, string][] = [
    ["open", "open", "warn"],
    ["not_reproduced", "cleared on rescan", "success"],
    ["fixed_verified", "verified fixed", "success"],
    ["suppressed", "closed by triage", "neutral"],
    ["accepted_risk", "closed by triage", "neutral"],
    ["false_positive", "closed by triage", "neutral"],
    ["missing", "no longer recorded", "neutral"],
    ["brand_new", "brand new", "neutral"],
  ];
  for (const [s, label, tone] of rows) assert.deepEqual(fixAttemptStatus(s), { label, tone }, s);
});

test("attempt summary, breakdown and polling", () => {
  assert.equal(fixAttemptSummary({ total: 3, open: 1, cleared: false }), "1 of 3 still open");
  assert.equal(fixAttemptSummary({ total: 3, open: 0, cleared: true }), "All 3 cleared");
  assert.equal(fixAttemptSummary({ total: 1, open: 0, cleared: true }), "Cleared");
  assert.equal(fixAttemptSummary({ total: 0, open: 0, cleared: true }), "No findings recorded");
  assert.equal(
    fixAttemptBreakdown([
      { id: "1", rule_id: "a", status: "open" },
      { id: "2", rule_id: "b", status: "not_reproduced" },
      { id: "3", rule_id: "c", status: "not_reproduced" },
      { id: "4", rule_id: "d", status: "suppressed" },
    ]),
    "1 open · 2 cleared on rescan · 1 closed by triage",
  );
  assert.equal(fixAttemptsPolling(null), false);
  assert.equal(fixAttemptsPolling({ attempts: [] }), false);
  const a = { id: "a", created_at: "", tool: "codex", project_root_hash: "h", project_name: "p", handle: "", seeded: true, total: 1, open: 0, cleared: true, findings: [] };
  assert.equal(fixAttemptsPolling({ attempts: [a] }), false);
  assert.equal(fixAttemptsPolling({ attempts: [a, { ...a, cleared: false, open: 1 }] }), true);
});

test("the task request posts to the task's route with the merged body", () => {
  const req = taskLaunchRequest(
    { launchPath: "/api/security/fix/launch", launchBody: { query: "", finding: "f1", project_root_hash: "h1" } },
    { tool: "claude-code", model: "opus", sandbox: true, workspace_source: "live" },
  );
  assert.equal(req.path, "/api/security/fix/launch");
  assert.deepEqual(JSON.parse(req.body), {
    query: "",
    finding: "f1",
    project_root_hash: "h1",
    tool: "claude-code",
    model: "opus",
    sandbox: true,
    workspace_source: "live",
  });
  assert.equal("project_root" in JSON.parse(req.body), false);
});

test("task mode's picker keeps terminal agents only, each with its seed label", () => {
  const items = buildToolPickerItems({
    tools: ["claude-code", "hermes"],
    toolInfo: [],
    gui: [{ id: "zed-ide", label: "Zed", surface: "ide", adapter: "", hosts: [], allowed: true, watched: true }],
    shellEnabled: true,
    shellTool: "terminal",
    labelFor: (id) => id,
    unlaunchable: [{ tool: "poolside", kind: "ide", note: "IDE only" }],
  });
  assert.ok(items.some((i) => i.kind === "shell"));
  const task = taskPickerItems(items, { "claude-code": "leading_positional", hermes: "none" });
  assert.deepEqual(
    task.map((i) => [i.value, i.detail]),
    [
      ["claude-code", "Starts on the task"],
      ["hermes", "Paste the task"],
    ],
  );
  assert.match(task[1].searchable, /paste the task/);
});
