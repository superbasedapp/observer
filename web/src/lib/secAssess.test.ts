import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { HELP_REGISTRY } from "./help.ts";
import { CODE_SECURITY_SETTINGS } from "./codeSecuritySettings.ts";
import {
  ASSESS_BACKEND_UNRECORDED,
  ASSESS_ENV_TOP_LEVEL,
  ASSESS_HELD_WORDS,
  ASSESS_HELPER_SETTING,
  ASSESS_HELPER_HOLDS,
  ASSESS_HELPER_OFF,
  ASSESS_HELPER_ON,
  ASSESS_HELPER_OTHER_WAY,
  ASSESS_IMPORT_REASONS,
  ASSESS_LAUNCH_PATH,
  ASSESS_MASK_DOWNGRADE,
  ASSESS_NONE,
  ASSESS_NO_CHOICES,
  ASSESS_NO_TICKS,
  ASSESS_PREPARE_LABEL,
  ASSESS_PREPARE_WARNING,
  ASSESS_PREVIOUS_NOTE,
  ASSESS_REFUSALS,
  ASSESS_REFUSED_ABOVE,
  ASSESS_RETEST_FINDINGS_NOTE,
  ASSESS_RULE_WORDS,
  ASSESS_RUN_RECORD_FILE,
  ASSESS_SECRET_MODE_SHORT,
  ASSESS_SETTINGS_WHERE,
  ASSESS_STATE,
  ASSESS_TASK_ONLY,
  ASSESS_WINDOW_UNRECORDED,
  assessAuditLine,
  assessBoxActionWords,
  assessCanDeleteData,
  assessCanStop,
  assessCanValidate,
  assessRunMaskLine,
  assessCloudLine,
  assessCompareLine,
  assessConfirmWords,
  assessConsentKey,
  assessCrossed,
  assessEnvFilesLine,
  assessEnvLine,
  assessGroundingLine,
  assessHelperView,
  assessHeldRuleLine,
  assessImportConflict,
  assessImportLabel,
  assessImportLine,
  assessImportable,
  assessLaunchBody,
  assessLaunchRefusal,
  assessModelLines,
  assessLimitsLines,
  assessDefaultProject,
  assessModeTone,
  assessNoteDraftFor,
  assessPlanNotice,
  assessPlanPath,
  assessPolling,
  assessPrepareOn,
  assessPrepareSteps,
  assessPreflightRows,
  assessPreviousLine,
  assessPreviousNote,
  assessPreviousOptionLabel,
  assessPrimary,
  assessReady,
  assessRefusalWords,
  assessRelaxLine,
  assessRelaxOpen,
  assessRelaxState,
  assessRelaxedLine,
  assessReportError,
  assessReportLine,
  assessReportPath,
  assessRequestBody,
  assessRouteWords,
  assessRowOffered,
  assessRunLabel,
  assessRunScopeLines,
  assessRunState,
  assessRunWhere,
  assessRunsUnreadableWords,
  assessRefTallyWords,
  assessSafetyRows,
  assessSandboxWords,
  assessScopeChoiceLine,
  assessScopeLine,
  assessScopeToggle,
  assessSecretModeLine,
  assessSettingsLines,
  assessStartChoice,
  assessStartInForce,
  assessPreflightApart,
  assessStartLine,
  assessStartNoneWords,
  assessStartNote,
  assessStartPlanDetails,
  assessTypeLabel,
  ASSESS_START_NONE_WORDS,
  assessStartSelectedPlan,
  assessStartText,
  assessState,
  assessTaskFor,
  assessTickedRows,
  assessTimeBoxLine,
  assessToolLine,
  assessUnapplied,
  assessWaitingLine,
  assessValidateLabel,
  assessRefConditionWords,
  assessValidationLine,
  type AssessEnv,
  type AssessGrounding,
  type AssessKind,
  type AssessLimits,
  type AssessNoteDraft,
  type AssessModelSettings,
  type AssessPlan,
  type AssessPrevious,
  type AssessProbePlan,
  type AssessRelaxPlan,
  type AssessRelaxRow,
  type AssessRun,
  type AssessScope,
  type AssessStart,
  type AssessTicks,
  type AssessToolRow,
} from "./secAssess.ts";
import { taskLaunchBody, taskLaunchRequest, taskPickerItems } from "./terminalTask.ts";
import { buildToolPickerItems } from "./toolPicker.ts";

const pentest: AssessKind = {
  id: "pentest_local",
  title: "Penetration test (your own app, local)",
  summary: "s",
  mode: "Sandboxed",
  launchable: true,
  sandbox: "required",
  target: "required",
  files: ["report.md", "findings.sarif"],
};

const threat: AssessKind = { ...pentest, id: "threat_model", title: "Threat model", mode: "Read-only", sandbox: "optional", target: "none" };

const rasp: AssessKind = {
  ...pentest,
  id: "rasp",
  title: "Runtime protection (RASP)",
  mode: "Not agent-shaped",
  launchable: false,
  sandbox: "na",
  target: "none",
  reason: "Not agent-shaped.",
  pointer: "Plane A.",
};

function plan(over: Partial<AssessPlan> = {}): AssessPlan {
  return {
    confirm_token: "tok",
    run_id: "20261114-ab12cd",
    kind: pentest,
    project: { project_root_hash: "h1", name: "api", root_path: "/home/u/api", on_disk: true },
    ok: true,
    target: "http://localhost:3000/",
    target_typed: true,
    candidates: [],
    boundary: ["b"],
    allowed_tools: ["claude-code"],
    seeds: { "claude-code": "leading_positional", hermes: "none" },
    backend: "bwrap",
    ...over,
  };
}

test("plan and report paths carry the query", () => {
  assert.equal(assessPlanPath("pentest_local", "h1"), "/api/security/assessments/plan?kind=pentest_local&project=h1");
  assert.equal(
    assessPlanPath("pentest_local", "h1", " http://localhost:3000 "),
    "/api/security/assessments/plan?kind=pentest_local&project=h1&target=http%3A%2F%2Flocalhost%3A3000",
  );
  assert.equal(assessReportPath("20261114-ab12cd"), "/api/security/assessments/report?run=20261114-ab12cd");
});

test("a target kind sends the target and its confirmation; others send neither", () => {
  assert.deepEqual(assessLaunchBody(plan()), {
    assessment: "pentest_local",
    project_root_hash: "h1",
    run_id: "20261114-ab12cd",
    target: "http://localhost:3000/",
    confirm_target: "http://localhost:3000/",
  });
  assert.deepEqual(assessLaunchBody(plan({ kind: threat, target: undefined })), {
    assessment: "threat_model",
    project_root_hash: "h1",
    run_id: "20261114-ab12cd",
  });
});

test("the launch body never carries the launch shape's kind, and the dialog adds only the agent choice", () => {
  const task = assessTaskFor(plan());
  assert.equal(task.launchPath, ASSESS_LAUNCH_PATH);
  assert.equal("kind" in task.launchBody, false);
  const body = taskLaunchBody(task, { tool: "claude-code", model: undefined, project_root: "/elsewhere" });
  assert.equal(body.tool, "claude-code");
  assert.equal(body.assessment, "pentest_local");
  assert.equal("project_root" in body, false);
});

test("a confined kind narrows the picker and tells the dialog the server chooses the sandbox", () => {
  const task = assessTaskFor(plan());
  assert.deepEqual(task.allowedTools, ["claude-code"]);
  assert.match(task.serverSandbox ?? "", /sandbox/);
  assert.match(task.serverSandbox ?? "", /bwrap/);
  assert.match(task.serverSandbox ?? "", /never run unsandboxed/);
  assert.equal(task.projectRoot, "/home/u/api");
  assert.match(task.summary, /http:\/\/localhost:3000\//);
  assert.match(task.summary, /\.observer\/assessments\/20261114-ab12cd\//);
});

test("a confined kind with no agent offers an empty picker, never every agent", () => {
  const task = assessTaskFor(plan({ allowed_tools: null }));
  assert.deepEqual(task.allowedTools, []);
});

test("an unconfined kind leaves the picker and the sandbox controls alone", () => {
  const task = assessTaskFor(plan({ kind: threat, target: undefined, allowed_tools: null }));
  assert.equal(task.allowedTools, undefined);
  assert.equal(task.serverSandbox, undefined);
});

test("taskPickerItems keeps only the allowed terminal agents", () => {
  const items = buildToolPickerItems({
    tools: ["claude-code", "hermes", "codex"],
    toolInfo: [],
    gui: [],
    shellEnabled: false,
    shellTool: "terminal",
    labelFor: (id) => id,
    unlaunchable: [],
  });
  const all = taskPickerItems(items, { "claude-code": "leading_positional", hermes: "none", codex: "flag" });
  const narrowed = taskPickerItems(items, { "claude-code": "leading_positional", hermes: "none", codex: "flag" }, ["claude-code"]);
  assert.ok(all.length >= narrowed.length);
  assert.deepEqual(
    narrowed.map((i) => i.value),
    ["claude-code"],
  );
  assert.deepEqual(taskPickerItems(items, {}, []).map((i) => i.value), []);
});

test("Choose agent is blocked until every gate the page can see is met, in order", () => {
  const ok = plan();
  assert.equal(assessReady(ok, true, true, true), null);
  assert.match(assessReady(plan({ kind: rasp }), true, true, true) ?? "", /Not agent-shaped/);
  assert.match(assessReady(ok, true, true, false) ?? "", /cannot start a terminal/);
  assert.match(assessReady(plan({ project: { ...ok.project, on_disk: false } }), true, true, true) ?? "", /not on this machine/);
  assert.equal(assessReady(plan({ ok: false, reason: "No sandbox here." }), true, true, true), "No sandbox here.");
  assert.match(assessReady(plan({ target_typed: false, target: "" }), true, true, true) ?? "", /Choose the target/);
  assert.match(assessReady(ok, false, true, true) ?? "", /Confirm the target/);
  assert.match(assessReady(ok, true, false, true) ?? "", /dock/);
  // A kind with no target needs no confirmation.
  assert.equal(assessReady(plan({ kind: threat, target: undefined, target_typed: false }), false, true, true), null);
});

test("the confirmation sentence names the exact target", () => {
  assert.match(assessConfirmWords("http://localhost:3000/"), /http:\/\/localhost:3000\//);
});

test("every run state has words, a tone and a next step; an unknown state reads as itself", () => {
  for (const s of ["started", "ended_empty", "report_ready", "findings_ready", "imported", "import_failed", "import_unavailable"]) {
    const w = assessState(s);
    assert.ok(w.label && w.next, s);
    assert.equal(w, ASSESS_STATE[s]);
  }
  assert.deepEqual(assessState("weird_state"), { label: "weird state", tone: "neutral", next: "" });
});

test("mode tone and sandbox words", () => {
  assert.equal(assessModeTone(pentest), "info");
  assert.equal(assessModeTone(threat), "success");
  assert.equal(assessModeTone({ ...threat, mode: "Your cloud session" }), "warn");
  assert.equal(assessModeTone({ ...threat, mode: "Partial" }), "warn");
  assert.equal(assessModeTone(rasp), "neutral");
  assert.match(assessSandboxWords("required"), /refuses to start without one/);
  assert.equal(assessSandboxWords("odd"), "odd");
});

test("import outcome words: counts when imported, the reason otherwise", () => {
  assert.equal(assessImportLine(null), "");
  assert.equal(
    assessImportLine({ at: "t", outcome: "imported", prepared: 2, findings: 2, new: 1, with_lineage: 0 }),
    "2 findings imported (1 new)",
  );
  assert.match(
    assessImportLine({ at: "t", outcome: "imported", prepared: 1, findings: 1, new: 1, with_lineage: 0, truncated: true }),
    /1 finding imported \(1 new\)\. The file held more/,
  );
  assert.match(assessImportLine({ at: "t", outcome: "failed", reason: "not_sarif", prepared: 0, findings: 0, new: 0, with_lineage: 0 }), /not a SARIF file/);
  assert.match(
    assessImportLine({ at: "t", outcome: "unavailable", reason: "component_not_selected", prepared: 0, findings: 0, new: 0, with_lineage: 0 }),
    /not turned on/,
  );
  assert.equal(assessImportLine({ at: "t", outcome: "failed", reason: "zzz", prepared: 0, findings: 0, new: 0, with_lineage: 0 }), "The import failed.");
});

test("the cloud line counts by class and says it is the agent's own list", () => {
  assert.equal(assessCloudLine(null), "");
  assert.equal(assessCloudLine({ read_only: 0, secret_material: 0, mutating: 0, unknown: 0 }), "The agent listed no cloud commands.");
  assert.equal(
    assessCloudLine({ read_only: 4, secret_material: 0, mutating: 0, unknown: 0 }),
    "The agent listed 4 cloud commands: 4 read-only.",
  );
  assert.equal(
    assessCloudLine({ read_only: 3, secret_material: 1, mutating: 2, unknown: 1 }),
    "The agent listed 7 cloud commands: 3 read-only, 2 that change something, 1 that return secret material, 1 Observer cannot classify.",
  );
  assert.equal(assessCrossed({ read_only: 3, secret_material: 0, mutating: 0, unknown: 5 }), false);
  assert.equal(assessCrossed({ read_only: 3, secret_material: 0, mutating: 1, unknown: 0 }), true);
  assert.equal(assessCrossed({ read_only: 3, secret_material: 1, mutating: 0, unknown: 0 }), true);
  assert.equal(assessCrossed(undefined), false);
});

function run(over: Partial<AssessRun> = {}): AssessRun {
  return {
    id: "r1",
    created_at: "2026-11-14T00:00:00Z",
    kind: "threat_model",
    kind_title: "Threat model",
    tool: "claude-code",
    project_root_hash: "h1",
    project_name: "api",
    seeded: true,
    sandboxed: false,
    state: "started",
    files: { report: false, sarif: false, commands: false },
    report_bytes: 0,
    ...over,
  };
}

test("where a run ran, in words", () => {
  assert.equal(assessRunWhere(run()), "not sandboxed");
  // A sandboxed run whose record names no backend says so; it never guesses one (N-20).
  assert.equal(assessRunWhere(run({ sandboxed: true })), "in a sandbox (backend not recorded for this run)");
  assert.equal(assessRunWhere(run({ sandboxed: true, target: "http://localhost:3000/" })), "http://localhost:3000/ · in a sandbox (backend not recorded for this run)");
  assert.equal(ASSESS_BACKEND_UNRECORDED, "backend not recorded for this run");
  assert.equal(ASSESS_SETTINGS_WHERE, "Settings > Guard > Code security");
  assert.equal(assessRunWhere(run({ sandboxed: true, backend: "bwrap", target: "http://localhost:3000/" })), "http://localhost:3000/ · in a sandbox (bwrap)");
});

test("the list keeps refreshing while a run can still receive a result file", () => {
  assert.equal(assessPolling(null), false);
  assert.equal(assessPolling({ runs: [run({ state: "imported" }), run({ state: "import_failed" })] }), false);
  assert.equal(assessPolling({ runs: [run({ state: "imported" }), run({ state: "report_ready" })] }), true);
  assert.equal(assessPolling({ runs: [run({ state: "started" })] }), true);
});

test("Import is offered for a findings file that is not already imported", () => {
  assert.equal(assessImportable(run({ state: "findings_ready", files: { report: true, sarif: true, commands: false } })), true);
  assert.equal(assessImportable(run({ state: "import_failed", files: { report: true, sarif: true, commands: false } })), true);
  assert.equal(assessImportable(run({ state: "imported", files: { report: true, sarif: true, commands: false } })), false);
  assert.equal(assessImportable(run({ state: "report_ready", files: { report: true, sarif: false, commands: false } })), false);
});

// --- Guardrails for one run (plan section 13) ------------------------------

const scanner: AssessRelaxRow = {
  key: "R-179",
  type: "rule",
  title: "Allow network and vulnerability scanners (guard rule R-179)",
  lifts: "lifts one rule",
  why: "w",
  route: "self",
  row: "C4",
  reason: "Your tick is the consent.",
  ticked: false,
};
const tier: AssessRelaxRow = { ...scanner, key: "tier", type: "tier", title: "Wider network", route: "refused", row: "T1", code: "tier_above_max" };

function relaxPlan(over: Partial<AssessRelaxPlan> = {}): AssessRelaxPlan {
  return {
    tenancy: "individual",
    scope: "session",
    scope_words: "for this terminal's session only",
    minutes: 60,
    reported: false,
    report_row: "R3",
    enrolled: false,
    tier_live: "proxy_only",
    tier_hosts: [],
    rows: [scanner, tier],
    lines: [],
    ...over,
  };
}

test("a launch that lifts nothing has exactly the body it always had", () => {
  const p = plan();
  assert.deepEqual(assessLaunchBody(p), assessLaunchBody(p, ASSESS_NO_TICKS));
  const body = assessLaunchBody(p, ASSESS_NO_TICKS);
  assert.ok(!("relaxations" in body) && !("tier_relax" in body), JSON.stringify(body));
});

test("ticked guardrails travel on the launch, the request and the plan read", () => {
  const p = plan();
  const ticks: AssessTicks = { rules: ["R-179"], tier: true };
  const launch = assessLaunchBody(p, ticks);
  assert.deepEqual(launch.relaxations, ["R-179"]);
  assert.equal(launch.tier_relax, true);
  // The request restates the run, project and target and carries no agent or confirmation.
  const req = assessRequestBody(p, ticks);
  assert.deepEqual(req, {
    assessment: "pentest_local",
    project_root_hash: "h1",
    run_id: "20261114-ab12cd",
    relaxations: ["R-179"],
    target: "http://localhost:3000/",
  });
  const url = assessPlanPath("pentest_local", "h1", "http://localhost:3000/", ticks, "20261114-ab12cd");
  const qs = new URL(url, "http://x").searchParams;
  assert.equal(qs.get("relax"), "R-179");
  assert.equal(qs.get("tier_relax"), "1");
  assert.equal(qs.get("run"), "20261114-ab12cd");
  // Nothing ticked adds nothing to the read.
  assert.equal(assessPlanPath("pentest_local", "h1"), "/api/security/assessments/plan?kind=pentest_local&project=h1");
});

test("the dialog task says the sandbox network is wider only when that row is ticked", () => {
  const p = plan({ relax: relaxPlan({ tier_hosts: ["registry.npmjs.org"] }), backend: "bwrap" });
  assert.match(assessTaskFor(p, undefined, ASSESS_NO_TICKS).serverSandbox ?? "", /only route out is Observer's model connection/);
  const wide = assessTaskFor(p, undefined, { rules: [], tier: true });
  assert.match(wide.serverSandbox ?? "", /wider than usual/);
  assert.match(wide.serverSandbox ?? "", /registry\.npmjs\.org/);
  assert.equal(wide.launchBody.tier_relax, true);
});

test("the primary button follows who must consent", () => {
  const ok = (over: Partial<AssessPlan> = {}) => plan({ relax: relaxPlan({ rows: [{ ...scanner, route: "org_request" }, tier] }), ...over });
  const none = ASSESS_NO_TICKS;
  const ticked: AssessTicks = { rules: ["R-179"], tier: false };
  // Nothing the organization decides is ticked: the ordinary Choose agent.
  assert.deepEqual(assessPrimary(ok(), none, true, true, true), { action: "start", label: "Choose agent", block: null });
  // Ticked and not asked yet: ask; asking needs neither a terminal dock nor a launch-capable dashboard.
  const ask = assessPrimary(ok(), ticked, true, false, false);
  assert.equal(ask.action, "ask");
  assert.equal(ask.label, "Ask my organization");
  assert.equal(ask.block, null);
  // Asking still needs the confirmed target.
  assert.equal(assessPrimary(ok(), ticked, false, true, true).block, "Confirm the target first");
  // A held run that is not approved yet waits, and is never startable.
  const waiting = assessPrimary(ok({ held: { at: "t", ready: false, rules: [{ rule: "R-179", state: "waiting" }] } }), ticked, true, true, true);
  assert.equal(waiting.action, "wait");
  assert.ok(waiting.block);
  // Approved: start, with the ordinary gates still applied.
  const ready = ok({ held: { at: "t", ready: true, rules: [{ rule: "R-179", state: "approved", grant_id: 31 }] } });
  assert.deepEqual(assessPrimary(ready, ticked, true, true, true), { action: "start", label: "Approved: start", block: null });
  assert.equal(assessPrimary(ready, ticked, true, false, true).block, "The terminal dock is not available on this page");
  // A self-route tick (the individual path) is the ordinary start.
  const self = plan({ relax: relaxPlan() });
  assert.equal(assessPrimary(self, ticked, true, true, true).action, "start");
});

test("a row is offered only when someone can consent to it", () => {
  assert.equal(assessRowOffered({ route: "self" }), true);
  assert.equal(assessRowOffered({ route: "org_request" }), true);
  assert.equal(assessRowOffered({ route: "refused" }), false);
  assert.equal(assessRowOffered({ route: "not_needed" }), false);
  assert.equal(assessRouteWords("self"), "You approve this");
  assert.equal(assessRouteWords("org_request"), "Your organization approves this");
  assert.equal(assessRouteWords("something else"), "Not offered");
});

test("the scope line says what is covered, how long, and what is not", () => {
  const ticks: AssessTicks = { rules: ["R-179"], tier: false };
  assert.equal(assessScopeLine(relaxPlan(), ASSESS_NO_TICKS), "");
  assert.match(assessScopeLine(relaxPlan(), ticks), /this terminal's session only.*60 minutes/);
  const project = assessScopeLine(relaxPlan({ scope: "project" }), ticks);
  assert.match(project, /every session in this project/);
  assert.match(project, /outside the box/);
  const org = relaxPlan({ rows: [{ ...scanner, route: "org_request" }, tier], tenancy: "managed" });
  const orgLine = assessScopeLine(org, ticks);
  assert.match(orgLine, /ends at its own expiry/);
  assert.match(orgLine, /cannot revoke/);
  assert.match(assessScopeLine(relaxPlan({ rows: [scanner, { ...tier, route: "self" }] }), { rules: [], tier: true }), /wider network is the one you already configured/);
});

test("the report line says whether the organization sees the run", () => {
  assert.equal(assessReportLine(null), "");
  assert.match(assessReportLine(relaxPlan()), /not reported/);
  assert.match(assessReportLine(relaxPlan({ reported: true })), /you turned that on/);
  assert.match(assessReportLine(relaxPlan({ reported: true, tenancy: "managed" })), /manages are reported/);
});

test("a run's guardrails read in one sentence each, with how they ended", () => {
  assert.equal(assessRelaxLine({ key: "R-179", type: "rule", route: "self", state: "pending_bind" }), "Network and vulnerability scanner rule lifted: waiting for the session");
  assert.equal(
    assessRelaxLine({ key: "R-179", type: "rule", route: "self", state: "active", scope: "project", approval_id: 7 }),
    "Network and vulnerability scanner rule lifted: in force (approval #7; whole project)",
  );
  assert.equal(
    assessRelaxLine({ key: "R-179", type: "rule", route: "org_request", state: "org_grant", grant_id: 31 }),
    "Network and vulnerability scanner rule lifted: under your organization's grant (grant G-31)",
  );
  assert.equal(
    assessRelaxLine({ key: "R-179", type: "rule", route: "self", state: "ended", end_reason: "terminal_exit" }),
    "Network and vulnerability scanner rule lifted: ended (ended when the terminal closed)",
  );
  assert.match(assessRelaxLine({ key: "R-179", type: "rule", route: "self", state: "existing", note: "existing_row" }), /already covered this/);
  assert.match(assessRelaxLine({ key: "R-179", type: "rule", route: "self", state: "failed", note: "create_failed" }), /guard kept asking/);
  // A rule the table does not know reads as a guard rule, never as its id.
  assert.equal(assessRelaxLine({ key: "R-999", type: "rule", route: "self", state: "active" }), "A guard rule lifted: in force");
  assert.doesNotMatch(Object.values(ASSESS_RULE_WORDS).join(" "), /R-\d/);
  assert.equal(
    assessRelaxLine({ key: "tier", type: "tier", route: "self", state: "tier", hosts: ["a.example", "b.example"] }),
    "Wider sandbox network: wider network for this run (hosts: a.example, b.example)",
  );
  // An unknown state reads as itself, never as empty.
  assert.equal(assessRelaxState("odd_state").label, "odd state");
});

test("the changed-verdict count says exact and approximate apart", () => {
  assert.equal(assessRelaxedLine(null), "");
  assert.equal(assessRelaxedLine({ exact: 0, approx: 0 }), "No command needed the lifted guardrail.");
  assert.match(assessRelaxedLine({ exact: 1, approx: 0 }), /^1 command that the guard would have stopped ran under this run's approval\.$/);
  assert.match(assessRelaxedLine({ exact: 3, approx: 5 }), /3 commands.*about 5 under your organization's grant \(counted by grant, so approximate\)/);
});

test("a held run's rules and state read as the organization's answer", () => {
  assert.equal(assessHeldRuleLine({ rule: "R-179", state: "waiting", request_id: 101 }), "R-179: waiting for your organization [request #101]");
  assert.equal(assessHeldRuleLine({ rule: "R-179", state: "approved", grant_id: 31 }), "R-179: approved [grant G-31]");
  assert.equal(
    assessHeldRuleLine({ rule: "R-179", state: "narrower", grant_id: 40, why: "it is for another project" }),
    "R-179: approved, but narrower than asked [grant G-40] (it is for another project)",
  );
  assert.match(assessHeldRuleLine({ rule: "R-179", state: "declined", why: "not this quarter" }), /declined.*not this quarter/);
  assert.match(assessHeldRuleLine({ rule: "R-179", state: "queued" }), /could not be reached/);
  const held = { state: "held", phase: "held", held: { at: "t", ready: false, rules: [] } };
  assert.equal(assessRunState(held).label, "waiting for your organization");
  assert.equal(assessRunState({ ...held, held: { at: "t", ready: true, rules: [] } }).label, "approved: start");
  assert.equal(assessRunState({ state: "cancelled", phase: "cancelled" }).label, "cancelled");
  assert.equal(assessRunState({ state: "started", phase: "started" }).label, "running");
});

// The first live run (2026-11-15): a launch whose terminal exited within seconds stayed "running" for
// hours beside "ended when the terminal closed". The server now sends ended_empty for a run that is
// over and wrote nothing; the words say it is over, why, and that nothing was produced.
test("a run that ended with nothing written reads as over, with how it ended, never as running", () => {
  const rows: Array<{ end_why: string | undefined; why: string }> = [
    { end_why: "terminal_gone", why: "ended when the terminal closed" },
    { end_why: "time_box", why: "closed by Observer at the time box" },
    { end_why: "stopped", why: "stopped from this page" },
    { end_why: undefined, why: "it ended" },
    { end_why: "some_new_reason", why: "it ended" },
  ];
  for (const row of rows) {
    const w = assessRunState({ state: "ended_empty", phase: "started", end_why: row.end_why });
    assert.equal(w.label, "ended without a result", row.why);
    assert.equal(w.tone, "warn", row.why);
    assert.ok(w.next.includes(`(${row.why})`), `${row.why}: ${w.next}`);
    assert.ok(!/Waiting for the agent|running/.test(`${w.label} ${w.next}`), row.why);
  }
  // A run that is still going keeps its running words; one that wrote something keeps the words of its files.
  assert.equal(assessRunState({ state: "started", phase: "started", end_why: undefined }).label, "running");
  assert.equal(assessRunState({ state: "report_ready", phase: "started", end_why: "terminal_gone" }).label, "report ready");
  // Over, so the list has no reason to keep refreshing for it.
  const over = run({ state: "ended_empty", end_why: "terminal_gone", ended_at: "2026-11-15T10:00:00Z", can_stop: false });
  assert.equal(assessPolling({ runs: [over] }), false);
  assert.equal(assessImportable(over), false);
});

test("the list keeps refreshing while a run waits or holds a guardrail", () => {
  const base = run({ state: "imported" });
  assert.equal(assessPolling({ runs: [base] }), false);
  assert.equal(assessPolling({ runs: [{ ...base, state: "held", phase: "held" }] }), true);
  assert.equal(assessPolling({ runs: [{ ...base, relax: [{ key: "R-179", type: "rule", route: "self", state: "active" }] }] }), true);
  // Once the run ended, or was cancelled, nothing is still moving.
  assert.equal(
    assessPolling({ runs: [{ ...base, ended_at: "t", relax: [{ key: "R-179", type: "rule", route: "self", state: "active" }] }] }),
    false,
  );
  assert.equal(assessRelaxOpen({ phase: "cancelled", relax: [{ key: "R-179", type: "rule", route: "self", state: "active" }] }), false);
  assert.equal(assessTickedRows(relaxPlan(), { rules: ["R-179"], tier: false }).length, 1);
  assert.equal(assessTickedRows(null, { rules: ["R-179"], tier: false }).length, 0);
});

test("a run's time box reads as within, over or ended, never as verified", () => {
  const live = { time_box_minutes: 45, time_box_action: "stop_button", over_time_box: false } as const;
  assert.deepEqual(assessTimeBoxLine({}), { text: "", tone: "neutral" });
  assert.deepEqual(assessTimeBoxLine({ ...live, phase: "held" }), { text: "", tone: "neutral" });
  const inside = assessTimeBoxLine(live);
  assert.match(inside.text, /^45-minute time box\. Nothing closes the terminal for you; use Stop when you are ready\.$/);
  assert.equal(inside.tone, "neutral");
  const over = assessTimeBoxLine({ ...live, over_time_box: true });
  assert.match(over.text, /^Over its 45-minute time box\./);
  assert.equal(over.tone, "warn");
  const closes = assessTimeBoxLine({ ...live, over_time_box: true, time_box_action: "auto_close" });
  assert.match(closes.text, /closes the terminal at the deadline/);
  // An unknown action reads as the stop button.
  assert.equal(assessBoxActionWords("kill"), assessBoxActionWords("stop_button"));
  const ended = assessTimeBoxLine({ ...live, ended_at: "2026-11-14T12:00:00Z", end_why: "stopped" });
  assert.equal(ended.text, "Within its 45-minute time box; stopped from this page.");
  const endedOver = assessTimeBoxLine({ ...live, over_time_box: true, ended_at: "2026-11-14T12:00:00Z", end_why: "time_box" });
  assert.equal(endedOver.text, "Over its 45-minute time box; closed by Observer at the time box.");
  assert.equal(endedOver.tone, "warn");
});

test("the git check line says what the comparison found and when it was taken", () => {
  assert.equal(assessAuditLine({}), null);
  assert.deepEqual(assessAuditLine({ audit: "pending", audit_words: "Checked when the run ends" }), {
    text: "Git check: Checked when the run ends.",
    tone: "neutral",
  });
  const changed = assessAuditLine({ audit: "changed", audit_words: "Git state changed during the run window" });
  assert.equal(changed?.tone, "warn");
  assert.doesNotMatch(changed?.text ?? "", /clean|verified|confirmed|crossed/i);
  // Taken 12 minutes after the terminal was seen gone: it says so.
  const late = assessAuditLine({
    audit: "no_change",
    audit_words: "No git change seen",
    ended_at: "2026-11-14T12:00:00Z",
    audit_at: "2026-11-14T12:12:00Z",
  });
  assert.equal(late?.text, "Git check: No git change seen (taken 12 minutes after the terminal was seen gone).");
  // A snapshot taken right away does not.
  const prompt = assessAuditLine({ audit: "no_change", audit_words: "No git change seen", ended_at: "2026-11-14T12:00:00Z", audit_at: "2026-11-14T12:00:30Z" });
  assert.equal(prompt?.text, "Git check: No git change seen.");
  // A verdict with no words from the server reads as its own name.
  assert.equal(assessAuditLine({ audit: "could_not_check" })?.text, "Git check: could not check.");
});

test("a partly checked git check is a warning: never read as no change, never as clean", () => {
  const words = "No change seen in the files that could be compared; some changed files could not be compared";
  const partly = assessAuditLine({ audit: "partly_checked", audit_words: words });
  assert.equal(partly?.text, `Git check: ${words}.`);
  assert.equal(partly?.tone, "warn");
  assert.doesNotMatch(partly?.text ?? "", /\bclean\b|verified|confirmed/i);
  // No words from the server: the verdict reads as its own name.
  assert.equal(assessAuditLine({ audit: "partly_checked" })?.text, "Git check: partly checked.");
  // The other verdicts keep their tones: a failed snapshot and no change stay neutral.
  assert.equal(assessAuditLine({ audit: "could_not_check", audit_words: "Could not be checked" })?.tone, "neutral");
  assert.equal(assessAuditLine({ audit: "no_change", audit_words: "No git change seen" })?.tone, "neutral");
  assert.equal(assessAuditLine({ audit: "changed", audit_words: "Git state changed during the run window" })?.tone, "warn");
  // The verdict's code and sentence are the Go side's (internal/secassess/tree.go).
  const go = readFileSync(new URL("../../../internal/secassess/tree.go", import.meta.url), "utf8");
  assert.match(go, /AuditPartial\s+AuditVerdict = "partly_checked"/);
  assert.equal(go.match(/case AuditPartial:\s*return "([^"]+)"/)?.[1], words);
  assert.match(readFileSync(new URL("./secAssess.ts", import.meta.url), "utf8"), /no_change \| changed \| partly_checked \| could_not_check/);
});

test("Stop and Delete follow whether the terminal is live", () => {
  assert.equal(assessCanStop({ can_stop: true }), true);
  assert.equal(assessCanStop({ can_stop: true, phase: "held" }), false);
  assert.equal(assessCanStop({ can_stop: false }), false);
  assert.equal(assessCanStop({}), false);
  assert.equal(assessCanDeleteData({ has_data: true }), true);
  assert.equal(assessCanDeleteData({ has_data: true, can_stop: true }), false);
  assert.equal(assessCanDeleteData({ has_data: false }), false);
  assert.equal(assessCanDeleteData({}), false);
});

test("the plan's settings in force name the time box, the action and the git check", () => {
  assert.deepEqual(assessLimitsLines(null), []);
  const l: AssessLimits = {
    time_box_minutes: 90,
    time_box_action: "auto_close",
    boundary_audit: true,
    audit_policy: "untracked_reported",
    audit_limits: "Files git ignores are not covered.",
    relaxation_note: "approvals end at your cap, 60 minutes in",
  };
  const lines = assessLimitsLines(l);
  assert.equal(lines.length, 3);
  assert.match(lines[0].text, /^Time box: 90 minutes\. Observer closes the terminal at the deadline\.$/);
  assert.equal(lines[1].tone, "warn");
  assert.match(lines[1].text, /approvals end at your cap, 60 minutes in/);
  assert.match(lines[2].text, /Files git ignores are not covered\./);
  const off = assessLimitsLines({ ...l, boundary_audit: false, relaxation_note: undefined });
  assert.equal(off.length, 2);
  assert.match(off[1].text, /off\. The run row will say the git state was not checked/);
});

test("the list keeps refreshing while a terminal is live or its git check is pending", () => {
  const base = run({ state: "imported" });
  assert.equal(assessPolling({ runs: [{ ...base, can_stop: true }] }), true);
  assert.equal(assessPolling({ runs: [{ ...base, audit: "pending" }] }), true);
  assert.equal(assessPolling({ runs: [{ ...base, audit: "no_change" }] }), false);
});

const zeroRefs = { found: 0, exists: 0, claimed_not_found: 0, missing: 0, invalid: 0, unchecked: 0 };

test("a validation reads as what was checked, never as the agent being right", () => {
  const refs = { found: 12, exists: 3, claimed_not_found: 0, missing: 1, invalid: 0, unchecked: 2 };
  const ok = assessValidationLine({ state: "valid", at: "t", refs });
  assert.equal(
    ok?.text,
    `Model checked: nothing was refused. References: 12 found near the cited line, 3 exist with nothing matched near the cited line, 1 missing, 2 not checked. ${ASSESS_WINDOW_UNRECORDED}`,
  );
  assert.equal(ok?.tone, "neutral");
  assert.doesNotMatch(ok?.text ?? "", /verified|confirmed|clean|correct/i);
  const partial = assessValidationLine({ state: "partial", at: "t", refused: 2, refs: zeroRefs });
  assert.equal(partial?.text, "Model checked: 2 items were refused.");
  assert.equal(partial?.tone, "warn");
  assert.equal(assessValidationLine({ state: "partial", at: "t", refused: 1, refs })?.text.startsWith("Model checked: 1 item was refused."), true);
  const bad = assessValidationLine({ state: "invalid", at: "t", fatal: "not_json", refs });
  assert.equal(bad?.text, "Model refused: it is not JSON.");
  assert.equal(bad?.tone, "danger");
  assert.equal(assessValidationLine({ state: "invalid", at: "t", fatal: "a_new_code", refs })?.text, "Model refused: a new code.");
  const stale = assessValidationLine({ state: "valid", at: "t", stale: true, anyway: true, refs: zeroRefs });
  assert.match(stale?.text ?? "", /Checked before the run ended\. The model changed after this check; check it again\.$/);
  assert.equal(stale?.tone, "warn");
  assert.equal(assessValidationLine(null), null);
  assert.equal(assessRefTallyWords(zeroRefs), "");
});

test("a validation line carries the window its references were matched under, and what hiding secrets did to them", () => {
  const refs = { found: 192, exists: 0, claimed_not_found: 7, missing: 0, invalid: 0, unchecked: 0 };
  const line = assessValidationLine({ state: "valid", at: "t", refs, ref_window_lines: 5, ref_text_hidden: 6 });
  assert.equal(
    line?.text,
    "Model checked: nothing was refused. References: 192 found near the cited line, 7 cited text not found in the cited range. A reference is found when its text is on a code line within 5 lines of the first cited line. 6 references quote text that hiding secrets changed, so they could not be found in the file.",
  );
  assert.equal(assessValidationLine({ state: "valid", at: "t", refs, ref_window_lines: 1, ref_text_hidden: 1 })?.text.endsWith("A reference is found only when its text is on the first cited line itself. 1 reference quotes text that hiding secrets changed, so it could not be found in the file."), true);
  // A partial check says it too, and a check that predates the record says nothing about a window it never kept.
  assert.match(assessValidationLine({ state: "partial", at: "t", refused: 1, refs, ref_window_lines: 20 })?.text ?? "", /within 20 lines of the first cited line.$/);
  assert.doesNotMatch(assessValidationLine({ state: "valid", at: "t", refs })?.text ?? "", /within|first cited line itself|hiding secrets/);
  // No references to count: no conditions to state.
  assert.equal(assessValidationLine({ state: "valid", at: "t", refs: zeroRefs, ref_window_lines: 5 })?.text, "Model checked: nothing was refused.");
});

test("assessRefConditionWords: the window in lines, the singular and plural of the hidden count, and a sentence that it was not recorded for an unknown window", () => {
  assert.deepEqual(assessRefConditionWords(5, 0), ["A reference is found when its text is on a code line within 5 lines of the first cited line."]);
  assert.deepEqual(assessRefConditionWords(1, undefined), ["A reference is found only when its text is on the first cited line itself."]);
  assert.deepEqual(assessRefConditionWords(50, 2)[1], "2 references quote text that hiding secrets changed, so they could not be found in the file.");
  // A check that kept no window says so: never a window of our own guess, and never silence (N-20).
  assert.deepEqual(assessRefConditionWords(undefined, 3), [ASSESS_WINDOW_UNRECORDED]);
  assert.deepEqual(assessRefConditionWords(0, 3), [ASSESS_WINDOW_UNRECORDED]);
  assert.deepEqual(assessRefConditionWords(-2, undefined), [ASSESS_WINDOW_UNRECORDED]);
  assert.match(ASSESS_WINDOW_UNRECORDED, /was not recorded for this check\.$/);
  assert.doesNotMatch(assessRefConditionWords(5, 2).join(" "), /verified|confirmed|clean|secure|safe/i);
});

test("Validate is offered for a written model that has no current validation", () => {
  const base = { contract: "threatmodel.v1", files: { report: true, sarif: false, commands: false, model: true }, phase: "started" };
  assert.equal(assessCanValidate(base), true);
  assert.equal(assessCanValidate({ ...base, validation: { state: "valid", at: "t", refs: zeroRefs } }), false);
  assert.equal(assessCanValidate({ ...base, validation: { state: "valid", stale: true, at: "t", refs: zeroRefs } }), true);
  assert.equal(assessCanValidate({ ...base, contract: undefined }), false);
  assert.equal(assessCanValidate({ ...base, contract: "sarif" }), false);
  assert.equal(assessCanValidate({ ...base, files: { ...base.files, model: false } }), false);
  assert.equal(assessCanValidate({ ...base, phase: "held" }), false);
  assert.equal(assessValidateLabel({}), "Validate");
  assert.equal(assessValidateLabel({ can_stop: true }), "Validate anyway");
  assert.equal(assessValidateLabel({ validation: { state: "valid", at: "t", refs: zeroRefs } }), "Validate again");
});

test("the model states have words, and every state the server can send has an entry", () => {
  for (const s of ["started", "ended_empty", "report_ready", "model_ready", "validated", "invalid", "findings_ready", "imported", "import_failed", "import_unavailable"]) {
    assert.ok(ASSESS_STATE[s], `no words for state ${s}`);
  }
  assert.equal(assessState("model_ready").label, "model written");
  assert.equal(assessState("invalid").label, "model refused");
});

// --- The model contract's import (depth plan W1c) --------------------------

const imp = (over: Partial<NonNullable<AssessRun["import"]>>): NonNullable<AssessRun["import"]> => ({
  at: "t",
  outcome: "imported",
  prepared: 0,
  findings: 0,
  new: 0,
  with_lineage: 0,
  ...over,
});

test("a derived import says how many candidates were not imported and why, nothing silent", () => {
  // Every candidate imported: just the count.
  assert.equal(
    assessImportLine(imp({ prepared: 3, findings: 3, new: 2, derived: { considered: 3, kept: 3 } })),
    "3 findings imported (2 new)",
  );
  // Some left out: each reason with a count, in the settings' own words.
  const line = assessImportLine(
    imp({
      prepared: 2,
      findings: 2,
      new: 2,
      derived: { considered: 9, kept: 2, no_location: 3, under_min_band: 2, duplicate: 1, over_cap: 1, over_ceiling: 0, min_band: "high", cap: 2 },
    }),
  );
  assert.match(line, /^2 findings imported \(2 new\)\. 7 of 9 not imported: /);
  assert.match(line, /3 with no location in the code/);
  assert.match(line, /2 under your minimum band \(high\)/);
  assert.match(line, /1 repeating another/);
  assert.match(line, /1 past your cap of 2/);
  assert.doesNotMatch(line, /ceiling/);
  // The import's own ceiling is named, and never described as the developer's cap.
  const ceil = assessImportLine(imp({ prepared: 1000, findings: 1000, new: 1000, derived: { considered: 1200, kept: 1000, over_ceiling: 200 } }));
  assert.match(ceil, /200 past the import's own 1000-result ceiling/);
  assert.doesNotMatch(ceil, /your cap/);
});

test("an import that derived nothing says so without saying the project is clean", () => {
  const none = assessImportLine(imp({ outcome: "no_findings", derived: { considered: 0, kept: 0 } }));
  assert.match(none, /Nothing was derived to import: the model listed no missing mitigation or reported weakness\./);
  const some = assessImportLine(imp({ outcome: "no_findings", derived: { considered: 3, kept: 0, no_location: 3 } }));
  assert.match(some, /Nothing was derived to import from 3 candidates\. 3 of 3 not imported: 3 with no location in the code\./);
  assert.match(assessImportLine(imp({ outcome: "no_findings", derived: { considered: 1, kept: 0, under_min_band: 1, min_band: "critical" } })), /from 1 candidate\./);
  for (const line of [none, some, assessState("no_findings").next]) {
    assert.doesNotMatch(line, /\bclean\b|no weaknesses|no vulnerabilities|is secure|verified|confirmed/i);
  }
  assert.equal(assessState("no_findings").label, "nothing to import");
  assert.match(assessImportLine(imp({ outcome: "failed", reason: "model_unavailable" })), /stored copy of the checked model is gone/);
});

test("a model run is importable once its model is validated; the agent's own findings file plays no part", () => {
  const files = { report: true, sarif: false, commands: false, model: true };
  const m = (state: string, extra: Partial<AssessRun> = {}) => run({ contract: "threatmodel.v1", state, files, ...extra });
  assert.equal(assessImportable(m("validated")), true);
  assert.equal(assessImportable(m("import_failed")), true);
  assert.equal(assessImportable(m("import_unavailable")), true);
  // Nothing derived: it can be imported again, since a setting may have changed.
  assert.equal(assessImportable(m("no_findings")), true);
  for (const state of ["started", "report_ready", "model_ready", "invalid", "imported"]) {
    assert.equal(assessImportable(m(state)), false, state);
  }
  // A findings file the agent wrote anyway does not make a model run importable.
  assert.equal(assessImportable(m("model_ready", { files: { ...files, sarif: true } })), false);
  // A legacy run keeps the old rule.
  assert.equal(assessImportable(run({ state: "findings_ready", files: { report: true, sarif: true, commands: false } })), true);
  assert.equal(assessImportable(run({ contract: "sarif", state: "findings_ready", files: { report: true, sarif: true, commands: false } })), true);
});

test("import labels and the not-validated refusal have words", () => {
  assert.equal(assessImportLabel("validated"), "Import findings");
  assert.equal(assessImportLabel("findings_ready"), "Import findings");
  for (const st of ["import_failed", "import_unavailable", "no_findings"]) assert.equal(assessImportLabel(st), "Import again");
  assert.match(assessImportConflict(JSON.stringify({ error: "x", code: "not_validated" })), /Check the model first: use Validate/);
  assert.equal(assessImportConflict("the run has no findings file to import yet\n"), "The run has no findings file to import yet.");
  // A code with no row reads as the server's own sentence, never as another refusal's words.
  assert.equal(assessImportConflict(JSON.stringify({ error: "something new went wrong", code: "other" })), "Something new went wrong.");
  // An answer with no words at all reads as the old route's refusal.
  assert.equal(assessImportConflict(""), "The run has no findings file to import yet.");
  // The run record's refusals are the run record's, not "no findings file".
  assert.match(assessImportConflict(JSON.stringify({ error: "x", code: "run_record_unreadable", file: "/d/secassess-runs.json" })), /run record cannot be read/);
});

test("a lost stored model offers Validate again", () => {
  const base = run({
    contract: "pentest.v1",
    state: "import_failed",
    files: { report: true, sarif: false, commands: false, model: true },
    validation: { state: "valid", at: "t", refs: { found: 0, exists: 0, claimed_not_found: 0, missing: 0, invalid: 0, unchecked: 0 } },
  });
  assert.equal(assessCanValidate(base), false);
  assert.equal(assessCanValidate({ ...base, import: imp({ outcome: "failed", reason: "model_unavailable" }) }), true);
  assert.equal(assessCanValidate({ ...base, import: imp({ outcome: "failed", reason: "node_error" }) }), false);
});

test("the launch carries the digest of the task the developer read, when the plan has one", () => {
  const body = assessLaunchBody(plan({ prompt_sha256: "ab".repeat(32) }));
  assert.equal(body.prompt_sha256, "ab".repeat(32));
  assert.ok(!("prompt_sha256" in assessLaunchBody(plan())));
  // It reaches the launch route through the New terminal dialog's own body.
  const task = assessTaskFor(plan({ prompt_sha256: "cd".repeat(32) }));
  assert.equal(taskLaunchBody(task, { tool: "claude-code" }).prompt_sha256, "cd".repeat(32));
});

const tmModel: AssessModelSettings = {
  prompt_version: "tm.2",
  frameworks: "all",
  method_extras: "both",
  self_check: true,
  import_min_band: "low",
  findings_cap: 0,
  rerun_dedup: true,
};

test("the plan's settings in force name what the task asks for and what the import will do", () => {
  assert.deepEqual(assessModelLines(undefined), []);
  assert.deepEqual(assessModelLines(null), []);
  const tm = assessModelLines(tmModel).map((l) => l.text);
  assert.match(tm[0], /structured assessment\.json \(task version tm\.2\)/);
  assert.ok(tm.some((l) => l === "Frameworks asked for: STRIDE, LINDDUN and the AI frameworks."), tm.join("\n"));
  assert.ok(tm.some((l) => l === "Abuse cases and attack trees: both are asked for."), tm.join("\n"));
  assert.ok(tm.some((l) => /told to check its own file/.test(l)));
  // "No cap" is the developer's own setting: the importer still keeps at most 1,000 results per run, and the words say so.
  assert.ok(
    tm.some(
      (l) =>
        l ===
        "On import: every finding with a location in the code, no cap (the importer keeps at most 1,000 results per run); a re-run updates the findings you already imported.",
    ),
    tm.join("\n"),
  );
  // A pen test names its categories, not the threat model's sets; the other settings change the words.
  const pt = assessModelLines({
    prompt_version: "pt.2",
    categories: "auth_access",
    self_check: false,
    import_min_band: "high",
    findings_cap: 50,
    rerun_dedup: false,
  }).map((l) => l.text);
  assert.ok(pt.some((l) => l === "Test categories: Authentication and access control only."), pt.join("\n"));
  assert.ok(!pt.some((l) => /Frameworks asked for|Abuse cases/.test(l)));
  assert.ok(pt.some((l) => /not asked to check its own file/.test(l)));
  assert.ok(pt.some((l) => l === "On import: findings at high risk and above, at most 50, highest risk first; each run's findings stay apart."), pt.join("\n"));
  for (const l of [...tm, ...pt]) assert.doesNotMatch(l, /verified|confirmed|\bclean\b/i);
});

test("a launch refused because the task changed has its own words; any other refusal shows the server's text", () => {
  const refusal = (code: string) => ({ status: 409, body: JSON.stringify({ error: "x", code, prompt: "SECURITY ASSESSMENT: ...", prompt_sha256: "ab" }) });
  const words = assessLaunchRefusal(refusal("plan_changed"));
  assert.match(words ?? "", /The task changed after you read it/);
  assert.match(words ?? "", /Nothing was started\./);
  assert.match(words ?? "", /open the assessment again to read the new task/);
  // Every other 409 has words too: a code with a row reads as the row, one without as the server's own sentence.
  assert.match(assessLaunchRefusal(refusal("held_run_mismatch")) ?? "", /^X\.$/);
  assert.match(assessLaunchRefusal(refusal("run_record_busy")) ?? "", /Another Observer process is writing the run record/);
  assert.equal(assessLaunchRefusal({ status: 409, body: JSON.stringify({ error: "a rule nobody mapped", code: "brand_new" }) }), "A rule nobody mapped.");
  // The older routes' plain-text 409 reads as the server's sentence.
  assert.equal(assessLaunchRefusal({ status: 409, body: "that run was already started: read the plan again\n" }), "That run was already started: read the plan again.");
  // Any other status keeps the dialog's own text (the org terminal gate's 403, say).
  assert.equal(assessLaunchRefusal({ status: 403, body: "terminals are off for your organization" }), null);
  assert.equal(assessLaunchRefusal({ status: 409, body: "" }), null);
  assert.equal(assessLaunchRefusal(new Error("boom")), null);
  assert.equal(assessLaunchRefusal(null), null);
  // The task the dialog is opened with carries it.
  assert.equal(assessTaskFor(plan()).refusalText, assessLaunchRefusal);
});

// --- Review fixes: local reference credit, unchecked references, the run record ---

test("the reference tally says found NEAR the cited line and what the other counts mean", () => {
  const all = { found: 4, exists: 3, claimed_not_found: 2, missing: 1, invalid: 5, unchecked: 6 };
  assert.equal(
    assessRefTallyWords(all),
    "References: 4 found near the cited line, 3 exist with nothing matched near the cited line, 2 cited text not found in the cited range, 1 missing, 5 malformed, 6 not checked.",
  );
  assert.equal(assessRefTallyWords({ ...zeroRefs, found: 1 }), "References: 1 found near the cited line.");
  assert.equal(assessRefTallyWords({ ...zeroRefs, exists: 2 }), "References: 2 exist with nothing matched near the cited line.");
  // One reference reads as one: "1 exists", never "1 exist".
  assert.equal(assessRefTallyWords({ ...zeroRefs, exists: 1 }), "References: 1 exists with nothing matched near the cited line.");
  assert.equal(assessRefTallyWords({ ...zeroRefs, claimed_not_found: 1 }), "References: 1 cited text not found in the cited range.");
  assert.equal(assessRefTallyWords({ ...zeroRefs, unchecked: 9 }), "References: 9 not checked.");
  assert.doesNotMatch(assessRefTallyWords(all), /found at the cited line/);
  // The source's own comments do not teach the old rule either.
  assert.doesNotMatch(readFileSync(new URL("./secAssess.ts", import.meta.url), "utf8"), /found at the cited line/i);
});

test("a partial validation names each cause: refused items, references past the check's budget, both, or neither", () => {
  const where = "The budget is set in Settings > Guard > Code security.";
  // These checks kept no window, so each tally says its conditions were not recorded (N-20).
  const unrecorded = ASSESS_WINDOW_UNRECORDED;
  // Refused items only: the line it always had.
  const refused = assessValidationLine({ state: "partial", at: "t", refused: 2, refs: zeroRefs });
  assert.equal(refused?.text, "Model checked: 2 items were refused.");
  assert.equal(refused?.tone, "warn");
  // References the check ran out of budget for, nothing refused: it says so and keeps the tally.
  const unchecked = assessValidationLine({ state: "partial", at: "t", refs: { ...zeroRefs, found: 7, unchecked: 3 } });
  assert.equal(
    unchecked?.text,
    `Model checked: 3 references could not be checked within the check's budget, so the model is only partly checked. ${where} References: 7 found near the cited line, 3 not checked. ${unrecorded}`,
  );
  assert.equal(unchecked?.tone, "warn");
  assert.doesNotMatch(unchecked?.text ?? "", /some items were left out|nothing was refused|verified|confirmed|\bclean\b/i);
  assert.match(
    assessValidationLine({ state: "partial", at: "t", refs: { ...zeroRefs, unchecked: 1 } })?.text ?? "",
    /^Model checked: 1 reference could not be checked within the check's budget/,
  );
  // Both causes: each is said once, the refused items first.
  const both = assessValidationLine({ state: "partial", at: "t", refused: 1, refs: { ...zeroRefs, found: 2, unchecked: 4 } });
  assert.equal(
    both?.text,
    `Model checked: 1 item was refused. 4 references could not be checked within the check's budget, so the model is only partly checked. ${where} References: 2 found near the cited line, 4 not checked. ${unrecorded}`,
  );
  // Neither count: the items the validator left out, as before.
  const neither = assessValidationLine({ state: "partial", at: "t", refs: zeroRefs });
  assert.equal(neither?.text, "Model checked: some items were left out.");
  assert.equal(neither?.tone, "warn");
  // A stale partial keeps its stale line after the cause.
  assert.match(
    assessValidationLine({ state: "partial", at: "t", stale: true, refs: { ...zeroRefs, unchecked: 2 } })?.text ?? "",
    /only partly checked\..*The model changed after this check; check it again\.$/,
  );
});

test("a model too large to keep reads as final: the reason in words, no Validate; a lost copy still offers Validate", () => {
  const line = assessImportLine(imp({ outcome: "failed", reason: "model_too_large_to_keep" }));
  assert.equal(line, ASSESS_IMPORT_REASONS.model_too_large_to_keep);
  assert.equal(
    line,
    "The checked model is too large to keep, so no findings can be derived from it. Checking it again will not change that: have the agent write a smaller assessment.json, then check that.",
  );
  assert.doesNotMatch(line, /verified|confirmed|\bclean\b/i);
  // It is its own reason: not the generic failure, not the lost-copy words.
  assert.notEqual(line, "The import failed.");
  assert.notEqual(line, ASSESS_IMPORT_REASONS.model_unavailable);
  const base = run({
    contract: "pentest.v1",
    state: "import_failed",
    files: { report: true, sarif: false, commands: false, model: true },
    validation: { state: "valid", at: "t", refs: zeroRefs },
  });
  assert.equal(assessCanValidate({ ...base, import: imp({ outcome: "failed", reason: "model_too_large_to_keep" }) }), false);
  assert.equal(assessCanValidate({ ...base, import: imp({ outcome: "failed", reason: "model_unavailable" }) }), true);
});

// goRefusalCodes reads every machine code the Go assess routes can answer a
// refusal with out of the sources, the way the other cross-language pins in
// this directory read a Go table: the eligibility and consent code constants
// (internal/secassess), and the codes the dashboard's assess handlers write
// (constants, {"code": "..."} bodies, Code: fields and refusal calls).
function goRefusalCodes(): Map<string, string> {
  const repo = new URL("../../../", import.meta.url);
  const found = new Map<string, string>();
  const add = (file: string, src: string, res: RegExp[]) => {
    for (const re of res) for (const m of src.matchAll(re)) if (!found.has(m[1])) found.set(m[1], file);
  };
  for (const f of ["internal/secassess/eligible.go", "internal/secassess/consent.go"]) {
    add(f, readFileSync(new URL(f, repo), "utf8"), [/^\s*Code[A-Za-z]*\s*=\s*"([a-z0-9_]+)"/gm]);
  }
  const dir = new URL("internal/intelligence/dashboard/", repo);
  for (const f of readdirSync(dir)) {
    if (!/^security_assess.*\.go$/.test(f) || f.endsWith("_test.go")) continue;
    add(f, readFileSync(new URL(f, dir), "utf8"), [
      /^\s*(?:const\s+)?code[A-Z][A-Za-z]*\s*=\s*"([a-z0-9_]+)"/gm,
      /"code":\s*"([a-z0-9_]+)"/g,
      /\bCode:\s*"([a-z0-9_]+)"/g,
      /writeSecurityAssessRefusal\(w,\s*[^,]+,\s*[^,]*,\s*"([a-z0-9_]+)"/g,
      /http\.Status[A-Za-z]+,\s*"([a-z0-9_]+)",/g,
    ]);
  }
  return found;
}

test("every refusal code the Go assess routes can send has words, and no row names a code Go never sends", () => {
  const go = goRefusalCodes();
  // The pin must have read the sources: the eligibility rows alone are eleven codes.
  assert.ok(go.size >= 40, `read only ${go.size} codes from the Go sources: ${[...go.keys()].join(", ")}`);
  for (const must of ["run_record_unreadable", "run_record_full", "run_record_busy", "plan_changed", "not_validated", "sandbox_unavailable", "relax_disabled", "validation_timeout", "not_held"]) {
    assert.ok(go.has(must), `the pin did not read ${must}: its patterns have drifted from the Go sources`);
  }
  for (const [code, file] of go) {
    assert.ok(Object.prototype.hasOwnProperty.call(ASSESS_REFUSALS, code), `${file} sends the code ${code}, which has no words in ASSESS_REFUSALS`);
  }
  for (const code of Object.keys(ASSESS_REFUSALS)) {
    assert.ok(go.has(code), `ASSESS_REFUSALS has a row for ${code}, which no Go assess route sends`);
  }
});

// One row per code: a plain sentence, the server's own sentence where that names the cause.
for (const [code, row] of Object.entries(ASSESS_REFUSALS)) {
  test(`refusal ${code} has words; ${row.own ? "the server's sentence wins when it names the cause" : "the words are the table's"}`, () => {
    const server = "the server's own sentence about the cause";
    const w = assessRefusalWords({ status: 409, body: JSON.stringify({ error: server, code }) });
    assert.equal(w, row.own ? "The server's own sentence about the cause." : row.words);
    // With no sentence from the server the row's words stand alone.
    assert.equal(assessRefusalWords({ status: 409, body: JSON.stringify({ code }) }), row.words);
    assert.match(row.words, /^[A-Z][\s\S]*[.]$/, "a sentence, not a fragment");
    assert.doesNotMatch(row.words, /verified|confirmed|\bclean\b/i);
    assert.doesNotMatch(row.words, /[\u{1F300}-\u{1FAFF}\u2600-\u27BF]/u, "plain words, no emoji");
  });
}

test("the run record's three refusals each say what happened, and the unreadable one the way out and what it costs", () => {
  const file = "/home/u/.observer/secassess-runs.json";
  const body = (code: string) => JSON.stringify({ error: "the server's text", code, file });
  const unreadable = assessRefusalWords({ status: 409, body: body("run_record_unreadable") }) ?? "";
  assert.match(unreadable, /no assessment run is started or changed/);
  assert.match(unreadable, /no time limit, no Stop and no closing check/);
  assert.match(unreadable, /close any other Observer that has it open/);
  assert.match(unreadable, /rename secassess-runs\.json to secassess-runs\.json\.bad/);
  assert.match(unreadable, /The run list and each listed run's stored evidence will be gone/);
  assert.match(unreadable, /the project files and the reports under \.observer\/assessments are untouched/);
  // The file's path is named, for this code only.
  assert.ok(unreadable.endsWith(` The file is ${file}.`), unreadable);
  assert.equal(ASSESS_RUN_RECORD_FILE, "secassess-runs.json");
  const full = assessRefusalWords({ status: 409, body: body("run_record_full") }) ?? "";
  assert.match(full, /full of runs that are still in use/);
  assert.match(full, /Stop a running assessment, or wait for it to end/);
  assert.doesNotMatch(full, /The file is/);
  assert.match(assessRefusalWords({ status: 409, body: body("run_record_busy") }) ?? "", /Another Observer process is writing the run record\. Try again in a moment\./);
  // Never the generic words of the buttons that used to answer every 409 alike.
  for (const code of ["run_record_unreadable", "run_record_full", "run_record_busy"]) {
    const w = assessRefusalWords({ status: 409, body: body(code) }) ?? "";
    assert.doesNotMatch(w, /cannot be validated yet|no terminal to stop|no longer listed|no findings file|no longer waiting/i, code);
  }
});

test("Stop, Validate, Delete, Cancel and Import show the server's real answer, never one generic sentence", () => {
  const e = (code: string, error = "x") => ({ status: 409, body: JSON.stringify({ error, code }) });
  // Stop and Validate answer not_started alike; Validate also has its own.
  assert.match(assessRefusalWords(e("not_started")) ?? "", /no terminal to stop and no model to check yet/);
  assert.match(assessRefusalWords(e("run_running")) ?? "", /Validate again when it ends, or use Validate anyway/);
  assert.match(assessRefusalWords(e("no_model")) ?? "", /has not written assessment\.json yet/);
  assert.match(assessRefusalWords(e("project_gone")) ?? "", /folder is no longer on this machine/);
  assert.match(assessRefusalWords(e("no_model_contract")) ?? "", /not started under a result contract/);
  assert.match(assessRefusalWords(e("not_held")) ?? "", /no longer waiting for your organization/);
  // A 504 is a refusal with words too (validation_timeout), though not a 409.
  assert.match(
    assessRefusalWords({ status: 504, body: JSON.stringify({ error: "the validation did not finish in time", code: "validation_timeout" }) }) ?? "",
    /did not finish in time\. Nothing was recorded/,
  );
  // A code the table has no row for reads as the server's own sentence, whatever the status.
  assert.equal(assessRefusalWords(e("newer_server_code", "the run is in a state this page does not know")), "The run is in a state this page does not know.");
  assert.equal(assessRefusalWords({ status: 500, body: JSON.stringify({ error: "disk full" }) }), "Disk full.");
  // A plain-text 409 reads as the server's sentence; other plain text is left to the caller.
  assert.equal(assessRefusalWords({ status: 409, body: "the run is already over\n" }), "The run is already over.");
  assert.equal(assessRefusalWords({ status: 404, body: "unknown run" }), null);
  assert.equal(assessRefusalWords({ status: 409, body: "   " }), null);
  assert.equal(assessRefusalWords({ status: 409, body: JSON.stringify({ code: "newer_server_code" }) }), null);
  assert.equal(assessRefusalWords(new Error("network down")), null);
  assert.equal(assessRefusalWords(undefined), null);
  assert.equal(assessRefusalWords({ status: "409", body: "x" }), null);
  // A code that is a property of every object is not a row.
  assert.equal(assessRefusalWords(e("constructor", "plain")), "Plain.");
  assert.equal(assessRefusalWords(e("__proto__", "plain")), "Plain.");
  // A JSON array body is not a refusal object: a 409 shows it as text, any other status leaves it to the caller.
  assert.equal(assessRefusalWords({ status: 409, body: "[1,2]" }), "[1,2].");
  assert.equal(assessRefusalWords({ status: 500, body: "[1,2]" }), null);
});

test("the report dialog's words keep the file's own states and give a 409 the run record's words", () => {
  assert.equal(assessReportError(404), "The report is not there yet. The agent writes it when it finishes.");
  assert.match(assessReportError(413), /over the size cap/);
  assert.match(assessReportError(422), /not a plain file/);
  assert.equal(assessReportError(500), "The report could not be read.");
  assert.equal(assessReportError(409), "The report could not be read.");
  assert.match(assessReportError(409, JSON.stringify({ error: "x", code: "run_record_busy" })), /Another Observer process is writing the run record/);
  assert.match(
    assessReportError(409, JSON.stringify({ error: "x", code: "run_record_unreadable", file: "/d/secassess-runs.json" })),
    /rename secassess-runs\.json to secassess-runs\.json\.bad/,
  );
});

test("the unreadable run record is said with its file, the steps that free it and what they cost; no step is a button", () => {
  const w = assessRunsUnreadableWords("D:\\data\\.observer\\secassess-runs.json");
  assert.equal(w.line, "The run record (secassess-runs.json) cannot be read, so runs may be missing from this list. Nothing was deleted.");
  assert.ok(w.line.length <= 160, "the callout's one line");
  assert.equal(w.where, "The record is D:\\data\\.observer\\secassess-runs.json.");
  assert.deepEqual(w.steps, [
    "Close any other Observer that has this file open.",
    "In Observer's data folder, rename secassess-runs.json to secassess-runs.json.bad.",
    "Reopen this page.",
  ]);
  assert.match(w.effect, /no run can be started, stopped, checked or imported/);
  assert.match(w.effect, /Observer does not move it for you/);
  assert.equal(
    w.cost,
    "The run list and each listed run's stored evidence (its checked model and git snapshots) will be gone. The project files and the reports under .observer/assessments in each project are untouched.",
  );
  // Without the path (an older server) the file is still named.
  const bare = assessRunsUnreadableWords();
  assert.match(bare.line, /\(secassess-runs\.json\)/);
  assert.equal(bare.where, "The record is secassess-runs.json, in Observer's data folder.");
  assert.equal(assessRunsUnreadableWords("/home/u/.observer/secassess-runs.json").line, bare.line);
  for (const t of [w.line, w.where, w.effect, w.cost, ...w.steps]) assert.doesNotMatch(t, /verified|confirmed|\bclean\b/i);
});

test("the help says found NEAR the cited line, the budget, the partial git check and the importer's ceiling", () => {
  const help = (id: string) => {
    const e = HELP_REGISTRY.find((x) => x.id === id);
    assert.ok(e, `no help entry ${id}`);
    return `${e.oneLiner}\n${e.detail ?? ""}`;
  };
  const runs = help("card.code_security_assess_runs");
  const limits = help("card.code_security_assess_limits");
  const plan = help("card.code_security_assess_plan");
  for (const [id, t] of [["runs", runs], ["limits", limits], ["plan", plan]] as const) {
    assert.doesNotMatch(t, /found at the cited line/i, `${id} still says found AT the cited line`);
  }
  // Found near the cited line, within the match window, a setting.
  assert.match(runs, /found near the cited line \(the text the agent quoted is on a code line within the match window of the first line it cited, 5 lines by default, a setting/);
  assert.match(runs, /1 means the cited line itself/);
  assert.match(runs, /exist with nothing matched near the cited line/);
  assert.match(runs, /cite text that is nowhere in the cited range/);
  assert.match(runs, /A reference counts as found only near the line the agent cited, never for a match elsewhere in a long range/);
  // Unchecked references: the budget, and the partial state.
  assert.match(runs, /ran out of budget for read not checked, never found/);
  assert.match(runs, /could not be checked within the check's budget, and the model then reads as only partly checked/);
  // The unreadable run record, with the way out and its cost, and no button.
  assert.match(runs, /secassess-runs\.json/);
  assert.match(runs, /rename it to secassess-runs\.json\.bad and reopen this page/);
  assert.match(runs, /Observer does not move the file for you/);
  // The model too large to keep.
  assert.match(runs, /too large for Observer to keep/);
  // The git check: the fourth outcome, content comparison, tracked-only for a pen test, and never clean.
  assert.match(limits, /No change seen in the files that could be compared; some changed files could not be compared/);
  assert.match(limits, /more than 400 paths changed, or a file could not be read in time, is a folder or is over 32 MiB/);
  assert.match(limits, /Each changed and untracked file is compared by its content, so a second edit of a file that was already modified is seen\./);
  assert.match(limits, /A penetration test or red team still ignores untracked churn such as build caches, so it compares tracked files by content only/);
  assert.match(limits, /It still never says clean/);
  // "No cap" says the importer's own ceiling.
  assert.match(limits, /the cap, which is none by default though the importer keeps at most 1,000 results per run whatever it is/);
});

test("the settings' help agrees with the words: the git check's comparison, the cap's ceiling, the reference window and budgets", () => {
  const row = (key: string) => {
    const r = CODE_SECURITY_SETTINGS.find((x) => x.key === key);
    assert.ok(r, key);
    return r;
  };
  assert.ok(
    row("security.assessments.boundary_audit").help.endsWith(
      "Changed and untracked files are compared by their content, up to 400 paths; one that cannot be read in time, is a folder or is over 32 MiB is not compared, and the row then says it was only partly checked.",
    ),
  );
  const cap = row("security.assessments.findings_cap");
  assert.match(cap.help, /the importer keeps at most 1,000 results per run whatever this is/);
  assert.equal(cap.optionLabels?.["0"], "No cap (the importer keeps at most 1,000 per run)");
  assert.match(row("security.assessments.model_max_mib").help, /the importer separately keeps at most 1,000 results per run/);
  const win = row("security.assessments.ref_match_window_lines");
  assert.match(win.help, /found only when the text the agent quoted is on a code line within this many lines of the first line it cited \(1 is the cited line itself\)/);
  assert.match(win.help, /exists with nothing matched near the cited line/);
  for (const key of ["ref_budget_files", "ref_budget_mib", "ref_budget_seconds"]) {
    const h = row(`security.assessments.${key}`).help;
    assert.match(h, /read not checked/, key);
    assert.match(h, /partial/, key);
  }
  // No setting teaches the old rule.
  for (const r of CODE_SECURITY_SETTINGS) assert.doesNotMatch(r.help, /found at the cited line/i, r.key);
});

test("every button that can be refused turns the answer into words through the one table", () => {
  const dir = new URL("../components/secassess/", import.meta.url);
  const list = readFileSync(new URL("AssessRunsList.tsx", dir), "utf8");
  // Import, Cancel, and Stop / Validate / Delete (post) each ask the table first.
  assert.equal((list.match(/assessRefusalWords\(e\) \?\?/g) ?? []).length, 3);
  assert.match(list, /ASSESS_STOP_PATH/);
  assert.match(list, /ASSESS_VALIDATE_PATH/);
  const planSrc = readFileSync(new URL("AssessPlanDialog.tsx", dir), "utf8");
  assert.match(planSrc, /setAskErr\(assessRefusalWords\(e\) \?\? apiReason\(e\)\)/);
  const report = readFileSync(new URL("AssessReportDialog.tsx", dir), "utf8");
  assert.match(report, /assessReportError\(res\.status, body\)/);
  // The launch goes through the New terminal dialog's refusalText hook.
  assert.equal(assessTaskFor(plan()).refusalText, assessLaunchRefusal);
  // The card shows the recovery callout from the one words function, not a literal.
  const card = readFileSync(new URL("SecAssessCard.tsx", dir), "utf8");
  assert.match(card, /assessRunsUnreadableWords\(file\)/);
  assert.match(card, /<RunsUnreadable file=\{data\.runs_file\} \/>/);
});

// --- The plan's choices and facts (depth plan W3.2 to W3.4, W4.1 to W4.6) ----

const scopeBlock: AssessScope = { dirs: ["cmd", "internal", "web"], paths: [], note: "", max_paths: 8, max_note: 200 };
const groundingFull: AssessGrounding = {
  mode: "full",
  sections: ["languages", "manifests", "infra", "spec", "dependencies", "findings"],
  bytes: 3174,
  dropped: 0,
  ai_app: false,
};

test("an untouched dialog reads and launches exactly what it always did", () => {
  // No choices: the plan address and the launch body are the ones of the earlier waves.
  assert.equal(assessPlanPath("threat_model", "h1", undefined, undefined, undefined, ASSESS_NO_CHOICES), assessPlanPath("threat_model", "h1"));
  assert.equal(assessPlanPath("threat_model", "h1", undefined, undefined, undefined, {}), "/api/security/assessments/plan?kind=threat_model&project=h1");
  assert.deepEqual(assessLaunchBody(plan({ kind: threat, target: undefined }), ASSESS_NO_TICKS, ASSESS_NO_CHOICES), assessLaunchBody(plan({ kind: threat, target: undefined })));
  const body = assessLaunchBody(plan({ kind: threat, target: undefined, scope: scopeBlock }), ASSESS_NO_TICKS, {});
  for (const k of ["scope_paths", "scope_note", "previous_run", "start"]) assert.ok(!(k in body), `${k} is sent only when chosen`);
  // Blank choices are not choices.
  const blank = { scopePaths: ["", "  "], scopeNote: "   ", previousRun: "", start: " " };
  assert.equal(assessPlanPath("threat_model", "h1", undefined, undefined, undefined, blank), "/api/security/assessments/plan?kind=threat_model&project=h1");
  assert.deepEqual(assessLaunchBody(plan({ kind: threat, target: undefined }), ASSESS_NO_TICKS, blank), assessLaunchBody(plan({ kind: threat, target: undefined })));
});

test("the plan address carries each choice: places (repeated), note, comparison, start command", () => {
  const url = assessPlanPath("threat_model", "h1", undefined, undefined, undefined, {
    scopePaths: ["cmd/api", " internal/db ", "cmd/api"],
    scopeNote: "  the payment flow  ",
    previousRun: "00000000000000a1",
  });
  const qs = new URL(url, "http://x").searchParams;
  assert.deepEqual(qs.getAll("scope_path"), ["cmd/api", "internal/db"], "trimmed, in the order chosen, each once");
  assert.equal(qs.get("scope_note"), "the payment flow");
  assert.equal(qs.get("previous_run"), "00000000000000a1");
  assert.equal(qs.get("start"), null);
  // The words that mean "no comparison" and "no declared command" are sent as chosen.
  assert.equal(new URL(assessPlanPath("threat_model", "h1", undefined, undefined, undefined, { previousRun: ASSESS_NONE }), "http://x").searchParams.get("previous_run"), "none");
  const pt = new URL(assessPlanPath("pentest_local", "h1", "http://localhost:3000/", ASSESS_NO_TICKS, "r9", { start: "npm run dev" }), "http://x").searchParams;
  assert.equal(pt.get("start"), "npm run dev");
  assert.equal(pt.get("run"), "r9", "the held run's id still travels");
  assert.equal(new URL(assessPlanPath("pentest_local", "h1", undefined, undefined, undefined, { start: ASSESS_NONE }), "http://x").searchParams.get("start"), "none");
  // The earlier parameters keep their place and spelling.
  assert.ok(url.startsWith("/api/security/assessments/plan?kind=threat_model&project=h1&scope_path=cmd%2Fapi"), url);
});

test("the launch carries the same choices the plan was read with, and only those", () => {
  const choices = { scopePaths: ["cmd/api", "internal/db"], scopeNote: " payment flow ", previousRun: "00000000000000a1" };
  const p = plan({ kind: threat, target: undefined, scope: { ...scopeBlock, paths: ["cmd/api", "internal/db"] } });
  const body = assessLaunchBody(p, ASSESS_NO_TICKS, choices);
  assert.deepEqual(body.scope_paths, ["cmd/api", "internal/db"]);
  assert.equal(body.scope_note, "payment flow");
  assert.equal(body.previous_run, "00000000000000a1");
  assert.ok(!("start" in body));
  // The places the plan read carried equal the places the launch carries.
  const read = new URL(assessPlanPath("threat_model", "h1", undefined, undefined, undefined, choices), "http://x").searchParams;
  assert.deepEqual(read.getAll("scope_path"), body.scope_paths);
  assert.equal(read.get("scope_note"), body.scope_note);
  assert.equal(read.get("previous_run"), body.previous_run);
  // A typed place the server refused is not sent: the launch rebuilds the task that was read.
  const refused = plan({ kind: threat, target: undefined, scope: { ...scopeBlock, paths: ["cmd/api"], refused: [{ path: "../etc", reason: "outside the project" }] } });
  assert.deepEqual(assessLaunchBody(refused, ASSESS_NO_TICKS, { scopePaths: ["cmd/api", "../etc"] }).scope_paths, ["cmd/api"]);
  // Every place refused: nothing is sent for the scope.
  const none = plan({ kind: threat, target: undefined, scope: { ...scopeBlock, paths: [] } });
  assert.ok(!("scope_paths" in assessLaunchBody(none, ASSESS_NO_TICKS, { scopePaths: ["../etc"] })));
  // A plan with no scope block sends what was chosen.
  assert.deepEqual(assessLaunchBody(plan({ kind: threat, target: undefined }), ASSESS_NO_TICKS, { scopePaths: ["a"] }).scope_paths, ["a"]);
  // A pen test sends its start command, with the words for none.
  assert.equal(assessLaunchBody(plan(), ASSESS_NO_TICKS, { start: " npm run dev " }).start, "npm run dev");
  assert.equal(assessLaunchBody(plan(), ASSESS_NO_TICKS, { start: ASSESS_NONE }).start, "none");
  // It reaches the launch route through the New terminal dialog's own body.
  const task = assessTaskFor(p, undefined, ASSESS_NO_TICKS, choices);
  assert.deepEqual(task.launchBody.scope_paths, ["cmd/api", "internal/db"]);
  assert.equal(taskLaunchBody(task, { tool: "claude-code" }).previous_run, "00000000000000a1");
  assert.ok(!("scope_paths" in assessTaskFor(p).launchBody));
});

test("the request to the organization is unchanged by the plan's choices", () => {
  assert.deepEqual(assessRequestBody(plan(), { rules: ["R-179"], tier: false }), {
    assessment: "pentest_local",
    project_root_hash: "h1",
    run_id: "20261114-ab12cd",
    relaxations: ["R-179"],
    target: "http://localhost:3000/",
  });
});

test("the scope reads as the whole project until places are chosen, then as a request the agent is not held to", () => {
  assert.equal(assessScopeChoiceLine(undefined), "");
  assert.equal(assessScopeChoiceLine(null), "");
  assert.equal(assessScopeChoiceLine(scopeBlock), "By default the whole project is covered.");
  const one = assessScopeChoiceLine({ paths: ["cmd/api"] });
  assert.match(one, /^The task asks the agent to model only cmd\/api\./);
  assert.match(one, /It may read the rest for what calls it or what it calls/);
  assert.match(one, /told to list everything else as out of scope/);
  assert.match(one, /That is a request in the task: the agent is not stopped from reading anything\.$/);
  assert.match(assessScopeChoiceLine({ paths: ["cmd/api", "internal/db"] }), /model only cmd\/api, internal\/db\./);
});

test("ticking and unticking places keeps each once, refuses past the cap in words, and ignores a blank", () => {
  assert.deepEqual(assessScopeToggle([], "cmd", true, 8), { paths: ["cmd"] });
  assert.deepEqual(assessScopeToggle(["cmd"], " internal ", true, 8), { paths: ["cmd", "internal"] });
  assert.deepEqual(assessScopeToggle(["cmd"], "cmd", true, 8), { paths: ["cmd"] }, "a place already chosen is not added twice");
  assert.deepEqual(assessScopeToggle(["cmd", "web"], "cmd", false, 8), { paths: ["web"] });
  assert.deepEqual(assessScopeToggle(["cmd"], "   ", true, 8), { paths: ["cmd"] });
  const full = ["a", "b", "c"];
  assert.deepEqual(assessScopeToggle(full, "d", true, 3), { paths: full, error: "At most 3 places. Remove one first." });
  // Removing at the cap still works, and a cap of 0 means the server's, so none is applied here.
  assert.deepEqual(assessScopeToggle(full, "c", false, 3), { paths: ["a", "b"] });
  assert.deepEqual(assessScopeToggle(full, "d", true, 0), { paths: ["a", "b", "c", "d"] });
  // The caller's list is never changed in place.
  assert.deepEqual(full, ["a", "b", "c"]);
});

test("the project-facts line says what the digest holds, its size, what was left out and what Observer saw", () => {
  assert.equal(assessGroundingLine(undefined), "");
  assert.equal(assessGroundingLine(null), "");
  assert.equal(assessGroundingLine(groundingFull), "The task carries a digest of facts from the project: 6 sections, 3.1 KiB.");
  assert.equal(assessGroundingLine({ ...groundingFull, mode: "off", sections: [], bytes: 0 }), "No digest: the setting is off.");
  assert.equal(
    assessGroundingLine({ ...groundingFull, mode: "without_findings", sections: ["languages", "manifests"], bytes: 900 }),
    "The task carries a digest of facts from the project, without the open findings: 2 sections, 900 bytes.",
  );
  assert.equal(assessGroundingLine({ ...groundingFull, sections: ["languages"], bytes: 1024 }), "The task carries a digest of facts from the project: 1 section, 1.0 KiB.");
  assert.equal(
    assessGroundingLine({ ...groundingFull, dropped: 3 }),
    "The task carries a digest of facts from the project: 6 sections, 3.1 KiB. 3 strings were left out (characters the task does not accept, or the size cap).",
  );
  assert.match(assessGroundingLine({ ...groundingFull, dropped: 1 }), / 1 string was left out /);
  assert.match(assessGroundingLine({ ...groundingFull, ai_app: true }), / Observer found signs that it is an AI application\.$/);
  // Nothing readable is said, not an empty digest passed off as facts.
  assert.equal(assessGroundingLine({ ...groundingFull, sections: [], bytes: 0 }), "The task carries a digest of facts from the project: nothing could be read from the project's files.");
});

test("the comparison line and its picker labels name the earlier run, or say there is none", () => {
  const fmt = (iso: string) => `on ${iso.slice(0, 10)}`;
  const prev: AssessPrevious = {
    options: [
      { id: "00000000000000a1", created_at: "2026-11-13T09:00:00Z", scope: ["cmd/api"] },
      { id: "00000000000000a0", created_at: "2026-11-12T09:00:00Z" },
    ],
    selected: "00000000000000a1",
    default_run: "00000000000000a1",
    note: ASSESS_PREVIOUS_NOTE,
  };
  assert.equal(assessPreviousLine(undefined), "");
  assert.equal(assessPreviousLine(prev, fmt), "Compared with the earlier run (Threat model, on 2026-11-13) once the new model is checked.");
  assert.equal(assessPreviousLine(prev), "Compared with the earlier run (Threat model, 2026-11-13) once the new model is checked.");
  assert.equal(assessPreviousLine({ ...prev, selected: "" }), "No comparison: nothing is compared once the new model is checked.");
  assert.equal(
    assessPreviousLine({ ...prev, options: [], selected: "", default_run: "" }),
    "No earlier checked threat model of this project exists, so there is nothing to compare with.",
  );
  // A pick the list no longer holds has no checked copy: the line does not promise a comparison.
  assert.equal(assessPreviousLine({ ...prev, selected: "gone" }), "The earlier run chosen is no longer among the earlier checked runs, so there may be nothing to compare with.");
  assert.doesNotMatch(assessPreviousLine({ ...prev, selected: "gone" }), /^Compared with/);
  assert.equal(assessPreviousOptionLabel(prev.options[0], fmt), "Threat model, on 2026-11-13, scope cmd/api");
  assert.equal(assessPreviousOptionLabel(prev.options[1], fmt), "Threat model, on 2026-11-12");
  // No run id is on the page: a person asks which run, not which identifier.
  for (const s of [assessPreviousLine(prev, fmt), assessPreviousLine({ ...prev, selected: "gone" }), assessPreviousOptionLabel(prev.options[0], fmt)]) assert.doesNotMatch(s, /00000000000000a|gone/);
});

test("the sentence under the comparison picker claims no more than is true: nothing is given, folders are asked about, and it is a request", () => {
  assert.equal(
    ASSESS_PREVIOUS_NOTE,
    "Observer gives the agent nothing from the earlier run and asks it not to open other runs' folders. That is a request, not a barrier.",
  );
  assert.equal(assessPreviousNote(undefined), "");
  assert.equal(assessPreviousNote(null), "");
  // The server's own sentence is shown as it is; a blank one is the constant.
  assert.equal(assessPreviousNote({ note: "  the server says this  " }), "the server says this");
  assert.equal(assessPreviousNote({ note: "" }), ASSESS_PREVIOUS_NOTE);
  assert.equal(assessPreviousNote({ note: "   " }), ASSESS_PREVIOUS_NOTE);
  // The retired promise is nowhere in the dialog's own words.
  const dir = new URL("../components/secassess/", import.meta.url);
  for (const f of ["AssessPreviousPicker.tsx", "AssessPlanDialog.tsx", "AssessRunsList.tsx", "AssessScopePicker.tsx", "AssessStartPlan.tsx", "AssessBeforeStart.tsx", "SecAssessCard.tsx"]) {
    assert.doesNotMatch(readFileSync(new URL(f, dir), "utf8"), /Nothing from the earlier run is given to the agent/, f);
  }
  assert.doesNotMatch(readFileSync(new URL("secAssess.ts", import.meta.url), "utf8"), /Nothing from the earlier run is given to the agent/);
  // The picker shows it through the one function.
  assert.match(readFileSync(new URL("AssessPreviousPicker.tsx", dir), "utf8"), /assessPreviousNote\(previous\)/);
});

test("a run row says how its comparison went: still to come, made, not made because the earlier copy is gone, too large to keep", () => {
  assert.equal(assessCompareLine({}), "");
  assert.equal(assessCompareLine({ compare_state: "previous_missing" }), "", "no earlier run chosen, nothing to say");
  const E = "Threat model, Nov 13, 2026, 09:00";
  const p = { previous_run: "00000000000000a1" };
  assert.equal(assessCompareLine(p, E), "Compared with the earlier run (" + E + "): shown once the model is checked");
  assert.equal(assessCompareLine({ ...p, compare_state: "" }, E), "Compared with the earlier run (" + E + "): shown once the model is checked");
  assert.equal(assessCompareLine({ ...p, compare_state: "ok" }, E), "Compared with the earlier run (" + E + ")");
  assert.equal(
    assessCompareLine({ ...p, compare_state: "previous_missing" }, E),
    "Not compared with the earlier run (" + E + "): Observer no longer has a usable checked copy of it",
  );
  assert.equal(
    assessCompareLine({ ...p, compare_state: "too_large" }, E),
    "Compared with the earlier run (" + E + "), but the comparison was too large to keep",
  );
  // A state Observer has no words for never claims a comparison was made.
  assert.equal(
    assessCompareLine({ ...p, compare_state: "something_new" }, E),
    "The earlier run (" + E + ") was chosen for comparison; how it went is not shown here",
  );
  // The run list no longer holds the earlier run: it is said so, never named by its id.
  assert.equal(assessCompareLine({ ...p, compare_state: "ok" }), "Compared with an earlier run that is no longer in the list");
  assert.equal(assessCompareLine({ ...p, compare_state: "previous_missing" }, ""), "Not compared with an earlier run that is no longer in the list: Observer no longer has a usable checked copy of it");
  assert.equal(assessCompareLine({ ...p, compare_state: "something_new" }), "An earlier run that is no longer in the list was chosen for comparison; how it went is not shown here");
  for (const st of ["", "ok", "previous_missing", "too_large", "x"]) assert.doesNotMatch(assessCompareLine({ ...p, compare_state: st }, E), /00000000000000a1/);
  // The run row's second line is this one.
  assert.equal(assessRunScopeLines({ ...p, compare_state: "previous_missing" }, E).previous, assessCompareLine({ ...p, compare_state: "previous_missing" }, E));
});

test("one label names a run wherever one is chosen or mentioned: what it is, when, and how it stands", () => {
  const fmt = (iso: string) => "Nov " + iso.slice(8, 10) + ", 2026, " + iso.slice(11, 16);
  assert.equal(assessRunLabel("Threat model", "2026-11-15T14:57:00Z", fmt, "validated"), "Threat model, Nov 15, 2026, 14:57, validated");
  assert.equal(assessRunLabel("Threat model", "2026-11-15T14:57:00Z", fmt), "Threat model, Nov 15, 2026, 14:57");
  // The same label in all three places: the run row's line, the plan's picker, the model view's select.
  const created = "2026-11-15T14:57:00Z";
  const picker = assessPreviousOptionLabel({ id: "e34b2a55dfcdcc06", created_at: created }, fmt);
  assert.equal(picker, assessRunLabel("Threat model", created, fmt));
  assert.equal(assessCompareLine({ previous_run: "e34b2a55dfcdcc06", compare_state: "ok" }, picker), "Compared with the earlier run (" + picker + ")");
  // A run with no title or date still reads as a run of its kind, never as an id.
  assert.equal(assessRunLabel("", "", fmt), "Threat model");
  assert.equal(assessRunLabel(undefined, undefined), "Threat model");
  // Two runs a minute apart read differently, which an hour-granular label would not.
  assert.notEqual(assessRunLabel("Threat model", "2026-11-15T14:57:00Z", fmt, "validated"), assessRunLabel("Threat model", "2026-11-15T14:58:00Z", fmt, "validated"));
  // A kind's own title carries a clarifier in parentheses; a label is itself put in parentheses by the sentence that names the earlier run, so the clarifier does not nest ("(Penetration test (your own app, local), ...)").
  assert.equal(assessRunLabel("Penetration test (your own app, local)", "2026-11-15T09:00:00Z", fmt), "Penetration test, Nov 15, 2026, 09:00");
  assert.equal(assessRunLabel("Retest of earlier findings (your own app, local)", "2026-11-16T09:00:00Z", fmt), "Retest of earlier findings, Nov 16, 2026, 09:00");
  assert.equal(assessRunLabel("Red team exercise (your own app, local)", "2026-11-15T08:30:00Z", fmt, "validated"), "Red team exercise, Nov 15, 2026, 08:30, validated");
  // A title that is only a clarifier is not emptied into nothing; a title with no clarifier is untouched.
  assert.equal(assessRunLabel("(local)", "", fmt), "Threat model");
  assert.equal(assessRunLabel("Cloud posture review", "2026-11-11T10:00:00Z", fmt), "Cloud posture review, Nov 11, 2026, 10:00");
});

test("no start command is stated once: the start section says it, the preflight list leaves it out, and a field says Or only when something is above it", () => {
  const none: AssessStart = { plans: [], selected_command: "", edit: "", edited: false, none_found: true };
  const plan = { command: "npm run dev", port: 3000, source: "package.json" };
  const note = { id: "no_start_command", level: "warn", text: "The project names 1 start command, but none that can be written as a plain command; the agent will look for one or you can type it." };
  const other = { id: "start_port", level: "warn", text: "A port fact." };
  // The sentence: the server's when it came, the same words from here when it did not, nothing once a command is in force or a plan is offered.
  assert.equal(assessStartNoneWords(none, note.text), note.text);
  assert.equal(assessStartNoneWords(none), ASSESS_START_NONE_WORDS);
  assert.equal(assessStartNoneWords(none, "  "), ASSESS_START_NONE_WORDS);
  assert.equal(assessStartNoneWords({ ...none, selected_command: "make dev", edited: true }), "");
  assert.equal(assessStartNoneWords({ ...none, plans: [plan], none_found: false }), "");
  assert.equal(assessStartNoneWords({ ...none, none_found: false }), "", "a project that declares no command is the start line's to say");
  assert.equal(assessStartNoneWords(undefined), "");
  assert.equal(assessStartNote([other, note]), note.text);
  assert.equal(assessStartNote([other]), "");
  assert.equal(assessStartNote(undefined), "");
  // The preflight list loses only that note, and only while the start section is on the page.
  assert.deepEqual(assessPreflightApart([note, other], none), [other]);
  assert.deepEqual(assessPreflightApart([note, other], undefined), [note, other]);
  assert.equal(assessPreflightApart(undefined, none), undefined);
  // "Or" leads something.
  assert.equal(assessTypeLabel("the command", true), "Or type the command");
  assert.equal(assessTypeLabel("the command", false), "Type the command");
  // The sentence is one of the words the page may carry: no key, no id, no flag.
  assert.doesNotMatch(ASSESS_START_NONE_WORDS, /_|--|no_start/);
});

test("the start line says which command the agent is told to run, who typed it, or that it looks for one", () => {
  const start: AssessStart = { plans: [], selected_command: "npm run dev", edit: "npm run dev", edited: false, none_found: false };
  assert.equal(assessStartLine(undefined), "");
  assert.equal(assessStartLine(start), "The agent is told to start the application with: npm run dev.");
  assert.equal(assessStartLine({ ...start, edited: true }), "The agent is told to start the application with: npm run dev (typed by you).");
  assert.equal(assessStartLine({ ...start, selected_command: "", edit: "" }), "No start command is declared, so the agent is told to find one itself.");
  assert.equal(assessStartLine({ ...start, selected_command: "", edit: "", none_found: true }), "No start command was found, so the agent is told to find one itself.");
  assert.match(assessStartLine({ ...start, selected_command: "", edit: "", not_preselected: true }), /none was chosen for you/);
  // A start command that is chosen wins over the note that none was.
  assert.equal(assessStartLine({ ...start, not_preselected: true }), "The agent is told to start the application with: npm run dev.");
});

const startWithFolder: AssessStart = {
  plans: [
    { command: "npm run dev", port: 5173, source: "package.json scripts", cwd: "web", choice: "web::npm run dev" },
    { command: "npm run dev", port: 3000, source: "package.json scripts" },
    { command: "python manage.py runserver 8000", port: 8000, source: "manage.py", prepare: ["python manage.py migrate", "python manage.py loaddata seed"], needs: ["db"] },
  ],
  selected_command: "web::npm run dev",
  edit: "npm run dev",
  edited: false,
  none_found: false,
};

test("a start plan is picked by its choice, falling back to its command, and the field shows the command not the choice", () => {
  const [web, root, dj] = startWithFolder.plans;
  assert.equal(assessStartChoice(web), "web::npm run dev");
  assert.equal(assessStartChoice(root), "npm run dev", "no choice: the command is the choice");
  assert.equal(assessStartChoice({ command: "x", choice: "" }), "x");
  // The server's pick stands until the developer chooses.
  assert.equal(assessStartInForce(startWithFolder, undefined), "web::npm run dev");
  assert.equal(assessStartInForce(startWithFolder, "npm run dev"), "npm run dev");
  assert.equal(assessStartInForce(startWithFolder, ASSESS_NONE), "");
  assert.equal(assessStartInForce(startWithFolder, "make dev"), "make dev", "a typed command is its own choice");
  // Two plans with the same command in different folders are told apart by the choice.
  assert.equal(assessStartSelectedPlan(startWithFolder, undefined), web);
  assert.equal(assessStartSelectedPlan(startWithFolder, "npm run dev"), root);
  assert.equal(assessStartSelectedPlan(startWithFolder, dj.command), dj);
  assert.equal(assessStartSelectedPlan(startWithFolder, ASSESS_NONE), undefined);
  assert.equal(assessStartSelectedPlan(startWithFolder, "make dev"), undefined);
  // An older server with no choice at all: the command is what it sent back.
  const old: AssessStart = { plans: [{ command: "npm run dev", source: "s" }], selected_command: "npm run dev", edit: "npm run dev", edited: false, none_found: false };
  assert.equal(assessStartSelectedPlan(old, undefined)?.command, "npm run dev");
  // The field holds the command (a choice string is not a command), or the typed text, or nothing.
  assert.equal(assessStartText(startWithFolder, undefined), "npm run dev");
  assert.equal(assessStartText(startWithFolder, "npm run dev"), "npm run dev");
  assert.equal(assessStartText(startWithFolder, ASSESS_NONE), "");
  assert.equal(assessStartText(startWithFolder, "make dev"), "make dev");
  assert.equal(assessStartText({ ...startWithFolder, selected_command: "" }, undefined), "");
});

test("the start line names the folder a plan runs in, and the preparation steps only when they were chosen", () => {
  assert.equal(assessStartLine(startWithFolder), "The agent is told to start the application with: npm run dev (in web/).");
  assert.equal(assessStartLine({ ...startWithFolder, edited: true }), "The agent is told to start the application with: npm run dev (in web/, typed by you).");
  assert.equal(
    assessStartLine({ ...startWithFolder, selected_command: "npm run dev" }),
    "The agent is told to start the application with: npm run dev.",
    "the plan in the project's own folder says no folder",
  );
  const dj = { ...startWithFolder, selected_command: "python manage.py runserver 8000" };
  assert.equal(assessStartLine(dj), "The agent is told to start the application with: python manage.py runserver 8000.");
  assert.equal(assessStartLine({ ...dj, prepare: false }), "The agent is told to start the application with: python manage.py runserver 8000.");
  assert.equal(
    assessStartLine({ ...dj, prepare: true }),
    "The agent is told to start the application with: python manage.py runserver 8000. It is told to run the preparation steps first.",
  );
  // A plan with no steps never says it will run them, even if the flag is set.
  assert.equal(assessStartLine({ ...startWithFolder, prepare: true }), "The agent is told to start the application with: npm run dev (in web/).");
});

test("preparation steps are opt-in: off by default, on only for a plan that has steps and only when ticked or echoed by the server", () => {
  const dj = "python manage.py runserver 8000";
  assert.deepEqual(assessPrepareSteps(startWithFolder, dj), ["python manage.py migrate", "python manage.py loaddata seed"]);
  assert.deepEqual(assessPrepareSteps(startWithFolder, undefined), [], "the server's pick has none");
  assert.deepEqual(assessPrepareSteps(startWithFolder, ASSESS_NONE), []);
  assert.deepEqual(assessPrepareSteps(startWithFolder, "python manage.py runserver 9000"), [], "a typed command has none of its own");
  assert.deepEqual(assessPrepareSteps({ ...startWithFolder, plans: [{ command: "x", source: "s", prepare: ["  ", ""] }], selected_command: "x" }, undefined), [], "blank steps are no steps");
  // Default off, with or without a tick on the way.
  assert.equal(assessPrepareOn(startWithFolder, dj, undefined), false);
  assert.equal(assessPrepareOn({ ...startWithFolder, prepare: false }, dj, undefined), false);
  assert.equal(assessPrepareOn(startWithFolder, dj, true), true);
  assert.equal(assessPrepareOn(startWithFolder, dj, false), false);
  // A held run's echo shows its own choice; the developer's tick wins over it.
  assert.equal(assessPrepareOn({ ...startWithFolder, prepare: true }, dj, undefined), true);
  assert.equal(assessPrepareOn({ ...startWithFolder, prepare: true }, dj, false), false);
  // No steps on the plan in force: never on.
  assert.equal(assessPrepareOn({ ...startWithFolder, prepare: true }, undefined, true), false);
  assert.equal(assessPrepareOn({ ...startWithFolder, prepare: true }, ASSESS_NONE, true), false);
  assert.equal(ASSESS_PREPARE_LABEL, "Run the preparation steps first");
  assert.match(ASSESS_PREPARE_WARNING, /can change local data in the project, for example its database file\.$/);
});

test("the plan address and the bodies carry the preparation opt-in only when ticked, and a choice of plan or none does not carry it on its own", () => {
  const dj = "python manage.py runserver 8000";
  const q = (c: Parameters<typeof assessPlanPath>[5]) => new URL(assessPlanPath("pentest_local", "h1", "http://localhost:3000/", undefined, undefined, c), "http://x").searchParams;
  assert.equal(q({ start: dj }).get("prepare"), null, "absent means no");
  assert.equal(q({ start: dj, prepare: false }).get("prepare"), null);
  assert.equal(q({ start: dj, prepare: true }).get("prepare"), "yes");
  assert.equal(q({ start: dj, prepare: true }).get("start"), dj, "the start choice still travels beside it");
  assert.equal(q({ prepare: true }).get("prepare"), "yes", "the server's default plan can be prepared too");
  // The launch and the held request carry it, as a boolean, and only when on.
  assert.equal(assessLaunchBody(plan(), ASSESS_NO_TICKS, { start: dj, prepare: true }).prepare, true);
  assert.ok(!("prepare" in assessLaunchBody(plan(), ASSESS_NO_TICKS, { start: dj })));
  assert.ok(!("prepare" in assessLaunchBody(plan(), ASSESS_NO_TICKS, { start: dj, prepare: false })));
  const held = assessRequestBody(plan(), { rules: ["R-179"], tier: false }, { start: dj, prepare: true });
  assert.equal(held.prepare, true);
  assert.equal(held.start, dj);
  assert.ok(!("prepare" in assessRequestBody(plan(), { rules: ["R-179"], tier: false }, { start: dj })));
  // The New terminal dialog's own body gets it.
  assert.equal(assessTaskFor(plan(), undefined, ASSESS_NO_TICKS, { start: dj, prepare: true }).launchBody.prepare, true);
  assert.equal(taskLaunchBody(assessTaskFor(plan(), undefined, ASSESS_NO_TICKS, { start: dj, prepare: true }), { tool: "claude-code" }).prepare, true);
  // The plan read and the launch carry the same opt-in.
  const c = { start: "web::npm run dev", prepare: true };
  assert.equal(q(c).get("start"), assessLaunchBody(plan(), ASSESS_NO_TICKS, c).start);
  assert.equal(q(c).get("prepare") === "yes", assessLaunchBody(plan(), ASSESS_NO_TICKS, c).prepare === true);
});

test("the dialog clears the preparation tick when the start choice changes, and the picker follows the choice, not the command", () => {
  const dir = new URL("../components/secassess/", import.meta.url);
  const dialog = readFileSync(new URL("AssessPlanDialog.tsx", dir), "utf8");
  // A new pick, a typed command and the none row each start unticked.
  assert.match(dialog, /start: choice, prepare: undefined/);
  assert.match(dialog, /: text\.trim\(\), prepare: undefined/);
  assert.match(dialog, /onPrepare=\{\(on\) => setChoices\(\(c\) => \(\{ \.\.\.c, prepare: on \? true : undefined \}\)\)\}/);
  // A project change clears every choice, the tick with them.
  assert.match(dialog, /setChoices\(ASSESS_NO_CHOICES\)/);
  const picker = readFileSync(new URL("AssessStartPlan.tsx", dir), "utf8");
  assert.match(picker, /assessStartChoice\(p\)/);
  assert.doesNotMatch(picker, /p\.command === inForce/);
});

test("an offered start command lists its folder, port, source, preparation steps and the services the sandbox cannot start", () => {
  assert.deepEqual(assessStartPlanDetails({ command: "npm run dev", source: "package.json scripts" }), ["Read from package.json scripts"]);
  const dj = { command: "python manage.py runserver 8000", port: 8000, source: "manage.py", prepare: ["python manage.py migrate"], needs: ["db", "redis"] };
  assert.deepEqual(assessStartPlanDetails(dj), [
    "Port 8000",
    "Read from manage.py",
    "Preparation steps, not run unless you choose to: python manage.py migrate",
    "Needs: db, redis. The sandbox has no container engine.",
  ]);
  // Under the selected plan the opt-in lists the steps, so they are not said twice.
  assert.deepEqual(assessStartPlanDetails(dj, true), ["Port 8000", "Read from manage.py", "Needs: db, redis. The sandbox has no container engine."]);
  // A plan that runs in a subfolder says which, first; the project's own folder says nothing.
  assert.deepEqual(assessStartPlanDetails({ command: "npm run dev", source: "launch.json", cwd: "web", choice: "web::npm run dev" }), ["In the folder web/", "Read from launch.json"]);
  assert.deepEqual(assessStartPlanDetails({ command: "npm run dev", source: "s", cwd: "apps/web/" })[0], "In the folder apps/web/");
  assert.deepEqual(assessStartPlanDetails({ command: "npm run dev", source: "s", cwd: "" }), ["Read from s"]);
  assert.deepEqual(assessStartPlanDetails({ command: "x", source: "", port: 0, prepare: [], needs: [] }), []);
});

test("preflight notes read likely-to-fail first, then worth knowing, then notes, in the server's order within a level", () => {
  assert.deepEqual(assessPreflightRows(undefined), []);
  const rows = assessPreflightRows([
    { id: "spec", level: "info", text: "An API spec was found." },
    { id: "env", level: "warn", text: "2 environment files are in this folder." },
    { id: "deps", level: "likely_fails", text: "No node_modules folder: the sandbox cannot install packages." },
    { id: "lock", level: "warn", text: "No lockfile." },
    { id: "odd", level: "something_new", text: "A note of a kind Observer has no words for." },
  ]);
  assert.deepEqual(
    rows.map((r) => r.id),
    ["deps", "env", "lock", "spec", "odd"],
  );
  assert.deepEqual(
    rows.map((r) => [r.label, r.tone]),
    [
      ["Likely to fail", "danger"],
      ["Worth knowing", "warn"],
      ["Worth knowing", "warn"],
      ["Note", "neutral"],
      ["Note", "neutral"],
    ],
  );
  assert.equal(rows[0].text, "No node_modules folder: the sandbox cannot install packages.");
});

test("a tool reads as found, not found with what the agent does instead, or not known, and a scanner may need an answer", () => {
  const t: AssessToolRow = { id: "curl", purpose: "Send HTTP requests", command: "curl", present: true, guarded: false, fallback: "The agent writes the request in the language of the project." };
  assert.equal(assessToolLine(t), "Send HTTP requests. Found in the sandbox's standard folders.");
  assert.equal(
    assessToolLine({ ...t, present: false }),
    "Send HTTP requests. Not found in the sandbox's standard folders. The agent writes the request in the language of the project.",
  );
  assert.equal(
    assessToolLine({ ...t, present: null }),
    "Send HTTP requests. Observer could not tell whether it is there; the agent checks for itself.",
    "unknown is said as unknown, not as absent",
  );
  assert.equal(assessToolLine({ ...t, guarded: true }), "Send HTTP requests. Found in the sandbox's standard folders. It may need your answer: Observer's guard can ask before it runs.");
  // A purpose that already ends in a full stop is not given a second one, and a missing fallback adds nothing.
  assert.equal(assessToolLine({ ...t, purpose: "Port scanning.", present: false, fallback: "" }), "Port scanning. Not found in the sandbox's standard folders.");
});

test("the environment line is the server's sentence; the files are named, never their contents", () => {
  const env: AssessEnv = { files: [".env", ".env.local"], count: 2, configured: "warn", effective: "warn", line: "2 .env files are in this folder and are readable inside the sandbox." };
  assert.equal(assessEnvLine(undefined), "");
  assert.equal(assessEnvLine({ ...env, line: "" }), "");
  assert.equal(assessEnvLine({ ...env, line: "  spaced  " }), "spaced");
  assert.equal(assessEnvLine(env), "2 .env files are in this folder and are readable inside the sandbox.");
  assert.equal(assessEnvFilesLine(env), "Named: .env, .env.local.");
  assert.equal(assessEnvFilesLine(undefined), "");
  assert.equal(assessEnvFilesLine({ ...env, files: [] }), "");
  const many = Array.from({ length: 9 }, (_, i) => `.env.${i}`);
  assert.equal(assessEnvFilesLine({ ...env, files: many, count: 9 }), "Named: .env.0, .env.1, .env.2, .env.3, .env.4, .env.5, and 3 more.");
  // The count can be larger than the names the server listed.
  assert.equal(assessEnvFilesLine({ ...env, files: [".env"], count: 4 }), "Named: .env, and 3 more.");
});

test("each safety rule says how it is held: by the task alone, or by a check that prevents it, looks afterwards or lets you stop, and where else", () => {
  assert.deepEqual(assessSafetyRows(undefined), []);
  const rows = assessSafetyRows([
    { id: "target", rule: "Test only the target", prompt: true, helper: "-", observer: "The sandbox's network", observer_kind: "prevents", prompt_only: false },
    { id: "pace", rule: "At most 5 requests a second", prompt: true, helper: "-", observer: "-", observer_kind: "", prompt_only: true },
    { id: "budget", rule: "At most 600 requests", prompt: true, helper: "Counts and refuses past the budget", observer: "Probe count when checked", observer_kind: "detects", prompt_only: false },
    { id: "blank", rule: "No real credentials", prompt: true, helper: " ", observer: "", prompt_only: true },
    { id: "git", rule: "Do not destroy tracked files", prompt: true, helper: "-", observer: "A git check afterwards; it sees tracked-file edits only", observer_kind: "detects", prompt_only: false },
    { id: "time", rule: "Stay inside the time box", prompt: true, helper: "-", observer: "The deadline and the Stop button", observer_kind: "stops", prompt_only: false },
  ]);
  assert.deepEqual(rows[0], {
    id: "target",
    rule: "Test only the target",
    held: "Held outside the task",
    kind: "prevents",
    tone: "info",
    promptOnly: false,
    where: ["Observer: The sandbox's network"],
  });
  assert.deepEqual(rows[1], { id: "pace", rule: "At most 5 requests a second", held: "Held by the task only", kind: "task_only", tone: "neutral", promptOnly: true, where: [] });
  assert.deepEqual(rows[2].where, ["Request helper: Counts and refuses past the budget", "Observer: Probe count when checked"]);
  assert.equal(rows[2].held, "Checked afterwards, not prevented");
  assert.deepEqual(rows[3].where, [], "an empty cell is the same as a dash");
  assert.equal(rows[4].held, "Checked afterwards, not prevented");
  assert.equal(rows[5].held, "You can stop the run; the limit is advisory");
  assert.deepEqual(rows.map((r) => r.kind), ["prevents", "task_only", "detects", "task_only", "detects", "stops"]);
  // Only a check that prevents reads as held outside the task, and only it is more than neutral.
  assert.deepEqual(rows.map((r) => r.tone), ["info", "neutral", "neutral", "neutral", "neutral", "neutral"]);
  assert.equal(rows.filter((r) => /^Held outside the task$/.test(r.held)).length, 1);
  assert.equal(ASSESS_TASK_ONLY, "Held by the task only");
  assert.deepEqual(ASSESS_HELD_WORDS, {
    task_only: "Held by the task only",
    prevents: "Held outside the task",
    detects: "Checked afterwards, not prevented",
    stops: "You can stop the run; the limit is advisory",
    noted: "Noted outside the task, not a guarantee",
  });
});

test("a safety row with no kind, or a kind Observer has no words for, is a note and never reads as held", () => {
  const base = { id: "x", rule: "r", prompt: true, helper: "-", prompt_only: false };
  // An older server: text in the observer cell and no kind at all.
  const noKind = assessSafetyRows([{ ...base, observer: "Some check" }])[0];
  assert.equal(noKind.kind, "noted");
  assert.equal(noKind.held, "Noted outside the task, not a guarantee");
  assert.deepEqual(noKind.where, ["Observer notes: Some check"]);
  assert.equal(noKind.tone, "neutral");
  // A kind from a newer server.
  const odd = assessSafetyRows([{ ...base, observer: "Some check", observer_kind: "guarantees" }])[0];
  assert.equal(odd.kind, "noted");
  assert.doesNotMatch(odd.held, /^Held outside/);
  // A kind with no text behind it is not believed: nothing is claimed that nothing explains.
  for (const observer of ["-", "", "  "]) {
    const r = assessSafetyRows([{ ...base, observer, observer_kind: "prevents" }])[0];
    assert.equal(r.kind, "task_only", `observer "${observer}"`);
    assert.equal(r.held, "Held by the task only");
  }
  // A request helper with no observer check is a note as well, in its own words.
  const helper = assessSafetyRows([{ ...base, helper: "Counts the requests", observer: "-" }])[0];
  assert.equal(helper.kind, "noted");
  assert.deepEqual(helper.where, ["Request helper: Counts the requests"]);
  // The server's own prompt_only is kept as it came, and wins: nothing but the task holds it.
  const promptOnly = assessSafetyRows([{ ...base, observer: "-", prompt_only: true, observer_kind: "prevents" }])[0];
  assert.equal(promptOnly.kind, "task_only");
  assert.equal(promptOnly.promptOnly, true);
  // A row that says it is held by something but names nothing is the weakest reading.
  assert.equal(assessSafetyRows([{ ...base, observer: "-" }])[0].kind, "task_only");
});

test("the environment-files sentence says only the top level is counted, and that a scanner's finding in a subfolder is still known", () => {
  assert.match(ASSESS_ENV_TOP_LEVEL, /^Only environment files at the top level of this folder are counted\./);
  assert.match(ASSESS_ENV_TOP_LEVEL, /Those in subfolders are not/);
  assert.match(ASSESS_ENV_TOP_LEVEL, /a scanner has found a secret in one, Observer's findings still know about it\.$/);
  // The section shows it with the server's sentence and nowhere else says "in this folder" of the whole project.
  const dir = new URL("../components/secassess/", import.meta.url);
  const before = readFileSync(new URL("AssessBeforeStart.tsx", dir), "utf8");
  assert.match(before, /\{ASSESS_ENV_TOP_LEVEL\}/);
  assert.match(before, /data-testid="assess-env-top-level"/);
  for (const f of ["AssessBeforeStart.tsx", "AssessPlanDialog.tsx", "AssessStartPlan.tsx", "AssessScopePicker.tsx"]) {
    assert.doesNotMatch(readFileSync(new URL(f, dir), "utf8"), /environment files? in this folder/i, f);
  }
});

test("the scope note field follows the note the dialog holds: typed text stays while it is unchanged, and a changed or cleared note resets it", () => {
  const s0: AssessNoteDraft = { text: "payment flow", seen: "payment flow" };
  // Nothing changed under the field: the very same state comes back.
  assert.equal(assessNoteDraftFor(s0, "payment flow"), s0);
  // The developer is typing: text and seen differ, the dialog's note has not moved, what is typed stays.
  const typing: AssessNoteDraft = { text: "payment flow and refunds", seen: "payment flow" };
  assert.equal(assessNoteDraftFor(typing, "payment flow"), typing);
  // The note was applied and the dialog now holds it: the field is in step with it.
  assert.deepEqual(assessNoteDraftFor(typing, "payment flow and refunds"), { text: "payment flow and refunds", seen: "payment flow and refunds" });
  // Another project, or a plan read again with a different note: typed text is replaced by the held note.
  assert.deepEqual(assessNoteDraftFor(typing, ""), { text: "", seen: "" });
  assert.deepEqual(assessNoteDraftFor(s0, "billing"), { text: "billing", seen: "billing" });
  // A cleared note on the dialog's side empties the field even though the developer had text in it.
  assert.deepEqual(assessNoteDraftFor({ text: "stale words", seen: "payment flow" }, ""), { text: "", seen: "" });
  // The picker uses it: derived state during render, a project change remounts it with a key, and typed text is set against what it last saw.
  const dir = new URL("../components/secassess/", import.meta.url);
  const picker = readFileSync(new URL("AssessScopePicker.tsx", dir), "utf8");
  assert.match(picker, /assessNoteDraftFor\(noteState, note\)/);
  assert.match(picker, /if \(synced !== noteState\) setNoteState\(synced\)/);
  assert.match(picker, /setNoteState\(\{ text, seen: synced\.seen \}\)/);
  assert.doesNotMatch(picker, /useState\(note\)/, "no state initialised once from the prop");
  assert.match(readFileSync(new URL("AssessPlanDialog.tsx", dir), "utf8"), /key=\{project\?\.project_root_hash \?\? ""\}/);
});

test("the request budget and pace read as held by the task only, in every combination", () => {
  const l: AssessLimits = { time_box_minutes: 45, time_box_action: "stop_button", boundary_audit: true, audit_policy: "strict", audit_limits: "Files git ignores are not covered." };
  assert.equal(assessLimitsLines(l).length, 2, "a kind with no request limits has no request line");
  const both = assessLimitsLines({ ...l, request_budget: 600, pace_rps: 5 });
  assert.equal(both.length, 3);
  assert.equal(both[2].text, "Request budget 600, at most 5 a second. Held by the task only: nothing between the agent and the target counts them.");
  assert.equal(both[2].tone, "neutral");
  assert.equal(assessLimitsLines({ ...l, request_budget: 200 })[2].text, "Request budget 200. Held by the task only: nothing between the agent and the target counts them.");
  assert.equal(assessLimitsLines({ ...l, pace_rps: 10 })[2].text, "At most 10 requests a second. Held by the task only: nothing between the agent and the target paces them.");
  assert.equal(assessLimitsLines({ ...l, pace_rps: 1 })[2].text, "At most 1 request a second. Held by the task only: nothing between the agent and the target paces them.");
  assert.equal(assessLimitsLines({ ...l, request_budget: 0, pace_rps: 0 }).length, 2);
});

test("the environment-files line says what was chosen, and when the sandbox cannot do it, what happens instead", () => {
  assert.equal(assessSecretModeLine(undefined, undefined), null);
  assert.equal(
    assessSecretModeLine("mask", "warn")?.text,
    "Environment files: Hide in the sandbox is chosen, but the sandbox this run will use cannot hide files, so it acts as a warning.",
  );
  assert.equal(assessSecretModeLine("mask", "warn")?.tone, "warn");
  // Each closed reason has its own words; one this build does not know reads as the general one.
  assert.equal(
    assessSecretModeLine("mask", "warn", "no_backend")?.text,
    "Environment files: Hide in the sandbox is chosen, but no sandbox is chosen for this run yet, so it acts as a warning.",
  );
  assert.equal(
    assessSecretModeLine("mask", "warn", "launcher_cannot_report")?.text,
    "Environment files: Hide in the sandbox is chosen, but this daemon's launcher cannot report what the mask hid, and a mask nobody can check is not asked for, so it acts as a warning.",
  );
  assert.equal(assessSecretModeLine("mask", "warn", "made_up")?.text, assessSecretModeLine("mask", "warn")?.text);
  assert.equal(assessSecretModeLine("warn", "refuse")?.text, "Environment files: Warn is chosen, but Refuse is what applies to this run.");
  assert.equal(assessSecretModeLine("warn", "refuse")?.tone, "warn");
  // Chosen and in force agree: the Settings card's own words, so the two never describe a choice two ways.
  assert.equal(assessSecretModeLine("warn", "warn")?.text, "Environment files: Warn in the plan and tell the agent.");
  assert.equal(assessSecretModeLine("refuse", "refuse")?.text, "Environment files: Refuse while a secret is open in one.");
  assert.equal(assessSecretModeLine("off", "off")?.text, "Environment files: Say nothing.");
  assert.equal(assessSecretModeLine("warn", "warn")?.tone, "neutral");
  // The card's label for Hide says it acts as Warn where the sandbox cannot: once Hide is really in force it is not repeated.
  assert.equal(assessSecretModeLine("mask", "mask")?.text, "Environment files: Hide in the sandbox.");
  // Only one of the two given reads as that one.
  assert.equal(assessSecretModeLine("warn", undefined)?.text, "Environment files: Warn in the plan and tell the agent.");
  assert.equal(assessSecretModeLine(undefined, "warn")?.text, "Environment files: Warn in the plan and tell the agent.");
});

test("the short words of the environment-files modes cover every choice the Settings card offers", () => {
  const row = CODE_SECURITY_SETTINGS.find((r) => r.key === "security.assessments.workspace_secret_mode");
  assert.ok(row, "the card has the row");
  assert.deepEqual([...Object.keys(ASSESS_SECRET_MODE_SHORT)].sort(), [...row.values].map(String).sort());
});

test("the project facts and the environment mode join the settings in force for a pen test and a threat model", () => {
  const pt = assessModelLines({
    prompt_version: "pt.2",
    categories: "all",
    self_check: true,
    import_min_band: "low",
    findings_cap: 0,
    rerun_dedup: true,
    secret_mode: "mask",
    secret_mode_effective: "warn",
  }, groundingFull).map((l) => l.text);
  assert.ok(pt.includes("The task carries a digest of facts from the project: 6 sections, 3.1 KiB."), pt.join("\n"));
  assert.ok(pt.includes("Environment files: Hide in the sandbox is chosen, but the sandbox this run will use cannot hide files, so it acts as a warning."), pt.join("\n"));
  // The facts line points at its help entry, and only that line does.
  const lines = assessModelLines(tmModel, groundingFull);
  assert.deepEqual(lines.filter((l) => l.help).map((l) => l.help), ["card.code_security_assess_grounding"]);
  // Without a grounding block the setting is named in the card's own words.
  const byCard = assessModelLines({ ...tmModel, grounding: "without_findings" }).map((l) => l.text);
  assert.ok(byCard.includes("Project facts in the task: Facts only, without open findings."), byCard.join("\n"));
  assert.ok(assessModelLines({ ...tmModel, grounding: "off" }).some((l) => l.text === "Project facts in the task: No digest."));
  // Neither: the lines are the ones the wave before gave.
  assert.ok(!assessModelLines(tmModel).some((l) => /Project facts|digest|Environment files/.test(l.text)));
});

test("the settings in force are the limits then the model lines, with the request limits taken from either block", () => {
  assert.deepEqual(assessSettingsLines(null), []);
  assert.deepEqual(assessSettingsLines(undefined), []);
  const limits: AssessLimits = { time_box_minutes: 45, time_box_action: "stop_button", boundary_audit: true, audit_policy: "strict", audit_limits: "L." };
  const onlyLimits = assessSettingsLines({ limits, model: undefined, grounding: undefined }).map((l) => l.text);
  assert.equal(onlyLimits.length, 2);
  const fromModel = assessSettingsLines({
    limits,
    model: { ...tmModel, request_budget: 1200, pace_rps: 2 },
    grounding: groundingFull,
  }).map((l) => l.text);
  assert.ok(fromModel.includes("Request budget 1200, at most 2 a second. Held by the task only: nothing between the agent and the target counts them."), fromModel.join("\n"));
  assert.ok(fromModel.some((l) => l.startsWith("The task carries a digest")));
  // The limits block wins where both carry a value.
  const both = assessSettingsLines({ limits: { ...limits, request_budget: 600, pace_rps: 5 }, model: { ...tmModel, request_budget: 1200, pace_rps: 2 }, grounding: undefined }).map((l) => l.text);
  assert.ok(both.some((l) => l.startsWith("Request budget 600, at most 5 a second.")), both.join("\n"));
  assert.ok(!both.some((l) => l.includes("1200")));
  // The existing line order is kept: time box, git check, then the model's.
  assert.match(onlyLimits[0], /^Time box: 45 minutes\./);
  assert.match(onlyLimits[1], /^Git check:/);
});

test("a run row says what a threat model was scoped to and what it is compared with", () => {
  assert.deepEqual(assessRunScopeLines({}), { scope: "", previous: "" });
  assert.deepEqual(assessRunScopeLines({ scope: { paths: [] } }), { scope: "", previous: "" });
  assert.deepEqual(assessRunScopeLines({ scope: { paths: ["cmd/api", "internal/db"] } }), { scope: "Scope: cmd/api, internal/db", previous: "" });
  assert.deepEqual(assessRunScopeLines({ scope: { paths: ["cmd/api"], note: "payment flow" } }).scope, "Scope: cmd/api. Note: payment flow");
  assert.deepEqual(assessRunScopeLines({ scope: { paths: [], note: "payment flow" } }).scope, "Note: payment flow");
  assert.equal(assessRunScopeLines({ previous_run: "00000000000000a1" }, "Threat model, Nov 13, 2026, 09:00").previous, "Compared with the earlier run (Threat model, Nov 13, 2026, 09:00): shown once the model is checked");
});

test("the three refusals of the plan's choices have words that name what to do, and the server's sentence wins", () => {
  const body = (code: string) => ({ status: 409, body: JSON.stringify({ error: "the place ../etc is outside the project", code }) });
  for (const code of ["scope_invalid", "start_invalid", "secret_files_open", "findings_unreadable"]) {
    assert.ok(Object.prototype.hasOwnProperty.call(ASSESS_REFUSALS, code), code);
    assert.equal(assessRefusalWords(body(code)), "The place ../etc is outside the project.", `${code}: the server names the cause`);
    assert.match(ASSESS_REFUSALS[code].words, /Nothing was started\./);
  }
  assert.match(ASSESS_REFUSALS.scope_invalid.words, /Fix or remove it/);
  assert.match(ASSESS_REFUSALS.start_invalid.words, /at most 8 words/);
  assert.match(ASSESS_REFUSALS.start_invalid.words, /leave it empty and the agent will look for one/);
  assert.match(ASSESS_REFUSALS.secret_files_open.words, /change the setting/);
  assert.match(ASSESS_REFUSALS.findings_unreadable.words, /could not read its findings/);
  // The launch dialog shows them for a 409.
  assert.equal(assessLaunchRefusal(body("scope_invalid")), "The place ../etc is outside the project.");
});

test("the plan's own words never call anything confirmed, verified, vulnerable, clean, secure or authentic", () => {
  const banned = /\b(confirmed|verified|vulnerable|clean|secure|authentic)\b/i;
  const strings: string[] = [];
  const add = (...s: (string | null | undefined)[]) => strings.push(...s.filter((x): x is string => typeof x === "string"));
  for (const g of [groundingFull, { ...groundingFull, mode: "off" }, { ...groundingFull, mode: "without_findings", dropped: 2, ai_app: true }, { ...groundingFull, sections: [] }]) add(assessGroundingLine(g));
  add(assessScopeChoiceLine(scopeBlock), assessScopeChoiceLine({ paths: ["a", "b"] }));
  add(assessScopeToggle(["a"], "b", true, 1).error);
  const prev: AssessPrevious = { options: [{ id: "x", created_at: "2026-11-13T09:00:00Z" }], selected: "x", default_run: "x", note: "n" };
  add(assessPreviousLine(prev), assessPreviousLine({ ...prev, selected: "" }), assessPreviousLine({ ...prev, options: [], selected: "" }), assessPreviousOptionLabel(prev.options[0]));
  const start: AssessStart = { plans: [], selected_command: "npm run dev", edit: "", edited: true, none_found: false };
  add(assessStartLine(start), assessStartLine({ ...start, selected_command: "" }), assessStartLine({ ...start, selected_command: "", none_found: true }));
  add(...assessStartPlanDetails({ command: "c", port: 1, source: "s", prepare: ["p"], needs: ["n"] }));
  for (const level of ["likely_fails", "warn", "info", "other"]) for (const r of assessPreflightRows([{ id: "i", level, text: "t" }])) add(r.label);
  for (const present of [true, false, null] as const) add(assessToolLine({ id: "t", purpose: "p", command: "c", present, guarded: true, fallback: "f" }));
  add(assessEnvFilesLine({ files: ["a"], count: 3, configured: "", effective: "", line: "" }));
  const safety = assessSafetyRows([
    { id: "a", rule: "r", prompt: true, helper: "h", observer: "o", prompt_only: false },
    { id: "b", rule: "r", prompt: true, helper: "-", observer: "-", prompt_only: true },
    ...["prevents", "detects", "stops", "", "other"].map((k) => ({ id: k, rule: "r", prompt: true, helper: "-", observer: "o", observer_kind: k, prompt_only: false })),
  ]);
  for (const r of safety) add(r.held, ...r.where);
  add(...Object.values(ASSESS_HELD_WORDS), ASSESS_ENV_TOP_LEVEL, ASSESS_PREPARE_LABEL, ASSESS_PREPARE_WARNING, ASSESS_PREVIOUS_NOTE);
  for (const state of ["", "ok", "previous_missing", "too_large", "other"]) add(assessCompareLine({ previous_run: "x", compare_state: state }));
  add(assessStartLine({ ...startWithFolder, prepare: true, selected_command: "python manage.py runserver 8000" }), assessStartLine(startWithFolder), ...assessStartPlanDetails(startWithFolder.plans[0]), ...assessStartPlanDetails(startWithFolder.plans[2]));
  const l: AssessLimits = { time_box_minutes: 45, time_box_action: "stop_button", boundary_audit: true, audit_policy: "strict", audit_limits: "L.", request_budget: 600, pace_rps: 5 };
  for (const x of assessLimitsLines(l)) add(x.text);
  for (const x of assessModelLines({ ...tmModel, secret_mode: "mask", secret_mode_effective: "warn", grounding: "full" }, groundingFull)) add(x.text);
  for (const mode of ["mask", "warn", "refuse", "off"]) add(assessSecretModeLine(mode, mode)?.text, assessSecretModeLine("mask", mode)?.text);
  const rr = assessRunScopeLines({ scope: { paths: ["a"], note: "n" }, previous_run: "x" });
  add(rr.scope, rr.previous);
  for (const code of ["scope_invalid", "start_invalid", "secret_files_open", "findings_unreadable"]) add(ASSESS_REFUSALS[code].words);
  assert.ok(strings.length > 40, `only ${strings.length} strings were checked`);
  for (const s of strings) {
    assert.doesNotMatch(s, banned, s);
    assert.doesNotMatch(s, /[\u{1F300}-\u{1FAFF}☀-➿]/u, `no emoji in: ${s}`);
  }
});

test("the dialog's four help entries exist and the dialog's sections point at them", () => {
  const ids = ["card.code_security_assess_scope", "card.code_security_assess_grounding", "card.code_security_assess_previous", "card.code_security_assess_start"];
  const dir = new URL("../components/secassess/", import.meta.url);
  const src = ["AssessScopePicker.tsx", "AssessPreviousPicker.tsx", "AssessStartPlan.tsx", "AssessBeforeStart.tsx"].map((f) => readFileSync(new URL(f, dir), "utf8")).join("\n");
  for (const id of ids) assert.ok(HELP_REGISTRY.some((h) => h.id === id), `${id} is in the help registry`);
  for (const id of [ids[0], ids[2], ids[3]]) assert.ok(src.includes(id), `${id} is on its section`);
  // The facts line carries the grounding entry through the settings list.
  assert.ok(readFileSync(new URL("secAssess.ts", import.meta.url), "utf8").includes(ids[1]));
  // The dialog builds its whole list through the one function, and keeps the limits test id.
  const dialog = readFileSync(new URL("AssessPlanDialog.tsx", dir), "utf8");
  assert.match(dialog, /assessSettingsLines\(data\)/);
  assert.match(dialog, /data-testid="assess-limits"/);
});

test("the button waits for a place or a start command that was typed and not yet applied", () => {
  assert.equal(assessUnapplied("", false), null);
  assert.equal(assessUnapplied("   ", false), null, "blank space is nothing typed");
  assert.equal(assessUnapplied("internal/db", false), "Add the place you typed to the scope, or clear it first");
  assert.equal(assessUnapplied("", true), "Use the start command you typed, or clear it first");
  // A place is named first when both wait.
  assert.equal(assessUnapplied("web", true), "Add the place you typed to the scope, or clear it first");
});

test("the consent is for one target in one project, not for one read of the plan (N-8)", () => {
  assert.equal(assessConsentKey("h1", "http://localhost:3000/"), assessConsentKey("h1", "http://localhost:3000/"));
  assert.notEqual(assessConsentKey("h1", "http://localhost:3000/"), assessConsentKey("h2", "http://localhost:3000/"), "another project needs its own consent");
  assert.notEqual(assessConsentKey("h1", "http://localhost:3000/"), assessConsentKey("h1", "http://localhost:3001/"), "another target needs its own consent");
  // No run id goes into it: a new read of the plan mints a new one.
  assert.equal(assessConsentKey(undefined, "t"), "|t");
  const src = readFileSync(new URL("../components/secassess/AssessPlanDialog.tsx", import.meta.url), "utf8");
  assert.ok(!src.includes("${data.run_id}|"), "the dialog no longer ties the consent to a run id");
});

test("the footer reason: a refusal the note shows is pointed at, every other reason stands alone (N-10)", () => {
  const kind = { launchable: true } as AssessPlan["kind"];
  const project = { on_disk: true } as AssessPlan["project"];
  const refused = { ok: false, reason: "Turn it on in the settings.", kind, project };
  assert.equal(assessWaitingLine(null, refused), null);
  assert.equal(assessWaitingLine("Turn it on in the settings.", refused), ASSESS_REFUSED_ABOVE, "the plan's own refusal is in the note: not printed twice");
  assert.equal(assessWaitingLine("Confirm the target first", { ...refused, ok: true, reason: undefined }), "Confirm the target first");
  assert.equal(assessWaitingLine("Choose the target first", { ...refused, ok: true }), "Choose the target first", "an ok plan has no note: the reason stays");
  // A project that is not on disk is said in the footer: the note is only for a plan the server judged.
  assert.equal(assessWaitingLine("This project's folder is not on this machine", { ...refused, project: { on_disk: false } as AssessPlan["project"], reason: "This project's folder is not on this machine" }), "This project's folder is not on this machine");
  assert.doesNotMatch(ASSESS_REFUSED_ABOVE, /_|\b[A-Z]-\d+\b/, "plain words");
});

test("the note over a refused plan says it once: a retest refused for named findings points at their list (N-10)", () => {
  assert.equal(assessPlanNotice({ ok: true, reason: undefined } as AssessPlan), null);
  assert.equal(assessPlanNotice({ ok: false, reason: "The target must be on this machine." } as AssessPlan), "The target must be on this machine.");
  const named = { ok: false, code: "retest_findings", reason: "The finding F-4 has no stored request to replay. Nothing was started.", retest: { refused: [{ finding: "F-4", code: "no_request" }] } } as unknown as AssessPlan;
  assert.equal(assessPlanNotice(named), ASSESS_RETEST_FINDINGS_NOTE);
  assert.doesNotMatch(ASSESS_RETEST_FINDINGS_NOTE, /F-\d/, "the list names the findings, the note does not");
  assert.match(ASSESS_RETEST_FINDINGS_NOTE, /Nothing was started\./);
  // The same code with no finding named by the list keeps the server's sentence.
  assert.equal(assessPlanNotice({ ...named, retest: { refused: [] } } as unknown as AssessPlan), named.reason);
  assert.equal(assessPlanNotice({ ...named, code: "retest_helper" } as unknown as AssessPlan), named.reason);
});

// --- The request helper on the plan (depth plan W5b) -------------------------

const probeOn: AssessProbePlan = { state: "on", files: ["probe.py", "probe.json"], dir: ".observer/assessments/20261114-ab12cd", budget: 600, pace_rps: 5 };

test("the plan's request helper: on lists the two files and the folder, the budget and the pace, and says the log is a file the agent can write", () => {
  const v = assessHelperView(probeOn)!;
  assert.equal(v.state, "on");
  assert.equal(v.lead, ASSESS_HELPER_ON);
  assert.equal(
    ASSESS_HELPER_ON,
    "Observer writes these two files into the run folder before the agent starts; the helper sends requests to the target address only, applies the pace and the request budget, and logs each request to probes.jsonl. The log is a file the agent can write.",
  );
  assert.deepEqual(v.files, ["probe.py", "probe.json"]);
  assert.equal(v.dir, ".observer/assessments/20261114-ab12cd");
  assert.deepEqual(v.facts, ["Request budget: 600 requests.", "Pace: at most 5 requests a second.", ASSESS_HELPER_OTHER_WAY]);
  // The two files are named even when the server sends none, and a one-request budget reads singular.
  assert.deepEqual(assessHelperView({ ...probeOn, files: undefined })!.files, ["probe.py", "probe.json"]);
  assert.deepEqual(assessHelperView({ ...probeOn, files: [] })!.files, ["probe.py", "probe.json"]);
  const one = assessHelperView({ ...probeOn, budget: 1, pace_rps: 1 })!;
  assert.deepEqual(one.facts.slice(0, 2), ["Request budget: 1 request.", "Pace: at most 1 request a second."]);
  // A number that is not set is not printed as zero.
  assert.deepEqual(assessHelperView({ ...probeOn, budget: 0, pace_rps: 0 })!.facts, [ASSESS_HELPER_OTHER_WAY]);
  assert.equal(assessHelperView(undefined), null);
  assert.equal(assessHelperView(null), null);
});

test("the plan's request helper: off and withheld write nothing and say every finding's evidence reads No log", () => {
  const off = assessHelperView({ state: "off", dir: ".observer/assessments/x", budget: 600, pace_rps: 5 })!;
  assert.equal(off.state, "off");
  assert.equal(off.lead, "The request helper is off (a setting): nothing is written, and every finding's evidence reads No log.");
  assert.equal(off.lead, ASSESS_HELPER_OFF);
  assert.deepEqual(off.files, []);
  assert.equal(off.dir, "");
  // The setting is named by its label, never by its key.
  assert.deepEqual(off.facts, ['The setting is "Request helper for penetration tests" (Settings > Guard > Code security).']);
  assert.ok(off.facts.every((f) => !f.includes("probe_helper")));
  const why = "python3 was not seen in the sandbox's standard folders.";
  const held = assessHelperView({ state: "withheld", withheld_reason: `The request helper is left out: ${why}`, dir: "d", budget: 600, pace_rps: 5 })!;
  assert.equal(held.state, "withheld");
  assert.equal(held.lead, `The request helper is left out: ${why} Every finding's evidence reads No log.`);
  assert.deepEqual(held.files, []);
  // A reason with no full stop gets one, and none at all reads as a plain sentence.
  assert.equal(assessHelperView({ state: "withheld", withheld_reason: "python3 was not seen", dir: "d", budget: 1, pace_rps: 1 })!.lead, "python3 was not seen. Every finding's evidence reads No log.");
  assert.equal(assessHelperView({ state: "withheld", dir: "d", budget: 1, pace_rps: 1 })!.lead, "The request helper is left out of this run. Every finding's evidence reads No log.");
  // A state this view does not know writes nothing and promises nothing.
  const odd = assessHelperView({ state: "mystery" as never, files: ["probe.py"], dir: "d", budget: 1, pace_rps: 1 })!;
  assert.equal(odd.state, "withheld");
  assert.deepEqual(odd.files, []);
  assert.match(odd.lead, /Every finding's evidence reads No log\.$/);
});

test("the settings in force say what holds the request limits: the task alone, or the task and the helper for what goes through it", () => {
  const limits: AssessLimits = { time_box_minutes: 45, time_box_action: "stop_button", boundary_audit: true, audit_policy: "strict", audit_limits: "L.", request_budget: 600, pace_rps: 5 };
  const lines = (probe?: AssessProbePlan) => assessSettingsLines({ limits, model: undefined, grounding: undefined, probe }).map((l) => l.text);
  assert.ok(lines().includes("Request budget 600, at most 5 a second. Held by the task only: nothing between the agent and the target counts them."));
  assert.ok(lines({ ...probeOn, state: "off" }).includes("Request budget 600, at most 5 a second. Held by the task only: nothing between the agent and the target counts them."));
  assert.ok(lines({ ...probeOn, state: "withheld" }).some((t) => t.includes("Held by the task only")));
  const on = lines(probeOn).find((t) => t.startsWith("Request budget"))!;
  assert.equal(on, `Request budget 600, at most 5 a second. ${ASSESS_HELPER_HOLDS}`);
  assert.doesNotMatch(on, /Held by the task only|nothing between the agent and the target/);
  assert.match(on, /A request the agent makes another way, with curl or its own code, is not counted or paced\./);
  // The same for a budget alone and a pace alone.
  assert.equal(assessLimitsLines({ ...limits, pace_rps: undefined }, true)[2].text, `Request budget 600. ${ASSESS_HELPER_HOLDS}`);
  assert.equal(assessLimitsLines({ ...limits, request_budget: undefined, pace_rps: 1 }, true)[2].text, `At most 1 request a second. ${ASSESS_HELPER_HOLDS}`);
  // A kind with no request limits has no request line, with the helper or without.
  assert.equal(assessLimitsLines({ ...limits, request_budget: undefined, pace_rps: undefined }, true).length, 2);
});

test("no sentence of the request helper's plan reads as a clearance or a confirmation, and none names a setting key", () => {
  const banned = /\b(confirmed|verified|vulnerable|clean|secure|safe|passed|authentic|observed)\b/i;
  const views = [
    assessHelperView(probeOn),
    assessHelperView({ state: "off", dir: "d", budget: 1, pace_rps: 1 }),
    assessHelperView({ state: "withheld", dir: "d", budget: 1, pace_rps: 1 }),
    assessHelperView({ state: "withheld", withheld_reason: "python3 was not seen in the sandbox's standard folders", dir: "d", budget: 1, pace_rps: 1 }),
  ];
  for (const v of views) {
    for (const t of [v!.lead, ...v!.facts]) {
      assert.doesNotMatch(t, banned, t);
      assert.doesNotMatch(t, /[a-z]+_[a-z]+/, `no raw code or key in: ${t}`);
    }
  }
  assert.doesNotMatch(ASSESS_HELPER_HOLDS, banned);
});

test("the plan dialog mounts the request helper's block from the plan, and the block has its help entry", () => {
  const dir = new URL("../components/secassess/", import.meta.url);
  const dialog = readFileSync(new URL("AssessPlanDialog.tsx", dir), "utf8");
  assert.match(dialog, /\{data\.probe && <AssessRequestHelper probe=\{data\.probe\} \/>\}/);
  const block = readFileSync(new URL("AssessRequestHelper.tsx", dir), "utf8");
  assert.match(block, /assessHelperView\(probe\)/);
  assert.match(block, /data-testid="assess-helper"/);
  assert.ok(block.includes("card.code_security_assess_probe"));
  assert.ok(HELP_REGISTRY.some((h) => h.id === "card.code_security_assess_probe"), "the entry is in the registry");
  assert.doesNotMatch(block, /dangerouslySetInnerHTML|innerHTML|probe_helper/);
});

// --- The workspace secret mask (decision D32) ---------------------------------

test("a run row says what the workspace secret mask covered, and a partial mask is a warning with its count", () => {
  assert.equal(assessRunMaskLine({}), null);
  assert.equal(assessRunMaskLine({ secret_mode: "warn" }), null);
  const done = assessRunMaskLine({ secret_mask: { reported: true, masked: 3, complete: true, gaps: 0, words: "3 files hidden inside the box.", partial: false } });
  assert.deepEqual(done, { text: "Environment files: 3 files hidden inside the box.", tone: "neutral" });
  const partial = assessRunMaskLine({
    secret_mode: "mask",
    secret_mask: { reported: true, masked: 1, complete: false, gaps: 4, words: "1 file hidden inside the box; 4 places could not be covered.", partial: true },
  });
  assert.equal(partial?.tone, "warn");
  assert.match(partial?.text ?? "", /4 places could not be covered/);
  const none = assessRunMaskLine({ secret_mask: { reported: false, masked: 0, complete: false, gaps: 0, words: "the sandbox did not report what it hid.", partial: true } });
  assert.equal(none?.tone, "warn");
  // A chosen mask that acted as a warning says why, in the closed reason's words.
  assert.equal(
    assessRunMaskLine({ secret_mode: "warn", secret_mode_why: "backend_cannot_mask" })?.text,
    "Environment files: Hide in the sandbox was chosen, but the sandbox this run will use cannot hide files, so it acted as a warning.",
  );
  assert.equal(assessRunMaskLine({ secret_mode: "warn", secret_mode_why: "no_backend" })?.tone, "warn");
  // The words never claim more than a name-based snapshot does.
  for (const l of [done, partial, none]) assert.doesNotMatch(l?.text ?? "", /\b(safe|secure|verified|confirmed|protected)\b/i);
});

test("the mask's downgrade reasons are the Go table's, row for row", () => {
  const go = readFileSync(new URL("../../../internal/secassess/secretmode.go", import.meta.url), "utf8");
  const block = go.match(/var maskDowngrades = \[\]maskDowngrade\{([\s\S]*?)\n\}/);
  assert.ok(block, "the Go table was not found");
  const rows = [...block[1].matchAll(/\{Mask\w+, "([a-z_]+)", "([^"]+)"\}/g)].map((m) => [m[1], m[2]] as const);
  assert.equal(rows.length, 3, "the Go table has three rows");
  for (const [why, clause] of rows) assert.equal(ASSESS_MASK_DOWNGRADE[why], clause, `${why}: the words differ from the Go clause`);
  assert.deepEqual(Object.keys(ASSESS_MASK_DOWNGRADE).sort(), rows.map(([w]) => w).sort());
});

// ---- the launch body the Go route starts (the first live run, 2026-11-15) ----
//
// The first live run refused every pen test launch with 409 sandbox_required: this
// side sends no sandbox fields for a task whose route chooses the sandbox, and the
// route used to read the body's own sandbox flag. The route decides now; this pins
// the body that goes on the wire, which internal/intelligence/dashboard's
// TestDialogLaunchBodiesStartPastTheSandboxRules decodes into the real request type
// (unknown members refused) and posts to the real handler.

/** The members the dialog's Isolation and Workspace controls and its sign-in step add to a launch; a task whose route chooses the sandbox sends none of them (NewTerminalDialog sandboxManaged). */
const DIALOG_SANDBOX_MEMBERS = ["sandbox", "backend", "workspace_source", "workspace_remote", "workspace_branch", "sign_in_seed", "sign_in_ask"];

const redTeam: AssessKind = { ...pentest, id: "red_team_local", title: "Red team (your own app, local)" };

/** dialogLaunchBody is the JSON the New terminal dialog posts for a task, as NewTerminalDialog.tsx builds it: the task's own fields, then the agent choice, and the sandbox fields only for a task that does not choose its sandbox (`sandboxManaged = !!task.serverSandbox`). */
function dialogLaunchBody(plan_: AssessPlan, tool: string, model?: string, choices?: Parameters<typeof assessTaskFor>[3]): Record<string, unknown> {
  const task = assessTaskFor(plan_, undefined, ASSESS_NO_TICKS, choices);
  const sandboxManaged = !!task.serverSandbox;
  assert.ok(sandboxManaged, `${plan_.kind.id}: a confined kind tells the dialog its route chooses the sandbox`);
  const sandboxFields = sandboxManaged ? {} : { sandbox: true, workspace_source: "live" };
  return JSON.parse(taskLaunchRequest(task, { tool, model: model || undefined, ...sandboxFields }).body);
}

const LAUNCH_BODY_FIXTURES: Record<string, Record<string, unknown>> = {
  pentest_local: dialogLaunchBody(plan(), "claude-code"),
  red_team_local: dialogLaunchBody(plan({ kind: redTeam }), "claude-code"),
  pentest_local_model_chosen: dialogLaunchBody(plan(), "claude-code", "sonnet"),
  // The red team's objective, and a retest of two findings of an earlier run (W7.3, W7.2): the same body plus their own members.
  red_team_local_objective: dialogLaunchBody(plan({ kind: { ...redTeam, exercise: true } }), "claude-code", undefined, { objective: "Read another user's entries without signing in as them." }),
  pentest_retest: dialogLaunchBody(plan({ kind: { ...pentest, id: "pentest_retest", title: "Retest of earlier findings (your own app, local)", from_run: true } }), "claude-code", undefined, { ofRun: "20261113-ef34ab", findings: ["F-1", "F-5"] }),
};

const LAUNCH_BODIES_FILE = new URL("../../../internal/secassess/testdata/assess_launch_bodies.json", import.meta.url);

test("a confined kind's launch body carries no sandbox, backend, workspace or sign-in member: the route chooses them", () => {
  for (const [name, body] of Object.entries(LAUNCH_BODY_FIXTURES)) {
    for (const m of DIALOG_SANDBOX_MEMBERS) assert.equal(m in body, false, `${name}: the dialog sends ${m} for a task whose route chooses the sandbox`);
    assert.equal(body.tool, "claude-code", name);
    assert.equal(typeof body.assessment, "string", name);
    assert.equal(body.target, "http://localhost:3000/", name);
    assert.equal(body.confirm_target, "http://localhost:3000/", name);
  }
  assert.equal(LAUNCH_BODY_FIXTURES.pentest_local_model_chosen.model, "sonnet");
  assert.equal("model" in LAUNCH_BODY_FIXTURES.pentest_local, false);
  // The kind that leaves the sandbox to the developer keeps the dialog's own controls, so nothing here is sent for it.
  assert.equal(assessTaskFor(plan({ kind: threat, target: undefined, allowed_tools: null })).serverSandbox, undefined);
});

test("the launch bodies are the checked-in JSON the Go route tests post (UPDATE_FIXTURES=1 rewrites the file)", () => {
  const want = `${JSON.stringify(LAUNCH_BODY_FIXTURES, null, 2)}\n`;
  if (process.env.UPDATE_FIXTURES === "1") {
    writeFileSync(LAUNCH_BODIES_FILE, want);
    return;
  }
  const got = readFileSync(LAUNCH_BODIES_FILE, "utf8").replace(/\r\n/g, "\n");
  assert.equal(got, want, "internal/secassess/testdata/assess_launch_bodies.json is out of date: run the lib test with UPDATE_FIXTURES=1 and commit the file");
  assert.deepEqual(Object.keys(JSON.parse(got)), Object.keys(LAUNCH_BODY_FIXTURES));
});

test("the plan dialog starts on the project assessed last, else the first active project, else the first", () => {
  const options = [
    { project_root_hash: "a", active: true },
    { project_root_hash: "b", active: true },
    { project_root_hash: "c", active: false },
  ];
  const run = (project_root_hash: string, created_at: string) => ({ project_root_hash, created_at });
  // The newest run decides, whatever the order the list came in.
  assert.equal(assessDefaultProject(options, [run("a", "2026-11-14T10:00:00Z"), run("b", "2026-11-15T10:00:00Z"), run("c", "2026-11-13T10:00:00Z")])?.project_root_hash, "b");
  assert.equal(assessDefaultProject(options, [run("b", "2026-11-15T10:00:00Z"), run("a", "2026-11-16T10:00:00Z")])?.project_root_hash, "a");
  // A run of a project that is no longer an option (its folder is gone) is not a reason to start there.
  assert.equal(assessDefaultProject(options, [run("gone", "2026-11-16T10:00:00Z"), run("b", "2026-11-15T10:00:00Z")])?.project_root_hash, "b");
  // No run to go by: the first active project, else the first option.
  assert.equal(assessDefaultProject(options, [])?.project_root_hash, "a");
  assert.equal(assessDefaultProject(options, undefined)?.project_root_hash, "a");
  assert.equal(assessDefaultProject([{ project_root_hash: "c", active: false }, { project_root_hash: "d", active: false }], [])?.project_root_hash, "c");
  assert.equal(assessDefaultProject([{ project_root_hash: "c", active: false }, { project_root_hash: "d", active: true }], [])?.project_root_hash, "d");
  // Stamps that cannot be read are ignored, never trusted.
  assert.equal(assessDefaultProject(options, [run("c", "not a date")])?.project_root_hash, "a");
  assert.equal(assessDefaultProject([], [run("a", "2026-11-14T10:00:00Z")]), undefined);
});

// ---- the retest and the red team's objective (depth plan W7.2, W7.3) --------

const retestKind: AssessKind = { ...pentest, id: "pentest_retest", title: "Retest of earlier findings (your own app, local)", from_run: true };
const exerciseKind: AssessKind = { ...redTeam, exercise: true };

test("the plan address carries the objective, the earlier run and each chosen finding, in the order chosen, and nothing blank", () => {
  const rows: [string, Parameters<typeof assessPlanPath>[5], string][] = [
    ["no choice", {}, "/api/security/assessments/plan?kind=red_team_local&project=h1"],
    ["an objective", { objective: "Read another user's entries" }, "/api/security/assessments/plan?kind=red_team_local&project=h1&objective=Read+another+user%27s+entries"],
    ["an objective is trimmed", { objective: "  reach the export  " }, "/api/security/assessments/plan?kind=red_team_local&project=h1&objective=reach+the+export"],
    ["a blank objective is no objective", { objective: "   " }, "/api/security/assessments/plan?kind=red_team_local&project=h1"],
    ["an earlier run", { ofRun: " 00000000000000f4 " }, "/api/security/assessments/plan?kind=red_team_local&project=h1&of_run=00000000000000f4"],
    ["findings repeat the parameter in the order chosen", { findings: ["F-3", "F-1"] }, "/api/security/assessments/plan?kind=red_team_local&project=h1&finding=F-3&finding=F-1"],
    ["a blank finding is dropped", { findings: ["F-1", " ", ""] }, "/api/security/assessments/plan?kind=red_team_local&project=h1&finding=F-1"],
    ["a finding chosen twice is kept, so the server refuses it by name", { findings: ["F-1", "F-1"] }, "/api/security/assessments/plan?kind=red_team_local&project=h1&finding=F-1&finding=F-1"],
    ["the three together", { objective: "o", ofRun: "r", findings: ["F-1"] }, "/api/security/assessments/plan?kind=red_team_local&project=h1&objective=o&of_run=r&finding=F-1"],
  ];
  for (const [name, choices, want] of rows) assert.equal(assessPlanPath("red_team_local", "h1", undefined, undefined, undefined, choices), want, name);
});

test("the launch body carries the objective for the kind that asks for one and the retest's run and findings for the retest, and no other kind gains a member", () => {
  const exercise = plan({ kind: exerciseKind });
  const retest = plan({ kind: retestKind });
  const rows: [string, AssessPlan, Parameters<typeof assessLaunchBody>[2], Record<string, unknown>][] = [
    ["a red team with an objective", exercise, { objective: " Read another user's entries " }, { objective: "Read another user's entries" }],
    ["a red team with a blank objective", exercise, { objective: "  " }, {}],
    ["a red team with none", exercise, {}, {}],
    ["a red team never sends a retest's members", exercise, { ofRun: "r", findings: ["F-1"] }, {}],
    ["a retest with its run and findings", retest, { ofRun: "00000000000000f4", findings: ["F-1", "F-5"] }, { of_run: "00000000000000f4", finding_ids: ["F-1", "F-5"] }],
    ["a retest with no finding chosen sends no list", retest, { ofRun: "r", findings: [] }, { of_run: "r" }],
    ["a retest never sends an objective", retest, { objective: "x" }, {}],
    ["a pen test sends neither", plan(), { objective: "x", ofRun: "r", findings: ["F-1"] }, {}],
    ["a threat model sends neither", plan({ kind: threat, target: undefined }), { objective: "x", ofRun: "r", findings: ["F-1"] }, {}],
  ];
  for (const [name, p, choices, extra] of rows) {
    const base = assessLaunchBody(p);
    assert.deepEqual(assessLaunchBody(p, ASSESS_NO_TICKS, choices), { ...base, ...extra }, name);
  }
  // The plan's digest still goes with it.
  assert.equal(assessLaunchBody(plan({ kind: retestKind, prompt_sha256: "abc" }), ASSESS_NO_TICKS, { ofRun: "r", findings: ["F-1"] }).prompt_sha256, "abc");
});

test("the seven retest refusals have words that say nothing was started, or that there is no export, and one of them names the finding itself", () => {
  const codes = ["retest_run_unknown", "retest_run_mismatch", "retest_no_model", "retest_findings", "retest_helper", "retest_too_large", "retest_no_export"];
  for (const code of codes) {
    assert.ok(Object.prototype.hasOwnProperty.call(ASSESS_REFUSALS, code), code);
    const w = ASSESS_REFUSALS[code].words;
    if (code === "retest_no_export") assert.match(w, /no export of its own/, code);
    else assert.match(w, /[Nn]othing was started/, code);
    assert.equal(ASSESS_REFUSALS[code].own === true, code === "retest_findings", `${code}: only the finding's own sentence is the server's`);
  }
  // The server's sentence for a finding it cannot replay names the finding, so it is the one shown.
  const server = "The finding F-4 has no stored request to replay (its reproduction is code or text only). Leave it out. Nothing was started.";
  assert.equal(assessRefusalWords({ status: 409, body: JSON.stringify({ error: server, code: "retest_findings" }) }), server);
  // No row reads as a config key, a validator row or a raw code.
  for (const code of codes) assert.doesNotMatch(ASSESS_REFUSALS[code].words, /\b[a-z]+_[a-z_]+\b|\bRT\d\b|\bE\d{2}\b/, code);
});

test("the helper refusals name the switch by its label and the screen, never 'the settings' (N-10)", () => {
  const label = CODE_SECURITY_SETTINGS.find((r) => r.key === ASSESS_HELPER_SETTING)?.label;
  assert.equal(label, "Request helper for penetration tests");
  for (const code of ["retest_helper", "helper_exists", "helper_not_written"]) {
    const w = ASSESS_REFUSALS[code].words;
    assert.ok(w.includes(`"${label}"`), `${code}: ${w}`);
    assert.ok(w.includes(ASSESS_SETTINGS_WHERE), `${code}: ${w}`);
    assert.doesNotMatch(w, /in the settings|probe_helper|security\.assessments/, code);
  }
  assert.match(ASSESS_REFUSALS.retest_helper.words, /^A retest needs the request helper.*Turn on "Request helper for penetration tests" in Settings > Guard > Code security, and install python3/);
  assert.equal(ASSESS_HELPER_SETTING, "security.assessments.probe_helper");
});

test("a retest has no findings to import, whatever its state", () => {
  const files = { report: true, sarif: false, commands: false, model: true };
  for (const state of ["validated", "no_findings", "import_failed", "import_unavailable", "findings_ready"]) {
    assert.equal(assessImportable({ state, files, contract: "retest.v1" }), false, state);
  }
  // Another model contract is as it was.
  assert.equal(assessImportable({ state: "validated", files, contract: "pentest.v1" }), true);
});

test("a retest's and a red team's launch bodies are the ones the Go route decodes (the card hides the retest kind; the picker opens its plan)", () => {
  const retestBody = LAUNCH_BODY_FIXTURES.pentest_retest;
  assert.equal(retestBody.assessment, "pentest_retest");
  assert.equal(retestBody.of_run, "20261113-ef34ab");
  assert.deepEqual(retestBody.finding_ids, ["F-1", "F-5"]);
  assert.equal("objective" in retestBody, false);
  const redBody = LAUNCH_BODY_FIXTURES.red_team_local_objective;
  assert.equal(redBody.objective, "Read another user's entries without signing in as them.");
  assert.equal("of_run" in redBody, false);
  assert.equal("finding_ids" in redBody, false);
});

test("a run held for the organization keeps a red team's objective and a retest's earlier run and findings, and no other kind gains a member", () => {
  const ticks = { rules: ["R-179"], tier: false };
  const red: AssessKind = { ...pentest, id: "red_team_local", exercise: true };
  const retest: AssessKind = { ...pentest, id: "pentest_retest", from_run: true };
  const held = assessRequestBody(plan({ kind: red }), ticks, { objective: "  Read another user's data " });
  assert.equal(held.objective, "Read another user's data");
  assert.ok(!("objective" in assessRequestBody(plan({ kind: red }), ticks, { objective: "   " })), "an empty objective is not sent");
  assert.ok(!("objective" in assessRequestBody(plan(), ticks, { objective: "ignored" })), "a kind with no exercise sends none");
  const r = assessRequestBody(plan({ kind: retest }), ticks, { ofRun: "0123456789abcdef", findings: ["F-1", "F-2"] });
  assert.equal(r.of_run, "0123456789abcdef");
  assert.deepEqual(r.finding_ids, ["F-1", "F-2"]);
  assert.ok(!("of_run" in assessRequestBody(plan(), ticks, { ofRun: "0123456789abcdef", findings: ["F-1"] })));
  // The same members the launch body carries.
  const c = { objective: "x", ofRun: "0123456789abcdef", findings: ["F-1"] };
  for (const k of [red, retest]) {
    const a = assessRequestBody(plan({ kind: k }), ticks, c);
    const b = assessLaunchBody(plan({ kind: k }), ticks, c);
    for (const key of ["objective", "of_run", "finding_ids"]) assert.deepEqual(a[key], b[key], `${k.id}: ${key}`);
  }
});
