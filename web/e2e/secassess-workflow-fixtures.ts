import type { Page, Route } from "@playwright/test";
import {
  FIXTURE_PT,
  FIXTURE_PT_RETESTED,
  FIXTURE_RED_TEAM,
  FIXTURE_RED_TEAM_AGENT,
  FIXTURE_RED_TEAM_AGENT_RUN,
  FIXTURE_RED_TEAM_RUN,
  FIXTURE_RETEST,
  FIXTURE_RETEST_OF_RUN,
  FIXTURE_RETEST_RUN_NEW,
  FIXTURE_RETEST_RUN_OLD,
  FIXTURE_SINCE_RUN,
  FIXTURE_TM,
  FIXTURE_TM_SINCE,
} from "../src/lib/secAssessModelFixture.ts";
import type { AssessModelResponse, ModelIssue, PTFinding } from "../src/lib/secAssessModel.ts";

// Synthetic data for the workflow spec (security-assessments-workflow.spec.ts):
// the projects, the six assessment kinds, a run in every state the card shows,
// and a plan for each kind, in the exact shape of the server's answers. Every
// name is invented (an application called "ledger", a folder under /work); no
// path, host, token or text here comes from a real project or a real run. The
// words in the kinds and the plans are the server's own, kept as they are, so
// the spec reads what a person reads.

export type Json = Record<string, unknown>;

export const PROJECT_ALPHA = { project_root_hash: "hash-alpha", name: "alpha-probe", root_path: "/work/alpha-probe", active: true, state: "ready", reason: "", blocking: 0, open: 0, counts: [], runs: [] };
export const PROJECT_LEDGER = { project_root_hash: "hash-ledger", name: "ledger", root_path: "/work/ledger", active: true, state: "blocking", reason: "", blocking: 1, open: 4, counts: [], runs: [] };

export const KINDS: Json[] = [
  {
    id: "threat_model",
    title: "Threat model",
    summary: "A STRIDE-style threat model of this project: assets, trust boundaries, data flows, threats and mitigations, plus findings for concrete weaknesses.",
    mode: "Read-only",
    launchable: true,
    sandbox: "optional",
    target: "none",
    files: ["report.md", "assessment.json"],
    note: "Read-only. The agent reads the repository and writes two files into the run directory.",
  },
  {
    id: "pentest_local",
    title: "Penetration test (your own app, local)",
    summary: "A time-boxed test of one development server of this project, started inside a sandbox and reached only on loopback.",
    mode: "Sandboxed",
    launchable: true,
    sandbox: "required",
    target: "required",
    files: ["report.md", "assessment.json"],
    note: "Runs only in a sandbox whose network leaves the agent no route except its model connection.",
  },
  {
    id: "red_team_local",
    title: "Red team exercise (your own app, local)",
    summary: "An objective-driven exercise against one development server of this project, started inside a sandbox and reached only on loopback.",
    mode: "Sandboxed",
    launchable: true,
    sandbox: "required",
    target: "required",
    files: ["report.md", "assessment.json"],
    note: "Same confinement as the penetration test.",
    exercise: true,
  },
  {
    id: "cspm_readonly",
    title: "Cloud posture review (read-only)",
    summary: "A read-only review of your cloud setup using your own cloud CLI session, plus this repository's infrastructure code.",
    mode: "Your cloud session",
    launchable: true,
    sandbox: "optional",
    target: "none",
    files: ["report.md", "findings.sarif", "commands.txt"],
    note: "A sandbox hides your home directory, so the cloud CLI would not be signed in inside one.",
  },
  {
    id: "iast_instrumented_tests",
    title: "Instrumented tests (not full IAST)",
    summary: "Runs the project's own tests with security assertions added in a scratch worktree and reports the dataflow issues it observes. Partial: this is not full IAST.",
    mode: "Partial",
    launchable: true,
    sandbox: "optional",
    target: "none",
    files: ["report.md", "findings.sarif"],
    note: "Partial. It does not instrument the running application.",
  },
  {
    id: "rasp",
    title: "Runtime protection (RASP)",
    summary: "Protection inside the running, deployed application.",
    mode: "Not agent-shaped",
    launchable: false,
    sandbox: "na",
    target: "none",
    files: [],
    reason: "Runtime protection runs inside the deployed application and decides on live traffic. A coding agent in a terminal on a development machine is not that, so there is nothing to launch.",
    pointer:
      "Observer has a runtime feature for a hosted LLM application: it observes the application's inputs and outputs for an organization and can refuse unsafe input. That is monitoring and admission control, not application self-protection, and the organization sets it up; it is not launched from here.",
  },
];

/** The retest kind: started from an earlier run's findings in its model view, never from the card (the card's grid leaves a from_run kind out). It is served in the kinds list, as the real server does, and is not part of KINDS: the card shows six. */
export const RETEST_KIND: Json = {
  id: "pentest_retest",
  title: "Retest of earlier findings (your own app, local)",
  summary: "Sends the stored requests of findings from an earlier run again, once, in a copy of the project in a box, and labels each finding reproduced, not reproduced or inconclusive.",
  mode: "Sandboxed",
  launchable: true,
  sandbox: "required",
  target: "required",
  files: ["report.md", "assessment.json"],
  note: "Labels only: it closes nothing and changes no finding.",
  from_run: true,
};

const AUDIT_LIMITS = "Files git ignores (.env, local databases, caches, node_modules) are not covered, and a change made by you in the same window is counted too.";

/** run builds one run row; the defaults are an ended, checked pen test of the ledger project. */
export function run(over: Json): Json {
  return {
    id: "0000000000000001",
    created_at: "2026-11-15T10:00:00Z",
    kind: "pentest_local",
    kind_title: "Penetration test (your own app, local)",
    tool: "claude-code",
    project_root_hash: PROJECT_LEDGER.project_root_hash,
    project_name: PROJECT_LEDGER.name,
    // The launch's own token: opaque, never a name.
    handle: "H" + "x".repeat(42),
    seeded: true,
    sandboxed: true,
    backend: "bwrap",
    tier: "proxy_only",
    target: "http://localhost:3000/",
    state: "validated",
    phase: "started",
    files: { report: true, sarif: false, commands: false, model: true },
    report_bytes: 4200,
    contract: "pentest.v1",
    has_model: true,
    has_data: true,
    time_box_minutes: 45,
    time_box_action: "stop_button",
    deadline: "2026-11-15T10:45:00Z",
    over_time_box: false,
    ended_at: "2026-11-15T10:30:00Z",
    end_why: "terminal_gone",
    audit: "no_change",
    audit_words: "No git change seen",
    audit_at: "2026-11-15T10:31:00Z",
    audit_limits: AUDIT_LIMITS,
    validation: { state: "valid", at: "2026-11-15T10:35:00Z", refused: 0, refs: { found: 21, exists: 0, claimed_not_found: 0, missing: 0, invalid: 0, unchecked: 0 } },
    ...over,
  };
}

/** The run ids the spec refers to. */
export const ID = {
  tmNew: "00000000000000a2",
  tmOld: FIXTURE_SINCE_RUN,
  tmOther: "00000000000000a3",
  ptChecked: "00000000000000b1",
  ptWritten: "00000000000000b2",
  ptEmpty: "00000000000000b3",
  ptLive: "00000000000000b4",
  cspm: "00000000000000c1",
  invalid: "00000000000000c2",
  imported: "00000000000000c3",
  importFailed: "00000000000000c4",
  // The retest arc (depth plan W7.2 and W7.3): a pen test with two retests, a red team run with an objective and a chain, and the two retests.
  ptRetested: FIXTURE_RETEST_OF_RUN,
  redTeam: FIXTURE_RED_TEAM_RUN,
  redTeamAgent: FIXTURE_RED_TEAM_AGENT_RUN,
  retestNew: FIXTURE_RETEST_RUN_NEW,
  retestOld: FIXTURE_RETEST_RUN_OLD,
};

/** The objective the red team run of the fixtures was given. */
export const RED_TEAM_OBJECTIVE = "Read another user's entries without signing in as them.";

/** runsWithRetests is runsEveryState with the rows of the retest arc after them (so the indexes of the other rows hold): a pen test that two retests labelled, a red team run, and the two retest runs, the older one with no checked copy left. */
export function runsWithRetests(): Json[] {
  return [
    ...runsEveryState(),
    run({ id: ID.ptRetested, created_at: "2026-11-15T09:00:00Z" }),
    run({ id: ID.redTeam, created_at: "2026-11-15T08:30:00Z", kind: "red_team_local", kind_title: "Red team exercise (your own app, local)", objective: RED_TEAM_OBJECTIVE }),
    run({
      id: ID.retestNew,
      created_at: "2026-11-16T09:00:00Z",
      kind: "pentest_retest",
      kind_title: "Retest of earlier findings (your own app, local)",
      contract: "retest.v1",
      retest_of: ID.ptRetested,
      retest_findings: ["F-1", "F-2", "F-3", "F-5", "F-6"],
    }),
    run({
      id: ID.retestOld,
      created_at: "2026-11-15T16:00:00Z",
      kind: "pentest_retest",
      kind_title: "Retest of earlier findings (your own app, local)",
      contract: "retest.v1",
      retest_of: ID.ptRetested,
      retest_findings: ["F-1", "F-2"],
      has_model: undefined,
    }),
  ];
}


// ---- the CVSS 4.0 base score on findings (depth plan W7.1) ----
//
// The vectors are the specification's published examples or invented; the
// scores are what the server would compute for them (the mocked answer carries
// the computed members, the page never computes one itself).

/** An all-high network vector: base score 9.3, critical. */
export const CVSS_CRITICAL = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";
/** A vector with no impact on any of the six impact metrics: base score 0.0, rated none, which has no band. */
export const CVSS_NONE = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N";
/** A low-confidentiality vector: base score 6.9, medium. */
export const CVSS_MEDIUM = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N";

/** The issue the check raises for a vector it cannot read, in the server's words (secassess cvssVector): it names the finding, and carries the finding's id as its item; the path is the finding's index in the agent's file. */
export const CVSS_DROPPED_ISSUE: ModelIssue = {
  row: "V5",
  code: "bad_cvss_dropped",
  severity: "dropped",
  path: "findings[3]",
  item: "F-4",
  message: "The CVSS vector of finding F-4 carries a threat, environmental or supplemental metric (only the 11 base metrics are read) (at E), so it was left out. The finding keeps its likelihood and impact rating.",
};

/** fixturePtCvss is a pen test whose findings show what a CVSS line can sit beside: F-1 is critical by both readings, F-2 is rated medium by the agent while its vector scores 0.0 (rated none, no band), F-3 is rated low while its vector scores medium, and F-4 had a vector Observer could not read and left out. */
export function fixturePtCvss(): AssessModelResponse {
  const a = JSON.parse(JSON.stringify(FIXTURE_PT)) as AssessModelResponse;
  const pt = a.record.result.pt!;
  const f = pt.findings!;
  Object.assign(f[0], { cvss: CVSS_CRITICAL, cvss_score: 9.3, cvss_band: "critical" });
  Object.assign(f[1], { cvss: CVSS_NONE, cvss_score: 0 });
  Object.assign(f[2], { cvss: CVSS_MEDIUM, cvss_score: 6.9, cvss_band: "medium" });
  const dropped: PTFinding = {
    id: "F-4",
    title: "The admin list answers without a session",
    category: "ATHN",
    rating: { likelihood: 3, impact: 4 },
    basis: "observed",
    where: {},
    reproduction: [{ step: "Ask for the admin list with no session", request: { method: "GET", path: "/api/admin/users" } }],
    impact: "The list of accounts can be read by anyone.",
    status: "open",
    band: "high",
    score: 12,
  };
  pt.findings = [...f, dropped];
  a.record.result.report = { ...a.record.result.report, state: "partial", counts: { findings: { read: 4, kept: 4 } }, issues: [CVSS_DROPPED_ISSUE] };
  return a;
}

/** The answers the retest arc's runs open on (a spec may replace one through Wire.models). */
const ARC_MODELS: Record<string, AssessModelResponse> = {
  [ID.ptRetested]: FIXTURE_PT_RETESTED,
  [ID.redTeam]: FIXTURE_RED_TEAM,
  [ID.redTeamAgent]: FIXTURE_RED_TEAM_AGENT,
  [ID.retestNew]: FIXTURE_RETEST,
};

/** runsEveryState is one run per state the card can show, newest first, all on the ledger project except where a test needs another. */
export function runsEveryState(): Json[] {
  return [
    run({ id: ID.ptLive, created_at: "2026-11-15T12:00:00Z", state: "started", ended_at: undefined, end_why: undefined, can_stop: true, files: { report: false, sarif: false, commands: false }, has_model: undefined, contract: undefined, validation: undefined, audit: "pending", audit_words: "Checked when the run ends", report_bytes: 0 }),
    run({ id: ID.ptEmpty, created_at: "2026-11-15T11:30:00Z", state: "ended_empty", files: { report: false, sarif: false, commands: false }, has_model: undefined, contract: undefined, validation: undefined, report_bytes: 0 }),
    run({ id: ID.ptWritten, created_at: "2026-11-15T11:00:00Z", state: "model_ready", validation: undefined }),
    run({ id: ID.ptChecked, created_at: "2026-11-15T10:00:00Z" }),
    run({
      id: ID.tmNew,
      created_at: "2026-11-14T10:00:00Z",
      kind: "threat_model",
      kind_title: "Threat model",
      target: undefined,
      backend: undefined,
      contract: "threatmodel.v1",
      previous_run: ID.tmOld,
      compare_state: "ok",
      sandboxed: false,
      tier: undefined,
    }),
    run({ id: ID.tmOld, created_at: "2026-11-13T10:00:00Z", kind: "threat_model", kind_title: "Threat model", target: undefined, backend: undefined, contract: "threatmodel.v1", sandboxed: false, tier: undefined }),
    run({ id: ID.invalid, created_at: "2026-11-12T10:00:00Z", state: "invalid", validation: { state: "invalid", at: "2026-11-12T10:30:00Z", fatal: "schema_mismatch", refs: { found: 0, exists: 0, claimed_not_found: 0, missing: 0, invalid: 0, unchecked: 0 } }, has_model: undefined }),
    run({ id: ID.cspm, created_at: "2026-11-11T10:00:00Z", kind: "cspm_readonly", kind_title: "Cloud posture review (read-only)", state: "findings_ready", target: undefined, backend: undefined, sandboxed: false, tier: undefined, contract: undefined, validation: undefined, has_model: undefined, files: { report: true, sarif: true, commands: true }, cloud: { read_only: 12, secret_material: 0, mutating: 0, unknown: 1 } }),
    run({ id: ID.imported, created_at: "2026-11-10T10:00:00Z", state: "imported", import: { at: "2026-11-10T10:40:00Z", outcome: "imported", prepared: 7, findings: 6, new: 4, with_lineage: 6 } }),
    run({ id: ID.importFailed, created_at: "2026-11-09T10:00:00Z", state: "import_failed", import: { at: "2026-11-09T10:40:00Z", outcome: "failed", reason: "refused", prepared: 0, findings: 0, new: 0, with_lineage: 0 } }),
  ];
}

export type Wire = {
  runs: Json[];
  kinds?: Json[];
  projects?: Json[];
  /** Answers the plan route from its query. */
  planFor?: (u: URL) => Json;
  /** Mint a new run id for every plan read, as the server does (the default answers one id for every read). */
  freshRunIds?: boolean;
  plans: URL[];
  /** The model answers by run id (since member added when asked). */
  models?: Record<string, AssessModelResponse>;
  modelReads: string[];
  launches: Json[];
  posts: { path: string; body: Json }[];
};

export function newWire(runs: Json[] = runsEveryState()): Wire {
  return { runs, plans: [], modelReads: [], launches: [], posts: [] };
}

/** mockAll stubs the assessment routes, the Code security status and the terminal launch routes; everything else (the page, navigation, theme) is the real dashboard. */
export async function mockAll(page: Page, wire: Wire) {
  await page.route("**/api/**", (route) => route.continue());
  await page.route("**/api/jobs*", (route) => route.fulfill({ json: { confirm_token: "tok", jobs: [] } }));
  await page.route("**/api/security/status", (route) => route.fulfill({ json: { module: "code-security", projects: wire.projects ?? [PROJECT_ALPHA, PROJECT_LEDGER] } }));
  await page.route("**/api/security/assessments", (route) => route.fulfill({ json: { kinds: wire.kinds ?? [...KINDS, RETEST_KIND], runs: wire.runs, import_available: true, launch: true } }));
  await page.route("**/api/security/assessments/plan*", (route) => {
    const u = new URL(route.request().url());
    wire.plans.push(u);
    const body = (wire.planFor ?? planFor)(u);
    return route.fulfill({ json: wire.freshRunIds ? { ...body, run_id: String(wire.plans.length).padStart(16, "0") } : body });
  });
  await page.route("**/api/security/assessments/model*", async (route: Route) => {
    const u = new URL(route.request().url());
    const id = u.searchParams.get("run") ?? "";
    const since = u.searchParams.get("since");
    wire.modelReads.push(since ? `${id}+${since}` : id);
    const own = wire.models?.[id];
    const fixed = id === ID.tmNew ? (since ? FIXTURE_TM_SINCE : FIXTURE_TM) : id === ID.ptChecked ? FIXTURE_PT : null;
    const body = own ?? fixed ?? ARC_MODELS[id];
    if (!body) return route.fulfill({ status: 404, json: { error: "no stored model for this run", code: "no_stored_model" } });
    return route.fulfill({ json: body });
  });
  await page.route("**/api/security/assessments/report*", (route) => {
    const u = new URL(route.request().url());
    return route.fulfill({ contentType: "text/markdown", headers: { "X-Observer-Redacted": "2" }, body: `# Report of ${u.searchParams.get("run")}\n\nThe agent's report, as plain text.\n` });
  });
  await page.route("**/api/security/assessments/validate", async (route) => {
    const body = route.request().postDataJSON() as { run: string };
    wire.posts.push({ path: "validate", body });
    const i = wire.runs.findIndex((r) => r.id === body.run);
    wire.runs[i] = { ...wire.runs[i], state: "validated", contract: "pentest.v1", has_model: true, validation: { state: "valid", at: "2026-11-15T13:00:00Z", refused: 0, refs: { found: 27, exists: 1, claimed_not_found: 0, missing: 0, invalid: 0, unchecked: 0 } } };
    await route.fulfill({ json: { run: wire.runs[i] } });
  });
  await page.route("**/api/terminal/sessions*", (route) =>
    route.fulfill({
      json: {
        sessions: [],
        launchable_tools: ["claude-code"],
        launchable_tool_info: [{ tool: "claude-code", allowed: true, watched: true }],
        allowed_project_roots: ["/work/alpha-probe", "/work/ledger"],
        fresh_enabled: true,
        shell_enabled: false,
      },
    }),
  );
  await page.route("**/api/terminal/launch/preflight*", (route) => route.fulfill({ json: { tool: "claude-code", verdict: "ok", bin: "/usr/bin/claude", can_install: false } }));
  await page.route("**/api/terminal/launch/models*", (route) => route.fulfill({ json: { tool: "claude-code", supported: false, models: [] } }));
  await page.route("**/api/security/assessments/launch", async (route) => {
    wire.launches.push(route.request().postDataJSON() as Json);
    await route.fulfill({ json: { handle: "H9", tool: "claude-code", command: "claude" } });
  });
  await page.addInitScript(() => {
    try {
      localStorage.setItem("sb_tour_completed", "1");
      sessionStorage.setItem("sb_firstrun_closed_this_visit", "1");
    } catch {
      /* private mode: ignore */
    }
  });
}

const LIMITS = { time_box_minutes: 60, time_box_action: "stop_button", boundary_audit: true, audit_policy: "strict", audit_limits: AUDIT_LIMITS };

const BOUNDARY = ["Work only in this project.", "Do not commit, push, stash, reset, rebase or switch branches in the developer's checkout."];

/** previousFor is the "compare with an earlier run" block of a threat model plan: the earlier checked runs of the project asked about, the newest chosen unless the query says otherwise. */
function previousFor(u: URL): Json | undefined {
  if (u.searchParams.get("project") !== PROJECT_LEDGER.project_root_hash) return undefined;
  const asked = u.searchParams.get("previous_run");
  const options = [
    { id: ID.tmNew, created_at: "2026-11-14T10:00:00Z" },
    { id: ID.tmOld, created_at: "2026-11-13T10:00:00Z" },
  ];
  return {
    options,
    selected: asked === null ? ID.tmNew : asked === "none" ? "" : asked,
    default_run: ID.tmNew,
    note: "Observer gives the agent nothing from the earlier run and asks it not to open other runs' folders.",
  };
}

/** The request helper block a pen test, red team or retest plan carries when the helper is on. */
const HELPER_ON = { state: "on", files: ["probe.py", "probe.json"], dir: ".observer/assessments/00000000000000f1", budget: 600, pace_rps: 5 };

/** objectiveFor is the red team plan's objective block: what the task carries, cleaned as the server cleans it (no line breaks, no backticks), and the bound in characters. */
function objectiveFor(u: URL): Json {
  const typed = (u.searchParams.get("objective") ?? "").replace(/[\r\n]+/g, " ").replace(/`/g, "").trim();
  return { text: typed.slice(0, 200), max: 200 };
}

/** What the earlier run's checked model stored for each of its findings that has a stored request. */
const RETEST_STORED: Json[] = [
  { id: "F-1", title: "Entry search is injectable", category: "INPV", steps: 2, has_condition: true, condition: "status 200 and the body holds 412" },
  { id: "F-2", title: "An export can be read with another account's session", category: "ATHZ", steps: 1, has_condition: true, condition: "status 200 and no X-Owner-Check header", hidden: true },
  { id: "F-3", title: "Error pages name the framework and version", category: "INFO", steps: 1, has_condition: false },
  { id: "F-5", title: "The health route lists the database address", category: "CONF", steps: 1, has_condition: true, condition: "status 200 and the body holds db.internal" },
  { id: "F-6", title: "The admin list answers without a session", category: "ATHN", steps: 1, has_condition: true, condition: "status 200 and the body holds users" },
];

/** retestFor is the retest block of the plan: the earlier run's findings that have a stored request, the ones the query chose that can be replayed, and each one it refuses by name (a finding with no stored request, one the model does not hold, one chosen twice, and those past the bound). */
function retestFor(u: URL): Json {
  const asked = u.searchParams.getAll("finding");
  const seen = new Set<string>();
  const selected: string[] = [];
  const refused: Json[] = [];
  for (const id of asked) {
    if (seen.has(id)) refused.push({ finding: id, code: "duplicate" });
    else if (id === "F-4") refused.push({ finding: id, code: "no_request" });
    else if (!RETEST_STORED.some((f) => f.id === id)) refused.push({ finding: id, code: "unknown_finding" });
    else if (selected.length >= 8) refused.push({ finding: id, code: "too_many" });
    else selected.push(id);
    seen.add(id);
  }
  return { of_run: u.searchParams.get("of_run") ?? "", of_kind: "pentest_local", of_target: "http://localhost:3000/", findings: RETEST_STORED, selected, max: 8, ...(refused.length > 0 ? { refused } : {}) };
}

/** promptFor is the task text of a pen test, red team or retest plan; a retest's names the earlier run and the findings it replays, a red team's carries the objective typed. */
function promptFor(u: URL, kind: Json, target: string): string {
  if (kind.id === "pentest_retest") {
    const ids = retestFor(u).selected as string[];
    return `RETEST of run ${u.searchParams.get("of_run")} against ${target}: send the stored requests of ${ids.join(", ")} once each and label each finding reproduced, not reproduced or inconclusive. Close nothing.`;
  }
  const objective = kind.id === "red_team_local" ? (objectiveFor(u).text as string) : "";
  return `SECURITY ASSESSMENT: ${kind.title} of ${target}.${objective ? ` Objective: ${objective}` : ""}`;
}

/** planFor answers a plan read for any kind, from its query: the kind, the project, a typed target, the ticked guardrails. A target that is not on loopback is refused, as the server does. */
export function planFor(u: URL): Json {
  const kindId = u.searchParams.get("kind") ?? "threat_model";
  const kind = [...KINDS, RETEST_KIND].find((k) => k.id === kindId) as Json;
  const hash = u.searchParams.get("project") ?? PROJECT_ALPHA.project_root_hash;
  const project = hash === PROJECT_LEDGER.project_root_hash ? PROJECT_LEDGER : PROJECT_ALPHA;
  const base: Json = {
    confirm_token: "tok",
    run_id: "00000000000000f1",
    kind,
    project: { project_root_hash: project.project_root_hash, name: project.name, root_path: project.root_path, on_disk: true },
    ok: true,
    target_typed: false,
    candidates: [],
    boundary: BOUNDARY,
    allowed_tools: null,
    seeds: { "claude-code": "leading_positional" },
    limits: LIMITS,
  };
  if (kindId === "threat_model") {
    return {
      ...base,
      prompt: `SECURITY ASSESSMENT: Threat model of ${project.name}.`,
      prompt_sha256: "ab".repeat(32),
      model: { prompt_version: "tm.6", frameworks: "all", method_extras: "both", self_check: true, import_min_band: "low", findings_cap: 0, rerun_dedup: true, grounding: "full" },
      scope: { dirs: ["cmd", "internal"], paths: [], note: "", refused: [], max_paths: 8, max_note: 200 },
      ...(previousFor(u) ? { previous: previousFor(u) } : {}),
    };
  }
  if (kindId === "pentest_local" || kindId === "red_team_local" || kindId === "pentest_retest") {
    const target = (u.searchParams.get("target") ?? "").trim();
    const onLoopback = /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\]):\d+/.test(target);
    const refused = target !== "" && !onLoopback;
    const relaxRules = (u.searchParams.get("relax") ?? "").split(",").filter(Boolean);
    const managed = u.searchParams.get("tenancy") === "managed";
    return {
      ...base,
      ok: !refused,
      ...(refused ? { code: "target_required", reason: "The target must be localhost, 127.0.0.1 or [::1] with a port. Only your own app, on this machine, can be tested." } : {}),
      target: refused ? "" : target,
      target_typed: target !== "" && !refused,
      candidates: [{ url: "http://localhost:3000/", name: "dev", source: ".claude/launch.json" }],
      backend: "bwrap",
      tier: "proxy_only",
      allowed_tools: ["claude-code"],
      residual: "The sandbox's only route out is Observer's model proxy.",
      limits: { ...LIMITS, time_box_minutes: kindId === "pentest_local" ? 45 : 60 },
      ...(!refused && target !== "" ? { prompt: promptFor(u, kind, target), prompt_sha256: "cd".repeat(32) } : {}),
      ...(kindId === "red_team_local" ? { objective: objectiveFor(u) } : {}),
      ...(kindId === "pentest_retest" ? { retest: retestFor(u), probe: HELPER_ON } : {}),
      model: { prompt_version: "pt.6", categories: "all", self_check: true, import_min_band: "low", findings_cap: 0, rerun_dedup: true, grounding: "full", secret_mode: "mask", secret_mode_effective: "mask", request_budget: 600, pace_rps: 5 },
      relax: {
        tenancy: managed ? "managed" : "individual",
        scope: "session",
        scope_words: "for this terminal's session only",
        minutes: 60,
        reported: managed,
        report_row: managed ? "R1" : "R3",
        enrolled: managed,
        tier_live: "proxy_only",
        tier_hosts: [],
        rows: [
          {
            key: "R-179",
            type: "rule",
            title: "Allow network and vulnerability scanners",
            lifts: "This lifts that one rule for this run, for the project's terminal only. Every other rule still applies.",
            why: "w",
            route: managed ? "org_request" : "self",
            row: managed ? "C5" : "C4",
            reason: managed ? "Your organization governs this rule here, so it has to approve." : "Your tick is the consent.",
            ticked: relaxRules.includes("R-179"),
          },
        ],
        lines: [],
      },
    };
  }
  // Cloud posture review and instrumented tests: no target, no sandbox words, a prompt at once.
  return { ...base, prompt: `SECURITY ASSESSMENT: ${kind.title} of ${project.name}.`, prompt_sha256: "ef".repeat(32) };
}

export async function openOverview(page: Page) {
  await page.goto("/code-security?tab=overview", { waitUntil: "domcontentloaded" });
  await page.getByTestId("assess-card").waitFor({ timeout: 15000 });
}
