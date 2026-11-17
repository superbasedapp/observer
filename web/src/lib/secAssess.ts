// secAssess is the Code security Overview's "Security assessments" card model
// (plan of record docs/plans/security-assessments-module-plan-2026-11-13.md,
// sections 4 and 6): the shapes of GET /api/security/assessments, /plan, the
// task the New terminal dialog is opened with, and the words of a run's
// state, import outcome and cloud boundary. Pure: no fetch, no React.
//
// Nothing here decides a rule. The server's own rules (E1 to E10) say whether
// a launch may start; this file only carries the answer and the sentences.

import type { NewTerminalTask, TaskLaunchResponse } from "./terminalTask.ts";
import type { Tone } from "../../../shared/lib/tone.ts";
import { CODE_SECURITY_SETTINGS } from "./codeSecuritySettings.ts";

export const ASSESS_LIST_PATH = "/api/security/assessments";
export const ASSESS_PLAN_PATH = "/api/security/assessments/plan";
export const ASSESS_LAUNCH_PATH = "/api/security/assessments/launch";
export const ASSESS_REPORT_PATH = "/api/security/assessments/report";
export const ASSESS_IMPORT_PATH = "/api/security/assessments/import";
export const ASSESS_REQUEST_PATH = "/api/security/assessments/request";
export const ASSESS_CANCEL_PATH = "/api/security/assessments/cancel";
export const ASSESS_STOP_PATH = "/api/security/assessments/stop";
export const ASSESS_DELETE_DATA_PATH = "/api/security/assessments/delete-data";
export const ASSESS_VALIDATE_PATH = "/api/security/assessments/validate";
export const ASSESS_MODEL_PATH = "/api/security/assessments/model";
export const ASSESS_FIX_PATH = "/api/security/assessments/fix";
export const ASSESS_EXPORT_PATH = "/api/security/assessments/export";

/** The reference tally of a validation (what Observer found when it looked at each reference). */
export type AssessRefTally = {
  found: number;
  exists: number;
  claimed_not_found: number;
  missing: number;
  invalid: number;
  unchecked: number;
};

/** The outcome of the last validation of a run's assessment.json. */
export type AssessValidation = {
  /** valid | partial | invalid. */
  state: string;
  at: string;
  /** The closed reason code of a refused file. */
  fatal?: string;
  /** Validated before the run ended. */
  anyway?: boolean;
  /** assessment.json changed after this validation. */
  stale?: boolean;
  refs: AssessRefTally;
  /** The match window the references were checked under (setting ref_match_window_lines); absent for a check that predates it. */
  ref_window_lines?: number;
  /** References whose quoted text hiding secrets changed, and that did not read found. */
  ref_text_hidden?: number;
  issues?: number;
  refused?: number;
};

/** The time box, deadline action and git check in force for a run (the plan's
 *  "settings in force"; docs/plans/security-assessments-depth-plan-2026-11-14.md W0). */
export type AssessLimits = {
  time_box_minutes: number;
  /** stop_button | auto_close. */
  time_box_action: string;
  boundary_audit: boolean;
  /** How this kind's git check reads a change (strict, untracked_reported, not_audited). */
  audit_policy: string;
  /** What the git check cannot see, in a sentence. */
  audit_limits: string;
  /** Set when the time box is longer than the relaxation window. */
  relaxation_note?: string;
  /** Pen test and red team: the most requests the agent is told to send (depth plan W4.6). */
  request_budget?: number;
  /** Pen test and red team: the most requests a second the agent is told to send. */
  pace_rps?: number;
};

/** One kind of assessment (the server's kind table row). */
export type AssessKind = {
  id: string;
  /** The kind has guardrails a run may ask to lift (docs/plans/security-assessments-module-plan-2026-11-13.md section 13). */
  relaxable?: boolean;
  title: string;
  summary: string;
  /** The badge words ("Read-only", "Sandboxed", "Your cloud session", "Partial", "Not agent-shaped"). */
  mode: string;
  /** false: there is no agent-shaped launch (reason and pointer say why and where to look). */
  launchable: boolean;
  reason?: string;
  pointer?: string;
  /** "optional" | "required" | "na". */
  sandbox: string;
  /** "none" | "required". */
  target: string;
  files: string[];
  note?: string;
  /** Why a launch of this kind cannot start on this machine right now ("" when nothing blocks it). */
  blocked?: string;
  blocked_code?: string;
  /** The red team: the kind asks for an objective and a chain of steps. */
  exercise?: boolean;
  /** The retest: started from an earlier run's findings in its model view, never from the card. */
  from_run?: boolean;
};

/** What the derivation of a model's findings did: how many candidates it
 *  considered, how many it kept, and why each of the others was not imported. */
export type AssessDerived = {
  considered: number;
  kept: number;
  no_location?: number;
  under_min_band?: number;
  duplicate?: number;
  over_cap?: number;
  over_ceiling?: number;
  /** The settings the derivation ran under. */
  min_band?: string;
  cap?: number;
  dedup?: boolean;
};

export type AssessImport = {
  at: string;
  /** "imported" | "no_findings" | "failed" | "unavailable". */
  outcome: string;
  reason?: string;
  prepared: number;
  prep_refused?: Record<string, number>;
  dropped?: number;
  findings: number;
  new: number;
  with_lineage: number;
  refused?: Record<string, number>;
  truncated?: boolean;
  /** Set for the import of a checked model. */
  derived?: AssessDerived;
};

/** What the agent's cloud command list held, by class. */
export type AssessCloud = {
  read_only: number;
  secret_material: number;
  mutating: number;
  unknown: number;
};

/** The consent route of one relaxation row, decided by the server's table. */
export type AssessRoute = "self" | "org_request" | "not_needed" | "refused";

/** One guardrail row of the plan (the server's relaxation table plus the route it decided). */
export type AssessRelaxRow = {
  /** The guard rule id ("R-179"), or "tier" for the sandbox network row. */
  key: string;
  /** "rule" | "tier". */
  type: string;
  title: string;
  /** What lifting it allows, in words. */
  lifts: string;
  /** Why this kind may ask. */
  why: string;
  route: AssessRoute;
  /** The consent-table row that decided ("C3", "T2"). */
  row: string;
  /** The refusal code of a row that is not offered. */
  code?: string;
  /** The sentence that says who consents, or why the row is not offered. */
  reason: string;
  ticked: boolean;
};

/** The relaxations part of the plan. */
export type AssessRelaxPlan = {
  /** "managed" | "individual" | "unresolved". */
  tenancy: string;
  /** "session" | "project" | "org". */
  scope: string;
  scope_words: string;
  /** The hard cap of one run's approval, in minutes. */
  minutes: number;
  /** The run writes audit rows to the org rail. */
  reported: boolean;
  report_row: string;
  enrolled: boolean;
  tier_live: string;
  tier_hosts: string[];
  rows: AssessRelaxRow[];
  /** The boundary lines the prompt gains with the ticked rows. */
  lines: string[];
};

/** One rule of a held run and where the organization's answer stands. */
export type AssessHeldRule = {
  rule: string;
  /** waiting | approved | narrower | declined | lapsed | queued. */
  state: string;
  grant_id?: number;
  request_id?: number;
  why?: string;
};

/** A held run's live answer, read from the node's verified grant cache. */
export type AssessHeld = {
  at: string;
  /** Every rule has a grant in force that covers the run. */
  ready: boolean;
  rules: AssessHeldRule[];
};

/** One relaxation recorded on a run. */
export type AssessRunRelax = {
  key: string;
  type: string;
  route: string;
  /** pending_bind | active | org_grant | not_bound | existing | lost | failed | ended | tier. */
  state: string;
  scope?: string;
  approval_id?: number;
  grant_id?: number;
  expires_at?: string;
  end_reason?: string;
  note?: string;
  hosts?: string[];
};

export type AssessRun = {
  id: string;
  created_at: string;
  kind: string;
  kind_title: string;
  tool: string;
  project_root_hash: string;
  project_name: string;
  handle?: string;
  seeded: boolean;
  sandboxed: boolean;
  backend?: string;
  tier?: string;
  target?: string;
  /** started | ended_empty | report_ready | model_ready | validated | invalid | findings_ready | imported | no_findings | import_failed | import_unavailable. */
  state: string;
  files: { report: boolean; sarif: boolean; commands: boolean; model?: boolean };
  /** The result contract the run was launched under; absent is the SARIF contract. */
  contract?: string;
  /** The last validation of the run's assessment.json. */
  validation?: AssessValidation;
  report_bytes: number;
  cloud?: AssessCloud;
  boundary_crossed?: boolean;
  import?: AssessImport;
  project_gone?: boolean;
  /** held (waiting for the organization), started or cancelled. */
  phase?: string;
  /** The held run's live answer. */
  held?: AssessHeld;
  relax?: AssessRunRelax[];
  relax_minutes?: number;
  /** The run writes audit rows to the org rail. */
  reported?: boolean;
  tenancy?: string;
  ended_at?: string;
  /** Verdicts the run's relaxations changed: exact for a local approval, approx for an org grant. */
  relaxed?: { exact: number; approx: number };
  /** The time box recorded at launch, in minutes (absent on a run recorded before time boxes). */
  time_box_minutes?: number;
  /** stop_button | auto_close, as recorded at launch. */
  time_box_action?: string;
  deadline?: string;
  /** The run is (or ended) past its deadline. */
  over_time_box?: boolean;
  /** The run has a terminal that has not ended: Stop applies. */
  can_stop?: boolean;
  /** terminal_gone | time_box | stopped. */
  end_why?: string;
  /** The git check: no_change | changed | partly_checked | could_not_check | not_audited | not_checked | pending | unrecorded.
   *  partly_checked: nothing changed in the files that could be compared, but some changed files could not be
   *  (more than 400 paths changed, or a file could not be read in time, is a folder or is over 32 MiB). */
  audit?: string;
  audit_words?: string;
  audit_at?: string;
  /** What the git check cannot see. */
  audit_limits?: string;
  /** The run has stored evidence that Delete removes. */
  has_data?: boolean;
  /** Threat model: the places the run was scoped to and the developer's note (absent: the whole project). */
  scope?: { paths: string[]; note?: string };
  /** Threat model: the earlier checked run the new model is compared with once it is checked. */
  previous_run?: string;
  /** How that comparison went, once the model was checked: ok | previous_missing (the earlier run's
   *  checked copy is gone, was too large to keep or is not a threat model) | too_large (the comparison
   *  did not fit the stored copy). Absent until the model has been checked. */
  compare_state?: string;
  /** The run has a stored, checked copy of its model to open. The server leaves the key out when there is none (a
   *  validation stays on the row after Delete evidence), so only true means there is one. */
  has_model?: boolean;
  /** Pen test and red team: the environment-files mode that was in force for the run (mask reads warn where the
   *  run's sandbox could not hide files), and the closed reason when it did (ASSESS_MASK_DOWNGRADE). */
  secret_mode?: string;
  secret_mode_why?: string;
  /** What the workspace secret mask covered once the box had started; absent when the launch did not ask for it. */
  secret_mask?: AssessMask;
  /** Red team: the developer's own objective, as it was cleaned for the task. Text, never markup. */
  objective?: string;
  /** Retest: the earlier run it replays, and the findings it was asked to replay. */
  retest_of?: string;
  retest_findings?: string[];
};

/** What the sandbox's workspace secret mask covered for a run: counts and closed reasons, never a path.
 *  `partial` says some environment or key files may still be readable inside the box (some places could not be
 *  covered, or nothing was reported); `words` is the server's sentence for it (decision D32). */
export type AssessMask = {
  reported: boolean;
  masked: number;
  complete: boolean;
  gaps: number;
  reasons?: { id: string; count: number; words: string }[];
  words: string;
  partial: boolean;
};

/** GET /api/security/assessments. */
export type AssessList = {
  kinds: AssessKind[];
  runs: AssessRun[];
  /** The SARIF import is selected on this node. */
  import_available: boolean;
  /** This dashboard can start a terminal at all. */
  launch: boolean;
  /** The run record exists but cannot be read: the empty list is not "no runs". */
  runs_unreadable?: boolean;
  /** The closed reason code of an unreadable record (run_record_unreadable). */
  runs_error?: string;
  /** The path of the run record, given while it cannot be read. */
  runs_file?: string;
};

export type AssessCandidate = {
  url: string;
  name?: string;
  /** Where the address was read from (a project file), when the server says. */
  source?: string;
};

/** A typed scope path the server refused, with its plain reason. */
export type AssessScopeRefusal = { path: string; reason: string };

/** The threat model's scope (depth plan W3.3): the project's top-level
 *  directories to pick from, and the scope the server accepted. */
export type AssessScope = {
  /** The project's top-level directories, the picker's choices. */
  dirs: string[];
  /** The effective validated paths (the subset the server accepted). */
  paths: string[];
  /** The effective, cleaned note. */
  note: string;
  refused?: AssessScopeRefusal[];
  max_paths: number;
  max_note: number;
};

/** What the task carries about the project (depth plan W3.2): the digest's
 *  setting, the sections it holds and its size. */
export type AssessGrounding = {
  /** full | without_findings | off. */
  mode: string;
  /** The section ids rendered (languages, manifests, infra, spec, dependencies, ai, start, findings). */
  sections: string[];
  /** The digest's size inside the task, in bytes. */
  bytes: number;
  /** Strings left out (characters the task does not accept, or the size cap). */
  dropped: number;
  /** The project shows signs of being an AI application. */
  ai_app: boolean;
};

/** One earlier checked threat model of this project the new one can be compared with. */
export type AssessPreviousOption = { id: string; created_at: string; scope?: string[] };

/** The comparison with an earlier run (depth plan W3.4). Observer puts nothing
 *  from the earlier run in the task; the task asks the agent not to open other
 *  runs' folders, which is a request and not a barrier. */
export type AssessPrevious = {
  /** Checked threat models of this project, newest first. */
  options: AssessPreviousOption[];
  /** The run id chosen ("" is none). */
  selected: string;
  /** The server's own default pick ("" is none). */
  default_run: string;
  /** One sentence on what the earlier run's files mean for the agent (see ASSESS_PREVIOUS_NOTE). */
  note: string;
};

/** One way the project says its development server starts (depth plan W4.1). */
export type AssessStartPlan = {
  command: string;
  /** What the dialog sends back as `start` to pick this plan. It equals `command` when `cwd` is
   *  empty; a plan that runs in a subfolder has its own choice string. Absent on an older server:
   *  then the command is the choice. */
  choice?: string;
  /** The folder, relative to the project, the command runs in ("" or absent: the project's own). */
  cwd?: string;
  port?: number;
  /** Where the command was read from. */
  source: string;
  /** Declared steps that run first (a migrate or seed). They run only when the developer opts in
   *  (AssessStart.prepare), because they can change local data in the project. */
  prepare?: string[];
  /** Services the application names that the sandbox cannot start. */
  needs?: string[];
};

/** The start command part of a pen test or red team plan. */
export type AssessStart = {
  /** Most likely first. */
  plans: AssessStartPlan[];
  /** The choice string in force ("" is none): a plan's `choice` (its `command` when it has none), or
   *  the command the developer typed. */
  selected_command: string;
  /** The text for the input (the effective command). */
  edit: string;
  /** The developer typed it. */
  edited: boolean;
  /** The developer opted in to the selected plan's preparation steps (default false). */
  prepare?: boolean;
  /** Why a typed command was refused, in plain words. */
  error?: string;
  /** No plan could be read from the project's files. */
  none_found: boolean;
  /** The project names start commands but none was chosen for the developer (the likeliest one is no well-known program), so the dialog asks. */
  not_preselected?: boolean;
};

/** A fact noticed before the run starts: advice, never a refusal. */
export type AssessPreflightNote = { id: string; level: "likely_fails" | "warn" | "info" | string; text: string };

/** One tool the task may use inside the sandbox. */
export type AssessToolRow = {
  id: string;
  purpose: string;
  command: string;
  /** null: Observer could not tell. */
  present: boolean | null;
  /** Rule R-179 may ask the developer before it runs. */
  guarded: boolean;
  /** What the agent does without it. */
  fallback: string;
};

/** The environment files in the project folder (depth plan W4.4). */
export type AssessEnv = {
  /** File names only, never contents. */
  files: string[];
  count: number;
  /** The setting's value and the value in force (they can differ). */
  configured: string;
  effective: string;
  /** Why a configured mask acts as a warning (a closed word, see ASSESS_MASK_DOWNGRADE); absent when it does not. */
  downgrade?: string;
  /** The sentence to show ("" when there is nothing to say). */
  line: string;
};

/** One rule of the safety table and where it is held (depth plan W4.6). */
export type AssessSafetyRow = {
  id: string;
  rule: string;
  /** The rule is written in the task. */
  prompt: boolean;
  /** What the request helper does about it; "-" where it does nothing. */
  helper: string;
  /** What Observer itself checks; "-" where it checks nothing. */
  observer: string;
  /** What that check does: prevents (it holds the rule outside the task), detects (it looks afterwards and
   *  prevents nothing) or stops (you can stop the run, but the limit itself is advisory); "" when the
   *  observer cell is "-". A value Observer has no words for is treated as a plain note. */
  observer_kind?: "prevents" | "detects" | "stops" | "" | string;
  /** Nothing but the task holds it. */
  prompt_only: boolean;
};

/** The request helper of a pen test or red team plan (depth plan W5b): whether Observer writes it into the run folder, and with what limits. */
export type AssessProbePlan = {
  /** on: the two files are written; off: the setting is off; withheld: left out because python3 was not seen in the sandbox's standard folders. */
  state: "on" | "off" | "withheld";
  /** The files written into the run folder when the state is on (probe.py and probe.json). */
  files?: string[];
  /** The run folder, relative to the project: .observer/assessments/<run id>. */
  dir: string;
  /** The server's sentence for a helper left out. */
  withheld_reason?: string;
  /** The most requests the helper sends. */
  budget: number;
  /** The most requests a second it sends. */
  pace_rps: number;
};

export type AssessPlanProject = {
  project_root_hash: string;
  name: string;
  root_path: string;
  on_disk: boolean;
};

/** GET /api/security/assessments/plan. */
export type AssessPlan = {
  confirm_token: string;
  run_id: string;
  kind: AssessKind;
  project: AssessPlanProject;
  /** true: a launch of this kind could start now (with the agent chosen next). */
  ok: boolean;
  rule?: string;
  code?: string;
  reason?: string;
  /** The normalized target the prompt names ("" until one is chosen). */
  target?: string;
  /** The caller named the target (false: a placeholder stood in for the checks). */
  target_typed: boolean;
  candidates: AssessCandidate[];
  boundary: string[];
  prompt?: string;
  backend?: string;
  tier?: string;
  /** Agents that can run a confined kind; null means any agent. */
  allowed_tools: string[] | null;
  seeds: Record<string, string>;
  residual?: string;
  /** The guardrails a run may ask to lift, with the route the server decided for each. */
  relax?: AssessRelaxPlan;
  /** The answer for the held run this plan replays. */
  held?: AssessHeld;
  /** The time box, deadline action and git check this run would start under. */
  limits?: AssessLimits;
  /** The digest of `prompt`: the launch sends it back so a task that changed
   *  after the developer read it is refused (plan_changed) instead of started. */
  prompt_sha256?: string;
  /** The model contract's settings in force; absent for a kind without one. */
  model?: AssessModelSettings;
  /** Threat model: the scope choices (depth plan W3.3). */
  scope?: AssessScope;
  /** Threat model, pen test and red team: what the task carries about the project (W3.2). */
  grounding?: AssessGrounding;
  /** Threat model: the earlier run to compare with (W3.4). */
  previous?: AssessPrevious;
  /** Pen test and red team: how the application starts (W4.1). */
  start?: AssessStart;
  /** Pen test and red team: facts noticed before the run starts (W4.2). */
  preflight?: AssessPreflightNote[];
  /** Pen test and red team: the tools in the sandbox (W4.3). */
  tools?: AssessToolRow[];
  /** Pen test and red team: the environment files in the folder (W4.4). */
  env?: AssessEnv;
  /** Pen test and red team: where each safety rule is held (W4.6). */
  safety?: AssessSafetyRow[];
  /** Pen test and red team: the request helper written into the run folder, or why not (W5b). */
  probe?: AssessProbePlan;
  /** Red team: the objective in force (cleaned by the server) and its bound in characters. */
  objective?: AssessObjective;
  /** Retest: the earlier run, the findings it can replay and the ones this plan replays. */
  retest?: AssessRetestPlan;
};

/** The red team's objective block of the plan: `text` is the objective in force, cleaned (no line breaks, no backticks), `max` its bound in characters. */
export type AssessObjective = { text: string; max: number };

/** One finding of the earlier run that a retest can replay: what the earlier run's checked model stored for it. */
export type AssessRetestFinding = {
  id: string;
  title: string;
  category?: string;
  /** How many stored requests the finding has. */
  steps: number;
  /** A response condition was stored for it (without one no label can be backed by the log). */
  has_condition: boolean;
  condition?: string;
  /** A stored request had a value hidden when it was kept, so the replay may differ from the original request. */
  hidden?: boolean;
};

/** A finding the retest cannot replay, with the closed word for why (unknown_finding | no_request | too_many | duplicate). */
export type AssessRetestRefused = { finding: string; code: string };

/** The retest block of the plan. `of_target` is the address the earlier run confirmed, offered as a suggestion only. */
export type AssessRetestPlan = {
  of_run: string;
  of_kind?: string;
  of_target?: string;
  findings: AssessRetestFinding[];
  selected: string[];
  max: number;
  refused?: AssessRetestRefused[];
};

/** The model contract's part of the plan's settings in force. */
export type AssessModelSettings = {
  prompt_version: string;
  /** Preset ids of the settings (a threat model has frameworks and method extras, a pen test its categories). */
  frameworks?: string;
  method_extras?: string;
  categories?: string;
  self_check: boolean;
  import_min_band: string;
  findings_cap: number;
  rerun_dedup: boolean;
  /** The project-facts setting (full, without_findings, off). */
  grounding?: string;
  /** The environment-files setting as chosen, and the value in force (the sandbox may not be able to do what was chosen). */
  secret_mode?: string;
  secret_mode_effective?: string;
  /** Why the chosen mask acts as a warning (ASSESS_MASK_DOWNGRADE); absent when it does not. */
  secret_mode_downgrade?: string;
  /** Pen test and red team: the request limits (also on `limits`). */
  request_budget?: number;
  pace_rps?: number;
};

/** The kinds' words on the plan dialog's sandbox line. */
export const ASSESS_SANDBOX_WORDS: Readonly<Record<string, string>> = {
  required: "Runs in a sandbox that Observer chooses; it refuses to start without one",
  optional: "Your choice of sandbox in the next step",
  na: "No launch",
};

/** assessSandboxWords is a kind's sandbox policy in words. */
export function assessSandboxWords(sandbox: string): string {
  return ASSESS_SANDBOX_WORDS[sandbox] ?? sandbox;
}

/** assessDefaultProject is the project the plan dialog opens on. The Code security page is not scoped to one project, so the
 *  project "in context" is the one the developer last assessed: the project of the newest run in the list that is still among
 *  the options. With no run to go by it is the first active project, else the first option (the order the page lists them in).
 *  The developer can always pick another; this only decides where the picker starts. undefined when there is no option. */
export function assessDefaultProject<P extends { project_root_hash: string; active?: boolean }>(
  options: readonly P[],
  runs: readonly { project_root_hash: string; created_at: string }[] | undefined,
): P | undefined {
  let newest: { hash: string; at: number } | null = null;
  for (const r of runs ?? []) {
    const at = Date.parse(r.created_at);
    if (Number.isNaN(at) || !options.some((p) => p.project_root_hash === r.project_root_hash)) continue;
    if (newest === null || at > newest.at) newest = { hash: r.project_root_hash, at };
  }
  const recent = newest ? options.find((p) => p.project_root_hash === newest.hash) : undefined;
  return recent ?? options.find((p) => p.active) ?? options[0];
}

/** assessModeTone is a kind's badge tone: sandboxed and read-only kinds are
 *  calm, a kind that uses the developer's own cloud session or is partial is
 *  a caution, and one with no launch is neutral. */
export function assessModeTone(k: Pick<AssessKind, "launchable" | "sandbox" | "mode">): Tone {
  if (!k.launchable) return "neutral";
  if (k.sandbox === "required") return "info";
  if (k.mode === "Your cloud session" || k.mode === "Partial") return "warn";
  return "success";
}

/** The guardrails the developer ticked: rule ids and the tier row's tick. */
export type AssessTicks = { rules: string[]; tier: boolean };

/** assessNoTicks is the empty selection (a launch that names no guardrail). */
export const ASSESS_NO_TICKS: AssessTicks = { rules: [], tier: false };

/** The word that stands for "no comparison" (previous_run) and "no declared
 *  start command" (start): a choice made on purpose, as against a field left
 *  alone so that the server's own default stands. */
export const ASSESS_NONE = "none";

/** The choices a developer makes on the plan beside the guardrail ticks (depth
 *  plan W3.3, W3.4, W4.1). A field left undefined is a choice not made: the
 *  server's default stands, nothing is sent, and an untouched dialog reads and
 *  launches exactly what it always did. The plan read and the launch carry the
 *  same choices, so the task the developer read is the task that starts. */
export type AssessChoices = {
  /** Threat model: the places to model (empty or undefined: the whole project). */
  scopePaths?: string[];
  /** Threat model: a note in the developer's own words. */
  scopeNote?: string;
  /** Threat model: a run id, or ASSESS_NONE. */
  previousRun?: string;
  /** Pen test and red team: the start choice (a plan's `choice`), the typed start command, or ASSESS_NONE. */
  start?: string;
  /** Pen test and red team: run the selected plan's preparation steps first. They can change local data
   *  in the project, so only an explicit tick sets this; changing the start choice clears it. */
  prepare?: boolean;
  /** Red team: the objective in the developer's own words (at most the plan's bound, in characters). */
  objective?: string;
  /** Retest: the earlier run whose findings are replayed, and the finding ids chosen, in the order chosen. */
  ofRun?: string;
  findings?: string[];
};

/** ASSESS_NO_CHOICES is the dialog before anything is chosen. */
export const ASSESS_NO_CHOICES: AssessChoices = {};

/** assessChosenScope is the choices' scope paths, trimmed, without blanks or
 *  repeats, in the order they were chosen. */
function assessChosenScope(c: AssessChoices | undefined): string[] {
  const out: string[] = [];
  for (const p of c?.scopePaths ?? []) {
    const t = p.trim();
    if (t && !out.includes(t)) out.push(t);
  }
  return out;
}

/** assessChosenFindings is the retest's chosen finding ids, trimmed, without blanks, in the order they were chosen. A repeat is kept: the server refuses it by name, and a choice is never changed silently. */
function assessChosenFindings(c: AssessChoices | undefined): string[] {
  return (c?.findings ?? []).map((id) => id.trim()).filter((id) => id !== "");
}

/** assessPlanPath is the plan read's URL for one kind, one project, an
 *  optional typed target, the ticked guardrails (so the prompt shows their
 *  lines), to replay a run held for the organization its run id and, last, the
 *  developer's other choices (scope, comparison, start command, and `prepare=yes`
 *  when they opted in to the start plan's preparation steps; absent is no). */
export function assessPlanPath(
  kind: string,
  project: string,
  target?: string,
  ticks?: AssessTicks,
  run?: string,
  choices?: AssessChoices,
): string {
  const qs = new URLSearchParams({ kind, project });
  const t = (target ?? "").trim();
  if (t) qs.set("target", t);
  if (ticks && ticks.rules.length > 0) qs.set("relax", ticks.rules.join(","));
  if (ticks?.tier) qs.set("tier_relax", "1");
  if (run) qs.set("run", run);
  for (const p of assessChosenScope(choices)) qs.append("scope_path", p);
  const note = (choices?.scopeNote ?? "").trim();
  if (note) qs.set("scope_note", note);
  const prev = (choices?.previousRun ?? "").trim();
  if (prev) qs.set("previous_run", prev);
  const start = (choices?.start ?? "").trim();
  if (start) qs.set("start", start);
  // Preparation steps are opt-in: absent means no.
  if (choices?.prepare === true) qs.set("prepare", "yes");
  const objective = (choices?.objective ?? "").trim();
  if (objective) qs.set("objective", objective);
  const ofRun = (choices?.ofRun ?? "").trim();
  if (ofRun) qs.set("of_run", ofRun);
  for (const id of assessChosenFindings(choices)) qs.append("finding", id);
  return `${ASSESS_PLAN_PATH}?${qs.toString()}`;
}

/** assessReportError is the report dialog's words for a refused read: the
 *  file's own states (not written yet, over the size cap, not a plain file) and,
 *  for a 409, the run record being unusable, which carries its own words. */
export function assessReportError(status: number, body = ""): string {
  switch (status) {
    case 404:
      return "The report is not there yet. The agent writes it when it finishes.";
    case 409:
      return assessRefusalWords({ status, body }) ?? "The report could not be read.";
    case 413:
      return "The report is over the size cap, so it is not shown here. Open the file in the project's .observer/assessments folder.";
    case 422:
      return "The report is not a plain file, so it is not shown.";
    default:
      return "The report could not be read.";
  }
}

/** assessReportPath is the report read's URL for one run. */
export function assessReportPath(run: string): string {
  return `${ASSESS_REPORT_PATH}?${new URLSearchParams({ run }).toString()}`;
}

/** assessLaunchBody is the task fields of POST /api/security/assessments/launch;
 *  the New terminal dialog adds the agent choice. The kind travels as
 *  "assessment" (the launch body's own "kind" is the launch shape). The target
 *  is sent twice by design: as typed, and as the confirmation the developer
 *  gave to the exact string the plan showed. A kind without a target sends
 *  neither. The guardrails are sent only when one is ticked, and the scope, the
 *  comparison and the start command only when one was chosen, so a launch that
 *  lifts and chooses nothing has exactly the body it always had. The scope
 *  paths are the ones the server accepted when it read the plan (a typed path it
 *  refused is not sent), so the launch rebuilds the task the developer read. */
export function assessLaunchBody(
  plan: Pick<AssessPlan, "kind" | "project" | "run_id" | "target" | "prompt_sha256" | "scope">,
  ticks: AssessTicks = ASSESS_NO_TICKS,
  choices: AssessChoices = ASSESS_NO_CHOICES,
): Record<string, unknown> {
  const body: Record<string, unknown> = {
    assessment: plan.kind.id,
    project_root_hash: plan.project.project_root_hash,
    run_id: plan.run_id,
  };
  if (plan.kind.target === "required") {
    body.target = plan.target ?? "";
    body.confirm_target = plan.target ?? "";
  }
  if (ticks.rules.length > 0) body.relaxations = ticks.rules;
  if (ticks.tier) body.tier_relax = true;
  const chosen = assessChosenScope(choices);
  if (chosen.length > 0) {
    const accepted = plan.scope ? plan.scope.paths : chosen;
    if (accepted.length > 0) body.scope_paths = accepted;
  }
  const note = (choices.scopeNote ?? "").trim();
  if (note) body.scope_note = note;
  const prev = (choices.previousRun ?? "").trim();
  if (prev) body.previous_run = prev;
  const start = (choices.start ?? "").trim();
  if (start) body.start = start;
  if (choices.prepare === true) body.prepare = true;
  // A red team's objective and a retest's earlier run and findings are sent
  // only by the kind that takes them, so no other launch gains a member.
  const objective = (choices.objective ?? "").trim();
  if (plan.kind.exercise === true && objective) body.objective = objective;
  const ofRun = (choices.ofRun ?? "").trim();
  if (plan.kind.from_run === true && ofRun) body.of_run = ofRun;
  const findingIds = assessChosenFindings(choices);
  if (plan.kind.from_run === true && findingIds.length > 0) body.finding_ids = findingIds;
  // The digest of the task the developer read: the server refuses the launch
  // (409 plan_changed) when the task it would start is a different one.
  if (plan.prompt_sha256) body.prompt_sha256 = plan.prompt_sha256;
  return body;
}

/** assessRequestBody is the body of POST /api/security/assessments/request:
 *  the same run, project, target and ticked guardrails as the launch will
 *  send, without the agent. A start command the developer chose is sent too, with
 *  the opt-in to its preparation steps when they gave it, so the run held for the
 *  organization keeps both. */
export function assessRequestBody(
  plan: Pick<AssessPlan, "kind" | "project" | "run_id" | "target">,
  ticks: AssessTicks,
  choices: AssessChoices = ASSESS_NO_CHOICES,
): Record<string, unknown> {
  const body: Record<string, unknown> = {
    assessment: plan.kind.id,
    project_root_hash: plan.project.project_root_hash,
    run_id: plan.run_id,
    relaxations: ticks.rules,
  };
  if (plan.kind.target === "required") body.target = plan.target ?? "";
  const start = (choices.start ?? "").trim();
  if (start) body.start = start;
  if (choices.prepare === true) body.prepare = true;
  // A red team run held for the organization keeps its objective; a retest's earlier run and findings travel the same way (a retest has no guardrail to ask about, so the server answers nothing to request).
  const objective = (choices.objective ?? "").trim();
  if (plan.kind.exercise === true && objective) body.objective = objective;
  const ofRun = (choices.ofRun ?? "").trim();
  if (plan.kind.from_run === true && ofRun) body.of_run = ofRun;
  const findingIds = assessChosenFindings(choices);
  if (plan.kind.from_run === true && findingIds.length > 0) body.finding_ids = findingIds;
  return body;
}

/** assessConfirmWords is the one sentence the developer ticks before a
 *  target kind starts, naming the exact target. */
export function assessConfirmWords(target: string): string {
  return `This is my own application, running on this machine, and ${target} is the only thing the agent may test.`;
}

/** assessReady is why the plan's Choose agent button is disabled, or null. */
export function assessReady(
  plan: Pick<AssessPlan, "ok" | "reason" | "kind" | "target" | "target_typed" | "project">,
  confirmed: boolean,
  dockReady: boolean,
  launch: boolean,
): string | null {
  if (!plan.kind.launchable) return plan.kind.reason ?? "This assessment has no launch";
  if (!launch) return "This dashboard cannot start a terminal";
  if (!plan.project.on_disk) return "This project's folder is not on this machine";
  if (!plan.ok) return plan.reason ?? "This assessment cannot start on this machine";
  if (plan.kind.target === "required") {
    if (!plan.target_typed || !plan.target) return "Choose the target first";
    if (!confirmed) return "Confirm the target first";
  }
  if (!dockReady) return "The terminal dock is not available on this page";
  return null;
}

/** assessLaunchRefusal is the sentence for a launch the server refused with a
 *  409: the task changed after the developer read it (plan_changed), the run
 *  record cannot be used, a rule of the plan no longer holds. Every code has
 *  its words (ASSESS_REFUSALS), and a code without a row reads as the server's
 *  own sentence. null for any other status, which shows the server's text as
 *  the dialog always has (the org terminal gate's 403, say). */
export function assessLaunchRefusal(e: unknown): string | null {
  return (e as { status?: unknown } | null)?.status === 409 ? assessRefusalWords(e) : null;
}

/** assessTaskFor is the task the New terminal dialog is opened with. */
export function assessTaskFor(
  plan: AssessPlan,
  onStarted?: (r: TaskLaunchResponse) => void,
  ticks: AssessTicks = ASSESS_NO_TICKS,
  choices: AssessChoices = ASSESS_NO_CHOICES,
): NewTerminalTask {
  const confined = plan.kind.sandbox === "required";
  const where = plan.kind.target === "required" && plan.target ? ` against ${plan.target}` : "";
  const hosts = plan.relax?.tier_hosts ?? [];
  return {
    title: plan.kind.title,
    summary: `In ${plan.project.name || plan.project.root_path}${where}. The agent gets the task and writes its report into .observer/assessments/${plan.run_id}/.`,
    projectRoot: plan.project.root_path,
    launchPath: ASSESS_LAUNCH_PATH,
    launchBody: assessLaunchBody(plan, ticks, choices),
    seeds: plan.seeds,
    confirmToken: plan.confirm_token,
    allowedTools: confined ? (plan.allowed_tools ?? []) : undefined,
    refusalText: assessLaunchRefusal,
    serverSandbox: confined
      ? ticks.tier
        ? `This assessment runs in a sandbox${plan.backend ? ` (${plan.backend})` : ""} that Observer sets up for it. Its network is wider than usual for this run: besides the model connection it can reach only ${hosts.length > 0 ? hosts.join(", ") : "the hosts you listed"}. If the sandbox cannot be built the launch is refused, never run unsandboxed.`
        : `This assessment runs in a sandbox${plan.backend ? ` (${plan.backend})` : ""} that Observer sets up for it. The agent's only route out is Observer's model connection. If the sandbox cannot be built the launch is refused, never run unsandboxed.`
      : undefined,
    onStarted,
  };
}

/** The words and tone of each run state. */
export const ASSESS_STATE: Readonly<Record<string, { label: string; tone: Tone; next: string }>> = {
  started: {
    label: "running",
    tone: "info",
    next: "Waiting for the agent to write its report into the run folder.",
  },
  // The run's terminal ended and the agent wrote no report, model or findings
  // file (the server derives this: secassess.StateEndedEmpty). assessRunState
  // adds how it ended.
  ended_empty: {
    label: "ended without a result",
    tone: "warn",
    next: "The run ended and the agent wrote nothing into the run folder, so there is nothing to read or check. Open the run's terminal session to see why, then start the assessment again.",
  },
  report_ready: {
    label: "report ready",
    tone: "success",
    next: "Read the report. The agent has not written a findings file yet.",
  },
  model_ready: {
    label: "model written",
    tone: "info",
    next: "The agent wrote its model. Validate it to check its structure and file references.",
  },
  validated: {
    label: "validated",
    tone: "success",
    next: "Observer checked the model's structure and file references. It does not check that the agent's reasoning is right.",
  },
  invalid: {
    label: "model refused",
    tone: "danger",
    next: "The model file was refused. The report is still readable.",
  },
  no_findings: {
    label: "nothing to import",
    tone: "neutral",
    next: "Nothing was derived to import from this model. That says nothing about the project: only a missing mitigation or a reported weakness with a location in the code becomes a finding.",
  },
  findings_ready: {
    label: "findings ready",
    tone: "warn",
    next: "Import the findings to see them on the Findings tab.",
  },
  imported: {
    label: "imported",
    tone: "success",
    next: "The findings are on the Findings tab, tagged with this run.",
  },
  import_failed: {
    label: "import failed",
    tone: "danger",
    next: "The findings file was refused. The report is still readable.",
  },
  import_unavailable: {
    label: "import off",
    tone: "neutral",
    next: "The SARIF import is not turned on here. The report is still readable.",
  },
  held: {
    label: "waiting for your organization",
    tone: "warn",
    next: "Observer asked your organization to lift the ticked guardrail. The run starts when its grant is in force.",
  },
  cancelled: {
    label: "cancelled",
    tone: "neutral",
    next: "The request was withdrawn. Nothing started.",
  },
};

/** assessState is a run state's words; an unknown state reads as itself. */
export function assessState(state: string): { label: string; tone: Tone; next: string } {
  return ASSESS_STATE[state] ?? { label: state.replace(/_/g, " ") || "unknown", tone: "neutral", next: "" };
}

/** The import failure and unavailable reasons, in words. */
export const ASSESS_IMPORT_REASONS: Readonly<Record<string, string>> = {
  not_sarif: "The findings file is not a SARIF file.",
  too_large: "The findings file is over the size cap.",
  too_deep: "The findings file is nested too deeply to read.",
  no_usable_result: "The findings file held no result the import could use.",
  unreadable: "The findings file could not be read.",
  import_refused: "The import refused the file.",
  node_error: "The node could not record the findings.",
  component_not_selected: "The SARIF import is not turned on. Turn it on in Settings, then import again.",
  import_not_in_build: "This build has no SARIF import.",
  model_unavailable: "The stored copy of the checked model is gone. Check the model again, then import.",
  model_too_large_to_keep:
    "The checked model is too large to keep, so no findings can be derived from it. Checking it again will not change that: have the agent write a smaller assessment.json, then check that.",
};

/** assessImportLine is a run's last import outcome in one sentence, or "" when
 *  none was recorded. */
export function assessImportLine(imp: AssessImport | null | undefined): string {
  if (!imp) return "";
  if (imp.outcome === "imported") {
    const n = imp.findings;
    const fresh = imp.new;
    const base = `${n} ${n === 1 ? "finding" : "findings"} imported (${fresh} new)`;
    const left = assessDerivedLine(imp.derived);
    if (!imp.truncated && !left) return base;
    return `${base}.${imp.truncated ? " The file held more than the import keeps." : ""}${left ? ` ${left}` : ""}`;
  }
  if (imp.outcome === "no_findings") {
    const d = imp.derived;
    if (!d || d.considered === 0) return "Nothing was derived to import: the model listed no missing mitigation or reported weakness.";
    return `Nothing was derived to import from ${d.considered} ${d.considered === 1 ? "candidate" : "candidates"}. ${assessDerivedLine(d)}`.trim();
  }
  return ASSESS_IMPORT_REASONS[imp.reason ?? ""] ?? (imp.outcome === "unavailable" ? "The import is not available." : "The import failed.");
}

/** assessImportConflict is the sentence for a 409 from the import route: a run
 *  under a model contract whose model has not been checked (or changed since)
 *  has nothing to derive findings from (not_validated), the run record cannot
 *  be used (run_record_*), and the old route's plain-text refusal is a run with
 *  no findings file yet. An answer with no words at all reads as that last one. */
export function assessImportConflict(body: string): string {
  return assessRefusalWords({ status: 409, body }) ?? "The run has no findings file to import yet.";
}

/** assessImportLabel is the Import button's label for a run's state. */
export function assessImportLabel(state: string): string {
  return state === "import_failed" || state === "import_unavailable" || state === "no_findings" ? "Import again" : "Import findings";
}

/** assessDerivedLine says, in one sentence, how many candidates of a model were
 *  not imported and why, or "" when every one was. Nothing is left out silently:
 *  each reason with a count shows, the import's own 1000-result ceiling included. */
export function assessDerivedLine(d: AssessDerived | null | undefined): string {
  if (!d) return "";
  const left = d.considered - d.kept;
  if (left <= 0) return "";
  const parts: string[] = [];
  if ((d.no_location ?? 0) > 0) parts.push(`${d.no_location} with no location in the code`);
  if ((d.under_min_band ?? 0) > 0) parts.push(`${d.under_min_band} under your minimum band${d.min_band ? ` (${d.min_band})` : ""}`);
  if ((d.duplicate ?? 0) > 0) parts.push(`${d.duplicate} repeating another`);
  if ((d.over_cap ?? 0) > 0) parts.push(`${d.over_cap} past your cap of ${d.cap ?? 0}`);
  if ((d.over_ceiling ?? 0) > 0) parts.push(`${d.over_ceiling} past the import's own 1000-result ceiling`);
  return `${left} of ${d.considered} not imported: ${parts.join(", ")}.`;
}

/** assessCloudLine is a cloud run's command list in words, or "" for a run
 *  without one. It is the agent's own list, classified by verb: a check of
 *  the boundary, not a trace of what ran. */
export function assessCloudLine(c: AssessCloud | null | undefined): string {
  if (!c) return "";
  const total = c.read_only + c.secret_material + c.mutating + c.unknown;
  if (total === 0) return "The agent listed no cloud commands.";
  const parts = [`${c.read_only} read-only`];
  if (c.mutating > 0) parts.push(`${c.mutating} that change something`);
  if (c.secret_material > 0) parts.push(`${c.secret_material} that return secret material`);
  if (c.unknown > 0) parts.push(`${c.unknown} Observer cannot classify`);
  return `The agent listed ${total} cloud ${total === 1 ? "command" : "commands"}: ${parts.join(", ")}.`;
}

/** assessCrossed is whether a cloud list holds a command outside the
 *  read-only boundary (the run is shown as having crossed it). */
export function assessCrossed(c: AssessCloud | null | undefined): boolean {
  return !!c && (c.mutating > 0 || c.secret_material > 0);
}

/** ASSESS_BACKEND_UNRECORDED is what a sandboxed run's row says when its record names no sandbox: a run launched before the launcher reported the backend it built kept none, and the row says so instead of leaving the reader to wonder whether it was left out. The backend is never guessed from today's settings. */
export const ASSESS_BACKEND_UNRECORDED = "backend not recorded for this run";

/** assessRunTarget is a run's one line of where it ran. */
export function assessRunWhere(r: Pick<AssessRun, "sandboxed" | "backend" | "target">): string {
  const parts: string[] = [];
  if (r.target) parts.push(r.target);
  parts.push(r.sandboxed ? `in a sandbox (${r.backend ? r.backend : ASSESS_BACKEND_UNRECORDED})` : "not sandboxed");
  return parts.join(" · ");
}

/** ASSESS_COMPARED_KIND is how an earlier run in the comparison is named: only a
 *  threat model is ever compared with another. */
export const ASSESS_COMPARED_KIND = "Threat model";

/** assessRunLabel is how a run is named wherever one is chosen or mentioned (the
 *  run row's comparison line, the plan's comparison picker, the model view's
 *  compare select): what it is and when it ran, in the app's date format, and
 *  how it stands when the place that names it knows that. A run is named, never
 *  identified by its id: a person asks "which run", and two runs of the same
 *  hour read differently by their minute. */
export function assessRunLabel(kindTitle: string | undefined, createdAt: string | undefined, fmtDate?: (iso: string) => string, state?: string): string {
  // The kind's own title carries a clarifier in parentheses ("Penetration test (your own app, local)"); inside the parentheses a sentence puts around a run's name it read as "(Penetration test (your own app, local), Nov 15, 2026, 09:00)". The words before it name the kind, and the date tells two runs apart.
  const kind = (kindTitle ?? "").replace(/\s*\([^()]*\)\s*$/, "").trim() || ASSESS_COMPARED_KIND;
  const at = (createdAt ?? "").trim();
  const when = at ? (fmtDate ? fmtDate(at) : at.slice(0, 10)) : "";
  const st = (state ?? "").trim();
  return [kind, when, st].filter((x) => x !== "").join(", ");
}

/** assessEarlierWords is how the comparison names the earlier run: by its label
 *  when the run list still holds it, otherwise as an earlier run the list no
 *  longer holds (the list is capped, and the run's data may be deleted). */
function assessEarlierWords(label: string | undefined): string {
  const l = (label ?? "").trim();
  return l ? `the earlier run (${l})` : "an earlier run that is no longer in the list";
}

/** assessCompareLine is the second small line of a threat model run: which
 *  earlier run it is compared with and how that went. `earlier` is that run's
 *  label (assessRunLabel), found by the caller in the run list; "" when the list
 *  no longer holds it. Nothing is compared until the new model has been
 *  checked, so a run with no outcome yet says the comparison is still to come.
 *  When the earlier run's checked copy is gone (or was too large to keep, or is
 *  not a threat model) the line says no comparison was made, never that there
 *  was one. A state Observer has no words for says only that the run was chosen.
 *  "" when no earlier run was chosen. */
export function assessCompareLine(r: Pick<AssessRun, "previous_run" | "compare_state">, earlier?: string): string {
  const id = (r.previous_run ?? "").trim();
  if (!id) return "";
  const who = assessEarlierWords(earlier);
  switch ((r.compare_state ?? "").trim()) {
    case "":
      return `Compared with ${who}: shown once the model is checked`;
    case "ok":
      return `Compared with ${who}`;
    case "previous_missing":
      return `Not compared with ${who}: Observer no longer has a usable checked copy of it`;
    case "too_large":
      return `Compared with ${who}, but the comparison was too large to keep`;
    default:
      return `${who.charAt(0).toUpperCase()}${who.slice(1)} was chosen for comparison; how it went is not shown here`;
  }
}

/** assessRunScopeLines are a threat model run's two small lines about what it
 *  was scoped to and what it is compared with, each "" when the run has none
 *  (the whole project, no comparison). The scope line carries the developer's
 *  note whether or not places were chosen: the task carries it either way. */
export function assessRunScopeLines(r: Pick<AssessRun, "scope" | "previous_run" | "compare_state">, earlier?: string): { scope: string; previous: string } {
  const paths = r.scope?.paths ?? [];
  const note = (r.scope?.note ?? "").trim();
  const scope = paths.length > 0 ? `Scope: ${paths.join(", ")}${note ? `. Note: ${note}` : ""}` : note ? `Note: ${note}` : "";
  return { scope, previous: assessCompareLine(r, earlier) };
}

/** assessRunMaskLine is the line a run row carries about the environment files of a pen test or red team:
 *  what the workspace secret mask covered (a warning when some files may still be readable inside the box,
 *  with the server's counts), or why a chosen mask acted as a warning. null for a run that asked for neither. */
export function assessRunMaskLine(r: Pick<AssessRun, "secret_mode" | "secret_mode_why" | "secret_mask">): AssessLine | null {
  if (r.secret_mask) return { text: `Environment files: ${r.secret_mask.words}`, tone: r.secret_mask.partial ? "warn" : "neutral" };
  if (r.secret_mode_why) {
    return { text: `Environment files: ${secretModeShort("mask")} was chosen, but ${maskDowngradeWords(r.secret_mode_why)}, so it acted as a warning.`, tone: "warn" };
  }
  return null;
}

/** assessPolling is whether the runs list keeps refreshing: while any run may
 *  still receive a result file, is waiting for the organization or holds a
 *  guardrail still in force (its state can move without the dashboard doing
 *  anything). */
export function assessPolling(l: Pick<AssessList, "runs"> | null | undefined): boolean {
  return (l?.runs ?? []).some(
    (r) =>
      r.state === "started" ||
      r.state === "report_ready" ||
      r.state === "findings_ready" ||
      r.phase === "held" ||
      assessRelaxOpen(r) ||
      r.can_stop === true ||
      r.audit === "pending",
  );
}

/** ASSESS_IMPORT_SETTINGS is where the SARIF import is turned on: the Components page, opened on the import's own row. */
export const ASSESS_IMPORT_SETTINGS = "/settings/components?component=security.scan.sarif-import";

/** assessImportable is whether the run's Import button is offered: a findings
 *  file exists and the import is not already done. */
export function assessImportable(r: Pick<AssessRun, "state" | "files" | "contract">): boolean {
  // A retest has no findings of its own to import: its labels are shown on the findings of the run it replayed.
  if (r.contract === "retest.v1") return false;
  // A run under a model contract imports what Observer derives from its checked
  // model: offered once the model is validated (and again after a failure or an
  // import that derived nothing, since a setting may have changed). The
  // agent's own findings file plays no part.
  if (r.contract && r.contract !== "sarif") {
    return ["validated", "import_failed", "import_unavailable", "no_findings"].includes(r.state);
  }
  return r.files.sarif && r.state !== "imported";
}


// --- Guardrails for one run (plan section 13) ------------------------------
//
// The server decides every row's route and every run's relaxation state; the
// functions below only choose the sentences and the one button the dialog
// offers.

/** The relaxation rows the developer ticked, in plan order. */
export function assessTickedRows(relax: AssessRelaxPlan | null | undefined, ticks: AssessTicks): AssessRelaxRow[] {
  return (relax?.rows ?? []).filter((r) => (r.type === "tier" ? ticks.tier : ticks.rules.includes(r.key)));
}

/** assessRowOffered is whether a row can be ticked: the developer's own tick
 *  is the consent (self), or the organization approves and Observer asks. */
export function assessRowOffered(row: Pick<AssessRelaxRow, "route">): boolean {
  return row.route === "self" || row.route === "org_request";
}

/** The consent words of a route, shown beside a row's tick. */
export const ASSESS_ROUTE_WORDS: Readonly<Record<AssessRoute, string>> = {
  self: "You approve this",
  org_request: "Your organization approves this",
  not_needed: "Nothing to lift",
  refused: "Not offered",
};

/** assessRouteWords is a route's label; an unknown route reads as refused. */
export function assessRouteWords(route: string): string {
  return ASSESS_ROUTE_WORDS[route as AssessRoute] ?? ASSESS_ROUTE_WORDS.refused;
}

/** assessScopeLine says what a ticked guardrail covers, how long it lasts and
 *  what it does not cover, from the plan's own facts. "" when nothing is
 *  ticked. */
export function assessScopeLine(relax: AssessRelaxPlan | null | undefined, ticks: AssessTicks): string {
  const ticked = assessTickedRows(relax, ticks);
  if (!relax || ticked.length === 0) return "";
  const parts: string[] = [];
  if (ticked.some((r) => r.type === "rule" && r.route === "self")) {
    parts.push(
      relax.scope === "project"
        ? `Your approval covers every session in this project, including one you start outside the box, until the run ends, and never longer than ${relax.minutes} minutes.`
        : `Your approval covers this terminal's session only, ends when the terminal closes, and never lasts longer than ${relax.minutes} minutes. Until Observer has identified the session the guard asks as usual.`,
    );
  }
  if (ticked.some((r) => r.type === "rule" && r.route === "org_request")) {
    parts.push(
      `Your organization's grant covers this project on this machine and ends at its own expiry, which is not the end of the run (you ask for up to ${relax.minutes} minutes). Observer cannot revoke it.`,
    );
  }
  if (ticked.some((r) => r.type === "tier")) {
    parts.push("The wider network is the one you already configured: the run is let start under it, and the scope is held by the task text and your word.");
  }
  return parts.join(" ");
}

/** assessReportLine says whether the run is reported to the organization. */
export function assessReportLine(relax: AssessRelaxPlan | null | undefined): string {
  if (!relax) return "";
  if (relax.reported) {
    return relax.tenancy === "individual"
      ? "This run is reported to your organization (you turned that on): when it started, ended and was imported."
      : "Runs on a node your organization manages are reported to it: when each started, ended and was imported, with the guardrails lifted.";
  }
  return "This run is not reported to your organization.";
}

/** The one action the plan's primary button takes. */
export type AssessAction = "start" | "ask" | "wait";

/** assessPrimary is the plan's primary button: Choose agent when nothing the
 *  organization must approve is ticked, Ask my organization when something is
 *  and no request was filed, a disabled wait while a held run is not approved,
 *  and Approved: start once it is. block is why the button is disabled. */
export function assessPrimary(
  plan: Pick<AssessPlan, "ok" | "reason" | "kind" | "target" | "target_typed" | "project" | "relax" | "held">,
  ticks: AssessTicks,
  confirmed: boolean,
  dockReady: boolean,
  launch: boolean,
): { action: AssessAction; label: string; block: string | null } {
  const org = assessTickedRows(plan.relax, ticks).filter((r) => r.route === "org_request");
  if (org.length === 0) return { action: "start", label: "Choose agent", block: assessReady(plan, confirmed, dockReady, launch) };
  if (plan.held?.ready) return { action: "start", label: "Approved: start", block: assessReady(plan, confirmed, dockReady, launch) };
  if (plan.held) {
    return { action: "wait", label: "Waiting for your organization", block: "Your organization has not approved this yet. This page updates when it does." };
  }
  // Asking starts nothing, so the terminal dock is not needed here.
  return { action: "ask", label: "Ask my organization", block: assessReady(plan, confirmed, true, true) };
}

/** assessRelaxOpen is whether a run still holds a guardrail in force or about
 *  to be bound (its state can change on its own). */
export function assessRelaxOpen(r: Pick<AssessRun, "relax" | "ended_at" | "phase">): boolean {
  if (r.phase === "cancelled" || r.ended_at) return false;
  return (r.relax ?? []).some((x) => x.state === "pending_bind" || x.state === "active" || x.state === "org_grant" || x.state === "tier");
}

/** The words of a guardrail's lifecycle state on a run. */
export const ASSESS_RELAX_STATE: Readonly<Record<string, { label: string; tone: Tone }>> = {
  pending_bind: { label: "waiting for the session", tone: "info" },
  active: { label: "in force", tone: "warn" },
  org_grant: { label: "under your organization's grant", tone: "warn" },
  not_bound: { label: "never took effect", tone: "neutral" },
  existing: { label: "your own approval covered it", tone: "neutral" },
  lost: { label: "no longer managed", tone: "neutral" },
  failed: { label: "could not be set", tone: "danger" },
  ended: { label: "ended", tone: "neutral" },
  tier: { label: "wider network for this run", tone: "warn" },
};

/** assessRelaxState is a relaxation state's label and tone; an unknown state reads as itself. */
export function assessRelaxState(state: string): { label: string; tone: Tone } {
  return ASSESS_RELAX_STATE[state] ?? { label: state.replace(/_/g, " ") || "unknown", tone: "neutral" };
}

const END_REASONS: Readonly<Record<string, string>> = {
  terminal_exit: "ended when the terminal closed",
  expired: "ended at its time limit",
  cancelled: "ended because the run was cancelled",
};

const RELAX_NOTES: Readonly<Record<string, string>> = {
  existing_row: "an approval of yours already covered this, so the run left it alone",
  create_failed: "the approval could not be created, so the guard kept asking",
  row_changed: "the approval was changed by someone else, so the run stopped managing it",
};

/** ASSESS_RULE_WORDS names each guard rule a run may lift by what it stops, not by its id: a person reads "Network and vulnerability scanner rule", and the id stays in the record (AssessRunRelax.key) for whoever needs it. */
export const ASSESS_RULE_WORDS: Readonly<Record<string, string>> = {
  "R-179": "Network and vulnerability scanner rule",
};

/** assessRuleWords is a lifted guard rule in words; a rule this table does not know reads as "A guard rule", never as its id. */
export function assessRuleWords(key: string): string {
  return ASSESS_RULE_WORDS[key] ?? "A guard rule";
}

/** assessRelaxLine is one guardrail of a run in one sentence: what it was,
 *  the state it is in, and how it ended or why it did not take effect. */
export function assessRelaxLine(x: AssessRunRelax): string {
  const name = x.type === "tier" ? "Wider sandbox network" : `${assessRuleWords(x.key)} lifted`;
  const state = assessRelaxState(x.state).label;
  const bits: string[] = [];
  if (x.type === "tier" && x.hosts && x.hosts.length > 0) bits.push(`hosts: ${x.hosts.join(", ")}`);
  if (x.grant_id) bits.push(`grant G-${x.grant_id}`);
  if (x.approval_id) bits.push(`approval #${x.approval_id}`);
  if (x.scope === "project") bits.push("whole project");
  if (x.end_reason && END_REASONS[x.end_reason]) bits.push(END_REASONS[x.end_reason]);
  if (x.note && RELAX_NOTES[x.note]) bits.push(RELAX_NOTES[x.note]);
  return `${name}: ${state}${bits.length > 0 ? ` (${bits.join("; ")})` : ""}`;
}

/** assessRelaxedLine says how many verdicts the run's guardrails changed, or
 *  "" when it was not counted. An org grant's count is by grant, so it is
 *  approximate and says so. */
export function assessRelaxedLine(r: { exact: number; approx: number } | null | undefined): string {
  if (!r) return "";
  const parts: string[] = [];
  if (r.exact > 0) parts.push(`${r.exact} ${r.exact === 1 ? "command" : "commands"} that the guard would have stopped ran under this run's approval`);
  if (r.approx > 0) parts.push(`about ${r.approx} under your organization's grant (counted by grant, so approximate)`);
  return parts.length > 0 ? `${parts.join("; ")}.` : "No command needed the lifted guardrail.";
}

const HELD_RULE_STATES: Readonly<Record<string, string>> = {
  waiting: "waiting for your organization",
  approved: "approved",
  narrower: "approved, but narrower than asked",
  declined: "declined",
  lapsed: "the request lapsed",
  queued: "queued: your organization could not be reached, so it will be sent on the next sync",
};

/** assessHeldRuleLine is one rule of a held run in one sentence. */
export function assessHeldRuleLine(r: AssessHeldRule): string {
  const base = `${r.rule}: ${HELD_RULE_STATES[r.state] ?? r.state}`;
  const bits: string[] = [];
  if (r.grant_id) bits.push(`grant G-${r.grant_id}`);
  if (r.request_id) bits.push(`request #${r.request_id}`);
  const tail = r.why ? ` (${r.why})` : "";
  return `${base}${bits.length > 0 ? ` [${bits.join(", ")}]` : ""}${tail}`;
}

/** assessRunState is a run's state words with the held answer folded in (a
 *  held run is waiting, or approved and ready to start) and, for a run that
 *  ended with nothing written, how it ended: the terminal closed, the time box,
 *  Stop. */
export function assessRunState(r: Pick<AssessRun, "state" | "phase" | "held" | "end_why">): { label: string; tone: Tone; next: string } {
  if (r.phase === "held" && r.held?.ready) {
    return { label: "approved: start", tone: "success", next: "Your organization approved. Start the run when you are ready." };
  }
  const words = assessState(r.state);
  if (r.state === "ended_empty") {
    const why = ASSESS_END_WHY[r.end_why ?? ""] ?? "it ended";
    return { ...words, next: `The agent wrote nothing into the run folder (${why}), so there is nothing to read or check. Open the run's terminal session to see why, then start the assessment again.` };
  }
  return words;
}
/** assessCardEmpty is the card's line while no run exists. */
export const ASSESS_EMPTY = "No assessments yet. Start one above; the agent works in a terminal you can watch.";

// --- Time box, Stop and the git check (depth plan W0) ----------------------
//
// The server records the time box on the run at launch and derives the rest
// (deadline, over its time box, whether Stop applies, the git check's verdict)
// from the run record. The functions below only choose the sentences. None of
// them says a run was verified, confirmed or clean: the git check is a
// comparison of git state before and after the run, and says what it cannot see.

/** The words of how a run ended, when it did. */
export const ASSESS_END_WHY: Readonly<Record<string, string>> = {
  terminal_gone: "ended when the terminal closed",
  time_box: "closed by Observer at the time box",
  stopped: "stopped from this page",
};

/** The words of what happens at the deadline. */
export const ASSESS_BOX_ACTION: Readonly<Record<string, string>> = {
  stop_button: "Nothing closes the terminal for you; use Stop when you are ready",
  auto_close: "Observer closes the terminal at the deadline",
};

/** assessBoxActionWords is the deadline action in a sentence (an unknown value reads as the stop button). */
export function assessBoxActionWords(action: string | undefined): string {
  return ASSESS_BOX_ACTION[action ?? ""] ?? ASSESS_BOX_ACTION.stop_button;
}

/** assessTimeBoxLine is a run row's time line: its box while it runs, "over its
 *  time box" past the deadline, and how it ended. "" for a run recorded before
 *  time boxes. */
export function assessTimeBoxLine(r: Pick<AssessRun, "time_box_minutes" | "time_box_action" | "over_time_box" | "ended_at" | "end_why" | "phase">): {
  text: string;
  tone: Tone;
} {
  const n = r.time_box_minutes ?? 0;
  if (n <= 0 || r.phase === "held" || r.phase === "cancelled") return { text: "", tone: "neutral" };
  const box = `${n}-minute time box`;
  if (r.ended_at) {
    const why = ASSESS_END_WHY[r.end_why ?? ""] ?? "ended";
    return r.over_time_box
      ? { text: `Over its ${box}; ${why}.`, tone: "warn" }
      : { text: `Within its ${box}; ${why}.`, tone: "neutral" };
  }
  if (r.over_time_box) {
    return { text: `Over its ${box}. ${assessBoxActionWords(r.time_box_action)}.`, tone: "warn" };
  }
  return { text: `${box}. ${assessBoxActionWords(r.time_box_action)}.`, tone: "neutral" };
}

/** assessAuditLine is the run row's git check line, or null when the run has
 *  nothing to say (recorded before the check existed, or not started). A
 *  verdict taken well after the terminal was seen gone says how long after:
 *  anything changed in that gap, by anyone, is counted. */
export function assessAuditLine(r: Pick<AssessRun, "audit" | "audit_words" | "audit_at" | "ended_at">): { text: string; tone: Tone } | null {
  const a = r.audit ?? "";
  if (a === "") return null;
  const words = r.audit_words || a.replace(/_/g, " ");
  let gap = "";
  if (r.audit_at && r.ended_at) {
    const mins = Math.round((Date.parse(r.audit_at) - Date.parse(r.ended_at)) / 60000);
    if (Number.isFinite(mins) && mins >= 2) gap = ` (taken ${mins} minutes after the terminal was seen gone)`;
  }
  // A change, and a comparison that could not cover every changed file, both
  // ask for a look; could_not_check (a snapshot failed) stays neutral as it was.
  return { text: `Git check: ${words}${gap}.`, tone: a === "changed" || a === "partly_checked" ? "warn" : "neutral" };
}

/** assessCanStop is whether the run row offers Stop. */
export function assessCanStop(r: Pick<AssessRun, "can_stop" | "phase">): boolean {
  return r.can_stop === true && r.phase !== "held" && r.phase !== "cancelled";
}

/** assessCanDeleteData is whether the run row offers Delete stored evidence:
 *  the run has some, and its terminal is not live (deleting the launch snapshot
 *  of a live run would leave its git check nothing to compare). */
export function assessCanDeleteData(r: Pick<AssessRun, "has_data" | "can_stop">): boolean {
  return r.has_data === true && r.can_stop !== true;
}

/** One sentence of the plan's "settings in force" list. `help` is the id of
 *  the help entry that explains it, when it has one. */
export type AssessLine = { text: string; tone: Tone; help?: string };

/** The words a rule carries when nothing but the task holds it: no helper and
 *  no check of Observer's own sits between the agent and the target. */
export const ASSESS_TASK_ONLY = "Held by the task only";

/** What holds the request limits when the request helper is written into the run folder: the task, and the helper for the requests that go through it. A request made another way is not counted or paced. */
export const ASSESS_HELPER_HOLDS =
  "Held by the task, and by the request helper for the requests that go through it. A request the agent makes another way, with curl or its own code, is not counted or paced.";

/** assessRequestLimitsLine is the request budget and pace in one sentence, or
 *  "" when neither is set (a kind that sends no requests). Today nothing between
 *  the agent and the target counts or paces them, and the sentence says so. */
function assessRequestLimitsLine(l: Pick<AssessLimits, "request_budget" | "pace_rps">, helperOn = false): string {
  const budget = l.request_budget ?? 0;
  const pace = l.pace_rps ?? 0;
  if (helperOn && (budget > 0 || pace > 0)) {
    const what = budget > 0 && pace > 0 ? `Request budget ${budget}, at most ${pace} a second` : budget > 0 ? `Request budget ${budget}` : `At most ${pace} ${pace === 1 ? "request" : "requests"} a second`;
    return `${what}. ${ASSESS_HELPER_HOLDS}`;
  }
  if (budget > 0 && pace > 0) {
    return `Request budget ${budget}, at most ${pace} a second. ${ASSESS_TASK_ONLY}: nothing between the agent and the target counts them.`;
  }
  if (budget > 0) return `Request budget ${budget}. ${ASSESS_TASK_ONLY}: nothing between the agent and the target counts them.`;
  if (pace > 0) return `At most ${pace} ${pace === 1 ? "request" : "requests"} a second. ${ASSESS_TASK_ONLY}: nothing between the agent and the target paces them.`;
  return "";
}

/** assessLimitsLines are the plan dialog's "settings in force" sentences. */
export function assessLimitsLines(l: AssessLimits | null | undefined, helperOn = false): AssessLine[] {
  if (!l) return [];
  const out: AssessLine[] = [
    { text: `Time box: ${l.time_box_minutes} minutes. ${assessBoxActionWords(l.time_box_action)}.`, tone: "neutral" },
  ];
  if (l.relaxation_note) out.push({ text: `Longer than the guardrail window: ${l.relaxation_note}.`, tone: "warn" });
  out.push(
    l.boundary_audit
      ? { text: `Git check: Observer compares the project's git state before and after the run. ${l.audit_limits}`, tone: "neutral" }
      : { text: "Git check: off. The run row will say the git state was not checked.", tone: "neutral" },
  );
  const requests = assessRequestLimitsLine(l, helperOn);
  if (requests) out.push({ text: requests, tone: "neutral" });
  return out;
}

/** settingLabel is a settings-card picker value in the card's own words, so the
 *  plan dialog and the Settings card never describe a choice two ways. */
function settingLabel(key: string, value: string | number | boolean): string {
  const row = CODE_SECURITY_SETTINGS.find((r) => r.key === key);
  return row?.optionLabels?.[String(value)] ?? String(value);
}

/** assessKiB is a size in bytes in the words the digest line uses. */
function assessKiB(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "0 bytes";
  return bytes < 1024 ? `${Math.round(bytes)} bytes` : `${(bytes / 1024).toFixed(1)} KiB`;
}

/** assessGroundingLine says what the task carries about the project: the digest
 *  of facts Observer read from the project's own files, how many sections it
 *  holds and its size, whether the open findings are left out, how many strings
 *  were left out and whether the project shows signs of being an AI application.
 *  "" when the plan has no grounding block. */
export function assessGroundingLine(g: AssessGrounding | null | undefined): string {
  if (!g) return "";
  if (g.mode === "off") return "No digest: the setting is off.";
  const sections = g.sections?.length ?? 0;
  const lead =
    g.mode === "without_findings"
      ? "The task carries a digest of facts from the project, without the open findings"
      : "The task carries a digest of facts from the project";
  const size =
    sections === 0
      ? "nothing could be read from the project's files"
      : `${sections} ${sections === 1 ? "section" : "sections"}, ${assessKiB(g.bytes)}`;
  const parts = [`${lead}: ${size}.`];
  if (g.dropped > 0) {
    parts.push(`${g.dropped} ${g.dropped === 1 ? "string was" : "strings were"} left out (characters the task does not accept, or the size cap).`);
  }
  if (g.ai_app) parts.push("Observer found signs that it is an AI application.");
  return parts.join(" ");
}

/** The environment-files choices in short words. The Settings card's own label
 *  for Hide says it acts as Warn where the run's sandbox cannot hide files,
 *  which is not true of a run whose sandbox can, so the one place that can
 *  describe a mode that is really in force uses these. */
export const ASSESS_SECRET_MODE_SHORT: Readonly<Record<string, string>> = {
  mask: "Hide in the sandbox",
  warn: "Warn",
  refuse: "Refuse",
  off: "Off",
};

function secretModeShort(mode: string): string {
  return ASSESS_SECRET_MODE_SHORT[mode] ?? mode;
}

/** Why a chosen mask acts as a warning, per closed reason (decision D32). Held to the Go table
 *  (internal/secassess secretmode.go) by a test. A reason this build does not know reads as the
 *  general one. */
export const ASSESS_MASK_DOWNGRADE: Readonly<Record<string, string>> = {
  no_backend: "no sandbox is chosen for this run yet",
  backend_cannot_mask: "the sandbox this run will use cannot hide files",
  launcher_cannot_report: "this daemon's launcher cannot report what the mask hid, and a mask nobody can check is not asked for",
};

function maskDowngradeWords(why: string | undefined): string {
  return ASSESS_MASK_DOWNGRADE[why ?? ""] ?? ASSESS_MASK_DOWNGRADE.backend_cannot_mask;
}

/** assessSecretModeLine says what happens to the environment files of a pen
 *  test: the choice, or, when the sandbox cannot do what was chosen (or an
 *  organization's setting differs), the choice and what applies instead. null
 *  when the plan names neither. */
export function assessSecretModeLine(configured: string | undefined, effective: string | undefined, downgrade?: string): AssessLine | null {
  const chosen = configured ?? effective;
  const inForce = effective ?? configured;
  if (!chosen || !inForce) return null;
  if (chosen !== inForce) {
    if (chosen === "mask" && inForce === "warn") {
      return {
        text: `Environment files: ${secretModeShort(chosen)} is chosen, but ${maskDowngradeWords(downgrade)}, so it acts as a warning.`,
        tone: "warn",
      };
    }
    return {
      text: `Environment files: ${secretModeShort(chosen)} is chosen, but ${secretModeShort(inForce)} is what applies to this run.`,
      tone: "warn",
    };
  }
  const words = inForce === "mask" ? secretModeShort(inForce) : settingLabel("security.assessments.workspace_secret_mode", inForce);
  return { text: `Environment files: ${words}.`, tone: "neutral" };
}

/** assessModelLines are the model contract's lines of the plan's "settings in
 *  force": what the task asks the agent for, what it carries about the project,
 *  what happens to environment files, and what the import will do. [] for a
 *  kind without a model contract. The plan's grounding block, when it has one,
 *  is the project-facts line (the digest's own size); otherwise the setting. */
export function assessModelLines(m: AssessModelSettings | null | undefined, grounding?: AssessGrounding | null): AssessLine[] {
  if (!m) return [];
  const out: AssessLine[] = [
    {
      text: `Result: the agent writes a structured assessment.json (task version ${m.prompt_version}) and a report. Observer checks the structure and file references, and derives the importable findings from it; the agent writes no findings file.`,
      tone: "neutral",
    },
  ];
  if (m.frameworks) out.push({ text: `Frameworks asked for: ${settingLabel("security.assessments.tm_frameworks", m.frameworks)}.`, tone: "neutral" });
  if (m.method_extras) out.push({ text: `Abuse cases and attack trees: ${m.method_extras === "both" ? "both are asked for" : settingLabel("security.assessments.tm_method_extras", m.method_extras)}.`, tone: "neutral" });
  if (m.categories) out.push({ text: `Test categories: ${settingLabel("security.assessments.pt_categories", m.categories)}.`, tone: "neutral" });
  if (grounding) {
    out.push({ text: assessGroundingLine(grounding), tone: "neutral", help: "card.code_security_assess_grounding" });
  } else if (m.grounding) {
    out.push({
      text: `Project facts in the task: ${settingLabel("security.assessments.grounding", m.grounding)}.`,
      tone: "neutral",
      help: "card.code_security_assess_grounding",
    });
  }
  const env = assessSecretModeLine(m.secret_mode, m.secret_mode_effective, m.secret_mode_downgrade);
  if (env) out.push(env);
  out.push({
    text: m.self_check
      ? "The agent is told to check its own file with Observer before it finishes."
      : "The agent is not asked to check its own file before it finishes.",
    tone: "neutral",
  });
  const band = m.import_min_band === "low" ? "every finding with a location in the code" : `findings at ${m.import_min_band} risk and above`;
  // "No cap" is the developer's own setting; the importer still keeps at most
  // 1,000 results per run, so the words never read as unlimited.
  const cap = m.findings_cap > 0 ? `at most ${m.findings_cap}, highest risk first` : "no cap (the importer keeps at most 1,000 results per run)";
  const rerun = m.rerun_dedup ? "a re-run updates the findings you already imported" : "each run's findings stay apart";
  out.push({ text: `On import: ${band}, ${cap}; ${rerun}.`, tone: "neutral" });
  return out;
}

/** assessSettingsLines is the whole "settings in force" list of a plan: the
 *  limits, then the model contract's lines with the project facts. The request
 *  limits come from the plan's limits, or from its model block when only that
 *  carries them. */
export function assessSettingsLines(plan: Pick<AssessPlan, "limits" | "model" | "grounding" | "probe"> | null | undefined): AssessLine[] {
  if (!plan) return [];
  const limits = plan.limits
    ? {
        ...plan.limits,
        request_budget: plan.limits.request_budget ?? plan.model?.request_budget,
        pace_rps: plan.limits.pace_rps ?? plan.model?.pace_rps,
      }
    : undefined;
  return [...assessLimitsLines(limits, plan.probe?.state === "on"), ...assessModelLines(plan.model, plan.grounding)];
}

// --- The plan's choices and facts (depth plan W3.3, W3.4, W4.1 to W4.6) -----
//
// Each helper below is one sentence or one row of the plan dialog. They carry
// what the server read from the project's own files and say what Observer does
// not know. None of them says the project is secure, clean or checked, and none
// says the agent's reasoning was looked at.

/** assessScopeChoiceLine says what the scope means for the task: with no places
 *  chosen the whole project; with some, a request to the agent, which is not
 *  stopped from reading anything. "" without a scope block. */
export function assessScopeChoiceLine(scope: Pick<AssessScope, "paths"> | null | undefined): string {
  if (!scope) return "";
  if (scope.paths.length === 0) return "By default the whole project is covered.";
  return `The task asks the agent to model only ${scope.paths.join(", ")}. It may read the rest for what calls it or what it calls, and it is told to list everything else as out of scope. That is a request in the task: the agent is not stopped from reading anything.`;
}

/** assessScopeToggle ticks or unticks a place in the chosen list. A place
 *  already chosen is not added twice, and a list already at its cap refuses
 *  another with a sentence (the server refuses too; this says so first). */
export function assessScopeToggle(current: readonly string[], place: string, on: boolean, max: number): { paths: string[]; error?: string } {
  const p = place.trim();
  if (!p) return { paths: [...current] };
  if (!on) return { paths: current.filter((x) => x !== p) };
  if (current.includes(p)) return { paths: [...current] };
  if (max > 0 && current.length >= max) return { paths: [...current], error: `At most ${max} places. Remove one first.` };
  return { paths: [...current, p] };
}

/** assessUnapplied is why the plan's button waits when the developer has typed
 *  something that is not in the task yet: a place not yet added to the scope, or
 *  a start command not yet used. null when everything typed has been applied. */
export function assessUnapplied(scopeTyped: string, startDirty: boolean): string | null {
  if (scopeTyped.trim() !== "") return "Add the place you typed to the scope, or clear it first";
  if (startDirty) return "Use the start command you typed, or clear it first";
  return null;
}

/** assessConsentKey is what the plan's consent tick is for: one target in one
 *  project. It is deliberately not tied to the plan read (every read mints a new
 *  run id): the consent holds while the plan is read again for a choice that
 *  does not change the target, and a new target or project clears it. */
export function assessConsentKey(projectHash: string | undefined, target: string): string {
  return `${projectHash ?? ""}|${target}`;
}

/** The line beside a button that cannot be pressed when the plan's own refusal is already on screen in its note (the note names it in full). */
export const ASSESS_REFUSED_ABOVE = "Nothing can start here. The reason is in the note above.";

/** assessWaitingLine is the reason printed beside the disabled button. A plan the server refused says its reason in the note "This cannot start here" in the body of the dialog, and the footer would print the same sentence again (four lines for the helper refusal), so the footer points at the note and says the reason once. Any other reason (the target not chosen, the consent not ticked) is short and stands alone. null when nothing blocks. */
export function assessWaitingLine(block: string | null, plan: Pick<AssessPlan, "ok" | "reason" | "kind" | "project">): string | null {
  if (block === null) return null;
  const noteShown = !plan.ok && !!plan.reason && plan.kind.launchable && plan.project.on_disk;
  return noteShown && block === plan.reason ? ASSESS_REFUSED_ABOVE : block;
}

/** The note over a retest plan that was refused for particular findings: they are named, each with its reason, in the list of what the retest replays, so the note does not name the first of them again. */
export const ASSESS_RETEST_FINDINGS_NOTE =
  "The findings listed under What the retest replays cannot be replayed. Leave them out, then open the retest plan again. Nothing was started.";

/** assessPlanNotice is what the plan's note "This cannot start here" says: the server's sentence, except for a retest refused for named findings, whose list already says which and why (N-10). null when the plan is not refused. */
export function assessPlanNotice(plan: Pick<AssessPlan, "ok" | "reason" | "code" | "retest">): string | null {
  if (plan.ok || !plan.reason) return null;
  if (plan.code === "retest_findings" && (plan.retest?.refused ?? []).length > 0) return ASSESS_RETEST_FINDINGS_NOTE;
  return plan.reason;
}

/** assessPreviousOptionLabel is one earlier run in the comparison picker. */
export function assessPreviousOptionLabel(o: AssessPreviousOption, fmtDate?: (iso: string) => string): string {
  const scope = o.scope && o.scope.length > 0 ? `, scope ${o.scope.join(", ")}` : "";
  return `${assessRunLabel(ASSESS_COMPARED_KIND, o.created_at, fmtDate)}${scope}`;
}

/** The sentence under the comparison picker when the server gave none: what
 *  the earlier run's files mean for the agent. It claims no more than is true.
 *  Observer puts nothing from the earlier run in the task, and the task asks the
 *  agent not to open other runs' folders; that is a request, not a barrier,
 *  because an earlier run's files stay in the project's .observer/assessments
 *  folder where the agent can read them. */
export const ASSESS_PREVIOUS_NOTE =
  "Observer gives the agent nothing from the earlier run and asks it not to open other runs' folders. That is a request, not a barrier.";

/** assessPreviousNote is the sentence shown under the comparison picker: the
 *  server's, or ASSESS_PREVIOUS_NOTE when it sent none. */
export function assessPreviousNote(previous: Pick<AssessPrevious, "note"> | null | undefined): string {
  if (!previous) return "";
  const n = (previous.note ?? "").trim();
  return n === "" ? ASSESS_PREVIOUS_NOTE : n;
}

/** assessPreviousLine says which earlier run the new model is compared with,
 *  or that none is. The comparison is Observer's, made once the new model is
 *  checked; Observer puts nothing from the earlier run in the task. */
export function assessPreviousLine(previous: AssessPrevious | null | undefined, fmtDate?: (iso: string) => string): string {
  if (!previous) return "";
  if (previous.options.length === 0 && !previous.selected) {
    return "No earlier checked threat model of this project exists, so there is nothing to compare with.";
  }
  if (!previous.selected) return "No comparison: nothing is compared once the new model is checked.";
  const o = previous.options.find((x) => x.id === previous.selected);
  // A run the list no longer holds has no checked copy to compare with: say so
  // rather than promise a comparison.
  if (!o) return "The earlier run chosen is no longer among the earlier checked runs, so there may be nothing to compare with.";
  return `Compared with ${assessEarlierWords(assessRunLabel(ASSESS_COMPARED_KIND, o.created_at, fmtDate))} once the new model is checked.`;
}

/** assessStartChoice is the string that picks a start plan: its own `choice`,
 *  or its command when the server gave no choice (a plan in the project's own
 *  folder, or an older server). */
export function assessStartChoice(p: Pick<AssessStartPlan, "command" | "choice">): string {
  return p.choice ? p.choice : p.command;
}

/** assessStartInForce is the start choice in force: the server's pick until the
 *  developer chose, then what they chose (ASSESS_NONE is no declared command, ""). */
export function assessStartInForce(start: Pick<AssessStart, "selected_command">, chosen: string | undefined): string {
  if (chosen === undefined) return start.selected_command;
  return chosen === ASSESS_NONE ? "" : chosen;
}

/** assessStartSelectedPlan is the offered plan the start choice in force picks,
 *  or undefined for no command or one the developer typed. */
export function assessStartSelectedPlan(start: Pick<AssessStart, "plans" | "selected_command">, chosen: string | undefined): AssessStartPlan | undefined {
  const inForce = assessStartInForce(start, chosen);
  if (inForce === "") return undefined;
  return start.plans.find((p) => assessStartChoice(p) === inForce);
}

/** assessStartText is what the start field holds when nothing is being typed:
 *  the command of the plan in force (a plan's choice may carry its folder, which
 *  is not a command), or the text the developer typed. */
export function assessStartText(start: Pick<AssessStart, "plans" | "selected_command">, chosen: string | undefined): string {
  const p = assessStartSelectedPlan(start, chosen);
  return p ? p.command : assessStartInForce(start, chosen);
}

/** assessDirWords is a folder as the dialog says it: "web/" for web. */
function assessDirWords(dir: string): string {
  const d = dir.trim();
  return d.endsWith("/") ? d : `${d}/`;
}

/** assessPrepareSteps are the selected plan's preparation steps, [] when the
 *  plan in force has none (or is typed, or none). */
export function assessPrepareSteps(start: Pick<AssessStart, "plans" | "selected_command">, chosen: string | undefined): string[] {
  return assessStartSelectedPlan(start, chosen)?.prepare?.filter((s) => s.trim() !== "") ?? [];
}

/** assessPrepareOn is whether the preparation steps are ticked: the
 *  developer's tick when they made one, else what the server echoes (a held run
 *  keeps its own); false by default. It is only ever true for a plan that has
 *  steps. */
export function assessPrepareOn(start: Pick<AssessStart, "plans" | "selected_command" | "prepare">, chosen: string | undefined, ticked: boolean | undefined): boolean {
  if (assessPrepareSteps(start, chosen).length === 0) return false;
  return ticked ?? start.prepare === true;
}

/** The words of the opt-in to a start plan's preparation steps: a checkbox
 *  that is off until the developer ticks it, and one plain sentence on why. */
export const ASSESS_PREPARE_LABEL = "Run the preparation steps first";
export const ASSESS_PREPARE_WARNING = "Preparation steps can change local data in the project, for example its database file.";

/** assessStartLine says how the agent is told to start the application: with
 *  the command in force (and the folder it runs in, and whether its preparation
 *  steps run first), or to find one itself. "" without a start block. */
export function assessStartLine(start: AssessStart | null | undefined): string {
  if (!start) return "";
  if (start.selected_command) {
    const p = assessStartSelectedPlan(start, undefined);
    const cmd = p ? p.command : start.selected_command;
    const notes = [p?.cwd ? `in ${assessDirWords(p.cwd)}` : "", start.edited ? "typed by you" : ""].filter(Boolean);
    const prep = start.prepare === true && (p?.prepare?.length ?? 0) > 0 ? " It is told to run the preparation steps first." : "";
    return `The agent is told to start the application with: ${cmd}${notes.length > 0 ? ` (${notes.join(", ")})` : ""}.${prep}`;
  }
  if (start.not_preselected) {
    return "The project names start commands, but none is a well-known program, so none was chosen for you. Pick one, type one, or leave it and the agent is told to find one itself.";
  }
  return start.none_found
    ? "No start command was found, so the agent is told to find one itself."
    : "No start command is declared, so the agent is told to find one itself.";
}

/** ASSESS_START_NOTE_ID is the preflight note that says no start command was found. The "How the
 *  application starts" section says it, so the "Before it starts" list leaves it out while that
 *  section is on the page: a fact is stated once (UX-11). */
export const ASSESS_START_NOTE_ID = "no_start_command";

/** ASSESS_START_NONE_WORDS is the one sentence for a project with no readable start command, used
 *  when the server's own sentence (assessStartNote) did not come with the plan. It carries the cause,
 *  what happens and what to do, so nothing else says it. */
export const ASSESS_START_NONE_WORDS = "No start command could be read from the project's files; the agent will look for one or you can type it.";

/** assessStartNote is the server's sentence for "no start command" from the plan's preflight notes,
 *  or "" when there is none. The start section shows it in place of the note's row. */
export function assessStartNote(preflight: readonly AssessPreflightNote[] | null | undefined): string {
  return (preflight ?? []).find((n) => n.id === ASSESS_START_NOTE_ID)?.text.trim() ?? "";
}

/** assessPreflightApart is the preflight notes the "Before it starts" list shows: all of them, less
 *  the one the start section says in its own words when that section is on the page. */
export function assessPreflightApart(
  preflight: readonly AssessPreflightNote[] | null | undefined,
  start: AssessStart | null | undefined,
): AssessPreflightNote[] | undefined {
  if (!preflight) return undefined;
  return start ? preflight.filter((n) => n.id !== ASSESS_START_NOTE_ID) : [...preflight];
}

/** assessStartNoneWords is the sentence for a project with no readable start command and none typed
 *  or chosen, "" otherwise (a command in force is said by assessStartLine instead). It is the only
 *  statement of that fact on the page: the start line is not shown beside it. */
export function assessStartNoneWords(start: AssessStart | null | undefined, note?: string): string {
  if (!start || !start.none_found || start.plans.length > 0 || start.selected_command) return "";
  const n = (note ?? "").trim();
  return n === "" ? ASSESS_START_NONE_WORDS : n;
}

/** assessTypeLabel is the label of a field that offers a way to type something beside a list of
 *  choices: "Or type ..." when there are choices above it, "Type ..." when there are none, so the
 *  word "Or" never leads nothing. */
export function assessTypeLabel(what: string, offered: boolean): string {
  return `${offered ? "Or type" : "Type"} ${what}`;
}

/** assessStartPlanDetails are the small lines under one offered start command:
 *  the folder it runs in when that is not the project's own, its port, where it
 *  was read from, its preparation steps and the services it names. The selected
 *  plan's preparation steps are shown by the opt-in under it instead, so they
 *  are not listed twice. */
export function assessStartPlanDetails(p: AssessStartPlan, selected = false): string[] {
  const out: string[] = [];
  if (p.cwd && p.cwd.trim() !== "") out.push(`In the folder ${assessDirWords(p.cwd)}`);
  if (p.port && p.port > 0) out.push(`Port ${p.port}`);
  if (p.source) out.push(`Read from ${p.source}`);
  if (!selected && p.prepare && p.prepare.length > 0) out.push(`Preparation steps, not run unless you choose to: ${p.prepare.join("; ")}`);
  if (p.needs && p.needs.length > 0) out.push(`Needs: ${p.needs.join(", ")}. The sandbox has no container engine.`);
  return out;
}

/** The preflight levels in the order they show, with their words and tones. */
const ASSESS_PREFLIGHT_LEVELS: readonly { level: string; label: string; tone: Tone }[] = [
  { level: "likely_fails", label: "Likely to fail", tone: "danger" },
  { level: "warn", label: "Worth knowing", tone: "warn" },
  { level: "info", label: "Note", tone: "neutral" },
];

/** One row of "Before it starts". */
export type AssessPreflightRow = { id: string; level: string; label: string; tone: Tone; text: string };

/** assessPreflightRows are the plan's preflight notes in the order the dialog
 *  shows them: the ones likely to fail first, then the ones worth knowing, then
 *  the plain notes, each level in the order the server gave. A level Observer
 *  has no words for reads as a plain note, last. They are advice: none of them
 *  stops a launch. */
export function assessPreflightRows(notes: readonly AssessPreflightNote[] | null | undefined): AssessPreflightRow[] {
  const rank = (level: string) => {
    const i = ASSESS_PREFLIGHT_LEVELS.findIndex((l) => l.level === level);
    return i < 0 ? ASSESS_PREFLIGHT_LEVELS.length : i;
  };
  return (notes ?? [])
    .map((n, i) => ({ n, i }))
    .sort((a, b) => rank(a.n.level) - rank(b.n.level) || a.i - b.i)
    .map(({ n }) => {
      const def = ASSESS_PREFLIGHT_LEVELS.find((l) => l.level === n.level) ?? ASSESS_PREFLIGHT_LEVELS[ASSESS_PREFLIGHT_LEVELS.length - 1];
      return { id: n.id, level: n.level, label: def.label, tone: def.tone, text: n.text };
    });
}

/** assessToolLine is one tool of the sandbox in a sentence: what it is for,
 *  whether Observer found it in the sandbox's standard folders (it looks from
 *  outside, so it can say it could not tell), what the agent does without it,
 *  and that a scanner may need the developer's answer. */
export function assessToolLine(t: AssessToolRow): string {
  const dot = (s: string) => {
    const x = s.trim();
    return x === "" ? "" : /[.!?]$/.test(x) ? x : `${x}.`;
  };
  const parts: string[] = [];
  const purpose = dot(t.purpose);
  if (purpose) parts.push(purpose);
  if (t.present === true) parts.push("Found in the sandbox's standard folders.");
  else if (t.present === false) {
    parts.push("Not found in the sandbox's standard folders.");
    const fb = dot(t.fallback);
    if (fb) parts.push(fb);
  } else {
    parts.push("Observer could not tell whether it is there; the agent checks for itself.");
  }
  if (t.guarded) parts.push("It may need your answer: Observer's guard can ask before it runs.");
  return parts.join(" ");
}

/** assessEnvLine is the sentence about environment files in the folder, as the
 *  server gave it, or "". */
export function assessEnvLine(env: AssessEnv | null | undefined): string {
  return (env?.line ?? "").trim();
}

/** The sentence that goes with the environment-files line: only the top level
 *  of the folder is counted. An environment file in a subfolder is not, so a
 *  count of none is not a claim about the whole project. A secret a scanner has
 *  found in one still reaches Observer's findings. */
export const ASSESS_ENV_TOP_LEVEL =
  "Only environment files at the top level of this folder are counted. Those in subfolders are not; if a scanner has found a secret in one, Observer's findings still know about it.";

/** assessEnvFilesLine names the environment files (names only, never
 *  contents), the first six and how many more there are. "" when there are
 *  none. */
export function assessEnvFilesLine(env: AssessEnv | null | undefined): string {
  const files = env?.files ?? [];
  if (files.length === 0) return "";
  const shown = files.slice(0, 6);
  const more = Math.max(files.length, env?.count ?? 0) - shown.length;
  return `Named: ${shown.join(", ")}${more > 0 ? `, and ${more} more` : ""}.`;
}

/** How a rule is held, in the order of what the words promise. task_only: the
 *  task is all there is. prevents: Observer holds it outside the task. detects:
 *  Observer looks afterwards and prevents nothing. stops: the limit is advice,
 *  and the developer can stop the run. noted: Observer or the request helper
 *  says something about it and Observer has no more specific word for what. */
export type AssessHeldKind = "task_only" | "prevents" | "detects" | "stops" | "noted";

/** The words of each way of being held. Only a check that prevents reads as
 *  held outside the task. */
export const ASSESS_HELD_WORDS: Readonly<Record<AssessHeldKind, string>> = {
  task_only: ASSESS_TASK_ONLY,
  prevents: "Held outside the task",
  detects: "Checked afterwards, not prevented",
  stops: "You can stop the run; the limit is advisory",
  noted: "Noted outside the task, not a guarantee",
};

/** One row of "What holds each rule". */
export type AssessSafetyDisplayRow = {
  id: string;
  rule: string;
  /** The words of the pill (ASSESS_HELD_WORDS of `kind`). */
  held: string;
  kind: AssessHeldKind;
  /** The pill's tone: only a check that prevents is more than neutral. */
  tone: Tone;
  promptOnly: boolean;
  /** Where else the rule is held, or what Observer notes about it, when it says anything. */
  where: string[];
};

/** assessSafetyRows says, for each rule, how it is held: by the task alone, or
 *  with a check of Observer's own that prevents it, looks at it afterwards, only
 *  lets the developer stop the run, or (a kind Observer has no words for, or a
 *  request helper) is merely noted. The words come from the row's
 *  `observer_kind`, never from the fact that the observer cell has text. A "-"
 *  in a cell means nothing there, and an observer check with no text to show
 *  cannot be claimed. */
export function assessSafetyRows(rows: readonly AssessSafetyRow[] | null | undefined): AssessSafetyDisplayRow[] {
  const cell = (s: string | undefined) => {
    const t = (s ?? "").trim();
    return t === "" || t === "-" ? "" : t;
  };
  return (rows ?? []).map((r) => {
    const where: string[] = [];
    const helper = cell(r.helper);
    const observer = cell(r.observer);
    const reported = (r.observer_kind ?? "").trim();
    // A kind is believed only with an observer cell that explains it.
    const known = observer && (reported === "prevents" || reported === "detects" || reported === "stops") ? reported : "";
    let kind: AssessHeldKind;
    if (r.prompt_only) kind = "task_only";
    else if (known) kind = known;
    else if (observer || helper) kind = "noted";
    else kind = "task_only";
    if (helper) where.push(`Request helper: ${helper}`);
    if (observer) where.push(kind === "noted" ? `Observer notes: ${observer}` : `Observer: ${observer}`);
    return {
      id: r.id,
      rule: r.rule,
      held: ASSESS_HELD_WORDS[kind],
      kind,
      tone: kind === "prevents" ? "info" : "neutral",
      promptOnly: r.prompt_only,
      where,
    };
  });
}

// --- The request helper (depth plan W5b) -------------------------------------

/** What the plan says about the request helper when it is written: where it goes, what it does and that its log is a file the agent can write. */
export const ASSESS_HELPER_ON =
  "Observer writes these two files into the run folder before the agent starts; the helper sends requests to the target address only, applies the pace and the request budget, and logs each request to probes.jsonl. The log is a file the agent can write.";

/** What the plan says when the setting is off. */
export const ASSESS_HELPER_OFF = "The request helper is off (a setting): nothing is written, and every finding's evidence reads No log.";

/** What follows the reason when the helper is left out. */
export const ASSESS_HELPER_WITHHELD_TAIL = "Every finding's evidence reads No log.";

/** What the plan says when the helper is on: a request made another way is not in the log, so the finding it backs reads No log. */
export const ASSESS_HELPER_OTHER_WAY =
  "A request the agent makes another way, with curl or its own code, is not logged, and a finding that rests on it reads No log.";

/** The files the helper is, when the plan names none. */
const ASSESS_HELPER_FILES: readonly string[] = ["probe.py", "probe.json"];

/** ASSESS_SETTINGS_WHERE is where the assessment settings are on the screen: the Settings page, its Guard section and the Code security card in it. A sentence that sends a reader to a setting names this and the row's label, never a config key. */
export const ASSESS_SETTINGS_WHERE = "Settings > Guard > Code security";

/** The settings-card row that switches the helper, so the plan names it by its label and a refusal links to it. */
export const ASSESS_HELPER_SETTING = "security.assessments.probe_helper";

/** AssessHelperView is the plan's request helper block as the dialog draws it. */
export type AssessHelperView = {
  state: "on" | "off" | "withheld";
  /** The sentence that says what the block means for this run. */
  lead: string;
  /** The files written into the run folder (none unless the helper is on). */
  files: string[];
  /** The run folder, "" when nothing is written. */
  dir: string;
  /** The request budget and pace, then any note, each a sentence. */
  facts: string[];
};

/** assessHelperView words the plan's request helper block: what is written and where, the budget and pace, and what a finding reads when nothing is. A state this view does not know reads as withheld (nothing is written, every finding reads No log), never as on. */
export function assessHelperView(p: AssessProbePlan | null | undefined): AssessHelperView | null {
  if (!p) return null;
  const dot = (t: string) => {
    const x = t.trim();
    return x === "" ? "" : /[.!?]$/.test(x) ? x : `${x}.`;
  };
  if (p.state === "on") {
    const files = (p.files ?? []).filter((f) => typeof f === "string" && f !== "");
    const budget = p.budget > 0 ? `Request budget: ${p.budget} ${p.budget === 1 ? "request" : "requests"}.` : "";
    const pace = p.pace_rps > 0 ? `Pace: at most ${p.pace_rps} ${p.pace_rps === 1 ? "request" : "requests"} a second.` : "";
    return {
      state: "on",
      lead: ASSESS_HELPER_ON,
      files: files.length > 0 ? files : [...ASSESS_HELPER_FILES],
      dir: p.dir ?? "",
      facts: [budget, pace, ASSESS_HELPER_OTHER_WAY].filter((x) => x !== ""),
    };
  }
  if (p.state === "off") {
    const label = CODE_SECURITY_SETTINGS.find((r) => r.key === ASSESS_HELPER_SETTING)?.label;
    return {
      state: "off",
      lead: ASSESS_HELPER_OFF,
      files: [],
      dir: "",
      facts: label ? [`The setting is "${label}" (${ASSESS_SETTINGS_WHERE}).`] : [],
    };
  }
  const reason = dot(p.withheld_reason ?? "") || "The request helper is left out of this run.";
  return { state: "withheld", lead: `${reason} ${ASSESS_HELPER_WITHHELD_TAIL}`, files: [], dir: "", facts: [] };
}

/** assessNoteDraft is the scope note field's state: the text being typed and
 *  the note (the dialog's) it was last in step with. */
export type AssessNoteDraft = { text: string; seen: string };

/** assessNoteDraftFor is the note field's state for the note the dialog holds
 *  now. While that note is the one the field was last in step with, what is
 *  typed stays; when the dialog's note changes (another project, a plan read
 *  again, a note cleaned or cleared by the server), the field follows it, so it
 *  never shows a note the choices no longer hold. The same state is returned
 *  when nothing changed, so a caller can tell. */
export function assessNoteDraftFor(prev: AssessNoteDraft, note: string): AssessNoteDraft {
  return prev.seen === note ? prev : { text: note, seen: note };
}

// --- The run record (secassess-runs.json) -----------------------------------
//
// The record of runs lives in one file in Observer's data folder. When it
// cannot be read the list is empty because of that, not because nothing was
// run, and every route that records a run answers 409 with run_record_unreadable
// (run_record_full and run_record_busy are its two milder siblings). The way
// out is to rename the file; Observer does not do that for the developer (the
// route that would is owner-local and this module adds no guard rule), so the
// words below only say how, and what it costs.

/** The run record's file name, in Observer's data folder. */
export const ASSESS_RUN_RECORD_FILE = "secassess-runs.json";

/** assessRunsUnreadableWords is what the runs list says when its record cannot
 *  be read: one line for the callout, the record's path when the server gave
 *  it, the steps that free it, and what taking them costs. */
export function assessRunsUnreadableWords(file?: string): { line: string; where: string; steps: string[]; cost: string; effect: string } {
  const name = (file ?? "").split(/[\\/]/).pop() || ASSESS_RUN_RECORD_FILE;
  return {
    line: `The run record (${name}) cannot be read, so runs may be missing from this list. Nothing was deleted.`,
    where: file ? `The record is ${file}.` : `The record is ${ASSESS_RUN_RECORD_FILE}, in Observer's data folder.`,
    effect:
      "While it cannot be read no run can be started, stopped, checked or imported: a run that could not be recorded would have no time limit, no Stop and no closing check. The file is left as it is, and Observer does not move it for you.",
    steps: [
      "Close any other Observer that has this file open.",
      `In Observer's data folder, rename ${ASSESS_RUN_RECORD_FILE} to ${ASSESS_RUN_RECORD_FILE}.bad.`,
      "Reopen this page.",
    ],
    cost:
      "The run list and each listed run's stored evidence (its checked model and git snapshots) will be gone. The project files and the reports under .observer/assessments in each project are untouched.",
  };
}

// --- What a refused request says --------------------------------------------
//
// The assess routes answer a refusal with JSON {error, code, ...}: the machine
// code is closed, and ASSESS_REFUSALS gives every one of them words, so no
// button falls back to "this could not be done" or to the raw JSON. The server
// sends its own sentence too; where that sentence names the cause (which tool,
// which rule, which port) it is the one shown. A test reads the codes out of
// the Go sources and fails when one has no row here.

/** One refusal code in words. */
export type AssessRefusal = {
  words: string;
  /** The server's own sentence names the cause (the tool, the rule, the port), so it is shown instead when present. */
  own?: boolean;
};

const RUN_RECORD_RECOVERY = `To recover, close any other Observer that has it open, rename ${ASSESS_RUN_RECORD_FILE} to ${ASSESS_RUN_RECORD_FILE}.bad in Observer's data folder, then try again. The run list and each listed run's stored evidence will be gone; the project files and the reports under .observer/assessments are untouched.`;

/** The label of the request helper's switch in Settings, which the refusals name (read from the settings table, never copied). */
const HELPER_SWITCH = CODE_SECURITY_SETTINGS.find((r) => r.key === ASSESS_HELPER_SETTING)?.label ?? "Request helper for penetration tests";

/** Every machine code an assess route answers a refusal with, in words. */
export const ASSESS_REFUSALS: Readonly<Record<string, AssessRefusal>> = {
  // The run record cannot be used.
  run_record_unreadable: {
    words: `The run record cannot be read, so no assessment run is started or changed: a run that could not be recorded would have no time limit, no Stop and no closing check. Nothing in the file was changed. ${RUN_RECORD_RECOVERY}`,
  },
  run_record_full: {
    words: "The run record is full of runs that are still in use, so a new run could not be recorded. Stop a running assessment, or wait for it to end, and try again.",
  },
  run_record_busy: { words: "Another Observer process is writing the run record. Try again in a moment." },
  // A launch, a request or a plan that no longer matches.
  plan_changed: {
    words:
      "The task changed after you read it, because a setting or the project changed. Nothing was started. Close this window and open the assessment again to read the new task, then start it.",
  },
  held_run_mismatch: { words: "This launch is not the run that was held for your organization's approval. Nothing was started. Read the plan again.", own: true },
  // The choices made on the plan (depth plan W3.3, W4.1, W4.4). The server's
  // sentence names the place, the command or the file, so it is shown instead.
  scope_invalid: {
    words:
      "A place in the scope is not a path inside the project, or is written in a way that is not accepted. Nothing was started. Fix or remove it, then read the plan again.",
    own: true,
  },
  start_invalid: {
    words:
      "The start command cannot be used. It is at most 8 words of letters, digits and a few plain marks, with no quotes, pipes or variables. Nothing was started. Edit it, or leave it empty and the agent will look for one.",
    own: true,
  },
  secret_files_open: {
    words:
      "The setting for environment files is Refuse, and Observer's findings hold an open secret in one of this project's environment or key files. Nothing was started. Deal with that finding, or change the setting.",
    own: true,
  },
  findings_unreadable: {
    words:
      "The setting for environment files is Refuse, and Observer could not read its findings for this project, so it cannot tell whether a secret is open in an environment or key file. Nothing was started. Try again, or change the setting.",
    own: true,
  },
  // The request helper (depth plan W5b): the task says its two files are in the run folder, so a launch that cannot write them does not start.
  helper_exists: {
    words:
      "The run folder already holds a different probe.py or probe.json from an earlier attempt, so the run did not start and nothing there was changed. Look in .observer/assessments, or turn off \"" + HELPER_SWITCH + "\" in " + ASSESS_SETTINGS_WHERE + ", then try again.",
  },
  helper_not_written: {
    words:
      "The request helper could not be written into the run folder, so the run did not start. The folder may be missing or not writable. Check that the project folder can be written to, or turn off \"" + HELPER_SWITCH + "\" in " + ASSESS_SETTINGS_WHERE + ", then try again.",
  },
  // The eligibility rules (E1 to E10): the server's sentence says which one and what to do.
  not_agent_shaped: { words: "This assessment has no agent launch, so nothing was started.", own: true },
  project_missing: { words: "The project's folder is not on this machine, so nothing was started.", own: true },
  target_required: { words: "This assessment needs a target on this machine. Name one, then start it again.", own: true },
  target_unconfirmed: { words: "The confirmation does not match the target. Confirm the exact target shown, then start it again.", own: true },
  target_reserved_port: { words: "The target is on a port that Observer or its sandbox needs. Use the port your development server uses.", own: true },
  sandbox_required: { words: "This assessment runs only in a sandbox, so nothing was started.", own: true },
  sandbox_unavailable: { words: "No sandbox is available for this agent on this machine, so nothing was started. The assessment is never run unsandboxed.", own: true },
  tier_not_confined: { words: "The sandbox network is not confined enough for this assessment, so nothing was started.", own: true },
  tool_not_proxy_routed: { words: "This agent is not routed through Observer's proxy, so it would start with no route to its model. Pick another agent.", own: true },
  backend_not_grounded: { words: "No sandbox backend on this machine fits this assessment, so nothing was started.", own: true },
  source_not_live: { words: "A sandboxed assessment needs the live workspace, so nothing was started.", own: true },
  // The consent rows (guardrails a run may ask to lift).
  relax_disabled: { words: "Lifting a guardrail is turned off for this assessment in Settings, so nothing was started.", own: true },
  needs_org: { words: "This guardrail is governed by an organization this node is not enrolled with, so it cannot be lifted here.", own: true },
  tier_above_max: { words: "A wider sandbox network is above the highest level Settings allows, so none is offered.", own: true },
  tier_unsupported: { words: "The sandbox network is at a level a run cannot be widened from, so none is offered.", own: true },
  needs_allow_hosts: { words: "A wider sandbox network is offered only with a list of the hosts the box may reach. Set that list under the sandbox settings first.", own: true },
  needs_org_setting: { words: "Your organization sets the sandbox network on this machine, so it cannot be widened here. Ask your administrator.", own: true },
  relaxation_not_available: { words: "That guardrail cannot be lifted for this assessment.", own: true },
  unknown_relaxation: { words: "That guardrail is not one this assessment offers. Read the plan again." },
  relaxation_not_granted: {
    words: "Your organization has not approved that guardrail for this project yet, or its grant ends too soon. Ask your organization first, then start the run once it is approved.",
    own: true,
  },
  relaxation_held_by_another_run: {
    words: "Another assessment run in this project already holds the approval for that guardrail. Wait for that run to end, or use the session scope.",
    own: true,
  },
  // Asking the organization.
  not_enrolled: { words: "This node is not enrolled with an organization, so there is nobody to send a request to." },
  not_held: { words: "The run is no longer waiting for your organization." },
  nothing_to_request: { words: "Nothing ticked needs your organization's approval: start the run instead." },
  bad_request: { words: "The request was not accepted.", own: true },
  refused: { words: "The request was refused before it was sent.", own: true },
  too_many_open: { words: "You already have the most open requests to your organization that are allowed. Wait for one to be answered, then try again." },
  outbox_full: { words: "Your organization is unreachable and the queue of unsent requests is full. Try again when it can be reached." },
  send_failed: { words: "The request could not be sent to your organization.", own: true },
  // Stop, Validate and the stored model.
  not_started: { words: "The run has not started, so it has no terminal to stop and no model to check yet." },
  run_running: { words: "The run has not ended, so its model may still be written. Validate again when it ends, or use Validate anyway." },
  no_model: { words: "The run has not written assessment.json yet." },
  no_model_contract: { words: "This run was not started under a result contract that has a model to check." },
  project_gone: { words: "The project's folder is no longer on this machine, so its files cannot be checked against the model." },
  validation_timeout: { words: "The check of the model did not finish in time. Nothing was recorded. Try again." },
  no_stored_model: { words: "No checked copy of this run's model is stored. Check the model again." },
  // The fix and export routes of the model view (depth plan W6b).
  unknown_item: {
    words:
      "The stored model holds no threat or finding with that id: the checked copy may have been replaced since this list was read. Nothing was started. Close the model and open it again.",
  },
  no_location: {
    words: "This item cites no place that Observer found in the project and can name in a task, so there is nothing to point a fix at. Nothing was started.",
  },
  bad_format: { words: "The download format is not one Observer offers. Nothing was saved. Use one of the two download buttons." },
  fix_too_large: { words: "This item's task does not fit the size limit for a task, so it cannot be started from here. Nothing was started." },
  prompt_digest_required: {
    words: "The launch did not name the task you read, so nothing was started. Close this window, open Fix with an agent again, read the task and choose an agent.",
  },
  // The comparison with an earlier run (the model view's "Changes since").
  since_unknown: { words: "The run to compare with is not listed, or it is this run. Choose another run.", own: true },
  since_mismatch: { words: "A run can be compared only with an earlier run of the same project and the same kind of assessment.", own: true },
  since_not_earlier: { words: "The run to compare with was started after this one. A run can be compared only with an earlier run.", own: true },
  since_no_model: { words: "The earlier run has no stored model to compare with: it was deleted, or its model was not kept.", own: true },
  since_not_threat_model: { words: "Only a threat model with a kept model can be compared with an earlier run.", own: true },
  // The retest of earlier findings (depth plan W7.2): labels only, so every refusal says nothing was started or, for the export, that there is none.
  retest_run_unknown: {
    words: "The run to retest is not in the run history, so nothing was started. Open the penetration test or red team run again and start the retest from there.",
  },
  retest_run_mismatch: {
    words: "That run belongs to another project, or it was not a penetration test or red team run, so it cannot be retested here. Nothing was started.",
  },
  retest_no_model: {
    words: "That run has no checked model kept, so there are no stored requests to replay. Check the run's model first. Nothing was started.",
  },
  retest_findings: {
    words: "Choose between 1 and 8 findings that have a stored request to replay. Nothing was started.",
    own: true,
  },
  retest_helper: {
    words:
      "A retest needs the request helper, which sends the stored requests and logs them. The helper is off, or it was left out because python3 was not found, so nothing was started. Turn on \"" + HELPER_SWITCH + "\" in " + ASSESS_SETTINGS_WHERE + ", and install python3 on this machine if it was left out.",
  },
  retest_too_large: {
    words: "The stored requests of these findings do not fit the request helper's settings file. Choose fewer findings. Nothing was started.",
  },
  retest_no_export: {
    words: "A retest has no export of its own: its labels are shown on the findings of the run it replayed.",
  },
  not_validated: { words: "Check the model first: use Validate, then import. The import takes the findings Observer derives from a checked model." },
  internal: { words: "The approvals could not be read.", own: true },
};

/** sentence turns a server's lowercase fragment into a sentence. */
function sentence(s: string): string {
  const t = s.trim();
  if (t === "") return "";
  const cap = t.charAt(0).toUpperCase() + t.slice(1);
  return /[.!?]$/.test(cap) ? cap : `${cap}.`;
}

/** The JSON a refusal carries: the machine code, the server's own sentence and,
 *  for the run record, the file's path. */
type RefusalBody = { code?: unknown; error?: unknown; file?: unknown };

/** refusalBody reads a response body as a JSON object, or null when it is plain
 *  text (the older routes' refusals), an array or a scalar. */
function refusalBody(body: string): RefusalBody | null {
  try {
    const parsed: unknown = JSON.parse(body);
    return parsed !== null && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as RefusalBody) : null;
  } catch {
    return null;
  }
}

/** assessRefusalWords is the words for a refused assess request, or null when
 *  the error has none to give (not an API error, no body, or a plain-text body
 *  on anything but a 409). A JSON refusal reads as its code's row, with the
 *  server's own sentence in its place when that names the cause; a code with no
 *  row reads as the server's sentence, never as a generic failure. A plain-text
 *  409 (the older routes' refusals) reads as the server's sentence. */
export function assessRefusalWords(e: unknown): string | null {
  const status = (e as { status?: unknown } | null)?.status;
  const body = (e as { body?: unknown } | null)?.body;
  if (typeof status !== "number" || typeof body !== "string") return null;
  const j = refusalBody(body);
  if (!j) {
    const t = body.trim();
    return status === 409 && t !== "" ? sentence(t) : null;
  }
  const server = typeof j.error === "string" ? sentence(j.error) : "";
  const row = typeof j.code === "string" && Object.prototype.hasOwnProperty.call(ASSESS_REFUSALS, j.code) ? ASSESS_REFUSALS[j.code] : undefined;
  if (!row) return server || null;
  const words = row.own && server ? server : row.words;
  const file = typeof j.file === "string" && j.file !== "" && j.code === "run_record_unreadable" ? ` The file is ${j.file}.` : "";
  return `${words}${file}`;
}

// --- The model check (depth plan W1b) --------------------------------------
//
// A threat model, penetration test or red team run writes an assessment.json.
// Observer checks its structure and the file references in it; the sentences
// below say what was checked and never that the agent was right. "Found near
// the cited line" is the only credit a reference earns: the text the agent
// quoted is on a code line within the match window of the first line it cited
// (the setting ref_match_window_lines, 5 by default; 1 is the cited line
// itself). A reference whose text is only further away, even inside a long
// cited range, reads as existing with nothing matched near the cited line.

/** The words of a refused file's reason code (validator rows V1 and V2). */
export const ASSESS_FATAL_WORDS: Readonly<Record<string, string>> = {
  too_large: "it is over the size cap",
  too_deep: "it is nested too deeply",
  not_json: "it is not JSON",
  not_object: "it is not a JSON object",
  bad_shape: "its shape does not match the schema",
  schema_mismatch: "it names a different schema than this kind of run uses",
  run_id_mismatch: "it names a different run",
  trailing_data: "there is data after the JSON",
  no_model_contract: "this run has no model contract",
  not_regular: "it is a link, a folder or a device, not a file",
};

/** assessRefTallyWords is the references line of a validation: only the counts that are not zero. */
export function assessRefTallyWords(t: AssessRefTally): string {
  const parts: string[] = [];
  if (t.found > 0) parts.push(`${t.found} found near the cited line`);
  if (t.exists > 0) parts.push(`${t.exists} ${t.exists === 1 ? "exists" : "exist"} with nothing matched near the cited line`);
  if (t.claimed_not_found > 0) parts.push(`${t.claimed_not_found} cited text not found in the cited range`);
  if (t.missing > 0) parts.push(`${t.missing} missing`);
  if (t.invalid > 0) parts.push(`${t.invalid} malformed`);
  if (t.unchecked > 0) parts.push(`${t.unchecked} not checked`);
  return parts.length > 0 ? `References: ${parts.join(", ")}.` : "";
}

/** ASSESS_WINDOW_UNRECORDED is what a reference tally says when its check kept no match window: a check made before the conditions were recorded. The counts are shown, and the line says they come without their conditions, so a reader never takes them for a count made under today's setting (N-20). */
export const ASSESS_WINDOW_UNRECORDED = "How many lines from the cited line a reference could match was not recorded for this check.";

/** assessRefConditionWords are the sentences that give a reference tally its conditions: the match window it was made under and how many references quoted text that hiding secrets changed, so a count is never read without them. A check that predates them (no window) says that they were not recorded, never a window of its own guess. */
export function assessRefConditionWords(window: number | undefined, hidden: number | undefined): string[] {
  if (!(typeof window === "number" && window > 0)) return [ASSESS_WINDOW_UNRECORDED];
  const out = [window === 1 ? "A reference is found only when its text is on the first cited line itself." : `A reference is found when its text is on a code line within ${window} lines of the first cited line.`];
  const h = typeof hidden === "number" && hidden > 0 ? hidden : 0;
  if (h > 0) {
    out.push(`${h} ${h === 1 ? "reference quotes" : "references quote"} text that hiding secrets changed, so ${h === 1 ? "it" : "they"} could not be found in the file.`);
  }
  return out;
}

/** assessValidationLine is a run row's model check line, or null when the run has none. */
export function assessValidationLine(v: AssessValidation | null | undefined): { text: string; tone: Tone } | null {
  if (!v) return null;
  const bits: string[] = [];
  let tone: Tone = "neutral";
  if (v.state === "invalid") {
    const why = ASSESS_FATAL_WORDS[v.fatal ?? ""] ?? (v.fatal ? v.fatal.replace(/_/g, " ") : "it could not be read");
    bits.push(`Model refused: ${why}.`);
    tone = "danger";
  } else if (v.state === "partial") {
    const n = v.refused ?? 0;
    const u = v.refs?.unchecked ?? 0;
    // A partial check has three causes: items the validator refused, references
    // it ran out of budget for, and items it left out. The first two have
    // counts; "left out" is what is said when neither does.
    if (n > 0) bits.push(`Model checked: ${n} ${n === 1 ? "item was" : "items were"} refused.`);
    else if (u === 0) bits.push("Model checked: some items were left out.");
    if (u > 0) {
      bits.push(
        `${n > 0 ? "" : "Model checked: "}${u} ${u === 1 ? "reference" : "references"} could not be checked within the check's budget, so the model is only partly checked. The budget is set in ${ASSESS_SETTINGS_WHERE}.`,
      );
    }
    tone = "warn";
    const refs = assessRefTallyWords(v.refs);
    if (refs) bits.push(refs, ...assessRefConditionWords(v.ref_window_lines, v.ref_text_hidden));
  } else {
    bits.push("Model checked: nothing was refused.");
    const refs = assessRefTallyWords(v.refs);
    if (refs) bits.push(refs, ...assessRefConditionWords(v.ref_window_lines, v.ref_text_hidden));
  }
  if (v.anyway) bits.push("Checked before the run ended.");
  if (v.stale) {
    bits.push("The model changed after this check; check it again.");
    tone = tone === "danger" ? "danger" : "warn";
  }
  return { text: bits.join(" "), tone };
}

/** assessCanValidate is whether the run row offers Validate: it was launched
 *  under a model contract, its assessment.json exists, and it is not held. */
export function assessCanValidate(r: Pick<AssessRun, "contract" | "files" | "phase" | "validation" | "import">): boolean {
  if (!r.contract || r.contract === "sarif" || r.phase === "held" || r.phase === "cancelled") return false;
  if (!r.files.model) return false;
  // A validation that is current is not offered again; a stale one is, and so is
  // one whose stored copy was lost (the import cannot derive from nothing).
  return !r.validation || r.validation.stale === true || r.import?.reason === "model_unavailable";
}

/** assessValidateLabel is the Validate button's label. */
export function assessValidateLabel(r: Pick<AssessRun, "validation" | "can_stop">): string {
  if (r.can_stop === true) return "Validate anyway";
  return r.validation ? "Validate again" : "Validate";
}
