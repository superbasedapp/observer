// Tests of the sandbox setup panel's pure copy and decisions
// (sandboxSetup.ts, sandbox installation lifecycle plan section 3.7 and 10):
// one test per button label, state chip, error code and rule.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { getHelp } from "./help.ts";
import {
  CHANNEL_BUTTON_LABELS,
  CLASS_BUTTON_LABELS,
  CREDENTIAL_FORM_NOTE,
  CREDENTIAL_STORED_NOTE,
  CREDENTIAL_STORE_LABEL,
  KIND_TERMINAL_VERBS,
  SETUP_DOCS_HELP,
  SETUP_OVERVIEW_HELP,
  SETUP_PREREQ_HELP,
  UNKNOWN_RUNNABLE_HINT,
  afterNote,
  credentialErrorSentence,
  credentialFields,
  credentialGuideNote,
  credentialRunFields,
  ELEVATED_GUIDE_HINT,
  ERROR_SENTENCES,
  SETUP_INPUT_WAIT_MS,
  STALE_TOKEN_MSG,
  STATE_CHIPS,
  consentFolderFor,
  consentLine,
  consentNeedsFolder,
  defaultSetupBackend,
  downloadButtonLabel,
  elevatedGuideHint,
  manageActions,
  maybeWaitingForInput,
  opProgress,
  opProgressLabel,
  parseSetupError,
  planHeadline,
  recordView,
  setupCandidates,
  setupErrorSentence,
  setupHelpId,
  setupLine,
  setupRoutesAbsent,
  shortDigest,
  sizeMB,
  stateChip,
  stepButtonLabel,
  stepButtonRuns,
  stepCopyText,
  stepTakesInput,
  summaryOptionLabel,
  summarySetUp,
  unknownStepHint,
  versionLabel,
} from "./sandboxSetup.ts";
import type {
  SandboxSetupConsent,
  SandboxSetupPlan,
  SandboxSetupRecord,
  SandboxSetupStep,
  SandboxSetupSummary,
} from "./sandboxSetupTypes.ts";
import type { SandboxAvailability, SandboxBackendAvail } from "./types.ts";

const DASHES = /[\u2013\u2014]/;

const step = (over: Partial<SandboxSetupStep>): SandboxSetupStep => ({
  prereq: "bwrap",
  kind: "program",
  label: "bubblewrap",
  state: "missing",
  class: "terminal",
  channel: "pm",
  can_run: true,
  can_undo: false,
  ...over,
});

const consent: SandboxSetupConsent = {
  pin: "cloud-hypervisor-linux-amd64",
  version: "54.0",
  sha256: "ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
  bytes: 4_812_345,
  source: "vendor_release",
};

const record = (over: Partial<SandboxSetupRecord>): SandboxSetupRecord => ({
  id: 7,
  tool: "cloud-hypervisor",
  channel: "pinned_download",
  command: "download cloud-hypervisor v54.0",
  status: "installed",
  installed_at: "2026-11-06T09:00:00Z",
  can_uninstall: false,
  can_forget: true,
  subject_kind: "sandbox",
  backend: "cloud-hypervisor",
  ...over,
});

// ---------------------------------------------------------------------------
// Button labels, one test per class
// ---------------------------------------------------------------------------

test("label: auto reads Turn on", () => {
  assert.equal(stepButtonLabel(step({ class: "auto", channel: "component_select" })), "Turn on");
});

test("label: terminal reads Install in terminal", () => {
  assert.equal(stepButtonLabel(step({ class: "terminal" })), "Install in terminal");
});

test("label: elevated says it asks for the password", () => {
  assert.equal(stepButtonLabel(step({ class: "elevated" })), "Install in terminal (asks for your password)");
});

test("label: a pinned download names its size and version", () => {
  const s = step({ class: "auto", channel: "pinned_download", consent });
  assert.equal(stepButtonLabel(s), "Download and install (5 MB, v54.0)");
  assert.equal(downloadButtonLabel({ ...consent, version: "v54.0", bytes: 200 }), "Download and install (1 MB, v54.0)");
});

test("label: guide reads Copy command, and nothing without a command", () => {
  assert.equal(stepButtonLabel(step({ class: "guide", display: "sudo apt-get install -y bubblewrap", display_is_command: true })), "Copy command");
  assert.equal(stepButtonLabel(step({ class: "guide" })), null);
});

// A guide whose display is a sentence copied that sentence as a "command"
// before the daemon flagged command displays; it offers no button now.
test("label: a guide whose display is a sentence offers nothing to copy", () => {
  const s = step({ class: "guide", channel: "none", display: "Install the bubblewrap package with your distribution's package manager, then check again." });
  assert.equal(stepButtonLabel(s), null);
  assert.equal(stepCopyText(s), null);
});

test("copy: a command display, else a credential step's command, is what is copied", () => {
  assert.equal(stepCopyText(step({ class: "guide", display: "sudo apt-get install -y bubblewrap", display_is_command: true })), "sudo apt-get install -y bubblewrap");
  const key = step({ prereq: "hosted-key", kind: "credential", class: "guide", channel: "none", display: "Paste the provider's API key.", command: "observer sandbox hosted connect daytona", fields: ["DAYTONA_API_KEY"] });
  assert.equal(stepCopyText(key), "observer sandbox hosted connect daytona");
  assert.equal(stepButtonLabel(key), "Copy command");
});

// The operator's Daytona report: the key step read "Turn on", which sent no
// key and was refused with a generic sentence.
test("label: a key step never gets a plain button", () => {
  const key = step({ prereq: "hosted-key", kind: "credential", class: "auto", channel: "hosted_connect", fields: ["DAYTONA_API_KEY"] });
  assert.equal(stepTakesInput(key), true);
  assert.equal(stepButtonLabel(key), null);
});

test("label: a consent screen and a sign-in name the terminal they open", () => {
  assert.equal(stepButtonLabel(step({ prereq: "hosted-consent", kind: "consent", class: "auto", channel: "hosted_consent" })), CHANNEL_BUTTON_LABELS.hosted_consent);
  assert.equal(stepButtonLabel(step({ prereq: "orgshell-login", kind: "account", class: "auto", channel: "orgshell_login" })), "Sign in in terminal");
  for (const l of Object.values(CHANNEL_BUTTON_LABELS)) assert.doesNotMatch(l, /Turn on/);
});

// ---------------------------------------------------------------------------
// Credential (API key) steps
// ---------------------------------------------------------------------------

const keyStep = (over: Partial<SandboxSetupStep> = {}): SandboxSetupStep =>
  step({ prereq: "hosted-key", kind: "credential", label: "The provider's API key in this machine's keychain", class: "auto", channel: "hosted_connect", fields: ["DAYTONA_API_KEY"], ...over });

test("credential: a runnable key step asks for the provider's fields", () => {
  assert.deepEqual(credentialFields(keyStep()), ["DAYTONA_API_KEY"]);
  assert.deepEqual(credentialFields(keyStep({ fields: ["MODAL_TOKEN_ID", "MODAL_TOKEN_SECRET"] })), ["MODAL_TOKEN_ID", "MODAL_TOKEN_SECRET"]);
});

const noFormCases: [string, Partial<SandboxSetupStep>][] = [
  ["done", { state: "done" }],
  ["not needed", { state: "not_applicable" }],
  ["not runnable (organization or an earlier blocked step)", { can_run: false, state: "not_allowed" }],
  ["no field names from the daemon", { fields: [] }],
  ["a guide (guided installs off)", { class: "guide", channel: "none", command: "observer sandbox hosted connect daytona" }],
];
for (const [name, over] of noFormCases) {
  test(`credential: no key form when ${name}`, () => {
    assert.equal(credentialFields(keyStep(over)), null);
  });
}

test("credential: the run request carries each named field, trimmed, and nothing else", () => {
  assert.deepEqual(credentialRunFields(["A", "B"], { A: "  one ", B: "two", C: "stray" }), { A: "one", B: "two" });
  assert.deepEqual(credentialRunFields(["A"], {}), { A: "" });
});

test("credential: a refused store shows the daemon's sentence, which names a field and never a value", () => {
  const body = JSON.stringify({ code: "step_not_runnable", error: "MODAL_TOKEN_SECRET is required" });
  assert.equal(credentialErrorSentence(400, body), "The key was not stored: MODAL_TOKEN_SECRET is required.");
  assert.equal(credentialErrorSentence(400, JSON.stringify({ code: "step_not_runnable", error: "a key is required." })), "The key was not stored: a key is required.");
  assert.equal(credentialErrorSentence(409, JSON.stringify({ code: "plan_changed", error: "x" })), ERROR_SENTENCES.plan_changed);
  assert.equal(credentialErrorSentence(403, JSON.stringify({ code: "not_allowed_by_org", error: "x" })), ERROR_SENTENCES.not_allowed_by_org);
});

test("credential: a key step turned guide names the command's prompts and the card's form", () => {
  const g = keyStep({ class: "guide", channel: "none", command: "observer sandbox hosted connect modal", fields: ["MODAL_TOKEN_ID", "MODAL_TOKEN_SECRET"] });
  assert.equal(
    credentialGuideNote(g),
    "Run it in a terminal of your own: it asks for MODAL_TOKEN_ID and MODAL_TOKEN_SECRET and keeps them in this machine's keychain. The Connect form on the Hosted sandboxes card stores them too.",
  );
  assert.match(credentialGuideNote(keyStep({ class: "guide", channel: "none", command: "observer sandbox hosted connect e2b", fields: ["E2B_API_KEY"] })) ?? "", /asks for E2B_API_KEY and keeps it/);
  assert.equal(credentialGuideNote(keyStep()), null);
  assert.equal(credentialGuideNote(step({ class: "guide", command: "x" })), null);
  for (const s of [CREDENTIAL_FORM_NOTE, CREDENTIAL_STORE_LABEL, CREDENTIAL_STORED_NOTE, credentialGuideNote(g) ?? ""]) assert.doesNotMatch(s, DASHES);
});

test("label: never offers no button", () => {
  assert.equal(stepButtonLabel(step({ class: "never", display: "enable nested virtualization" })), null);
  assert.equal(CLASS_BUTTON_LABELS.never, null);
});

test("label: an unknown class offers no button", () => {
  assert.equal(stepButtonLabel(step({ class: "teleport" })), null);
});

// D-11: a terminal step that starts a service or pulls an image never says
// "Install"; one row per kind verb.
for (const [kind, verb] of Object.entries(KIND_TERMINAL_VERBS)) {
  test(`label: a ${kind} terminal step reads ${verb}`, () => {
    assert.equal(stepButtonLabel(step({ kind, class: "terminal", channel: "terminal_cmd" })), verb);
    assert.equal(stepButtonLabel(step({ kind, class: "elevated", channel: "terminal_cmd" })), `${verb} (asks for your password)`);
    assert.doesNotMatch(verb, /install/i);
    assert.doesNotMatch(verb, DASHES);
  });
}

test("label: a program terminal step still reads Install in terminal", () => {
  assert.equal(stepButtonLabel(step({ kind: "program", class: "terminal" })), "Install in terminal");
});

test("unconfirmed: the headline asks for the check, the chooser and Manage say set up", () => {
  const plan: SandboxSetupPlan = { backend: "bwrap", label: "Bubblewrap", steps: [], next: -1, ready: false, unconfirmed: true, checked: false, fingerprint: "f" };
  assert.match(planHeadline(plan), /set up as far as Observer can see\. Press Check this machine/);
  assert.equal(summaryOptionLabel({ backend: "bwrap", label: "Bubblewrap", ready: false, unconfirmed: true }), "Bubblewrap (set up, not checked)");
  assert.equal(summarySetUp({ backend: "bwrap", label: "Bubblewrap", ready: false, unconfirmed: true }), true);
  assert.equal(summarySetUp({ backend: "bwrap", label: "Bubblewrap", ready: true }), true);
  assert.equal(summarySetUp({ backend: "bwrap", label: "Bubblewrap", ready: false, next: "x" }), false);
  assert.equal(summarySetUp(undefined), false);
  assert.doesNotMatch(planHeadline(plan), DASHES);
});

test("an unknown step Observer can run says the check decides; others say nothing", () => {
  assert.equal(unknownStepHint(step({ state: "unknown", class: "terminal", can_run: false })), UNKNOWN_RUNNABLE_HINT);
  assert.equal(unknownStepHint(step({ state: "unknown", class: "never", can_run: false })), null);
  assert.equal(unknownStepHint(step({ state: "missing", class: "terminal" })), null);
  assert.doesNotMatch(UNKNOWN_RUNNABLE_HINT, DASHES);
});

test("only auto, terminal and elevated buttons ask the daemon to run", () => {
  for (const [cls, runs] of [["auto", true], ["terminal", true], ["elevated", true], ["guide", false], ["never", false]] as const) {
    assert.equal(stepButtonRuns(step({ class: cls })), runs, cls);
  }
});

test("no button label carries an em or en dash", () => {
  for (const l of Object.values(CLASS_BUTTON_LABELS)) assert.doesNotMatch(l ?? "", DASHES);
});

// ---------------------------------------------------------------------------
// State chips, one test per state
// ---------------------------------------------------------------------------

const chipCases: [string, string, string][] = [
  ["done", "Done", "ok"],
  ["missing", "Needed", "warn"],
  ["unknown", "Not checked yet", "info"],
  ["blocked", "Blocked on this machine", "bad"],
  ["not_applicable", "Not needed here", "muted"],
  ["in_flight", "In progress", "info"],
  ["not_allowed", "Not allowed by your organization", "bad"],
];
for (const [state, label, tone] of chipCases) {
  test(`chip: ${state} reads ${label}`, () => {
    assert.deepEqual(stateChip(state), { label, tone });
    assert.doesNotMatch(label, DASHES);
  });
}

test("chip: every closed state has a row and an unknown state names itself", () => {
  assert.equal(Object.keys(STATE_CHIPS).length, chipCases.length);
  assert.deepEqual(stateChip("half_done"), { label: "half done", tone: "info" });
});

// ---------------------------------------------------------------------------
// Consent line
// ---------------------------------------------------------------------------

test("consent: version, size in MB, the first 12 hex of the sha256 and the source", () => {
  const line = consentLine(consent);
  assert.equal(
    line,
    "Downloads v54.0 (5 MB) from the vendor's release, checked against sha256 abcdef012345 before it is installed.",
  );
  assert.match(consentLine({ ...consent, source: "org_mirror" }), /from your organization's mirror/);
  assert.doesNotMatch(line, DASHES);
});

test("sizes, versions and digests format as people read them", () => {
  assert.equal(sizeMB(0), "1");
  assert.equal(sizeMB(42_400_000), "42");
  assert.equal(versionLabel("V1.2"), "v1.2");
  assert.equal(versionLabel(""), "an unknown version");
  assert.equal(shortDigest("ABCDEF0123456789ff"), "abcdef012345");
});

// ---------------------------------------------------------------------------
// Error codes, one test per closed code
// ---------------------------------------------------------------------------

const codes: [string, RegExp][] = [
  ["plan_changed", /fresh plan is below/],
  ["not_allowed_by_org", /organization does not allow/],
  ["install_disabled", /Allow guided install and uninstall/],
  ["elevation_disabled", /\[terminal\.sandbox\.setup\]\.allow_elevated/],
  ["consent_required", /agreement to the version, size and checksum/],
  ["live_runs", /still running on this backend/],
  ["step_not_runnable", /cannot run from here right now/],
  ["unknown_step", /no longer in the plan/],
  ["not_in_build", /cannot set up sandbox backends/],
  ["terminal_unavailable", /nowhere to run the installer/],
];
for (const [code, want] of codes) {
  test(`error: ${code} maps to its sentence`, () => {
    const s = setupErrorSentence(409, JSON.stringify({ error: `raw ${code}`, code }));
    assert.match(s, want);
    assert.doesNotMatch(s, /^api \d/);
    assert.doesNotMatch(s, DASHES);
  });
}

test("error: every closed code has a sentence", () => {
  assert.equal(Object.keys(ERROR_SENTENCES).length, codes.length);
});

test("error: a code-less confirm token 403 reads as a stale token", () => {
  assert.equal(setupErrorSentence(403, "forbidden: missing or invalid confirm token\n"), STALE_TOKEN_MSG);
});

test("error: an unknown code keeps the server's sentence, else a status sentence", () => {
  assert.equal(setupErrorSentence(500, JSON.stringify({ error: "the engine said no", code: "weird" })), "the engine said no");
  assert.equal(setupErrorSentence(500, ""), "The setup request failed (HTTP 500).");
  assert.equal(setupErrorSentence(0, ""), "The setup request could not reach the daemon.");
});

test("error: a plan_changed body carries the fresh plan", () => {
  const plan = { backend: "bwrap", label: "Bubblewrap", steps: [], next: -1, ready: true, checked: false, fingerprint: "f2" };
  const p = parseSetupError(JSON.stringify({ error: "plan changed", code: "plan_changed", plan }));
  assert.equal(p.code, "plan_changed");
  assert.equal(p.plan?.fingerprint, "f2");
  assert.deepEqual(parseSetupError("plain text"), { code: "", error: "plain text" });
});

test("rule: 404 component_not_installed and 501 hide the panel; other answers do not", () => {
  assert.equal(setupRoutesAbsent(404, '{"error":"component_not_installed"}'), true);
  assert.equal(setupRoutesAbsent(501, ""), true);
  assert.equal(setupRoutesAbsent(404, "no such backend"), false);
  assert.equal(setupRoutesAbsent(500, "component_not_installed"), false);
});

// ---------------------------------------------------------------------------
// The "may be waiting for input" rule
// ---------------------------------------------------------------------------

test("rule: an install running 90 s or more may be waiting for input", () => {
  const start = Date.parse("2026-11-06T09:00:00Z");
  const r = record({ status: "installing" });
  assert.equal(maybeWaitingForInput(r, start + SETUP_INPUT_WAIT_MS - 1), false);
  assert.equal(maybeWaitingForInput(r, start + SETUP_INPUT_WAIT_MS), true);
  assert.equal(SETUP_INPUT_WAIT_MS, 90_000);
});

test("rule: the server's own flag wins, a finished record never waits", () => {
  const start = Date.parse("2026-11-06T09:00:00Z");
  assert.equal(maybeWaitingForInput(record({ status: "installing", maybe_waiting_for_input: true }), start), true);
  assert.equal(maybeWaitingForInput(record({ status: "installed" }), start + 10 * SETUP_INPUT_WAIT_MS), false);
  assert.equal(maybeWaitingForInput(undefined, start), false);
});

test("rule: an uninstall counts from its own start", () => {
  const start = Date.parse("2026-11-06T10:00:00Z");
  const r = record({ status: "uninstalling", uninstall_started_at: "2026-11-06T10:00:00Z" });
  assert.equal(maybeWaitingForInput(r, start + 1000), false);
  assert.equal(maybeWaitingForInput(r, start + SETUP_INPUT_WAIT_MS), true);
});

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

test("record: installed reads Installed from this dashboard on <date>", () => {
  const v = recordView(record({}));
  assert.match(v.line, /^Installed from this dashboard on /);
  assert.equal(v.tone, "ok");
  assert.equal(v.remedy, null);
});

test("record: a failed step names its exit code and the remedy", () => {
  const v = recordView(record({ status: "install_failed", exit_code: 100 }));
  assert.equal(v.tone, "warn");
  assert.match(v.remedy ?? "", /exited with code 100/);
});

test("record: installed but not detected and interrupted each name the next step", () => {
  assert.match(recordView(record({ status: "installed_not_found" })).remedy ?? "", /Check this machine/);
  assert.match(recordView(record({ status: "install_interrupted" })).remedy ?? "", /Run it again/);
});

test("recordView: a consent or sign-in run reads as a run, never an install", () => {
  for (const channel of ["hosted_consent", "org_shell"]) {
    const failed = recordView(record({ channel, status: "install_failed", exit_code: 1 }));
    assert.match(failed.line, /The run started from this dashboard/);
    assert.match(failed.remedy ?? "", /exited with code 1/);
    assert.doesNotMatch(failed.line + (failed.remedy ?? ""), /install|download|curl/i);
    assert.match(recordView(record({ channel, status: "installed" })).line, /^Done from this dashboard/);
  }
});

// ---------------------------------------------------------------------------
// Manage actions
// ---------------------------------------------------------------------------

test("manage: Undo only where the server says can_undo", () => {
  assert.deepEqual(manageActions(step({ state: "done", can_undo: true })), [{ action: "undo", label: "Undo" }]);
  assert.deepEqual(manageActions(step({ state: "done", can_undo: false })), []);
});

test("manage: Update when the pin moved past the placed file", () => {
  const s = step({ state: "done", class: "auto", channel: "pinned_download", consent, record: record({ digest: "0000" }), can_undo: true });
  assert.deepEqual(manageActions(s), [
    { action: "update", label: "Update to v54.0" },
    { action: "undo", label: "Undo" },
  ]);
  const same = { ...s, record: record({ digest: consent.sha256.toLowerCase() }) };
  assert.deepEqual(manageActions(same).map((a) => a.action), ["undo"]);
});

test("manage: Update when the server's reason says one is available", () => {
  const s = step({ state: "done", record: record({ channel: "pm" }), reason: "update available: v0.12, installed v0.11" });
  assert.deepEqual(manageActions(s), [{ action: "update", label: "Update" }]);
});

test("manage: Repair when a step this dashboard set up no longer verifies", () => {
  assert.deepEqual(manageActions(step({ state: "missing", record: record({}) })), [{ action: "repair", label: "Repair" }]);
  assert.deepEqual(manageActions(step({ state: "missing", record: record({ status: "install_failed" }) })), []);
  assert.deepEqual(manageActions(step({ state: "missing" })), []);
});

// ---------------------------------------------------------------------------
// The elevated guide hint
// ---------------------------------------------------------------------------

test("rule: a guide step that elevates says how it becomes a button", () => {
  assert.equal(elevatedGuideHint(step({ class: "guide", display: "sudo apt-get install -y bubblewrap" })), ELEVATED_GUIDE_HINT);
  assert.equal(
    elevatedGuideHint(step({ class: "guide", display: "powershell -Command Start-Process dism -Verb RunAs" })),
    ELEVATED_GUIDE_HINT,
  );
  assert.equal(elevatedGuideHint(step({ class: "guide", display: "brew install colima" })), null);
  assert.equal(elevatedGuideHint(step({ class: "elevated", display: "sudo apt-get install -y bubblewrap" })), null);
  assert.doesNotMatch(ELEVATED_GUIDE_HINT, DASHES);
});

// ---------------------------------------------------------------------------
// Plans, summaries and candidates
// ---------------------------------------------------------------------------

const plan = (over: Partial<SandboxSetupPlan>): SandboxSetupPlan => ({
  backend: "bwrap",
  label: "Bubblewrap",
  steps: [step({ state: "done", label: "module" }), step({ label: "bubblewrap" })],
  next: 1,
  ready: false,
  checked: false,
  fingerprint: "f1",
  ...over,
});

test("headline: blocked, ready and the next step", () => {
  assert.equal(planHeadline(plan({ blocked: "runs on native Linux only" })), "Bubblewrap cannot be set up on this machine: runs on native Linux only");
  assert.equal(planHeadline(plan({ ready: true, next: -1 })), "Bubblewrap is set up and runs here.");
  assert.equal(planHeadline(plan({})), "Bubblewrap is not set up yet. Next: bubblewrap.");
  assert.equal(planHeadline(plan({ next: -1 })), "Bubblewrap is not set up yet.");
});

const backend = (over: Partial<SandboxBackendAvail>): SandboxBackendAvail => ({
  id: "bwrap",
  label: "Bubblewrap",
  class: "process",
  location: "local",
  maturity: "beta",
  available: true,
  beta: false,
  capture_by_tier: {},
  component: "terminals.sandbox",
  ...over,
});

const probe: SandboxAvailability = {
  available: true,
  default_on: false,
  backends: [
    backend({}),
    backend({ id: "landlock", label: "Landlock only", available: false, verdict: "disabled_by_config", when_enabled_available: true }),
    backend({ id: "oci-runc", label: "Docker or Podman", available: false, verdict: "module_inactive" }),
    backend({ id: "cloud-hypervisor", label: "Cloud Hypervisor", available: false, verdict: "backend_missing", reason: "cloud-hypervisor not found" }),
    backend({ id: "openshell-org", label: "Org OpenShell", available: false, verdict: "org_gateway_not_offered" }),
  ],
};

const summaries: SandboxSetupSummary[] = [
  { backend: "bwrap", label: "Bubblewrap", ready: true },
  { backend: "landlock", label: "Landlock only", ready: false, next: "Turn on Landlock only" },
  { backend: "oci-runc", label: "Docker or Podman", ready: false, next: "Select the module" },
  { backend: "cloud-hypervisor", label: "Cloud Hypervisor", ready: false, next: "cloud-hypervisor" },
  { backend: "openshell", label: "OpenShell", ready: false, blocked: "OpenShell does not run in WSL2" },
  { backend: "openshell-org", label: "Org OpenShell", ready: false },
];

test("candidates: offered rows that are not ready, with counts per state", () => {
  const c = setupCandidates(probe, summaries);
  assert.deepEqual(c.rows.map((r) => r.backend), ["landlock", "oci-runc", "cloud-hypervisor"]);
  assert.equal(c.count, 3);
  assert.equal(c.notEnabled, 1);
  assert.equal(c.needsModule, 1);
  assert.equal(c.other, 1);
  assert.equal(c.rows[0].next, "Turn on Landlock only");
});

test("candidates: no summaries means nothing to set up; no probe keeps the daemon's rows", () => {
  assert.equal(setupCandidates(probe, null).count, 0);
  const c = setupCandidates(null, summaries);
  assert.equal(c.count, 4);
  assert.ok(c.rows.every((r) => r.state === "unknown"));
});

test("the dialog's one line names the count", () => {
  assert.equal(setupLine(3), "Set up a sandbox backend (3 available to set up)");
});

test("the panel starts on the preselected row, else the first not ready", () => {
  assert.equal(defaultSetupBackend(summaries, "oci-runc"), "oci-runc");
  assert.equal(defaultSetupBackend(summaries, "nope"), "landlock");
  assert.equal(defaultSetupBackend([{ backend: "bwrap", label: "Bubblewrap", ready: true }]), "bwrap");
  assert.equal(defaultSetupBackend([]), undefined);
});

test("the row chooser labels each row's state", () => {
  assert.equal(summaryOptionLabel(summaries[0]), "Bubblewrap (set up)");
  assert.equal(summaryOptionLabel(summaries[1]), "Landlock only (next: Turn on Landlock only)");
  assert.equal(summaryOptionLabel(summaries[4]), "OpenShell (cannot run here)");
  assert.equal(summaryOptionLabel(summaries[5]), "Org OpenShell (not set up)");
});

test("op progress: a fraction and a line, unknown size handled", () => {
  assert.equal(opProgress(5, 10), 0.5);
  assert.equal(opProgress(5, 0), null);
  assert.equal(opProgress(20, 10), 1);
  assert.equal(opProgressLabel(2_000_000, 4_000_000), "2 of 4 MB (50%)");
  assert.equal(opProgressLabel(0, 0), "Starting");
  assert.equal(opProgressLabel(3_000_000, 0), "3 MB downloaded");
});

// ---------------------------------------------------------------------------
// Help (the dashboard's own drawer) and "afterwards" notes
// ---------------------------------------------------------------------------

// The docs anchors the Go prerequisite table carries, read from its source
// (internal/sandboxsetup/prereqs.go): a new anchor without a help entry here
// fails, so no step's help ever falls back to a page outside the dashboard.
function goDocsAnchors(): string[] {
  const src = readFileSync(new URL("../../../internal/sandboxsetup/prereqs.go", import.meta.url), "utf8");
  const block = /\/\/ Docs anchors\.\s*const \(([\s\S]*?)\n\)/.exec(src);
  assert.ok(block, "prereqs.go has no Docs anchors const block");
  return [...block[1].matchAll(/=\s*"([^"]+)"/g)].map((m) => m[1]);
}

test("help: every docs anchor of the prerequisite table maps to a help entry", () => {
  const anchors = goDocsAnchors();
  assert.ok(anchors.length >= 10, `read only ${anchors.length} anchors`);
  for (const a of anchors) {
    const id = SETUP_DOCS_HELP[a];
    assert.ok(id, `no help entry for docs anchor ${a}`);
    assert.ok(getHelp(id), `${a} maps to ${id}, which is not in the help registry`);
  }
  for (const a of Object.keys(SETUP_DOCS_HELP)) assert.ok(anchors.includes(a), `SETUP_DOCS_HELP names ${a}, which no remedy carries`);
});

test("help: every step-specific and overview entry exists, and lives under the Terminals page", () => {
  for (const id of [...Object.values(SETUP_PREREQ_HELP), ...Object.values(SETUP_DOCS_HELP), SETUP_OVERVIEW_HELP]) {
    const e = getHelp(id);
    assert.ok(e, `${id} is not in the help registry`);
    assert.match(id, /^glossary\.terminals_sandbox_setup/);
    for (const rel of e.related ?? []) assert.ok(getHelp(rel), `${id} relates to missing ${rel}`);
    assert.doesNotMatch([e.title, e.oneLiner, e.detail ?? ""].join("\n"), DASHES);
    assert.doesNotMatch([e.title, e.oneLiner, e.detail ?? ""].join("\n"), /github\.com/);
  }
});

test("help: a step opens its own entry, else its docs anchor's, else the overview", () => {
  assert.equal(setupHelpId({ prereq: "hosted-key", docs: "sandboxed-terminals.md#hosted-sandboxes-beta-e2b-modal-and-vercel-sandbox" }), "glossary.terminals_sandbox_setup_hosted_key");
  assert.equal(setupHelpId({ prereq: "enable", docs: "sandboxed-terminals.md#enabling-it" }), "glossary.terminals_sandbox_setup_enable");
  assert.equal(setupHelpId({ prereq: "bwrap", docs: "sandboxed-terminals.md#enabling-it" }), "glossary.terminals_sandbox_setup_bwrap");
  assert.equal(setupHelpId({ prereq: "runsc", docs: "sandboxed-terminals.md#gvisor-oci-runsc-beta" }), "glossary.terminals_sandbox_setup_gvisor");
  assert.equal(setupHelpId({ prereq: "orgshell-login", docs: "sandbox-openshell-org.md#turning-it-on" }), "glossary.terminals_sandbox_setup_org_shell");
  assert.equal(setupHelpId({ prereq: "mystery", docs: "nowhere.md#x" }), SETUP_OVERVIEW_HELP);
  assert.equal(setupHelpId({ prereq: "mystery" }), SETUP_OVERVIEW_HELP);
});

test("help: the key step's entry says where the key is pasted and that it is never shown again", () => {
  const e = getHelp("glossary.terminals_sandbox_setup_hosted_key");
  assert.ok(e?.detail);
  assert.match(e.oneLiner, new RegExp(CREDENTIAL_STORE_LABEL));
  for (const name of ["E2B_API_KEY", "MODAL_TOKEN_SECRET", "VERCEL_PROJECT_ID", "DOCKER_SANDBOXES_TOKEN", "DAYTONA_API_KEY", "INSTABOX_API_KEY"]) assert.match(e.detail, new RegExp(name));
  assert.match(e.detail, /Hosted sandboxes card/);
});

const afterCases: [string, RegExp][] = [
  ["relogin", /sign out and back in/],
  ["reboot", /restart the computer/],
  ["engine_restart", /container engine restarts/],
  ["daemon_restart", /restart Observer/],
];
for (const [after, want] of afterCases) {
  test(`after: ${after} names what to do`, () => {
    assert.match(afterNote(after) ?? "", want);
    assert.doesNotMatch(afterNote(after) ?? "", DASHES);
  });
}

test("after: nothing for none, an unknown value names itself", () => {
  assert.equal(afterNote(""), null);
  assert.equal(afterNote(undefined), null);
  assert.equal(afterNote("power_cycle"), "Afterwards: power cycle.");
});

test("consent folder: a consent step's run, repair and update send the picked folder; undo and other steps send none (review finding 7)", () => {
  const consent = step({ prereq: "hosted-consent", kind: "consent", class: "auto", channel: "hosted_consent" });
  const other = step({ prereq: "oci-image", class: "auto", channel: "oci_pull" });
  const rows: Array<[SandboxSetupStep, "run" | "undo" | "update" | "repair", string, string | undefined]> = [
    [consent, "run", "/home/dev/observer-workspace", "/home/dev/observer-workspace"],
    [consent, "repair", "/home/dev/proj", "/home/dev/proj"],
    [consent, "update", " /home/dev/proj ", "/home/dev/proj"],
    [consent, "undo", "/home/dev/proj", undefined],
    [consent, "repair", "", undefined],
    [other, "repair", "/home/dev/proj", undefined],
  ];
  for (const [s, action, picked, want] of rows) {
    assert.equal(consentFolderFor(s, action, picked), want, `${s.channel} ${action} ${JSON.stringify(picked)}`);
  }
});

test("consent folder: the picker shows for an unsettled consent step and for a Repair or Update, never for Undo alone", () => {
  const consent = step({ prereq: "hosted-consent", kind: "consent", class: "auto", channel: "hosted_consent" });
  assert.equal(consentNeedsFolder(consent, false, []), true);
  assert.equal(consentNeedsFolder(consent, true, [{ action: "repair", label: "Repair" }]), true);
  assert.equal(consentNeedsFolder(consent, true, [{ action: "undo", label: "Undo" }]), false);
  assert.equal(consentNeedsFolder(consent, true, []), false);
  assert.equal(consentNeedsFolder(step({ channel: "oci_pull" }), false, []), false);
});
