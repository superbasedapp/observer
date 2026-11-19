// sandboxSetup.ts is the one owner of the sandbox setup panel's copy and
// decisions (sandbox installation lifecycle plan section 3.7), pure functions
// over the wire types in sandboxSetupTypes.ts, so the New Terminal dialog's
// inline panel and the Settings "Set up" / "Manage" panel can never word the
// same fact two ways. The server owns every decision that matters (a step's
// class after the switches, can_run, can_undo, the plan fingerprint); this
// module only phrases it. Dispatch is on a step's class, state and channel
// (its capability shape), never on a backend id.
//
// Copy rules (plan 3.7, the toolInstall.ts honesty convention): never a bare
// "unavailable", name the exact blocker and where the switch lives, never a
// raw `api <status>` string (DI-05), and no em or en dashes.

import type {
  SandboxSetupAction,
  SandboxSetupConsent,
  SandboxSetupPlan,
  SandboxSetupRecord,
  SandboxSetupStep,
  SandboxSetupSummary,
} from "./sandboxSetupTypes.ts";
import { backendState, offeredHere, type BackendStateName } from "./sandboxIsolation.ts";
import { INSTALL_STATUS_COPY, fmtInstallDate, installFailedRemedy } from "./toolUninstall.ts";
import type { SandboxAvailability } from "./types.ts";

// ---------------------------------------------------------------------------
// Sizes and versions
// ---------------------------------------------------------------------------

/** sizeMB renders a byte count in whole MB (decimal, never below 1), as the scanner cards do. */
export function sizeMB(bytes: number): string {
  return `${Math.max(1, Math.round((Number.isFinite(bytes) ? bytes : 0) / 1_000_000))}`;
}

/** versionLabel renders a version with exactly one leading "v" ("54.0" and "v54.0" read "v54.0"). */
export function versionLabel(version: string): string {
  const v = (version || "").trim().replace(/^v/i, "");
  return v ? `v${v}` : "an unknown version";
}

/** shortDigest is the first 12 hex characters of a sha256, the length people compare by eye. */
export function shortDigest(sha256: string): string {
  return (sha256 || "").trim().toLowerCase().slice(0, 12);
}

// ---------------------------------------------------------------------------
// Button labels (one per class)
// ---------------------------------------------------------------------------

/** The primary button's label per class; never has none (words and a docs link only). */
export const CLASS_BUTTON_LABELS: Record<string, string | null> = {
  auto: "Turn on",
  terminal: "Install in terminal",
  elevated: "Install in terminal (asks for your password)",
  guide: "Copy command",
  never: null,
};

/**
 * CHANNEL_BUTTON_LABELS name an auto step whose channel opens a setup
 * terminal rather than changing something in place, so a consent screen or a
 * sign-in never reads "Turn on".
 */
export const CHANNEL_BUTTON_LABELS: Record<string, string> = {
  hosted_consent: "Open the consent screen in terminal",
  orgshell_login: "Sign in in terminal",
};

/**
 * KIND_TERMINAL_VERBS name what a terminal or elevated step does by its kind,
 * so a step that starts a service or pulls an image never says "Install". A
 * kind absent here installs something (a program, a package).
 */
export const KIND_TERMINAL_VERBS: Record<string, string> = {
  service: "Start in terminal",
  image: "Pull in terminal",
  account: "Sign in in terminal",
  consent: "Open in terminal",
  os_feature: "Turn on in terminal",
};

/**
 * downloadButtonLabel is a pinned download's button: the size and version
 * the person agrees to before the click (the sha256 sits in the consent line
 * beside it).
 */
export function downloadButtonLabel(c: SandboxSetupConsent): string {
  return `Download and install (${sizeMB(c.bytes)} MB, ${versionLabel(c.version)})`;
}

/**
 * stepCopyText is what a guide step's "Copy command" copies: a credential
 * step's CLI form, or a display the daemon flags as a command line. A display
 * that is a sentence ("Install bubblewrap with your package manager") is
 * never offered as a command; null when there is nothing to copy.
 */
export function stepCopyText(step: SandboxSetupStep): string | null {
  if (step.command) return step.command;
  if (step.display_is_command && step.display) return step.display;
  return null;
}

/**
 * stepTakesInput reports a step whose action is typed in rather than
 * clicked (a provider's API key): it never gets a plain button, which would
 * send nothing and be refused.
 */
export function stepTakesInput(step: SandboxSetupStep): boolean {
  return step.channel === "hosted_connect";
}

/**
 * stepButtonLabel is the one button a step offers, or null for none. A step
 * that carries a download consent and runs in-process reads as a download;
 * a step that takes typed input has its own form instead; otherwise the
 * label follows the channel or the class. A guide step offers "Copy command"
 * only when it has a command to copy.
 */
export function stepButtonLabel(step: SandboxSetupStep): string | null {
  if (step.consent && step.class === "auto") return downloadButtonLabel(step.consent);
  if (stepTakesInput(step)) return null;
  if (step.class === "guide") return stepCopyText(step) ? CLASS_BUTTON_LABELS.guide : null;
  if (step.class === "auto" && step.action) return step.action;
  if (step.class === "auto" && CHANNEL_BUTTON_LABELS[step.channel]) return CHANNEL_BUTTON_LABELS[step.channel];
  const verb = KIND_TERMINAL_VERBS[step.kind];
  if (verb && step.class === "terminal") return verb;
  if (verb && step.class === "elevated") return `${verb} (asks for your password)`;
  if (!(step.class in CLASS_BUTTON_LABELS)) return null;
  return CLASS_BUTTON_LABELS[step.class];
}

/**
 * stepButtonRuns reports whether the step's button asks the daemon to run it
 * (true) or only copies its command (false). A runnable button shows only
 * when the server says can_run.
 */
export function stepButtonRuns(step: SandboxSetupStep): boolean {
  return step.class === "auto" || step.class === "terminal" || step.class === "elevated";
}

// ---------------------------------------------------------------------------
// State chips (one per state)
// ---------------------------------------------------------------------------

/** The chip tone a state reads in. */
export type ChipTone = "ok" | "warn" | "bad" | "info" | "muted";

/** STATE_CHIPS names every closed step state (sandboxsetup.StepState). */
export const STATE_CHIPS: Record<string, { label: string; tone: ChipTone }> = {
  done: { label: "Done", tone: "ok" },
  missing: { label: "Needed", tone: "warn" },
  unknown: { label: "Not checked yet", tone: "info" },
  blocked: { label: "Blocked on this machine", tone: "bad" },
  not_applicable: { label: "Not needed here", tone: "muted" },
  in_flight: { label: "In progress", tone: "info" },
  not_allowed: { label: "Not allowed by your organization", tone: "bad" },
};

/** stateChip is a step state's chip; an unknown state names itself plainly. */
export function stateChip(state: string): { label: string; tone: ChipTone } {
  return STATE_CHIPS[state] ?? { label: (state || "unknown").replaceAll("_", " "), tone: "info" };
}

// ---------------------------------------------------------------------------
// Consent line
// ---------------------------------------------------------------------------

/** SOURCE_LABELS names the closed download sources for people. */
export const SOURCE_LABELS: Record<string, string> = {
  vendor_release: "the vendor's release",
  org_mirror: "your organization's mirror",
  from_file: "a file on this machine",
};

/** sourceLabel names a download source. */
export function sourceLabel(source: string): string {
  return SOURCE_LABELS[source] ?? (source ? source.replaceAll("_", " ") : "an unnamed source");
}

/**
 * consentLine is what a person agrees to before a pinned download: the
 * version, the size in MB, the first 12 hex of the sha256 and the source.
 */
export function consentLine(c: SandboxSetupConsent): string {
  return (
    `Downloads ${versionLabel(c.version)} (${sizeMB(c.bytes)} MB) from ${sourceLabel(c.source)}, ` +
    `checked against sha256 ${shortDigest(c.sha256)} before it is installed.`
  );
}

// ---------------------------------------------------------------------------
// Errors (the closed codes of plan 3.6)
// ---------------------------------------------------------------------------

/** ERROR_SENTENCES maps every closed error code of the setup routes to a sentence. */
export const ERROR_SENTENCES: Record<string, string> = {
  plan_changed:
    "This machine changed since the plan was shown. The fresh plan is below: check the step and press its button again.",
  not_allowed_by_org:
    "Your organization does not allow this sandbox backend on this machine, so it cannot be set up here. Ask your organization's admin about its allowed backends.",
  install_disabled:
    "Guided install is switched off. Turn on \"Allow guided install and uninstall\" in Terminals > Settings > Fresh-agent launch policy, or run the step's command yourself in a terminal.",
  elevation_disabled:
    "Steps that ask for your password are switched off. Turn on \"Let a setup step ask for your password\" in Terminals > Settings > Sandbox isolation ([terminal.sandbox.setup].allow_elevated = true in ~/.observer/config.toml) to let the dashboard open them in a terminal, or copy the command and run it yourself.",
  consent_required:
    "The download needs your agreement to the version, size and checksum shown. Read the line above the button and press it again.",
  live_runs:
    "A sandboxed terminal is still running on this backend. Close it first, then try again.",
  step_not_runnable:
    "This step cannot run from here right now. Press Re-check for the current plan.",
  unknown_step: "This step is no longer in the plan. Press Re-check for the current plan.",
  not_in_build:
    "This Observer build cannot set up sandbox backends. Settings > Components lists the builds that include it.",
  terminal_unavailable:
    "The in-dashboard terminal is unavailable on this daemon, so there is nowhere to run the installer. Either [handoff].allow_dashboard_launch is false in ~/.observer/config.toml, or this OS has no PTY backend.",
};

/**
 * ELEVATED_GUIDE_HINT tells the person how a password step becomes a button
 * (operator ruling O1: [terminal.sandbox.setup].allow_elevated defaults to
 * false, so such a step reads as a guide step until they turn the key on).
 */
export const ELEVATED_GUIDE_HINT =
  "This command asks for your password, so the dashboard only shows it. To have the dashboard open it in a terminal where you type the password, turn on \"Let a setup step ask for your password\" in Terminals > Settings > Sandbox isolation ([terminal.sandbox.setup].allow_elevated = true in ~/.observer/config.toml), then press Re-check.";

/**
 * elevatedGuideHint is ELEVATED_GUIDE_HINT for a guide step whose command
 * elevates (sudo, or a Windows RunAs wrapper), else null. The plan's wire
 * shape carries no "degraded from elevated" flag, so the served command is
 * the evidence.
 */
export function elevatedGuideHint(step: SandboxSetupStep): string | null {
  if (step.class !== "guide" || !step.display) return null;
  return /^\s*sudo\s|-Verb\s+RunAs/i.test(step.display) ? ELEVATED_GUIDE_HINT : null;
}

/** STALE_TOKEN_MSG is the plain-text 403 of the confirm token check. */
export const STALE_TOKEN_MSG = "The dashboard's confirm token for this panel is stale. Reload the page and try again.";

/** NO_TOKEN_MSG is said when /api/remote/config hands out no confirm token. */
export const NO_TOKEN_MSG = "No confirm token. Reload the page.";

/** The parsed error body of a setup route: {"error", "code"} and, for plan_changed, the fresh plan. */
export type ParsedSetupError = { code: string; error: string; plan?: SandboxSetupPlan };

/** parseSetupError reads a setup route's JSON error body; a plain-text body yields its text as error. */
export function parseSetupError(body: string): ParsedSetupError {
  try {
    const j = JSON.parse(body) as { code?: unknown; error?: unknown; plan?: unknown };
    if (j && typeof j === "object") {
      const plan = j.plan && typeof j.plan === "object" ? (j.plan as SandboxSetupPlan) : undefined;
      return {
        code: typeof j.code === "string" ? j.code : "",
        error: typeof j.error === "string" ? j.error : "",
        ...(plan ? { plan } : {}),
      };
    }
  } catch {
    // Not JSON: the confirm token check and a proxy answer in plain text.
  }
  return { code: "", error: (body || "").trim() };
}

/**
 * setupErrorSentence turns a failed setup request into one named sentence.
 * The closed code wins; a code-less 403 naming the confirm token reads as a
 * stale token; otherwise the server's own sentence, else a status sentence.
 * Never a raw `api <status>` string.
 */
export function setupErrorSentence(status: number, body: string): string {
  const p = parseSetupError(body);
  if (p.code && ERROR_SENTENCES[p.code]) return ERROR_SENTENCES[p.code];
  if (status === 403 && /confirm token/i.test(p.error)) return STALE_TOKEN_MSG;
  if (status === 501) return ERROR_SENTENCES.not_in_build;
  if (status === 503) return ERROR_SENTENCES.terminal_unavailable;
  if (p.error) return p.error;
  return status > 0 ? `The setup request failed (HTTP ${status}).` : "The setup request could not reach the daemon.";
}

/**
 * setupRoutesAbsent reports an answer that means this node offers no setup
 * at all (the module's routes answer 404 component_not_installed, or 501 not
 * in this build): the panel then renders nothing.
 */
export function setupRoutesAbsent(status: number, body: string): boolean {
  if (status === 501) return true;
  return status === 404 && /component_not_installed/.test(body || "");
}

// ---------------------------------------------------------------------------
// Records and the "may be waiting for input" rule
// ---------------------------------------------------------------------------

/**
 * SETUP_INPUT_WAIT_MS mirrors internal/toolinstall.InputWaitAfter (90 s): an
 * install still running after it may be sitting at a prompt in its terminal.
 */
export const SETUP_INPUT_WAIT_MS = 90_000;

const IN_FLIGHT_STATUSES = new Set(["installing", "uninstalling"]);

/**
 * maybeWaitingForInput reports a record still in flight long enough that it
 * may be waiting at a prompt: the server's own flag, or 90 s since the
 * record's start (installed_at; uninstall_started_at for an uninstall).
 */
export function maybeWaitingForInput(rec: SandboxSetupRecord | undefined, nowMs: number): boolean {
  if (!rec || !IN_FLIGHT_STATUSES.has(rec.status)) return false;
  if (rec.maybe_waiting_for_input) return true;
  const started = rec.status === "uninstalling" ? rec.uninstall_started_at || rec.installed_at : rec.installed_at;
  const t = Date.parse(started || "");
  return Number.isFinite(t) && nowMs - t >= SETUP_INPUT_WAIT_MS;
}

/** The record line and its follow-up under a step. */
export type RecordView = {
  tone: "info" | "ok" | "warn";
  /** "Installed from this dashboard on <date>." and its siblings. */
  line: string;
  /** The next step after a failure or a missing result, else null. */
  remedy: string | null;
};

/**
 * recordView phrases a step's tool_installs record with the guided install's
 * own lifecycle copy (toolUninstall.ts), so a sandbox step and an agent
 * install read alike. A failed step names its exit code and the remedy.
 */
const INSTALLED_PREFIX = "Installed from this dashboard on ";
const LAST_RUN_PREFIX = "Last run from this dashboard on ";

// RUN_ONLY_CHANNELS are the channels whose terminal only runs one of
// Observer's own commands (the consent screen, the org-shell sign-in): nothing
// is installed, so their record reads as a run, never as an install with
// download-host advice.
const RUN_ONLY_CHANNELS = new Set<string>(["hosted_consent", "org_shell"]);

const RUN_STATUS_COPY: Record<string, { tone: "info" | "ok" | "warn"; line: (date: string) => string }> = {
  installing: { tone: "info", line: (d) => `Running from this dashboard (started ${d}).` },
  installed: { tone: "ok", line: (d) => `Done from this dashboard on ${d}.` },
  installed_not_found: { tone: "warn", line: (d) => `Run from this dashboard on ${d}; it finished, but its result is not detected yet.` },
  install_failed: { tone: "warn", line: (d) => `The run started from this dashboard on ${d} did not finish successfully.` },
  install_interrupted: { tone: "warn", line: (d) => `The run started from this dashboard on ${d} stopped before it finished.` },
};

// runRecordView phrases a run-only step's record (RUN_ONLY_CHANNELS).
function runRecordView(rec: SandboxSetupRecord): RecordView {
  const row = RUN_STATUS_COPY[rec.status];
  const date = fmtInstallDate(rec.installed_at);
  const line = row ? row.line(date) : `Run from this dashboard on ${date} (status: ${rec.status || "unknown"}).`;
  let remedy: string | null = null;
  if (rec.status === "install_failed") {
    const outcome = typeof rec.exit_code === "number" ? `It exited with code ${rec.exit_code}.` : "It failed.";
    remedy = `${outcome} Its own message is in the step's terminal output; fix what it says and run the step again.`;
  } else if (rec.status === "installed_not_found") {
    remedy = "Press Check this machine, or run the step again.";
  } else if (rec.status === "install_interrupted") {
    remedy = "The daemon restarted while it ran. Run it again.";
  }
  return { tone: row ? row.tone : "info", line, remedy };
}

export function recordView(rec: SandboxSetupRecord, stepDone = true): RecordView {
  if (RUN_ONLY_CHANNELS.has(rec.channel)) return runRecordView(rec);
  const row = INSTALL_STATUS_COPY[rec.status];
  const date = fmtInstallDate(rec.installed_at);
  let line = row ? row.line(date) : `Installed from this dashboard on ${date} (status: ${rec.status || "unknown"}).`;
  // A step that is not done now (its result was removed outside Observer)
  // reads its record as history, never "Installed" (D-R4-5).
  if (!stepDone && line.startsWith(INSTALLED_PREFIX)) line = LAST_RUN_PREFIX + line.slice(INSTALLED_PREFIX.length);
  let remedy: string | null = null;
  if (rec.status === "install_failed") remedy = installFailedRemedy(rec.exit_code);
  else if (rec.status === "installed_not_found") {
    remedy = "The step finished, but the dashboard does not detect its result yet. Press Check this machine, or run the step again.";
  } else if (rec.status === "install_interrupted") {
    remedy = "The step stopped before it finished (the daemon restarted). Run it again.";
  }
  return { tone: row ? row.tone : "info", line, remedy };
}

// ---------------------------------------------------------------------------
// Manage mode: Undo, Update, Repair
// ---------------------------------------------------------------------------

/** One Manage action a step offers. */
export type ManageAction = { action: "undo" | "update" | "repair"; label: string };

const PRESENT_STATUSES = new Set(["installed", "installed_not_found", "install_interrupted", "uninstall_failed", "uninstall_interrupted"]);

/** UNDO_ARMED_NOTE is the armed Undo's note for a step only this row uses. */
export const UNDO_ARMED_NOTE = "Reverses only what this dashboard did for this step.";

/**
 * undoArmedNote is the armed Undo's note: a step whose one setting other
 * hosted rows also read says, before it runs, which rows change with it
 * (the server's undo_also); every other step keeps UNDO_ARMED_NOTE.
 */
export function undoArmedNote(step: Pick<SandboxSetupStep, "undo_also">): string {
  const also = step.undo_also?.trim();
  return also ? `${UNDO_ARMED_NOTE} ${also}` : UNDO_ARMED_NOTE;
}

/**
 * manageActions are the Manage buttons a step offers, in order:
 *   - Update when the step is done, was placed by this dashboard, and the
 *     download it would fetch now differs from the one placed (the pin moved),
 *     or the server's reason says an update is available;
 *   - Repair when this dashboard set the step up and it no longer verifies
 *     (state missing with a record that says it was installed);
 *   - Undo when the server says the step can be undone.
 */
export function manageActions(step: SandboxSetupStep): ManageAction[] {
  const out: ManageAction[] = [];
  const rec = step.record;
  const placed = !!rec && PRESENT_STATUSES.has(rec.status);
  const pinMoved = !!rec?.digest && !!step.consent?.sha256 && rec.digest.toLowerCase() !== step.consent.sha256.toLowerCase();
  if (step.state === "done" && placed && (pinMoved || /update available/i.test(step.reason ?? ""))) {
    out.push({ action: "update", label: step.consent ? `Update to ${versionLabel(step.consent.version)}` : "Update" });
  }
  if (step.state === "missing" && placed) out.push({ action: "repair", label: "Repair" });
  if (step.can_undo) out.push({ action: "undo", label: "Undo" });
  return out;
}

/**
 * consentFolderFor is the folder a step's action sends (the run request's
 * from_file): a consent step's run, repair or update runs the consent screen
 * again and needs the folder the person picked; undo and every other step
 * send none. An empty pick sends none, so the daemon falls back to the
 * default workspace when it is set up.
 */
export function consentFolderFor(step: SandboxSetupStep, action: SandboxSetupAction, picked: string): string | undefined {
  if (step.channel !== "hosted_consent" || action === "undo") return undefined;
  const folder = picked.trim();
  return folder === "" ? undefined : folder;
}

/**
 * consentNeedsFolder reports whether a step shows the consent folder picker:
 * a consent step that is not settled yet, or one with a Manage action that
 * runs the consent screen again (repair, update).
 */
export function consentNeedsFolder(step: SandboxSetupStep, settled: boolean, actions: ManageAction[]): boolean {
  if (step.channel !== "hosted_consent") return false;
  return !settled || actions.some((a) => a.action !== "undo");
}

// ---------------------------------------------------------------------------
// The plan's headline
// ---------------------------------------------------------------------------

/** planHeadline is the one line above a plan's checklist. */
export function planHeadline(plan: SandboxSetupPlan): string {
  if (plan.blocked) return `${plan.label} cannot be set up on this machine: ${plan.blocked}`;
  if (plan.ready) return `${plan.label} is set up and runs here.`;
  if (plan.unconfirmed) return `${plan.label} is set up as far as Observer can see. Press Check this machine to confirm it runs here.`;
  const next = plan.next >= 0 ? plan.steps[plan.next] : undefined;
  return next ? `${plan.label} is not set up yet. Next: ${next.label}.` : `${plan.label} is not set up yet.`;
}

// ---------------------------------------------------------------------------
// The dialog's one line: setup candidates
// ---------------------------------------------------------------------------

/** One offered row on this host that is not ready yet. */
export type SetupCandidate = {
  backend: string;
  label: string;
  /** The next step's label, when the daemon names one. */
  next?: string;
  /** The row's setup is beta (the daemon's sentence). */
  beta?: string;
  /** The probe's state for the row ("unknown" when the probe does not list it). */
  state: BackendStateName | "unknown";
};

/** setupCandidates' answer: the rows and the counts the dialog's one line needs. */
export type SetupCandidates = {
  rows: SetupCandidate[];
  /** rows.length: "N available to set up". */
  count: number;
  /** Of those, how many only need enabling, need their module, or need more. */
  notEnabled: number;
  needsModule: number;
  other: number;
};

/**
 * setupCandidates returns the offered rows on this host that are not ready
 * and that setup can move forward: the daemon's summaries (one per offered
 * row on this host) less the ready ones, the ones that can never run here
 * (blocked) and the ones the probe says are not offered on this node. The
 * probe only classifies each row for the counts.
 */
export function setupCandidates(
  probe: SandboxAvailability | null,
  summaries: SandboxSetupSummary[] | null | undefined,
): SetupCandidates {
  const byId = new Map((probe?.backends ?? []).map((b) => [b.id, b]));
  const rows: SetupCandidate[] = [];
  for (const s of summaries ?? []) {
    if (s.ready || s.blocked) continue;
    const b = byId.get(s.backend);
    if (b && !offeredHere(b)) continue;
    const state: SetupCandidate["state"] = b ? backendState(b).state : "unknown";
    if (state === "available") continue;
    rows.push({
      backend: s.backend,
      label: s.label || b?.label || s.backend,
      ...(s.next ? { next: s.next } : {}),
      ...(s.beta ? { beta: s.beta } : {}),
      state,
    });
  }
  return {
    rows,
    count: rows.length,
    notEnabled: rows.filter((r) => r.state === "not_enabled").length,
    needsModule: rows.filter((r) => r.state === "needs_module").length,
    other: rows.filter((r) => r.state !== "not_enabled" && r.state !== "needs_module").length,
  };
}

/**
 * setupLine is the dialog's one line under the Isolation picker; each row
 * whose setup is beta is named after the count with "(beta)".
 */
export function setupLine(count: number, betaLabels: string[] = []): string {
  const line = `Set up a sandbox backend (${count} available to set up)`;
  return betaLabels.length > 0 ? `${line}: ${betaLabels.map(betaLabel).join(", ")}` : line;
}

/** betaLabel is a row's label with "(beta)" after it. */
export function betaLabel(label: string): string {
  return `${label} (beta)`;
}

/**
 * defaultSetupBackend is the row the panel starts on: the preselected one
 * when the daemon lists it, else the first row that is not ready and not
 * blocked, else the first row.
 */
export function defaultSetupBackend(summaries: SandboxSetupSummary[], preselected?: string): string | undefined {
  if (preselected && summaries.some((s) => s.backend === preselected)) return preselected;
  return (summaries.find((s) => !s.ready && !s.blocked) ?? summaries[0])?.backend;
}

/** summaryOptionLabel is a row in the panel's row chooser. */
export function summaryOptionLabel(s: SandboxSetupSummary): string {
  const label = s.beta ? betaLabel(s.label) : s.label;
  if (s.ready) return `${label} (set up)`;
  if (s.unconfirmed) return `${label} (set up, not checked)`;
  if (s.blocked) return `${label} (cannot run here)`;
  return s.next ? `${label} (next: ${s.next})` : `${label} (not set up)`;
}

/**
 * summaryFromPlan is the row chooser's list with the entry for plan's row
 * read from that plan (D-R4-3): after a check the label follows the checked
 * plan, not the passive summary fetched when the panel opened. Rows the plan
 * does not name are kept as they are.
 */
export function summaryFromPlan(rows: SandboxSetupSummary[], plan: SandboxSetupPlan | null): SandboxSetupSummary[] {
  if (!plan) return rows;
  return rows.map((r) => {
    if (r.backend !== plan.backend) return r;
    const next = plan.next >= 0 ? plan.steps[plan.next]?.label : undefined;
    return { ...r, ready: plan.ready, unconfirmed: plan.unconfirmed, blocked: plan.blocked, beta: plan.beta ?? r.beta, next };
  });
}

/** planInFlight reports a plan with a step still running. */
export function planInFlight(plan: SandboxSetupPlan | null): boolean {
  return !!plan?.steps.some((s) => s.state === "in_flight" || s.record?.status === "installing" || s.record?.status === "uninstalling");
}

/** One row of the re-probe table below. */
type ReprobeRule = { name: string; when: (prevInFlight: boolean | null, inFlight: boolean, resumed: boolean) => boolean; reprobe: boolean };

/**
 * REPROBE_RULES decide, top-down, whether a new plan in the setup panel asks
 * the New Terminal dialog to fetch the sandbox probe again (D-R4-2), so the
 * Isolation text follows a step that settled:
 *   - still_running: a step is still in flight: no.
 *   - step_settled: the plan before this one had a step in flight: yes.
 *   - first_after_resume: the first plan after the dialog came back from a
 *     setup terminal: yes (the step may have settled after the dialog's
 *     first probe).
 *   - otherwise: no.
 */
export const REPROBE_RULES: ReprobeRule[] = [
  { name: "still_running", when: (_p, inFlight) => inFlight, reprobe: false },
  { name: "step_settled", when: (p) => p === true, reprobe: true },
  { name: "first_after_resume", when: (p, _i, resumed) => p === null && resumed, reprobe: true },
  { name: "otherwise", when: () => true, reprobe: false },
];

/** setupSettleReprobe walks REPROBE_RULES. prevInFlight is null for the first plan. */
export function setupSettleReprobe(prevInFlight: boolean | null, inFlight: boolean, resumed: boolean): boolean {
  for (const r of REPROBE_RULES) if (r.when(prevInFlight, inFlight, resumed)) return r.reprobe;
  return false;
}

/**
 * summarySetUp reports a row whose button reads "Manage" rather than "Set
 * up": ready, or set up as far as the passive plan can see.
 */
export function summarySetUp(s: SandboxSetupSummary | undefined): boolean {
  return !!s && (s.ready || !!s.unconfirmed);
}

/**
 * UNKNOWN_RUNNABLE_HINT is said under a step Observer can run but that only
 * the check can judge (a service, an image): it gets its button after "Check
 * this machine" shows it is needed.
 */
export const UNKNOWN_RUNNABLE_HINT =
  "Only the check of this machine can tell whether this step is needed. Press Check this machine; if it is, its button appears here.";

/** unknownStepHint is UNKNOWN_RUNNABLE_HINT for such a step, else null. */
export function unknownStepHint(step: SandboxSetupStep): string | null {
  return step.state === "unknown" && stepButtonRuns(step) ? UNKNOWN_RUNNABLE_HINT : null;
}

/** opProgress is an in-process op's fraction done (0 to 1), or null when its size is unknown. */
export function opProgress(done: number, total: number): number | null {
  if (!(total > 0)) return null;
  return Math.min(1, Math.max(0, done / total));
}

/** opProgressLabel is the line beside an op's progress bar. */
export function opProgressLabel(done: number, total: number): string {
  const p = opProgress(done, total);
  if (p === null) return done > 0 ? `${sizeMB(done)} MB downloaded` : "Starting";
  return `${sizeMB(done)} of ${sizeMB(total)} MB (${Math.round(p * 100)}%)`;
}

// ---------------------------------------------------------------------------
// Credential steps (a provider's API key)
// ---------------------------------------------------------------------------

/** CREDENTIAL_STORE_LABEL is the key form's button. */
export const CREDENTIAL_STORE_LABEL = "Store in this machine's keychain";

/** CREDENTIAL_FORM_NOTE is said under the key form: where the key goes and that it never comes back. */
export const CREDENTIAL_FORM_NOTE =
  "Sent once to Observer on this computer and kept in its keychain, bound to the endpoint of the region saved for this provider. It is never shown again, never logged, and the field clears when you press the button.";

/** CREDENTIAL_STORED_NOTE is said once the daemon stored the key. */
export const CREDENTIAL_STORED_NOTE = "The key is stored in this machine's keychain.";

/**
 * credentialFields are the fields a credential step's form asks for, or
 * null when the step shows no form: it is not a typed-input step, it is done
 * or not needed, the daemon says it cannot run now (a step before it is
 * blocked, or the organization does not allow the backend), or the daemon
 * named no fields.
 */
export function credentialFields(step: SandboxSetupStep): string[] | null {
  if (!stepTakesInput(step) || !step.can_run) return null;
  if (step.state === "done" || step.state === "not_applicable") return null;
  const names = (step.fields ?? []).filter((n) => n.trim() !== "");
  return names.length > 0 ? names : null;
}

/**
 * credentialRunFields is the run request's fields: each named field's typed
 * value, trimmed, and nothing else.
 */
export function credentialRunFields(names: string[], values: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const n of names) out[n] = (values[n] ?? "").trim();
  return out;
}

/**
 * credentialErrorSentence phrases a refused key store. The daemon's own
 * refusal names a field, never a value (a missing field, a region the key
 * cannot be bound to), so it is shown as said; any other failure reads as
 * every setup failure does.
 */
export function credentialErrorSentence(status: number, body: string): string {
  const p = parseSetupError(body);
  if (p.code === "step_not_runnable" && p.error) return `The key was not stored: ${p.error.replace(/\.\s*$/, "")}.`;
  return setupErrorSentence(status, body);
}

/** joinNames lists names as "A", "A and B", "A, B and C". */
function joinNames(names: string[]): string {
  if (names.length <= 1) return names.join("");
  return `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`;
}

/**
 * credentialGuideNote is said under a credential step that became a guide
 * (guided installs are switched off): the command asks for the same values
 * and stores them the same way, and the Hosted sandboxes card's Connect form
 * is not affected by that switch. null for any other step.
 */
export function credentialGuideNote(step: SandboxSetupStep): string | null {
  if (step.kind !== "credential" || step.class !== "guide" || !step.command) return null;
  const names = step.fields ?? [];
  const what = names.length > 0 ? joinNames(names) : "the provider's key";
  return `Run it in a terminal of your own: it asks for ${what} and keeps ${names.length > 1 ? "them" : "it"} in this machine's keychain. The Connect form on the Hosted sandboxes card stores ${names.length > 1 ? "them" : "it"} too.`;
}

// ---------------------------------------------------------------------------
// Help (the dashboard's own help drawer) and "afterwards" notes
// ---------------------------------------------------------------------------

/** SETUP_HELP_LABEL is a step card's help link. */
export const SETUP_HELP_LABEL = "How this step works";

/**
 * SETUP_PREREQ_HELP names the help entry of a step whose subject is more
 * specific than its docs anchor (the generic module and enable steps, which
 * every backend shares, and the hosted steps, which share one anchor).
 */
export const SETUP_PREREQ_HELP: Record<string, string> = {
  component: "glossary.terminals_sandbox_setup_module",
  enable: "glossary.terminals_sandbox_setup_enable",
  "hosted-account": "glossary.terminals_sandbox_setup_hosted_account",
  "hosted-key": "glossary.terminals_sandbox_setup_hosted_key",
  "hosted-consent": "glossary.terminals_sandbox_setup_hosted_consent",
  "hosted-custody": "glossary.terminals_sandbox_setup_hosted_custody",
};

/**
 * SETUP_DOCS_HELP maps every docs anchor a setup remedy carries
 * (internal/sandboxsetup/prereqs.go, the docs constants) to the help entry
 * written from that docs section, so a step's help opens in the dashboard's
 * help drawer instead of a page outside it. sandboxSetup.test.ts reads
 * prereqs.go and fails when an anchor has no row here.
 */
export const SETUP_DOCS_HELP: Record<string, string> = {
  "sandboxed-terminals.md#enabling-it": "glossary.terminals_sandbox_setup_bwrap",
  "sandboxed-terminals.md#which-engine-which-socket": "glossary.terminals_sandbox_setup_engine",
  "sandboxed-terminals.md#the-default-image-on-this-machine-pull-and-revoked-images": "glossary.terminals_sandbox_setup_image",
  "sandboxed-terminals.md#gvisor-oci-runsc-beta": "glossary.terminals_sandbox_setup_gvisor",
  "sandboxed-terminals.md#landlock-only-process_lite-beta": "glossary.terminals_sandbox_setup_landlock",
  "sandboxed-terminals.md#microvm-sandboxes-cloud-hypervisor-beta": "glossary.terminals_sandbox_setup_vm",
  "sandboxed-terminals.md#the-probe": "glossary.terminals_sandbox_setup_kvm",
  "sandboxed-terminals.md#image-set-and-import": "glossary.terminals_sandbox_setup_vm_images",
  "sandboxed-terminals.md#native-windows-mxc-processcontainer-mxc-process-beta": "glossary.terminals_sandbox_setup_mxc",
  "sandboxed-terminals.md#the-mxc-files-as-a-signed-kind": "glossary.terminals_sandbox_setup_mxc_files",
  "sandboxed-terminals.md#macos-sandboxes-beta-seatbelt-and-apple-container": "glossary.terminals_sandbox_setup_macos",
  "sandboxed-terminals.md#hosted-sandboxes-beta-e2b-modal-and-vercel-sandbox": "glossary.terminals_sandbox_setup_hosted",
  "sandbox-openshell.md#what-you-need": "glossary.terminals_sandbox_setup_openshell",
  "sandbox-openshell.md#managed-gateway-mode-the-default": "glossary.terminals_sandbox_setup_openshell_gateway",
  "sandbox-openshell-org.md#turning-it-on": "glossary.terminals_sandbox_setup_org_shell",
  "sandboxed-terminals.md#the-isolation-engine-component-isolation": "glossary.terminals_sandbox_setup_module",
  "sandbox-credential-custody.md#the-four-custody-modes": "glossary.terminals_sandbox_setup_hosted_custody",
};

/** SETUP_OVERVIEW_HELP is the help entry about the checklist as a whole. */
export const SETUP_OVERVIEW_HELP = "glossary.terminals_sandbox_setup";

/**
 * setupHelpId is the help entry a step card opens: the step's own entry,
 * else its docs anchor's, else the checklist's overview (never a link out
 * of the dashboard).
 */
export function setupHelpId(step: Pick<SandboxSetupStep, "prereq" | "docs">): string {
  return SETUP_PREREQ_HELP[step.prereq] ?? SETUP_DOCS_HELP[(step.docs ?? "").trim()] ?? SETUP_OVERVIEW_HELP;
}

/** AFTER_NOTES says what the person does once a step ran (the closed After vocabulary). */
export const AFTER_NOTES: Record<string, string> = {
  relogin: "Afterwards, sign out and back in so the change applies to your account.",
  reboot: "Afterwards, restart the computer (or WSL) so the change takes effect.",
  engine_restart: "Afterwards, the container engine restarts; containers it runs stop.",
  daemon_restart: "Afterwards, restart Observer so it picks the change up.",
};

/** afterNote is a step's "afterwards" sentence, or null for none. */
export function afterNote(after: string | undefined): string | null {
  if (!after) return null;
  return AFTER_NOTES[after] ?? `Afterwards: ${after.replaceAll("_", " ")}.`;
}
