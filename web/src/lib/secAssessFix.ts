// secAssessFix is the model view's two additions (depth plan
// docs/plans/security-assessments-depth-plan-2026-11-14.md, wave W6b, decision
// D24): "Fix with an agent" on a threat or a pen test finding, and the two
// file downloads (a Markdown report and the checked model as JSON). It holds
// the shapes of GET /api/security/assessments/fix, the rule that says which
// items offer a fix, the words of the fix dialog and of every refusal of the
// fix and export routes, the task the New terminal dialog is opened with, and
// the download's file name. Pure: no fetch, no React.
//
// The task is the server's. It is built from the stored, checked copy with
// Observer's own words and the places Observer found; nothing the assessment's
// agent wrote as prose is in it, and this file never builds or edits it. The
// dialog shows it, and the launch sends back only the digest of what was read.
// Nothing here changes a finding or the model.

import type { Tone } from "../../../shared/lib/tone.ts";
import type { NewTerminalTask, TaskLaunchResponse } from "./terminalTask.ts";
import { ASSESS_EXPORT_PATH, ASSESS_FIX_PATH, assessRefusalWords } from "./secAssess.ts";
import { MIT_STATE_WORDS, plural } from "./secAssessModel.ts";

export { ASSESS_EXPORT_PATH, ASSESS_FIX_PATH };

// ---- the wire shapes ----

/** The two kinds of item a fix can start from. */
export type AssessFixItemKind = "threat" | "finding";

/** The two reference states a place can be listed in (secassess.RefState.Located): the other states name no place that exists. */
export type AssessFixPlaceState = "found" | "exists";

/** One place the task lists. */
export type AssessFixPlace = { path: string; line?: number; end_line?: number; state: AssessFixPlaceState };

/** GET /api/security/assessments/fix?run=&item=: the task the agent would get, and what the dialog shows beside it. */
export type AssessFixPlan = {
  confirm_token: string;
  run: string;
  item: string;
  item_kind: AssessFixItemKind;
  /** Observer's band for the item, or "" when it has none. */
  band: "low" | "medium" | "high" | "critical" | "";
  project: { name: string; root_path: string; on_disk: boolean };
  /** The exact task the agent gets. Observer's wording; never the agent's prose. */
  prompt: string;
  prompt_sha256: string;
  /** The places the prompt lists (at most 20). */
  places: AssessFixPlace[];
  /** Located places the prompt does not list. */
  places_omitted: number;
  /** Observer's sentences for the dialog (they are not in the prompt). */
  notes?: string[];
  /** Launchable terminal tool -> seed kind ("none": the task is pasted). */
  seeds: Record<string, string>;
};

/** The two file formats of the export route. */
export type AssessExportFormat = "md" | "json";

// ---- paths ----

/** assessFixPlanPath is the plan read's URL for one item of a run's checked model. */
export function assessFixPlanPath(run: string, item: string): string {
  return `${ASSESS_FIX_PATH}?${new URLSearchParams({ run, item }).toString()}`;
}

/** assessExportPath is the download's URL for one run and format. */
export function assessExportPath(run: string, format: AssessExportFormat): string {
  return `${ASSESS_EXPORT_PATH}?${new URLSearchParams({ run, format }).toString()}`;
}

// ---- which items offer a fix ----

/** The part of a reference the fix rule reads. */
export type FixRefLike = { path?: string; state?: string } | null | undefined;

/** fixableItem is whether an item cites at least one place Observer found: a reference in the state found or exists with a path. It is the rule of the server (secassess.fixPlaces), so a button is offered exactly where a plan can be built; a reference the check did not locate names no place to point a fix at. */
export function fixableItem(refs: readonly FixRefLike[] | null | undefined): boolean {
  return (refs ?? []).some((r) => r != null && (r.state === "found" || r.state === "exists") && typeof r.path === "string" && r.path !== "");
}

// ---- the words of the dialog ----

/** The words of each place state: the model view's own words for the two located states, so a place reads the same here as in the table. */
export const FIX_PLACE_WORDS: Readonly<Record<AssessFixPlaceState, { label: string; tone: Tone }>> = {
  found: { label: MIT_STATE_WORDS.found.label, tone: MIT_STATE_WORDS.found.tone },
  exists: { label: MIT_STATE_WORDS.exists.label, tone: MIT_STATE_WORDS.exists.tone },
};

/** fixPlaceWords is a place state in words; a state this view does not know reads as the weaker one. */
export function fixPlaceWords(state: string | undefined): { label: string; tone: Tone } {
  return state === "found" ? FIX_PLACE_WORDS.found : FIX_PLACE_WORDS.exists;
}

/** fixPlaceText is "path:line" (or "path:line-end" for a range, or the bare path when no line is cited). */
export function fixPlaceText(p: Pick<AssessFixPlace, "path" | "line" | "end_line">): string {
  const path = p?.path ?? "";
  if (typeof p?.line !== "number" || p.line <= 0) return path;
  const end = typeof p.end_line === "number" && p.end_line > p.line ? `-${p.end_line}` : "";
  return `${path}:${p.line}${end}`;
}

/** fixItemWord is the kind of item in one word, for the dialog's lines. */
export function fixItemWord(kind: string | undefined): "Threat" | "Finding" {
  return kind === "finding" ? "Finding" : "Threat";
}

/** fixPlanHeadline is the dialog's first line: the item, Observer's band for it, how many places the task points at and how many cited places it does not list. */
export function fixPlanHeadline(plan: Pick<AssessFixPlan, "item" | "item_kind" | "band" | "places" | "places_omitted">): string {
  const n = plan.places?.length ?? 0;
  const band = plan.band ? ` (band ${plan.band})` : "";
  const left = plan.places_omitted ?? 0;
  const more = left > 0 ? ` ${left} more ${plural(left, "place", "places")} that Observer located ${plural(left, "is", "are")} not listed in the task.` : "";
  return `${fixItemWord(plan.item_kind)} ${plan.item}${band}. The task points the agent at ${n} ${plural(n, "place", "places")} in the project.${more}`;
}

/** fixPlanNotes are Observer's sentences the plan carries for the dialog, with anything that is not text left out. */
export function fixPlanNotes(plan: Pick<AssessFixPlan, "notes">): string[] {
  return (plan.notes ?? []).filter((s) => typeof s === "string" && s.trim() !== "");
}

/** The sentence under the prompt: what the next step is, that the agent edits the project, where the sandbox choice is made, and what the task is made of. */
export const FIX_NEXT_WORDS =
  "Next you pick the agent. Unless you choose a clone or a sandbox, it edits files in this project's live folder. The New terminal dialog's choices apply: the agent, its model, where the work happens and any sandbox. With no sandbox chosen the agent runs on this machine with your access.";

/** The sentence about what is in the task and what the fix does not do. */
export const FIX_TASK_WORDS =
  "The task is Observer's wording and the places listed above. Nothing the assessment's agent wrote as prose is in it. Nothing here changes the model or any finding: read the changes the agent makes before you keep them.";

/** The line under the button on a threat or finding. */
export const FIX_BUTTON_NOTE = "Starts a coding agent that edits this project, with a task built from the places cited here.";

/** The reason the dialog's Choose agent button is disabled, or null. */
export function fixChooseBlock(plan: Pick<AssessFixPlan, "project"> | null, dockReady: boolean, refreshing: boolean): string | null {
  if (!plan) return "The task has not been read yet";
  if (!plan.project.on_disk) return "This project's folder is not on this machine";
  if (!dockReady) return "The terminal dock is not available on this page";
  if (refreshing) return "The task is being read again";
  return null;
}

/** assessFixEnabled is whether the model view offers a fix: the stored copy holds a model and the run has ended. Until then the server refuses (run_running), so the button is not offered and a line says why. */
export function assessFixEnabled(hasModel: boolean, endedAt: string | null | undefined): boolean {
  return hasModel && typeof endedAt === "string" && endedAt !== "";
}

/** The note shown in place of the fix button while a run has not ended. */
export const FIX_AFTER_END_WORDS = "Fix with an agent is offered once the run has ended: a fix would change files the run's git check is still watching.";

// ---- refusals ----

/** The words of the codes the fix route sends that the shared table words for another route (the validate button's, the assessment launch's): the fix route says what is true for a fix. */
const FIX_WORDS: Readonly<Record<string, string>> = {
  run_running:
    "The run has not ended, and a fix would change files that its git check is watching. Nothing was started. Wait for the run to end, or stop it, then try again.",
  project_gone: "The project's folder is no longer on this machine, so there is nothing to fix there. Nothing was started.",
  plan_changed:
    "The task changed after you read it, because the stored model or the project changed. Nothing was started. Close this window, open Fix with an agent again to read the new task, then choose an agent.",
};

/** errorCode reads the machine code out of a refusal's JSON body, or "". */
function errorCode(e: unknown): string {
  const body = (e as { body?: unknown } | null)?.body;
  if (typeof body !== "string") return "";
  try {
    const j: unknown = JSON.parse(body);
    const c = (j as { code?: unknown } | null)?.code;
    return typeof c === "string" ? c : "";
  } catch {
    return "";
  }
}

/** isUnknownRun is whether the error is the plain-text 404 the routes answer for a run that is not listed. */
function isUnknownRun(e: unknown): boolean {
  const o = e as { status?: unknown; body?: unknown } | null;
  return o?.status === 404 && typeof o.body === "string" && o.body.trim() === "unknown run";
}

/** fixErrorWords is the words of a refused or failed read of a fix plan, or null when the error has none to give (then the caller says why in the error's own reason). A code with no row reads as the server's sentence. */
export function fixErrorWords(e: unknown): string | null {
  if (isUnknownRun(e)) return "This run is no longer listed.";
  const code = errorCode(e);
  if (Object.prototype.hasOwnProperty.call(FIX_WORDS, code)) return FIX_WORDS[code];
  return assessRefusalWords(e);
}

/** The codes a repeat of the same read cannot change: the item, the model or the folder is not there. */
const NO_RETRY_CODES: ReadonlySet<string> = new Set(["no_location", "unknown_item", "no_stored_model", "project_gone", "fix_too_large"]);

/** fixRetryHelps is whether reading the plan again can give another answer: false for a refusal that names something that is not there, true for a busy record, a run that has not ended yet, a timeout or a network failure. */
export function fixRetryHelps(e: unknown): boolean {
  if (isUnknownRun(e)) return false;
  return !NO_RETRY_CODES.has(errorCode(e));
}

/** fixRefusalText is the New terminal dialog's own words for a refusal of the fix launch: the fix route's words for a task that changed, a run that has not ended or a folder that is gone, and the shared words for the rest. null for any other failure, which shows the server's text as the dialog always has (the org terminal gate's 403, say). */
export function fixRefusalText(e: unknown): string | null {
  const status = (e as { status?: unknown } | null)?.status;
  if (status !== 404 && status !== 409) return null;
  return fixErrorWords(e);
}

// ---- the task ----

/** fixTaskFor is the task the New terminal dialog is opened with: the fix route is its launch route, and its body is the item and the digest of the task the developer read. The dialog adds the agent, the model and its own sandbox and workspace choices. No tool list is set (any terminal agent may be chosen) and no sandbox is chosen here. */
export function fixTaskFor(plan: AssessFixPlan, onStarted?: (r: TaskLaunchResponse) => void): NewTerminalTask {
  const n = plan.places?.length ?? 0;
  return {
    title: plan.item_kind === "finding" ? "Fix this finding" : "Fix this threat",
    summary: `In ${plan.project.name || plan.project.root_path}. The task points the agent at ${n} ${plural(n, "place", "places")}; the agent edits the project, and nothing here changes the model.`,
    projectRoot: plan.project.root_path,
    launchPath: ASSESS_FIX_PATH,
    launchBody: { run: plan.run, item: plan.item, prompt_sha256: plan.prompt_sha256 },
    seeds: plan.seeds ?? {},
    confirmToken: plan.confirm_token,
    refusalText: fixRefusalText,
    onStarted,
  };
}

// ---- the downloads ----

/** One download button: the format the route takes, the button's words, its test id and what the file is. */
export type ExportDownload = {
  format: AssessExportFormat;
  label: string;
  testId: string;
  /** The file extension of the attachment. */
  ext: string;
};

/** The two downloads, in the order of the footer's buttons. */
export const EXPORT_DOWNLOADS: readonly ExportDownload[] = [
  { format: "md", label: "Download report (Markdown)", testId: "assess-export-download-md", ext: "md" },
  { format: "json", label: "Download checked model (JSON)", testId: "assess-export-download-json", ext: "json" },
];

/** The sentence under the download buttons. */
export const EXPORT_DOWNLOAD_NOTE =
  "The downloads are rendered by Observer from the checked copy. They are not the agent's own report, and recognised secrets are hidden in them while hiding is on.";

/** The reason a download is unavailable when the run has no model to render. */
export const EXPORT_DOWNLOAD_NONE = "There is no model to download from this run.";

/** exportFileName is the downloaded file's name: the server's, read from Content-Disposition when it is a plain file name of this export, else a name built from the run and format. */
export function exportFileName(disposition: string | null | undefined, run: string, format: AssessExportFormat): string {
  const ext = format === "md" ? "md" : "json";
  const m = /filename="([^"\\/]+)"/.exec(disposition ?? "") ?? /filename=([^;"\\/\s]+)/.exec(disposition ?? "");
  if (m && new RegExp(`^observer-assessment-[A-Za-z0-9_-]{1,64}\\.${ext}$`).test(m[1])) return m[1];
  return `observer-assessment-${/^[A-Za-z0-9_-]{1,64}$/.test(run) ? run : "run"}.${ext}`;
}

/** exportErrorWords is what a refused download says. Nothing was saved, and it never reads as a file. */
export function exportErrorWords(status: number, body: string): string {
  const words = isUnknownRun({ status, body }) ? "This run is no longer listed." : assessRefusalWords({ status, body });
  if (words) return words.includes("Nothing was saved") ? words : `${words} Nothing was saved.`;
  return "The download could not be made. Nothing was saved.";
}
