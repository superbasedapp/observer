// scanSteps holds the pure helpers behind the Code security page's scan
// dialog, progress bar, job grid and last-scan summary (redesign plan
// docs/plans/code-security-page-redesign-plan-2026-11-06.md, sections 3.5,
// 4.2, 4.3): what each scanner step is in words, which steps a scan starts
// with, the start request's body, and the lines and cells a job shows.
// Pure: no fetch, no React.

import type { ScanStartBody, ScanJobTiming, ScanResultTiming } from "./codeSecurityApi.ts";
import { reasonWords, scanJobTotals } from "./codeSecurity.ts";
import type { ScanJob, ScanOnline, ScanResult, ScanStep } from "./codeSecurity.ts";

/** A job as the redesigned API returns it: the base job plus the timing fields. */
export type TimedJob = ScanJob & ScanJobTiming;
/** A step result with its timing. */
export type TimedResult = ScanResult & ScanResultTiming;

/** asTimed reads a job with the redesign's added fields. */
export function asTimed(job: ScanJob | null | undefined): TimedJob | null {
  return job ? (job as TimedJob) : null;
}

/** resultsOf is a project's step results with their timing. */
export function resultsOf(p: ScanJob["projects"][number]): TimedResult[] {
  return p.steps as TimedResult[];
}

/** The localStorage key that remembers the last scanner choice. */
export const SCAN_STEPS_KEY = "sbo.codeSecurity.scanSteps";

type StepInfo = { description: string; short: string };

const STEP_INFO: Readonly<Record<string, StepInfo>> = {
  history: { description: "Keys and tokens committed in each project's recent git history", short: "Secrets" },
  deps: { description: "Lockfiles against the local OSV database", short: "Dependencies" },
  code: { description: "Observer's code rules over Python, JavaScript, TypeScript and Go", short: "Code" },
  actionlint: { description: "GitHub workflow files", short: "Workflows" },
  "iac.trivy": { description: "Terraform, Kubernetes and Docker files", short: "IaC (Trivy)" },
  "iac.kics": { description: "Terraform, Kubernetes and Docker files", short: "IaC (KICS)" },
};

/** stepInfo describes a scanner step; an id nothing here knows gets its own
 *  label (or the id in words) and a generic description. */
export function stepInfo(id: string, label?: string): StepInfo {
  const known = STEP_INFO[id];
  if (known) return known;
  const name = label || reasonWords(id.replaceAll(".", " "));
  return { description: "Runs this scanner on each project", short: name };
}

/** scanStepReasonWords is a scanner step's not-ready reason in words. A
 *  scanner whose component is off reads "turned off" (the dialog's link goes
 *  to its switch), never the component key, as the Overview's problem list
 *  already says it. */
export function scanStepReasonWords(reason: string | undefined): string {
  if (/^not selected \(.+\)$/.test(reason ?? "")) return "turned off";
  return reasonWords(reason);
}

/** stepLabel is the name to show for a step id, from the node's step list first. */
export function stepLabel(id: string, steps: ScanStep[]): string {
  const s = steps.find((x) => x.id === id);
  return s?.label || stepInfo(id).short;
}

/** parseRemembered reads the stored choice: a list of step ids, else null. */
export function parseRemembered(raw: string | null | undefined): string[] | null {
  if (!raw) return null;
  try {
    const v: unknown = JSON.parse(raw);
    if (!Array.isArray(v)) return null;
    return v.filter((x): x is string => typeof x === "string");
  } catch {
    return null;
  }
}

/** defaultSteps are the step ids a fresh dialog checks: the remembered ones
 *  that are still ready, else every ready step. */
export function defaultSteps(steps: ScanStep[], remembered: string[] | null): string[] {
  const ready = steps.filter((s) => s.ready).map((s) => s.id);
  if (!remembered) return ready;
  const kept = ready.filter((id) => remembered.includes(id));
  return kept.length > 0 ? kept : ready;
}

/** scanStartBody builds the start request. steps goes out only when the
 *  choice is narrower than every ready step (an empty list means all);
 *  online goes out only when true (the dialog's "Also check online"). */
export function scanStartBody(opts: { all: boolean; projects: string[]; chosen: string[]; ready: string[]; online?: boolean }): ScanStartBody {
  const body: ScanStartBody = opts.all ? { all: true } : { projects: opts.projects };
  const every = opts.ready.length === opts.chosen.length && opts.ready.every((id) => opts.chosen.includes(id));
  if (!every) body.steps = opts.chosen;
  if (opts.online) body.online = true;
  return body;
}

// ---- the online dependency check (dashboard CLI parity plan, decision P-1) ----

/** The localStorage key that remembers the "Also check online" choice. */
export const SCAN_ONLINE_KEY = "sbo.codeSecurity.scanOnline";

/** parseRememberedOnline reads the stored online choice: on only for a stored true. */
export function parseRememberedOnline(raw: string | null | undefined): boolean {
  return raw === "true";
}

/** Where a closed online gate is fixed: the Package checks card for the
 *  gate's own reasons, the scanner switches for the driver. */
export type OnlineFix = "package-checks" | "scanners" | "none";

// ONLINE_REASONS: each reason the online check can be closed or not run
// for, in words, and where it is fixed. A reason not listed is spelled out
// and fixed nowhere in particular.
const ONLINE_REASONS: Readonly<Record<string, { words: string; fix: OnlineFix }>> = {
  online_checks_off: { words: "Online package checks are off", fix: "package-checks" },
  disclosure_not_shown: { words: "The online checks' disclosure has not been accepted", fix: "package-checks" },
  online_needs_scalibr: { words: "Only the SCALIBR dependency driver checks online, and it is not on", fix: "scanners" },
  online_unavailable: { words: "No online check could be set up for this project", fix: "none" },
  config_unreadable: { words: "The settings could not be read", fix: "none" },
};

/** onlineReasonWords is why the online check is closed or did not run. */
export function onlineReasonWords(reason: string | undefined): string {
  if (!reason) return "";
  return ONLINE_REASONS[reason]?.words ?? reasonWords(reason);
}

/** onlineFix is where a closed online gate is fixed. */
export function onlineFix(reason: string | undefined): OnlineFix {
  if (!reason) return "none";
  return ONLINE_REASONS[reason]?.fix ?? "none";
}

/** onlineFixLabel is the link text that goes to the fix, "" for none. */
export function onlineFixLabel(fix: OnlineFix): string {
  switch (fix) {
    case "package-checks":
      return "Turn on online checks in Scanners > Package checks";
    case "scanners":
      return "Turn on the SCALIBR driver in Scanners";
    default:
      return "";
  }
}

/** onlineSends says what leaves the machine when the online check runs:
 *  ecosystem, public package name and version (never a private name), and
 *  on an individual node each git submodule's pinned commit id. */
export function onlineSends(relay: boolean | undefined): string {
  if (relay) {
    return "Sends the ecosystem, public name and version of each package no local database covers to your organization's relay. Private package names are withheld. Git submodules are not checked online on a managed node.";
  }
  return "Sends the ecosystem, public name and version of each package no local database covers to api.osv.dev, and each git submodule's pinned commit id (never its URL or path). Private package names are withheld.";
}

/** The dialog's "Also check online" option: shown while the step it applies
 *  to is chosen; ticked only while the gate is open and the person wants
 *  it; otherwise disabled with why and where to fix it. */
export type OnlineOption = {
  show: boolean;
  enabled: boolean;
  checked: boolean;
  /** Why the box cannot be ticked, "" when it can. */
  blocked: string;
  fix: OnlineFix;
  sends: string;
};

/** onlineOption works out the dialog's online option. */
export function onlineOption(o: { online?: ScanOnline | null; chosen: readonly string[]; wanted: boolean }): OnlineOption {
  const off: OnlineOption = { show: false, enabled: false, checked: false, blocked: "", fix: "none", sends: "" };
  const st = o.online;
  if (!st || !o.chosen.includes(st.step)) return off;
  const sends = onlineSends(st.relay);
  if (!st.open) {
    return { show: true, enabled: false, checked: false, blocked: onlineReasonWords(st.reason) || "Online checks are not available", fix: onlineFix(st.reason), sends };
  }
  return { show: true, enabled: true, checked: o.wanted, blocked: "", fix: "none", sends };
}

/** onlineResultNote is a step result's online line: "" when the job did
 *  not ask for online checks on it, "checked online", or why not. */
export function onlineResultNote(r: Pick<ScanResult, "online">): string {
  if (!r.online) return "";
  if (r.online === "checked") return "checked online";
  const why = onlineReasonWords(r.online);
  return `not checked online: ${why.charAt(0).toLowerCase()}${why.slice(1)}`;
}

/** jobOnlineSuffix is " with online checks" for a job that asked for them. */
export function jobOnlineSuffix(job: Pick<ScanJob, "online">): string {
  return job.online ? " with online checks" : "";
}

/** scanChoiceProblem is why a scan cannot start from this choice, or "". */
export function scanChoiceProblem(c: { projectCount: number; stepCount: number; readyCount: number }): string {
  if (c.readyCount === 0) return "No scanner is ready on this node. Set one up in Scanners first.";
  if (c.projectCount === 0) return "Choose at least one project to scan.";
  if (c.stepCount === 0) return "Choose at least one scanner.";
  return "";
}

/** startLabel is the dialog's primary button text. */
export function startLabel(projectCount: number, stepCount: number): string {
  return `Scan ${projectCount} ${projectCount === 1 ? "project" : "projects"} with ${stepCount} ${stepCount === 1 ? "scanner" : "scanners"}`;
}

/** clockLabel formats a span as m:ss, or h:mm:ss from an hour. */
export function clockLabel(ms: number): string {
  const total = Math.max(0, Math.floor(ms / 1000));
  const s = total % 60;
  const m = Math.floor(total / 60) % 60;
  const h = Math.floor(total / 3600);
  const ss = String(s).padStart(2, "0");
  return h > 0 ? `${h}:${String(m).padStart(2, "0")}:${ss}` : `${m}:${ss}`;
}

/** elapsedLabel is the time since an ISO instant ("0:14"); "" when the
 *  instant is missing or unreadable. */
export function elapsedLabel(fromIso: string | undefined, nowMs: number): string {
  if (!fromIso) return "";
  const t = Date.parse(fromIso);
  if (!Number.isFinite(t)) return "";
  return clockLabel(nowMs - t);
}

/** jobDurationMs is how long a finished job ran, or null. */
export function jobDurationMs(job: ScanJob): number | null {
  if (!job.finished_at) return null;
  const a = Date.parse(job.started_at);
  const b = Date.parse(job.finished_at);
  if (!Number.isFinite(a) || !Number.isFinite(b)) return null;
  return Math.max(0, b - a);
}

function plural(n: number, one: string, many: string): string {
  return `${n} ${n === 1 ? one : many}`;
}

function outcomeTail(job: ScanJob): string {
  const t = scanJobTotals(job);
  const parts: string[] = [];
  if (t.new > 0) parts.push(plural(t.new, "new finding", "new findings"));
  else if (t.findings > 0) parts.push(`${plural(t.findings, "finding", "findings")}, none new`);
  else parts.push("no findings");
  if (t.failed > 0) parts.push(`${plural(t.failed, "scanner", "scanners")} failed`);
  return parts.join(", ");
}

/** jobResultLine is a finished job in one line: "Scanned 12 projects in
 *  3:41: 14 new findings, 1 scanner failed". */
export function jobResultLine(job: ScanJob): string {
  const dur = jobDurationMs(job);
  const inTime = dur == null ? "" : ` in ${clockLabel(dur)}`;
  const what = job.scope === "all" || job.projects.length !== 1 ? plural(job.total, "project", "projects") : job.projects[0].name;
  if (job.state === "cancelled") {
    return `Cancelled after ${job.done} of ${plural(job.total, "project", "projects")}${inTime}: ${outcomeTail(job)}`;
  }
  return `Scanned ${what}${inTime}: ${outcomeTail(job)}`;
}

/** runningParts are the pieces of the running line, in order: the where
 *  (projects done), the current project, the current step. */
export function runningParts(job: TimedJob, steps: ScanStep[]): string[] {
  const parts: string[] = [];
  if (job.scope === "all") {
    parts.push(`Scanning ${Math.min(job.done + 1, Math.max(job.total, 1))} of ${plural(job.total, "project", "projects")}`);
  } else {
    parts.push("Scanning");
  }
  const cur = job.current;
  if (cur?.name) parts.push(cur.name);
  if (cur) {
    const label = cur.step_id ? stepLabel(cur.step_id, steps) : cur.step;
    if (label) parts.push(label);
  }
  return parts;
}

/** jobStepIds are the scanner columns a job grid shows: the job's own list,
 *  else the ids its results used, in first-seen order. */
export function jobStepIds(job: TimedJob): string[] {
  if (job.steps && job.steps.length > 0) return job.steps;
  const seen: string[] = [];
  for (const p of job.projects) for (const r of p.steps) if (!seen.includes(r.id)) seen.push(r.id);
  return seen;
}

export type CellKind = "clean" | "findings" | "failed" | "skipped" | "waiting" | "running" | "other";
export type CellTone = "success" | "warn" | "danger" | "neutral" | "info";
export type Cell = { kind: CellKind; label: string; tone: CellTone; durationMs?: number };

/** cellOf is one grid cell: a result's outcome, or the step still to come or
 *  under way. */
export function cellOf(opts: { result?: TimedResult; running: boolean; jobRunning: boolean }): Cell {
  const r = opts.result;
  if (!r) {
    if (opts.running) return { kind: "running", label: "Running", tone: "info" };
    if (opts.jobRunning) return { kind: "waiting", label: "Waiting", tone: "neutral" };
    return { kind: "skipped", label: "Not run", tone: "neutral" };
  }
  const d = r.duration_ms != null ? { durationMs: r.duration_ms } : {};
  switch (r.outcome) {
    case "clean":
      return { kind: "clean", label: "Clean", tone: "success", ...d };
    case "findings":
      return {
        kind: "findings",
        label: r.new > 0 ? `${plural(r.findings, "finding", "findings")}, ${r.new} new` : plural(r.findings, "finding", "findings"),
        tone: "warn",
        ...d,
      };
    case "failed":
      return { kind: "failed", label: r.reason ? `Failed: ${reasonWords(r.reason)}` : "Failed", tone: "danger", ...d };
    case "busy":
      return { kind: "failed", label: "Busy", tone: "warn", ...d };
    case "skipped":
      return { kind: "skipped", label: r.reason ? `Skipped: ${reasonWords(r.reason)}` : "Skipped", tone: "neutral", ...d };
    case "not_scanned":
      return { kind: "skipped", label: r.reason ? `Not scanned: ${reasonWords(r.reason)}` : "Not scanned", tone: "neutral", ...d };
    case "unknown":
      return { kind: "other", label: "Unknown", tone: "warn", ...d };
    default:
      return { kind: "other", label: reasonWords(r.outcome), tone: "neutral", ...d };
  }
}

/** failedResults lists the step results that failed, with their reasons. */
export function failedResults(job: ScanJob, steps: ScanStep[]): { project: string; step: string; reason: string }[] {
  const out: { project: string; step: string; reason: string }[] = [];
  for (const p of job.projects) {
    for (const r of p.steps) {
      if (r.outcome === "failed" || r.outcome === "busy") {
        out.push({ project: p.name, step: stepLabel(r.id, steps) || r.label, reason: reasonWords(r.reason) || reasonWords(r.outcome) });
      }
    }
  }
  return out;
}
