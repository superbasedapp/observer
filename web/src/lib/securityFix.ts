// securityFix is the Findings tab's "Fix with an agent" model (plan of
// record docs/plans/fix-findings-with-agent-plan-2026-11-13.md, sections 1,
// 2, 5 and 6): the shapes of GET /api/security/fix/plan and
// /api/security/fix/attempts, the selection -> query rule (one finding, a
// group's drill-down, or the current filter; the server reads its own rows
// and forces status=open), the task the New terminal dialog is opened with,
// and the attempt words. Pure: no fetch, no React.

import {
  findingsApiParams,
  groupDrillDown,
  type FindingGroup,
  type FindingsFilters,
  type FindingsGroupBy,
} from "./codeSecurityApi.ts";
import type { NewTerminalTask, TaskLaunchResponse } from "./terminalTask.ts";
import type { Tone } from "../../../shared/lib/tone.ts";

export { taskSeedLabel as fixSeedLabel } from "./terminalTask.ts";

export const FIX_PLAN_PATH = "/api/security/fix/plan";
export const FIX_LAUNCH_PATH = "/api/security/fix/launch";
export const FIX_ATTEMPTS_PATH = "/api/security/fix/attempts";

/** One project of the fix plan: one launch is one project. */
export type FixPlanProject = {
  project_root_hash: string;
  name: string;
  root_path: string;
  /** false: the folder is not on this machine, so a launch is refused. */
  on_disk: boolean;
  /** The open findings the selection holds in this project. */
  findings: number;
  /** How many of them the prompt lists (the rest are counted). */
  listed: number;
  /** The exact task prompt the agent gets. */
  prompt: string;
};

/** GET /api/security/fix/plan. projects is sorted most findings first. */
export type FixPlan = {
  confirm_token: string;
  total: number;
  /** The selection held more findings than the server reads at once. */
  truncated: boolean;
  projects: FixPlanProject[];
  /** Launchable terminal tool -> seed kind ("none": paste the task). */
  seeds: Record<string, string>;
};

export type FixAttemptFinding = { id: string; rule_id: string; status: string };

/** One row of GET /api/security/fix/attempts. */
export type FixAttempt = {
  id: string;
  created_at: string;
  tool: string;
  project_root_hash: string;
  project_name: string;
  handle: string;
  seeded: boolean;
  total: number;
  open: number;
  /** None of its findings is still open. */
  cleared: boolean;
  findings: FixAttemptFinding[];
};

export type FixAttemptsResponse = { attempts: FixAttempt[] };

/** FixSelection is what a "Fix with an agent" button hands the plan. */
export type FixSelection =
  | { kind: "finding"; id: string }
  | { kind: "filters"; filters: FindingsFilters }
  | { kind: "group"; by: Exclude<FindingsGroupBy, "none">; group: FindingGroup; filters: FindingsFilters };

/** fixSelectionFilters is the findings filters a non-finding selection
 *  resolves to (a group is its drill-down), or null for one finding. */
export function fixSelectionFilters(sel: FixSelection): FindingsFilters | null {
  switch (sel.kind) {
    case "finding":
      return null;
    case "filters":
      return sel.filters;
    case "group":
      return groupDrillDown(sel.by, sel.group, sel.filters);
  }
}

/** fixPlanQuery is the selection as the plan's query string (no leading
 *  "?"): finding=<id>, or exactly the params GET /api/security/findings
 *  takes for the filters, empty values left out. The launch POST sends the
 *  same string back. */
export function fixPlanQuery(sel: FixSelection): string {
  const qs = new URLSearchParams();
  const filters = fixSelectionFilters(sel);
  if (filters == null) {
    if (sel.kind === "finding") qs.set("finding", sel.id);
    return qs.toString();
  }
  for (const [k, v] of Object.entries(findingsApiParams(filters))) {
    if (v !== "") qs.set(k, v);
  }
  return qs.toString();
}

/** fixPlanPath is the plan read's URL. */
export function fixPlanPath(sel: FixSelection): string {
  const q = fixPlanQuery(sel);
  return q ? `${FIX_PLAN_PATH}?${q}` : FIX_PLAN_PATH;
}

/** fixLaunchBody is the task fields of POST /api/security/fix/launch; the
 *  New terminal dialog adds the agent choice. */
export function fixLaunchBody(sel: FixSelection, project: Pick<FixPlanProject, "project_root_hash">): Record<string, unknown> {
  return {
    query: sel.kind === "finding" ? "" : fixPlanQuery(sel),
    finding: sel.kind === "finding" ? sel.id : "",
    project_root_hash: project.project_root_hash,
  };
}

function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}

/** fixPlanHeadline is the plan's first line. */
export function fixPlanHeadline(plan: Pick<FixPlan, "total" | "truncated" | "projects">): string {
  if (plan.projects.length === 0) return "No open findings match this selection.";
  const count = plan.truncated ? `At least ${plural(plan.total, "open finding")}` : plural(plan.total, "open finding");
  return `${count} in ${plural(plan.projects.length, "project")}. One agent works on one project at a time.`;
}

/** fixProjectNote is a plan row's second line, or "" when there is nothing
 *  beyond the count to say. */
export function fixProjectNote(p: Pick<FixPlanProject, "on_disk" | "findings" | "listed">): string {
  const parts: string[] = [];
  if (!p.on_disk) parts.push("Not on this machine: a launch here would be refused");
  if (p.listed < p.findings) parts.push(`The prompt lists the ${p.listed} most severe; a rescan shows the rest`);
  return parts.join(". ");
}

/** fixTaskFor is the task the New terminal dialog is opened with for one
 *  plan project. */
export function fixTaskFor(
  sel: FixSelection,
  plan: Pick<FixPlan, "seeds" | "confirm_token">,
  project: FixPlanProject,
  onStarted?: (r: TaskLaunchResponse) => void,
): NewTerminalTask {
  const listed = project.listed < project.findings ? ` (the prompt lists ${project.listed})` : "";
  return {
    title: `Fix ${plural(project.findings, "Code security finding")}`,
    summary: `In ${project.name || project.root_path}${listed}. The agent gets the task below; a rescan shows whether each finding cleared.`,
    projectRoot: project.root_path,
    launchPath: FIX_LAUNCH_PATH,
    launchBody: fixLaunchBody(sel, project),
    seeds: plan.seeds,
    confirmToken: plan.confirm_token,
    onStarted,
  };
}

/** The attempt words of each finding status, with the pill tone. */
export const FIX_ATTEMPT_STATUS: Readonly<Record<string, { label: string; tone: Tone }>> = {
  open: { label: "open", tone: "warn" },
  not_reproduced: { label: "cleared on rescan", tone: "success" },
  fixed_verified: { label: "verified fixed", tone: "success" },
  suppressed: { label: "closed by triage", tone: "neutral" },
  accepted_risk: { label: "closed by triage", tone: "neutral" },
  false_positive: { label: "closed by triage", tone: "neutral" },
  missing: { label: "no longer recorded", tone: "neutral" },
};

/** fixAttemptStatus is a finding status's words and tone; an unknown status
 *  reads as itself, neutral. */
export function fixAttemptStatus(status: string): { label: string; tone: Tone } {
  return FIX_ATTEMPT_STATUS[status] ?? { label: status.replace(/_/g, " ") || "unknown", tone: "neutral" };
}

/** fixAttemptSummary is an attempt's one line of state. */
export function fixAttemptSummary(a: Pick<FixAttempt, "total" | "open" | "cleared">): string {
  if (a.total === 0) return "No findings recorded";
  if (a.cleared) return a.total === 1 ? "Cleared" : `All ${a.total} cleared`;
  return `${a.open} of ${a.total} still open`;
}

/** fixAttemptBreakdown counts an attempt's findings by status words, in the
 *  status table's order ("2 cleared on rescan · 1 open"). */
export function fixAttemptBreakdown(findings: FixAttemptFinding[]): string {
  const counts = new Map<string, number>();
  for (const f of findings) {
    const l = fixAttemptStatus(f.status).label;
    counts.set(l, (counts.get(l) ?? 0) + 1);
  }
  const order = [...new Set(Object.values(FIX_ATTEMPT_STATUS).map((s) => s.label))];
  const keys = [...counts.keys()].sort((x, y) => {
    const ix = order.indexOf(x);
    const iy = order.indexOf(y);
    return (ix < 0 ? order.length : ix) - (iy < 0 ? order.length : iy);
  });
  return keys.map((k) => `${counts.get(k)} ${k}`).join(" · ");
}

/** fixAttemptsPolling is whether the attempts list keeps refreshing: while
 *  any attempt still has an open finding. */
export function fixAttemptsPolling(r: FixAttemptsResponse | null | undefined): boolean {
  return (r?.attempts ?? []).some((a) => !a.cleared);
}
