// terminalTask is the New terminal dialog's task mode (fix findings with an
// agent, docs/plans/fix-findings-with-agent-plan-2026-11-13.md section 1):
// a caller opens the dialog with a task, and the dialog launches the chosen
// agent through the task's own route instead of POST /api/terminal/launch,
// in the task's project folder only. The task's route re-derives everything
// it needs from its own body (the dialog adds only the agent choice), so the
// dialog knows nothing about what the task is. Pure: no fetch, no React.

import type { ToolPickerItem } from "./toolPicker.ts";

/** TaskSeedKind is how a tool's TUI takes a first prompt on argv
 *  (integration.TaskSeedFor). "none" (or a tool the table does not name)
 *  means the terminal opens bare and the task is pasted. */
export type TaskSeedKind = "leading_positional" | "trailing_positional" | "trailing_after_dashdash" | "flag" | "none";

/** NewTerminalTask is what task mode is given. */
export type NewTerminalTask = {
  /** The banner's headline ("Fix 3 Code security findings"). */
  title: string;
  /** The banner's second line (the project and what the prompt lists). */
  summary: string;
  /** The project folder the launch runs in; the dialog shows it fixed. */
  projectRoot: string;
  /** The POST route that starts the launch. */
  launchPath: string;
  /** The task's own fields; the dialog adds tool, model and the sandbox fields. */
  launchBody: Record<string, unknown>;
  /** Tool id -> seed kind, for each picker row's label. */
  seeds: Record<string, string>;
  /** The confirm token the task's read minted (optional: the dialog falls
   *  back to the tab's own confirm token). */
  confirmToken?: string;
  /** The agents the picker may offer (tool ids), for a task whose route
   *  accepts only some of them (a sandboxed security assessment needs an
   *  agent that can be sandboxed and is routed through the proxy). Absent:
   *  any terminal agent. An empty list offers none. */
  allowedTools?: string[];
  /** Set for a task whose route chooses the sandbox itself (a security
   *  assessment): one sentence saying so. The dialog then hides its own
   *  Isolation and Workspace controls, sends no sandbox fields (the route
   *  derives them and refuses a launch it cannot confine), and shows this
   *  sentence in the banner. Absent: the dialog's own controls apply. */
  serverSandbox?: string;
  /** Called once the launch started (e.g. to refresh an attempts list). */
  onStarted?: (r: TaskLaunchResponse) => void;
  /** A task's own words for a refusal of its launch route, or null to show the
   *  server's text as the dialog always has. A security assessment uses it for
   *  "the task changed after you read it", which the server answers as JSON. */
  refusalText?: (e: unknown) => string | null;
};

/** TaskLaunchResponse is the task route's answer: the terminal launch
 *  response plus whether the prompt was typed in for the agent. */
export type TaskLaunchResponse = {
  token: string;
  tool: string;
  subcommand?: string;
  has_project_root?: boolean;
  seeded?: boolean;
  /** The task text, present only when it was not typed in (seeded false). */
  prompt?: string;
  attempt_id?: string;
};

/** Whether the task reaches the agent on start, per seed kind. A kind this
 *  table does not know is read as "paste": never claim a seed we cannot see. */
const SEEDED: Record<TaskSeedKind, boolean> = {
  leading_positional: true,
  trailing_positional: true,
  trailing_after_dashdash: true,
  flag: true,
  none: false,
};

/** The picker row label of each outcome. */
const SEED_LABELS = {
  seeded: "Starts on the task",
  paste: "Paste the task",
} as const;

/** taskSeeded is whether the tool is started with the task typed in. */
export function taskSeeded(seeds: Record<string, string>, tool: string): boolean {
  const kind = seeds[tool];
  return kind != null && (SEEDED as Record<string, boolean>)[kind] === true;
}

/** taskSeedLabel is the picker row's line for a tool in task mode. */
export function taskSeedLabel(seeds: Record<string, string>, tool: string): string {
  return taskSeeded(seeds, tool) ? SEED_LABELS.seeded : SEED_LABELS.paste;
}

/** taskLaunchBody is the task route's request: the task's own fields, then
 *  the dialog's agent choice (tool, model, the sandbox fields; an undefined
 *  value is left out). project_root is never sent: the task route derives
 *  the folder from its own fields. */
export function taskLaunchBody(task: Pick<NewTerminalTask, "launchBody">, choice: Record<string, unknown>): Record<string, unknown> {
  const body: Record<string, unknown> = { ...task.launchBody };
  for (const [k, v] of Object.entries(choice)) {
    if (k === "project_root" || v === undefined) continue;
    body[k] = v;
  }
  delete body.project_root;
  return body;
}

/** taskLaunchRequest is the task launch's route and JSON body (the dialog
 *  adds the confirm headers). */
export function taskLaunchRequest(
  task: Pick<NewTerminalTask, "launchPath" | "launchBody">,
  choice: Record<string, unknown>,
): { path: string; body: string } {
  return { path: task.launchPath, body: JSON.stringify(taskLaunchBody(task, choice)) };
}

/** taskPickerItems is the tool picker in task mode: terminal agents only (no
 *  IDE or desktop rows, no Shell, nothing unlaunchable), each with its seed
 *  label as the row's detail line. */
export function taskPickerItems(
  items: ToolPickerItem[],
  seeds: Record<string, string>,
  allowedTools?: readonly string[],
): ToolPickerItem[] {
  const allowed = allowedTools ? new Set(allowedTools) : null;
  return items
    .filter((i) => i.kind === "cli" && (allowed === null || allowed.has(i.value)))
    .map((i) => {
      const seed = taskSeedLabel(seeds, i.value);
      return { ...i, detail: i.detail ? `${seed} · ${i.detail}` : seed, searchable: `${i.searchable} ${seed.toLowerCase()}` };
    });
}

/** taskPasteText is the text the dialog keeps for copying after a launch:
 *  the prompt when the agent was not started on it, else null. */
export function taskPasteText(r: Pick<TaskLaunchResponse, "seeded" | "prompt">): string | null {
  if (r.seeded !== false) return null;
  const p = (r.prompt ?? "").trim();
  return p ? r.prompt ?? "" : null;
}
