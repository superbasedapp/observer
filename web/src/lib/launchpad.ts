// launchpad.ts: the pure half of door A, the launchpad (docs/plans/
// local-dashboard-first-run-options-2026-11-18.md section 8, steps 3 and 4).
// "Start a coding agent" opens New terminal for one tool; on a fresh machine
// the launch needs three launch-policy opt-ins, which the dialog asks for as
// ONE previewed consent (POST /api/terminal/first-launch), then a guided
// install when the tool is missing, then the launch. The terminal then opens
// docked on the left with a live usage meter on the right.
//
// Every decision here is an ordered rule table walked top-down (CLAUDE.md
// rule 5), one test case per row in launchpad.test.ts. No imports, so node
// --test pins it directly; the components read only these results.

/**
 * SUGGESTED_FIRST_AGENTS is the operator's order for a fresh machine's
 * suggested agents (Claude Code, Codex, Gemini CLI, OpenCode). Only those the
 * integration registry can guided-install on this OS are shown.
 */
export const SUGGESTED_FIRST_AGENTS = ["claude-code", "codex", "gemini-cli", "opencode"] as const;

/** The part of a preflight reply the suggestion rule reads. */
export type SuggestionProbe = { install_command?: string } | null | undefined;

/**
 * suggestedFirstAgents keeps the suggested agents that this daemon can launch
 * and whose preflight names a guided install command (the registry has an
 * install plan on this OS), in the operator's order.
 */
export function suggestedFirstAgents(launchable: readonly string[], probes: Record<string, SuggestionProbe>): string[] {
  return SUGGESTED_FIRST_AGENTS.filter((t) => launchable.includes(t) && !!probes[t]?.install_command?.trim());
}

// ---------------------------------------------------------------------------
// The first-launch folder (operator rule): the most recent project from
// history, else a new empty ~/observer-playground, named in the consent and
// created only on consent.
// ---------------------------------------------------------------------------

/** Where the first-launch folder came from. */
export type FolderSource = "recent_project" | "playground" | "none";

/** The first-launch folder and why it was chosen. */
export type FirstLaunchFolder = { path: string; source: FolderSource };

/** A project row as GET /api/projects returns it (most recent first). */
export type HistoryProject = { root_path: string; last_seen?: string };

type FolderInput = { projects: readonly HistoryProject[]; playgroundPath: string };

function isAbsolute(p: string): boolean {
  return p.startsWith("/") || /^[A-Za-z]:[\\/]/.test(p);
}

/** mostRecentProject is the history project with the latest last_seen (list order breaks ties). */
function mostRecentProject(projects: readonly HistoryProject[]): string {
  let best = "";
  let bestSeen = "";
  for (const p of projects) {
    const root = p.root_path?.trim() ?? "";
    if (!isAbsolute(root)) continue;
    const seen = p.last_seen ?? "";
    if (!best || seen > bestSeen) {
      best = root;
      bestSeen = seen;
    }
  }
  return best;
}

const FOLDER_RULES: { source: FolderSource; pick: (i: FolderInput) => string }[] = [
  { source: "recent_project", pick: (i) => mostRecentProject(i.projects) },
  { source: "playground", pick: (i) => i.playgroundPath.trim() },
];

/** firstLaunchFolder walks FOLDER_RULES; "none" when neither yields a path. */
export function firstLaunchFolder(projects: readonly HistoryProject[], playgroundPath: string): FirstLaunchFolder {
  const input = { projects, playgroundPath };
  for (const r of FOLDER_RULES) {
    const path = r.pick(input);
    if (path) return { path, source: r.source };
  }
  return { path: "", source: "none" };
}

/**
 * homeShortPath writes a folder under the home directory as "~/..." for the
 * consent copy. The home directory is read off the playground path the route
 * named (home joined with "observer-playground"); anything else is left as is.
 */
export function homeShortPath(path: string, playgroundPath: string): string {
  const m = /^(.*)[\\/]observer-playground$/.exec(playgroundPath);
  if (!m || !m[1]) return path;
  const home = m[1];
  if (path === home) return "~";
  for (const sep of ["/", "\\"]) {
    if (path.startsWith(home + sep)) return "~/" + path.slice(home.length + 1).replace(/\\/g, "/");
  }
  return path;
}

// ---------------------------------------------------------------------------
// The consent: which launch-policy changes a first launch still needs. The
// server walks the same table (internal/intelligence/dashboard
// terminal_first_launch.go firstLaunchRules) and refuses a save whose list
// differs from the one the person saw.
// ---------------------------------------------------------------------------

/** One change the first-launch consent makes. */
export type ConsentChange = "allow_tool" | "allow_fresh" | "allow_folder" | "create_folder";

/** What the consent rules read. */
export type ConsentState = {
  /** The tool is on [terminal.launch].allowed_tools. */
  toolAllowed: boolean;
  /** [terminal.launch].allow_fresh_agent is on (unknown counts as off: the server decides). */
  freshOn: boolean;
  /** The launch folder; "" is the agent's default directory, which needs no allow-list entry. */
  folder: string;
  /** The folder is covered by allowed_project_roots. */
  folderPermitted: boolean;
  /** The folder is the playground and does not exist yet. */
  folderMissing: boolean;
};

export const CONSENT_RULES: { change: ConsentChange; needed: (s: ConsentState) => boolean }[] = [
  { change: "allow_tool", needed: (s) => !s.toolAllowed },
  { change: "allow_fresh", needed: (s) => !s.freshOn },
  { change: "allow_folder", needed: (s) => s.folder !== "" && !s.folderPermitted },
  { change: "create_folder", needed: (s) => s.folder !== "" && s.folderMissing },
];

/** consentChanges walks CONSENT_RULES. */
export function consentChanges(s: ConsentState): ConsentChange[] {
  return CONSENT_RULES.filter((r) => r.needed(s)).map((r) => r.change);
}

/**
 * consentTriggers reports whether the one-step consent is offered: the tool
 * is not allowed yet, or fresh launches are off. A folder alone keeps its own
 * "Allow this folder" step, as before.
 */
export function consentTriggers(changes: readonly ConsentChange[]): boolean {
  return changes.includes("allow_tool") || changes.includes("allow_fresh");
}

/** The consent heading: "To start Claude Code here, Observer will:". */
export function consentHeading(toolLabel: string): string {
  return `To start ${toolLabel} here, Observer will:`;
}

/**
 * consentLines is the consent's bullet list, one line per change, in table
 * order. A folder that is allowed and created is one line ("(created now)").
 */
export function consentLines(toolLabel: string, changes: readonly ConsentChange[], folder: string): string[] {
  const out: string[] = [];
  const creates = changes.includes("create_folder");
  for (const c of changes) {
    if (c === "allow_tool") out.push(`allow ${toolLabel} to launch from the dashboard`);
    else if (c === "allow_fresh") out.push("allow fresh launches");
    else if (c === "allow_folder") out.push(`allow the folder ${folder}${creates ? " (created now)" : ""}`);
    else if (c === "create_folder" && !changes.includes("allow_folder")) out.push(`create the folder ${folder}`);
  }
  return out;
}

/** The setting each change writes, for the consent's "exactly which settings" line. */
export const CONSENT_SETTING: Record<ConsentChange, string | null> = {
  allow_tool: "allowed_tools",
  allow_fresh: "allow_fresh_agent",
  allow_folder: "allowed_project_roots",
  create_folder: null,
};

/** consentSettings lists the [terminal.launch] keys the consent writes, in table order. */
export function consentSettings(changes: readonly ConsentChange[]): string[] {
  return changes.map((c) => CONSENT_SETTING[c]).filter((k): k is string => k !== null);
}

// ---------------------------------------------------------------------------
// The launchpad's steps: consent, then a guided install when the tool is
// missing, then the launch.
// ---------------------------------------------------------------------------

/** One step of a launchpad launch. */
export type LaunchpadStep = "consent" | "install" | "launch";

/** What the step rules read. */
export type StepsState = {
  /** The consent's changes (consentChanges), or [] once saved. */
  consent: readonly ConsentChange[];
  /** The preflight verdict says the tool is installed; null while unknown. */
  installed: boolean | null;
};

export const STEP_RULES: { step: LaunchpadStep; needed: (s: StepsState) => boolean }[] = [
  { step: "consent", needed: (s) => consentTriggers(s.consent) },
  { step: "install", needed: (s) => s.installed === false },
  { step: "launch", needed: () => true },
];

/** launchpadSteps walks STEP_RULES: the steps still ahead, in order. */
export function launchpadSteps(s: StepsState): LaunchpadStep[] {
  return STEP_RULES.filter((r) => r.needed(s)).map((r) => r.step);
}

/** isInstalledVerdict: the preflight verdicts that launch without an install. */
export function isInstalledVerdict(verdict: string | undefined): boolean | null {
  if (!verdict) return null;
  return verdict === "ok" || verdict === "ok_off_path" || verdict === "shadowed";
}

// ---------------------------------------------------------------------------
// The docked split and its meter.
// ---------------------------------------------------------------------------

/** What the split's terminal is running. */
export type SplitKind = "install" | "agent";

/** What splitForLaunch reads about one launch from the dialog. */
export type SplitLaunch = {
  /** The dialog was opened by openNewTerminalFor ("Start a coding agent"). */
  launchpad: boolean;
  /** The dock label the dialog gave the terminal ("claude-code", "codex install", "ssh · box"). */
  label: string;
  /** The terminal is a setup step the dialog resumes after (install, uninstall, sandbox setup). */
  resumes: boolean;
};

export const SPLIT_RULES: { kind: SplitKind | null; when: (l: SplitLaunch) => boolean }[] = [
  { kind: null, when: (l) => !l.launchpad },
  { kind: "install", when: (l) => l.resumes && l.label.endsWith(" install") },
  { kind: null, when: (l) => l.resumes },
  { kind: null, when: (l) => l.label.startsWith("ssh · ") },
  { kind: "agent", when: () => true },
];

/**
 * splitForLaunch decides whether a launch from the dialog opens in the docked
 * split: only a launchpad launch does, its guided install as "install" and the
 * agent as "agent". An uninstall, a sandbox setup step or an SSH shell (no
 * captured session to meter) keeps the normal terminal view, as does every
 * launch from a plain New terminal.
 */
export function splitForLaunch(l: SplitLaunch): SplitKind | null {
  for (const r of SPLIT_RULES) if (r.when(l)) return r.kind;
  return null;
}

/** The meter's state. Only "live" and "ended" show numbers. */
export type MeterPhase = "installing" | "installed" | "starting" | "waiting" | "live" | "ended";

/** What the meter rules read. */
export type MeterInput = {
  kind: SplitKind;
  /** The terminal's connection status from the dock. */
  status: string | undefined;
  /** The terminal is linked to a captured session. */
  correlated: boolean;
  /** The linked session has a captured turn, token or action. */
  hasActivity: boolean;
};

function ended(status: string | undefined): boolean {
  return status === "exited" || status === "error";
}

export const METER_RULES: { phase: MeterPhase; when: (i: MeterInput) => boolean }[] = [
  { phase: "installed", when: (i) => i.kind === "install" && ended(i.status) },
  { phase: "installing", when: (i) => i.kind === "install" },
  { phase: "ended", when: (i) => ended(i.status) },
  { phase: "starting", when: (i) => !i.correlated },
  { phase: "waiting", when: (i) => !i.hasActivity },
  { phase: "live", when: () => true },
];

/** meterPhase walks METER_RULES. */
export function meterPhase(i: MeterInput): MeterPhase {
  for (const r of METER_RULES) if (r.when(i)) return r.phase;
  return "live";
}

/** meterShowsNumbers: numbers only once real ones exist. */
export function meterShowsNumbers(phase: MeterPhase, hasActivity: boolean): boolean {
  return phase === "live" || (phase === "ended" && hasActivity);
}

/** The session detail fields the meter reads (GET /api/session/<id>). */
export type MeterSession = {
  model?: string;
  tokens?: { input?: number; output?: number; cache_read?: number; cache_creation?: number };
  per_model?: { model: string }[];
  cost_usd?: number;
  total_actions?: number;
  turn_count?: number;
  proxy_turn_count?: number;
};

/** The meter's numbers. */
export type MeterReading = {
  tokens: number;
  costUSD: number;
  /** Where the priced tokens came from, for the "est." tooltip. */
  costBasis: "proxy" | "transcript" | "mixed" | "none";
  model: string;
  /** Further models the session used ("+1"). */
  extraModels: number;
  actions: number;
  hasActivity: boolean;
};

function n(v: number | undefined): number {
  return typeof v === "number" && Number.isFinite(v) ? v : 0;
}

/** meterReading derives the meter's numbers from a session detail reply. */
export function meterReading(sd: MeterSession | null | undefined): MeterReading {
  const t = sd?.tokens ?? {};
  const tokens = n(t.input) + n(t.output) + n(t.cache_read) + n(t.cache_creation);
  const turns = n(sd?.turn_count);
  const proxied = n(sd?.proxy_turn_count);
  const costBasis = turns === 0 ? "none" : proxied >= turns ? "proxy" : proxied === 0 ? "transcript" : "mixed";
  const models = (sd?.per_model ?? []).map((m) => m.model).filter(Boolean);
  const model = sd?.model?.trim() || models[0] || "";
  const extraModels = new Set(models.filter((m) => m !== model)).size;
  const actions = n(sd?.total_actions);
  return {
    tokens,
    costUSD: n(sd?.cost_usd),
    costBasis,
    model,
    extraModels,
    actions,
    hasActivity: tokens > 0 || actions > 0 || turns > 0,
  };
}

/** The "est." tooltip for the meter's cost, by basis. */
export const COST_BASIS_NOTE: Record<MeterReading["costBasis"], string> = {
  proxy: "Estimated: priced from the token counts the proxy measured and the model price table. Not your bill.",
  transcript: "Estimated: priced from the token counts in the tool's transcript and the model price table. Not your bill.",
  mixed: "Estimated: priced from proxy-measured and transcript token counts and the model price table. Not your bill.",
  none: "No priced turn yet.",
};

/** The meter's sentence for each phase without numbers. */
export const METER_PHASE_TEXT: Record<MeterPhase, string> = {
  installing: "Installing. Numbers appear once the agent runs and you send a prompt.",
  installed: "Install finished. New terminal starts the agent next.",
  starting: "Starting. Numbers appear after your first prompt lands.",
  waiting: "Waiting for your first prompt.",
  live: "",
  ended: "This terminal ended.",
};

// ---------------------------------------------------------------------------
// Continuing after a step: once the consent is saved the dialog goes on by
// itself (guided install when the tool is missing, else the launch), and
// after a launchpad install it starts the agent. Never an install after an
// install, so a failed install cannot loop.
// ---------------------------------------------------------------------------

/** Why the dialog is continuing on its own. */
export type ContinueMode = "after_consent" | "after_install";

/** What the dialog does next on its own. */
export type ContinueAction = "wait" | "install" | "launch" | "stop";

/** What the continue rules read. */
export type ContinueInput = {
  mode: ContinueMode;
  /** The launch allow-list accepts the tool (the re-read after the save landed). */
  allowed: boolean;
  /** Something other than the install verdict holds Start (remote, sandbox, a step). */
  otherBlock: boolean;
  /** isInstalledVerdict of the preflight; null while unknown. */
  installed: boolean | null;
  /** The preflight also holds Start for this installed tool (e.g. a runtime too old). */
  verdictBlocks: boolean;
  /** The preflight offers a guided install the dashboard can run. */
  canInstall: boolean;
};

export const CONTINUE_RULES: { action: ContinueAction; when: (i: ContinueInput) => boolean }[] = [
  { action: "wait", when: (i) => !i.allowed },
  { action: "stop", when: (i) => i.otherBlock },
  { action: "wait", when: (i) => i.installed === null },
  { action: "launch", when: (i) => i.installed === true && !i.verdictBlocks },
  { action: "stop", when: (i) => i.installed === true },
  { action: "install", when: (i) => i.mode === "after_consent" && i.canInstall },
  { action: "stop", when: () => true },
];

/** continueAction walks CONTINUE_RULES. */
export function continueAction(i: ContinueInput): ContinueAction {
  for (const r of CONTINUE_RULES) if (r.when(i)) return r.action;
  return "stop";
}
