// firstRunDoors - the pure half of the Overview welcome band (local dashboard
// first-run design, docs/plans/local-dashboard-first-run-options-2026-11-18.md
// section 8, steps 0 and 1). The band shows one of two doors:
//
//   - door B, history: this machine already has AI coding history. The band
//     reveals it while the watcher reads it (real capture progress from GET
//     /api/firstrun), then settles into "your AI coding at a glance" (GET
//     /api/firstrun/glance). Buttons: Start a coding agent, Take the tour.
//   - door A, fresh: nothing here yet. "Start a coding agent" leads; the tour
//     and the sample data are secondary.
//
// Every decision is an ordered rule table walked top-down (CLAUDE.md #5),
// pinned one case per row by firstRunDoors.test.ts. No JSX, no fetch, no
// storage access except through the injected Storage seam: the components
// under components/firstrun/ only render what this file decides.
//
// Honesty rules (binding, section 8.4): only real numbers; a counter moves
// only between two server readings; an estimate says "est."; a model with
// no price is "price unknown", never $0; an empty machine says so plainly.

import type { FirstRunCaptureState, FirstRunResponse, FirstRunTool } from "./firstRun.ts";

export const FIRST_RUN_GLANCE_PATH = "/api/firstrun/glance";

/** Per-browser "Not now" on the welcome band. */
export const WELCOME_BAND_DISMISS_KEY = "sb_welcome_band_dismissed";

// ---- wire shape: GET /api/firstrun/glance -----------------------------------

export type GlanceTool = { tool: string; name: string; sessions: number };

export type GlanceSpendState = "none" | "priced" | "unpriced";

export type GlanceResponse = {
  window_days: number;
  sessions: number;
  project_count: number;
  recent_sessions: number;
  tools: GlanceTool[];
  top_model?: { model: string; turns: number; share: number; models: number };
  spend: {
    state: GlanceSpendState;
    usd: number;
    tokens: number;
    priced_tokens: number;
    priced_turns: number;
    unpriced_turns: number;
    estimated: boolean;
  };
  busiest_project?: { name: string; root: string; sessions: number };
  rereads?: number;
  active_now?: { tool: string; name: string; project?: string };
  generated_at: string;
};

// ---- which door --------------------------------------------------------------

export type Door = "hidden" | "history" | "looking" | "fresh";

export type DoorInput = {
  /** The brief first-run read (null until it answers or when it failed). */
  brief: FirstRunResponse | null;
  /** The installer's ?connecting=1 hand-off is waiting (or ran out). */
  handoffActive: boolean;
  /** "Not now" was pressed in this browser. */
  dismissed: boolean;
};

type DoorRule = { name: string; when: (i: DoorInput) => boolean; door: Door };

const MOVING: ReadonlySet<FirstRunCaptureState> = new Set(["idle", "scanning"]);

/**
 * DOOR_RULES decides the band. Hidden first: during the hand-off the page
 * makes no decisions; with no first-run read (a remote viewer, an older
 * daemon) there is nothing honest to say. Then history wins as soon as any
 * session is captured or the scan has found files to read.
 */
export const DOOR_RULES: readonly DoorRule[] = [
  { name: "connect hand-off waiting", when: (i) => i.handoffActive, door: "hidden" },
  { name: "dismissed in this browser", when: (i) => i.dismissed, door: "hidden" },
  { name: "no first-run read", when: (i) => i.brief == null, door: "hidden" },
  { name: "sessions captured", when: (i) => (i.brief?.sessions ?? 0) > 0, door: "history" },
  {
    name: "history files found, being read",
    when: (i) => i.brief?.capture.state === "scanning" && (i.brief?.capture.files_found ?? 0) > 0,
    door: "history",
  },
  {
    name: "watcher still looking",
    when: (i) => !!i.brief?.watcher_running && MOVING.has(i.brief.capture.state),
    door: "looking",
  },
  { name: "nothing here", when: () => true, door: "fresh" },
];

export function doorOf(i: DoorInput): Door {
  for (const r of DOOR_RULES) if (r.when(i)) return r.door;
  return "hidden";
}

// ---- the reveal phase (door B) ----------------------------------------------

export type RevealPhase = "revealing" | "settled";

/** revealPhase: the band reveals while the watcher's first pass still moves. */
export function revealPhase(d: Pick<FirstRunResponse, "watcher_running" | "capture"> | null): RevealPhase {
  if (d && d.watcher_running && MOVING.has(d.capture.state)) return "revealing";
  return "settled";
}

// ---- the honest line ---------------------------------------------------------

function fmtN(n: number): string {
  return Math.max(0, Math.round(n)).toLocaleString("en-US");
}

function plural(n: number, noun: string): string {
  return `${fmtN(n)} ${noun}${n === 1 ? "" : "s"}`;
}

/** toolList names up to two tools, then "and N more". */
export function toolList(names: readonly string[]): string {
  const ns = names.filter((n) => n.trim() !== "");
  if (ns.length === 0) return "";
  if (ns.length === 1) return ns[0]!;
  if (ns.length === 2) return `${ns[0]} and ${ns[1]}`;
  return `${ns[0]}, ${ns[1]} and ${ns.length - 2} more`;
}

/**
 * toolsWithSessions lists the tools that have captured sessions, most first,
 * from the full first-run read's rows.
 */
export function toolsWithSessions(tools: readonly FirstRunTool[]): FirstRunTool[] {
  return tools
    .filter((t) => t.sessions > 0)
    .sort((a, b) => b.sessions - a.sessions || a.name.localeCompare(b.name));
}

/**
 * honestLine is the band's one-line summary: what is really on this
 * machine, in plain words. Tool names come from the full read when it has
 * answered; until then the line names the count only.
 */
export function honestLine(door: Door, brief: FirstRunResponse | null, toolNames: readonly string[]): string {
  const sessions = brief?.sessions ?? 0;
  const scanning = revealPhase(brief) === "revealing";
  switch (door) {
    case "history": {
      if (sessions === 0) return "We found AI coding history on this machine. Reading it now.";
      const from = toolList(toolNames);
      const tail = from ? ` from ${from}` : "";
      return scanning
        ? `We found ${plural(sessions, "session")}${tail} so far.`
        : `We found ${plural(sessions, "session")}${tail} on this machine.`;
    }
    case "looking":
      return "Looking for AI coding history on this machine.";
    case "fresh":
      return "No AI coding history here yet.";
    default:
      return "";
  }
}

// ---- "Start a coding agent": which tool to preselect ------------------------

/**
 * SUGGESTED_ORDER is the operator's order for suggested agents on a fresh
 * machine (Claude Code, Codex, Gemini CLI, OpenCode); it also breaks ties
 * between tools with the same session count.
 */
export const SUGGESTED_ORDER: readonly string[] = ["claude-code", "codex", "gemini-cli", "opencode"];

function suggestRank(tool: string): number {
  const i = SUGGESTED_ORDER.indexOf(tool);
  return i < 0 ? SUGGESTED_ORDER.length : i;
}

/**
 * startAgentTool picks the tool "Start a coding agent" preselects: the
 * most-used tool the New terminal picker offers, else a detected one in the
 * suggested order. null opens the dialog with no tool (its own default).
 */
export function startAgentTool(tools: readonly FirstRunTool[] | null | undefined): string | null {
  const offered = (tools ?? []).filter((t) => t.launchable && (t.detected || t.sessions > 0));
  if (offered.length === 0) return null;
  const best = [...offered].sort(
    (a, b) => b.sessions - a.sessions || suggestRank(a.tool) - suggestRank(b.tool) || a.tool.localeCompare(b.tool),
  )[0];
  return best?.tool ?? null;
}

// ---- the reveal's counters ---------------------------------------------------

export type RevealCounters = {
  sessions: number;
  projects: number;
  filesRead: number;
  filesFound: number;
  /** The overall share of found files handled, 0..1, or null when unknown. */
  ratio: number | null;
};

/** revealCounters reads the counters from one real reading. */
export function revealCounters(d: FirstRunResponse | null): RevealCounters {
  const c = d?.capture;
  const found = c?.files_found ?? 0;
  const handled = (c?.files_processed ?? 0) + (c?.files_failed ?? 0);
  return {
    sessions: d?.sessions ?? 0,
    projects: d?.project_count ?? 0,
    filesRead: c?.files_processed ?? 0,
    filesFound: found,
    ratio: c?.state === "done" ? 1 : found > 0 ? Math.min(1, handled / found) : null,
  };
}

/**
 * monotonic keeps a counter from stepping back between two readings of the
 * same scan (a reading served from an older cache entry): the shown value is
 * the larger real reading, never an invented one.
 */
export function monotonic(prev: number | null, next: number): number {
  if (prev == null || !Number.isFinite(prev)) return next;
  return Math.max(prev, next);
}

// ---- the settled card: "your AI coding at a glance" --------------------------

export type GlanceFact = {
  key: "sessions" | "model" | "spend" | "project" | "rereads";
  label: string;
  value: string;
  /** The small line under the value: the honesty caveat or the context. */
  sub: string;
  href: string;
};

/**
 * Formatting seam: the dashboard's one cost formatter (fmtCost) and whether
 * it renders dollars (dollarsShown; an organization can show its developers
 * token usage instead).
 */
export type Money = { format: (usd: number, tokens: number) => string; dollars: boolean };

type FactRule = {
  key: GlanceFact["key"];
  build: (g: GlanceResponse, money: Money) => GlanceFact | null;
};

function days(g: GlanceResponse): string {
  return `last ${g.window_days || 30} days`;
}

function spendFact(g: GlanceResponse, money: Money): GlanceFact | null {
  const sp = g.spend;
  if (sp.state === "none") return null;
  if (!money.dollars) {
    // Token usage view: every turn's tokens are real, priced or not.
    return {
      key: "spend",
      label: `Token usage, ${days(g)}`,
      value: money.format(0, sp.tokens),
      sub: `${plural(sp.priced_turns + sp.unpriced_turns, "turn")}.`,
      href: "/cost",
    };
  }
  const base = { key: "spend" as const, label: `Spend, ${days(g)}`, href: "/cost" };
  switch (sp.state) {
    case "priced": {
      const unpriced =
        sp.unpriced_turns > 0
          ? ` ${plural(sp.unpriced_turns, "turn")} on models with no price ${sp.unpriced_turns === 1 ? "is" : "are"} not counted.`
          : "";
      const how = sp.estimated ? "Estimated from token counts and list prices." : "As recorded by your tools.";
      return {
        ...base,
        value: `${money.format(sp.usd, sp.priced_tokens)}${sp.estimated ? " est." : ""}`,
        sub: `${how}${unpriced}`,
      };
    }
    case "unpriced":
      return {
        ...base,
        value: "price unknown",
        sub: `${plural(sp.unpriced_turns, "turn")}, all on models with no price yet.`,
      };
    default:
      return null;
  }
}

/**
 * GLANCE_FACTS is the settled card, in order: sessions (with tools and
 * projects), the most used model, the window's spend, the busiest project,
 * and the re-reads Discovery found. A fact with nothing true to say is left
 * out rather than shown as zero.
 */
export const GLANCE_FACTS: readonly FactRule[] = [
  {
    key: "sessions",
    build: (g) =>
      g.sessions > 0
        ? {
            key: "sessions",
            label: "Sessions",
            value: fmtN(g.sessions),
            sub: [
              g.tools.length > 0 ? `across ${plural(g.tools.length, "tool")}` : "",
              g.project_count > 0 ? plural(g.project_count, "project") : "",
            ]
              .filter(Boolean)
              .join(" · "),
            href: "/sessions",
          }
        : null,
  },
  {
    key: "model",
    build: (g) =>
      g.top_model
        ? {
            key: "model",
            label: "Most used model",
            value: g.top_model.model,
            sub: `${Math.round(g.top_model.share * 100)}% of turns, ${days(g)}`,
            href: "/cost",
          }
        : null,
  },
  { key: "spend", build: spendFact },
  {
    key: "project",
    build: (g) =>
      g.busiest_project && g.busiest_project.sessions > 0
        ? {
            key: "project",
            label: "Busiest project",
            value: g.busiest_project.name,
            sub: plural(g.busiest_project.sessions, "session"),
            href: "/projects",
          }
        : null,
  },
  {
    key: "rereads",
    build: (g) =>
      (g.rereads ?? 0) > 0
        ? {
            key: "rereads",
            label: "Unchanged files read again",
            value: fmtN(g.rereads ?? 0),
            sub: `${days(g)}. Each one costs tokens.`,
            href: "/discovery",
          }
        : null,
  },
];

export function glanceFacts(g: GlanceResponse | null, money: Money): GlanceFact[] {
  if (!g) return [];
  const out: GlanceFact[] = [];
  for (const r of GLANCE_FACTS) {
    const f = r.build(g, money);
    if (f) out.push(f);
  }
  return out;
}

/**
 * activeLine names the agent that was at work when the glance was read:
 * "Claude Code was working in app a few minutes ago." The card reads the
 * glance once, so the line says when, never "right now" (the live ribbon
 * is the surface that keeps up).
 */
export function activeLine(g: GlanceResponse | null): string {
  const a = g?.active_now;
  if (!a) return "";
  return a.project
    ? `${a.name} was working in ${a.project} in the last 15 minutes.`
    : `${a.name} was working in the last 15 minutes.`;
}

// ---- "Not now", kept per browser ---------------------------------------------

export type BandStorage = Pick<Storage, "getItem" | "setItem"> | null | undefined;

export function readBandDismissed(s: BandStorage): boolean {
  try {
    return s?.getItem(WELCOME_BAND_DISMISS_KEY) === "1";
  } catch {
    return false;
  }
}

export function writeBandDismissed(s: BandStorage): void {
  try {
    s?.setItem(WELCOME_BAND_DISMISS_KEY, "1");
  } catch {
    // Storage unavailable: hidden for this page view only.
  }
}
