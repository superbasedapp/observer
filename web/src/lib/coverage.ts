// coverage - the pure half of the Tools page Coverage tab and the Overview
// "Tool coverage" card (T-935): every supported AI tool, whether it was found
// on this machine, how it is captured, how far its history capture got, and
// the one next step for anything not connected. No JSX, no fetch: pinned by
// coverage.test.ts.
//
// Two sources, one row shape:
//   - GET /api/firstrun?all=1 (owner-local): the first-run model with every
//     supported tool listed (internal/captureprogress for the history state).
//   - GET /api/tools/status (view): what a remote viewer may read when the
//     owner-local route is refused. It has no history, session or project
//     facts, so those stay null (unknown), never zero.
//
// Every rule reads capability facts the server already computed (detected,
// enabled, the probes, the wiring, launchable); none names a tool.

import { historyBadge, type FirstRunHistory, type FirstRunProbe, type FirstRunResponse, type Tone } from "./firstRun.ts";
import type { ToolStatusRow, ToolsStatusResponse, ToolWiring } from "./types";

/** The coverage read: the first-run model with every supported tool listed. */
export const COVERAGE_PATH = "/api/firstrun";
export const COVERAGE_PARAMS = { all: "1" } as const;
/** The remote-viewer fallback read (the Connected-tools matrix). */
export const COVERAGE_FALLBACK_PATH = "/api/tools/status";
/** Where the full list lives; the Overview card links here. */
export const COVERAGE_HREF = "/tools?tab=coverage";
/** Poll cadence while history capture is still moving. */
export const COVERAGE_POLL_MS = 5000;

export type CoverageSource = "local" | "remote";

/** One tool in the coverage list, from either source. */
export type CoverageRow = {
  tool: string;
  name: string;
  /** Found here: its session folder exists or it already has captured data. */
  found: boolean;
  detectedPath?: string;
  enabled: boolean;
  /** The watcher reads its session files; null when the source cannot say. */
  watcherActive: boolean | null;
  hooks?: FirstRunProbe;
  mcp?: FirstRunProbe;
  proxy?: FirstRunProbe;
  /** History capture state; null when the source cannot say (remote). */
  history: FirstRunHistory | null;
  sessions: number | null;
  projects: number | null;
  /** Captured actions (remote source only; the local one counts sessions). */
  actions: number | null;
  lastSeenAt?: string;
  wiring?: ToolWiring;
  /** The New terminal picker offers it, and so its guided install. */
  launchable: boolean;
};

/** rowsFromFirstRun maps the owner-local read onto coverage rows. */
export function rowsFromFirstRun(d: FirstRunResponse): CoverageRow[] {
  return (d.tools ?? []).map((t) => ({
    tool: t.tool,
    name: t.name || t.tool,
    found: t.detected || t.sessions > 0 || (t.history?.files_found ?? 0) > 0,
    detectedPath: t.detected_path || undefined,
    enabled: t.enabled,
    watcherActive: t.watcher_active,
    hooks: t.hooks,
    mcp: t.mcp,
    proxy: t.proxy,
    history: t.history ?? null,
    sessions: t.sessions,
    projects: t.projects,
    actions: null,
    lastSeenAt: t.last_seen_at || undefined,
    wiring: t.wiring,
    launchable: t.launchable === true,
  }));
}

/**
 * rowsFromToolsStatus maps the remote-viewer fallback onto coverage rows.
 * `nameOf` turns a tool id into its display name (lib/tools toolMeta in the
 * app; injected so this module stays importable under node --test).
 */
export function rowsFromToolsStatus(d: ToolsStatusResponse, nameOf: (tool: string) => string): CoverageRow[] {
  return (d.tools ?? []).map((r: ToolStatusRow) => ({
    tool: r.tool,
    name: nameOf(r.tool) || r.tool,
    found: r.detected || r.action_count > 0,
    detectedPath: r.detected_path || undefined,
    enabled: r.enabled,
    watcherActive: null,
    hooks: r.hooks,
    mcp: r.mcp,
    proxy: r.proxy,
    history: null,
    sessions: null,
    projects: null,
    actions: r.action_count,
    lastSeenAt: r.last_seen_at || undefined,
    wiring: r.wiring,
    // The guided install is an owner-local action; a remote view never
    // offers it.
    launchable: false,
  }));
}

// ---- the status of one row -------------------------------------------------

export type CoverageState = "attention" | "off" | "reading" | "capturing" | "idle" | "not_found";

export type CoverageStatus = { state: CoverageState; label: string; tone: Tone };

/** isCapturing: some capture path is live for the row right now. */
export function isCapturing(r: CoverageRow): boolean {
  if (!r.found || !r.enabled) return false;
  if (r.hooks?.registered || r.proxy?.registered) return true;
  // The remote source cannot see the watcher; an enabled, found tool is read
  // by the daemon serving this dashboard.
  return r.watcherActive ?? true;
}

// Ordered: the first row whose `when` holds decides (CLAUDE.md #5).
const STATUS_RULES: ReadonlyArray<{ when: (r: CoverageRow) => boolean; status: (r: CoverageRow) => CoverageStatus }> = [
  { when: (r) => !r.found, status: () => ({ state: "not_found", label: "Not found", tone: "neutral" }) },
  { when: (r) => !r.enabled, status: () => ({ state: "off", label: "Capture off", tone: "warn" }) },
  {
    when: (r) => r.history?.state === "failed" || r.history?.state === "not_running",
    status: (r) => ({ state: "attention", ...historyBadge(r.history!.state) }),
  },
  { when: (r) => r.history?.state === "scanning", status: () => ({ state: "reading", label: "Reading history", tone: "accent" }) },
  { when: isCapturing, status: () => ({ state: "capturing", label: "Capturing", tone: "success" }) },
  { when: () => true, status: () => ({ state: "idle", label: "Not capturing", tone: "neutral" }) },
];

/** coverageStatus is a row's status badge. */
export function coverageStatus(r: CoverageRow): CoverageStatus {
  const rule = STATUS_RULES.find((x) => x.when(r)) ?? STATUS_RULES[STATUS_RULES.length - 1];
  return rule.status(r);
}

// ---- how a row is captured --------------------------------------------------

/** One "how is this captured" chip. */
export type CoverageChip = { key: string; label: string; tone: Tone; title: string };

function probeChip(key: string, name: string, p: FirstRunProbe | undefined, optional: string): CoverageChip | null {
  if (!p || p.no_hooks || p.unprobed) return null;
  if (p.registered) {
    return { key, label: p.via_plugin ? `${name} on (plugin)` : `${name} on`, tone: "success", title: p.detail || `${name} point at SuperBased.` };
  }
  if (p.partial) return { key, label: `${name} partly on`, tone: "warn", title: p.detail || `Some ${name.toLowerCase()} point at SuperBased.` };
  return { key, label: `${name} off`, tone: "neutral", title: p.detail ? `${optional} ${p.detail}` : optional };
}

/**
 * coverageChips lists the capture paths of a found tool: session files (the
 * watcher), hooks, MCP and the proxy route. An integration the tool does not
 * have is left out (n/a is not "off"); a tool not found here gets none.
 */
export function coverageChips(r: CoverageRow): CoverageChip[] {
  if (!r.found) return [];
  const out: CoverageChip[] = [];
  if (r.watcherActive === true || (r.watcherActive === null && r.enabled)) {
    out.push({ key: "files", label: "Session files", tone: "success", title: "The watcher reads this tool's session files." });
  } else {
    out.push({
      key: "files",
      label: "Session files off",
      tone: "neutral",
      title: r.history?.reason || "The watcher is not reading this tool's files.",
    });
  }
  const chips = [
    probeChip("hooks", "Hooks", r.hooks, "Hooks add live events and guardrails."),
    probeChip("mcp", "MCP", r.mcp, "Optional. Lets the tool ask SuperBased about your project."),
    r.proxy
      ? r.proxy.registered
        ? { key: "proxy", label: "Proxy routed", tone: "success" as Tone, title: r.proxy.detail || "Requests go through the local proxy." }
        : { key: "proxy", label: "Proxy not routed", tone: "neutral" as Tone, title: "Optional. Routing through the proxy adds exact token counts." }
      : null,
  ];
  for (const c of chips) if (c) out.push(c);
  return out;
}

// ---- the next step ------------------------------------------------------------

/** The one next step a row offers. */
export type NextStep =
  /** Open the New terminal dialog with the tool picked (its guided install). */
  | { kind: "install"; label: string; detail: string }
  /** Go to an existing dashboard action. */
  | { kind: "link"; label: string; href: string; detail: string }
  /** Nothing to click; the detail says what happens next. */
  | { kind: "note"; detail: string };

/** The Settings > Connected tools deep link for one tool (T-421). */
export function connectedToolsHref(tool?: string, open?: "setup" | "doctor"): string {
  const p = new URLSearchParams({ section: "tools" });
  if (tool) p.set("tool", tool);
  if (tool && open) p.set("open", open);
  return `/settings?${p.toString()}`;
}

function wants(p: FirstRunProbe | undefined): boolean {
  return !!p && !p.registered && !p.no_hooks && !p.unprobed;
}

// Ordered: the first row whose `when` holds decides; a row with no match is
// connected and offers nothing.
const NEXT_RULES: ReadonlyArray<{ name: string; when: (r: CoverageRow) => boolean; step: (r: CoverageRow) => NextStep }> = [
  {
    name: "not found, guided install offered",
    when: (r) => !r.found && r.launchable,
    step: () => ({
      kind: "install",
      label: "Install",
      detail: "Not found here. Install it from a new terminal; capture starts once it writes its first session.",
    }),
  },
  {
    name: "not found",
    when: (r) => !r.found,
    step: () => ({ kind: "note", detail: "Not found here. Capture starts by itself once this tool writes its first session." }),
  },
  {
    name: "capture off",
    when: (r) => !r.enabled,
    step: () => ({
      kind: "link",
      label: "Open Connected tools",
      href: connectedToolsHref(),
      detail: "Capture for this tool is off in your settings.",
    }),
  },
  {
    name: "history could not be read",
    when: (r) => r.history?.state === "failed",
    step: (r) => ({
      kind: "link",
      label: "Run checks",
      href: connectedToolsHref(r.tool, "doctor"),
      detail: r.history?.reason || "Some session files could not be read.",
    }),
  },
  {
    name: "watcher not running",
    when: (r) => r.history?.state === "not_running",
    step: () => ({ kind: "note", detail: "Start SuperBased with observer start to capture this tool." }),
  },
  {
    name: "hooks not registered",
    when: (r) => !!r.wiring?.hooks.register && wants(r.hooks),
    step: (r) => ({
      kind: "link",
      label: r.hooks?.partial ? "Finish hooks" : "Register hooks",
      href: connectedToolsHref(r.tool, "setup"),
      detail: "Hooks add live events and guardrails.",
    }),
  },
  {
    name: "proxy not routed",
    when: (r) => !!r.wiring?.route.register && wants(r.proxy),
    step: (r) => ({
      kind: "link",
      label: "Route through proxy",
      href: connectedToolsHref(r.tool, "setup"),
      detail: "Optional. Adds exact token counts.",
    }),
  },
];

/** The rule names in order (for the table test). */
export const NEXT_RULE_NAMES: readonly string[] = NEXT_RULES.map((r) => r.name);

/** nextStep is a row's one next step, or null when it is connected. */
export function nextStep(r: CoverageRow): NextStep | null {
  const rule = NEXT_RULES.find((x) => x.when(r));
  return rule ? rule.step(r) : null;
}

// ---- order, filter, summary -------------------------------------------------

const STATE_ORDER: Record<CoverageState, number> = {
  attention: 0,
  off: 1,
  reading: 2,
  capturing: 3,
  idle: 4,
  not_found: 5,
};

/** sortRows: found tools first (needing attention first), then by activity, then by name. */
export function sortRows(rows: readonly CoverageRow[]): CoverageRow[] {
  const activity = (r: CoverageRow) => r.sessions ?? r.actions ?? 0;
  return [...rows].sort(
    (a, b) =>
      STATE_ORDER[coverageStatus(a).state] - STATE_ORDER[coverageStatus(b).state] ||
      activity(b) - activity(a) ||
      a.name.localeCompare(b.name),
  );
}

export type CoverageFilter = "found" | "not_found" | "all";

export function filterRows(rows: readonly CoverageRow[], f: CoverageFilter): CoverageRow[] {
  if (f === "all") return [...rows];
  return rows.filter((r) => (f === "found" ? r.found : !r.found));
}

/** The default filter: the found tools, or everything when none was found. */
export function defaultFilter(rows: readonly CoverageRow[]): CoverageFilter {
  return rows.some((r) => r.found) ? "found" : "all";
}

export type CoverageSummary = {
  supported: number;
  found: number;
  capturing: number;
  attention: number;
  notFound: number;
  headline: string;
};

/**
 * coverageSummary counts the list. `supported` is the server's catalog size
 * when it sent one, else the rows (the remote source lists the catalog plus
 * any tool with captured rows).
 */
export function coverageSummary(rows: readonly CoverageRow[], supported?: number): CoverageSummary {
  let found = 0;
  let capturing = 0;
  let attention = 0;
  for (const r of rows) {
    if (!r.found) continue;
    found++;
    const s = coverageStatus(r).state;
    if (s === "capturing" || s === "reading") capturing++;
    if (s === "attention" || s === "off") attention++;
  }
  const total = supported && supported > 0 ? Math.max(supported, found) : rows.length;
  const headline = `${found} of ${total} supported tools detected, ${capturing} capturing`;
  return { supported: total, found, capturing, attention, notFound: total - found, headline };
}

// ---- the view ---------------------------------------------------------------

/** A read's state, as useApi reports it. */
export type ReadState<T> = { data: T | null; loading: boolean; error: Error | null; status?: number | null };

/** isLocalOnlyRefusal: the owner-local route refused a remote viewer. */
export function isLocalOnlyRefusal(s: { error: Error | null; status?: number | null }): boolean {
  if (!s.error) return false;
  return s.status === 403 || /local dashboard|local_route_refused/i.test(s.error.message);
}

export type CoverageView =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  /** Refused here and the fallback is not readable either. */
  | { kind: "local_only" }
  | {
      kind: "ready";
      source: CoverageSource;
      rows: CoverageRow[];
      summary: CoverageSummary;
      /** The watcher is running (null: the source cannot say). */
      watcherRunning: boolean | null;
      /** History capture is still moving (keep reading). */
      moving: boolean;
    };

/**
 * coverageView decides what the coverage surfaces render from the primary
 * (owner-local) read and, when that one is refused, the fallback read.
 */
export function coverageView(
  primary: ReadState<FirstRunResponse>,
  fallback: ReadState<ToolsStatusResponse>,
  nameOf: (tool: string) => string,
): CoverageView {
  if (primary.data) {
    const d = primary.data;
    const rows = sortRows(rowsFromFirstRun(d));
    return {
      kind: "ready",
      source: "local",
      rows,
      summary: coverageSummary(rows, d.supported),
      watcherRunning: d.watcher_running,
      moving: d.watcher_running && (d.capture.state === "scanning" || d.capture.state === "idle"),
    };
  }
  if (primary.error && isLocalOnlyRefusal(primary)) {
    if (fallback.data) {
      const rows = sortRows(rowsFromToolsStatus(fallback.data, nameOf));
      return { kind: "ready", source: "remote", rows, summary: coverageSummary(rows), watcherRunning: null, moving: false };
    }
    if (fallback.error) return { kind: "local_only" };
    return { kind: "loading" };
  }
  if (primary.error) return { kind: "error", message: primary.error.message || "Could not load tool coverage." };
  return { kind: "loading" };
}

/** fmtAgo is a short "how long ago" for a last-activity timestamp. */
export function fmtAgo(iso: string | undefined, now: number = Date.now()): string | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return null;
  const s = Math.max(0, Math.round((now - t) / 1000));
  if (s < 60) return "just now";
  const m = Math.round(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.round(m / 60);
  if (h < 48) return `${h} h ago`;
  const d = Math.round(h / 24);
  return `${d} days ago`;
}

/** countLine is a found row's activity line, or null when unknown. */
export function countLine(r: CoverageRow): string | null {
  const n = (v: number, noun: string) => `${v.toLocaleString("en-US")} ${noun}${v === 1 ? "" : "s"}`;
  if (r.sessions != null) {
    if (r.sessions === 0) return "No sessions yet";
    return r.projects ? `${n(r.sessions, "session")}, ${n(r.projects, "project")}` : n(r.sessions, "session");
  }
  if (r.actions != null) return r.actions > 0 ? n(r.actions, "action") : "No actions yet";
  return null;
}
