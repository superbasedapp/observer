// firstRun - the pure half of the first-run capture view (T-922): the wire
// shape of GET /api/firstrun (internal/intelligence/dashboard/firstrun.go),
// the view model the dialog renders, and the small open/close store the
// dialog, the tour and the reopen surfaces share. No JSX, no fetch: pinned by
// firstRun.test.ts.

import type { ToolWiring } from "./types";
//
// What the dialog shows is the daemon's own work made visible: the AI tools
// found on this machine and how far the watcher's first pass over their
// existing history has got. The seen flag lives on the daemon (beside its
// database), so a second browser or a reinstall over the same data behaves
// the same; only "closed for this visit" is browser-local.

/** One integration probe (the Connected-tools ToolProbe shape). */
export type FirstRunProbe = {
  registered: boolean;
  partial?: boolean;
  via_plugin?: boolean;
  no_hooks?: boolean;
  unprobed?: boolean;
  detail?: string;
};

export type FirstRunHistoryState =
  | "scanning"
  | "done"
  | "failed"
  | "stopped"
  | "waiting"
  | "off"
  | "not_running";

export type FirstRunHistory = {
  state: FirstRunHistoryState;
  reason?: string;
  files_found: number;
  files_processed: number;
  files_failed: number;
};

export type FirstRunTool = {
  tool: string;
  name: string;
  detected: boolean;
  detected_path?: string;
  enabled: boolean;
  watcher_active: boolean;
  hooks?: FirstRunProbe;
  proxy?: FirstRunProbe;
  history: FirstRunHistory;
  sessions: number;
  projects: number;
  last_seen_at?: string;
  // Additive for the Tools page coverage view (T-935); the dialog ignores
  // them. Same shapes as the Connected-tools row (GET /api/tools/status).
  mcp?: FirstRunProbe;
  wiring?: ToolWiring;
  /** The New terminal picker offers this tool (and its guided install). */
  launchable?: boolean;
};

export type FirstRunCaptureState = "idle" | "scanning" | "done" | "stopped" | "not_running";

export type FirstRunProject = {
  name: string;
  root: string;
  sessions: number;
  tools: string[];
  last_session_at?: string;
};

export type FirstRunResponse = {
  auto_open: boolean;
  seen: boolean;
  install: "fresh" | "existing" | "unknown";
  watcher_running: boolean;
  capture: {
    state: FirstRunCaptureState;
    started_at?: string;
    finished_at?: string;
    files_found: number;
    files_processed: number;
    files_failed: number;
  };
  tools: FirstRunTool[];
  supported_not_found: number;
  /** Supported tools (the adapter catalog); 0 or absent on a brief read. */
  supported?: number;
  sessions: number;
  project_count: number;
  projects: FirstRunProject[];
  generated_at: string;
  confirm_token?: string;
  /** Notices the owner dismissed for good, kept on the daemon (WINNODE2 16b). */
  dismissed?: string[];
};

export const FIRST_RUN_PATH = "/api/firstrun";
export const FIRST_RUN_SEEN_PATH = "/api/firstrun/seen";
/** Poll cadence while the dialog is open and the capture is still moving. */
export const FIRST_RUN_POLL_MS = 3000;

export type Tone = "accent" | "success" | "warn" | "danger" | "neutral";

/** The state badge for a tool's history capture: label and tone. */
export const HISTORY_BADGE: Record<FirstRunHistoryState, { label: string; tone: Tone }> = {
  scanning: { label: "Reading history", tone: "accent" },
  done: { label: "Captured", tone: "success" },
  failed: { label: "Could not read", tone: "danger" },
  stopped: { label: "Paused", tone: "warn" },
  waiting: { label: "Waiting", tone: "neutral" },
  off: { label: "Turned off", tone: "neutral" },
  not_running: { label: "Not running", tone: "warn" },
};

export function historyBadge(state: string): { label: string; tone: Tone } {
  return HISTORY_BADGE[state as FirstRunHistoryState] ?? { label: state || "Unknown", tone: "neutral" };
}

/**
 * toolBadge is a tool row's badge: its history state, except that a finished
 * pass that found no session files says so instead of "Captured".
 */
export function toolBadge(t: Pick<FirstRunTool, "history" | "sessions">): { label: string; tone: Tone } {
  if (t.history.state === "done" && t.history.files_found === 0 && t.sessions === 0) {
    return { label: "No history yet", tone: "neutral" };
  }
  return historyBadge(t.history.state);
}

/** One small "how is this captured" chip on a tool row. */
export type CaptureChip = { key: string; label: string; tone: Tone; title: string };

/**
 * captureChips lists how a tool is captured: its session files (the
 * watcher), its hooks, and the proxy route. A probe the tool does not have
 * is left out (n/a is not "off").
 */
export function captureChips(t: FirstRunTool): CaptureChip[] {
  const out: CaptureChip[] = [];
  out.push(
    t.watcher_active
      ? { key: "files", label: "Session files", tone: "success", title: "The watcher reads this tool's session files." }
      : { key: "files", label: "Session files off", tone: "neutral", title: t.history.reason || "The watcher is not reading this tool's files." },
  );
  const h = t.hooks;
  if (h && !h.no_hooks && !h.unprobed) {
    if (h.registered) {
      out.push({ key: "hooks", label: "Hooks on", tone: "success", title: h.detail || "Hooks point at SuperBased." });
    } else if (h.partial) {
      out.push({ key: "hooks", label: "Hooks partly on", tone: "warn", title: h.detail || "Some hook events point at SuperBased." });
    } else {
      out.push({ key: "hooks", label: "Hooks off", tone: "neutral", title: h.detail || "Hooks are not registered yet." });
    }
  }
  const p = t.proxy;
  if (p) {
    out.push(
      p.registered
        ? { key: "proxy", label: "Proxy routed", tone: "success", title: p.detail || "Requests go through the local proxy." }
        : { key: "proxy", label: "Proxy not routed", tone: "neutral", title: "Optional. Routing through the proxy adds exact token counts." },
    );
  }
  return out;
}

/** Share of found files handled (read or failed), 0..1, or null when unknown. */
export function progressRatio(found: number, processed: number, failed: number): number | null {
  if (!Number.isFinite(found) || found <= 0) return null;
  const handled = Math.max(0, (processed || 0) + (failed || 0));
  return Math.min(1, handled / found);
}

function plural(n: number, noun: string): string {
  return `${n.toLocaleString("en-US")} ${noun}${n === 1 ? "" : "s"}`;
}

/** The view the dialog body renders. */
export type FirstRunView =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "empty"; watcherRunning: boolean; supportedNotFound: number }
  | {
      kind: "ready";
      phase: FirstRunCaptureState;
      ratio: number | null;
      headline: string;
      detail: string;
      tools: FirstRunTool[];
      projects: FirstRunProject[];
      sessions: number;
      projectCount: number;
      supportedNotFound: number;
    };

/** headline is the one-line overall status, in plain words. */
export function headline(d: FirstRunResponse): { headline: string; detail: string } {
  const c = d.capture;
  const found = plural(d.sessions, "session");
  const across = d.project_count > 0 ? ` across ${plural(d.project_count, "project")}` : "";
  switch (c.state) {
    case "scanning":
      return {
        headline:
          c.files_found > 0
            ? `Reading your past sessions: ${c.files_processed.toLocaleString("en-US")} of ${plural(c.files_found, "file")}`
            : "Looking for your past sessions",
        detail: `${found}${across} captured so far. You can close this; capture keeps going in the background.`,
      };
    case "done":
      return {
        headline: d.sessions > 0 ? "Your past history is captured" : "Nothing to read yet",
        detail:
          d.sessions > 0
            ? `${found}${across}. New sessions show up as they happen.`
            : "Run one of your AI tools once and its sessions show up here by themselves.",
      };
    case "stopped":
      return {
        headline: "History capture paused",
        detail: `${found}${across} so far. It continues the next time the daemon starts.`,
      };
    case "not_running":
      return {
        headline: "The background watcher is not running here",
        detail: "Start SuperBased with observer start to capture past and new sessions.",
      };
    default:
      return { headline: "Starting history capture", detail: `${found}${across} captured so far.` };
  }
}

/**
 * firstRunView decides what the dialog body shows from the read's state.
 * A failed read wins over stale data only when there is no data at all.
 */
export function firstRunView(s: {
  data: FirstRunResponse | null;
  loading: boolean;
  error: Error | null;
}): FirstRunView {
  const d = s.data;
  if (!d) {
    if (s.error) return { kind: "error", message: s.error.message || "Could not load capture status." };
    return { kind: "loading" };
  }
  const tools = d.tools ?? [];
  if (tools.length === 0 && (d.sessions ?? 0) === 0) {
    return { kind: "empty", watcherRunning: d.watcher_running, supportedNotFound: d.supported_not_found ?? 0 };
  }
  const { headline: h, detail } = headline(d);
  const c = d.capture;
  return {
    kind: "ready",
    phase: c.state,
    ratio: c.state === "done" ? 1 : progressRatio(c.files_found, c.files_processed, c.files_failed),
    headline: h,
    detail,
    tools: sortTools(tools),
    projects: d.projects ?? [],
    sessions: d.sessions,
    projectCount: d.project_count,
    supportedNotFound: d.supported_not_found ?? 0,
  };
}

const HISTORY_ORDER: Record<string, number> = {
  scanning: 0,
  failed: 1,
  stopped: 2,
  done: 3,
  waiting: 4,
  not_running: 5,
  off: 6,
};

/** sortTools puts tools still moving first, then by sessions, then by name. */
export function sortTools(tools: readonly FirstRunTool[]): FirstRunTool[] {
  return [...tools].sort(
    (a, b) =>
      (HISTORY_ORDER[a.history.state] ?? 9) - (HISTORY_ORDER[b.history.state] ?? 9) ||
      b.sessions - a.sessions ||
      a.name.localeCompare(b.name),
  );
}

/** shouldPoll: keep reading while the capture can still change. */
export function shouldPoll(d: FirstRunResponse | null): boolean {
  if (!d) return true;
  if (!d.watcher_running) return false;
  return d.capture.state === "scanning" || d.capture.state === "idle";
}

/**
 * closeMarksSeen: closing the dialog once the capture has finished (the
 * owner saw the result) marks it seen on the daemon; closing it mid-capture
 * only hides it for this visit, so it comes back next time with the outcome.
 */
export function closeMarksSeen(d: FirstRunResponse | null): boolean {
  return d != null && d.capture.state === "done";
}

/** The seen POST: JSON plus the owner-local confirm header (T-530). */
export function seenRequestInit(seen: boolean, confirmToken: string): RequestInit {
  return {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Observer-Confirm": confirmToken },
    body: JSON.stringify({ seen }),
  };
}

// ---- the open/close store --------------------------------------------------
//
// One tiny external store (useSyncExternalStore) shared by the dialog host,
// the tour adapter (which holds its own first-visit auto-start until the
// dialog has decided and closed) and the reopen surfaces (command palette,
// Settings -> Connected tools).

export type FirstRunUiState = {
  /** The first read came back and the auto-open decision was taken. */
  decided: boolean;
  open: boolean;
};

let uiState: FirstRunUiState = { decided: false, open: false };
const listeners = new Set<() => void>();

function setUi(next: FirstRunUiState) {
  if (next.decided === uiState.decided && next.open === uiState.open) return;
  uiState = next;
  for (const l of listeners) l();
}

export function subscribeFirstRun(l: () => void): () => void {
  listeners.add(l);
  return () => listeners.delete(l);
}

export function firstRunSnapshot(): FirstRunUiState {
  return uiState;
}

/** decideFirstRun records the auto-open decision (first time only). */
export function decideFirstRun(open: boolean): void {
  if (uiState.decided) return;
  setUi({ decided: true, open });
}

/** openFirstRun opens the dialog on demand (reopen surfaces). */
export function openFirstRun(): void {
  setUi({ decided: true, open: true });
}

export function closeFirstRun(): void {
  setUi({ decided: true, open: false });
}

/** tourHeld: the first-visit tour waits while the dialog may still open. */
export function tourHeld(s: FirstRunUiState): boolean {
  return !s.decided || s.open;
}

/** Test seam: back to the initial state. */
export function resetFirstRunUi(): void {
  uiState = { decided: false, open: false };
  listeners.clear();
}

// ---- closed for this visit ------------------------------------------------

export const FIRST_RUN_VISIT_KEY = "sb_firstrun_closed_this_visit";

type MinimalStorage = Pick<Storage, "getItem" | "setItem">;

export function closedThisVisit(storage: MinimalStorage | null | undefined): boolean {
  try {
    return storage?.getItem(FIRST_RUN_VISIT_KEY) === "1";
  } catch {
    return false;
  }
}

export function markClosedThisVisit(storage: MinimalStorage | null | undefined): void {
  try {
    storage?.setItem(FIRST_RUN_VISIT_KEY, "1");
  } catch {
    // Storage unavailable: the dialog may open again on a reload.
  }
}

/** shouldAutoOpen: the daemon says so and it was not closed this visit. */
export function shouldAutoOpen(d: FirstRunResponse | null, closedVisit: boolean): boolean {
  return d != null && d.auto_open === true && !closedVisit;
}
