// sandboxSettingsView: what the Terminals > Settings "Sandbox isolation" card
// shows for the state of its three reads (lane L2). Pure (no React, no app
// path aliases) so sandboxSettingsView.test.ts runs under `node --test`.
//
// The card reads GET /api/terminal/sandbox/config (the editor), GET
// /api/terminal/sandbox (the running daemon's probe) and GET
// /api/terminal/sandbox/setup (the backend rows). A fresh install of the
// developer edition has the Sandboxes and VMs module installed but not
// turned on, so useApi skips every one of those reads (the routes are in
// /api/components/state inactive_routes): no data, no error. The card used
// to read that as "still loading" forever ("Sandbox probe has not returned
// yet." over "Loading sandbox configuration"), with nothing to enable. Every
// state now maps to something the person can act on, through the ordered
// rule tables below (first match wins, one test row per rule).

/** The phase of one read, as the card sees it. */
export type SandboxReadPhase =
  /** In flight, within the patience window. */
  | "pending"
  /** In flight longer than SANDBOX_READ_PATIENCE_MS: reported, never a spinner. */
  | "slow"
  /** Not sent: useApi skips a route whose module is off or that the visibility posture hides. */
  | "skipped"
  | "ok"
  | "error";

/** One read's state. */
export type SandboxRead = {
  phase: SandboxReadPhase;
  /** For ok: the reply carried what the card needs (the config's sandbox block). */
  complete?: boolean;
  /** For error: the route guard's component_not_installed answer, when it was that. */
  notInstalled?: { component: string; state: string } | null;
  /** For error: the failure as the client saw it (technical details only). */
  message?: string;
};

/** The Sandboxes and VMs module's state on this machine ("unknown" until read). */
export type SandboxModuleState = "active" | "available" | "absent" | "blocked" | "unknown";

/** SANDBOX_READ_PATIENCE_MS is how long a read may run before the card says it is slow. */
export const SANDBOX_READ_PATIENCE_MS = 15_000;

/** sandboxReadPhase maps useApi's fields to a phase. */
export function sandboxReadPhase(r: {
  skipped: boolean;
  hasData: boolean;
  error: boolean;
  slow: boolean;
}): SandboxReadPhase {
  if (r.skipped) return "skipped";
  if (r.hasData) return "ok";
  if (r.error) return "error";
  return r.slow ? "slow" : "pending";
}

// ---- the card's shape --------------------------------------------------

/**
 * The card's overall shape: hidden (the module is not in this build, or the
 * section is hidden here), the module-off pointer (installed, not turned on:
 * the way to turn it on), the blocked pointer, or the full card.
 */
export type SandboxCardShape = "hidden" | "module_off" | "module_blocked" | "shown";

export type SandboxCardShapeInput = {
  module: SandboxModuleState;
  /** The visibility posture hides the sandbox routes on this machine. */
  concealed: boolean;
  settings: SandboxRead;
  probe: SandboxRead;
};

function guardState(i: SandboxCardShapeInput): string | null {
  return i.settings.notInstalled?.state ?? i.probe.notInstalled?.state ?? null;
}

type ShapeRule = { name: string; when: (i: SandboxCardShapeInput) => boolean; shape: SandboxCardShape };

/** SANDBOX_CARD_SHAPE_RULES is the ordered shape table. */
export const SANDBOX_CARD_SHAPE_RULES: readonly ShapeRule[] = [
  { name: "the visibility posture hides the section", when: (i) => i.concealed, shape: "hidden" },
  { name: "the module is not in this build", when: (i) => i.module === "absent" || guardState(i) === "absent", shape: "hidden" },
  { name: "the module is blocked here", when: (i) => i.module === "blocked" || guardState(i) === "blocked", shape: "module_blocked" },
  {
    name: "the module is installed but not turned on",
    when: (i) =>
      i.module === "available" ||
      guardState(i) !== null ||
      i.settings.phase === "skipped" ||
      i.probe.phase === "skipped",
    shape: "module_off",
  },
  { name: "the module runs here", when: () => true, shape: "shown" },
];

/** sandboxCardShape walks SANDBOX_CARD_SHAPE_RULES top-down. */
export function sandboxCardShape(i: SandboxCardShapeInput): SandboxCardShape {
  return (SANDBOX_CARD_SHAPE_RULES.find((r) => r.when(i)) ?? SANDBOX_CARD_SHAPE_RULES[SANDBOX_CARD_SHAPE_RULES.length - 1]).shape;
}

// ---- the editor body ---------------------------------------------------

/** What the editor area shows. */
export type SandboxEditorState = "editor" | "local_only" | "load_error" | "incomplete" | "slow" | "loading";

type EditorRule = { name: string; when: (s: SandboxRead, localOnly: boolean) => boolean; state: SandboxEditorState };

/** SANDBOX_EDITOR_RULES is the ordered editor table. */
export const SANDBOX_EDITOR_RULES: readonly EditorRule[] = [
  { name: "the settings arrived", when: (s) => s.phase === "ok" && !!s.complete, state: "editor" },
  { name: "the route is local-only and this is a remote view", when: (_s, local) => local, state: "local_only" },
  { name: "the read failed", when: (s) => s.phase === "error", state: "load_error" },
  { name: "the reply had no sandbox settings", when: (s) => s.phase === "ok", state: "incomplete" },
  { name: "the read is taking too long", when: (s) => s.phase === "slow", state: "slow" },
  { name: "the read is in flight", when: () => true, state: "loading" },
];

/** sandboxEditorState walks SANDBOX_EDITOR_RULES top-down. */
export function sandboxEditorState(settings: SandboxRead, localOnly: boolean): SandboxEditorState {
  return (SANDBOX_EDITOR_RULES.find((r) => r.when(settings, localOnly)) ?? SANDBOX_EDITOR_RULES[SANDBOX_EDITOR_RULES.length - 1]).state;
}

// ---- the "Running daemon" line ----------------------------------------

/** The probe fields the line reads (lib/types SandboxAvailability). */
export type SandboxProbeFacts = {
  available: boolean;
  verdict?: string;
  reason?: string;
  backend?: string;
  backend_version?: string;
  home_mode?: string;
  egress?: string;
};

/** The line under "Running daemon:". */
export type SandboxProbeLine = {
  tone: "ok" | "neutral" | "warn";
  text: string;
  /** Internal detail (verdict code, raw reason), shown only as Technical details. */
  technical?: string;
  /** Offer "Check again". */
  retry: boolean;
};

const STILL_EDITABLE = "You can still change the settings below and set up a backend.";

function technicalOf(p: SandboxProbeFacts | null | undefined, extra?: string): string | undefined {
  const parts = [p?.verdict ? `verdict: ${p.verdict}` : "", p?.reason ?? "", extra ?? ""].filter((s) => s !== "");
  return parts.length ? parts.join("; ") : undefined;
}

type ProbeRule = {
  name: string;
  when: (r: SandboxRead, p: SandboxProbeFacts | null | undefined) => boolean;
  line: (r: SandboxRead, p: SandboxProbeFacts | null | undefined) => SandboxProbeLine;
};

/** SANDBOX_PROBE_RULES is the ordered "Running daemon" table. */
export const SANDBOX_PROBE_RULES: readonly ProbeRule[] = [
  {
    name: "a backend is available",
    when: (r, p) => r.phase === "ok" && !!p?.available,
    line: (_r, p) => ({
      tone: "ok",
      text: `${p?.backend ?? "bwrap"} ${p?.backend_version ?? ""} available; home is ${p?.home_mode ?? "isolated"}; network is ${p?.egress ?? "internet"}.`.replace(/ {2,}/g, " "),
      retry: false,
    }),
  },
  {
    name: "sandbox support is off",
    when: (r, p) => r.phase === "ok" && p?.verdict === "disabled_by_config",
    line: (_r, p) => ({
      tone: "neutral",
      text: "Sandbox support is off. Turn on Enable sandbox support below and save; it applies to the next launch.",
      technical: technicalOf(p),
      retry: false,
    }),
  },
  {
    name: "sandbox support is on but could not start",
    when: (r, p) => r.phase === "ok" && p?.verdict === "runtime_init_failed",
    line: (_r, p) => ({
      tone: "warn",
      text: "Sandbox support is on, but the daemon could not start it. Fix the setting the technical details name and save again.",
      technical: technicalOf(p),
      retry: true,
    }),
  },
  {
    name: "the check took too long",
    when: (r, p) => r.phase === "ok" && p?.verdict === "probe_timed_out",
    line: (_r, p) => ({
      tone: "warn",
      text: `The check of this machine's sandbox support took too long and is still running. ${STILL_EDITABLE}`,
      technical: technicalOf(p),
      retry: true,
    }),
  },
  {
    name: "the check stopped with an error",
    when: (r, p) => r.phase === "ok" && p?.verdict === "probe_failed",
    line: (_r, p) => ({
      tone: "warn",
      text: `The check of this machine's sandbox support stopped with an error. ${STILL_EDITABLE}`,
      technical: technicalOf(p),
      retry: true,
    }),
  },
  {
    name: "no backend can run (the server says which gap)",
    when: (r) => r.phase === "ok",
    line: (_r, p) => ({
      tone: "neutral",
      text: p?.reason || "No sandbox backend can run on this machine yet. The backends below say what each one needs.",
      technical: p?.verdict ? `verdict: ${p.verdict}` : undefined,
      retry: false,
    }),
  },
  {
    name: "the check failed",
    when: (r) => r.phase === "error",
    line: (r) => ({
      tone: "warn",
      text: `Could not check this machine's sandbox support. ${STILL_EDITABLE}`,
      technical: r.message,
      retry: true,
    }),
  },
  {
    name: "the check is taking too long",
    when: (r) => r.phase === "slow",
    line: () => ({
      tone: "warn",
      text: `The check of this machine's sandbox support has not answered yet. ${STILL_EDITABLE}`,
      retry: true,
    }),
  },
  {
    name: "the check is in flight",
    when: () => true,
    line: () => ({ tone: "neutral", text: "Checking this machine's sandbox support.", retry: false }),
  },
];

/** sandboxProbeLine walks SANDBOX_PROBE_RULES top-down. */
export function sandboxProbeLine(r: SandboxRead, p: SandboxProbeFacts | null | undefined): SandboxProbeLine {
  const rule = SANDBOX_PROBE_RULES.find((x) => x.when(r, p)) ?? SANDBOX_PROBE_RULES[SANDBOX_PROBE_RULES.length - 1];
  return rule.line(r, p);
}
