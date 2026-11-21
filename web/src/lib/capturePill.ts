// capturePill - the pure model behind the top bar's capture pill
// (components/TopBar.tsx CaptureStatePill) and the Claude pill of the
// Compression page's Proxy banner, fed by GET /api/setup/claude.
//
// The pill reports ONE thing: whether Claude Code traffic on this machine
// goes through this node's proxy. It used to read "Paused" for every status
// that was not ready, so a machine without Claude Code at all (node 1,
// 2026-10-06: status claude_not_installed) looked as if capture had stopped,
// while the watcher, the hooks and every other tool were capturing normally.
//
// T-803: "No Claude Code" sat in the Overview header of a node whose
// dashboard was full of Claude Code sessions (captured from another OS or
// imported; the daemon only looks for a `claude` binary on its own PATH).
// The pill's subject is this machine's Claude Code proxy route, and with no
// binary here there is no route to report, so the pill is hidden instead of
// contradicting the data next to it.
//
// OBS-1 (surface-gap arc Wave 1): the pill read "Active ... routes through
// this machine's proxy" from the install status alone (oauth_ready /
// api_key_ready), so it said Active with an unrouted settings file, and
// with a desktop app that ignores the route. It is now an ordered table
// over two inputs: the settings-file verdict (routed_to_observer) and the
// observed verdict (observed_route: sessions per capture surface that did
// or did not reach the proxy). "Active" needs proxied sessions; a routed
// file with none reads "Routed (file only)"; a routable surface that ran
// sessions around the proxy reads "Proxy partly bypassed" or "Proxy bypassed".
// Table-driven (CLAUDE.md #5).

import type { ObservedSurface, SetupClaude } from "./types";

/** The dot state, one of liveSignals CAPTURE_DOT's keys. */
export type CapturePillState = "active" | "paused" | "absent";

export type CapturePillView = {
  label: string;
  tooltip: string;
  state: CapturePillState;
  /** True when there is nothing for the pill to report: render no pill. */
  hidden?: boolean;
};

/** The part of the /api/setup/claude snapshot the pill reads. */
export type CapturePillInput = Pick<SetupClaude, "status" | "routed_to_observer" | "observed_route">;

const OTHER_TOOLS = "The watcher and the hooks capture every other tool either way.";

/**
 * The install statuses that mean Claude Code is on this machine.
 * extension_ready is the VS Code extension with no `claude` on PATH
 * (WINNODE2 16b): it reads the same settings-file route.
 */
const INSTALLED = new Set(["oauth_ready", "api_key_ready", "extension_ready"]);

/** States whose counts cannot say whether the traffic was proxied. */
const UNJUDGED = new Set(["unknown_measurability", "not_measurable"]);

/** The facts each table row is judged on, derived once from the input. */
type Facts = {
  status: string;
  fileRouted: boolean;
  windowDays: number;
  sessions: number;
  proxied: number;
  bypassed: ObservedSurface[];
  unjudged: ObservedSurface[];
};

// UNSTAMPED names sessions that carry no capture-surface stamp (older
// captures, or a session imported or captured from another OS); the daemon
// judges them at the tool level (P-172). Demo bug #11: the pill read the raw
// placeholder "Bypassed: unstamped", which told a viewer nothing.
const UNSTAMPED = "sessions with no surface stamp (older, imported or captured on another OS)";

// BYPASS_LEAD opens every bypass tooltip with what the verdict means, before
// the counts.
const BYPASS_LEAD =
  "Some Claude Code sessions did not go through this machine's proxy, so their tokens and cost come from transcripts (estimates) and the proxy's guard checks, compression and limit readings did not see them.";

function surfaceName(s: ObservedSurface): string {
  if (!s.kind) return UNSTAMPED;
  return s.host ? `${s.kind} (${s.host})` : s.kind;
}

function fileNote(f: Facts): string {
  return f.fileRouted
    ? "The settings file routes Claude Code to this proxy."
    : "The settings file does not route Claude Code to this proxy.";
}

function unjudgedNote(f: Facts): string {
  if (f.unjudged.length === 0) return "";
  return ` Not judged: ${f.unjudged.map(surfaceName).join(", ")} (whether that surface's proxied traffic joins its sessions is not grounded yet).`;
}

function bypassDetail(f: Facts): string {
  return f.bypassed
    .map((s) => `${surfaceName(s)}: ${s.sessions - s.proxied_sessions} of ${s.sessions} sessions did not reach the proxy`)
    .join("; ");
}

type Row = { when: (f: Facts) => boolean; view: (f: Facts) => CapturePillView };

/** The ordered table: the first row whose `when` holds decides the pill. */
const ROWS: Row[] = [
  {
    when: (f) => f.status === "claude_not_installed",
    view: () => ({
      label: "No Claude Code here",
      tooltip: `Claude Code was not found on this machine, so there is no Claude Code proxy route to show. ${OTHER_TOOLS}`,
      state: "absent",
      hidden: true,
    }),
  },
  {
    when: (f) => f.bypassed.length > 0 && f.proxied > 0,
    view: (f) => ({
      // The label is the plain verdict; which surfaces is in the tooltip, so
      // the header chip stays short (demo bugs #10 and #11).
      label: "Proxy partly bypassed",
      tooltip: `${BYPASS_LEAD} In the last ${f.windowDays} days ${f.proxied} of ${f.sessions} Claude Code sessions went through this machine's proxy, but ${bypassDetail(f)}. ${fileNote(f)} Route that surface too (Set up for Claude Code in Settings > Connected tools), or start it from a dashboard terminal (New terminal), which launches through the observer wrapper.${unjudgedNote(f)}`,
      state: "paused",
    }),
  },
  {
    when: (f) => f.bypassed.length > 0,
    view: (f) => ({
      label: "Proxy bypassed",
      tooltip: `${BYPASS_LEAD} In the last ${f.windowDays} days no Claude Code session reached this machine's proxy: ${bypassDetail(f)}. ${fileNote(f)} A routed tool whose sessions still miss the proxy either ignores the route or ran while the proxy was down.${unjudgedNote(f)}`,
      state: "paused",
    }),
  },
  {
    when: (f) => f.proxied > 0,
    view: (f) => ({
      label: "Active",
      tooltip: `In the last ${f.windowDays} days ${f.proxied} of ${f.sessions} Claude Code sessions went through this machine's proxy: capturing. ${fileNote(f)}${unjudgedNote(f)}`,
      state: "active",
    }),
  },
  {
    when: (f) => f.fileRouted,
    view: (f) => ({
      label: "Routed (file only)",
      tooltip: `The settings file routes Claude Code to this proxy, but no Claude Code session reached it in the last ${f.windowDays} days, so the route is configured, not yet observed.${unjudgedNote(f)} ${OTHER_TOOLS}`,
      state: "absent",
    }),
  },
  {
    when: (f) => INSTALLED.has(f.status),
    view: (f) => ({
      label: "Not routed",
      tooltip: `Claude Code is not routed through this machine's proxy: the settings file does not point here and no session reached the proxy in the last ${f.windowDays} days.${unjudgedNote(f)} ${OTHER_TOOLS}`,
      state: "paused",
    }),
  },
  {
    when: () => true,
    view: (f) => ({
      label: "Not routed",
      tooltip: `Claude Code is not routed through this machine's proxy (status: ${f.status}). ${OTHER_TOOLS}`,
      state: "paused",
    }),
  },
];

function factsOf(input: CapturePillInput): Facts {
  const surfaces = (input.observed_route?.surfaces ?? []).filter((s) => s.state !== "invalid_input");
  return {
    status: input.status,
    fileRouted: input.routed_to_observer === true,
    windowDays: input.observed_route?.window_days ?? 7,
    sessions: surfaces.reduce((n, s) => n + s.sessions, 0),
    proxied: surfaces.reduce((n, s) => n + s.proxied_sessions, 0),
    bypassed: surfaces.filter((s) => s.bypass),
    unjudged: surfaces.filter((s) => UNJUDGED.has(s.state) && s.sessions > 0),
  };
}

/** capturePillView maps a /api/setup/claude snapshot onto the pill. */
export function capturePillView(setup: CapturePillInput | null | undefined): CapturePillView {
  if (!setup || !setup.status) {
    return { label: "Checking", tooltip: "Reading the Claude Code proxy setup.", state: "absent" };
  }
  const facts = factsOf(setup);
  for (const row of ROWS) {
    if (row.when(facts)) return row.view(facts);
  }
  // Unreachable: the last row always holds.
  return { label: "Not routed", tooltip: OTHER_TOOLS, state: "paused" };
}
