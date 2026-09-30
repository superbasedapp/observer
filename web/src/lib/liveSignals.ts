import type { Tone } from "@shared/lib/tone";

// liveSignals - the node dashboard's presentation tables for LIVE state:
// which tone a status dot takes and whether it pings, how a terminal agent
// status moves, which tone a utilisation fill takes, how far a cache window
// has run down, and which list rows arrived after the first render. Decision
// logic as data (CLAUDE.md #5): each status value picks a row, never a tool
// name. Pure (type-only imports), so src/lib/liveSignals.test.ts runs it
// under plain node.

/** The shared LiveDot's tone set (shared/primitives/LiveDot.tsx). */
export type LiveTone = "success" | "warn" | "danger" | "info" | "idle";

/**
 * DotSignal - one state's live dot. The shared LiveDot pings for every tone
 * but idle; `still` keeps the tone and drops the halo, for a state that is
 * worth colouring but is not happening now (paused, signed in, an error that
 * already ended).
 */
export type DotSignal = {
  tone: LiveTone;
  still?: boolean;
  /** Accessible name, only where the dot carries meaning with no adjacent text. */
  label?: string;
};

/** A closed state -> dot table. */
export type DotTable = Readonly<Record<string, DotSignal>>;

/**
 * liveDotProps resolves a state against its dot table into LiveDot props.
 * An unknown state is honest: a still grey dot, never a guessed colour.
 */
export function liveDotProps(
  table: DotTable,
  state: string | null | undefined,
): LiveDotProps {
  const sig = state != null ? table[state] : undefined;
  if (!sig) return { tone: "idle" };
  const out: LiveDotProps = { tone: sig.tone };
  if (sig.still) out.still = true;
  if (sig.label) out.label = sig.label;
  return out;
}

/** The LiveDot props liveDotProps resolves. */
export type LiveDotProps = { tone: LiveTone; still?: boolean; className?: string; label?: string };

/** withDotClass adds layout classes (size, shrink) to resolved LiveDot props. */
export function withDotClass(props: LiveDotProps, extra: string): LiveDotProps {
  return { ...props, className: props.className ? `${extra} ${props.className}` : extra };
}

// TRANSPORT_DOT - a dashboard terminal's browser transport (LaunchTerminal
// Status, shared by the dock chip, the workspace tile and the terminal
// header). reconnecting is still live server-side, so it pings in warn; a
// policy-stopped exit is tinted by the stop decision (danger when the run was
// terminated or killed, warn otherwise), matching the modal banner.
export const TRANSPORT_DOT: DotTable = {
  connecting: { tone: "info" },
  open: { tone: "success" },
  reconnecting: { tone: "warn" },
  exited: { tone: "idle" },
  error: { tone: "danger", still: true },
  policy_stopped: { tone: "warn", still: true },
  policy_terminated: { tone: "danger", still: true },
};

// CAPTURE_DOT - the proxy capture state (TopBar capture pill, Sidebar
// watcher line): active captures now; paused is a warn state, not motion.
export const CAPTURE_DOT: DotTable = {
  active: { tone: "success" },
  paused: { tone: "warn", still: true },
};

// ACTIVITY_DOT - recency of the newest captured activity (TopBar "last
// activity", the cockpit status line): fresh pings; stale / idle is grey.
export const ACTIVITY_DOT: DotTable = {
  live: { tone: "success" },
  idle: { tone: "idle" },
};

// LIVE_TAIL_DOT - the Actions event-log tail: live refreshes every 5s;
// paused is frozen on purpose (warn, no motion).
export const LIVE_TAIL_DOT: DotTable = {
  live: { tone: "success" },
  paused: { tone: "warn", still: true },
};

// CLOUD_SIGN_IN_DOT - the TopBar cloud account badge. signing_in is in
// flight; a stored credential is a fact, not motion.
export const CLOUD_SIGN_IN_DOT: DotTable = {
  signing_in: { tone: "info" },
  signed_in: { tone: "success", still: true },
  signed_out: { tone: "idle" },
};

// INSTANCE_DOT - a remote instance's SSH port forward (InstanceSwitcher).
// The row shows only the instance name, so each dot carries its label.
export const INSTANCE_DOT: DotTable = {
  connected: { tone: "success", label: "Connected" },
  connecting: { tone: "warn", label: "Connecting" },
  error: { tone: "danger", still: true, label: "Connection error" },
  disconnected: { tone: "idle", label: "Not connected" },
};

// PROCESS_DOT - one process in the cockpit's process list. Running is
// coloured but still: six pinging rows would drown the section.
export const PROCESS_DOT: DotTable = {
  running: { tone: "success", still: true },
  exited: { tone: "idle" },
};

/** Agent-status motion: how the status glyph moves. */
export type StatusMotion = "spin" | "blink" | "still";

// AGENT_STATUS_MOTION - the terminal agent status (useTerminalStatuses):
// working spins its LoaderCircle, waiting-for-input blinks its Keyboard glyph
// like a caret, blocked is a static OctagonAlert, the rest are still. Glyphs
// come from VOCAB_ICONS.terminalAgentStatus. Unknown statuses are still.
export const AGENT_STATUS_MOTION: Readonly<Record<string, StatusMotion>> = {
  working: "spin",
  "waiting-for-input": "blink",
  blocked: "still",
  idle: "still",
  exited: "still",
  unknown: "still",
};

/** agentStatusMotion reads AGENT_STATUS_MOTION, "still" when unknown. */
export function agentStatusMotion(status: string | null | undefined): StatusMotion {
  return (status != null && AGENT_STATUS_MOTION[status]) || "still";
}

/** One row of an ordered threshold table: the first row whose bound the value exceeds wins. */
export type ToneBand = { above: number; tone: Tone };

// UTIL_BANDS - a utilisation percentage (rate-limit window, context fill):
// over 90% danger, over 70% warn, else accent. Walked top-down.
export const UTIL_BANDS: readonly ToneBand[] = [
  { above: 90, tone: "danger" },
  { above: 70, tone: "warn" },
  { above: Number.NEGATIVE_INFINITY, tone: "accent" },
];

/** bandTone walks an ordered band table; a non-finite value is neutral. */
export function bandTone(bands: readonly ToneBand[], value: number): Tone {
  if (!Number.isFinite(value)) return "neutral";
  for (const b of bands) if (value > b.above) return b.tone;
  return "neutral";
}

/**
 * cacheLifeRatio is the share of a cache window's current life still left:
 * (expires_at - now) / (expires_at - last_refresh), clamped to 0..1. It is
 * null (unknown, render no ring) when either timestamp is missing or
 * unparseable or the window has no positive span.
 */
export function cacheLifeRatio(
  w: { expires_at?: string | null; last_refresh?: string | null },
  nowMs: number,
): number | null {
  if (!w.expires_at || !w.last_refresh) return null;
  const end = Date.parse(w.expires_at);
  const start = Date.parse(w.last_refresh);
  if (!Number.isFinite(end) || !Number.isFinite(start) || end <= start) return null;
  return Math.max(0, Math.min(1, (end - nowMs) / (end - start)));
}

/**
 * ArrivalState remembers a list's keys as of the last commit and which of
 * them arrived after the baseline, so a newly arrived row can fade in once
 * without re-animating the whole list on every poll.
 */
export type ArrivalState = { seen: ReadonlySet<string>; arrived: ReadonlySet<string> };

/**
 * advanceArrivals folds one committed key list into the state. With no prior
 * state the keys become the baseline (nothing arrives on the first render).
 * A key arrives when it was not seen at the last commit, and stays arrived
 * while it remains in the list (so its class is never removed mid-animation);
 * a key that leaves is forgotten.
 */
export function advanceArrivals(prev: ArrivalState | null, keys: readonly string[]): ArrivalState {
  if (!prev) return { seen: new Set(keys), arrived: new Set() };
  const arrived = new Set<string>();
  for (const k of keys) if (!prev.seen.has(k) || prev.arrived.has(k)) arrived.add(k);
  return { seen: new Set(keys), arrived };
}

/** isArrival reports whether `key` arrived after the baseline (false with no baseline). */
export function isArrival(state: ArrivalState | null, key: string): boolean {
  if (!state) return false;
  return !state.seen.has(key) || state.arrived.has(key);
}

/** One row of an ordered freshness table: the first row whose bound the age is within wins. */
export type FreshnessBand = { withinMs: number; state: string };

// HEARTBEAT_BANDS - how recent a live session's newest activity is (the Live
// page card heartbeat). Walked top-down on the age in ms; an age past every
// bound is "quiet". A timestamp a little in the future (clock skew between
// the daemon and the browser) reads as just now, like relTime's "now".
export const HEARTBEAT_BANDS: readonly FreshnessBand[] = [
  { withinMs: 60_000, state: "beating" },
  { withinMs: 5 * 60_000, state: "warm" },
  { withinMs: Number.POSITIVE_INFINITY, state: "quiet" },
];

// HEARTBEAT_DOT - the heartbeat's dot per freshness state. The dot sits in the
// card header away from the "active N ago" text, so each row carries its own
// accessible name. warm keeps the colour without the ping: the session is
// still in the live window but nothing is happening this minute.
export const HEARTBEAT_DOT: DotTable = {
  beating: { tone: "success", label: "Active in the last minute" },
  warm: { tone: "success", still: true, label: "Active in the last 5 minutes" },
  quiet: { tone: "idle", label: "No activity for over 5 minutes" },
};

/**
 * freshnessState walks an ordered freshness table on the age of `iso` at
 * `nowMs`. It is null (unknown, an honest still grey dot through
 * liveDotProps) when the timestamp is missing or unparseable.
 */
export function freshnessState(
  bands: readonly FreshnessBand[],
  iso: string | null | undefined,
  nowMs: number,
): string | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  if (!Number.isFinite(t) || !Number.isFinite(nowMs)) return null;
  const age = Math.max(0, nowMs - t);
  for (const b of bands) if (age <= b.withinMs) return b.state;
  return null;
}
