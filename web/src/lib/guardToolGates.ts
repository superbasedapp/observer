// Tool-call blocking on THIS node (T-340 follow-up). The registry's
// hook_block says a tool CAN deny a call through its tool-gate hook; on a
// node it holds only while that hook is registered and current. Otherwise
// the tool falls back to the channel it would have with no hook (normally a
// sandboxed launch in enforce mode). The daemon reports the node state per
// tool as /api/guard/summary's tool_gates; this file turns it into the
// Security page's copy, so the page never shows the bare capability.

export type GuardToolGate = {
  tool: string;
  channel: string;
  current: boolean;
  installed: boolean;
  reason: string;
  /** Setup would make the hook hold (missing or stale); absent from an older daemon. */
  fixable?: boolean;
};

// CHANNEL_LABEL is the closed vocabulary of node channels a row can carry.
const CHANNEL_LABEL: Readonly<Record<string, string>> = {
  hook_block: "blocked by its hook",
  sandbox_enforce: "sandboxed launch",
  org_disallow: "org disallow only",
  recorded_acceptance: "recorded only",
};

export function guardToolGateChannelLabel(channel: string): string {
  return CHANNEL_LABEL[channel] ?? channel;
}

// GuardToolCallInput is the slice of /api/guard/summary that says whether
// the tool-call family is enforced on this node.
export type GuardToolCallInput = {
  enabled: boolean;
  mode: string;
  hook_failure?: { tool_gate: string };
};

// guardToolCallsEnforced reports whether the guard enforces tool calls on
// this node (review M4-05). The daemon's hook_failure.tool_gate is its own
// tool-family enforcement (an observe-mode node with a per-rule enforce
// override still enforces); an older daemon without it falls back to the
// global mode.
export function guardToolCallsEnforced(sum: GuardToolCallInput | undefined): boolean {
  if (!sum || !sum.enabled || sum.mode === "off") return false;
  if (sum.hook_failure) return sum.hook_failure.tool_gate === "closed";
  return sum.mode === "enforce";
}

export const TOOL_CALLS_NOT_ENFORCED = "tool calls: not blocked here; the guard does not enforce tool calls on this node";

// guardToolGateLine is the Guard posture tile's tool-call line, over the
// INSTALLED hook tools only (a tool with no config home on this machine has
// nothing to block). Null when the daemon did not report tool_gates, no
// hook tool is installed, or the guard is off (the hook failure line above
// already says hooks never block). A hook only blocks while the tool family
// is enforced, so a node that only observes tool calls never reads as
// blocking (review M4-05).
export function guardToolGateLine(gates: GuardToolGate[] | undefined, sum?: GuardToolCallInput): string | null {
  if (!gates) return null;
  if (sum && (!sum.enabled || sum.mode === "off")) return null;
  const installed = gates.filter((g) => g.installed);
  const n = installed.length;
  if (n === 0) return null;
  if (!guardToolCallsEnforced(sum)) return TOOL_CALLS_NOT_ENFORCED;
  const holding = installed.filter((g) => g.current).length;
  if (holding === n) {
    return n === 1
      ? "tool calls: the installed hook tool blocks by its hook"
      : `tool calls: all ${n} installed hook tools block by their hooks`;
  }
  return `tool calls: ${holding} of ${n} installed hook tools block by their hooks; the rest fall back (see Coverage)`;
}
