// terminalInitiator: who started a terminal run (lane cli-2, agent migration
// 220). The daemon records terminal_run.initiator from a closed set
// (internal/termrun/initiator.go) and, for an agent, its parent session; the
// Terminals page shows them in its run history. The labels are the same as
// the CLI's `observer terminals` "STARTED BY" column (cmd/observer
// launch_cli.go initiatorWords). No imports, so node:test pins it directly.

/** One label per initiator the daemon records. */
export const TERMINAL_INITIATOR_LABELS: Readonly<Record<string, string>> = {
  human_dashboard: "you (dashboard)",
  human_cli: "you (cli)",
  agent: "agent",
  unknown: "unknown",
};

/** initiatorLabel is the label of a recorded initiator, "" when none was recorded. */
export function initiatorLabel(initiator: string | undefined): string {
  if (!initiator) return "";
  return TERMINAL_INITIATOR_LABELS[initiator] ?? initiator;
}

/** isAgentInitiated reports whether an agent started the run. */
export function isAgentInitiated(initiator: string | undefined): boolean {
  return initiator === "agent";
}
