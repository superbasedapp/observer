// updateTerminal — the model behind Settings > Health "Update in a terminal"
// (dashboard-cli-parity lane L5, B-S5). GET /api/health/update-terminal says
// whether this copy can be updated from a dashboard terminal and with which
// fixed command (chosen server-side from the install method, never from
// input); POST (owner-local, confirm token) spawns it in a setup terminal.
// Pure: no fetch, no React, so node:test covers it.

export const UPDATE_TERMINAL_PATH = "/api/health/update-terminal";

export type UpdateTerminalPlan = {
  available: boolean;
  method?: string;
  command?: string;
  reason?: string;
};

export type UpdateTerminalView =
  | { kind: "button"; command: string }
  | { kind: "note"; text: string }
  | { kind: "none" };

// updateTerminalView decides what the update card shows beside the manual
// commands. Nothing until a check found a newer version; then the button when
// the daemon has a command for this install, else the daemon's reason (which
// names what to run instead).
export function updateTerminalView(
  plan: UpdateTerminalPlan | null | undefined,
  updateAvailable: boolean,
): UpdateTerminalView {
  if (!updateAvailable || !plan) return { kind: "none" };
  const command = (plan.command ?? "").trim();
  if (plan.available && command) return { kind: "button", command };
  const reason = (plan.reason ?? "").trim();
  if (reason) return { kind: "note", text: reason };
  return { kind: "none" };
}

// UPDATE_TERMINAL_RESTART_NOTE is shown with the terminal and after it
// closes: the update replaces the binary on disk, and the running daemon
// keeps the old one until it restarts.
export const UPDATE_TERMINAL_RESTART_NOTE =
  "The update replaces the observer binary on disk. This daemon keeps running the old version until it restarts: use Restart daemon at the top of this page once the command has finished.";
