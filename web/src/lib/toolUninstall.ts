import type { ToolInstallRecord } from "./types.ts";

// Pure copy + decision helpers for the dashboard-install record and its
// Uninstall (New terminal dialog strip + Settings > Connected tools). The
// server owns every decision that matters (can_uninstall, the exact command,
// the guidance for a channel with no defined uninstall); this module only
// phrases it, so the two surfaces can never say different things.

// fmtInstallDate renders a record timestamp as a short local date.
export function fmtInstallDate(iso: string | undefined): string {
  if (!iso) return "an unknown date";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "an unknown date";
  return d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

// INSTALL_STATUS_COPY is the closed lifecycle vocabulary of
// internal/toolinstall, as a table (one row per status). `tone` drives the
// line's colour; `present` is true when the tool is (or may be) still
// installed by the dashboard, which is when an Uninstall can make sense.
export const INSTALL_STATUS_COPY: Record<
  string,
  { tone: "info" | "ok" | "warn"; present: boolean; line: (date: string) => string }
> = {
  installing: { tone: "info", present: false, line: (d) => `Installing from this dashboard (started ${d}).` },
  installed: { tone: "ok", present: true, line: (d) => `Installed from this dashboard on ${d}.` },
  installed_not_found: {
    tone: "warn",
    present: true,
    line: (d) => `The install started from this dashboard on ${d} finished, but the tool was not found afterwards.`,
  },
  install_failed: {
    tone: "warn",
    present: false,
    line: (d) => `The install started from this dashboard on ${d} did not finish successfully, so there is nothing to uninstall.`,
  },
  install_interrupted: {
    tone: "warn",
    present: true,
    line: (d) => `An install started from this dashboard on ${d} was interrupted before it finished; it may be partly installed.`,
  },
  uninstalling: { tone: "info", present: true, line: () => "Uninstalling from this dashboard." },
  uninstalled: { tone: "info", present: false, line: (d) => `Installed from this dashboard on ${d}, and since uninstalled.` },
  uninstall_failed: {
    tone: "warn",
    present: true,
    line: (d) => `Installed from this dashboard on ${d}. The last uninstall did not finish successfully.`,
  },
  uninstall_interrupted: {
    tone: "warn",
    present: true,
    line: (d) => `Installed from this dashboard on ${d}. The last uninstall was interrupted before it finished.`,
  },
};

export type InstallRecordView = {
  tone: "info" | "ok" | "warn";
  headline: string;
  /** Second line: what was installed and how. */
  detail: string | null;
  /** The Uninstall button is offered. */
  showUninstall: boolean;
  /** The armed-confirm note naming exactly what will be removed and how. */
  confirmNote: string | null;
  /** Honest guidance for a channel with no defined uninstall. */
  guidance: string | null;
  /** The Forget button is offered. */
  showForget: boolean;
  /** Extra fact (e.g. the binary still resolves after an uninstall). */
  note: string | null;
  /** The run may be sitting at a prompt: offer to open its terminal. */
  waitingForInput: boolean;
};

// installNotFoundRemedy is the next step when an installer exited 0 but its
// binary does not resolve (T-034j): name the likely causes and the fix.
export const installNotFoundRemedy =
  "The installer reported success, but the dashboard cannot find the program it should have installed. " +
  "It may have been installed into a folder that is not on PATH yet (open a new terminal, or check the end of the install terminal's output for a PATH step), " +
  "or into another environment than this one. Fix the cause and press Re-check, or start the install again.";

// waitingForInputNote is shown while an install or uninstall has run long
// enough that it may be waiting at a prompt in its terminal (T-034j).
export const waitingForInputNote =
  "This is taking a while. The installer may be waiting for input: open its terminal to answer the prompt or to see where it stopped.";

// installFailedRemedy is the next step under a failed guided install, so the
// record never stops at "did not finish successfully". The installer is the
// vendor's own script and its real error is in the install terminal's output,
// so this names where to look and the usual causes, not a guess at which one
// happened.
export function installFailedRemedy(exitCode: number | null | undefined): string {
  const outcome = typeof exitCode === "number" ? `exited with code ${exitCode}` : "failed";
  return (
    `The installer ${outcome}. Its own error message is in the install terminal's output. ` +
    "Common causes: no network access to the vendor's download host (a proxy or firewall in the way), " +
    "a program the installer needs is missing (such as curl, tar or bzip2), or a folder it writes to is not writable. " +
    "Fix the cause and start the install again, or run the install command yourself in a terminal."
  );
}

// installRecordView phrases one record. Dispatch is on the server-reported
// STATUS and capability flags, never the tool's or channel's name.
export function installRecordView(rec: ToolInstallRecord): InstallRecordView {
  const row = INSTALL_STATUS_COPY[rec.status];
  const date = fmtInstallDate(rec.installed_at);
  const headline = row
    ? row.line(date)
    : `Installed from this dashboard on ${date} (status: ${rec.status || "unknown"}).`;
  const what = rec.package ? `${rec.package} via ${rec.channel}` : `with ${rec.channel === "script" ? "the vendor's install script" : rec.channel}`;
  const present = row ? row.present : true;
  const showUninstall = rec.can_uninstall && !!rec.uninstall_command;
  const confirmNote = showUninstall
    ? `Removes ${rec.package || rec.tool} by running: ${rec.uninstall_command}`
    : null;
  const guidance = present && !rec.uninstall_command && rec.uninstall_guidance ? rec.uninstall_guidance : null;
  let note: string | null = null;
  if (rec.status === "uninstalled" && rec.resolved_bin) {
    note = `${rec.tool} still resolves at ${rec.resolved_bin} - another install (not from this dashboard) provides it.`;
  } else if (rec.status === "install_failed") {
    note = installFailedRemedy(rec.exit_code);
  } else if (rec.status === "installed_not_found") {
    note = installNotFoundRemedy;
  }
  const waitingForInput = !!rec.maybe_waiting_for_input;
  if (waitingForInput) note = waitingForInputNote;
  return {
    tone: row ? row.tone : "info",
    headline,
    detail: `Installed ${what}: ${rec.command}`,
    showUninstall,
    confirmNote,
    guidance,
    showForget: rec.can_forget,
    note,
    waitingForInput,
  };
}

// uninstallErrorMessage turns a thrown POST /api/terminal/uninstall failure
// into copy. Status dispatch is correct here for the same reason it is on the
// install route (toolInstall.ts): each status names one blocker. The server's
// own sentence is kept for the 409s, which carry the specific reason (a stale
// record, a channel with no uninstall, a setup terminal already running).
export function uninstallErrorMessage(status: number, reason: string): string {
  switch (status) {
    case 503:
      return "The in-dashboard terminal is unavailable on this daemon, so there is nowhere to run the uninstaller. Dashboard launch may be turned off (handoff.allow_dashboard_launch, under More settings in Settings > Session attach).";
    case 403:
      return /confirm token/i.test(reason)
        ? "The dashboard's confirm token for this panel is stale - reload the page and try again."
        : "Guided install and uninstall are switched off. Turn on \"Allow guided install and uninstall\" in Terminals > Settings > Fresh-agent launch policy, or run the uninstall command yourself in a terminal.";
    case 404:
      return "This dashboard has no record of installing this tool, so it will not uninstall it.";
    case 501:
      return "This dashboard runs without the install record (run superbased with `observer start`).";
    default:
      return reason || "The uninstall could not be started.";
  }
}
