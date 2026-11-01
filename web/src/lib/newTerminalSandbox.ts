// newTerminalSandbox.ts holds the New Terminal dialog's sandbox and remote
// system decisions as pure functions (lane sbx-p2b, plans decision log
// P-017 (j) and P-026: the dialog's web tests). The dialog renders what these
// return; they own the honest disabled copy, so a test can pin every branch
// without rendering the dialog.

import { ISOLATION_NONE, isolationChoiceSummary, isolationOptions, launchBackend, type IsolationOption } from "./sandboxIsolation.ts";
import type { SandboxAvailability, SandboxSourceAvail } from "./types.ts";

// SHELL_TOOL is the reserved pseudo-tool sentinel for a fresh PLAIN SHELL
// launch (must match internal/termsvc.ShellTool = "shell" verbatim). It is
// deliberately never a member of launchable_tools (the capability registry);
// the dialog adds it client-side as its own option, gated by the SEPARATE
// [terminal.launch].allow_shell opt-in (shell_enabled from GET
// /api/terminal/sessions), not the AI-tool allow-list.
export const SHELL_TOOL = "shell";

/**
 * sandboxDisabledReason computes the "Run in sandbox" control's disabled
 * copy, honoring the honest-copy convention (CLAUDE.md): every disabled
 * control names the exact blocker verbatim from the server, never a generic
 * "unavailable", AND, where the operator can fix it, says where the switch
 * lives, the way sshSystemDisabledReason below does.
 *
 * Priority: no tool picked > the probe has not resolved yet (or failed: a
 * broken probe disables the control rather than erroring the whole dialog)
 * > the daemon-wide verdict > the shell pseudo-tool (never in the capability
 * registry the probe's per-tool map is built from) > the selected tool's own
 * SandboxToolAvail.reason. Returns null when the control should be enabled.
 *
 * A host whose only available rows are beta (verdict beta_not_chosen, see
 * betaRowChoosable) is not a daemon-wide blocker: the control stays enabled
 * so a beta row can be chosen, and the picker keeps Automatic disabled with
 * its reason.
 *
 * The daemon-wide verdict is split three ways on purpose, because the three
 * have three different fixes:
 *   - disabled_by_config: nothing is broken, the feature is off; the switch
 *     is on this dashboard and the save binds immediately.
 *   - runtime_init_failed: the operator already enabled it and the daemon
 *     could not build the runtime; the server's reason is the actual error.
 *   - everything else (backend_missing, backend_too_old, userns_denied,
 *     unsupported_platform): an environment gap, quoted verbatim.
 */
export function sandboxDisabledReason(tool: string, probe: SandboxAvailability | null): string | null {
  if (!tool) return "Choose a tool first.";
  if (!probe) {
    return "Sandbox status unknown - this daemon may not support sandboxed terminals, or the probe request failed.";
  }
  if (!probe.available && !betaRowChoosable(probe)) {
    // D-514: a build without terminals.sandbox cannot be switched on from
    // Terminals -> Settings, so the copy must name the build, not the switch.
    if (probe.verdict === "not_in_build" || /not in this build/i.test(probe.reason ?? "")) {
      return `Sandbox isolation is not in this build - ${probe.reason || "the terminal sandbox component is not compiled in"}. Settings -> Components lists the builds that include it.`;
    }
    if (probe.verdict === "disabled_by_config") {
      return "Sandbox isolation is turned off. Enable it in Terminals -> Settings -> Sandbox isolation and save; it takes effect immediately.";
    }
    if (probe.verdict === "runtime_init_failed") {
      return `Sandbox isolation is enabled but the daemon could not start it - ${probe.reason || "the sandbox runtime failed to initialize"}. Fix it in Terminals -> Settings -> Sandbox isolation.`;
    }
    return `Sandbox unavailable - ${probe.reason || "sandboxing is unavailable on this daemon"}`;
  }
  if (tool === SHELL_TOOL) {
    return "A plain shell has no AI-tool state dirs to sandbox - not sandbox-launchable.";
  }
  const t = probe.tools?.[tool];
  if (!t || !t.available) {
    return t?.reason || "No grounded sandbox profile for this tool - not sandbox-launchable.";
  }
  return null;
}

/**
 * betaRowChoosable reports a host whose only available rows are beta
 * (verdict beta_not_chosen; every macOS and Windows host today). Automatic
 * selection never takes a beta row (ruling P-062), so the daemon-wide probe
 * says unavailable, yet a launch that names one of those rows runs. The
 * picker therefore stays enabled there and lists the beta rows labelled
 * beta, while Automatic stays disabled with its reason (audit SBX-P3B F1).
 */
export function betaRowChoosable(probe: SandboxAvailability | null): boolean {
  if (!probe || probe.available || probe.verdict !== "beta_not_chosen") return false;
  return (probe.backends ?? []).some((b) => b.maturity !== "planned" && b.available && b.beta);
}

/** The Isolation picker's props exactly as the New Terminal dialog renders them. */
export type IsolationPickerProps = {
  options: IsolationOption[];
  /** The entry shown: the chosen one while a sandboxed launch is on, else None. */
  value: string;
  disabled: boolean;
  reason: string | null;
  chip: string | null;
};

/**
 * isolationPickerProps is the one place the dialog's Isolation picker state is
 * computed, so a test renders the picker with exactly what the dialog passes.
 * A chosen entry the picker lists as disabled (Automatic on a beta-only host)
 * shows as None: the dialog then turns the sandboxed launch off rather than
 * posting a launch the daemon would refuse.
 */
export function isolationPickerProps(
  tool: string,
  probe: SandboxAvailability | null,
  sandboxOn: boolean,
  choice: string,
): IsolationPickerProps {
  const options = isolationOptions(probe);
  const reason = sandboxDisabledReason(tool, probe);
  const picked = options.find((o) => o.id === choice);
  const value = sandboxOn && !picked?.disabled ? choice : ISOLATION_NONE;
  return { options, value, disabled: reason !== null, reason, chip: isolationChoiceSummary(probe, choice) };
}

/**
 * sshSystemDisabledReason computes the System picker's disabled copy: the
 * kill switch ([terminal.ssh].enabled) beats an empty profile list, because
 * turning the feature back on is a prerequisite to a profile mattering at
 * all. Returns null when the picker should be enabled.
 */
export function sshSystemDisabledReason(enabled: boolean, profileCount: number): string | null {
  if (!enabled) {
    return "SSH remote-system terminals are off. Turn them on in Terminals > Settings > Remote systems (applies to the next launch, no restart).";
  }
  if (profileCount === 0) {
    return "No remote systems yet. Add one in Terminals > Settings > Remote systems (applies to the next launch, no restart).";
  }
  return null;
}

/** The sandbox part of POST /api/terminal/launch's body. */
export type SandboxLaunchFields = {
  sandbox?: true;
  backend?: string;
  workspace_source?: string;
  workspace_remote?: string;
  workspace_branch?: string;
  /** The dialog shows the inline sign-in step (lane BOXSIGNIN). */
  sign_in_ask?: true;
  /** The step's answer: copy the tool's sign-in into the box, or not. */
  sign_in_seed?: boolean;
};

/**
 * sandboxLaunchFields is the sandbox part of the launch request, the one
 * place the dialog builds it. Off, it is empty, so the body is byte-identical
 * to a launch without the feature. A row chosen in the Isolation picker is
 * sent as `backend`, a beta row (mxc-process on Windows, seatbelt on a Mac)
 * included: choosing it in the dialog is the same explicit choice as the
 * CLI's --observer-sandbox <row> (Windows 11 Pro live run, B4). Automatic
 * sends no backend, so the daemon's own pick never takes a beta row (ruling
 * P-062). The server re-validates the row against its own probe.
 */
export function sandboxLaunchFields(input: {
  sandboxOn: boolean;
  isolationChoice: string;
  workspaceSource: string;
  workspaceRemote: string;
  workspaceBranch: string;
  branchApplies: boolean;
  /** The inline sign-in step's answer for this launch (lane BOXSIGNIN). */
  signInSeed?: boolean;
}): SandboxLaunchFields {
  if (!input.sandboxOn) return {};
  const backend = launchBackend(input.isolationChoice);
  return {
    sandbox: true,
    // The dialog can ask: a launch that could copy the tool's sign-in into
    // its box answers 409 sign_in_consent with the question instead of
    // starting, and the inline step answers it (lane BOXSIGNIN).
    sign_in_ask: true,
    ...(input.signInSeed !== undefined ? { sign_in_seed: input.signInSeed } : {}),
    ...(backend ? { backend } : {}),
    workspace_source: input.workspaceSource || "live",
    ...(input.workspaceRemote.trim() ? { workspace_remote: input.workspaceRemote.trim() } : {}),
    ...(input.branchApplies && input.workspaceBranch.trim() ? { workspace_branch: input.workspaceBranch.trim() } : {}),
  };
}

/** What a sandboxed launch's workspace choice blocks, before the POST. */
export type SandboxStartBlock = {
  /** "clone-remote" is chosen and the remote URL is empty. */
  remoteURLMissing: boolean;
  /** The chosen workspace source is in the probe and not available. */
  sourceUnavailable: boolean;
  /** Start is blocked; message says why. */
  blocks: boolean;
  message: string | null;
};

/**
 * sandboxStartBlock is the client-side hint that keeps an obviously doomed
 * sandboxed launch from being posted (the server re-validates regardless).
 * It applies only while a sandboxed launch is chosen and the control is
 * enabled: a source left on "clone-remote" with no URL, or a source the
 * probe reports unavailable, blocks Start with a message.
 */
export function sandboxStartBlock(input: {
  sandboxOn: boolean;
  controlDisabled: boolean;
  source: string;
  remote: string;
  sources: SandboxSourceAvail[] | undefined;
}): SandboxStartBlock {
  const active = input.sandboxOn && !input.controlDisabled;
  const avail = input.sources?.find((s) => s.id === input.source);
  const remoteURLMissing = active && input.source === "clone-remote" && input.remote.trim() === "";
  const sourceUnavailable = active && avail !== undefined && !avail.available;
  const blocks = remoteURLMissing || sourceUnavailable;
  let message: string | null = null;
  if (remoteURLMissing) message = "Enter a remote URL to clone into the sandbox.";
  else if (sourceUnavailable) message = "The selected workspace source isn't available - pick another one.";
  return { remoteURLMissing, sourceUnavailable, blocks, message };
}
