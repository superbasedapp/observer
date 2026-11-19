// newTerminalSandbox.ts holds the New Terminal dialog's sandbox and remote
// system decisions as pure functions (lane sbx-p2b, plans decision log
// P-017 (j) and P-026: the dialog's web tests). The dialog renders what these
// return; they own the honest disabled copy, so a test can pin every branch
// without rendering the dialog.

import {
  ISOLATION_AUTO,
  ISOLATION_NONE,
  backendNotes,
  isolationChoiceSummary,
  isolationOptions,
  launchBackend,
  unavailableRows,
  type IsolationOption,
  type UnavailableRow,
} from "./sandboxIsolation.ts";
import type { SandboxAvailability, SandboxHookNotice, SandboxKeyNotice, SandboxSourceAvail } from "./types.ts";
import { PLACES, type Place } from "./settingsPlaces.ts";
import { cloneURLProblem } from "./cloneURL.ts";

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
  /** The daemon's sentences about the chosen row (backendNotes). */
  notes: string[];
  /** The offered rows that cannot run here, each with its reason. */
  unavailable: UnavailableRow[];
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
  const chosen = value === ISOLATION_NONE ? undefined : probe?.backends?.find((b) => b.id === (value === ISOLATION_AUTO ? probe?.backend : value));
  return {
    options,
    value,
    disabled: reason !== null,
    reason,
    chip: isolationChoiceSummary(probe, choice),
    notes: backendNotes(chosen),
    unavailable: unavailableRows(probe),
  };
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
  /** Where a hosted row clones a clone-remote URL, when the launch chooses (SBXD-5). */
  workspace_clone_where?: string;
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
  /** The launch's own clone location (lib/hostedClone.ts cloneWhereLaunchValue; SBXD-5). */
  workspaceCloneWhere?: string;
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
    ...(input.workspaceRemote.trim() && input.workspaceCloneWhere ? { workspace_clone_where: input.workspaceCloneWhere } : {}),
    ...(input.branchApplies && input.workspaceBranch.trim() ? { workspace_branch: input.workspaceBranch.trim() } : {}),
  };
}

/**
 * chosenBackendRow is the row the Isolation picker resolves to (Automatic:
 * the probe's own pick), or undefined for None or a row the probe does not
 * list.
 */
export function chosenBackendRow(probe: SandboxAvailability | null, sandboxOn: boolean, choice: string) {
  if (!sandboxOn || !probe || choice === ISOLATION_NONE) return undefined;
  const id = choice === ISOLATION_AUTO ? probe.backend : choice;
  return probe.backends?.find((b) => b.id === id);
}

/**
 * rowSourceOffered reports whether the chosen row takes a workspace
 * source: true when no row is chosen or the row names no list of its own.
 */
export function rowSourceOffered(row: { label?: string; workspace_sources?: string[] } | undefined, source: string): boolean {
  return !row?.workspace_sources || row.workspace_sources.includes(source);
}

/** The parts of a backend row the workspace-source picker reads. */
type SourceRow = { label?: string; workspace_sources?: string[]; source_deliveries?: Record<string, string>; workspace_source_notes?: Record<string, string> };

/** One entry of the dialog's workspace-source picker. */
export type SandboxSourceOption = { id: string; label: string; disabled: boolean; title: string };

/**
 * sandboxSourceOptions is the dialog's workspace-source picker for the
 * chosen row: each source this machine offers, labelled by its delivery,
 * disabled when the probe says it is unavailable or the row does not take
 * it now. The reason comes from the data that says why: the row's own note
 * for a source it delivers but does not take now (workspace_source_notes,
 * say the remote-clone switch off on this machine), then the probe's reason;
 * "not offered by <row>" only for a source the row never takes.
 */
export function sandboxSourceOptions(
  row: SourceRow | undefined,
  sources: SandboxSourceAvail[] | undefined,
): SandboxSourceOption[] {
  return (sources ?? []).map((s) => {
    const name = sandboxSourceLabel(s.id, row);
    if (!rowSourceOffered(row, s.id)) {
      const note = row?.workspace_source_notes?.[s.id]?.trim();
      if (note) return { id: s.id, label: `${name} (not available now)`, disabled: true, title: note };
      const who = row?.label ?? "this backend";
      return { id: s.id, label: `${name} (not offered by ${who})`, disabled: true, title: `${row?.label ?? "This backend"} does not take this workspace source` };
    }
    if (!s.available) return { id: s.id, label: `${name} (unavailable)`, disabled: true, title: s.reason || "not available" };
    return { id: s.id, label: name, disabled: false, title: name };
  });
}

/**
 * sandboxSourceNotes are the lines the dialog shows under the picker for
 * the sources it disables with a reason the person can act on (a native
 * option's tooltip is easy to miss): "<source>: <the row's note>".
 */
export function sandboxSourceNotes(
  row: SourceRow | undefined,
  sources: SandboxSourceAvail[] | undefined,
): string[] {
  return (sources ?? [])
    .filter((s) => !rowSourceOffered(row, s.id) && !!row?.workspace_source_notes?.[s.id]?.trim())
    .map((s) => `${sandboxSourceLabel(s.id, row)}: ${row?.workspace_source_notes?.[s.id]?.trim()}`);
}

/**
 * A hosted launch's model key line, the row it is for, and whether it
 * blocks Start (a refusal) or is only said before it (which keys the agent
 * gets, or that it starts with none).
 */
export type HostedKeyBlock = SandboxKeyNotice & { backend: string; blocking: boolean };

/**
 * hostedKeyBlock is the line a hosted launch of `tool` meets on its model
 * key, for the row the Isolation picker resolves to (Automatic: the probe's
 * own pick): the tool's hosted_key line when that row runs on the
 * provider's machines, else null. The daemon decides the line with the
 * launch's own rule; this only says it before Start. A line blocks unless
 * the daemon marked it advisory (a daemon that predates the mark sent only
 * refusals, so an absent severity blocks).
 */
export function hostedKeyBlock(
  tool: string,
  probe: SandboxAvailability | null,
  sandboxOn: boolean,
  choice: string,
): HostedKeyBlock | null {
  if (!tool) return null;
  const row = chosenBackendRow(probe, sandboxOn, choice);
  if (!row || row.location !== "remote") return null;
  const n = probe?.tools?.[tool]?.hosted_key;
  return n && n.message ? { ...n, backend: row.id, blocking: n.severity !== "advisory" } : null;
}

/** The controls the key line offers under its sentence (decisions SBXD-1, SBXD-4). */
export type HostedKeyLineControls = {
  /** Where this launch keeps the key, in plain words (null: the daemon did not say). */
  where: string | null;
  /** Providers whose key, once pasted here, keeps the key on this machine. */
  keepHome: { id: string; label: string }[];
  /** "Also use the keys <tool> saved itself" (null: not offered for this launch). */
  toolKeys: { on: boolean; label: string } | null;
  /** "Also copy my <tool> login" (null: not offered for this launch). */
  loginSeed: { on: boolean; label: string } | null;
};

/**
 * hostedKeyLineControls reads the controls of a key line from the daemon's
 * answer only: it never decides which provider or tool qualifies (the
 * daemon's resolution table does), it only words them for `toolName`.
 */
export function hostedKeyLineControls(block: HostedKeyBlock | null, toolName: string): HostedKeyLineControls {
  const none: HostedKeyLineControls = { where: null, keepHome: [], toolKeys: null, loginSeed: null };
  if (!block) return none;
  const where =
    block.custody === "home_relay"
      ? "The key stays on this machine for this launch."
      : block.custody === "in_box_api_key"
        ? "The key goes into the box for this launch."
        : null;
  const name = toolName || "this agent";
  return {
    where,
    keepHome: block.keep_home ?? [],
    toolKeys: block.tool_keys ? { on: block.tool_keys.on, label: `Also use the keys ${name} saved itself` } : null,
    loginSeed: block.login_seed ? { on: block.login_seed.on, label: `Also copy my ${name} login (its short-lived access token only)` } : null,
  };
}

/** What a sandboxed launch's workspace choice blocks, before the POST. */
export type SandboxStartBlock = {
  /** "clone-remote" is chosen and the remote URL is empty. */
  remoteURLMissing: boolean;
  /** The chosen workspace source is in the probe and not available. */
  sourceUnavailable: boolean;
  /** The chosen hosted row cannot give this tool its model key. */
  hostedKey: boolean;
  /** The chosen hosted row cannot get this tool into its box. */
  hostedTool: boolean;
  /** The chosen hosted row cannot upload the chosen folder. */
  hostedWorkspace: boolean;
  /**
   * remoteURLProblem is what is wrong with the typed clone address, in plain
   * words (lib/cloneURL.ts, the daemon's own rules), or null.
   */
  remoteURLProblem: string | null;
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
  /** hostedKeyBlock's answer for the chosen row and tool (null: none). */
  hostedKey?: HostedKeyBlock | null;
  /** The chosen row (chosenBackendRow): a row that takes only some sources. */
  row?: { label: string; location?: string; workspace_sources?: string[]; workspace_source_notes?: Record<string, string> };
  /** hostedToolBlock's answer for the chosen row and tool (null: none). */
  hostedTool?: HostedKeyBlock | null;
  /** hostedWorkspaceBlock's answer for the chosen row, source and folder. */
  hostedWorkspace?: HostedWorkspaceBlock | null;
}): SandboxStartBlock {
  const active = input.sandboxOn && !input.controlDisabled;
  const avail = input.sources?.find((s) => s.id === input.source);
  const remoteURLMissing = active && input.source === "clone-remote" && input.remote.trim() === "";
  // A hosted row (location "remote") clones under the no-credential rule.
  const remoteURLProblem =
    active && input.source === "clone-remote" && !remoteURLMissing
      ? cloneURLProblem(input.remote, { noCredential: input.row?.location === "remote" })
      : null;
  const notOffered = active && !rowSourceOffered(input.row, input.source);
  const sourceUnavailable = active && ((avail !== undefined && !avail.available) || notOffered);
  const hostedKey = active && !!input.hostedKey;
  const hostedTool = active && !!input.hostedTool;
  const hostedWorkspace = active && !!input.hostedWorkspace && input.hostedWorkspace.blocking !== false;
  const blocks = remoteURLMissing || remoteURLProblem !== null || sourceUnavailable || hostedKey || hostedTool || hostedWorkspace;
  let message: string | null = null;
  if (remoteURLMissing) message = "Enter a remote URL to clone into the sandbox.";
  else if (remoteURLProblem) message = remoteURLProblem;
  else if (notOffered)
    message =
      input.row?.workspace_source_notes?.[input.source]?.trim() ||
      `${input.row?.label ?? "This backend"} does not take this workspace source - pick another one.`;
  else if (sourceUnavailable) message = "The selected workspace source isn't available - pick another one.";
  else if (hostedWorkspace) message = input.hostedWorkspace?.message ?? null;
  else if (hostedKey) message = input.hostedKey?.message ?? null;
  else if (hostedTool) message = input.hostedTool?.message ?? null;
  return { remoteURLMissing, sourceUnavailable, hostedKey, hostedTool, hostedWorkspace, remoteURLProblem, blocks, message };
}

/**
 * SANDBOX_SOURCE_LABELS maps the server's closed workspace-source vocabulary
 * (SandboxAvailability.sources[].id, mirrored 1:1 from internal/workspace's
 * Source constants) to the dialog's display labels; sandboxSourceLabel is
 * the one reader. Falls back to the raw id for a source the dialog has not
 * been taught yet, rather than hiding it.
 */
export const SANDBOX_SOURCE_LABELS: Record<string, string> = {
  live: "Live project directory",
  "clone-local": "Copy of the project (clone)",
  "clone-remote": "Clone a remote URL",
  worktree: "Worktree",
};

/**
 * DELIVERY_SOURCE_LABELS relabel a source by how the chosen row's box gets
 * it (the probe's source_deliveries), keyed "<source>:<delivery>": on a
 * hosted row the live source is an uploaded copy, never the folder itself,
 * so its label must not say "live" (lane UX, item H5).
 */
const DELIVERY_SOURCE_LABELS: Record<string, string> = {
  "live:sync": "Upload a copy of the project (changes come back as a diff)",
  "live:upload_snapshot": "Upload a copy of the project (changes come back as a diff)",
  // One source, "Clone a remote URL", whether the box or this machine
  // clones it (decision SBXD-5; the clone location picker says which).
  "clone-remote:remote_clone": "Clone a remote URL",
};

/**
 * sandboxSourceLabel is a workspace source's label for the chosen row: the
 * row's delivery label when the row says how the source reaches its box,
 * else the source's own label. Never branches on the row id.
 */
export function sandboxSourceLabel(source: string, row?: { source_deliveries?: Record<string, string> }): string {
  const delivery = row?.source_deliveries?.[source];
  if (delivery) {
    const byDelivery = DELIVERY_SOURCE_LABELS[`${source}:${delivery}`];
    if (byDelivery) return byDelivery;
  }
  return SANDBOX_SOURCE_LABELS[source] ?? source;
}

/**
 * hostedToolBlock is the refusal a hosted launch of `tool` would meet
 * because the tool cannot get into the box (no template set, and no install
 * way that can work there), for the row the Isolation picker resolves to:
 * that row's tool_notices line, else null. The daemon decides the line with
 * the launch's own rule (sandboxremote.PlanToolInstall); this only says it
 * before Start.
 */
export function hostedToolBlock(
  tool: string,
  probe: SandboxAvailability | null,
  sandboxOn: boolean,
  choice: string,
): HostedKeyBlock | null {
  if (!tool) return null;
  const row = chosenBackendRow(probe, sandboxOn, choice);
  if (!row || row.location !== "remote") return null;
  const n = row.tool_notices?.[tool];
  return n && n.message ? { ...n, backend: row.id, blocking: true } : null;
}

/** HOSTED_TOOL_PLACE is where a hosted tool notice is fixed when the daemon
 *  names no place (one that predates the field): Hosted sandboxes, where
 *  each provider's template is typed. */
export const HOSTED_TOOL_PLACE: Place = "terminal_sandbox_hosted";

/**
 * noticePlace is the settings place a pre-Start notice links to: the place
 * the daemon named when this dashboard knows it, else `fallback`. A place
 * this dashboard does not carry is never guessed into a path.
 */
export function noticePlace(n: { place?: string } | null | undefined, fallback: Place): Place {
  const p = n?.place;
  return p && Object.prototype.hasOwnProperty.call(PLACES, p) ? (p as Place) : fallback;
}

/** hostedToolPlace is where hostedToolBlock's notice links: the daemon's
 *  place, else Hosted sandboxes. */
export function hostedToolPlace(block: { place?: string } | null | undefined): Place {
  return noticePlace(block, HOSTED_TOOL_PLACE);
}

/**
 * hostedHookLine is what the dialog says before Start about guard in the
 * chosen hosted row's box for `tool` (lane HOOKS, SBXD-6): the row's
 * hook_notices line for the tool, as served (whether guard checks the
 * agent's commands there, and when it does not, the no-hook disclosure).
 * Null for a local row, none chosen, no tool, or a daemon that sends none.
 */
export function hostedHookLine(
  tool: string,
  row: { location: string; hook_notices?: Record<string, SandboxHookNotice> } | undefined,
): SandboxHookNotice | null {
  if (!tool || !row || row.location !== "remote") return null;
  const n = row.hook_notices?.[tool];
  return n && n.message ? n : null;
}

/**
 * hostedNetworkNotes are the chosen hosted row's sentences about its box's
 * own network at the configured tier (on a hosted internet tier: the
 * provider's network, the cloud metadata address not known to be refused),
 * shown as served before Start. Empty for a local row or none chosen.
 */
export function hostedNetworkNotes(row: { location: string; network_notes?: string[] } | undefined): string[] {
  if (!row || row.location !== "remote") return [];
  return row.network_notes ?? [];
}

/**
 * hostedUploadNeedsRepo reports whether the chosen row uploads `source` as
 * a copy of a git repository's files (delivery "sync", or a vendor row's
 * "upload_snapshot"): then the folder
 * must be a repository's own top level, which the dialog checks before
 * Start (lane UX, item H8).
 */
export function hostedUploadNeedsRepo(row: { source_deliveries?: Record<string, string> } | undefined, source: string): boolean {
  const d = row?.source_deliveries?.[source || "live"];
  return d === "sync" || d === "upload_snapshot";
}

/** GET /api/terminal/sandbox/hosted/workspace's answer for one folder. */
export type HostedWorkspaceReply = {
  dir: string;
  resolved?: string;
  ok: boolean;
  code?: string;
  message?: string;
  technical?: string;
};

/**
 * What the chosen folder's upload meets, said before Start: a refusal
 * (`blocking`: the folder cannot be uploaded) or a note that blocks nothing
 * (a folder that is not a git repository, uploaded through Observer's own
 * listing, decision SBXD-8), like the key line's advisory.
 */
export type HostedWorkspaceBlock = { code: string; message: string; technical?: string; blocking: boolean };

/**
 * hostedWorkspaceBlock is what a hosted launch meets on the chosen folder:
 * the refusal when it cannot be uploaded (inside a git repository, the home
 * folder, or not a repository while uploading such folders is off), or the
 * daemon's non-blocking note when it is uploaded although it is not a
 * repository: the daemon's answer for that folder when the chosen row
 * uploads the chosen source, else null. A reply for another folder, or none
 * (an older daemon, a failed read), blocks nothing: the launch still checks.
 */
export function hostedWorkspaceBlock(
  row: { source_deliveries?: Record<string, string> } | undefined,
  source: string,
  folder: string,
  reply: HostedWorkspaceReply | null,
): HostedWorkspaceBlock | null {
  if (!reply || !folder || reply.dir !== folder || !hostedUploadNeedsRepo(row, source)) return null;
  if (!reply.message) return null;
  return { code: reply.code ?? "", message: reply.message, technical: reply.technical, blocking: !reply.ok };
}
