import { Suspense, useEffect, useId, useMemo, useRef, useState } from "react";
import { SANDBOX_ISOLATION_PICKER } from "@/lib/components.gen";
import { Link } from "react-router-dom";
import { EyeOff, Lock, PowerOff, type LucideIcon } from "lucide-react";
import { ApiError, apiReason, fetchJSON, localConfirmHeaders } from "@/lib/api";
import { terminalsRefusalSentence } from "@/lib/governanceRefusal";
import {
  acceptAllBody,
  acceptNote,
  acceptOffered,
  acceptOneBody,
  pendingReasons,
  reasonLine,
  trustChip,
  type TrustAcceptBody,
  type TrustReply,
} from "@/lib/trustChip";
import { projectPolicyView, type ProjectPolicyReply } from "@/lib/projectPolicyLine";
import {
  ISOLATION_AUTO,
  ISOLATION_NONE,
  defaultIsolationChoice,
  isolationOptions,
} from "@/lib/sandboxIsolation";
import { SHELL_TOOL, isolationPickerProps, sandboxLaunchFields, sandboxStartBlock, sshSystemDisabledReason } from "@/lib/newTerminalSandbox";
import { DashboardInstallRecord } from "@/components/DashboardInstallRecord";
import type {
  GUILaunchable,
  UnlaunchableTool,
  GUILaunchResponse,
  GUIRun,
  LaunchableTool,
  ProjectRow,
  ProjectsResponse,
  SandboxAvailability,
  SSHProfileInfo,
  SSHProfilesResponse,
  TerminalSessionsMeta,
  ToolModels,
  ToolPreflight,
} from "@/lib/types";
import {
  PROJECT_ROOT_DENIED_MSG,
  REMOTE_TERMINAL_OFF_MSG,
  isProjectRootDeniedError,
  isTerminalCapabilityError,
  useRemoteTerminalGate,
} from "@/lib/remoteTerminal";
import {
  PREFLIGHT_NOTE_CAP,
  TOOL_NOT_WATCHED_MSG,
  annotateTool,
  installErrorMessage,
  installGuidanceFor,
  launchBlockedFor,
  launchBlockedReason,
  installRuntimeAdvisory,
  installRuntimeParts,
  launchRuntimeParts,
  launchRuntimeRemedy,
  pickerLegend,
  preflightErrorCopy,
  preflightStripCopy,
  type PreflightState,
} from "@/lib/toolInstall";
import { installPrereqRemedyFor } from "@/lib/installPrereq";
import { RuntimeRemedy } from "@/components/RuntimeRemedy";
import {
  guiLaunchDisabledReason,
  guiLaunchErrorMessage,
  isGUISelection,
} from "@/lib/guiLaunch";
import { guiAvailabilityName, guiLaunchSummary, guiLaunchedToast } from "@/lib/guiLaunchCopy";
import {
  buildToolPickerItems,
  preferredDefaultTool,
  type PickerStatus,
  type ToolPickerItem,
} from "@/lib/toolPicker";
import { toolMeta } from "@/lib/tools";
import {
  TERMINALS_FOLDERS_HASH,
  TERMINALS_LAUNCH_POLICY_HASH,
  TERMINALS_REMOTE_SYSTEMS_HASH,
} from "@/lib/nodePageTabs";
import { pushToast } from "@/components/Toast";
import {
  AllowFolderStep,
  FreshLaunchStep,
  SignInSeedStep,
  applyLaunchPolicyChange,
  isFreshLaunchDisabledError,
  postLaunchAskingSignIn,
  type SignInConsent,
} from "@/components/LaunchPolicyInline";
import { folderNeedsAllow, isPermittedRoot, stepHoldsStart } from "@/lib/launchPolicyStep";
import {
  Button,
  ComboChip,
  type ComboOption,
  Icon,
  Modal,
  Pill,
  ToolDot,
  Tooltip,
  TooltipSpan,
} from "@/components/primitives";

// Sentinel <select> value for the "type a path by hand" escape hatch. A NUL
// byte can never be a real project root, so it can't collide with one. The NUL
// is an ESCAPE (\u0000), never a literal byte — a literal NUL makes git treat
// this whole file as binary, hiding every change from diff review.
const CUSTOM_ROOT = "\u0000custom";


// LOCAL_SYSTEM is the "System" selector's sentinel for "this machine" — the
// ONLY value before the SSH feature existed, and the value that keeps this
// dialog byte-identical to its pre-SSH behaviour. A profile name can never
// collide with it: profile names are [a-z0-9][a-z0-9._-]* server-side, so they
// can never be empty.
const LOCAL_SYSTEM = "";

// SANDBOX_SOURCE_LABELS maps the server's closed workspace-source vocabulary
// (SandboxAvailability.sources[].id, mirrored 1:1 from internal/workspace's
// Source constants) to the dialog's display labels — the ONE place that
// vocabulary is spelled out for humans. Falls back to the raw id for any
// future source the dialog hasn't been taught about yet, rather than hiding
// it.
const SANDBOX_SOURCE_LABELS: Record<string, string> = {
  live: "Live project directory",
  "clone-local": "Copy of the project (clone)",
  "clone-remote": "Clone a remote URL",
  worktree: "Worktree",
};

// The sources whose launch takes a branch: a clone checks the name out as a
// new branch, a worktree run names its own branch's last component with it
// (observer-sandbox/<run>/<label>, "work" when empty).
const BRANCH_SOURCES: Record<string, { placeholder: string; hint: string }> = {
  "clone-remote": { placeholder: "main", hint: "" },
  worktree: {
    placeholder: "work",
    hint: "The run works on its own branch observer-sandbox/<run>/<name>; empty means \"work\".",
  },
};

/** branchField returns how the workspace panel shows the branch field for a
 * source: null when the source takes no branch. */
export function branchField(source: string): { placeholder: string; hint: string } | null {
  return BRANCH_SOURCES[source] ?? null;
}

// WORKTREE_BRANCH_RULES mirrors internal/workspace.ValidateRefComponent (git
// check-ref-format's rules for one ref component), the check the daemon
// enforces; here it only names the problem before a doomed submit.
const WORKTREE_BRANCH_RULES: { why: string; bad: (s: string) => boolean }[] = [
  { why: "is longer than 100 characters", bad: (s) => s.length > 100 },
  { why: "must not contain / or \\", bad: (s) => /[/\\]/.test(s) },
  // eslint-disable-next-line no-control-regex
  { why: "must not contain spaces or control characters", bad: (s) => /[\x00-\x20\x7f]/.test(s) },
  { why: "must not begin with - or .", bad: (s) => s.startsWith("-") || s.startsWith(".") },
  { why: "must not end with . or .lock", bad: (s) => s.endsWith(".") || s.endsWith(".lock") },
  { why: "must not contain .. or @{", bad: (s) => s.includes("..") || s.includes("@{") },
  { why: "must not be @", bad: (s) => s === "@" },
  { why: "must not contain any of ~ ^ : ? * [", bad: (s) => /[~^:?*[]/.test(s) },
];

/** worktreeBranchProblem names why a worktree branch name would be refused,
 * or null (an empty name is fine: the run uses "work"). Other sources are
 * checked by git itself. */
export function worktreeBranchProblem(source: string, branch: string): string | null {
  const b = branch.trim();
  if (source !== "worktree" || b === "") return null;
  for (const r of WORKTREE_BRANCH_RULES) {
    if (r.bad(b)) return `The branch name ${r.why} (it must be one git branch name component).`;
  }
  return null;
}

// STATUS_ICONS gives each picker status badge its glyph, so a status pill
// never reads like the neighbouring kind pill (CLI / IDE / Desktop). One row
// per status (CLAUDE.md #5); the words come from toolPicker.STATUS_LABELS.
const STATUS_ICONS: Record<PickerStatus, LucideIcon> = {
  not_allowed: Lock,
  not_captured: EyeOff,
  shell_off: PowerOff,
};

// PickerStatusPill is a picker row's muted status badge (Not allowed to
// launch / Not captured / Turned off), or nothing.
function PickerStatusPill({ item }: { item: ToolPickerItem }) {
  if (!item.status || !item.statusLabel) return null;
  return (
    <Pill case="none" icon={STATUS_ICONS[item.status]} className="!font-medium !text-fg-3">
      {item.statusLabel}
    </Pill>
  );
}

// PickerOptionLabel is a picker row's primary line: the human name, then the
// surface kind as a small badge, then (from the sm breakpoint up, where the
// row is wide enough) the status badge. Below sm the status moves to the
// secondary line (pickerOptionDetail) so a phone-width row never truncates
// the name to make room for it.
function PickerOptionLabel({ item }: { item: ToolPickerItem }) {
  return (
    <span className="flex min-w-0 items-center gap-1.5">
      <span className="min-w-0 truncate font-medium">{item.name}</span>
      <Pill case="none" className="shrink-0">
        {item.kindLabel}
      </Pill>
      {item.status && (
        <span className="ml-auto hidden shrink-0 sm:inline-flex">
          <PickerStatusPill item={item} />
        </span>
      )}
    </span>
  );
}

// pickerOptionDetail is a picker row's secondary line (ComboOption.detail):
// the status badge below sm, then any host list. ComboChip truncates it while
// the row is idle and shows it in full while the row is hovered/focused, so
// the long "Agents: ..." list never needs a tooltip over the list. Returns
// undefined when there is nothing to say (single-line row).
function pickerOptionDetail(item: ToolPickerItem) {
  if (!item.status && !item.detail) return undefined;
  return (
    <>
      {item.status && (
        <span className="mr-1 sm:hidden">
          <PickerStatusPill item={item} />
        </span>
      )}
      {item.detail}
    </>
  );
}

// Deep links into the Terminals Settings cards this dialog points at
// (T-488 / T-489): the dashboard controls that replaced the old
// "edit config.toml and restart" instructions.
const TERMINALS_LAUNCH_POLICY_HASH_PATH = `/terminals${TERMINALS_LAUNCH_POLICY_HASH}`;
const TERMINALS_FOLDERS_HASH_PATH = `/terminals${TERMINALS_FOLDERS_HASH}`;
const TERMINALS_REMOTE_SYSTEMS_HASH_PATH = `/terminals${TERMINALS_REMOTE_SYSTEMS_HASH}`;

// shortenPath renders an absolute root as ".../parent/leaf" for the option
// label (the full path rides along as the option title). Mirrors the
// FilterBar project-picker convention so the two surfaces read the same.
function shortenPath(p: string): string {
  if (!p) return "-";
  const parts = p.split("/").filter(Boolean);
  if (parts.length <= 2) return p;
  return ".../" + parts.slice(-2).join("/");
}

// isPermittedRoot and folderNeedsAllow (the allow-list partition, a UX hint;
// the server's canonical check is the only authority) live in
// lib/launchPolicyStep.ts, beside the inline step's states.

// POLICY_STEP_PENDING is Start's tip while an inline launch-policy step
// (Allow this folder, Turn on fresh-agent launch) has a change open.
const POLICY_STEP_PENDING = "Save or cancel the config change above first";

// NewTerminalDialog is the F1 "New terminal" affordance: start a FRESH agent
// (no --continue-from) in the embedded web terminal. The tool picker is
// populated from GET /api/terminal/sessions (launchable_tools — the capability
// registry), and the optional project root is validated + canonicalized
// server-side against the operator's [terminal.launch].allowed_project_roots.
//
// Fresh launch is a default-OFF opt-in ([terminal.launch].allow_fresh_agent):
// when the operator hasn't enabled it the POST returns 403 and we surface the
// honest reason rather than pretending it worked.

export type NewTerminalDraft = {
  tool: string;
  /** Selected SSH system ("" = this machine). See LOCAL_SYSTEM. */
  sshProfile?: string;
  rootSel: string;
  customRoot: string;
  modelSel: string;
  sandboxOn: boolean;
  workspaceSource: string;
  workspaceRemote: string;
  workspaceBranch: string;
  /**
   * Present ("gui") only when `tool` names a GUI (IDE/desktop-app)
   * launchable rather than a terminal AI tool — set so an installer-resumed
   * GUI selection is self-describing. The dialog re-derives the live
   * gui/terminal branch from `gui_launchables` on every render either way
   * (isGUISelection); this field is not itself load-bearing for that.
   */
  kind?: "gui";
};

type Props = {
  onClose: () => void;
  initialDraft?: NewTerminalDraft;
  /**
   * initialSandboxProbe seeds the sandbox probe before its fetch answers.
   * Only the component tests pass it (server rendering runs no effect, so
   * the probe fetch never answers there); the dialog fetches it either way.
   */
  initialSandboxProbe?: SandboxAvailability;
  /**
   * initialWindowsPathsToWSL seeds the sessions meta's windows_paths_to_wsl
   * before its fetch answers (component tests only, like
   * initialSandboxProbe).
   */
  initialWindowsPathsToWSL?: boolean;
  resumedAfterInstall?: boolean;
  /**
   * Called with the minted handle + tool once a fresh launch succeeds. The
   * third arg (review finding 8) reports whether the launch was given a project
   * root, so the dock enables Files/Git without a reload. The fourth arg is
   * present only for a guided installer: the dock restores that exact launch
   * draft when the installer terminal exits. Absence ≡ false/no resume.
   */
  onLaunched: (
    handle: string,
    tool: string,
    hasProjectRoot?: boolean,
    resumeDraft?: NewTerminalDraft,
  ) => void;
};

type FreshLaunchResponse = { token: string; tool: string; subcommand: string; has_project_root?: boolean };

// SSHLaunchResponse is the reply from POST /api/terminal/ssh. `label` names the
// system so the terminal tab header can never be mistaken for a local shell.
type SSHLaunchResponse = { token: string; tool: string; profile: string; label: string };

export function NewTerminalDialog({
  onClose,
  onLaunched,
  initialDraft,
  initialSandboxProbe,
  initialWindowsPathsToWSL = false,
  resumedAfterInstall = false,
}: Props) {
  const [tools, setTools] = useState<string[]>([]);
  // Per-tool annotations from the SAME GET /api/terminal/sessions reply
  // (launchable_tool_info — audit DI-06). Sourced from /sessions, which is a
  // VIEW route, and deliberately NOT from /api/terminal/policy, which is
  // owner-LOCAL and 403s for a paired remote device. Empty = the daemon
  // predates the field, which means UNKNOWN, never "not allowed".
  const [toolInfo, setToolInfo] = useState<LaunchableTool[]>([]);
  // The /api/terminal/sessions failure, surfaced instead of swallowed (DI-05).
  // Before this, a 503 on that route left the picker reading "no launchable
  // tools" with no hint that the request had failed at all.
  const [toolsError, setToolsError] = useState<string | null>(null);
  const [tool, setTool] = useState(initialDraft?.tool ?? "");
  // Known project roots (GET /api/projects, ordered most-recent-first) power
  // the working-directory dropdown; the user can still pick "Custom path…" to
  // type an arbitrary one. `rootSel` is the <select> value; `customRoot` holds
  // the hand-typed path only while CUSTOM_ROOT is selected.
  const [projects, setProjects] = useState<ProjectRow[]>([]);
  // The operator's canonicalized [terminal.launch].allowed_project_roots, straight
  // from GET /api/terminal/sessions. Used verbatim to mark which roots a fresh
  // launch will actually accept (empty = deny-all: only the agent's default cwd).
  const [allowedRoots, setAllowedRoots] = useState<string[]>([]);
  // The launch route refused because [terminal.launch].allow_fresh_agent is
  // off: the dialog then offers the inline step instead of the bare 403
  // (Windows 11 Pro rerun 2026-10-25, R3).
  const [freshOff, setFreshOff] = useState(false);
  // The launch's sign-in consent question (lane BOXSIGNIN): set from the
  // launch route's 409 and answered by the inline step, which starts the
  // launch again with the answer.
  const [signInConsent, setSignInConsent] = useState<SignInConsent | null>(null);
  // Folders the inline "Allow this folder" step saved in this dialog (B4,
  // Windows 11 Pro run 4): the step is gone once the folder is saved even
  // where the server stores another spelling (a daemon in WSL keeps C:\x as
  // /mnt/c/x), so the folder stays selected and Start works at once.
  const [savedRoots, setSavedRoots] = useState<string[]>([]);
  // An inline launch-policy step that is confirming, reviewing or saving its
  // change holds Start until it ends (lib/launchPolicyStep.ts stepHoldsStart).
  const [policyStepBusy, setPolicyStepBusy] = useState(false);
  // refreshAllowedRoots re-reads the canonical allow-list after the inline
  // "Allow this folder" step saved it (the server canonicalizes the path).
  function refreshAllowedRoots() {
    return fetchJSON<TerminalSessionsMeta>("/api/terminal/sessions").then((d) =>
      setAllowedRoots(d.allowed_project_roots ?? []),
    );
  }
  // shell_enabled from GET /api/terminal/sessions — the SEPARATE
  // [terminal.launch].allow_shell opt-in that gates the Shell option below,
  // independent of allow_fresh_agent / allowed_tools.
  const [shellEnabled, setShellEnabled] = useState(false);
  // windows_paths_to_wsl from the same reply: the custom-root hint about
  // Windows paths shows only for a daemon inside WSL (B4).
  const [windowsPathsToWSL, setWindowsPathsToWSL] = useState(initialWindowsPathsToWSL);
  // IDE / desktop-app rows (T2.3), from the SAME GET /api/terminal/sessions
  // reply — a sibling of launchable_tools, never a replacement. Empty on an
  // older daemon (the key is simply absent), which means "no GUI section",
  // never an error.
  const [guiLaunchables, setGuiLaunchables] = useState<GUILaunchable[]>([]);
  // Live/recently-exited GUI runs this daemon has spawned, same source.
  const [guiRuns, setGuiRuns] = useState<GUIRun[]>([]);
  // Advertised products the picker lists but cannot start (T-494), same
  // source; empty on an older daemon.
  const [unlaunchable, setUnlaunchable] = useState<UnlaunchableTool[]>([]);
  // SSH remote-system profiles (GET /api/terminal/ssh). `sshProbed` is
  // distinct from `sshEnabled`: it tracks whether the route answered at all,
  // so a genuinely old daemon (no /api/terminal/ssh route — 404) still hides
  // the System row entirely (fail-silent, matching every other probe in this
  // dialog), while a modern daemon's honest enabled:false or empty-profiles
  // reply still renders the row — visible-by-default per the 2026-08-28
  // operator ruling — with disabled copy naming the exact blocker (see
  // sshSystemDisabledReason).
  const [sshProbed, setSshProbed] = useState(false);
  const [sshEnabled, setSshEnabled] = useState(false);
  const [sshProfiles, setSshProfiles] = useState<SSHProfileInfo[]>([]);
  // The chosen system: "" (LOCAL_SYSTEM) = this machine, otherwise a profile
  // NAME. The name is the ONLY thing sent to the server; host/user/key/port are
  // resolved from the operator's config server-side and never travel from here.
  const [sshProfile, setSshProfile] = useState(initialDraft?.sshProfile ?? LOCAL_SYSTEM);
  const [rootSel, setRootSel] = useState(initialDraft?.rootSel ?? "");
  const [customRoot, setCustomRoot] = useState(initialDraft?.customRoot ?? "");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  // Pre-launch binary-resolution verdict for the selected tool (tool-binary-
  // resolution arc). Null when unknown, the seam is disabled (501), or the fetch
  // failed — in every case the strip simply doesn't render (fail-silent), so an
  // older daemon without the preflight endpoint behaves exactly as before.
  const [preflight, setPreflight] = useState<ToolPreflight | null>(null);
  // Whether the preflight ROUTE answered at all (DI-17). Before this, a 501 /
  // 400 / network failure was indistinguishable from "not asked yet": the
  // strip rendered nothing and Start stayed enabled, so a daemon that could
  // not check looked exactly like a healthy tool.
  const [preflightState, setPreflightState] = useState<PreflightState>("unknown");
  const [preflightErr, setPreflightErr] = useState("");
  // Bumped by the "Re-check" button to re-run the preflight effect without a
  // tool change or a dialog remount (DI-17: there was no manual re-check, so
  // installing a tool in another window could not be reflected here).
  const [recheckNonce, setRecheckNonce] = useState(0);
  const [installBusy, setInstallBusy] = useState(false);
  // Model-suggestion list for the selected tool (B5 model picker), from GET
  // /api/terminal/launch/models. Null when unknown, the tool doesn't support
  // model selection, the seam is disabled (404/501 on an older daemon), or the
  // fetch failed — in every case the picker simply doesn't render, mirroring
  // the preflight strip's fail-silent degrade.
  const [toolModels, setToolModels] = useState<ToolModels | null>(null);
  // The user's explicit model choice; "" means "use the tool's own default"
  // and is never sent on the launch POST.
  const [modelSel, setModelSel] = useState(initialDraft?.modelSel ?? "");
  const previousTool = useRef(tool);

  // Preserve an installer-resumed model on the first render, then clear it on
  // every real adapter transition — including a server-driven fallback when a
  // resumed adapter is no longer launchable. A dropdown-only reset misses that
  // fallback and can send one adapter's model to another.
  useEffect(() => {
    if (previousTool.current === tool) return;
    previousTool.current = tool;
    setModelSel("");
    // A failure belonging to the PREVIOUS tool must not be read as a verdict on
    // the new one (DI-17) — e.g. "codex is not installed" left hanging under a
    // freshly-selected claude-code.
    setErr(null);
  }, [tool]);
  // Sandbox probe result (B9 U7), from GET /api/terminal/sandbox. Null when
  // unfetched, the seam is disabled (an older daemon has no such route), or
  // the fetch failed — mirrors the preflight/model-picker fail-silent
  // degrade: the checkbox below simply renders disabled, never an error.
  // Fetched once on dialog open (the response already carries a per-tool
  // map covering every launchable tool, so a tool-change never needs its own
  // refetch — see sandboxDisabledReason).
  const [sandboxProbe, setSandboxProbe] = useState<SandboxAvailability | null>(initialSandboxProbe ?? null);
  // Whether the user has opted into a sandboxed launch. Seeded from the
  // server's [terminal.sandbox].default_on signal once the probe resolves;
  // the checkbox remains an explicit per-launch override.
  const [sandboxOn, setSandboxOn] = useState(initialDraft?.sandboxOn ?? false);
  // The Isolation picker's entry while sandboxOn is set: "Automatic" (the
  // daemon picks, never a beta row) by default, or a row chosen for this
  // launch (lane SBX-P3B), which the launch body then names.
  const [isolationChoice, setIsolationChoice] = useState(
    () => (initialSandboxProbe && defaultIsolationChoice(isolationOptions(initialSandboxProbe))) || ISOLATION_AUTO,
  );
  // True when the probe route answered 404 component_not_installed: the
  // Sandboxes and VMs module is not installed, so no Isolation picker shows.
  const [sandboxModuleAbsent, setSandboxModuleAbsent] = useState(false);
  const [workspaceSource, setWorkspaceSource] = useState(
    initialDraft?.workspaceSource ?? "live",
  );
  const [workspaceRemote, setWorkspaceRemote] = useState(
    initialDraft?.workspaceRemote ?? "",
  );
  const [workspaceBranch, setWorkspaceBranch] = useState(
    initialDraft?.workspaceBranch ?? "",
  );
  // Remote-device launch gate: a paired device can only fresh-launch when the
  // owner has enabled [remote].allow_terminal. When it's off we say so up front
  // and disable Start, rather than letting the POST fail with a raw 403.
  const { blocked: remoteBlocked } = useRemoteTerminalGate();

  useEffect(() => {
    let cancelled = false;
    fetchJSON<TerminalSessionsMeta>("/api/terminal/sessions")
      .then((d) => {
        if (cancelled) return;
        const list = d.launchable_tools ?? [];
        const guiRows = d.gui_launchables ?? [];
        setTools(list);
        setToolInfo(d.launchable_tool_info ?? []);
        setGuiLaunchables(guiRows);
        setGuiRuns(d.gui_runs ?? []);
        setUnlaunchable(d.unlaunchable_tools ?? []);
        setToolsError(null);
        setTool((current) => {
          if (current === SHELL_TOOL && d.shell_enabled) return current;
          // A GUI id is never a member of `list` (disjoint carriers, plan
          // §2.1) — check both so an installer-resumed GUI selection (or a
          // GUI id restored from a draft) survives this reconcile instead of
          // silently falling back to list[0].
          if (current && (list.includes(current) || guiRows.some((r) => r.id === current))) {
            return current;
          }
          // The first tool the launch allow-list accepts, so Start is usable
          // out of the box; else the first listed tool (pre-picker default).
          return preferredDefaultTool(list, d.launchable_tool_info ?? []);
        });
        setAllowedRoots(d.allowed_project_roots ?? []);
        setShellEnabled(d.shell_enabled ?? false);
        setWindowsPathsToWSL(d.windows_paths_to_wsl === true);
      })
      .catch((e) => {
        // DI-05: this route carries the whole picker. Swallowing its failure
        // left an empty dropdown reading "no launchable tools", which is a
        // FALSE statement about the daemon — say what actually happened.
        // P-031: with Terminals hidden by the org, say so (lane SEC-E).
        if (!cancelled) setToolsError(terminalsRefusalSentence(e) ?? apiReason(e));
      });
    // Suggest the projects Observer already knows about. We deliberately do NOT
    // auto-select the most-recent one: it may not be allow-listed, which would
    // dead-end the launch with a 400. The default stays "Agent's default
    // directory" (always permitted); permitted projects are clearly grouped so
    // the user can pick one that will actually launch.
    fetchJSON<ProjectsResponse>("/api/projects")
      .then((d) => {
        if (cancelled) return;
        setProjects(d.rows ?? []);
      })
      .catch(() => {
        /* no project index yet — leave the launcher-default selection */
      });
    // SSH systems. The route is owner-LOCAL, so a paired remote device gets a
    // 403 here — which lands in .catch() and correctly leaves the selector
    // hidden, matching the server-side posture that remote-driven SSH is not
    // offered in v1.
    fetchJSON<SSHProfilesResponse>("/api/terminal/ssh")
      .then((d) => {
        if (cancelled) return;
        setSshProbed(true);
        setSshEnabled(Boolean(d.enabled));
        setSshProfiles(d.profiles ?? []);
      })
      .catch(() => {
        /* route absent (old daemon build) or not reachable from here (paired
           remote device, owner-local route) — stay hidden, sshProbed false */
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // Fetch the pre-launch binary-resolution verdict whenever the selected tool
  // changes — or when the operator hits "Re-check" (recheckNonce).
  //
  // DI-17: a failure is NO LONGER fail-silent. This is the one probe in the
  // dialog whose whole job is to answer "will this launch work?", so an
  // unanswerable check is itself the news: the state goes to "error", the strip
  // names the server's own reason, and Start is disabled until the check
  // succeeds. (The models / sandbox / SSH probes stay fail-silent — they
  // degrade a nicety, not the launch's premise.)
  useEffect(() => {
    // The shell pseudo-tool is never in the capability registry the preflight
    // seam resolves against — skip the fetch and clear any stale AI-tool
    // verdict rather than let it 400 into a confusing strip. That is an
    // "unknown", not an error: a plain shell needs no binary resolution.
    if (!tool || tool === SHELL_TOOL) {
      setPreflight(null);
      setPreflightState("unknown");
      setPreflightErr("");
      return;
    }
    let cancelled = false;
    fetchJSON<ToolPreflight>("/api/terminal/launch/preflight", { tool })
      .then((d) => {
        if (cancelled) return;
        setPreflight(d);
        setPreflightState("ok");
        setPreflightErr("");
      })
      .catch((e) => {
        if (cancelled) return;
        setPreflight(null);
        setPreflightState("error");
        setPreflightErr(apiReason(e));
      });
    return () => {
      cancelled = true;
    };
  }, [tool, recheckNonce]);

  // Fetch the model-suggestion list for the selected tool (B5). Mirrors the
  // preflight effect exactly: Shell is skipped (it has no model concept), a
  // 404/501 or any other error clears the state silently, and a stale response
  // from a since-abandoned tool is ignored via the same cancellation flag. The
  // selected model is reset whenever the tool changes, whether or not the
  // fetch succeeds — a model picked for one tool must never leak into another.
  useEffect(() => {
    // A GUI row has no model concept either (plan §0.1: no model picker for
    // a GUI launch) — skip the fetch the same way Shell does, rather than
    // asking the model seam about a tool id it was never built to resolve.
    if (!tool || tool === SHELL_TOOL || isGUISelection(tool, guiLaunchables)) {
      setToolModels(null);
      return;
    }
    let cancelled = false;
    fetchJSON<ToolModels>("/api/terminal/launch/models", { tool })
      .then((d) => {
        if (!cancelled) setToolModels(d);
      })
      .catch(() => {
        if (!cancelled) setToolModels(null);
      });
    return () => {
      cancelled = true;
    };
  }, [tool, guiLaunchables]);

  // Fetch the sandbox probe (B9 U7) once on dialog open. Unlike preflight/
  // toolModels above this does NOT depend on `tool` — the response's `tools`
  // map already covers every launchable tool in one shot, so re-selecting the
  // tool dropdown re-evaluates sandboxDisabledReason from the SAME fetched
  // probe rather than re-fetching. A 404/501 (older daemon) or any other
  // error leaves sandboxProbe null, which sandboxDisabledReason renders as a
  // disabled checkbox with an honest "status unknown" reason — mirrors the
  // preflight/model-picker fail-silent degrade.
  useEffect(() => {
    let cancelled = false;
    fetchJSON<SandboxAvailability>("/api/terminal/sandbox")
      .then((d) => {
        if (!cancelled) {
          setSandboxProbe(d);
          if (!initialDraft) setSandboxOn(d.default_on ?? false);
          const first = defaultIsolationChoice(isolationOptions(d));
          if (first) setIsolationChoice(first);
        }
      })
      .catch((e: unknown) => {
        if (!cancelled) {
          setSandboxProbe(null);
          // 404 component_not_installed: the module is not installed here.
          setSandboxModuleAbsent(e instanceof ApiError && e.status === 404 && e.body.includes("component_not_installed"));
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // installTool spawns the tool's grounded install command in a fresh embedded
  // terminal (POST /api/terminal/install), the guided fix for a not_found /
  // foreign_only verdict. It is a Local + confirm-token-gated EXECUTE, so it
  // reads the double-submit token from /api/remote/config exactly like the
  // Remote page's privileged POSTs, then opens the returned handle in the dock
  // like any launch (labelled "<tool> install"). The server owns the argv — the
  // request carries only the tool name.
  // currentDraft is the exact launch draft the dock restores when a guided
  // install / uninstall terminal exits, so the dialog reopens where it was
  // with a fresh availability check.
  function currentDraft(): NewTerminalDraft {
    return {
      tool,
      rootSel,
      customRoot,
      modelSel,
      sandboxOn,
      workspaceSource,
      workspaceRemote,
      workspaceBranch,
      ...(gui ? { kind: "gui" as const } : {}),
    };
  }

  async function installTool() {
    if (!tool || installBusy) return;
    setInstallBusy(true);
    setErr(null);
    try {
      const cfg = await fetchJSON<{ confirm_token?: string }>("/api/remote/config");
      const ctok = cfg.confirm_token ?? "";
      if (!ctok) {
        setErr("No confirm token - reload the page.");
        return;
      }
      const r = await fetchJSON<{ handle: string; tool: string; command: string }>(
        "/api/terminal/install",
        undefined,
        {
          method: "POST",
          headers: { "Content-Type": "application/json", "X-Observer-Confirm": ctok },
          body: JSON.stringify({ tool }),
        },
      );
      onLaunched(r.handle, `${tool} install`, false, currentDraft());
    } catch (e) {
      // DI-05: never the raw `api <status> <path>: <body>` string. Each of this
      // route's statuses names one specific, fixable blocker — see
      // installErrorMessage's doc comment for why status dispatch is right here
      // and message dispatch is right on the launch path.
      setErr(installErrorMessage(e));
    } finally {
      setInstallBusy(false);
    }
  }

  // The path actually sent to the launch API: the hand-typed value when the
  // Custom escape hatch is chosen, otherwise the selected project root ("" ==
  // let the launcher use the agent's own default cwd). Validation is unchanged
  // — the server still canonicalizes it against [terminal.launch].allowed_project_roots.
  const effectiveRoot = useMemo(
    () => (rootSel === CUSTOM_ROOT ? customRoot.trim() : rootSel.trim()),
    [rootSel, customRoot],
  );

  // Repository trust chip (security Phase B, component security.trust): the
  // read-only trust check for the chosen directory, the same one the launch
  // runs. Fail-silent like the other probes: a daemon without the route, an
  // inactive component (404) or a failed read renders no chip. Its review
  // panel accepts from here (POST /api/security/trust), so an untrusted
  // repository is never a CLI-only dead end (lane SEC-TRUSTFIX); where the
  // organization keeps the accept off this dashboard (accept_allowed false)
  // the panel hides Accept and says who can accept (lane SEC-TRUST4).
  const [trustReply, setTrustReply] = useState<TrustReply | null>(null);
  const [trustBusy, setTrustBusy] = useState(false);
  const [trustErr, setTrustErr] = useState<string | null>(null);
  const trustRemote = sshProfile !== LOCAL_SYSTEM;
  async function acceptTrust(body: TrustAcceptBody | null) {
    if (!body || trustBusy) return;
    setTrustBusy(true);
    setTrustErr(null);
    try {
      const reply = await fetchJSON<TrustReply>("/api/security/trust", undefined, {
        method: "POST",
        headers: await localConfirmHeaders(),
        body: JSON.stringify(body),
      });
      setTrustReply(reply);
    } catch (e) {
      setTrustErr(apiReason(e) || "The accept did not go through.");
    } finally {
      setTrustBusy(false);
    }
  }
  useEffect(() => {
    if (trustRemote || !effectiveRoot) {
      setTrustReply(null);
      return;
    }
    let cancelled = false;
    fetchJSON<TrustReply>("/api/security/trust", { dir: effectiveRoot })
      .then((d) => {
        if (!cancelled) setTrustReply(d);
      })
      .catch(() => {
        if (!cancelled) setTrustReply(null);
      });
    return () => {
      cancelled = true;
    };
  }, [effectiveRoot, trustRemote]);
  const trust = useMemo(() => trustChip(trustReply), [trustReply]);

  // Project policy line (security plan 7.11, lane sec-p2b): whether the
  // organization's project rules apply in the chosen directory, read from
  // the machine's project match record. Shown only when the machine holds
  // project rules; any error shows nothing.
  const [projectPolicy, setProjectPolicy] = useState<ProjectPolicyReply | null>(null);
  useEffect(() => {
    if (trustRemote || !effectiveRoot) {
      setProjectPolicy(null);
      return;
    }
    let cancelled = false;
    fetchJSON<ProjectPolicyReply>("/api/terminal/project-policy", { dir: effectiveRoot })
      .then((d) => {
        if (!cancelled) setProjectPolicy(d);
      })
      .catch(() => {
        if (!cancelled) setProjectPolicy(null);
      });
    return () => {
      cancelled = true;
    };
  }, [effectiveRoot, trustRemote]);
  const policyLine = useMemo(() => projectPolicyView(projectPolicy), [projectPolicy]);

  // Partition the working-directory options against the server's allow-list.
  // Permitted = every canonical allowed root PLUS any known project under one
  // (deduped); a permitted known project shows its canonical entry when it IS an
  // allowed root, else its own path. Not permitted = known projects outside every
  // allowed root — shown disabled with an honest reason. Configured roots that
  // aren't known projects still surface (they're launch-ready).
  const { permittedRoots, blockedProjects } = useMemo(() => {
    const knownPaths = new Set(projects.map((p) => p.root_path));
    const permitted: string[] = [];
    const seen = new Set<string>();
    const add = (path: string) => {
      if (!seen.has(path)) {
        seen.add(path);
        permitted.push(path);
      }
    };
    // Configured roots that aren't themselves a known project row.
    for (const r of allowedRoots) {
      if (!knownPaths.has(r)) add(r);
    }
    const blocked: ProjectRow[] = [];
    for (const p of projects) {
      if (isPermittedRoot(p.root_path, allowedRoots)) add(p.root_path);
      else blocked.push(p);
    }
    return { permittedRoots: permitted, blockedProjects: blocked };
  }, [projects, allowedRoots]);

  // Verdict-derived UI state (tool-binary-resolution arc). A foreign_only /
  // not_found tool cannot be launched by the daemon, so Start is disabled — the
  // server stays the authority (it re-resolves at launch), this is the honest
  // up-front signal. DI-17 widened this to include a preflight that could not
  // be PERFORMED. All of it lives in one pure predicate now (launchBlockedFor),
  // shared with the Start button's tooltip so the two can never drift.
  const verdict = preflight?.verdict ?? "";
  // The availability strip's fully-resolved copy — one owner for the headline
  // sentence, the notes (rendered for EVERY verdict now), and the tone.
  // A GUI row is named by its label ("Zed"), never its launch id (T-333).
  const availabilityName = useMemo(() => guiAvailabilityName(tool, guiLaunchables), [tool, guiLaunchables]);
  const strip = useMemo(() => preflightStripCopy(availabilityName, preflight), [availabilityName, preflight]);
  // Notes beyond the visible cap, revealed by the "+N more" expander (DI-17:
  // the old hard slice(0,4) dropped the rest without saying so).
  const [notesExpanded, setNotesExpanded] = useState(false);
  useEffect(() => {
    setNotesExpanded(false);
  }, [tool, recheckNonce]);

  // Per-option annotations for the tool picker (DI-06). Branches on the
  // capability the server reported, never on a tool name.
  const toolAnnotations = useMemo(() => {
    const byTool = new Map(toolInfo.map((i) => [i.tool, i]));
    return tools.map((t) => annotateTool(t, byTool.get(t)));
  }, [tools, toolInfo]);
  const toolAnnotationFor = useMemo(
    () => new Map(toolAnnotations.map((a) => [a.tool, a])),
    [toolAnnotations],
  );
  const pickerLegendText = useMemo(() => pickerLegend(toolAnnotations), [toolAnnotations]);
  const selectedAnnotation = toolAnnotationFor.get(tool) ?? null;

  // The Tool picker's rows (toolPicker.ts owns grouping, order and status
  // vocabulary) and their ComboChip rendering. Each annotation is its own
  // field — name, kind badge, status badge, host list — instead of one long
  // native <option> string, so nothing can render wider than the dialog.
  const pickerItems = useMemo(
    () =>
      buildToolPickerItems({
        tools,
        toolInfo,
        gui: guiLaunchables,
        shellEnabled,
        shellTool: SHELL_TOOL,
        labelFor: (id) => toolMeta(id).label,
        unlaunchable,
      }),
    [tools, toolInfo, guiLaunchables, shellEnabled, unlaunchable],
  );
  const pickerItemFor = useMemo(
    () => new Map(pickerItems.map((i) => [i.value, i])),
    [pickerItems],
  );
  const toolOptions = useMemo<ComboOption[]>(
    () =>
      pickerItems.map((i) => ({
        value: i.value,
        label: <PickerOptionLabel item={i} />,
        searchable: i.searchable,
        leading: <ToolDot tool={i.dotKey} />,
        groupLabel: i.group,
        disabled: i.disabled,
        detail: pickerOptionDetail(i),
      })),
    [pickerItems],
  );
  const toolLabelId = useId();

  // gui is THE ONE derived predicate every GUI-specific branch below reads
  // (plan §2.4 / guiLaunch.ts's isGUISelection doc comment): install +
  // launch only — no resume, no continue, no attach, no model picker, no
  // sandbox, and Start posts { kind: "gui" } instead of docking a terminal.
  const selectedGUIRow = useMemo(
    () => guiLaunchables.find((r) => r.id === tool) ?? null,
    [guiLaunchables, tool],
  );
  const gui = isGUISelection(tool, guiLaunchables);
  // The routing verdict for the SELECTED GUI row: the preflight's dry-run of
  // the launcher's own wrap decision, used only once it answers for this very
  // tool (a stale reply for the previous selection must never phrase this
  // row's routing).
  const guiRoutingVerdict = preflight && preflight.tool === tool ? preflight : null;
  // The Shell pseudo-tool is gated by its own [terminal.launch].allow_shell
  // opt-in and is never a member of launchable_tool_info, so the AI-tool
  // allow-list must not be applied to it (absence would otherwise read as
  // "not allowed"). Its own disabled <option> is the gate. A GUI row carries
  // its OWN `allowed` flag straight from the wire (the SAME
  // [terminal.launch].allowed_tools allow-list, keyed on the GUI id) —
  // `selectedAnnotation` is always null for a GUI id (disjoint carriers), so
  // falling through to "allowed" there would wrongly ignore the row's gate.
  const selectedToolAllowed =
    tool === SHELL_TOOL
      ? true
      : gui
        ? (selectedGUIRow?.allowed ?? true)
        : selectedAnnotation === null || selectedAnnotation.allowed;
  // Start is disabled when the tool can't be resolved, when the check itself
  // failed, or when the LAUNCH allow-list refuses it — all three in one pure
  // predicate, shared with the button's tooltip below so they can't drift. The
  // picker, the availability strip and the Install button stay live regardless:
  // installing is not launching (DI-21).
  const launchBlockedByVerdict = launchBlockedFor(
    preflightState,
    verdict,
    selectedToolAllowed,
    launchRuntimeRemedy(preflight && preflight.tool === tool ? preflight : null) !== null,
  );

  const noAllowList = allowedRoots.length === 0;
  // A typed absolute folder the allow-list does not cover gets the inline
  // "Allow this folder" step (R4): the launch would be refused otherwise.
  const customFolderNeedsAllow = folderNeedsAllow(customRoot, allowedRoots, savedRoots);
  // Honest reason placed on every disabled option so hovering explains the block.
  const blockedTitle = noAllowList
    ? "No project folders are allow-listed - add one in Terminals > Settings > Folder Selection"
    : "Not in the project folder allow-list - add it in Terminals > Settings > Folder Selection";

  // The searchable folder-selector's option list (ComboChip): the agent's
  // default directory, then every permitted root, then every blocked known
  // project (shown but disabled, honest-reason tooltip — same partition the
  // native <select> used, now with type-ahead search over BOTH groups so a
  // large project index stays navigable). There is no filesystem-browse/
  // listdir daemon endpoint (as of this writing) to power a true directory-
  // tree picker, so this searchable list over the operator's allow-list +
  // observed-project index is the selector — not a live filesystem browser.
  // A "Custom path…" escape hatch below covers any allow-listed folder that
  // isn't yet a known project.
  const rootOptions = useMemo<ComboOption[]>(() => {
    const opts: ComboOption[] = [
      {
        value: "",
        label: "Agent's default directory (where SuperBased runs)",
        searchable: "agent's default directory where superbased runs",
        title:
          "No project root: the fresh agent runs in the SuperBased daemon's own working directory (where observer start / observer dashboard was launched from).",
      },
    ];
    for (const r of permittedRoots) {
      opts.push({
        value: r,
        label: <span className="font-mono text-[11px]">{shortenPath(r)}</span>,
        searchable: r.toLowerCase(),
        title: r,
        groupLabel: "Permitted",
      });
    }
    for (const p of blockedProjects) {
      opts.push({
        value: p.root_path,
        label: <span className="font-mono text-[11px]">{shortenPath(p.root_path)}</span>,
        searchable: p.root_path.toLowerCase(),
        title: `${p.root_path} - ${blockedTitle}`,
        disabled: true,
        groupLabel: "Not permitted",
      });
    }
    opts.push({
      value: CUSTOM_ROOT,
      label: "Custom path…",
      searchable: "custom path type manually",
      title: "Type an absolute path by hand - it must be allow-listed to launch.",
    });
    return opts;
  }, [permittedRoots, blockedProjects, blockedTitle]);

  // Sandbox toggle (B9 U7): null when the checkbox should be enabled, else the
  // honest disabled-copy string (see sandboxDisabledReason above).
  // On a host whose only available rows are beta the picker stays enabled
  // and Automatic stays disabled (betaRowChoosable, audit SBX-P3B F1).
  const isolationPicker = useMemo(
    () => isolationPickerProps(tool, sandboxProbe, sandboxOn, isolationChoice),
    [tool, sandboxProbe, sandboxOn, isolationChoice],
  );
  const sandboxCheckboxDisabled = isolationPicker.disabled;
  // A source the user has currently picked but that isn't actually available
  // (e.g. left on "clone-remote" after switching to a probe/tool where it's
  // gated off) blocks the client-side hint the same way an empty remote URL
  // does — the server re-validates regardless, this only prevents an
  // obviously-doomed submit.
  const selectedSourceAvail = sandboxProbe?.sources?.find((s) => s.id === workspaceSource);
  const startBlock = sandboxStartBlock({
    sandboxOn,
    controlDisabled: sandboxCheckboxDisabled,
    source: workspaceSource,
    remote: workspaceRemote,
    sources: sandboxProbe?.sources,
  });
  const sandboxRemoteURLMissing = startBlock.remoteURLMissing;
  const sandboxSourceUnavailable = startBlock.sourceUnavailable;
  const sandboxBranchProblem =
    sandboxOn && !sandboxCheckboxDisabled ? worktreeBranchProblem(workspaceSource, workspaceBranch) : null;
  const sandboxBlocksStart = startBlock.blocks || sandboxBranchProblem !== null;
  const sandboxBranch = branchField(workspaceSource);

  // sshMode is the ONE predicate the rest of the dialog branches on. Everything
  // it disables is disabled because the capability genuinely does not exist for
  // a remote system (see the honest disabled copy on each control), not because
  // we have not implemented it here.
  const sshMode = sshProfile !== LOCAL_SYSTEM;
  // The System row is visible whenever the probe answered at all (see
  // sshProbed above) — 2026-08-28 operator ruling: the surface should be
  // visible by default, not hidden behind enabled/profile state. Whether the
  // picker itself is USABLE is a separate question, answered by
  // sshSystemDisabledReason below.
  const showSystemPicker = sshProbed;
  const sshSystemReason = sshSystemDisabledReason(sshEnabled, sshProfiles.length);
  const sshSystemDisabled = sshSystemReason !== null;
  const selectedSSH = sshProfiles.find((p) => p.name === sshProfile) ?? null;
  // Honest disabled copy, one string, reused by every control the remote path
  // switches off (CLAUDE.md honest-disabled-control convention).
  const SSH_NA_MSG =
    "Not available for a remote system - the remote host's own SuperBased install owns project context, models, and sandboxing.";

  // A profile that vanishes from the server's list (config edited while the
  // dialog was open, or an installer-resumed draft naming a since-removed
  // system) must not leave a selection that would 400 on submit. Fall back to
  // this machine rather than silently launching somewhere else.
  useEffect(() => {
    if (sshProfile === LOCAL_SYSTEM) return;
    if (sshProfiles.length === 0) return;
    if (!sshProfiles.some((p) => p.name === sshProfile)) setSshProfile(LOCAL_SYSTEM);
  }, [sshProfile, sshProfiles]);

  // If the tool changes (or the probe resolves) into a state where the
  // sandbox checkbox becomes disabled, uncheck it rather than leaving a
  // stale "on" that the POST body would silently drop (sandbox fields are
  // only added when sandboxOn is true — see submit()).
  // The same holds for a chosen entry the picker lists as disabled
  // (Automatic on a beta-only host, where default_on would otherwise post a
  // launch naming no backend that the daemon refuses).
  useEffect(() => {
    if (sandboxOn && (sandboxCheckboxDisabled || isolationPicker.value === ISOLATION_NONE)) setSandboxOn(false);
  }, [sandboxCheckboxDisabled, sandboxOn, isolationPicker.value]);

  // A new tool, sandbox choice or row asks the sign-in question again.
  useEffect(() => {
    setSignInConsent(null);
  }, [tool, sandboxOn, isolationChoice]);

  async function submit(signInSeed?: boolean) {
    // A remote system takes an entirely different path: POST /api/terminal/ssh
    // with a profile NAME and nothing else. None of the local-launch inputs
    // (tool, project root, model, sandbox) apply — see sshMode.
    if (sshMode) {
      setBusy(true);
      setErr(null);
      try {
        const r = await fetchJSON<SSHLaunchResponse>("/api/terminal/ssh", undefined, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ profile: sshProfile }),
        });
        // The dock uses `tool` purely as a DISPLAY label (LaunchDock's tab
        // chip and LaunchTerminal's header — neither branches on it), so we
        // pass "ssh · <system>". That keeps a live remote tab from ever being
        // mistaken for a local shell, and it can never collide with a real
        // adapter name.
        //
        // hasProjectRoot is false by construction: an SSH session's cwd is on
        // another machine, so the local Files/Git panels have nothing to browse.
        onLaunched(r.token, `ssh · ${r.label || r.profile || sshProfile}`, false);
      } catch (e) {
        setErr(e instanceof Error ? e.message : String(e));
      } finally {
        setBusy(false);
      }
      return;
    }
    if (!tool) {
      setErr("choose a tool");
      return;
    }
    if (remoteBlocked) {
      setErr(REMOTE_TERMINAL_OFF_MSG);
      return;
    }
    // A GUI (IDE/desktop-app) row takes its own path: POST the SAME route
    // with kind:"gui" and NO model/sandbox fields (out of scope — plan §0.1).
    // There is no PTY behind a GUI launch, so success is a toast + close, not
    // a docked terminal tab — onLaunched (which always docks, see LaunchDock)
    // is deliberately not called here.
    if (gui) {
      setBusy(true);
      setErr(null);
      try {
        const r = await fetchJSON<GUILaunchResponse>("/api/terminal/launch", undefined, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            tool,
            kind: "gui",
            ...(selectedGUIRow?.project_dir_argv && effectiveRoot
              ? { project_root: effectiveRoot }
              : {}),
          }),
        });
        // wrap_note is NOT shown: it is the launch planner's engineering
        // explanation, not user copy. "routed through the SuperBased proxy"
        // comes only from the launch's own structured verdict
        // (routing_reaches_app; wrap_applied on an older daemon).
        pushToast(guiLaunchedToast(r), "success");
        onClose();
      } catch (e) {
        setErr(guiLaunchErrorMessage(e));
      } finally {
        setBusy(false);
      }
      return;
    }
    if (sandboxBlocksStart) {
      setErr(startBlock.blocks ? startBlock.message : sandboxBranchProblem);
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      // Sandbox fields are added ONLY when the checkbox is on — off, the
      // request body is byte-identical to a pre-U7 launch (plan §5). The
      // server re-validates workspace_source membership + everything else
      // and fail-CLOSES; this is a UX hint, not authorization.
      // The row chosen in the Isolation picker (a beta row too) is sent as
      // `backend`; "Automatic" sends none (sandboxLaunchFields, B4).
      const sandboxFields = sandboxLaunchFields({
        sandboxOn,
        isolationChoice,
        workspaceSource,
        workspaceRemote,
        workspaceBranch,
        branchApplies: sandboxBranch !== null,
        signInSeed,
      });
      // A launch that can copy the tool's sign-in answers with the question
      // instead (lane BOXSIGNIN): the inline step asks, its answer submits
      // again.
      const out = await postLaunchAskingSignIn(() =>
        fetchJSON<FreshLaunchResponse>("/api/terminal/launch", undefined, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            tool,
            project_root: effectiveRoot || undefined,
            model: modelSel || undefined,
            ...sandboxFields,
          }),
        }),
      );
      if ("consent" in out) {
        setSignInConsent(out.consent);
        setErr(null);
        return;
      }
      const r = out.started;
      onLaunched(r.token, r.tool || tool, r.has_project_root);
    } catch (e) {
      if (isFreshLaunchDisabledError(e)) {
        setFreshOff(true);
        setErr(null);
        return;
      }
      // Swap the raw server body for actionable guidance on the two known
      // policy gates — the remote allow_terminal 403 and the allowed_project_roots
      // 400 — and keep the verbatim message for every other failure so it stays
      // diagnosable.
      setErr(
        isTerminalCapabilityError(e)
          ? REMOTE_TERMINAL_OFF_MSG
          : isProjectRootDeniedError(e)
            ? PROJECT_ROOT_DENIED_MSG
            : e instanceof Error
              ? e.message
              : String(e),
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      title="New terminal"
      width={440}
      // Above the launch dock (z-80): the dialog opens from it.
      zIndex={85}
      dismissible={!busy}
      bodyClassName="p-4"
      footer={
        <>
          <button
            type="button"
            onClick={onClose}
            className="rounded-2 px-3 py-1.5 text-[12px] text-fg-2 hover:bg-overlay-1"
          >
            Cancel
          </button>
          {(() => {
            // The availability sentence comes from the SAME helper the strip
            // above uses (launchBlockedReason → preflightStripCopy), so the
            // button's tooltip and the strip can never drift apart again —
            // before DI-17 they were two hand-rolled copies that already had.
            const tip = sshMode
              ? null
              : policyStepBusy
              ? POLICY_STEP_PENDING
              : remoteBlocked
              ? REMOTE_TERMINAL_OFF_MSG
              : launchBlockedByVerdict
                ? launchBlockedReason(
                    tool,
                    preflightState,
                    preflight,
                    preflightErr,
                    selectedToolAllowed,
                    availabilityName,
                  ) ?? `${availabilityName} can't be launched from here right now`
                : sandboxBlocksStart
                  ? sandboxRemoteURLMissing
                    ? "Enter a remote URL to clone into the sandbox, or choose a different workspace"
                    : startBlock.blocks
                      ? "The selected workspace source isn't available - choose a different one"
                      : sandboxBranchProblem
                  : null;
            // The shared Button: disabled renders the opaque bg-bg-3 look in
            // both themes, not a faded accent fill (T-339).
            const startBtn = (
              <Button
                variant="primary"
                disabled={
                  busy ||
                  (sshMode
                    ? // A remote launch needs only a selected system. None of the
                      // local gates (tool chosen, binary verdict, sandbox
                      // workspace) apply, and remoteBlocked is about the
                      // [remote].allow_terminal INBOUND tier - an orthogonal
                      // feature (the route is owner-local anyway).
                      !sshProfile
                    : !tool || remoteBlocked || launchBlockedByVerdict || sandboxBlocksStart || policyStepBusy)
                }
                onClick={() => void submit()}
              >
                {busy
                  ? "Starting…"
                  : gui && selectedGUIRow
                    ? `Launch ${selectedGUIRow.label}`
                    : "Start"}
              </Button>
            );
            // The tip only shows while the button is disabled (blocked), and a
            // disabled <button> swallows pointer events - TooltipSpan gives it a
            // hoverable span reference. No tip → bare button (no extra tab stop).
            return tip ? (
              <TooltipSpan content={tip}>{startBtn}</TooltipSpan>
            ) : (
              startBtn
            );
          })()}
        </>
      }
    >
      <p className="mb-3 text-[11px] leading-relaxed text-fg-3">
        Start a fresh agent in the embedded terminal. Fresh launch, the allowed
        tools and the allowed project folders are set in the{" "}
        <Link
          to={TERMINALS_LAUNCH_POLICY_HASH_PATH}
          onClick={onClose}
          className="underline decoration-dotted underline-offset-2 hover:text-fg-1"
        >
          launch policy
        </Link>
        ; a launch outside them is refused. Changes apply to the next launch.
      </p>

      {remoteBlocked && (
        <div className="mb-3 rounded-2 border border-warn/40 bg-warn/10 px-2 py-1.5 text-[11px] text-warn">
          {REMOTE_TERMINAL_OFF_MSG}
        </div>
      )}

      {resumedAfterInstall && (
        <div className="mb-3 rounded-2 border border-ok/40 bg-ok/10 px-2 py-1.5 text-[11px] text-ok">
          The install or uninstall terminal finished. Your adapter, project, model, and sandbox choices were preserved;
          the availability check below has been refreshed.
        </div>
      )}

      {/* Read-only: GUI apps this daemon has launched (gui_runs, T2.3).
          There is no PTY behind a GUI run — nothing here is resumable or
          attachable, it's purely "what's already running" context so a
          second launch of the same app isn't a surprise. */}
      {guiRuns.length > 0 && (
        <div className="mb-3 rounded-2 border border-line-2 bg-bg-2 px-2 py-1.5 text-[10.5px] leading-relaxed text-fg-3">
          <div className="mb-1 font-medium text-fg-2">GUI apps launched this session</div>
          <ul className="space-y-0.5">
            {guiRuns.map((r) => (
              <li key={r.run_id} className="flex items-center justify-between gap-2">
                {/* r.notes (launch-composition advisories such as "pid and
                    exit code belong to the explorer.exe launcher stub") are
                    engineering caveats, not user copy - not rendered. */}
                <span className="truncate">{r.label}</span>
                <span className="shrink-0 font-mono">
                  {r.exited ? `exited (${r.exit_code})` : `pid ${r.pid}`}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {showSystemPicker && (
        <>
          <label
            htmlFor="new-terminal-system"
            className="mb-1 block text-[11px] font-medium text-fg-2"
          >
            System
          </label>
          <select
            id="new-terminal-system"
            value={sshProfile}
            disabled={sshSystemDisabled}
            title={sshSystemReason ?? undefined}
            onChange={(e) => setSshProfile(e.target.value)}
            className="w-full rounded-2 border bg-bg-0 px-2 py-1.5 text-[12px] text-fg-1"
          >
            <option value={LOCAL_SYSTEM} title="Run on the machine SuperBased is running on">
              This machine (local)
            </option>
            {/* Systems come from [[terminal.ssh.profiles]] in the operator's
                own config, edited on the owner-local Remote systems card
                (T-488). This picker SELECTS among them; it can never add
                one, which is the feature's core safety property. */}
            {sshProfiles.map((p) => (
              <option key={p.name} value={p.name} title={p.target}>
                {p.label} - {p.target}
              </option>
            ))}
          </select>
          {sshSystemReason && (
            <p className="mb-3 mt-1 text-[10.5px] leading-relaxed text-fg-3">
              {sshSystemReason}{" "}
              <Link
                to={TERMINALS_REMOTE_SYSTEMS_HASH_PATH}
                onClick={onClose}
                className="underline decoration-dotted underline-offset-2 hover:text-fg-1"
              >
                Open Remote systems
              </Link>
            </p>
          )}
          {!sshSystemReason && <div className="mb-3" />}
        </>
      )}

      {sshMode && selectedSSH && (
        <div className="mb-3 rounded-2 border border-accent/40 bg-accent/10 px-2 py-1.5 text-[11px] leading-relaxed text-fg-2">
          Opens an SSH shell on{" "}
          <code className="font-mono">{selectedSSH.target}</code>
          {selectedSSH.jump ? (
            <>
              {" "}via <code className="font-mono">{selectedSSH.jump}</code>
            </>
          ) : null}
          {selectedSSH.has_key && selectedSSH.key_hint ? (
            <>
              {" "}using key <code className="font-mono">{selectedSSH.key_hint}</code>
            </>
          ) : null}
          . If the host key is unknown, or a passphrase is needed, SuperBased
          does not answer for you - <strong>ssh asks in the terminal</strong> and
          you answer there. Sessions on this system are not captured here; the
          remote host's own SuperBased install owns that.
        </div>
      )}

      <label
        id={toolLabelId}
        htmlFor="new-terminal-tool"
        className="mb-1 block text-[11px] font-medium text-fg-2"
      >
        Tool
      </label>
      {/* Searchable picker (shared ComboChip): type-to-search, arrows, Enter;
          Escape closes only the popover, never this dialog. The popover is as
          wide as the field, so it can never spill past the dialog or the
          window the way the old native <select> option list did.
          Every AI-tool and GUI row stays SELECTABLE even when the launch
          allow-list refuses it — the guided install must stay reachable on
          precisely the fresh install that needs it: allowed_tools defaults to
          EMPTY (deny-all) while POST /api/terminal/install is ungated by it on
          purpose (DI-21). The allow-list blocks START instead
          (launchBlockedFor). Only Shell can be disabled: it has its own
          [terminal.launch].allow_shell opt-in and nothing to install. */}
      <div className="mb-3">
        <ComboChip
          id="new-terminal-tool"
          labelledBy={toolLabelId}
          value={tool}
          onChange={setTool}
          options={toolOptions}
          label="Tool"
          hideTriggerLabel
          fullWidth
          disabled={sshMode}
          triggerTooltip={null}
          placeholder="Search tools, IDEs and apps…"
          emptyHint="No tool matches. Clear the search to see every launchable tool."
          buttonValueRender={(sel) => {
            const item = sel ? pickerItemFor.get(sel.value) : undefined;
            if (!item) {
              return (
                <span className="min-w-0 flex-1 truncate text-left text-fg-3">
                  {toolsError
                    ? "Couldn't load the launchable tools"
                    : tools.length === 0 && guiLaunchables.length === 0
                      ? "No launchable tools"
                      : "Choose a tool"}
                </span>
              );
            }
            return (
              <span className="flex min-w-0 flex-1 items-center gap-1.5 text-left">
                <ToolDot tool={item.dotKey} />
                <span className="min-w-0 truncate font-semibold text-fg-0">{item.name}</span>
                <Pill case="none" className="shrink-0">
                  {item.kindLabel}
                </Pill>
              </span>
            );
          }}
        />
        {sshMode && (
          <p className="mt-1 text-[10.5px] leading-relaxed text-fg-3">
            Not used for a remote system - the SSH shell opens on that host.
          </p>
        )}
      </div>

      {/* DI-05: the picker's source route failed. Say so instead of letting
          the empty dropdown imply the daemon has no launchable tools. */}
      {toolsError && (
        <p className="-mt-2 mb-3 rounded-2 border border-danger/30 bg-danger/10 px-2 py-1.5 text-[10.5px] leading-relaxed text-danger">
          Couldn't load the launchable tools: {toolsError} - the tool list,
          project-root allow-list and Shell option are all unknown until this
          request succeeds. Reopen this dialog to retry.
        </p>
      )}

      {/* The selected tool is refused by the launch allow-list. A calm inline
          note under the picker (not a hover tooltip a native <option> may
          never show) says what that means and where the switch lives. It is
          what disables Start (launchBlockedFor); the availability strip and
          its Install button below stay fully live — installing is not
          launching (DI-21). One block for AI tools AND GUI rows: both read
          the same [terminal.launch].allowed_tools list (selectedToolAllowed). */}
      {!sshMode && tool && tool !== SHELL_TOOL && !selectedToolAllowed && (
        <div
          role="note"
          className="-mt-1 mb-3 flex gap-2 rounded-2 border border-line-2 bg-bg-2 px-2.5 py-2 text-[11px] leading-relaxed text-fg-2"
        >
          <Icon icon={Lock} size={12} className="mt-[3px] shrink-0 text-fg-3" />
          <div className="min-w-0">
            <p>
              <span className="font-medium text-fg-1">
                {pickerItemFor.get(tool)?.name ?? tool}
              </span>{" "}
              isn't allowed to launch from here yet. Allow it in the launch
              policy to enable Start (no restart needed). You can still install
              it from this dialog.
            </p>
            {/* SPA navigation (Link, not a bare <a>) so the Terminals page's
                hash effect can select the Settings tab and scroll to the card.
                The dialog closes on the way out — leaving a modal floating over
                the page the operator was just sent to read would defeat it. */}
            <Link
              to={TERMINALS_LAUNCH_POLICY_HASH_PATH}
              onClick={onClose}
              className="mt-1.5 inline-flex items-center rounded-2 border border-line-2 bg-bg-1 px-2 py-0.5 text-[11px] font-medium text-fg-1 hover:bg-bg-3"
            >
              Open launch policy
            </Link>
          </div>
        </div>
      )}

      {/* DI-06: the two independent allow-lists behind the picker, made
          visible up front instead of learned from a post-Start 403. Counts
          and the fix; each row's own status badge carries the specifics.
          Hidden while the not-allowed note above is showing, so the dialog
          never stacks two launch-policy links. */}
      {!sshMode && pickerLegendText && selectedToolAllowed && (
        <p className="-mt-2 mb-3 text-[10.5px] leading-relaxed text-fg-3">
          {pickerLegendText}{" "}
          <Link
            to={TERMINALS_LAUNCH_POLICY_HASH_PATH}
            onClick={onClose}
            className="underline decoration-dotted underline-offset-2 hover:text-fg-1"
          >
            Open the launch policy
          </Link>
          .
        </p>
      )}

      {!sshMode && selectedAnnotation && selectedAnnotation.allowed && !selectedAnnotation.watched && (
        <p className="-mt-2 mb-3 text-[10.5px] leading-relaxed text-fg-3">
          {tool} is {TOOL_NOT_WATCHED_MSG}. It will launch normally.
        </p>
      )}

      {/* The selected GUI row's remaining gating caveat (not grounded / not
          installed) — the allow-list case is the calm note above, so this
          only fires for an ALLOWED row, using the SAME copy as its terminal
          counterpart via guiLaunchDisabledReason. */}
      {!sshMode && gui && selectedGUIRow && selectedGUIRow.allowed && guiLaunchDisabledReason(selectedGUIRow, preflight, selectedGUIRow.allowed) && (
        <p className="-mt-2 mb-3 rounded-2 border border-warn/40 bg-warn/10 px-2 py-1.5 text-[10.5px] leading-relaxed text-warn">
          {guiLaunchDisabledReason(selectedGUIRow, preflight, selectedGUIRow.allowed)}
        </p>
      )}
      {!sshMode && gui && selectedGUIRow && selectedGUIRow.allowed && selectedGUIRow.adapter !== "" && !selectedGUIRow.watched && (
        <p className="-mt-2 mb-3 text-[10.5px] leading-relaxed text-fg-3">
          {selectedGUIRow.label} is {TOOL_NOT_WATCHED_MSG}. It will launch normally.
        </p>
      )}

      {!sshMode && !gui && toolModels && toolModels.supported && toolModels.models.length > 0 && (
        <>
          <label
            htmlFor="new-terminal-model"
            className="mb-1 block text-[11px] font-medium text-fg-2"
          >
            Model <span className="text-fg-3">(optional)</span>
          </label>
          <select
            id="new-terminal-model"
            value={modelSel}
            onChange={(e) => setModelSel(e.target.value)}
            className="mb-3 w-full rounded-2 border bg-bg-0 px-2 py-1.5 text-[12px] text-fg-1"
          >
            <option value="" title={`Let ${tool} choose its own default model`}>
              Tool default
            </option>
            {toolModels.models.map((m) => (
              <option key={m.model} value={m.model} title={m.model}>
                {m.model}
                {m.source === "history" && m.count
                  ? ` (${m.count.toLocaleString()} uses)`
                  : ""}
              </option>
            ))}
          </select>
        </>
      )}

      {sshMode ? (
        <p className="mb-3 rounded-2 border border-border/60 bg-bg-0 px-2 py-1.5 text-[11px] leading-relaxed text-fg-3">
          <span className="font-medium text-fg-2">Project root, model, sandbox</span>
          {" - "}
          {SSH_NA_MSG}
        </p>
      ) : gui ? (
        <>
          {/* GUI scope is install + launch only (plan §0.1): no resume, no
              continue, no attach, no model picker, no sandbox. The
              project-root control is the ONE exception, and only when the
              app actually takes a positional directory argument
              (project_dir_argv) — reused verbatim from the terminal path
              below so a permitted-folder pick behaves identically. */}
          {selectedGUIRow?.project_dir_argv ? (
            <>
              <label className="mb-1 block text-[11px] font-medium text-fg-2">
                Project root <span className="text-fg-3">(optional)</span>
              </label>
              <ComboChip
                value={rootSel}
                onChange={setRootSel}
                options={rootOptions}
                label="Folder"
                fullWidth
                popoverWidth={396}
                placeholder="Search permitted folders…"
                emptyHint="No folders match. Try “Custom path…” or add a root in Terminals → Settings → Folder Selection."
                buttonValueRender={(sel) => (
                  <span className="min-w-0 flex-1 truncate text-left font-semibold text-fg-0">
                    {sel?.label ?? "Agent's default directory (where SuperBased runs)"}
                  </span>
                )}
              />
              {noAllowList && projects.length > 0 && (
                <p className="mt-1 text-[10.5px] leading-relaxed text-fg-3">
                  No project roots are allow-listed, so only the agent's
                  default directory can launch - that's the SuperBased
                  daemon's own working directory (where{" "}
                  <code className="font-mono">observer start</code> ran).{" "}
                  <Link
                    to={TERMINALS_FOLDERS_HASH_PATH}
                    onClick={onClose}
                    className="underline decoration-dotted underline-offset-2 hover:text-fg-1"
                  >
                    Add a folder in Folder Selection
                  </Link>{" "}
                  to enable them.
                </p>
              )}
              {rootSel === CUSTOM_ROOT ? (
                <input
                  type="text"
                  value={customRoot}
                  onChange={(e) => setCustomRoot(e.target.value)}
                  autoFocus
                  placeholder="/abs/path/to/project (must be allow-listed)"
                  className="mt-2 w-full rounded-2 border bg-bg-0 px-2 py-1.5 font-mono text-[12px] text-fg-1"
                />
              ) : rootSel ? (
                <Tooltip content={rootSel}>
                  <div className="mt-1 break-all font-mono text-[10.5px] text-fg-3">
                    {rootSel}
                  </div>
                </Tooltip>
              ) : null}
              {rootSel === CUSTOM_ROOT && customFolderNeedsAllow && (
                <AllowFolderStep
                  path={customRoot.trim()}
                  onPhase={(p) => setPolicyStepBusy(stepHoldsStart(p))}
                  onConfirm={async (review) => {
                    const root = customRoot.trim();
                    await applyLaunchPolicyChange({ addRoot: root }, "Allow this folder for agent launches", review);
                    setSavedRoots((s) => (s.includes(root) ? s : [...s, root]));
                    await refreshAllowedRoots().catch(() => undefined);
                  }}
                />
              )}

              <div className="mb-3" />
            </>
          ) : null}
          {/* ONE calm line derived from structured fields only (guiLaunchCopy):
              the row's project_dir_argv / wrap_kind and the preflight's
              routing verdict (routing_reaches_app + routing_reason, the
              launcher's own wrap decision dry-run). Never the registry's
              free-text `note` / `wrap_reason`, and never a routing claim the
              daemon has not confirmed for this machine. */}
          {selectedGUIRow && guiLaunchSummary(selectedGUIRow, guiRoutingVerdict) && (
            <p className="mb-3 text-[11px] leading-relaxed text-fg-3">
              {guiLaunchSummary(selectedGUIRow, guiRoutingVerdict)}
            </p>
          )}
        </>
      ) : (
      <>
      <label className="mb-1 block text-[11px] font-medium text-fg-2">
        Project root <span className="text-fg-3">(optional)</span>
      </label>
      <ComboChip
        value={rootSel}
        onChange={setRootSel}
        options={rootOptions}
        label="Folder"
        fullWidth
        popoverWidth={396}
        placeholder="Search permitted folders…"
        emptyHint="No folders match. Try “Custom path…” or add a root in Terminals → Settings → Folder Selection."
        buttonValueRender={(sel) => (
          <span className="min-w-0 flex-1 truncate text-left font-semibold text-fg-0">
            {sel?.label ?? "Agent's default directory (where SuperBased runs)"}
          </span>
        )}
      />
      {noAllowList && projects.length > 0 && (
        <p className="mt-1 text-[10.5px] leading-relaxed text-fg-3">
          No project roots are allow-listed, so only the agent's default
          directory can launch - that's the SuperBased daemon's own working
          directory (where <code className="font-mono">observer start</code> ran).{" "}
          <Link
            to={TERMINALS_FOLDERS_HASH_PATH}
            onClick={onClose}
            className="underline decoration-dotted underline-offset-2 hover:text-fg-1"
          >
            Add a folder in Folder Selection
          </Link>{" "}
          to enable them.
        </p>
      )}
      {rootSel === CUSTOM_ROOT ? (
        <input
          type="text"
          value={customRoot}
          onChange={(e) => setCustomRoot(e.target.value)}
          autoFocus
          placeholder="/abs/path/to/project (must be allow-listed)"
          className="mt-2 w-full rounded-2 border bg-bg-0 px-2 py-1.5 font-mono text-[12px] text-fg-1"
        />
      ) : rootSel ? (
        <Tooltip content={rootSel}>
          <div className="mt-1 break-all font-mono text-[10.5px] text-fg-3">
            {rootSel}
          </div>
        </Tooltip>
      ) : null}
      {rootSel === CUSTOM_ROOT && customFolderNeedsAllow && (
        <AllowFolderStep
          path={customRoot.trim()}
          onPhase={(p) => setPolicyStepBusy(stepHoldsStart(p))}
          onConfirm={async (review) => {
            const root = customRoot.trim();
            await applyLaunchPolicyChange({ addRoot: root }, "Allow this folder for agent launches", review);
            setSavedRoots((s) => (s.includes(root) ? s : [...s, root]));
            await refreshAllowedRoots().catch(() => undefined);
          }}
        />
      )}

      {rootSel === CUSTOM_ROOT && windowsPathsToWSL && (
        <p className="mt-1 text-[10.5px] leading-relaxed text-fg-3">
          Windows paths (<code className="font-mono">C:\Users\…</code>) are
          accepted and translated to their WSL{" "}
          <code className="font-mono">/mnt/c/…</code> form.
        </p>
      )}
      <div className="mb-3" />

      {/* Isolation picker (sandbox plan v2 section 9), a compgen feature
          row of the Sandboxes and VMs module: null in a build without it, and
          hidden while the module is not installed, so the dialog looks as it
          does without the module. Choosing a backend is today's sandboxed
          launch. */}
      {!sandboxModuleAbsent && SANDBOX_ISOLATION_PICKER && (
        <Suspense fallback={null}>
          <SANDBOX_ISOLATION_PICKER
            options={isolationPicker.options}
            value={isolationPicker.value}
            disabled={isolationPicker.disabled}
            reason={isolationPicker.reason}
            chip={isolationPicker.chip}
            onChange={(v) => {
              if (v !== ISOLATION_NONE) setIsolationChoice(v);
              setSandboxOn(v !== ISOLATION_NONE);
            }}
          />
        </Suspense>
      )}

      {sandboxOn && !sandboxCheckboxDisabled && (
        <div className="mb-3 mt-2 rounded-2 border border-line-2 bg-bg-2 p-2">
          <label
            htmlFor="new-terminal-sandbox-source"
            className="mb-1 block text-[11px] font-medium text-fg-2"
          >
            Workspace
          </label>
          <select
            id="new-terminal-sandbox-source"
            value={workspaceSource}
            onChange={(e) => setWorkspaceSource(e.target.value)}
            className="w-full rounded-2 border bg-bg-0 px-2 py-1.5 text-[12px] text-fg-1"
          >
            {(sandboxProbe?.sources ?? []).map((s) => (
              // Native <option> - title= stays (React tooltip can't render
              // inside the browser-owned select popup), same convention as
              // the project-root optgroups above.
              <option
                key={s.id}
                value={s.id}
                disabled={!s.available}
                title={
                  s.available
                    ? SANDBOX_SOURCE_LABELS[s.id] ?? s.id
                    : s.reason || "not available"
                }
              >
                {SANDBOX_SOURCE_LABELS[s.id] ?? s.id}
                {s.available ? "" : " (unavailable)"}
              </option>
            ))}
          </select>
          {sandboxSourceUnavailable && (
            <p className="mt-1 text-[10.5px] leading-relaxed text-warn">
              {selectedSourceAvail?.reason || "This workspace source isn't available."}
            </p>
          )}
          {workspaceSource === "clone-remote" && (
            <>
              <label
                htmlFor="new-terminal-sandbox-remote"
                className="mb-1 mt-2 block text-[11px] font-medium text-fg-2"
              >
                Remote URL
              </label>
              <input
                id="new-terminal-sandbox-remote"
                type="text"
                value={workspaceRemote}
                onChange={(e) => setWorkspaceRemote(e.target.value)}
                placeholder="https://github.com/org/repo.git"
                className="w-full rounded-2 border bg-bg-0 px-2 py-1.5 font-mono text-[12px] text-fg-1"
              />
              {sandboxRemoteURLMissing && (
                <p className="mt-1 text-[10.5px] leading-relaxed text-warn">
                  Enter a remote URL - the daemon will run `git clone` with your
                  ambient auth into a managed workspace.
                </p>
              )}
            </>
          )}
          {sandboxBranch && (
            <>
              <label
                htmlFor="new-terminal-sandbox-branch"
                className="mb-1 mt-2 block text-[11px] font-medium text-fg-2"
              >
                Branch <span className="text-fg-3">(optional)</span>
              </label>
              <input
                id="new-terminal-sandbox-branch"
                type="text"
                value={workspaceBranch}
                onChange={(e) => setWorkspaceBranch(e.target.value)}
                placeholder={sandboxBranch.placeholder}
                className="w-full rounded-2 border bg-bg-0 px-2 py-1.5 font-mono text-[12px] text-fg-1"
              />
              {sandboxBranch.hint && (
                <p className="mt-1 text-[10.5px] leading-relaxed text-fg-3">{sandboxBranch.hint}</p>
              )}
              {sandboxBranchProblem && (
                <p className="mt-1 text-[10.5px] leading-relaxed text-warn">{sandboxBranchProblem}</p>
              )}
            </>
          )}
        </div>
      )}

      </>
      )}

      {/* Tool-availability strip (DI-03 + DI-17). ONE block, one owner for the
          copy (preflightStripCopy), covering all five verdicts, an
          unrecognised verdict, and a preflight that could not run at all.
          Notes render for EVERY verdict — the PATH-shim note arrives on a
          plain "ok" — and the not-installed branch always offers a next step:
          the runnable command, or the grounded reason there isn't one. */}
      {!sshMode && policyLine !== null && (
        <div
          data-testid="project-policy-line"
          title={policyLine.detail}
          className={
            "mb-2 text-[11px] leading-relaxed " + (policyLine.tone === "warn" ? "text-warn" : "text-fg-3")
          }
        >
          {policyLine.text}
        </div>
      )}
      {!sshMode && trust !== null && (
        <div
          data-testid="trust-chip"
          title={trust.detail}
          className={
            "mb-3 rounded-2 border px-2 py-1.5 text-[11px] leading-relaxed " +
            (trust.tone === "danger"
              ? "border-danger/30 bg-danger/10 text-danger"
              : trust.tone === "warn"
                ? "border-warn/40 bg-warn/10 text-warn"
                : "border-fg-3/30 bg-overlay-1 text-fg-3")
          }
        >
          <span className="font-medium">{trust.label}</span>
          {trust.tone !== "ok" && <span> - {trust.detail}</span>}
          {pendingReasons(trustReply).length > 0 && (
            <details data-testid="trust-review" className="mt-1.5 text-fg-2">
              <summary className="cursor-pointer font-medium">
                {acceptOffered(trustReply) ? "Review and accept" : "Review"}
              </summary>
              {acceptOffered(trustReply) ? (
                <p className="mt-1 text-fg-3">
                  Accept only what you have read. An accepted item in a local settings file becomes information;
                  any other is lowered one level. Any change to an item asks again.
                </p>
              ) : (
                <p data-testid="trust-accept-note" className="mt-1 text-fg-3">
                  {acceptNote(trustReply)}
                </p>
              )}
              <ul className="mt-1 space-y-1.5">
                {pendingReasons(trustReply).map((r) => (
                  <li key={r.digest} className="rounded-2 border border-fg-3/20 bg-overlay-1 px-2 py-1">
                    <div className="font-mono break-all">{reasonLine(r)}</div>
                    {r.excerpt && <div className="font-mono break-all text-fg-3">{r.excerpt}</div>}
                    {r.files && r.files.length > 0 && (
                      <div className="text-fg-3">runs {r.files.join(", ")} (their bytes are part of the digest)</div>
                    )}
                    {r.indicators && r.indicators.length > 0 && (
                      <div className="text-fg-3">it {r.indicators.join(", ")}</div>
                    )}
                    {acceptOffered(trustReply) && (
                      <button
                        type="button"
                        className="mt-1 rounded-2 border border-fg-3/30 px-1.5 py-0.5 disabled:opacity-50"
                        disabled={trustBusy}
                        onClick={() => void acceptTrust(acceptOneBody(effectiveRoot, r))}
                      >
                        Accept this item
                      </button>
                    )}
                  </li>
                ))}
              </ul>
              {acceptAllBody(effectiveRoot, trustReply) !== null && (
                <button
                  type="button"
                  data-testid="trust-accept-all"
                  className="mt-1.5 rounded-2 border border-fg-3/30 px-1.5 py-0.5 disabled:opacity-50"
                  disabled={trustBusy}
                  onClick={() => void acceptTrust(acceptAllBody(effectiveRoot, trustReply))}
                >
                  Accept the {pendingReasons(trustReply).length} item(s) shown
                </button>
              )}
              {trustReply?.truncated && (
                <p className="mt-1 text-fg-3">
                  The check was cut short: entries it did not read stay untrusted and are not accepted here.
                </p>
              )}
              {trustErr && <p className="mt-1 text-danger">{trustErr}</p>}
            </details>
          )}
        </div>
      )}

      {!sshMode &&
        tool &&
        tool !== SHELL_TOOL &&
        (preflightState === "error" || (strip !== null && strip.render)) && (
          <div className="mb-3 space-y-2">
            {preflightState === "error" && (
              <div className="rounded-2 border border-danger/30 bg-danger/10 px-2 py-1.5 text-[11px] leading-relaxed text-danger">
                {preflightErrorCopy(availabilityName, preflightErr)}
              </div>
            )}

            {strip !== null && strip.render && (
              <div
                className={
                  strip.tone === "warn"
                    ? "rounded-2 border border-warn/40 bg-warn/10 px-2 py-1.5 text-[11px] leading-relaxed text-warn"
                    : "rounded-2 border border-fg-3/30 bg-overlay-1 px-2 py-1.5 text-[11px] leading-relaxed text-fg-3"
                }
              >
                <div>{strip.headline}</div>
                {/* An installed tool on a too-old runtime: the headline is
                    the short sentence; the path, the fix command (copyable,
                    on its own) and the note follow in parts. */}
                {!strip.offerInstall && launchRuntimeParts(preflight) && (
                  <RuntimeRemedy parts={launchRuntimeParts(preflight)!} showSummary={false} />
                )}

                {/* All notes, each on its own line. Capped for height, with an
                    honest "+N more" expander — never a silent truncation. */}
                {(notesExpanded
                  ? strip.notes
                  : strip.notes.slice(0, PREFLIGHT_NOTE_CAP)
                ).map((n, i) => (
                  <div key={i} className="mt-1">
                    {n}
                  </div>
                ))}
                {!notesExpanded && strip.notes.length > PREFLIGHT_NOTE_CAP && (
                  <button
                    type="button"
                    onClick={() => setNotesExpanded(true)}
                    aria-label={`Show ${strip.notes.length - PREFLIGHT_NOTE_CAP} more availability notes`}
                    className="mt-1 underline decoration-dotted underline-offset-2 hover:text-fg-1"
                  >
                    +{strip.notes.length - PREFLIGHT_NOTE_CAP} more
                  </button>
                )}

                {strip.offerInstall && preflight && (
                  <>
                    {preflight.install_command && (
                      <>
                        <div className="mt-1.5 text-fg-3">Install it with:</div>
                        <code className="mt-1 block break-all rounded-2 bg-bg-0 px-2 py-1 font-mono text-[10.5px] text-fg-1">
                          {preflight.install_command}
                        </code>
                      </>
                    )}
                    {/* DI-03: no runnable command — say WHY, so this branch
                        never dead-ends on "X is not installed." alone. */}
                    {installGuidanceFor(preflight) && (
                      <div className="mt-1.5 text-fg-3">
                        {installGuidanceFor(preflight)}
                      </div>
                    )}
                    {/* The vendor installer's grounded prerequisites (unzip,
                        bzip2, ...) are missing: the server withholds
                        can_install and names the fix, so the script is never
                        started just to fail. Observer never runs sudo. */}
                    {installPrereqRemedyFor(preflight) && (
                      <div
                        className="mt-1.5 rounded-2 border border-warn/40 bg-warn/10 px-2 py-1 text-warn"
                        data-testid="install-prereq-remedy"
                      >
                        {installPrereqRemedyFor(preflight)}
                      </div>
                    )}
                    {/* The npm package would run on a host runtime older than
                        the vendor's floor: the server withholds can_install
                        and refuses the install; say why and how to fix it. */}
                    {installRuntimeParts(preflight) && (
                      <div
                        className="mt-1.5 rounded-2 border border-warn/40 bg-warn/10 px-2 py-1 text-warn"
                        data-testid="install-runtime-remedy"
                      >
                        <RuntimeRemedy parts={installRuntimeParts(preflight)!} />
                      </div>
                    )}
                    {/* T-396: the host runtime is above the vendor's floor but
                        outside its declared range. Said, never blocking. */}
                    {installRuntimeAdvisory(preflight) && (
                      <div className="mt-1.5 text-fg-3" data-testid="install-runtime-advisory">
                        {installRuntimeAdvisory(preflight)}
                      </div>
                    )}
                    {preflight.can_install && (
                      <Button
                        variant="primary"
                        size="sm"
                        disabled={installBusy}
                        onClick={installTool}
                        className="mt-2"
                      >
                        {installBusy ? "Starting install…" : "Install in terminal"}
                      </Button>
                    )}
                  </>
                )}
              </div>
            )}

            {/* DI-17: re-run the check without changing tool or reopening the
                dialog — the fix for "I installed it in another window". */}
            <button
              type="button"
              onClick={() => setRecheckNonce((n) => n + 1)}
              aria-label={`Re-check whether ${tool} is installed`}
              className="rounded-2 border px-2 py-0.5 text-[11px] text-fg-2 hover:bg-overlay-1 hover:text-fg-1"
            >
              Re-check
            </button>
          </div>
        )}

      {/* The tool's guided-install record from THIS dashboard (node-local
          tool_installs): "Installed from this dashboard on <date>" with the
          Uninstall (only when the server says this install can be reversed
          by a defined command) or the honest guidance + Forget for a vendor
          script. Rendered independently of the strip above, which hides on a
          plain "ok" verdict - exactly the state after a successful install. */}
      {!sshMode && tool && tool !== SHELL_TOOL && preflight?.dashboard_install && (
        <div className="mb-3">
          <DashboardInstallRecord
            record={preflight.dashboard_install}
            onUninstallStarted={(r) => onLaunched(r.handle, `${tool} uninstall`, false, currentDraft())}
            onChanged={() => setRecheckNonce((n) => n + 1)}
            onOpenTerminal={(h) => onLaunched(h, `${tool} install`, false, currentDraft())}
          />
        </div>
      )}

      {signInConsent && (
        <div className="mb-3">
          <SignInSeedStep
            consent={signInConsent}
            onPhase={(p) => setPolicyStepBusy(stepHoldsStart(p))}
            onAnswer={(yes) => {
              setSignInConsent(null);
              void submit(yes);
            }}
          />
        </div>
      )}
      {freshOff && (
        <div className="mb-3">
          <FreshLaunchStep
            onPhase={(p) => setPolicyStepBusy(stepHoldsStart(p))}
            onConfirm={async (review) => {
              await applyLaunchPolicyChange({ allowFresh: true }, "Turn on fresh-agent launch", review);
              setFreshOff(false);
            }}
          />
        </div>
      )}
      {err && (
        <div className="mb-3 rounded-2 border border-danger/30 bg-danger/10 px-2 py-1.5 text-[11px] text-danger">
          {err}
        </div>
      )}

    </Modal>
  );
}
