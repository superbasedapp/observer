import { useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { apiReason, fetchJSON } from "@/lib/api";
import type {
  GUILaunchable,
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
  pickerLegend,
  preflightErrorCopy,
  preflightStripCopy,
  toolNotAllowedReason,
  type PreflightState,
} from "@/lib/toolInstall";
import {
  guiLaunchDisabledReason,
  guiLaunchErrorMessage,
  isGUISelection,
  wrapSummary,
} from "@/lib/guiLaunch";
import { pushToast } from "@/components/Toast";
import { ComboChip, Tooltip, TooltipSpan, type ComboOption } from "@/components/primitives";

// Sentinel <select> value for the "type a path by hand" escape hatch. A NUL
// byte can never be a real project root, so it can't collide with one. The NUL
// is an ESCAPE (\u0000), never a literal byte — a literal NUL makes git treat
// this whole file as binary, hiding every change from diff review.
const CUSTOM_ROOT = "\u0000custom";

// SHELL_TOOL is the reserved pseudo-tool sentinel for a fresh PLAIN SHELL
// launch (must match internal/termsvc.ShellTool = "shell" verbatim). It is
// deliberately never a member of launchable_tools (the capability registry) —
// this dialog adds it client-side as its own option, gated by the SEPARATE
// [terminal.launch].allow_shell opt-in (shell_enabled from GET
// /api/terminal/sessions), not the AI-tool allow-list.
const SHELL_TOOL = "shell";

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

// sandboxDisabledReason computes the "Run in sandbox" checkbox's disabled
// copy, honoring the honest-copy convention (CLAUDE.md): every disabled
// control names the exact blocker verbatim from the server, never a generic
// "unavailable". Priority: no tool picked > the probe hasn't resolved yet (or
// failed — B5's fail-silent pattern: a broken probe disables the control
// rather than erroring the whole dialog) > the daemon-wide verdict
// (SandboxAvailability.reason, quoted verbatim) > the shell pseudo-tool
// (never in the capability registry the probe's per-tool map is built from)
// > the selected tool's own SandboxToolAvail.reason (v1 grounds only
// claude-code; every other launchable tool carries an honest reason instead
// of silently omitting itself from the map). Returns null when the checkbox
// should be enabled.
function sandboxDisabledReason(
  tool: string,
  probe: SandboxAvailability | null,
): string | null {
  if (!tool) return "Choose a tool first.";
  if (!probe) {
    return "Sandbox status unknown - this daemon may not support sandboxed terminals, or the probe request failed.";
  }
  if (!probe.available) {
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

// sshSystemDisabledReason computes the System picker's disabled copy,
// following the same honest-disabled-control convention as
// sandboxDisabledReason above: name the exact blocker and where its switch
// lives, never a generic "unavailable". Priority: the kill switch
// ([terminal.ssh].enabled) beats an empty profile list, because turning the
// feature back on is a prerequisite to a profile mattering at all. Returns
// null when the picker should be enabled (at least one profile, feature on).
function sshSystemDisabledReason(enabled: boolean, profileCount: number): string | null {
  if (!enabled) {
    return "SSH remote-system terminals are off. Set [terminal.ssh].enabled = true in ~/.observer/config.toml and restart the daemon.";
  }
  if (profileCount === 0) {
    return "No remote systems configured yet. Add a [[terminal.ssh.profiles]] block (name, host, user, key_path) to ~/.observer/config.toml and restart the daemon. See docs/ssh-terminals.md.";
  }
  return null;
}

// shortenPath renders an absolute root as ".../parent/leaf" for the option
// label (the full path rides along as the option title). Mirrors the
// FilterBar project-picker convention so the two surfaces read the same.
function shortenPath(p: string): string {
  if (!p) return "-";
  const parts = p.split("/").filter(Boolean);
  if (parts.length <= 2) return p;
  return ".../" + parts.slice(-2).join("/");
}

// isUnderOrEqual mirrors internal/termsvc's server-side isUnderOrEqual: child is
// permitted when it equals parent or is a descendant of it. Both operands are
// the SERVER's canonical strings (allowed_project_roots is canonicalized daemon-
// side; a known-project root is compared verbatim — this is a UX hint, the POST
// re-runs the authoritative check). Trailing slashes are trimmed so "/a/" and
// "/a" match. The embedded terminal only runs where the daemon hosts a PTY
// (never native Windows), so POSIX separators are safe.
function isUnderOrEqual(child: string, parent: string): boolean {
  const c = child.replace(/\/+$/, "");
  const p = parent.replace(/\/+$/, "");
  return c === p || c.startsWith(p + "/");
}

// isPermittedRoot reports whether a project root would pass the server's
// allowed_project_roots check, using the canonical allow-list verbatim. An empty
// allow-list permits nothing but the agent's own default cwd (deny-all).
//
// KNOWN COSMETIC MISMATCH (documented, not a gate): this check is LEXICAL while
// the server canonicalizes the requested root through EvalSymlinks at launch
// time, and known-project rows arrive as the tool-reported (unresolved) paths.
// A symlinked project path can therefore render as permitted here yet be
// rejected by the POST (surfaced via PROJECT_ROOT_DENIED_MSG), or render
// disabled here yet be acceptable via "Custom path…" with the resolved target.
// The server's canonical check remains the ONLY authority — this partition is a
// UX hint and must never be loosened into (or mistaken for) authorization.
function isPermittedRoot(path: string, allowedRoots: string[]): boolean {
  return allowedRoots.some((r) => isUnderOrEqual(path, r));
}

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
  // shell_enabled from GET /api/terminal/sessions — the SEPARATE
  // [terminal.launch].allow_shell opt-in that gates the Shell option below,
  // independent of allow_fresh_agent / allowed_tools.
  const [shellEnabled, setShellEnabled] = useState(false);
  // IDE / desktop-app rows (T2.3), from the SAME GET /api/terminal/sessions
  // reply — a sibling of launchable_tools, never a replacement. Empty on an
  // older daemon (the key is simply absent), which means "no GUI section",
  // never an error.
  const [guiLaunchables, setGuiLaunchables] = useState<GUILaunchable[]>([]);
  // Live/recently-exited GUI runs this daemon has spawned, same source.
  const [guiRuns, setGuiRuns] = useState<GUIRun[]>([]);
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
  const [sandboxProbe, setSandboxProbe] = useState<SandboxAvailability | null>(null);
  // Whether the user has opted into a sandboxed launch. Seeded from the
  // server's [terminal.sandbox].default_on signal once the probe resolves;
  // the checkbox remains an explicit per-launch override.
  const [sandboxOn, setSandboxOn] = useState(initialDraft?.sandboxOn ?? false);
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
          return list[0] ?? "";
        });
        setAllowedRoots(d.allowed_project_roots ?? []);
        setShellEnabled(d.shell_enabled ?? false);
      })
      .catch((e) => {
        // DI-05: this route carries the whole picker. Swallowing its failure
        // left an empty dropdown reading "no launchable tools", which is a
        // FALSE statement about the daemon — say what actually happened.
        if (!cancelled) setToolsError(apiReason(e));
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
        }
      })
      .catch(() => {
        if (!cancelled) setSandboxProbe(null);
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
      onLaunched(r.handle, `${tool} install`, false, {
        tool,
        rootSel,
        customRoot,
        modelSel,
        sandboxOn,
        workspaceSource,
        workspaceRemote,
        workspaceBranch,
        ...(gui ? { kind: "gui" as const } : {}),
      });
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
  const strip = useMemo(() => preflightStripCopy(tool, preflight), [tool, preflight]);
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

  // gui is THE ONE derived predicate every GUI-specific branch below reads
  // (plan §2.4 / guiLaunch.ts's isGUISelection doc comment): install +
  // launch only — no resume, no continue, no attach, no model picker, no
  // sandbox, and Start posts { kind: "gui" } instead of docking a terminal.
  const selectedGUIRow = useMemo(
    () => guiLaunchables.find((r) => r.id === tool) ?? null,
    [guiLaunchables, tool],
  );
  const gui = isGUISelection(tool, guiLaunchables);
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
  );

  const noAllowList = allowedRoots.length === 0;
  // Honest reason placed on every disabled option so hovering explains the block.
  const blockedTitle = noAllowList
    ? "No project roots are allow-listed - add one in [terminal.launch].allowed_project_roots (Terminals page → launch policy)"
    : "Not in [terminal.launch].allowed_project_roots - add it in the Terminals page → launch policy";

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
  const sandboxReason = useMemo(
    () => sandboxDisabledReason(tool, sandboxProbe),
    [tool, sandboxProbe],
  );
  const sandboxCheckboxDisabled = sandboxReason !== null;
  // A source the user has currently picked but that isn't actually available
  // (e.g. left on "clone-remote" after switching to a probe/tool where it's
  // gated off) blocks the client-side hint the same way an empty remote URL
  // does — the server re-validates regardless, this only prevents an
  // obviously-doomed submit.
  const selectedSourceAvail = sandboxProbe?.sources?.find((s) => s.id === workspaceSource);
  const sandboxRemoteURLMissing =
    sandboxOn && !sandboxCheckboxDisabled && workspaceSource === "clone-remote" && workspaceRemote.trim() === "";
  const sandboxSourceUnavailable =
    sandboxOn && !sandboxCheckboxDisabled && selectedSourceAvail !== undefined && !selectedSourceAvail.available;
  const sandboxBlocksStart = sandboxOn && !sandboxCheckboxDisabled && (sandboxRemoteURLMissing || sandboxSourceUnavailable);

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
  useEffect(() => {
    if (sandboxCheckboxDisabled && sandboxOn) setSandboxOn(false);
  }, [sandboxCheckboxDisabled, sandboxOn]);

  async function submit() {
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
        pushToast(
          `Launched ${r.label} (pid ${r.pid}) — ${
            r.wrap_applied ? "routing wrap applied" : `no wrap: ${r.wrap_note}`
          }`,
          "success",
        );
        onClose();
      } catch (e) {
        setErr(guiLaunchErrorMessage(e));
      } finally {
        setBusy(false);
      }
      return;
    }
    if (sandboxBlocksStart) {
      setErr(
        sandboxRemoteURLMissing
          ? "Enter a remote URL to clone into the sandbox."
          : "The selected workspace source isn't available - pick another one.",
      );
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      // Sandbox fields are added ONLY when the checkbox is on — off, the
      // request body is byte-identical to a pre-U7 launch (plan §5). The
      // server re-validates workspace_source membership + everything else
      // and fail-CLOSES; this is a UX hint, not authorization.
      const sandboxFields = sandboxOn
        ? {
            sandbox: true,
            workspace_source: workspaceSource || "live",
            ...(workspaceRemote.trim() ? { workspace_remote: workspaceRemote.trim() } : {}),
            ...(workspaceBranch.trim() ? { workspace_branch: workspaceBranch.trim() } : {}),
          }
        : {};
      const r = await fetchJSON<FreshLaunchResponse>(
        "/api/terminal/launch",
        undefined,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            tool,
            project_root: effectiveRoot || undefined,
            model: modelSel || undefined,
            ...sandboxFields,
          }),
        },
      );
      onLaunched(r.token, r.tool || tool, r.has_project_root);
    } catch (e) {
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
    <div
      className="fixed inset-0 z-[85] flex items-center justify-center bg-black/50 p-6"
      role="dialog"
      aria-modal="true"
      aria-label="New terminal"
      onClick={onClose}
    >
      <div
        className="w-[440px] max-w-[95vw] rounded-2 border bg-bg-1 p-4 shadow-lg"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-fg-1">New terminal</h2>
          <button
            type="button"
            onClick={onClose}
            className="rounded-2 px-2 py-0.5 text-[11px] text-fg-3 hover:bg-white/10 hover:text-fg-1"
          >
            ✕
          </button>
        </div>
        <p className="mb-3 text-[11px] leading-relaxed text-fg-3">
          Start a fresh agent in the embedded terminal. The operator must enable
          this in <code className="font-mono">[terminal.launch]</code> and
          allow-list the tool and project root - otherwise the launch is
          refused.
        </p>

        {remoteBlocked && (
          <div className="mb-3 rounded-2 border border-warn/40 bg-warn/10 px-2 py-1.5 text-[11px] text-warn">
            {REMOTE_TERMINAL_OFF_MSG}
          </div>
        )}

        {resumedAfterInstall && (
          <div className="mb-3 rounded-2 border border-ok/40 bg-ok/10 px-2 py-1.5 text-[11px] text-ok">
            Installer terminal finished. Your adapter, project, model, and sandbox choices were preserved;
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
                  <span className="truncate">
                    {r.label}
                    {r.notes && r.notes.length > 0 ? ` — ${r.notes.join("; ")}` : ""}
                  </span>
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
                  own config. This picker SELECTS among them; it can never add
                  one — that is the feature's core safety property. */}
              {sshProfiles.map((p) => (
                <option key={p.name} value={p.name} title={p.target}>
                  {p.label} - {p.target}
                </option>
              ))}
            </select>
            {sshSystemReason && (
              <p className="mb-3 mt-1 text-[10.5px] leading-relaxed text-fg-3">
                {sshSystemReason}
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

        <label className="mb-1 block text-[11px] font-medium text-fg-2">
          Tool
        </label>
        <select
          disabled={sshMode}
          title={sshMode ? SSH_NA_MSG : undefined}
          value={tool}
          onChange={(e) => {
            setTool(e.target.value);
          }}
          className="mb-3 w-full rounded-2 border bg-bg-0 px-2 py-1.5 text-[12px] text-fg-1"
        >
          {tools.length === 0 && (
            <option value="">
              {toolsError
                ? "couldn't load the launchable tools"
                : "no launchable tools"}
            </option>
          )}
          {/* Native <option> — title= stays (a React tooltip can't render inside
              the browser-owned select popup), the same convention as the Shell
              option below and the project-root list above. The annotation comes
              from the SERVER's two allow-lists (DI-06), so this branches on the
              reported capability, never on the tool's name.
              Every AI-tool option stays SELECTABLE — unlike Shell below, whose
              disabled state is correct because there is nothing to preflight or
              install behind it. Disabling a non-allow-listed tool here would
              make the guided install unreachable on precisely the fresh install
              that needs it: allowed_tools defaults to EMPTY (deny-all) while
              POST /api/terminal/install is ungated by it on purpose (DI-21). The
              allow-list blocks START instead (launchBlockedFor). */}
          {toolAnnotations.map((a) => (
            <option key={a.tool} value={a.tool} title={a.title ?? undefined}>
              {a.tool}
              {a.labelSuffix}
            </option>
          ))}
          {/* IDE / desktop-app rows (T2.3, plan §2.4). A visually separated
              group, not a merge into the AI-tool list above: these carry
              install + launch only (no resume/continue/attach/model/sandbox
              — see the `gui` predicate below). `adapter === ""` is a HOST row
              (an editor with no adapter of its own, e.g. vscode) — it shows
              which AI-tool adapters run inside it (`hosts`) instead of a
              watched pill, since a host has no capture of its own to watch. */}
          {guiLaunchables.length > 0 && (
            <optgroup label="IDE / desktop app">
              {guiLaunchables.map((r) => {
                const badge = r.surface === "ide" ? "IDE" : "Desktop";
                const isHost = r.adapter === "";
                const notAllowedSuffix = !r.allowed ? " · not allow-listed" : "";
                const notWatchedSuffix =
                  !isHost && r.allowed && !r.watched ? " · not watched" : "";
                const hostsSuffix =
                  isHost && r.hosts.length > 0 ? ` · hosts: ${r.hosts.join(", ")}` : "";
                const title = !r.allowed
                  ? toolNotAllowedReason(r.id)
                  : !isHost && !r.watched
                    ? TOOL_NOT_WATCHED_MSG
                    : r.note || undefined;
                return (
                  <option key={r.id} value={r.id} title={title}>
                    {r.label} [{badge}]
                    {notAllowedSuffix}
                    {notWatchedSuffix}
                    {hostsSuffix}
                  </option>
                );
              })}
            </optgroup>
          )}
          {/* Native <option> - title= stays (React tooltip can't render inside
              the browser-owned select popup). Shell is a reserved pseudo-tool,
              never a member of `tools` (the capability registry) - gated by
              its own SEPARATE [terminal.launch].allow_shell opt-in instead of
              the AI-tool allow-list. */}
          <option
            value={SHELL_TOOL}
            disabled={!shellEnabled}
            title={
              shellEnabled
                ? "Start a plain shell ($SHELL, or bash/sh as a fallback) - no AI tool involved."
                : "Not enabled - turn on [terminal.launch].allow_shell in Terminals → launch policy"
            }
          >
            Shell {shellEnabled ? "" : "(disabled)"}
          </option>
        </select>

        {/* DI-05: the picker's source route failed. Say so instead of letting
            the empty dropdown imply the daemon has no launchable tools. */}
        {toolsError && (
          <p className="-mt-2 mb-3 rounded-2 border border-danger/30 bg-danger/10 px-2 py-1.5 text-[10.5px] leading-relaxed text-danger">
            Couldn't load the launchable tools: {toolsError} — the tool list,
            project-root allow-list and Shell option are all unknown until this
            request succeeds. Reopen this dialog to retry.
          </p>
        )}

        {/* DI-06: the two independent allow-lists behind the picker, made
            visible up front instead of learned from a post-Start 403. The
            per-option title carries the specific reason; this line carries the
            counts and the fix. */}
        {!sshMode && pickerLegendText && (
          <p className="-mt-2 mb-3 text-[10.5px] leading-relaxed text-fg-3">
            {pickerLegendText}{" "}
            {/* SPA navigation (Link, not a bare <a>) so the Terminals page's
                hash effect can select the Settings tab and scroll to the card.
                The dialog closes on the way out — leaving a modal floating over
                the page the operator was just sent to read would defeat it. */}
            <Link
              to="/terminals#launch-policy"
              onClick={onClose}
              className="underline decoration-dotted underline-offset-2 hover:text-fg-1"
            >
              Open the launch policy
            </Link>
            .
          </p>
        )}

        {/* The selected tool's own caveat, spelled out rather than left to a
            hover on a native <option> the browser may never show. The disallowed
            case is what disables Start (see launchBlockedFor) — the availability
            strip and its Install button below stay fully live. */}
        {!sshMode && selectedAnnotation && !selectedAnnotation.allowed && (
          <p className="-mt-2 mb-3 rounded-2 border border-warn/40 bg-warn/10 px-2 py-1.5 text-[10.5px] leading-relaxed text-warn">
            {toolNotAllowedReason(tool)}{" "}
            <Link
              to="/terminals#launch-policy"
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

        {/* The selected GUI row's own gating caveat — mirrors the AI-tool
            blocks above (selectedAnnotation is always null for a GUI id, so
            those never fire here) using the SAME allow-list/preflight copy
            via guiLaunchDisabledReason, so a "not allowed" or "not
            installed" GUI row reads exactly like its terminal counterpart. */}
        {!sshMode && gui && selectedGUIRow && guiLaunchDisabledReason(selectedGUIRow, preflight, selectedGUIRow.allowed) && (
          <p className="-mt-2 mb-3 rounded-2 border border-warn/40 bg-warn/10 px-2 py-1.5 text-[10.5px] leading-relaxed text-warn">
            {guiLaunchDisabledReason(selectedGUIRow, preflight, selectedGUIRow.allowed)}{" "}
            {!selectedGUIRow.allowed && (
              <Link
                to="/terminals#launch-policy"
                onClick={onClose}
                className="underline decoration-dotted underline-offset-2 hover:text-fg-1"
              >
                Open the launch policy
              </Link>
            )}
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
                    default directory can launch — that's the SuperBased
                    daemon's own working directory (where{" "}
                    <code className="font-mono">observer start</code> ran).
                    Add roots under{" "}
                    <code className="font-mono">
                      [terminal.launch].allowed_project_roots
                    </code>{" "}
                    on the Terminals page (launch policy) to enable them.
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
                <div className="mb-3" />
              </>
            ) : (
              <p className="mb-3 rounded-2 border border-border/60 bg-bg-0 px-2 py-1.5 text-[11px] leading-relaxed text-fg-3">
                Launched without a project directory — this app takes none.
              </p>
            )}
            {selectedGUIRow && (
              <div className="mb-3 rounded-2 border border-line-2 bg-bg-2 px-2 py-1.5 text-[11px] leading-relaxed text-fg-3">
                <div>{wrapSummary(selectedGUIRow)}</div>
                {selectedGUIRow.note && <div className="mt-1">{selectedGUIRow.note}</div>}
              </div>
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
            directory (where <code className="font-mono">observer start</code> ran).
            Add roots under{" "}
            <code className="font-mono">[terminal.launch].allowed_project_roots</code>{" "}
            on the Terminals page (launch policy) to enable them.
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
        {rootSel === CUSTOM_ROOT && (
          <p className="mt-1 text-[10.5px] leading-relaxed text-fg-3">
            Windows paths (<code className="font-mono">C:\Users\…</code>) are
            accepted and translated to their WSL{" "}
            <code className="font-mono">/mnt/c/…</code> form.
          </p>
        )}
        <div className="mb-3" />

        <label className="mb-1 flex items-start gap-2">
          <input
            type="checkbox"
            checked={sandboxOn}
            disabled={sandboxCheckboxDisabled}
            title={sandboxReason ?? undefined}
            onChange={(e) => setSandboxOn(e.target.checked)}
            className="mt-0.5"
          />
          <span>
            <span className="font-medium text-fg-1">Run in sandbox</span>
            <span className="block text-[11px] text-fg-3">
              {sandboxReason ??
                "Launch inside a bubblewrap sandbox with an isolated $HOME - the agent can't read or write your real home directory or other projects."}
            </span>
          </span>
        </label>

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
                  placeholder="main"
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
        {!sshMode &&
          tool &&
          tool !== SHELL_TOOL &&
          (preflightState === "error" || (strip !== null && strip.render)) && (
            <div className="mb-3 space-y-2">
              {preflightState === "error" && (
                <div className="rounded-2 border border-danger/30 bg-danger/10 px-2 py-1.5 text-[11px] leading-relaxed text-danger">
                  {preflightErrorCopy(tool, preflightErr)}
                </div>
              )}

              {strip !== null && strip.render && (
                <div
                  className={
                    strip.tone === "warn"
                      ? "rounded-2 border border-warn/40 bg-warn/10 px-2 py-1.5 text-[11px] leading-relaxed text-warn"
                      : "rounded-2 border border-fg-3/30 bg-white/5 px-2 py-1.5 text-[11px] leading-relaxed text-fg-3"
                  }
                >
                  <div>{strip.headline}</div>

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

                  {strip.blocking && preflight && (
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
                      {preflight.can_install && (
                        <button
                          type="button"
                          disabled={installBusy}
                          onClick={installTool}
                          className="mt-2 rounded-2 bg-accent px-3 py-1 text-[11px] font-medium text-white disabled:opacity-50"
                        >
                          {installBusy ? "Starting install…" : "Install in terminal"}
                        </button>
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
                className="rounded-2 border px-2 py-0.5 text-[11px] text-fg-2 hover:bg-white/10 hover:text-fg-1"
              >
                Re-check
              </button>
            </div>
          )}

        {err && (
          <div className="mb-3 rounded-2 border border-danger/30 bg-danger/10 px-2 py-1.5 text-[11px] text-danger">
            {err}
          </div>
        )}

        <div className="flex justify-end gap-2">
          <button
            type="button"
            onClick={onClose}
            className="rounded-2 px-3 py-1.5 text-[12px] text-fg-2 hover:bg-white/10"
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
              : remoteBlocked
              ? REMOTE_TERMINAL_OFF_MSG
              : launchBlockedByVerdict
                ? launchBlockedReason(
                    tool,
                    preflightState,
                    preflight,
                    preflightErr,
                    selectedToolAllowed,
                  ) ?? `${tool} can't be launched from here right now`
                : sandboxBlocksStart
                  ? sandboxRemoteURLMissing
                    ? "Enter a remote URL to clone into the sandbox, or choose a different workspace"
                    : "The selected workspace source isn't available - choose a different one"
                  : null;
            const startBtn = (
              <button
                type="button"
                disabled={
                  busy ||
                  (sshMode
                    ? // A remote launch needs only a selected system. None of the
                      // local gates (tool chosen, binary verdict, sandbox
                      // workspace) apply, and remoteBlocked is about the
                      // [remote].allow_terminal INBOUND tier - an orthogonal
                      // feature (the route is owner-local anyway).
                      !sshProfile
                    : !tool || remoteBlocked || launchBlockedByVerdict || sandboxBlocksStart)
                }
                onClick={submit}
                className="rounded-2 bg-accent px-3 py-1.5 text-[12px] font-medium text-white disabled:opacity-50"
              >
                {busy
                  ? "Starting…"
                  : gui && selectedGUIRow
                    ? `Launch ${selectedGUIRow.label}`
                    : "Start"}
              </button>
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
        </div>
      </div>
    </div>
  );
}
