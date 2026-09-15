import {
  createContext,
  lazy,
  Suspense,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import type { ReactNode } from "react";
import { createPortal } from "react-dom";
import { useNavigate } from "react-router-dom";
import { isRemoteView } from "@/lib/remote";
import {
  LaunchTerminal,
  isLiveStatus,
  policyStopMessage,
} from "@/components/LaunchTerminal";
import type { Status, PolicyStopInfo } from "@/components/LaunchTerminal";
import { NewTerminalDialog } from "@/components/NewTerminalDialog";
import type { NewTerminalDraft } from "@/components/NewTerminalDialog";
import {
  useTerminalStatuses,
  AgentStatusBadge,
} from "@/components/useTerminalStatuses";
import {
  REMOTE_TERMINAL_OFF_MSG,
  useRemoteTerminalGate,
} from "@/lib/remoteTerminal";
import { usePointerDrag } from "@/lib/useDrag";
import { useMobileTerminal } from "@/lib/useMediaQuery";
import { useVisualViewport } from "@/lib/useVisualViewport";
import type { ProjectPanelTab } from "@/components/ProjectPanel";
import { CompanionProvider } from "@/components/primitives/companion";
import { Tooltip, TooltipSpan } from "@/components/primitives";

// Lazy so the per-terminal project panel (file tree + git graph) stays out of
// the critical chunk — it loads only when a terminal's Files/Git button fires.
const ProjectPanel = lazy(() => import("@/components/ProjectPanel"));

// Lazy so the per-terminal session cockpit (cost / tokens / live activity)
// stays out of the critical chunk — it loads only when a terminal's Session
// button fires. Same discipline as ProjectPanel above.
const SessionCockpitPanel = lazy(() => import("@/components/cockpit/SessionCockpitPanel"));
// Lazy for the same reason: the full session-detail slide-over pulls in the
// whole sessiondetail tab tree (messages table, charts, predictor), which a
// terminal-only visitor should never download.
const TerminalSessionModal = lazy(
  () => import("@/components/cockpit/TerminalSessionModal"),
);

// Project panels live in a BOUNDED z-band ABOVE the expanded-terminal backdrop
// (z-80) and the dock (z-70), but comfortably BELOW the guided tour (z-120/130)
// and the context menu (z-200). On every raise the sibling panels are
// renormalized into [PANEL_Z_BASE, PANEL_Z_MAX] (never a monotonically growing
// counter), so no amount of interaction can push a panel over the tour or its
// own menu (P2-4).
const PANEL_Z_BASE = 90;
const PANEL_Z_MAX = 110;

/**
 * renormalizeZ reassigns every open panel a compact z in [BASE, MAX], ordered
 * by current z ascending, with `raiseTok` forced to the top. Returns the SAME
 * array reference when nothing changes (so a redundant raise — e.g. the double
 * onRaise a title-drag fires — doesn't churn state or re-increment anything).
 */
// raiseKey is the composite `${kind}:${token}` identity a raise/close targets
// — a bare token would let raising a session cockpit also raise a project
// panel open on the same terminal (they're independent floating panels that
// happen to share a token).
function renormalizeZ(panels: PanelEntry[], raiseKey?: string): PanelEntry[] {
  const keyOf = (p: PanelEntry) => `${p.kind}:${p.token}`;
  const ordered = [...panels].sort((a, b) => {
    if (raiseKey) {
      if (keyOf(a) === raiseKey) return 1; // raised entry last (top)
      if (keyOf(b) === raiseKey) return -1;
    }
    return a.z - b.z;
  });
  const next = ordered.map((p, i) => ({
    ...p,
    z: Math.min(PANEL_Z_BASE + i, PANEL_Z_MAX),
  }));
  // Compare POSITIONALLY, not by matching token->old-z (P3-10): with 22+
  // panels several clamp to the z=110 ceiling, so raising one tied-at-ceiling
  // panel changes no z value. A by-z-only check would then report "unchanged"
  // and the raised panel wouldn't actually reorder. `panels` is always already
  // in renormalized (z-ascending, raiseKey-last) order, so a positional
  // token/kind/z diff catches a pure reordering among ceiling ties too.
  const changed = next.some((p, i) => {
    const old = panels[i];
    return !old || old.token !== p.token || old.kind !== p.kind || old.z !== p.z;
  });
  return changed ? next : panels;
}

/** Lowest cascade slot not currently occupied by an open panel (P2-5). */
function lowestFreeCascade(panels: PanelEntry[]): number {
  const used = new Set(panels.map((p) => p.cascade));
  let i = 0;
  while (used.has(i)) i++;
  return i;
}

// LaunchDock owns every live embedded terminal at the APP level, so a
// terminal survives the "Continue in…" modal closing and can be minimized
// without being destroyed. The core discipline: a launched `LaunchTerminal`
// is mounted ONCE at a stable position in this provider's tree and NEVER
// conditionally re-rendered into a different parent — because unmounting it
// tears down the websocket AND the xterm instance, losing the scrollback and
// forcing a fresh subscribe. It does NOT kill the child: since detach-replay
// the server keeps the PTY running across a viewer disconnect (termsession
// Unsubscribe removes the viewer without terminating the process, and idle
// reaping is off by default), which is why closeSession below must issue an
// explicit DELETE to reap and why LaunchTerminal reconnects instead of
// tombstoning when its socket drops. (The older "the server reaps the child on
// ws-disconnect" note here was simply wrong, and contradicted by both.)
// "Minimize" therefore only toggles CSS (the panel goes off-screen, the ws +
// process stay alive); "Stop & close" is the sole destructive path.
//
// UX (docs/session-handoff.md launch section, Tier 1):
//   - one session shown expanded at a time (a dim backdrop, like the modal);
//   - backdrop click, or Escape when the TUI isn't focused, → MINIMIZE;
//   - Escape while the live terminal is focused → goes to the TUI (the
//     embedded tool needs Escape — we never hijack it);
//   - Cmd/Ctrl-. → minimize from the keyboard even while focused;
//   - minimized sessions live as pills bottom-right; click to restore, × to
//     stop & close;
//   - a beforeunload guard warns before a tab-close/refresh kills a live
//     session (true detach/reattach across reloads is the Tier 2 follow-up).

/** A launched session the dock owns. token is the opaque launch handle. */
export type DockSession = { token: string; tool: string; sessionId: string; hasProjectRoot?: boolean };

/** One row of GET /api/launch/sessions (dashboard.LaunchInfo wire shape). */
type LaunchInfoWire = {
  token: string;
  subcommand?: string;
  session_id?: string;
  exited?: boolean;
  has_project_root?: boolean;
};

type LaunchDockCtx = {
  /** Register a freshly launched session and show it expanded. */
  launch: (s: DockSession) => void;
  /** Open the New-terminal dialog (the same one the floating dock's + uses). */
  openNewTerminal: () => void;
  /** The dock-owned live sessions (the Terminal Workspace reads these). */
  sessions: DockSession[];
  /** Per-token connection status. */
  statuses: Record<string, Status>;
  /** Stop & close (destructive — unmount → ws close → server reap). */
  closeSession: (token: string) => void;
  /** Expand a session as the floating panel (undocked view). */
  restore: (token: string) => void;
  /**
   * The Terminal Workspace grid seam (dock-grid design D2): register a grid
   * cell ELEMENT as the docking target for a session. The provider stays the
   * SOLE owner of the mounted LaunchTerminal — its stable host element is
   * imperatively reparented into the cell (a DOM move preserves the live
   * xterm), and reparented back to the floating tree when the cell
   * unregisters (el = null). One cell per token; the grid is a VIEW, never a
   * second owner.
   */
  registerWorkspaceCell: (token: string, el: HTMLElement | null) => void;
  /** True once the boot session-rehydrate has settled (success or failure). */
  sessionsHydrated: boolean;
  /**
   * One-click docking from a floating terminal window. When the Terminal
   * Workspace is mounted its sink receives the token immediately; otherwise
   * the token is queued (pendingDock) and the app navigates to /terminals,
   * where the workspace consumes the queue on mount. Never auto-invoked —
   * docking is always an explicit user gesture (both the floating-window and
   * the grid workflows are first-class).
   */
  requestDock: (token: string) => void;
  /** Workspace-registered dock sink (null on unmount). */
  registerDockSink: (fn: ((token: string) => void) | null) => void;
  /** Tokens queued by requestDock while the workspace was unmounted. */
  pendingDock: string[];
  clearPendingDock: () => void;
  /** Open the per-terminal project panel (file tree / git) for a token+tab. */
  openProjectPanel: (token: string, tab: ProjectPanelTab) => void;
  /**
   * Open/toggle the per-terminal session cockpit panel (cost / tokens / live
   * activity) for a token. Same live-token guard as openProjectPanel; rejects
   * a token whose session is gone or no longer live.
   */
  openSessionPanel: (token: string) => void;
  /**
   * Open the FULL session-detail slide-over over the terminal workspace for a
   * token (Task 9) — the terminal's "⊙ Session" control. Distinct from
   * openSessionPanel, which opens the small floating vitals cockpit that docks
   * beside the terminal: this one is the whole session detail (KPIs, messages,
   * cost & limits, cache, system) presented as a modal layer, so the terminal
   * is never navigated away from. One at a time — it is a modal, not a
   * cascading panel — so this is a plain "which token", not an array.
   */
  openSessionDetail: (token: string) => void;
  /**
   * Register/unregister the live paste-into-terminal callback for a token.
   * LaunchTerminal registers one while its seat is live + write-capable; a
   * project panel shows its paste items only when a callback exists for its
   * token (structurally read-only-safe). The callback routes text through
   * xterm's own paste pipeline (like a manual Ctrl+V).
   */
  registerPaste: (tok: string, fn: ((text: string) => void) | null) => void;
  /**
   * The open floating panels — project panels AND session cockpit panels,
   * one entry per terminal token × kind (multi-panel; a token can have both
   * a project panel and a session panel open at once).
   */
  panels: PanelEntry[];
};

// The two floating-panel kinds that share the same token-keyed stacking/
// cascade model. `tab` on PanelEntry is meaningful only for "project".
type PanelKind = "project" | "session";

// One open floating panel (project OR session cockpit). `z` is the
// provider-owned stacking order (a band above the expanded-terminal
// backdrop); `cascade` is the in-memory stagger slot assigned at open time
// and fixed for the panel's lifetime.
type PanelEntry = {
  token: string;
  kind: PanelKind;
  tab: ProjectPanelTab;
  z: number;
  cascade: number;
};

const Ctx = createContext<LaunchDockCtx | null>(null);

export function LaunchDockProvider({ children }: { children: ReactNode }) {
  const [sessions, setSessions] = useState<DockSession[]>([]);
  const [activeToken, setActiveToken] = useState<string | null>(null);
  const [statuses, setStatuses] = useState<Record<string, Status>>({});
  // Node-intervention policy-stop explanations, keyed by token — populated
  // from each mounted LaunchTerminal's exit frame (server:
  // internal/intelligence/dashboard policystop.go) so the minimized pill can
  // surface the same explanation as the expanded modal.
  const [policyStops, setPolicyStops] = useState<
    Record<string, PolicyStopInfo | undefined>
  >({});
  const [newOpen, setNewOpen] = useState(false);
  // Guided installers run in a visible setup PTY and normally exit when the
  // package is installed. Preserve the launcher's exact choices while that PTY
  // owns the screen, then reopen New Terminal against a fresh preflight when
  // it exits so the operator does not have to choose tool/root/model/sandbox
  // all over again.
  const [newTerminalDraft, setNewTerminalDraft] = useState<NewTerminalDraft>();
  const [resumedAfterInstall, setResumedAfterInstall] = useState(false);
  const [pendingInstall, setPendingInstall] = useState<{
    token: string;
    draft: NewTerminalDraft;
  } | null>(null);
  // The per-terminal floating panels — project panels (file tree + git) AND
  // session cockpit panels. ONE shared array for both kinds: multi-panel, one
  // entry per terminal token × kind, all simultaneously open, rendered at
  // provider level. z-order is renormalized into a bounded band on every
  // raise (renormalizeZ), so it never climbs into the tour/context-menu
  // layers, and stays shared across kinds so lowestFreeCascade sees every
  // open panel regardless of kind.
  const [panels, setPanels] = useState<PanelEntry[]>([]);
  // Live paste callbacks keyed by token — the paste-into-terminal channel. A
  // panel shows its paste items only when a callback exists for its token.
  const [pasteFns, setPasteFns] = useState<Record<string, (text: string) => void>>({});
  // Latest sessions/statuses read by openProjectPanel's live-token guard
  // WITHOUT re-creating the callback (it must stay identity-stable).
  const sessionsRef = useRef(sessions);
  sessionsRef.current = sessions;
  const statusesRef = useRef(statuses);
  statusesRef.current = statuses;
  // Latest pendingInstall read by closeSession WITHOUT re-creating that
  // callback (it is passed down to every terminal + panel and must stay
  // identity-stable). Same pattern as sessionsRef/statusesRef above.
  const pendingInstallRef = useRef(pendingInstall);
  pendingInstallRef.current = pendingInstall;
  // Workspace grid cells: token → the registered cell element the session's
  // stable host is reparented into (dock-grid design D2). Docked sessions
  // hide their floating pill; undocked ones behave exactly as before.
  const [cells, setCells] = useState<Record<string, HTMLElement>>({});
  // True once the boot rehydrate (GET /api/launch/sessions) has settled, so
  // the workspace can tell "still discovering sessions" from "this saved tile
  // is genuinely dead" (tombstone vs pending).
  const [sessionsHydrated, setSessionsHydrated] = useState(false);
  // Explicit-gesture docking plumbing (never automatic): the workspace
  // registers a sink while mounted; requestDock routes through it or queues +
  // navigates to /terminals.
  const dockSinkRef = useRef<((token: string) => void) | null>(null);
  const [pendingDock, setPendingDock] = useState<string[]>([]);
  const navigate = useNavigate();
  // A read-only remote paired device gets no dock gesture: the workspace
  // never registers a sink for it, so the button would minimize + queue an
  // unconsumable token (review MED). Stable per page load.
  const remoteViewer = isRemoteView();

  const launch = useCallback((s: DockSession) => {
    setSessions((prev) =>
      prev.some((p) => p.token === s.token) ? prev : [...prev, s],
    );
    setActiveToken(s.token);
  }, []);

  const minimize = useCallback(() => setActiveToken(null), []);
  const restore = useCallback((token: string) => setActiveToken(token), []);

  const closeSession = useCallback((token: string) => {
    // Reap the server-side process FIRST: since detach-replay, a ws close
    // only DETACHES (the child stays alive for reconnect / idle-reap), so the
    // destructive promise needs the explicit DELETE. Best-effort — the state
    // teardown below proceeds regardless; a failed DELETE leaves the session
    // to rehydrate honestly as a live pill on the next load.
    fetch(`/api/launch/${encodeURIComponent(token)}`, { method: "DELETE" }).catch(() => {
      /* daemon unreachable — nothing to reap */
    });
    setSessions((prev) => prev.filter((p) => p.token !== token));
    setStatuses((prev) => {
      // DI-17: closing the GUIDED-INSTALLER pill by hand must not destroy the
      // auto-resume. The resume effect below waits for that token's status to
      // reach "exited"/"error"; deleting the entry meant the condition could
      // never be met, so the operator's tool/root/model/sandbox choices were
      // silently dropped and they had to fill the dialog in again. The DELETE
      // above has just reaped the PTY, so "exited" is the honest status —
      // record it instead of forgetting the token.
      if (pendingInstallRef.current?.token === token) {
        return prev[token] === "exited" ? prev : { ...prev, [token]: "exited" };
      }
      const next = { ...prev };
      delete next[token];
      return next;
    });
    setActiveToken((cur) => (cur === token ? null : cur));
  }, []);

  const setStatus = useCallback((token: string, s: Status) => {
    setStatuses((prev) => (prev[token] === s ? prev : { ...prev, [token]: s }));
  }, []);

  const setPolicyStop = useCallback(
    (token: string, info: PolicyStopInfo | undefined) => {
      setPolicyStops((prev) =>
        prev[token] === info ? prev : { ...prev, [token]: info },
      );
    },
    [],
  );

  useEffect(() => {
    if (!pendingInstall) return;
    const status = statuses[pendingInstall.token];
    if (status !== "exited" && status !== "error") return;
    setNewTerminalDraft(pendingInstall.draft);
    setPendingInstall(null);
    setResumedAfterInstall(true);
    setActiveToken((current) =>
      current === pendingInstall.token ? null : current,
    );
    setNewOpen(true);
  }, [pendingInstall, statuses]);

  const registerWorkspaceCell = useCallback(
    (token: string, el: HTMLElement | null) => {
      setCells((prev) => {
        if (el === null) {
          if (!(token in prev)) return prev;
          const next = { ...prev };
          delete next[token];
          return next;
        }
        if (prev[token] === el) return prev;
        return { ...prev, [token]: el };
      });
    },
    [],
  );

  const openNewTerminal = useCallback(() => {
    // A manual reopen supersedes the pending automatic one, but deliberately
    // keeps the saved draft so an impatient operator still resumes in place.
    setPendingInstall(null);
    setResumedAfterInstall(false);
    setNewOpen(true);
  }, []);

  // Open/toggle the project panel for a token. Same-tab reopen closes it
  // (toggle); other-tab reopen retargets the tab and raises; a new token
  // appends a panel in the lowest free cascade slot. Rejects opening against
  // a token whose session is gone or no longer live (exited OR error — see
  // isLiveStatus) — the provider-side guard behind the disabled buttons
  // (P2-3), so a stale/programmatic open can't resurrect a dead token. Matches
  // entries on token && kind==="project" so a session cockpit open on the same
  // token is untouched.
  const openProjectPanel = useCallback((tok: string, tab: ProjectPanelTab) => {
    const known = sessionsRef.current.some((s) => s.token === tok);
    if (!known || !isLiveStatus(statusesRef.current[tok])) return;
    setPanels((prev) => {
      const existing = prev.find((p) => p.token === tok && p.kind === "project");
      if (existing) {
        if (existing.tab === tab) {
          return prev.filter((p) => !(p.token === tok && p.kind === "project"));
        }
        return renormalizeZ(
          prev.map((p) => (p.token === tok && p.kind === "project" ? { ...p, tab } : p)),
          `project:${tok}`,
        );
      }
      const cascade = lowestFreeCascade(prev);
      return renormalizeZ(
        [...prev, { token: tok, kind: "project", tab, z: PANEL_Z_BASE, cascade }],
        `project:${tok}`,
      );
    });
  }, []);
  const raiseProjectPanel = useCallback((tok: string) => {
    setPanels((prev) =>
      prev.some((p) => p.token === tok && p.kind === "project")
        ? renormalizeZ(prev, `project:${tok}`)
        : prev,
    );
  }, []);
  const setProjectPanelTab = useCallback((tok: string, tab: ProjectPanelTab) => {
    setPanels((prev) =>
      prev.map((p) => (p.token === tok && p.kind === "project" ? { ...p, tab } : p)),
    );
  }, []);
  const closeProjectPanelToken = useCallback((tok: string) => {
    setPanels((prev) => prev.filter((p) => !(p.token === tok && p.kind === "project")));
  }, []);

  // Open/toggle the session cockpit panel for a token — same live-token guard as
  // openProjectPanel, but a pure toggle (no tab to retarget): open→close,
  // closed→append at the lowest free cascade slot (shared with project
  // panels) and raise.
  const openSessionPanel = useCallback((tok: string) => {
    const known = sessionsRef.current.some((s) => s.token === tok);
    if (!known || !isLiveStatus(statusesRef.current[tok])) return;
    setPanels((prev) => {
      const existing = prev.find((p) => p.token === tok && p.kind === "session");
      if (existing) {
        return prev.filter((p) => !(p.token === tok && p.kind === "session"));
      }
      const cascade = lowestFreeCascade(prev);
      return renormalizeZ(
        [...prev, { token: tok, kind: "session", tab: "files", z: PANEL_Z_BASE, cascade }],
        `session:${tok}`,
      );
    });
  }, []);
  const raiseSessionPanel = useCallback((tok: string) => {
    setPanels((prev) =>
      prev.some((p) => p.token === tok && p.kind === "session")
        ? renormalizeZ(prev, `session:${tok}`)
        : prev,
    );
  }, []);
  const closeSessionPanelToken = useCallback((tok: string) => {
    setPanels((prev) => prev.filter((p) => !(p.token === tok && p.kind === "session")));
  }, []);

  // The full session-detail modal (Task 9). NOT part of the `panels` array:
  // panels are cascading, independently-stacked, several-at-once floating
  // windows, while this is a single modal layer with a scrim — modelling it as
  // a panel would mean a scrim per instance and a stacking contest between
  // modals. One token at a time; opening a second replaces the first.
  const [sessionDetailToken, setSessionDetailToken] = useState<string | null>(null);
  const openSessionDetail = useCallback((tok: string) => {
    // Same liveness guard the panel openers use: a token whose run is gone can
    // neither be correlated nor shown honestly.
    const known = sessionsRef.current.some((s) => s.token === tok);
    if (!known || !isLiveStatus(statusesRef.current[tok])) return;
    setSessionDetailToken((prev) => (prev === tok ? null : tok));
  }, []);
  // A terminal that closes (or dies) while its detail modal is open must not
  // leave the modal stranded against a dead token — the same reasoning the
  // panels array's own liveness sweep uses.
  useEffect(() => {
    if (!sessionDetailToken) return;
    const alive =
      sessions.some((s) => s.token === sessionDetailToken) &&
      isLiveStatus(statuses[sessionDetailToken]);
    if (!alive) setSessionDetailToken(null);
  }, [sessionDetailToken, sessions, statuses]);
  const registerPaste = useCallback(
    (tok: string, fn: ((text: string) => void) | null) => {
      setPasteFns((prev) => {
        if (fn === null) {
          if (!(tok in prev)) return prev;
          const next = { ...prev };
          delete next[tok];
          return next;
        }
        if (prev[tok] === fn) return prev;
        return { ...prev, [tok]: fn };
      });
    },
    [],
  );

  const registerDockSink = useCallback(
    (fn: ((token: string) => void) | null) => {
      dockSinkRef.current = fn;
    },
    [],
  );

  const requestDock = useCallback(
    (token: string) => {
      // Close the floating panel either way — the terminal is moving to the
      // grid (or its queue), not the modal.
      setActiveToken((cur) => (cur === token ? null : cur));
      const sink = dockSinkRef.current;
      if (sink) {
        sink(token);
        return;
      }
      setPendingDock((prev) => (prev.includes(token) ? prev : [...prev, token]));
      // Unique param per request: navigating to an identical URL would not
      // re-fire the page's [location.search] effect (review finding — a user
      // who locally switched to the Settings tab would strand the queued
      // dock), so each request carries a fresh nonce.
      navigate(`/terminals?tab=workspace&dock=${Date.now()}`);
    },
    [navigate],
  );

  const clearPendingDock = useCallback(() => setPendingDock([]), []);

  // Rehydrate on load: re-discover live terminal sessions the server kept
  // alive across a tab-close/refresh (Tier 2). Each becomes a MINIMIZED pill
  // (we don't steal focus by auto-expanding); its TerminalHost mounts the
  // LaunchTerminal off-screen, which reconnects the ws and replays the recent
  // output ring in the background. Dedup by handle so this never duplicates a
  // session already added via launch().
  useEffect(() => {
    let cancelled = false;
    fetch("/api/launch/sessions")
      .then((r) => (r.ok ? r.json() : null))
      .then((data: { sessions?: LaunchInfoWire[] } | null) => {
        if (cancelled || !data?.sessions) return;
        const live = data.sessions.filter((s) => s && !s.exited && s.token);
        if (live.length === 0) return;
        setSessions((prev) => {
          const known = new Set(prev.map((p) => p.token));
          const add: DockSession[] = live
            .filter((s) => !known.has(s.token))
            .map((s) => ({
              token: s.token,
              tool: s.subcommand || "terminal",
              sessionId: s.session_id || "",
              hasProjectRoot: !!s.has_project_root,
            }));
          return add.length ? [...prev, ...add] : prev;
        });
      })
      .catch(() => {
        /* dashboard without the launch seam (503) — nothing to rehydrate */
      })
      .finally(() => {
        if (!cancelled) setSessionsHydrated(true);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // Lifecycle (review finding 9): when a terminal's session disappears (Stop &
  // close, or a server reap that drops it from the rehydrate list), auto-close
  // its floating panels — otherwise already-fetched file/git content (or a
  // stale session cockpit) lingers on screen against a token the daemon has
  // already invalidated. Covers BOTH panel kinds unchanged (no kind check
  // needed — liveness is purely a function of the token).
  useEffect(() => {
    const liveTokens = new Set(sessions.map((s) => s.token));
    setPanels((prev) => {
      const next = prev.filter(
        (p) => liveTokens.has(p.token) && isLiveStatus(statuses[p.token]),
      );
      return next.length === prev.length ? prev : next;
    });
  }, [sessions, statuses]);

  // Warn before a tab-close/refresh silently kills a still-running session.
  useEffect(() => {
    const anyLive = sessions.some((s) => {
      const st = statuses[s.token];
      // "reconnecting" counts as live: the child is still running server-side,
      // so closing the tab still abandons a real session.
      return st === "open" || st === "connecting" || st === "reconnecting";
    });
    if (!anyLive) return;
    const onBeforeUnload = (e: BeforeUnloadEvent) => {
      e.preventDefault();
      e.returnValue = "";
    };
    window.addEventListener("beforeunload", onBeforeUnload);
    return () => window.removeEventListener("beforeunload", onBeforeUnload);
  }, [sessions, statuses]);

  const value = useMemo<LaunchDockCtx>(
    () => ({
      launch,
      openNewTerminal,
      sessions,
      statuses,
      closeSession,
      restore,
      registerWorkspaceCell,
      sessionsHydrated,
      requestDock,
      registerDockSink,
      pendingDock,
      clearPendingDock,
      openProjectPanel,
      openSessionPanel,
      openSessionDetail,
      registerPaste,
      panels,
    }),
    [
      launch,
      openNewTerminal,
      sessions,
      statuses,
      closeSession,
      restore,
      registerWorkspaceCell,
      sessionsHydrated,
      requestDock,
      registerDockSink,
      pendingDock,
      clearPendingDock,
      openProjectPanel,
      openSessionPanel,
      openSessionDetail,
      registerPaste,
      panels,
    ],
  );

  return (
    <Ctx.Provider value={value}>
      <CompanionProvider>
        {children}
      {sessions.map((s) => (
        <TerminalHost
          key={s.token}
          session={s}
          expanded={s.token === activeToken}
          cellEl={cells[s.token] ?? null}
          status={statuses[s.token]}
          onRequestDock={remoteViewer ? undefined : () => requestDock(s.token)}
          onMinimize={minimize}
          onClose={() => closeSession(s.token)}
          onStatus={(st) => setStatus(s.token, st)}
          onPolicyStop={(info) => setPolicyStop(s.token, info)}
          onOpenFiles={() => openProjectPanel(s.token, "files")}
          onOpenGit={() => openProjectPanel(s.token, "git")}
          onOpenSession={() => openSessionDetail(s.token)}
          registerPaste={registerPaste}
          projectPanelEnabled={s.hasProjectRoot ?? false}
          sessionPanelEnabled={s.tool !== "terminal"}
        />
      ))}
      <Dock
        sessions={sessions.filter((s) => !cells[s.token])}
        activeToken={activeToken}
        statuses={statuses}
        policyStops={policyStops}
        onRestore={restore}
        onClose={closeSession}
        onNew={openNewTerminal}
      />
      {newOpen && (
        <NewTerminalDialog
          initialDraft={newTerminalDraft}
          resumedAfterInstall={resumedAfterInstall}
          onClose={() => {
            setNewOpen(false);
            setResumedAfterInstall(false);
          }}
          onLaunched={(handle, tool, hasProjectRoot, resumeDraft) => {
            setNewOpen(false);
            setResumedAfterInstall(false);
            if (resumeDraft) {
              setNewTerminalDraft(resumeDraft);
              setPendingInstall({ token: handle, draft: resumeDraft });
            } else {
              setNewTerminalDraft(undefined);
              setPendingInstall(null);
            }
            launch({ token: handle, tool, sessionId: "", hasProjectRoot: hasProjectRoot ?? false });
          }}
        />
      )}
      {/* ONE ordered pass over the shared panels array, switching on kind per
          entry (P2-E). Array order = raise recency (renormalizeZ stores panels
          z-ascending, raised-last), so rendering in array order makes DOM order
          match z order — and when the bounded z-band [90,110] saturates and
          several panels tie at z=110, later DOM order breaks the tie in favour
          of the most-recently-raised panel. Two separate filtered .map()s could
          not: a DOM-later session panel would sit above a just-raised project
          panel at the same ceiling z. */}
      {panels.map((p) =>
        p.kind === "project" ? (
          <Suspense key={`project:${p.token}`} fallback={null}>
            <ProjectPanel
              token={p.token}
              tool={sessions.find((s) => s.token === p.token)?.tool ?? "terminal"}
              tab={p.tab}
              z={p.z}
              cascade={p.cascade}
              pasteToTerminal={pasteFns[p.token]}
              onRaise={() => raiseProjectPanel(p.token)}
              onTabChange={(t) => setProjectPanelTab(p.token, t)}
              onClose={() => closeProjectPanelToken(p.token)}
            />
          </Suspense>
        ) : (
          <Suspense key={`session:${p.token}`} fallback={null}>
            <SessionCockpitPanel
              token={p.token}
              z={p.z}
              cascade={p.cascade}
              onRaise={() => raiseSessionPanel(p.token)}
              onClose={() => closeSessionPanelToken(p.token)}
            />
          </Suspense>
        ),
      )}
      {/* The full session-detail modal (Task 9). Rendered LAST and outside the
          panels pass: it is a modal layer with its own scrim at z-112/114,
          above the panel band, not a member of it. Keyed on the token so
          switching terminals resets the link poll cleanly. */}
      {sessionDetailToken && (
        <Suspense key={`detail:${sessionDetailToken}`} fallback={null}>
          <TerminalSessionModal
            token={sessionDetailToken}
            onClose={() => setSessionDetailToken(null)}
            onOpenVitals={() => {
              const tok = sessionDetailToken;
              setSessionDetailToken(null);
              openSessionPanel(tok);
            }}
          />
        </Suspense>
      )}
      </CompanionProvider>
    </Ctx.Provider>
  );
}

export function useLaunchDock(): LaunchDockCtx {
  const v = useContext(Ctx);
  if (!v) throw new Error("useLaunchDock must be used within LaunchDockProvider");
  return v;
}

// TerminalHost renders a single session's LaunchTerminal at a STABLE tree
// position, into a STABLE detached host element via a one-time portal whose
// container NEVER changes — so the terminal never remounts (ws + child
// process persist). Presentation is an imperative DOM MOVE of that host
// element between three placements (dock-grid design D2):
//   docked   → the Terminal Workspace grid cell registered for this token;
//   expanded → the centered floating panel over a dim backdrop;
//   parked   → off-screen (minimized pill), kept full-size so the PTY
//              dimensions and scrollback survive and restore is instant.
// A DOM move preserves the live xterm; switching a React portal's container
// would recreate the DOM and orphan it — hence the imperative reparent.
function TerminalHost({
  session,
  expanded,
  cellEl,
  status,
  onRequestDock,
  onMinimize,
  onClose,
  onStatus,
  onPolicyStop,
  onOpenFiles,
  onOpenGit,
  onOpenSession,
  registerPaste,
  projectPanelEnabled,
  sessionPanelEnabled,
}: {
  session: DockSession;
  expanded: boolean;
  cellEl: HTMLElement | null;
  status: Status | undefined;
  onRequestDock: (() => void) | undefined;
  onMinimize: () => void;
  onClose: () => void;
  onStatus: (s: Status) => void;
  onPolicyStop: (info: PolicyStopInfo | undefined) => void;
  onOpenFiles: () => void;
  onOpenGit: () => void;
  onOpenSession: () => void;
  registerPaste: (tok: string, fn: ((text: string) => void) | null) => void;
  projectPanelEnabled: boolean;
  sessionPanelEnabled: boolean;
}) {
  const boxRef = useRef<HTMLDivElement | null>(null);
  const isLive = status === "open" || status === "connecting";
  const docked = cellEl !== null;
  // Token-bound paste registrar (stable) so LaunchTerminal can register its
  // paste-into-terminal callback for this token.
  const boundRegisterPaste = useCallback(
    (fn: ((text: string) => void) | null) => registerPaste(session.token, fn),
    [registerPaste, session.token],
  );
  const [hostEl] = useState(() => {
    const el = document.createElement("div");
    el.className = "flex w-full flex-1 min-h-0 flex-col";
    return el;
  });
  // Touch-phone presentation: the floating window becomes the whole viewport.
  // Capability-gated (coarse pointer AND small viewport) in lib/useMediaQuery —
  // a desktop user who merely narrows their window is untouched, so every
  // `mobile === false` path below is byte-for-byte what shipped.
  const mobile = useMobileTerminal();
  // Floating-window size: user-resizable (native CSS resize grip) and
  // persisted, so the modal workflow is first-class alongside the grid — a
  // resize refits the PTY via LaunchTerminal's ResizeObserver. The parked
  // wrapper uses the same size so PTY dimensions survive minimize/restore.
  const [floatSize, setFloatSize] = useState(loadFloatSize);
  useEffect(() => {
    // MOBILE MUST NOT PERSIST (defect D6). The phone panel is viewport-sized,
    // so measuring it and writing the result into FLOAT_SIZE_KEY feeds
    // phone-derived geometry into the DESKTOP default — one phone visit used
    // to shrink the user's desktop terminal window (measured: a 393px phone
    // wrote {w:480}) permanently, on every device sharing that storage.
    if (mobile) return;
    if (!expanded || docked) return;
    const el = boxRef.current;
    if (!el) return;
    let t: number | null = null;
    const persist = () => {
      const r = el.getBoundingClientRect();
      const next = { w: Math.round(r.width), h: Math.round(r.height) };
      if (next.w > 0 && next.h > 0) {
        setFloatSize(next);
        try {
          localStorage.setItem(FLOAT_SIZE_KEY, JSON.stringify(next));
        } catch {
          /* storage blocked — size still applies for this tab */
        }
      }
    };
    const ro = new ResizeObserver(() => {
      if (t) window.clearTimeout(t);
      t = window.setTimeout(() => {
        t = null;
        persist();
      }, 400);
    });
    ro.observe(el);
    return () => {
      // FLUSH a pending persist (review LOW): minimizing/docking within the
      // debounce window must not lose the final size across reloads.
      if (t) {
        window.clearTimeout(t);
        persist();
      }
      ro.disconnect();
    };
  }, [expanded, docked, mobile]);

  // Reparent the stable host: grid cell wins; otherwise the floating box.
  // Idempotent — appendChild moves the node (never clones), and the xterm
  // inside survives the move (its ResizeObserver refits to the new size).
  useEffect(() => {
    const target = cellEl ?? boxRef.current;
    if (target && hostEl.parentElement !== target) {
      target.appendChild(hostEl);
    }
  }, [cellEl, hostEl, expanded]);

  // Keyboard: while expanded (and NOT docked — the grid owns its own keys),
  // Cmd/Ctrl-. always minimizes; Escape minimizes UNLESS the live terminal
  // is focused (then it belongs to the TUI).
  useEffect(() => {
    if (!expanded || docked) return;
    const onKey = (e: KeyboardEvent) => {
      const box = boxRef.current;
      const focusedInTerminal = !!box && box.contains(document.activeElement);
      if ((e.metaKey || e.ctrlKey) && e.key === ".") {
        if (focusedInTerminal && isLive) return; // let the TUI have Ctrl-.
        e.preventDefault();
        onMinimize();
        return;
      }
      if (e.key === "Escape") {
        if (focusedInTerminal && isLive) return; // let the TUI have Escape
        onMinimize();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [expanded, docked, isLive, onMinimize]);

  const showModal = !docked && expanded;
  // The visible viewport box for the phone panel — keyboard, browser chrome
  // and all. Non-null whenever the phone panel is up and the page is not
  // pinch-zoomed; a parked or desktop panel keeps its shipped sizing exactly.
  // With no keyboard up it equals what 100dvh would have given, so this is not
  // "keyboard mode", just an accurate height. See the `style` prop below.
  const visibleBox = useVisualViewport(mobile && showModal);

  // D14: while the full-viewport terminal is up on a phone, the DOCUMENT
  // ELEMENT must refuse horizontal overscroll too. `overscroll-behavior` only
  // does anything on a scroll container, and the panel's own containment
  // therefore cannot speak for the root — which is precisely where Chrome
  // reads the property when deciding whether an edge swipe becomes
  // back-navigation. A swipe-left used to unload the whole dashboard, live PTY
  // and all (operator-reported). Restored on teardown so nothing leaks into
  // normal page scrolling; desktop is untouched.
  useEffect(() => {
    if (!mobile || !showModal) return;
    const el = document.documentElement;
    const prevX = el.style.overscrollBehaviorX;
    el.style.overscrollBehaviorX = "contain";
    return () => {
      el.style.overscrollBehaviorX = prevX;
    };
  }, [mobile, showModal]);

  // Backdrop-minimize must fire only when the PRESS started on the backdrop
  // itself: a resize-grip drag (or a text-selection drag) that releases over
  // the backdrop synthesizes a click on the wrapper — the common ancestor of
  // the mousedown and mouseup targets — which used to minimize the panel on
  // every enlarge (operator-reported).
  const backdropPress = useRef(false);
  return (
    <div
      className={
        docked
          ? "hidden"
          : showModal
            ? mobile
              ? // Phone: the backdrop IS the frame. `p-6` used to eat 48px of a
                // 393px screen, and centring is what made the overflow
                // unreachable — a centred flex item that is wider than its
                // container hangs off BOTH edges and no scroll can reach the
                // left one. `overscroll-contain` stops a drag past the top of
                // the terminal from triggering Android Chrome's
                // pull-to-refresh, which would tear the live PTY down (D11).
                "fixed inset-0 z-[80] flex items-stretch justify-stretch overscroll-contain bg-black/50 p-0"
              : "fixed inset-0 z-[80] flex items-center justify-center bg-black/50 p-6"
            : "pointer-events-none fixed left-[-100000px] top-0"
      }
      onMouseDown={
        showModal
          ? (e) => {
              backdropPress.current = e.target === e.currentTarget;
            }
          : undefined
      }
      onClick={
        showModal
          ? (e) => {
              const startedOnBackdrop = backdropPress.current;
              backdropPress.current = false;
              if (startedOnBackdrop && e.target === e.currentTarget) onMinimize();
            }
          : undefined
      }
      role={showModal ? "dialog" : undefined}
      aria-modal={showModal ? true : undefined}
      aria-hidden={showModal ? undefined : true}
      aria-label={showModal ? `${session.tool} terminal` : undefined}
    >
      {/* Deliberate: the resize hint stays a NATIVE title attribute here. A
          custom floating Tooltip would persist while the pointer rests over the
          live terminal (worse than the auto-dismissing native hint), so this one
          site keeps the browser's own tooltip. Suppressed on touch, where there
          is no resize grip to drag and no hover to dismiss the hint. */}
      <div
        ref={boxRef}
        data-testid="terminal-float-panel"
        title={
          showModal && !mobile ? "Drag the corner to resize - the terminal refits" : undefined
        }
        // THE INLINE STYLE IS WHY A TAILWIND BREAKPOINT ALONE CANNOT FIX THIS
        // (defect D1). An inline `width` beats any class, so the mobile branch
        // has to DROP the style, not merely restyle around it. On desktop the
        // persisted float size is unchanged.
        //
        // The mobile branch takes a style back, but only `height`/`transform`
        // — never `width`, which is what D1 was about. `h-[100dvh]` cannot do
        // this job: no CSS viewport unit shrinks for a keyboard (see
        // lib/useVisualViewport.ts), so without this the panel stays full
        // height and the line being typed sits underneath the keyboard.
        // Shrinking the panel is enough on its own — the terminal's existing
        // ResizeObserver sees it and refits the PTY to fewer rows, which lifts
        // the prompt into view.
        style={
          mobile
            ? visibleBox
              ? {
                  // PAN, DO NOT SHRINK. The height is the UNOCCLUDED height,
                  // so opening the keyboard does not change the panel's box —
                  // which means no ResizeObserver tick, no fit(), and no PTY
                  // resize. That is the whole point: a full-screen TUI lays
                  // itself out for the rows it is given, and squeezing them
                  // squeezes the app. Measured against a live claude 2.1.220
                  // on 2026-07-28: its composer is 5 lines at 20+ rows, 3 at
                  // 14, and exactly 2 at 8 — where it also shows only the TAIL
                  // of what you type, so a third line appears to overwrite the
                  // second. Shrinking the terminal to clear the keyboard is
                  // what put the operator's phone in that state.
                  height: visibleBox.fullHeight,
                  // Slide the panel up so its BOTTOM edge — the composer and
                  // the on-screen key bar — lands at the bottom of the visible
                  // area. The header scrolls off the top while the keyboard is
                  // up, which is the deliberate trade: what you need while
                  // typing is the line you are typing, and dismissing the
                  // keyboard brings the header straight back.
                  //
                  // offsetTop is folded in because a `position: fixed` panel is
                  // anchored to the LAYOUT viewport, so when iOS scrolls the
                  // visual viewport to reveal the focused field the panel would
                  // otherwise slide out of view.
                  //
                  // Emitted ONLY when it actually moves. A transform — even
                  // `translateY(0px)` — promotes the panel to its own
                  // compositing layer and makes it a containing block, which on
                  // iOS is a well-known way to break touch scrolling and
                  // momentum inside a descendant. With no keyboard up the shift
                  // is exactly 0, so the common case pays nothing.
                  ...(() => {
                    const shift =
                      visibleBox.offsetTop + visibleBox.height - visibleBox.fullHeight;
                    return shift !== 0 ? { transform: `translateY(${shift}px)` } : null;
                  })(),
                }
              : undefined
            : { width: floatSize.w, height: floatSize.h }
        }
        className={
          showModal
            ? mobile
              ? // Phone: fill the viewport exactly.
                //   min-w-0     — `min-w-[480px]` was the bug. Per CSS §10.4
                //                 min-width WINS over max-width, so
                //                 `max-w-[96vw]` was INERT and the box resolved
                //                 to 480px on a 393px screen (left edge at −43,
                //                 unreachable). Anything but 0 here re-breaks it.
                //   100dvh      — not `vh`: `vh` is the LARGE viewport and does
                //                 not shrink when the soft keyboard opens, which
                //                 hid the input + status lines behind it (D7).
                //   pb-safe     — the home-indicator inset, paired with
                //                 viewport-fit=cover in index.html (D12).
                //   resize-none — no grip to drag with a finger.
                "pointer-events-auto flex h-[100dvh] max-h-[100dvh] min-h-0 w-full min-w-0 max-w-full resize-none flex-col overflow-hidden overscroll-contain pb-[env(safe-area-inset-bottom)]"
              : "pointer-events-auto flex max-h-[92vh] min-h-[280px] w-auto min-w-[480px] max-w-[96vw] resize flex-col overflow-hidden"
            : mobile
              ? // Parked off-screen on a phone: keep it viewport-sized so the
                // PTY dimensions survive minimize/restore (the desktop branch
                // gets that from the inline style, which mobile has none of).
                "flex h-[100dvh] w-screen flex-col"
              : "flex flex-col"
        }
        onClick={(e) => e.stopPropagation()}
      />
      {createPortal(
        <LaunchTerminal
          token={session.token}
          tool={session.tool}
          expanded={expanded && !docked}
          fill
          onAddToGrid={docked ? undefined : onRequestDock}
          onMinimize={onMinimize}
          onClose={onClose}
          onStatus={onStatus}
          onPolicyStop={onPolicyStop}
          onOpenFiles={onOpenFiles}
          onOpenGit={onOpenGit}
          onOpenSession={onOpenSession}
          registerPaste={boundRegisterPaste}
          projectPanelEnabled={projectPanelEnabled}
          sessionPanelEnabled={sessionPanelEnabled}
        />,
        hostEl,
      )}
    </div>
  );
}

// Dock renders a pill per minimized session bottom-right. The currently
// expanded session has no pill (it's on screen). Click a pill to restore;
// × stops & closes it.
function Dock({
  sessions,
  activeToken,
  statuses,
  policyStops,
  onRestore,
  onClose,
  onNew,
}: {
  sessions: DockSession[];
  activeToken: string | null;
  statuses: Record<string, Status>;
  policyStops: Record<string, PolicyStopInfo | undefined>;
  onRestore: (token: string) => void;
  onClose: (token: string) => void;
  onNew: () => void;
}) {
  const pills = sessions.filter((s) => s.token !== activeToken);
  const agentStatuses = useTerminalStatuses();
  const drag = useDockDrag();
  // A paired remote device can only fresh-launch when the owner enabled
  // [remote].allow_terminal; when it's off we keep the button visible but
  // disabled with a reason (honest-disabled-control convention), rather than
  // opening a dialog that can only fail.
  const { blocked: remoteBlocked } = useRemoteTerminalGate();
  return (
    <div
      ref={drag.ref}
      style={drag.style}
      className="fixed bottom-4 right-4 z-[70] flex flex-col-reverse items-end gap-2"
    >
      {/* When remoteBlocked the button is disabled and swallows pointer
          events, so hover would never fire — TooltipSpan wraps it in a
          hoverable span; the enabled button is its own reference. */}
      {(() => {
        const newBtn = (
          <button type="button" onClick={onNew} disabled={remoteBlocked} className="flex items-center gap-1.5 rounded-full border bg-bg-1 px-3 py-1.5 text-[11px] font-medium text-fg-2 shadow-lg hover:text-fg-1 focus:outline-none disabled:cursor-not-allowed disabled:opacity-50 disabled:hover:text-fg-2"><span aria-hidden className="text-[13px] leading-none">+</span>New terminal</button>
        );
        const tip = remoteBlocked ? REMOTE_TERMINAL_OFF_MSG : "Start a fresh agent in the embedded terminal";
        return remoteBlocked ? (
          <TooltipSpan content={tip}>{newBtn}</TooltipSpan>
        ) : (
          <Tooltip content={tip}>{newBtn}</Tooltip>
        );
      })()}
      {pills.map((s) => (
        <DockPill
          key={s.token}
          session={s}
          agent={agentStatuses[s.token]}
          status={statuses[s.token]}
          policyStop={policyStops[s.token]}
          onRestore={() => onRestore(s.token)}
          onClose={() => onClose(s.token)}
        />
      ))}
      {/* Drag grip (rendered last so flex-col-reverse floats it to the TOP of
          the dock). Dragging only the grip keeps the "New terminal" button a
          plain click target — no click-vs-drag ambiguity. Double-click resets. */}
      <Tooltip content="Drag to move · double-click to reset">
        <button
          type="button"
          aria-label="Drag to move the terminal dock (double-click to reset)"
          onPointerDown={drag.gripHandlers.onPointerDown}
          onPointerMove={drag.gripHandlers.onPointerMove}
          onPointerUp={drag.gripHandlers.onPointerUp}
          onPointerCancel={drag.gripHandlers.onPointerCancel}
          onLostPointerCapture={drag.gripHandlers.onLostPointerCapture}
          onDoubleClick={drag.onReset}
          className="flex h-4 w-9 touch-none cursor-grab select-none items-center justify-center rounded-full border bg-bg-1 text-fg-4 shadow-lg hover:text-fg-2 active:cursor-grabbing"
        >
        <svg width="14" height="6" viewBox="0 0 14 6" fill="none" aria-hidden>
          <circle cx="2" cy="2" r="1" fill="currentColor" />
          <circle cx="7" cy="2" r="1" fill="currentColor" />
          <circle cx="12" cy="2" r="1" fill="currentColor" />
          <circle cx="2" cy="5" r="1" fill="currentColor" />
          <circle cx="7" cy="5" r="1" fill="currentColor" />
          <circle cx="12" cy="5" r="1" fill="currentColor" />
        </svg>
        </button>
      </Tooltip>
    </div>
  );
}

// Dock position persistence (usability follow-up): drag the grip to move the
// whole dock so it stops covering content bottom-right. The offset is stored in
// localStorage and clamped to the viewport (so a resize can't strand it).
const DOCK_POS_KEY = "sb_dock_pos";

// Floating terminal-window size (px), user-resizable + persisted. One shared
// size: every floating terminal opens at the last size the user chose.
const FLOAT_SIZE_KEY = "sb_terminal_float_size";

function loadFloatSize(): { w: number; h: number } {
  try {
    const raw = localStorage.getItem(FLOAT_SIZE_KEY);
    if (raw) {
      const p = JSON.parse(raw);
      if (typeof p?.w === "number" && typeof p?.h === "number" && p.w >= 320 && p.h >= 200) {
        return { w: p.w, h: p.h };
      }
    }
  } catch {
    /* malformed — fall through to the default */
  }
  return { w: 880, h: Math.max(360, Math.round(window.innerHeight * 0.6)) };
}

function useDockDrag() {
  const ref = useRef<HTMLDivElement | null>(null);
  const [pos, setPos] = useState<{ dx: number; dy: number }>(() => {
    try {
      const raw = localStorage.getItem(DOCK_POS_KEY);
      if (raw) {
        const p = JSON.parse(raw);
        if (typeof p?.dx === "number" && typeof p?.dy === "number") return p;
      }
    } catch {
      /* ignore malformed */
    }
    return { dx: 0, dy: 0 };
  });
  // usePointerDrag reports the cumulative delta from pointer-down, not an
  // absolute position — capture the pre-drag offset on gesture-start so
  // onMove can apply the delta on top of it.
  const base = useRef<{ dx: number; dy: number }>({ dx: 0, dy: 0 });

  // Clamp an offset so the dock stays fully on-screen. The element's current
  // rect already includes the current transform, so subtract the applied
  // offset to recover the un-transformed anchor, then bound the proposed one.
  const clamp = useCallback(
    (dx: number, dy: number) => {
      const el = ref.current;
      if (!el) return { dx, dy };
      const r = el.getBoundingClientRect();
      const m = 8;
      const baseLeft = r.left - pos.dx;
      const baseTop = r.top - pos.dy;
      const minDx = m - baseLeft;
      const maxDx = window.innerWidth - m - (baseLeft + r.width);
      const minDy = m - baseTop;
      const maxDy = window.innerHeight - m - (baseTop + r.height);
      return {
        dx: Math.min(Math.max(dx, minDx), Math.max(minDx, maxDx)),
        dy: Math.min(Math.max(dy, minDy), Math.max(minDy, maxDy)),
      };
    },
    [pos.dx, pos.dy],
  );

  // Pointer hygiene (primary-button-only, pointer-ID-pinned, single
  // finalizer on up/cancel/lost-capture) now lives in usePointerDrag; this
  // hook only owns the offset model, clamp policy, and localStorage persist.
  const gripHandlers = usePointerDrag({
    onStart: () => {
      base.current = pos;
    },
    onMove: (delta) => {
      setPos(clamp(base.current.dx + delta.dx, base.current.dy + delta.dy));
    },
    onEnd: () => {
      setPos((p) => {
        try {
          localStorage.setItem(DOCK_POS_KEY, JSON.stringify(p));
        } catch {
          /* storage full/blocked — position still applies for the session */
        }
        return p;
      });
    },
  });

  const onReset = useCallback(() => {
    setPos({ dx: 0, dy: 0 });
    try {
      localStorage.removeItem(DOCK_POS_KEY);
    } catch {
      /* ignore */
    }
  }, []);

  // Re-clamp on resize so a shrunk window can't strand the dock off-screen.
  useEffect(() => {
    const onResize = () => setPos((p) => clamp(p.dx, p.dy));
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, [clamp]);

  return {
    ref,
    style: { transform: `translate(${pos.dx}px, ${pos.dy}px)` },
    gripHandlers,
    onReset,
  };
}

function DockPill({
  session,
  status,
  agent,
  policyStop,
  onRestore,
  onClose,
}: {
  session: DockSession;
  status: Status | undefined;
  agent?: import("@/components/useTerminalStatuses").AgentStatusInfo;
  policyStop?: PolicyStopInfo;
  onRestore: () => void;
  onClose: () => void;
}) {
  const dot: Record<Status, string> = {
    connecting: "bg-fg-3 animate-pulse",
    open: "bg-ok",
    // Live server-side; only this browser's transport dropped.
    reconnecting: "bg-warn animate-pulse",
    exited: "bg-fg-3",
    error: "bg-danger",
  };
  const label: Record<Status, string> = {
    connecting: "connecting…",
    open: "live",
    reconnecting: "reconnecting…",
    exited: "exited",
    error: "error",
  };
  const st = status ?? "connecting";
  // A policy-stopped run is exited FOR A REASON worth calling out — tint the
  // dot/label danger|warn (matching the modal banner's own decision-aware
  // color) instead of the default neutral "exited" grey, and surface the
  // same message as a tooltip + native title (the label loses its own hover
  // in favour of the wrapping Tooltip below, so both carry it).
  const policyStopped = st === "exited" && !!policyStop;
  const policyStoppedDefinitive =
    policyStopped &&
    (policyStop!.decision === "terminated" || policyStop!.decision === "killed");
  const dotCls = policyStopped
    ? policyStoppedDefinitive
      ? "bg-danger"
      : "bg-warn"
    : dot[st];
  const labelCls = policyStopped
    ? policyStoppedDefinitive
      ? "text-danger"
      : "text-warn"
    : "text-fg-3";
  const restoreTip = policyStop
    ? policyStopMessage(policyStop)
    : `Restore ${session.tool} terminal`;
  return (
    <div className="flex items-center gap-2 rounded-full border bg-bg-1 py-1 pl-3 pr-1.5 shadow-lg">
      <Tooltip content={restoreTip}>
        <button
          type="button"
          onClick={onRestore}
          aria-label={`Restore ${session.tool} terminal`}
          title={policyStop ? policyStopMessage(policyStop) : undefined}
          className="flex items-center gap-2 text-[11px] text-fg-2 hover:text-fg-1 focus:outline-none"
        >
          <span className={`h-2 w-2 rounded-full ${dotCls}`} />
          <span className="font-mono text-fg-1">{session.tool}</span>
          <AgentStatusBadge info={agent} />
          <span
            className={`text-[9.5px] uppercase tracking-[0.05em] ${labelCls}`}
          >
            {label[st]}
          </span>
          <span aria-hidden className="text-fg-3">
            ▴
          </span>
        </button>
      </Tooltip>
      <Tooltip
        content={
          st === "open" ? "Stop the running process and close" : "Close"
        }
      >
        <button
          type="button"
          onClick={() => {
            // Closing kills the process — confirm while it's still live, same
            // as the terminal header's "Stop & close".
            if (
              (st === "open" || st === "connecting") &&
              !window.confirm(
                `Stop the running ${session.tool} session? This ends the process.`,
              )
            ) {
              return;
            }
            onClose();
          }}
          aria-label={
            st === "open" ? "Stop the running process and close" : "Close"
          }
          className="rounded-full px-1.5 text-[11px] text-fg-3 hover:bg-white/10 hover:text-fg-1 focus:outline-none"
        >
          ✕
        </button>
      </Tooltip>
    </div>
  );
}
