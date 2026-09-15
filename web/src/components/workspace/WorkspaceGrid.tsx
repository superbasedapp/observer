import { Suspense, lazy, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useLaunchDock } from "@/components/LaunchDock";
import { isRemoteView } from "@/lib/remote";
import { isLiveStatus, type Status } from "@/components/LaunchTerminal";
import { fmtShortId } from "@/lib/format";

// WorkspaceGrid — the Terminal Workspace dock grid (docs/plans/
// terminal-dock-grid-design-2026-07-20.md, P0; operator decisions 2026-07-21:
// max 9 concurrent, server-side layout persistence, auto-compacting grid with
// drag-to-move/reorder + drag-to-resize).
//
// Ownership discipline (design D2): the LaunchDockProvider remains the SOLE
// owner of every mounted terminal. This grid only registers a CELL ELEMENT
// per docked token (registerWorkspaceCell); the provider imperatively moves
// each session's stable host element into its cell — the grid is a VIEW.
// Removing a tile from the grid therefore never touches the PTY: the session
// falls back to the floating pill tray (design D3's honest dock ≠ session
// distinction); "Stop & close" is the only destructive control and confirms.
//
// react-grid-layout is loaded lazily (vendor-grid chunk) so non-terminal
// users never pay for it — same discipline as vendor-xterm.

const LazyGrid = lazy(() => import("./WorkspaceGridInner"));

export type WorkspaceLayoutItem = { i: string; x: number; y: number; w: number; h: number };
export type WorkspaceLayouts = Record<string, WorkspaceLayoutItem[]>;

/** The server-persisted blob (migration 073; presentation state only). */
type PersistedLayout = {
  v: number;
  docked: string[];
  layouts: WorkspaceLayouts;
};

export function WorkspaceGrid({
  policyHint,
  onOpenSettings,
}: {
  /** Honest first-run hint when fresh launch is policy-blocked ("" = ok). */
  policyHint: string;
  onOpenSettings: () => void;
}) {
  const dock = useLaunchDock();
  const [docked, setDocked] = useState<string[]>([]);
  const [layouts, setLayouts] = useState<WorkspaceLayouts>({});
  const [loaded, setLoaded] = useState(false);
  const saveTimer = useRef<number | null>(null);
  const saveWarned = useRef(false);
  // The latest not-yet-saved blob, so an unmount FLUSHES the pending save
  // instead of discarding it (review MED: navigating away within the debounce
  // window must not lose the arrangement).
  const pendingBlob = useRef<PersistedLayout | null>(null);
  // A paired remote device gets a READ-ONLY shared grid: no drag/resize, no
  // add/remove/stop controls, no save attempts (the save route is owner-local
  // — skipping avoids a guaranteed 403 per arrangement).
  const readOnly = isRemoteView();

  // Load the server-side layout once. null / fetch failure → empty grid.
  useEffect(() => {
    let cancelled = false;
    fetch("/api/terminal/workspace-layout")
      .then((r) => (r.ok ? r.json() : null))
      .then((data: { layout: PersistedLayout | null } | null) => {
        if (cancelled) return;
        const l = data?.layout;
        if (l && Array.isArray(l.docked)) {
          setDocked(l.docked.filter((t) => typeof t === "string"));
          setLayouts(l.layouts && typeof l.layouts === "object" ? l.layouts : {});
        }
      })
      .catch(() => {
        /* no layout yet / view-only remote — start empty */
      })
      .finally(() => {
        if (!cancelled) setLoaded(true);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // Debounced server save. Never fires before the initial load (would clobber
  // a real layout with the empty boot state). A save failure (e.g. a remote
  // View-only device — the save route is owner-local) degrades to in-memory
  // with one console warning, never a broken grid.
  const scheduleSave = useCallback(
    (nextDocked: string[], nextLayouts: WorkspaceLayouts) => {
      if (!loaded || readOnly) return;
      pendingBlob.current = { v: 1, docked: nextDocked, layouts: nextLayouts };
      if (saveTimer.current) window.clearTimeout(saveTimer.current);
      saveTimer.current = window.setTimeout(() => {
        pendingBlob.current = null;
        const blob: PersistedLayout = { v: 1, docked: nextDocked, layouts: nextLayouts };
        fetch("/api/terminal/workspace-layout/save", {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(blob),
        })
          .then((r) => {
            if (!r.ok && !saveWarned.current) {
              saveWarned.current = true;
              console.warn(
                `workspace layout not saved (HTTP ${r.status}) - arranging still works for this tab; saving needs the owner's local dashboard`,
              );
            }
          })
          .catch(() => {
            /* offline — in-memory layout still applies */
          });
      }, 1200);
    },
    [loaded, readOnly],
  );
  // Unmount: FLUSH a pending save (fire-and-forget; fetch survives unmount)
  // rather than dropping it.
  useEffect(
    () => () => {
      if (saveTimer.current) window.clearTimeout(saveTimer.current);
      const blob = pendingBlob.current;
      if (blob) {
        pendingBlob.current = null;
        fetch("/api/terminal/workspace-layout/save", {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(blob),
          keepalive: true,
        }).catch(() => {
          /* best-effort flush */
        });
      }
    },
    [],
  );

  const addToGrid = useCallback(
    (token: string) => {
      setDocked((prev) => {
        if (prev.includes(token)) return prev;
        const next = [...prev, token];
        setLayouts((cur) => {
          const withItem = { ...cur };
          for (const bp of Object.keys(withItem)) {
            if (!withItem[bp].some((it) => it.i === token)) {
              withItem[bp] = [
                ...withItem[bp],
                { i: token, x: (prev.length % 2) * 6, y: Number.MAX_SAFE_INTEGER, w: 6, h: 10 },
              ];
            }
          }
          scheduleSave(next, withItem);
          return withItem;
        });
        return next;
      });
    },
    [scheduleSave],
  );

  const removeFromGrid = useCallback(
    (token: string) => {
      setDocked((prev) => {
        const next = prev.filter((t) => t !== token);
        setLayouts((cur) => {
          const pruned: WorkspaceLayouts = {};
          for (const bp of Object.keys(cur)) pruned[bp] = cur[bp].filter((it) => it.i !== token);
          scheduleSave(next, pruned);
          return pruned;
        });
        return next;
      });
    },
    [scheduleSave],
  );

  const stopAndClose = useCallback(
    (token: string, tool: string, live: boolean) => {
      if (live && !window.confirm(`Stop the running ${tool} session? This ends the process.`)) {
        return;
      }
      dock.closeSession(token);
      removeFromGrid(token);
    },
    [dock, removeFromGrid],
  );

  // Dock sink: while this workspace is mounted, "Add to grid" on a floating
  // terminal window docks instantly; tokens queued while unmounted (the
  // provider navigated here) are consumed once on arrival. Explicit gestures
  // only — nothing auto-docks.
  // BOTH gated on `loaded` (review HIGH): docking into the pre-hydration
  // empty state would be wiped when the GET response replaces `docked`
  // (and the save is refused pre-load) — the tile would silently vanish.
  useEffect(() => {
    if (readOnly || !loaded) return;
    dock.registerDockSink(addToGrid);
    return () => dock.registerDockSink(null);
  }, [readOnly, loaded, dock.registerDockSink, addToGrid, dock]);
  useEffect(() => {
    if (readOnly || !loaded || dock.pendingDock.length === 0) return;
    for (const t of dock.pendingDock) addToGrid(t);
    dock.clearPendingDock();
  }, [readOnly, loaded, dock.pendingDock, addToGrid, dock]);

  const onLayoutsChange = useCallback(
    (all: WorkspaceLayouts) => {
      setLayouts(all);
      scheduleSave(docked, all);
    },
    [docked, scheduleSave],
  );

  const byToken = useMemo(() => {
    const m: Record<
      string,
      { tool: string; sessionId: string; hasProjectRoot: boolean }
    > = {};
    for (const s of dock.sessions)
      m[s.token] = {
        tool: s.tool,
        sessionId: s.sessionId,
        hasProjectRoot: s.hasProjectRoot ?? false,
      };
    return m;
  }, [dock.sessions]);

  const traySessions = dock.sessions.filter((s) => !docked.includes(s.token));
  const dockedLive = docked.filter((t) => byToken[t]);
  const dockedDead = docked.filter((t) => !byToken[t]);

  return (
    <div className="space-y-3">
      {/* Toolbar: new terminal + the undocked-session tray. */}
      <div className="flex flex-wrap items-center gap-2">
        {!readOnly && (
          <button
            type="button"
            onClick={dock.openNewTerminal}
            className="rounded-2 border border-accent/50 bg-accent/15 px-3 py-1 text-[12px] text-accent hover:bg-accent/25"
          >
            + New terminal
          </button>
        )}
        {readOnly && (
          <span className="text-[11px] text-fg-3">
            Read-only shared view - arrange the grid from the owner&apos;s dashboard.
          </span>
        )}
        {traySessions.length > 0 && (
          <span className="text-[11px] text-fg-3">Not on the grid:</span>
        )}
        {!readOnly &&
          traySessions.map((s) => (
          <button
            key={s.token}
            type="button"
            onClick={() => addToGrid(s.token)}
            title="Add this running terminal to the grid"
            className="flex items-center gap-1.5 rounded-full border border-line-2 bg-bg-1 px-2.5 py-1 text-[11px] text-fg-2 hover:text-fg-1"
          >
            <StatusDot status={dock.statuses[s.token]} />
            <span className="font-mono">{s.tool}</span>
              <span aria-hidden>＋</span>
            </button>
          ))}
        <span className="ml-auto text-[11px] text-fg-3">
          {dockedLive.length}/{docked.length || 0} tiles · drag headers to arrange · drag edges to resize
        </span>
      </div>

      {docked.length === 0 ? (
        <div className="flex min-h-[280px] flex-col items-center justify-center gap-3 rounded-2 border border-dashed border-line-2 bg-bg-1 p-8 text-center">
          <div className="text-[13px] font-medium text-fg-2">No terminals on the grid yet.</div>
          <div className="max-w-[460px] text-[12px] text-fg-3">
            Launch a fresh agent with “+ New terminal”, or add a running session from the tray above. Tiles
            drag by their header, resize from their edges, and auto-compact upward.
          </div>
          {policyHint && (
            <button
              type="button"
              onClick={onOpenSettings}
              className="text-[11px] text-warn underline decoration-dotted underline-offset-2"
            >
              {policyHint}
            </button>
          )}
        </div>
      ) : (
        <Suspense
          fallback={<div className="p-6 text-[12px] text-fg-3">Loading workspace grid…</div>}
        >
          <LazyGrid
            docked={docked}
            layouts={layouts}
            onLayoutsChange={onLayoutsChange}
            readOnly={readOnly}
            renderTile={(token) => {
              const meta = byToken[token];
              if (!meta) {
                return (
                  <TombstoneTile
                    key={token}
                    token={token}
                    // Pending (not dead) while the dock is still rehydrating
                    // OR while this token is reconnecting: a dropped transport
                    // is not an ended session, and reading "Session ended" for
                    // one is the exact mis-report this arc fixes.
                    pending={
                      !dock.sessionsHydrated ||
                      dock.statuses[token] === "reconnecting"
                    }
                    readOnly={readOnly}
                    onRemove={() => removeFromGrid(token)}
                  />
                );
              }
              return (
                <TerminalTile
                  key={token}
                  token={token}
                  tool={meta.tool}
                  hasProjectRoot={meta.hasProjectRoot}
                  status={dock.statuses[token]}
                  readOnly={readOnly}
                  onOpenWindow={() => {
                    removeFromGrid(token);
                    dock.restore(token);
                  }}
                  onUndock={() => removeFromGrid(token)}
                  onClose={() =>
                    stopAndClose(
                      token,
                      meta.tool,
                      dock.statuses[token] === "open" || dock.statuses[token] === "connecting",
                    )
                  }
                />
              );
            }}
          />
        </Suspense>
      )}
      {dockedDead.length > 0 && dock.sessionsHydrated && (
        <div className="text-[11px] text-fg-3">
          {dockedDead.length} saved tile(s) reference sessions that are no longer running (the daemon
          restarted or they exited) - remove them or relaunch.
        </div>
      )}
    </div>
  );
}

function StatusDot({ status }: { status: Status | undefined }) {
  const cls: Record<Status, string> = {
    connecting: "bg-fg-3 animate-pulse",
    open: "bg-ok",
    // Still live server-side — only this browser's transport dropped.
    reconnecting: "bg-warn animate-pulse",
    exited: "bg-fg-3",
    error: "bg-danger",
  };
  return <span className={`h-2 w-2 rounded-full ${cls[status ?? "connecting"]}`} />;
}

// TerminalTile: the grid cell chrome. The header (.ws-tile-drag) is the ONLY
// drag handle — the xterm body must never initiate a drag (keystrokes belong
// to the TUI). The body div is the registered docking cell the provider moves
// the session's stable host element into.
function TerminalTile({
  token,
  tool,
  hasProjectRoot,
  status,
  readOnly,
  onOpenWindow,
  onUndock,
  onClose,
}: {
  token: string;
  tool: string;
  hasProjectRoot: boolean;
  status: Status | undefined;
  readOnly: boolean;
  onOpenWindow: () => void;
  onUndock: () => void;
  onClose: () => void;
}) {
  const { registerWorkspaceCell, openProjectPanel } = useLaunchDock();
  const cellRef = useCallback(
    (el: HTMLDivElement | null) => registerWorkspaceCell(token, el),
    [token, registerWorkspaceCell],
  );
  const label: Record<Status, string> = {
    connecting: "connecting…",
    open: "live",
    reconnecting: "reconnecting…",
    exited: "exited",
    error: "error",
  };
  return (
    <div className="flex h-full min-h-0 flex-col overflow-hidden rounded-2 border border-line-2 bg-bg-1">
      <div className="flex items-center gap-2 border-b border-line-2 bg-bg-2 px-2 py-1">
        <span className="ws-tile-drag flex flex-1 cursor-grab items-center gap-2 active:cursor-grabbing">
          <StatusDot status={status} />
          <span className="font-mono text-[11px] text-fg-1">{tool}</span>
          <span className="text-[9.5px] uppercase tracking-[0.05em] text-fg-3">
            {label[status ?? "connecting"]}
          </span>
        </span>
        {/* Read-only project panel (file tree + git). Shown regardless of the
            grid's read-only mode — the remote gate is enforced server-side and
            the panel surfaces that honestly. Enabled for any run with a local
            directory (allow-listed project root, else the terminal's working
            directory); disabled with an honest title only when there is nothing
            local to browse, e.g. an SSH terminal. */}
        <button
          type="button"
          disabled={!hasProjectRoot || !isLiveStatus(status)}
          onClick={() => openProjectPanel(token, "files")}
          onMouseDown={(e) => e.stopPropagation()}
          onTouchStart={(e) => e.stopPropagation()}
          title={
            !isLiveStatus(status)
              ? "This session is no longer running - its project can no longer be browsed"
              : hasProjectRoot
                ? "Browse this terminal's files"
                : "This terminal has no directory on this machine to browse"
          }
          className="rounded px-1.5 text-[12px] leading-none text-fg-3 hover:bg-white/10 hover:text-fg-1 disabled:cursor-not-allowed disabled:opacity-50 disabled:hover:bg-transparent disabled:hover:text-fg-3"
        >
          ▤
        </button>
        <button
          type="button"
          disabled={!hasProjectRoot || !isLiveStatus(status)}
          onClick={() => openProjectPanel(token, "git")}
          onMouseDown={(e) => e.stopPropagation()}
          onTouchStart={(e) => e.stopPropagation()}
          title={
            !isLiveStatus(status)
              ? "This session is no longer running - its project can no longer be browsed"
              : hasProjectRoot
                ? "Show git status, changes, and history for this terminal's directory"
                : "This terminal has no directory on this machine to browse"
          }
          className="rounded px-1.5 text-[12px] leading-none text-fg-3 hover:bg-white/10 hover:text-fg-1 disabled:cursor-not-allowed disabled:opacity-50 disabled:hover:bg-transparent disabled:hover:text-fg-3"
        >
          ⎇
        </button>
        {!readOnly && (
          <>
        <button
          type="button"
          onClick={onOpenWindow}
          onMouseDown={(e) => e.stopPropagation()}
          onTouchStart={(e) => e.stopPropagation()}
          title="Open as window - undock into the resizable floating panel. The session keeps running."
          className="rounded px-1.5 text-[12px] leading-none text-fg-3 hover:bg-white/10 hover:text-fg-1"
        >
          ⬈
        </button>
        <button
          type="button"
          onClick={onUndock}
          onMouseDown={(e) => e.stopPropagation()}
          onTouchStart={(e) => e.stopPropagation()}
          title="Remove from grid - the session keeps running; find it in the tray."
          className="rounded px-1.5 text-[12px] leading-none text-fg-3 hover:bg-white/10 hover:text-fg-1"
        >
          ▭
        </button>
        <button
          type="button"
          onClick={onClose}
          onMouseDown={(e) => e.stopPropagation()}
          onTouchStart={(e) => e.stopPropagation()}
          title="Stop & close - ends the process."
          className="rounded px-1.5 text-[12px] leading-none text-fg-3 hover:bg-white/10 hover:text-danger"
        >
          ✕
        </button>
          </>
        )}
      </div>
      <div ref={cellRef} className="flex min-h-0 flex-1 flex-col" />
    </div>
  );
}

// TombstoneTile: a saved cell whose session is gone (daemon restart / exit) —
// honest dead-state with a remove affordance. While the provider is still
// rehydrating (no sessions known yet), or the token is reconnecting, it reads
// as pending instead of dead.
function TombstoneTile({
  token,
  pending,
  readOnly,
  onRemove,
}: {
  token: string;
  pending: boolean;
  readOnly: boolean;
  onRemove: () => void;
}) {
  return (
    <div className="flex h-full min-h-0 flex-col items-center justify-center gap-2 rounded-2 border border-dashed border-line-2 bg-bg-1 p-4 text-center">
      <div className="text-[12px] text-fg-3">
        {pending ? "Reconnecting…" : "Session ended or is no longer running."}
      </div>
      <div className="font-mono text-[10px] text-fg-4" title={token}>{fmtShortId(token, 12)}</div>
      {!pending && !readOnly && (
        <button
          type="button"
          onClick={onRemove}
          className="rounded-2 border border-line-2 bg-bg-2 px-2 py-1 text-[11px] text-fg-3 hover:bg-bg-3"
        >
          Remove tile
        </button>
      )}
    </div>
  );
}
