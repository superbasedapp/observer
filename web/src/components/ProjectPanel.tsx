import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { KeyboardEvent as ReactKeyboardEvent } from "react";
import { FloatingPanel } from "@/components/primitives/FloatingPanel";
import { ContextMenu, type ContextMenuItem } from "@/components/primitives/ContextMenu";
import { SegmentedControl } from "@/components/primitives/SegmentedControl";
import { TruncatedPath } from "@/components/primitives/TruncatedPath";
import { CloudDigestCard } from "@/components/CloudDigestCard";
import { fmtBytes } from "@/lib/format";
import {
  computeLaneGraph,
  fetchProjectFile,
  fetchProjectFiles,
  fetchProjectGit,
  fetchProjectMeta,
  ProjectPanelError,
  sanitizePastePath,
  toAbsolutePath,
  type DirEntry,
  type FileResp,
  type FilesResp,
  type GitCommit,
  type GitFileStatus,
  type GitInfo,
  type GraphRow,
  type LaneGraph,
  type ProjectMeta,
  type ProjectPanelErrorCode,
} from "@/lib/projectPanel";

// STORAGE KEY (shared): one persisted default rect across all project panels —
// tokens are ephemeral, so per-token rects would only accumulate garbage. The
// provider cascades additional panels +24px in memory.
const PANEL_RECT_KEY = "sb_project_panel_rect";

// copyToClipboard writes text to the system clipboard, falling back to a hidden
// <textarea> + execCommand("copy") on non-secure-context origins where
// navigator.clipboard is unavailable.
async function copyToClipboard(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    /* fall through to the legacy path */
  }
  try {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.top = "-1000px";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(ta);
    return ok;
  } catch {
    return false;
  }
}

// A right-click / "⋯" request from a tree row, file-viewer header, or git-change
// row: the root-relative path plus the client anchor point for the menu.
export type RowMenuRequest = { rel: string; x: number; y: number };

// rowMenuKeyDown makes a path-bearing row respond to the keyboard menu keys
// (P3-8): ContextMenu and Shift+F10 open the same copy/paste menu a right-click
// or "⋯" click opens, anchored at the row's lower-left corner — so the affordance
// is reachable without a pointer (it pairs with group-focus-within revealing the
// "⋯" handle when the row's button is focused).
function rowMenuKeyDown(
  rel: string,
  onRowMenu: (rel: string, x: number, y: number) => void,
) {
  return (e: ReactKeyboardEvent) => {
    if (e.key === "ContextMenu" || (e.shiftKey && e.key === "F10")) {
      e.preventDefault();
      const r = (e.currentTarget as HTMLElement).getBoundingClientRect();
      onRowMenu(rel, r.left + 8, r.bottom);
    }
  };
}

// Row-menu plumbing threaded through the Files/Git subtrees so every path-
// bearing row can raise the context menu and flash "Copied".
type RowMenuProps = {
  onRowMenu: (rel: string, x: number, y: number) => void;
  copiedRel: string | null;
};

// RowMenuHandle renders the always-available right-click surface + a hover "⋯"
// affordance (touch/discoverability) for one path-bearing row. It is a SIBLING
// overlay — never nested inside the row's own <button> (invalid) — positioned
// by its parent's `relative`. Also shows the transient "Copied" flash.
function RowMenuHandle({
  rel,
  onRowMenu,
  copied,
}: {
  rel: string;
  onRowMenu: (rel: string, x: number, y: number) => void;
  copied: boolean;
}) {
  return (
    <span className="pointer-events-none absolute inset-y-0 right-1 flex items-center">
      {copied && (
        <span className="pointer-events-none mr-1 rounded-1 bg-ok/20 px-1 py-[1px] text-[9.5px] font-medium text-ok">
          Copied
        </span>
      )}
      <button
        type="button"
        aria-label="Path actions"
        title="Copy or paste this path"
        onClick={(e) => {
          e.stopPropagation();
          const r = e.currentTarget.getBoundingClientRect();
          onRowMenu(rel, r.right, r.bottom);
        }}
        className="pointer-events-auto hidden h-4 w-4 place-items-center rounded-1 bg-bg-1/80 text-fg-3 hover:bg-bg-3 hover:text-fg-0 group-hover:grid group-focus-within:grid"
      >
        ⋯
      </button>
    </span>
  );
}

// ProjectPanel — the per-terminal Git tree + read-only File Explorer drawer.
// Rendered ONCE at LaunchDockProvider level and React.lazy-loaded so it stays
// out of the critical chunk. Every fetch is token-scoped (the server resolves
// the canonical project root); nothing here sends a filesystem path down.
//
// SECURITY: file contents are rendered strictly as TEXT NODES (line-numbered
// <pre>), never via dangerouslySetInnerHTML — the viewer cannot execute markup
// coming from a repository file.

export type ProjectPanelTab = "files" | "git";

/**
 * Tooltip for the "working directory" label. Shown when the panel is browsing
 * the directory the agent actually runs in rather than an allow-listed project
 * root, so the header never implies a project that was never chosen.
 */
const WORKING_DIR_HINT =
  "This terminal was launched without a project root, so these are the files in its working directory.";

const NO_ROOT_MSG =
  "This terminal has no browsable directory on this machine. An SSH terminal's files live on the remote host";

/** Friendly copy for each wire error code. */
function errorCopy(code: ProjectPanelErrorCode): { title: string; detail: string } {
  switch (code) {
    case "unknown_token":
      return {
        title: "Session not found",
        detail: "This terminal is no longer running, so its project can't be browsed.",
      };
    case "no_project_root":
      return { title: "Nothing to browse", detail: NO_ROOT_MSG + "." };
    case "remote_view_disabled":
      return {
        title: "Viewing disabled",
        detail: "The owner hasn't enabled remote terminal/file viewing for this device.",
      };
    case "git_unavailable":
      return {
        title: "Git unavailable",
        detail: "The git binary isn't available on the host serving this terminal.",
      };
    case "bad_path":
      return { title: "Invalid path", detail: "That path is outside the project root." };
    case "not_found":
      return { title: "Not found", detail: "That file or directory no longer exists." };
    default:
      return { title: "Request failed", detail: "Could not reach the daemon. Try again." };
  }
}

function ErrorState({ code }: { code: ProjectPanelErrorCode }) {
  const { title, detail } = errorCopy(code);
  return (
    <div className="flex h-full flex-col items-center justify-center gap-1 p-8 text-center">
      <div className="text-[13px] font-medium text-fg-1">{title}</div>
      <div className="max-w-[380px] text-[12px] text-fg-3">{detail}</div>
    </div>
  );
}

function codeOf(err: unknown): ProjectPanelErrorCode {
  return err instanceof ProjectPanelError ? err.code : "request_failed";
}

/** Relative "3h ago" style label from an RFC3339 timestamp. */
function relTime(iso: string): string {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "";
  const secs = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (secs < 60) return "just now";
  const mins = Math.round(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.round(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.round(hrs / 24);
  if (days < 30) return `${days}d ago`;
  const mos = Math.round(days / 30);
  if (mos < 12) return `${mos}mo ago`;
  return `${Math.round(mos / 12)}y ago`;
}

const RefreshButton = ({ onClick, busy }: { onClick: () => void; busy: boolean }) => (
  <button
    type="button"
    onClick={onClick}
    disabled={busy}
    title="Refresh"
    className="grid h-6 w-6 shrink-0 place-items-center rounded-2 border border-line-2 bg-bg-2 text-[12px] text-fg-2 hover:bg-bg-3 hover:text-fg-0 disabled:opacity-50"
  >
    <span className={busy ? "inline-block animate-spin" : ""} aria-hidden>
      ↻
    </span>
  </button>
);

export default function ProjectPanel({
  token,
  tool,
  tab,
  z,
  cascade,
  pasteToTerminal,
  onRaise,
  onTabChange,
  onClose,
}: {
  token: string;
  tool: string;
  tab: ProjectPanelTab;
  /** Provider-owned stacking order (band above the expanded-terminal backdrop). */
  z: number;
  /** In-memory cascade slot for the shared default rect (+24px per panel). */
  cascade: number;
  /**
   * Paste-into-terminal channel for THIS token when a live, write-capable seat
   * is on-screen — absent for read-only remote viewers. Its presence gates the
   * paste items. Routes through xterm's paste pipeline (like a manual Ctrl+V).
   */
  pasteToTerminal?: (text: string) => void;
  /** Raise this panel above siblings on pointer-down. */
  onRaise: () => void;
  onTabChange: (t: ProjectPanelTab) => void;
  onClose: () => void;
}) {
  const [meta, setMeta] = useState<ProjectMeta | null>(null);
  const [metaErr, setMetaErr] = useState<ProjectPanelErrorCode | null>(null);
  // When a git status row is clicked we jump to the Files tab and open it.
  const [openPath, setOpenPath] = useState<{ path: string; nonce: number } | null>(null);
  // Cursor-anchored context menu request + the row currently flashing "Copied".
  const [menu, setMenu] = useState<RowMenuRequest | null>(null);
  const [copiedRel, setCopiedRel] = useState<string | null>(null);
  const copyTimer = useRef<number | null>(null);
  // The served root is this terminal's own working directory, not an
  // operator-allow-listed project root. An older daemon omits root_kind
  // entirely; absence means "project_root", the only kind it could serve.
  const isWorkingDir = meta?.root_kind === "working_dir";

  useEffect(() => {
    let cancelled = false;
    setMeta(null);
    setMetaErr(null);
    fetchProjectMeta(token)
      .then((m) => {
        if (!cancelled) setMeta(m);
      })
      .catch((e) => {
        if (!cancelled) setMetaErr(codeOf(e));
      });
    return () => {
      cancelled = true;
    };
  }, [token]);

  useEffect(
    () => () => {
      if (copyTimer.current) window.clearTimeout(copyTimer.current);
    },
    [],
  );

  const openInFiles = useCallback(
    (path: string) => {
      setOpenPath({ path, nonce: Date.now() });
      onTabChange("files");
    },
    [onTabChange],
  );

  const openRowMenu = useCallback((rel: string, x: number, y: number) => {
    setMenu({ rel, x, y });
  }, []);

  const flashCopied = useCallback((rel: string) => {
    setCopiedRel(rel);
    if (copyTimer.current) window.clearTimeout(copyTimer.current);
    copyTimer.current = window.setTimeout(() => setCopiedRel(null), 1200);
  }, []);

  // Build the menu items for a given relative path. "Copy path" (absolute) needs
  // the resolved root; the paste items appear ONLY when a live writer seat is
  // registered for this token (structurally read-only-safe).
  const menuItems = useCallback(
    (rel: string): ContextMenuItem[] => {
      const root = meta?.root ?? "";
      const abs = root ? toAbsolutePath(root, rel) : rel;
      const items: ContextMenuItem[] = [
        {
          key: "copy-rel",
          label: "Copy relative path",
          onSelect: () => {
            // Flash "Copied" ONLY on a real success (P3-7): copyToClipboard
            // resolves false on a blocked clipboard + failed execCommand
            // fallback, and flashing then would be dishonest.
            void copyToClipboard(rel).then((ok) => {
              if (ok) flashCopied(rel);
            });
          },
        },
        {
          key: "copy-abs",
          label: "Copy path",
          disabled: !root,
          onSelect: () => {
            void copyToClipboard(abs).then((ok) => {
              if (ok) flashCopied(rel);
            });
          },
        },
      ];
      if (pasteToTerminal) {
        items.push(
          {
            key: "paste-rel",
            label: "Paste relative path into terminal",
            onSelect: () => pasteToTerminal(sanitizePastePath(rel)),
          },
          {
            key: "paste-abs",
            label: "Paste path into terminal",
            disabled: !root,
            onSelect: () => pasteToTerminal(sanitizePastePath(abs)),
          },
        );
      }
      return items;
    },
    [meta?.root, pasteToTerminal, flashCopied],
  );

  return (
    <FloatingPanel
      storageKey={PANEL_RECT_KEY}
      z={z}
      cascade={cascade}
      onRaise={onRaise}
      onClose={onClose}
      ariaLabel={isWorkingDir ? `${tool} working directory files` : `${tool} project files`}
      title={
        <span className="flex items-center gap-2">
          <span className="font-mono text-fg-0">{tool}</span>
          <span className="text-fg-3">· {isWorkingDir ? "working dir" : "project"}</span>
        </span>
      }
      subtitle={meta ? <span className="font-mono">{lastSegment(meta.root)}</span> : "resolving…"}
    >
      <div className="flex h-full min-h-0 flex-col">
        <div className="flex items-center gap-2 border-b border-line-1 px-4 py-2">
          <SegmentedControl<ProjectPanelTab>
            options={[
              { value: "files", label: "Files" },
              { value: "git", label: "Git" },
            ]}
            value={tab}
            onChange={onTabChange}
          />
          {/* Honest path label. This terminal was launched without a project
              root, so what is being browsed is the directory the agent actually
              runs in, not an operator-chosen project. Say so next to the path
              rather than letting the panel imply a project. */}
          <div className="flex min-w-0 flex-1 items-center gap-1.5">
            {meta && isWorkingDir && (
              <span
                className="shrink-0 text-[9.5px] uppercase tracking-[0.05em] text-fg-3"
                title={WORKING_DIR_HINT}
              >
                working directory
              </span>
            )}
            {meta && (
              <TruncatedPath value={meta.root} className="text-[11px] text-fg-3" />
            )}
          </div>
        </div>
        {meta && !isWorkingDir && (
          <div className="border-b border-line-1 px-4 py-2">
            <CloudDigestCard projectRoot={meta.root} />
          </div>
        )}
        <div className="min-h-0 flex-1">
          {metaErr ? (
            <ErrorState code={metaErr} />
          ) : tab === "files" ? (
            <FilesTab
              token={token}
              openPath={openPath}
              onRowMenu={openRowMenu}
              copiedRel={copiedRel}
            />
          ) : (
            <GitTab
              token={token}
              gitAvailable={meta?.git_available ?? true}
              onOpenFile={openInFiles}
              onRowMenu={openRowMenu}
              copiedRel={copiedRel}
            />
          )}
        </div>
      </div>
      {menu && (
        <ContextMenu
          x={menu.x}
          y={menu.y}
          items={menuItems(menu.rel)}
          onClose={() => setMenu(null)}
        />
      )}
    </FloatingPanel>
  );
}

function lastSegment(p: string): string {
  if (!p) return "";
  const parts = p.replace(/\/+$/, "").split("/");
  return parts[parts.length - 1] || p;
}

// ---------------------------------------------------------------------------
// Files tab
// ---------------------------------------------------------------------------

type DirState = {
  entries: DirEntry[];
  truncated: boolean;
  loading: boolean;
  error: ProjectPanelErrorCode | null;
};

const DIMMED = new Set([".git", "node_modules"]);

// DOM-bound caps (review finding 10): a hostile — or merely huge — repository
// must never be able to mount hundreds of thousands of nodes and freeze the
// tab. Content beyond a cap is simply not rendered (with an honest footer).
const MAX_FILE_LINES = 5000;
const MAX_STATUS_ROWS = 500;
const MAX_EXPANDED_DIRS = 50;
const REFRESH_CONCURRENCY = 4;

// runPool runs `fn` over `items` with at most `limit` in flight — used so
// Refresh re-fetches expanded directories without an unbounded fan-out (one
// request per loaded dir could otherwise be hundreds at once).
async function runPool<T>(
  items: T[],
  limit: number,
  fn: (item: T) => Promise<void>,
): Promise<void> {
  let cursor = 0;
  const worker = async () => {
    while (cursor < items.length) {
      const idx = cursor++;
      await fn(items[idx]);
    }
  };
  const n = Math.max(1, Math.min(limit, items.length));
  await Promise.all(Array.from({ length: n }, worker));
}

function joinPath(parent: string, name: string): string {
  return parent ? `${parent}/${name}` : name;
}

function FilesTab({
  token,
  openPath,
  onRowMenu,
  copiedRel,
}: RowMenuProps & {
  token: string;
  openPath: { path: string; nonce: number } | null;
}) {
  const [dirs, setDirs] = useState<Record<string, DirState>>({});
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [selected, setSelected] = useState<string | null>(null);
  const [file, setFile] = useState<FileResp | null>(null);
  const [fileLoading, setFileLoading] = useState(false);
  const [fileErr, setFileErr] = useState<ProjectPanelErrorCode | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const dirsRef = useRef(dirs);
  dirsRef.current = dirs;
  const expandedRef = useRef(expanded);
  expandedRef.current = expanded;
  // Stale-response fences (review finding 9): a late fetch for a path/file must
  // never overwrite a newer one. Each in-flight request captures a generation;
  // its result is dropped unless it is still the latest for that key.
  const fileReqRef = useRef(0);
  const dirReqRef = useRef<Record<string, number>>({});
  // Transient notice shown when the expand cap (finding 10) is hit.
  const [treeNotice, setTreeNotice] = useState<string | null>(null);

  const loadDir = useCallback(
    async (path: string) => {
      const myReq = (dirReqRef.current[path] ?? 0) + 1;
      dirReqRef.current[path] = myReq;
      setDirs((prev) => ({
        ...prev,
        [path]: {
          entries: prev[path]?.entries ?? [],
          truncated: prev[path]?.truncated ?? false,
          loading: true,
          error: null,
        },
      }));
      try {
        const resp: FilesResp = await fetchProjectFiles(token, path);
        if (dirReqRef.current[path] !== myReq) return; // superseded
        setDirs((prev) => ({
          ...prev,
          [path]: {
            entries: resp.entries,
            truncated: resp.truncated,
            loading: false,
            error: null,
          },
        }));
      } catch (e) {
        if (dirReqRef.current[path] !== myReq) return; // superseded
        setDirs((prev) => ({
          ...prev,
          [path]: { entries: [], truncated: false, loading: false, error: codeOf(e) },
        }));
      }
    },
    [token],
  );

  const loadFile = useCallback(
    async (path: string) => {
      const myReq = ++fileReqRef.current;
      setSelected(path);
      setFile(null);
      setFileErr(null);
      setFileLoading(true);
      try {
        const resp = await fetchProjectFile(token, path);
        if (fileReqRef.current !== myReq) return; // superseded by a newer open
        setFile(resp);
      } catch (e) {
        if (fileReqRef.current !== myReq) return; // superseded by a newer open
        setFileErr(codeOf(e));
      } finally {
        if (fileReqRef.current === myReq) setFileLoading(false);
      }
    },
    [token],
  );

  // Load the root once per token.
  useEffect(() => {
    setDirs({});
    setExpanded(new Set());
    setSelected(null);
    setFile(null);
    setFileErr(null);
    loadDir("");
  }, [token, loadDir]);

  const toggleDir = useCallback(
    (path: string) => {
      const isOpen = expandedRef.current.has(path);
      // Cap simultaneously-expanded directories (review finding 10): refuse a
      // new expansion past the ceiling with an honest notice, rather than let
      // the tree grow unbounded. Collapsing is always allowed.
      if (!isOpen && expandedRef.current.size >= MAX_EXPANDED_DIRS) {
        setTreeNotice(
          `Too many folders expanded (max ${MAX_EXPANDED_DIRS}). Collapse some to open more.`,
        );
        return;
      }
      setTreeNotice(null);
      setExpanded((prev) => {
        const next = new Set(prev);
        if (next.has(path)) {
          next.delete(path);
        } else {
          next.add(path);
          if (!dirsRef.current[path]) void loadDir(path);
        }
        return next;
      });
    },
    [loadDir],
  );

  // Respond to a git-status "open this file" request: expand ancestors + open.
  useEffect(() => {
    if (!openPath) return;
    const parts = openPath.path.split("/");
    const ancestors: string[] = [];
    for (let i = 0; i < parts.length - 1; i++) {
      ancestors.push(ancestors.length ? `${ancestors[ancestors.length - 1]}/${parts[i]}` : parts[i]);
    }
    setExpanded((prev) => {
      const next = new Set(prev);
      for (const a of ancestors) {
        next.add(a);
        if (!dirsRef.current[a]) void loadDir(a);
      }
      // The reveal path must also honor MAX_EXPANDED_DIRS: evict the
      // oldest-expanded non-ancestor dirs (Set preserves insertion order)
      // rather than let a git-status click bypass the cap.
      if (next.size > MAX_EXPANDED_DIRS) {
        const keep = new Set(ancestors);
        for (const p of next) {
          if (next.size <= MAX_EXPANDED_DIRS) break;
          if (!keep.has(p)) next.delete(p);
        }
      }
      return next;
    });
    void loadFile(openPath.path);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [openPath?.nonce]);

  const refresh = useCallback(async () => {
    setRefreshing(true);
    // Refetch only the currently-expanded directories (plus the always-visible
    // root), with bounded concurrency — never an unbounded fan-out over every
    // directory ever loaded (review finding 10).
    const targets = ["", ...expandedRef.current].filter(
      (p) => p === "" || dirsRef.current[p] !== undefined,
    );
    const uniq = Array.from(new Set(targets));
    await runPool(uniq, REFRESH_CONCURRENCY, (p) => loadDir(p));
    if (selected) await loadFile(selected);
    setRefreshing(false);
  }, [loadDir, loadFile, selected]);

  return (
    <div className="flex h-full min-h-0 flex-col">
      {/* Tree — ~40% */}
      <div className="flex min-h-0 basis-[40%] flex-col border-b border-line-1">
        <div className="flex items-center justify-between px-4 py-1.5">
          <span className="text-[10.5px] uppercase tracking-[0.05em] text-fg-3">Files</span>
          <RefreshButton onClick={() => void refresh()} busy={refreshing} />
        </div>
        {treeNotice && (
          <div className="px-4 pb-1 text-[10.5px] text-warn">{treeNotice}</div>
        )}
        <div className="min-h-0 flex-1 overflow-auto px-2 pb-2 font-mono text-[12px]">
          <DirChildren
            dirs={dirs}
            expanded={expanded}
            selected={selected}
            path=""
            depth={0}
            onToggle={toggleDir}
            onOpenFile={(p) => void loadFile(p)}
            onRowMenu={onRowMenu}
            copiedRel={copiedRel}
          />
        </div>
      </div>
      {/* Viewer — ~60% */}
      <div className="flex min-h-0 basis-[60%] flex-col">
        <FileViewer
          path={selected}
          file={file}
          loading={fileLoading}
          error={fileErr}
          onRefresh={() => selected && void loadFile(selected)}
          onRowMenu={onRowMenu}
          copiedRel={copiedRel}
        />
      </div>
    </div>
  );
}

function entryGlyph(type: DirEntry["type"], open: boolean): string {
  if (type === "dir") return open ? "▾" : "▸";
  if (type === "symlink") return "↳";
  return " ";
}

function DirChildren({
  dirs,
  expanded,
  selected,
  path,
  depth,
  onToggle,
  onOpenFile,
  onRowMenu,
  copiedRel,
}: RowMenuProps & {
  dirs: Record<string, DirState>;
  expanded: Set<string>;
  selected: string | null;
  path: string;
  depth: number;
  onToggle: (p: string) => void;
  onOpenFile: (p: string) => void;
}) {
  const state = dirs[path];
  if (!state) return null;
  if (state.loading && state.entries.length === 0) {
    return <div className="px-2 py-1 text-[11px] text-fg-4" style={{ paddingLeft: 8 + depth * 14 }}>loading…</div>;
  }
  if (state.error) {
    return (
      <div className="px-2 py-1 text-[11px] text-danger" style={{ paddingLeft: 8 + depth * 14 }}>
        {errorCopy(state.error).title}
      </div>
    );
  }
  // Dirs first, then files, each alphabetical (defensive — server also sorts).
  const entries = [...state.entries].sort((a, b) => {
    const ad = a.type === "dir" ? 0 : 1;
    const bd = b.type === "dir" ? 0 : 1;
    return ad - bd || a.name.localeCompare(b.name);
  });
  return (
    <div>
      {entries.map((e) => {
        const childPath = joinPath(path, e.name);
        const isDir = e.type === "dir";
        const isOpen = expanded.has(childPath);
        const dim = DIMMED.has(e.name);
        const isSel = selected === childPath;
        return (
          <div key={childPath}>
            <div
              className="group relative flex items-center"
              onContextMenu={(ev) => {
                ev.preventDefault();
                onRowMenu(childPath, ev.clientX, ev.clientY);
              }}
              onKeyDown={rowMenuKeyDown(childPath, onRowMenu)}
            >
              <button
                type="button"
                onClick={() => (isDir ? onToggle(childPath) : onOpenFile(childPath))}
                title={e.name}
                style={{ paddingLeft: 6 + depth * 14 }}
                className={
                  "flex w-full items-center gap-1.5 rounded-1 py-0.5 pr-6 text-left hover:bg-bg-2 " +
                  (isSel ? "bg-bg-3 text-fg-0" : dim ? "text-fg-4" : "text-fg-2")
                }
              >
                <span className="w-3 shrink-0 text-center text-fg-3" aria-hidden>
                  {entryGlyph(e.type, isOpen)}
                </span>
                <span className="min-w-0 flex-1 truncate">{e.name}</span>
                {!isDir && e.type === "file" && (
                  <span className="shrink-0 text-[10px] text-fg-4">{fmtBytes(e.size)}</span>
                )}
              </button>
              <RowMenuHandle rel={childPath} onRowMenu={onRowMenu} copied={copiedRel === childPath} />
            </div>
            {isDir && isOpen && (
              <DirChildren
                dirs={dirs}
                expanded={expanded}
                selected={selected}
                path={childPath}
                depth={depth + 1}
                onToggle={onToggle}
                onOpenFile={onOpenFile}
                onRowMenu={onRowMenu}
                copiedRel={copiedRel}
              />
            )}
          </div>
        );
      })}
      {state.truncated && (
        <div className="px-2 py-0.5 text-[10.5px] text-warn" style={{ paddingLeft: 8 + depth * 14 }}>
          Listing truncated (too many entries)
        </div>
      )}
    </div>
  );
}

function FileViewer({
  path,
  file,
  loading,
  error,
  onRefresh,
  onRowMenu,
  copiedRel,
}: RowMenuProps & {
  path: string | null;
  file: FileResp | null;
  loading: boolean;
  error: ProjectPanelErrorCode | null;
  onRefresh: () => void;
}) {
  const { lines, total } = useMemo(() => {
    if (!file || file.binary || !file.content) return { lines: [] as string[], total: 0 };
    // Trailing newline shouldn't render a phantom final line.
    const c = file.content.endsWith("\n") ? file.content.slice(0, -1) : file.content;
    const all = c.split("\n");
    // Hard-cap rendered lines (review finding 10): content beyond the cap is
    // NOT mounted — an honest footer reports the total.
    return { lines: all.slice(0, MAX_FILE_LINES), total: all.length };
  }, [file]);

  if (!path) {
    return (
      <div className="flex h-full items-center justify-center p-6 text-center text-[12px] text-fg-4">
        Select a file to view it here.
      </div>
    );
  }
  return (
    <div className="flex h-full min-h-0 flex-col">
      <div
        className="flex items-center gap-2 border-b border-line-1 px-4 py-1.5"
        onContextMenu={(ev) => {
          ev.preventDefault();
          onRowMenu(path, ev.clientX, ev.clientY);
        }}
        onKeyDown={rowMenuKeyDown(path, onRowMenu)}
      >
        <span className="min-w-0 flex-1">
          <TruncatedPath value={path} className="font-mono text-[11.5px] text-fg-1" />
        </span>
        {copiedRel === path && (
          <span className="shrink-0 rounded-1 bg-ok/20 px-1 py-[1px] text-[9.5px] font-medium text-ok">
            Copied
          </span>
        )}
        {file && !file.binary && (
          <span className="shrink-0 text-[10px] text-fg-4">{fmtBytes(file.size)}</span>
        )}
        <button
          type="button"
          aria-label="Path actions"
          title="Copy or paste this path"
          onClick={(e) => {
            const r = e.currentTarget.getBoundingClientRect();
            onRowMenu(path, r.right, r.bottom);
          }}
          className="grid h-6 w-6 shrink-0 place-items-center rounded-2 border border-line-2 bg-bg-2 text-[12px] text-fg-2 hover:bg-bg-3 hover:text-fg-0"
        >
          ⋯
        </button>
        <RefreshButton onClick={onRefresh} busy={loading} />
      </div>
      <div className="min-h-0 flex-1 overflow-auto">
        {loading ? (
          <div className="p-6 text-[12px] text-fg-4">Loading…</div>
        ) : error ? (
          <div className="p-6 text-[12px] text-danger">{errorCopy(error).title}</div>
        ) : !file ? null : file.binary ? (
          <div className="p-6 text-[12px] text-fg-4">
            Binary file - not shown ({fmtBytes(file.size)}).
          </div>
        ) : file.content === "" ? (
          <div className="p-6 text-[12px] text-fg-4">Empty file.</div>
        ) : (
          <>
            {(file.too_large || file.truncated) && (
              <div className="border-b border-line-1 bg-warn-soft px-4 py-1 text-[11px] text-warn">
                File is large - showing the first {fmtBytes(file.content.length)} only.
              </div>
            )}
            <pre className="m-0 overflow-x-auto p-0 font-mono text-[11.5px] leading-[1.5] text-fg-1">
              <code className="block">
                {lines.map((ln, i) => (
                  <div key={i} className="flex">
                    <span className="sticky left-0 w-12 shrink-0 select-none border-r border-line-1 bg-bg-1 pr-2 text-right text-fg-4">
                      {i + 1}
                    </span>
                    <span className="whitespace-pre px-3">{ln}</span>
                  </div>
                ))}
              </code>
            </pre>
            {total > MAX_FILE_LINES && (
              <div className="border-t border-line-1 bg-warn-soft px-4 py-1 text-[11px] text-warn">
                Showing first {MAX_FILE_LINES.toLocaleString()} of{" "}
                {total.toLocaleString()} lines - the rest isn't rendered.
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Git tab
// ---------------------------------------------------------------------------

function GitTab({
  token,
  gitAvailable,
  onOpenFile,
  onRowMenu,
  copiedRel,
}: RowMenuProps & {
  token: string;
  gitAvailable: boolean;
  onOpenFile: (path: string) => void;
}) {
  const [info, setInfo] = useState<GitInfo | null>(null);
  const [err, setErr] = useState<ProjectPanelErrorCode | null>(null);
  const [loading, setLoading] = useState(true);
  // Stale-response fence (review finding 9): drop a late git snapshot if a
  // newer load (or a token remount) has superseded it.
  const gitReqRef = useRef(0);

  const load = useCallback(async () => {
    const myReq = ++gitReqRef.current;
    setLoading(true);
    setErr(null);
    try {
      const resp = await fetchProjectGit(token);
      if (gitReqRef.current !== myReq) return; // superseded
      setInfo(resp);
    } catch (e) {
      if (gitReqRef.current !== myReq) return; // superseded
      setErr(codeOf(e));
    } finally {
      if (gitReqRef.current === myReq) setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    void load();
  }, [load]);

  if (!gitAvailable) return <ErrorState code="git_unavailable" />;
  if (err) return <ErrorState code={err} />;
  if (loading && !info) return <div className="p-6 text-[12px] text-fg-4">Loading git…</div>;
  if (!info) return null;
  if (!info.is_git) {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-1 p-8 text-center">
        <div className="text-[13px] font-medium text-fg-1">Not a git repository</div>
        <div className="max-w-[380px] text-[12px] text-fg-3">
          This project root isn't tracked by git.
        </div>
      </div>
    );
  }

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex items-center gap-2 border-b border-line-1 px-4 py-2">
        <span className="rounded-2 bg-bg-3 px-2 py-0.5 font-mono text-[11.5px] text-fg-0">
          {info.branch || "(detached)"}
        </span>
        {info.upstream && (
          <span className="text-[11px] text-fg-3">→ {info.upstream}</span>
        )}
        {(info.ahead > 0 || info.behind > 0) && (
          <span className="flex items-center gap-1 text-[11px]">
            {info.ahead > 0 && <span className="text-accent">↑{info.ahead}</span>}
            {info.behind > 0 && <span className="text-warn">↓{info.behind}</span>}
          </span>
        )}
        <div className="flex-1" />
        <RefreshButton onClick={() => void load()} busy={loading} />
      </div>
      <div className="min-h-0 flex-1 overflow-auto">
        <ChangesSection
          status={info.status}
          statusTruncated={info.status_truncated ?? false}
          onOpenFile={onOpenFile}
          onRowMenu={onRowMenu}
          copiedRel={copiedRel}
        />
        <HistorySection log={info.log} truncated={info.log_truncated} />
      </div>
    </div>
  );
}

// XY porcelain codes → a themed badge colour.
function xyColor(ch: string): string {
  switch (ch) {
    case "M":
      return "text-warn";
    case "A":
      return "text-accent";
    case "D":
      return "text-danger";
    case "R":
    case "C":
      return "text-accent";
    case "?":
      return "text-fg-3";
    default:
      return "text-fg-4";
  }
}

function StatusBadge({ staged, worktree }: { staged: string; worktree: string }) {
  const s = staged && staged !== "." ? staged : " ";
  const w = worktree && worktree !== "." ? worktree : " ";
  return (
    <span className="flex shrink-0 gap-0 font-mono text-[11px]">
      <span className={`w-2 text-center ${xyColor(staged)}`}>{s}</span>
      <span className={`w-2 text-center ${xyColor(worktree)}`}>{w}</span>
    </span>
  );
}

function ChangesSection({
  status,
  statusTruncated,
  onOpenFile,
  onRowMenu,
  copiedRel,
}: RowMenuProps & {
  status: GitFileStatus[];
  statusTruncated: boolean;
  onOpenFile: (path: string) => void;
}) {
  // Hard-cap rendered change rows (review finding 10): a 1 MiB status payload
  // can hold hundreds of thousands of tiny records — render at most the first
  // MAX_STATUS_ROWS and note the remainder.
  const shown = status.slice(0, MAX_STATUS_ROWS);
  const clientCapped = status.length > MAX_STATUS_ROWS;
  return (
    <section className="border-b border-line-1 px-2 py-2">
      <div className="px-2 pb-1 text-[10.5px] uppercase tracking-[0.05em] text-fg-3">
        Changes ({status.length}
        {statusTruncated ? "+" : ""})
      </div>
      {status.length === 0 ? (
        <div className="px-2 py-1 text-[11.5px] text-fg-4">Working tree clean.</div>
      ) : (
        <div>
          {shown.map((f) => (
            <div
              key={f.path + f.staged + f.worktree}
              className="group relative flex items-center"
              onContextMenu={(ev) => {
                ev.preventDefault();
                onRowMenu(f.path, ev.clientX, ev.clientY);
              }}
              onKeyDown={rowMenuKeyDown(f.path, onRowMenu)}
            >
              <button
                type="button"
                onClick={() => onOpenFile(f.path)}
                title={`Open ${f.path}`}
                className="flex w-full items-center gap-2 rounded-1 px-2 py-0.5 pr-6 text-left hover:bg-bg-2"
              >
                <StatusBadge staged={f.staged} worktree={f.worktree} />
                <span className="min-w-0 flex-1 truncate font-mono text-[11.5px] text-fg-2">
                  {f.renamed_from ? (
                    <>
                      <span className="text-fg-4">{f.renamed_from} → </span>
                      {f.path}
                    </>
                  ) : (
                    f.path
                  )}
                </span>
              </button>
              <RowMenuHandle rel={f.path} onRowMenu={onRowMenu} copied={copiedRel === f.path} />
            </div>
          ))}
          {clientCapped && (
            <div className="px-2 py-0.5 text-[10.5px] text-warn">
              +{(status.length - MAX_STATUS_ROWS).toLocaleString()} more changes not shown
            </div>
          )}
          {statusTruncated && !clientCapped && (
            <div className="px-2 py-0.5 text-[10.5px] text-warn">
              Showing first {status.length.toLocaleString()} changes - more exist on the server
            </div>
          )}
        </div>
      )}
    </section>
  );
}

const LANE_W = 14;
const ROW_H = 40;
const DOT_R = 3.5;
// Theme-safe rail palette (all defined CSS vars), cycled by lane column.
const RAIL_COLORS = [
  "var(--accent)",
  "var(--success)",
  "var(--info)",
  "var(--warn)",
  "var(--tok-read)",
  "var(--danger)",
];

function railColor(col: number): string {
  return RAIL_COLORS[((col % RAIL_COLORS.length) + RAIL_COLORS.length) % RAIL_COLORS.length];
}

function laneX(col: number): number {
  return col * LANE_W + LANE_W / 2;
}

function HistorySection({ log, truncated }: { log: GitCommit[]; truncated: boolean }) {
  const graph: LaneGraph = useMemo(() => computeLaneGraph(log), [log]);
  const gutterW = Math.max(1, graph.width) * LANE_W;

  return (
    <section className="px-2 py-2">
      <div className="px-2 pb-1 text-[10.5px] uppercase tracking-[0.05em] text-fg-3">
        History ({log.length}
        {truncated ? "+" : ""})
      </div>
      {log.length === 0 ? (
        <div className="px-2 py-1 text-[11.5px] text-fg-4">No commits.</div>
      ) : (
        <div>
          {log.map((c, i) => (
            <div key={c.hash} className="flex items-stretch gap-2 rounded-1 hover:bg-bg-2">
              <div style={{ width: gutterW }} className="shrink-0">
                <GraphCell row={graph.rows[i]} dotColor={railColor(graph.rows[i]?.col ?? 0)} />
              </div>
              <div className="min-w-0 flex-1 py-1.5 pr-2">
                <div className="flex items-baseline gap-2">
                  <span className="shrink-0 font-mono text-[11px] text-accent" title={c.hash}>
                    {c.hash.slice(0, 7)}
                  </span>
                  <span className="min-w-0 flex-1 truncate text-[12px] text-fg-1">{c.subject}</span>
                </div>
                <div className="mt-0.5 flex items-center gap-2 text-[10.5px] text-fg-3">
                  <span className="truncate">{c.author}</span>
                  <span className="shrink-0 text-fg-4">·</span>
                  <span className="shrink-0" title={c.date}>
                    {relTime(c.date)}
                  </span>
                  {c.refs.length > 0 && (
                    <span className="flex flex-wrap gap-1">
                      {c.refs.map((r) => (
                        <RefChip key={r} label={r} />
                      ))}
                    </span>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

function RefChip({ label }: { label: string }) {
  const isTag = label.startsWith("tag:");
  const isHead = label === "HEAD" || label.startsWith("HEAD ->");
  const text = label.replace(/^tag:\s*/, "").replace(/^HEAD ->\s*/, "");
  const cls = isTag
    ? "border-warn/40 text-warn"
    : isHead
      ? "border-accent/50 text-accent"
      : "border-line-2 text-fg-3";
  return (
    <span
      className={`rounded-1 border px-1 py-[1px] font-mono text-[9.5px] leading-none ${cls}`}
    >
      {isTag ? "⚑ " : ""}
      {text}
    </span>
  );
}

// One row of the commit lane graph, drawn as an inline SVG. Rails meet at the
// mid-line so a passthrough lane reads as one continuous vertical line across
// rows; the commit dot sits at the mid-line in its own column.
function GraphCell({ row, dotColor }: { row: GraphRow | undefined; dotColor: string }) {
  if (!row) return <svg width={LANE_W} height={ROW_H} aria-hidden />;
  const mid = ROW_H / 2;
  return (
    <svg width="100%" height={ROW_H} aria-hidden className="block">
      {row.top.map((seg, i) => (
        <line
          key={`t${i}`}
          x1={laneX(seg.fromCol)}
          y1={0}
          x2={laneX(seg.toCol)}
          y2={mid}
          stroke={railColor(seg.toCol)}
          strokeWidth={1.5}
          fill="none"
        />
      ))}
      {row.bottom.map((seg, i) => (
        <line
          key={`b${i}`}
          x1={laneX(seg.fromCol)}
          y1={mid}
          x2={laneX(seg.toCol)}
          y2={ROW_H}
          stroke={railColor(seg.toCol)}
          strokeWidth={1.5}
          fill="none"
        />
      ))}
      <circle cx={laneX(row.col)} cy={mid} r={DOT_R} fill={dotColor} stroke="var(--bg-1)" strokeWidth={1} />
    </svg>
  );
}
