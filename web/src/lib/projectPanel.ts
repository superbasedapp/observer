// Wire types + fetch helpers for the per-terminal project panel (Git tree +
// File Explorer). Mirrors the frozen wire contract in
// docs/plans/terminal-project-panels-and-org-sweep-plan-2026-07-23.md.
//
// All endpoints are token-scoped and GET-only: the browser never sends a
// filesystem root — the server resolves the canonical project root from the
// launch handle it retained at spawn/attach time. Errors arrive as a JSON
// envelope `{ "error": "<code>" }` with an HTTP status; we surface the CODE so
// the UI can render an honest state per case (unknown_token / no_project_root
// / remote_view_disabled / bad_path / not_found / git_unavailable).

/**
 * What the served root IS. "project_root" = an operator allow-listed launch
 * root; "working_dir" = the terminal's own working directory (a launch that
 * requested no root, so the agent runs in the daemon's cwd). The panel labels
 * the path differently per kind rather than always calling it a project.
 */
export type ProjectRootKind = "project_root" | "working_dir";

/** meta payload — GET /api/terminal/project/<token> */
export type ProjectMeta = {
  root: string;
  /**
   * Additive/optional: absent when talking to a daemon built before the
   * 2026-08-28 ruling widened browsing to the run's working directory. Absence
   * is read as "project_root", which is what every browsable root was then.
   */
  root_kind?: ProjectRootKind;
  git_available: boolean;
  is_git: boolean;
  branch: string;
};

export type EntryType = "dir" | "file" | "symlink" | "other";

/** One directory entry in a files listing. */
export type DirEntry = {
  name: string;
  type: EntryType;
  size: number;
  mtime: string; // RFC3339
};

/** files payload — GET /api/terminal/project/<token>/files?path=<rel> */
export type FilesResp = {
  path: string;
  entries: DirEntry[];
  truncated: boolean;
};

/** file payload — GET /api/terminal/project/<token>/file?path=<rel> */
export type FileResp = {
  path: string;
  content: string;
  size: number;
  truncated: boolean;
  binary: boolean;
  too_large: boolean;
};

/** One porcelain-v2 status row. staged/worktree are single XY chars. */
export type GitFileStatus = {
  path: string;
  staged: string;
  worktree: string;
  renamed_from: string;
};

/** One commit in the log. */
export type GitCommit = {
  hash: string;
  parents: string[];
  author: string;
  date: string; // RFC3339
  refs: string[];
  subject: string;
};

/** git payload — GET /api/terminal/project/<token>/git */
export type GitInfo = {
  is_git: boolean;
  branch: string;
  upstream: string;
  ahead: number;
  behind: number;
  status: GitFileStatus[];
  log: GitCommit[];
  log_truncated: boolean;
  // Additive/optional: the backend sets this when the status list was capped
  // server-side (more changes exist than were returned). Absence ≡ false.
  status_truncated?: boolean;
};

/** Known error codes from the panel endpoints' `{error}` envelope. */
export type ProjectPanelErrorCode =
  | "unknown_token"
  | "no_project_root"
  | "remote_view_disabled"
  | "bad_path"
  | "not_found"
  | "git_unavailable"
  | "request_failed";

/**
 * Typed error carrying the wire `code`. The panel UI branches on `.code` to
 * pick honest copy; `.status` is retained for debugging.
 */
export class ProjectPanelError extends Error {
  constructor(
    public readonly code: ProjectPanelErrorCode,
    public readonly status: number,
  ) {
    super(`project panel: ${code} (${status})`);
    this.name = "ProjectPanelError";
  }
}

function base(token: string): string {
  return `/api/terminal/project/${encodeURIComponent(token)}`;
}

// GET helper that reads the `{error}` envelope on a non-2xx response and
// throws a typed ProjectPanelError. Every endpoint here is GET, so no remote
// CSRF header is required (that only applies to unsafe methods).
async function get<T>(path: string): Promise<T> {
  let res: Response;
  try {
    res = await fetch(path, { headers: { Accept: "application/json" } });
  } catch {
    throw new ProjectPanelError("request_failed", 0);
  }
  if (!res.ok) {
    let code: ProjectPanelErrorCode = "request_failed";
    try {
      const body = (await res.json()) as { error?: string } | null;
      if (body && typeof body.error === "string") {
        code = body.error as ProjectPanelErrorCode;
      }
    } catch {
      /* non-JSON error body — keep the generic code */
    }
    throw new ProjectPanelError(code, res.status);
  }
  return res.json() as Promise<T>;
}

/** Resolve the panel meta (root path, git availability, branch). */
export function fetchProjectMeta(token: string): Promise<ProjectMeta> {
  return get<ProjectMeta>(base(token));
}

/** List one directory (relative to the project root; "" = root). */
export function fetchProjectFiles(token: string, path: string): Promise<FilesResp> {
  const q = path ? `?path=${encodeURIComponent(path)}` : "";
  // DEFENSIVE-NULL BOUNDARY: normalize a wire `null` listing to `[]` so the
  // tree can iterate/`.length` entries unconditionally.
  return get<FilesResp>(`${base(token)}/files${q}`).then((r) => ({
    ...r,
    entries: r.entries ?? [],
  }));
}

/** Read one file (relative to the project root). */
export function fetchProjectFile(token: string, path: string): Promise<FileResp> {
  return get<FileResp>(`${base(token)}/file?path=${encodeURIComponent(path)}`);
}

/** Snapshot the git state (branch, ahead/behind, status, log). */
export function fetchProjectGit(token: string): Promise<GitInfo> {
  // DEFENSIVE-NULL BOUNDARY (review finding 7): a clean repo encodes
  // status:null; a root commit encodes parents:null; an undecorated commit
  // encodes refs:null. Normalize every nullable slice to a non-nil array HERE,
  // once, so component code can `.length` / iterate / map them unconditionally.
  return get<GitInfo>(`${base(token)}/git`).then(normalizeGit);
}

/** Fill nullable git slices with empty arrays at the fetch boundary. */
function normalizeGit(r: GitInfo): GitInfo {
  return {
    ...r,
    status: (r.status ?? []).map((s) => ({
      ...s,
      path: s.path ?? "",
      staged: s.staged ?? "",
      worktree: s.worktree ?? "",
      renamed_from: s.renamed_from ?? "",
    })),
    log: (r.log ?? []).map((c) => ({
      ...c,
      parents: c.parents ?? [],
      refs: c.refs ?? [],
    })),
  };
}

// ---------------------------------------------------------------------------
// Path helpers for the file context menu (copy / paste-into-terminal).
// ---------------------------------------------------------------------------

/**
 * Join a root-relative (always "/"-separated) path onto the server-resolved
 * project root using the ROOT's own separator: a `\`-rooted Windows path
 * (e.g. `C:\src\app`) joins with `\`, a POSIX root with `/`. Pure.
 */
export function toAbsolutePath(root: string, rel: string): string {
  if (!root) return rel;
  const win = isWindowsRoot(root);
  const sep = win ? "\\" : "/";
  // Strip trailing separators, but only the ones that are real separators on
  // this platform: a POSIX root may legitimately END in a backslash (a literal
  // filename character), so only "/" is a trailing separator there. On Windows
  // both "\" and "/" are separators.
  const base = win ? root.replace(/[\\/]+$/, "") : root.replace(/\/+$/, "");
  if (!rel) return base;
  const parts = rel.split("/").filter(Boolean);
  return base + sep + parts.join(sep);
}

/**
 * Whether a server-resolved root is Windows-style. Classified ONLY on a
 * drive-letter root (`C:\`, `C:/`, `C:`) or a UNC path (`\\host\share`) — a
 * backslash ANYWHERE is not sufficient, because a POSIX absolute path such as
 * `/srv/project\archive` legitimately contains a backslash as a filename
 * character. A path that starts with "/" is POSIX regardless of backslashes.
 */
export function isWindowsRoot(root: string): boolean {
  if (root.startsWith("/")) return false;
  return /^[A-Za-z]:[\\/]?/.test(root) || /^\\\\/.test(root);
}

/**
 * Sanitize a path for the paste-into-terminal channel. Paste is routed through
 * xterm's own paste pipeline (`term.paste`) — IDENTICAL to a manual Ctrl+V — so
 * we deliberately do NOT hand-quote for a guessed shell: bracketed-paste mode
 * (which the running app enables) is what neutralizes shell metacharacters,
 * exactly as it does for a real clipboard paste, and a manual paste of a spaced
 * path isn't auto-quoted either (this also matches copy-to-clipboard, which
 * doesn't quote).
 *
 * The ONLY transform is stripping control bytes — C0 (`\u0000-\u001f`, which
 * includes newline/ESC), DEL and C1 (`\u007f-\u009f`) — so a hostile or
 * unrepresentable filename can neither smuggle an ESC control sequence nor
 * inject a newline that would auto-execute at a prompt.
 */
export function sanitizePastePath(p: string): string {
  // eslint-disable-next-line no-control-regex
  return p.replace(/[\u0000-\u001f\u007f-\u009f]/g, "");
}

// ---------------------------------------------------------------------------
// Commit lane-graph layout (client-side, greedy; no external dependency).
// ---------------------------------------------------------------------------

/** A rail segment within one row band, expressed in lane columns. */
export type LaneSegment = { fromCol: number; toCol: number };

/** Per-commit graph geometry: the dot column + incoming/outgoing rails. */
export type GraphRow = {
  /** Column the commit dot sits in. */
  col: number;
  /** Rails from the top edge (y=0) to the mid line (y=0.5). */
  top: LaneSegment[];
  /** Rails from the mid line (y=0.5) to the bottom edge (y=1). */
  bottom: LaneSegment[];
};

/** Result of laying out a commit list. `width` = max lane count. */
export type LaneGraph = {
  rows: GraphRow[];
  width: number;
};

function firstFree(lanes: (string | null)[]): number {
  for (let i = 0; i < lanes.length; i++) {
    if (lanes[i] == null) return i;
  }
  lanes.push(null);
  return lanes.length - 1;
}

/**
 * Assign each commit a lane column greedily and derive the rail segments for
 * an SVG swim-lane graph. Commits must be in topological order (children
 * before parents — i.e. newest first, as `git log` emits). Pure function.
 */
export function computeLaneGraph(commits: GitCommit[]): LaneGraph {
  // active[i] = the hash the lane in column i is currently waiting to draw.
  const active: (string | null)[] = [];
  const rows: GraphRow[] = [];
  let width = 0;

  for (const c of commits) {
    const before = active.slice();
    // Columns whose lane points at this commit (its children's rails).
    const myLanes: number[] = [];
    for (let i = 0; i < before.length; i++) {
      if (before[i] === c.hash) myLanes.push(i);
    }
    let myCol: number;
    if (myLanes.length === 0) {
      myCol = firstFree(active);
      active[myCol] = null; // reserve — a parent may reuse it below
    } else {
      myCol = myLanes[0];
    }
    // The dot consumes every lane that pointed at it (merges collapse).
    for (const i of myLanes) active[i] = null;

    // Place parents: reuse the dot's lane for the first, allocate for the
    // rest, and merge into any lane already expecting that parent.
    const parentCols: number[] = [];
    let firstPlaced = false;
    for (const p of c.parents) {
      const existing = active.indexOf(p);
      if (existing !== -1) {
        parentCols.push(existing);
        continue;
      }
      if (!firstPlaced) {
        active[myCol] = p;
        parentCols.push(myCol);
        firstPlaced = true;
      } else {
        const col = firstFree(active);
        active[col] = p;
        parentCols.push(col);
      }
    }

    // Incoming rails (top → mid).
    const top: LaneSegment[] = [];
    for (let i = 0; i < before.length; i++) {
      if (before[i] == null) continue;
      if (before[i] === c.hash) {
        top.push({ fromCol: i, toCol: myCol }); // rail lands on the dot
      } else {
        top.push({ fromCol: i, toCol: i }); // passthrough
      }
    }

    // Outgoing rails (mid → bottom).
    const bottom: LaneSegment[] = [];
    const parentSet = new Set(parentCols);
    for (let i = 0; i < active.length; i++) {
      if (active[i] == null) continue;
      if (parentSet.has(i)) {
        bottom.push({ fromCol: myCol, toCol: i }); // rail leaves the dot
      } else {
        bottom.push({ fromCol: i, toCol: i }); // passthrough
      }
    }

    rows.push({ col: myCol, top, bottom });
    width = Math.max(width, before.length, active.length);

    // Trim trailing empty lanes so the graph stays narrow.
    while (active.length > 0 && active[active.length - 1] == null) active.pop();
  }

  return { rows, width: Math.max(1, width) };
}
