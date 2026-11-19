// sandboxReturns.ts is the pure half of the Terminals page's "Changes from
// sandboxed runs" panel (components/SandboxReturnsPanel.tsx, lane RETURNS):
// the answer of GET /api/terminal/sandbox/returns, and the plain words, tones
// and choices the panel shows for each saved diff and each local copy. No
// fetch and no React here, so node tests cover every row.

/** The tones the panel's pills take (a subset of the shared Tone). */
export type ReturnTone = "success" | "warn" | "danger" | "neutral" | "info";

/** One hosted run's saved diff (cmd/observer hostedDiffView). */
export type HostedDiff = {
  run: string;
  saved_at: string;
  bytes: number;
  root?: string;
  clone_url?: string;
  path: string;
  /** The diff opens as a branch; `why` says why not. */
  exact: boolean;
  why?: string;
  base_commit?: string;
  excluded?: number;
  branch?: string;
  branch_exists?: boolean;
  apply_command: string;
  /** The files were sent from a folder that is not a git repository
   *  (decision SBXD-8): there is no branch, and the offer is the diff
   *  file's path, not an apply command. */
  no_repository?: boolean;
};

/** One local copy, return repository or kept worktree branch
 *  (cmd/observer localReturnView). */
export type LocalReturn = {
  id: string;
  source: "clone-local" | "clone-remote" | "worktree" | string;
  origin: string;
  created_at: string;
  copy_dir?: string;
  size_bytes: number;
  size_over?: boolean;
  run_live: boolean;
  /** pending | returned | nothing_new | refused | unknown ("" for a worktree). */
  state?: string;
  ref?: string;
  commit?: string;
  /** -1 when not counted. */
  commits: number;
  reason?: string;
  return_repo?: string;
  fetch_command?: string;
  branch?: string;
  kept?: string;
  removable: boolean;
  /** The server's removal verdict on the copy now (the rule the click
   *  applies); only these copies are counted for the one-click removal. */
  safe_to_remove?: boolean;
  /** Why the click would keep the copy, when it would. */
  keep_reason?: string;
};

/** The list route's answer. */
export type ReturnsPage = {
  hosted: HostedDiff[];
  local: LocalReturn[];
  confirm_token?: string;
};

/** One file a saved diff touches (the preview route's files). */
export type DiffFile = { path: string; added: number; deleted: number; binary?: boolean };

/** The preview route's answer. */
export type DiffPreview = { run: string; text: string; cut: boolean; files: DiffFile[] };

/** A status line: words and a tone. */
export type ReturnStatus = { label: string; tone: ReturnTone; detail?: string };

/** What a saved diff's row offers. */
export type HostedDiffOffer = {
  status: ReturnStatus;
  /** "Open as a branch" is offered (it may still be refused on the click). */
  canBranch: boolean;
  /** The branch the click creates, shown before it. */
  branch?: string;
  /** What "Copy" puts on the clipboard when no branch is offered: the
   *  diff file's path for a folder that is not a repository, else the
   *  apply command. */
  copy?: { label: string; text: string };
};

/** hostedDiffOffer is a saved diff's status and choices. */
export function hostedDiffOffer(d: HostedDiff): HostedDiffOffer {
  if (d.branch_exists) {
    return {
      status: { label: "Opened as a branch", tone: "success", detail: d.branch ? `Branch ${d.branch}` : undefined },
      canBranch: false,
      branch: d.branch,
    };
  }
  if (d.exact) {
    return {
      status: { label: "Ready to open as a branch", tone: "info", detail: excludedNote(d.excluded) },
      canBranch: true,
      branch: d.branch,
    };
  }
  if (d.no_repository) {
    return {
      status: {
        label: "Saved as a diff file",
        tone: "info",
        detail: "The files came from a folder that is not a git repository, so the changes are this diff file. Review them with Show changes, then apply the file yourself.",
      },
      canBranch: false,
      copy: { label: "Copy the diff path", text: d.path },
    };
  }
  return {
    status: {
      label: "Saved as a file only",
      tone: "warn",
      detail: d.why ? `It cannot be opened as a branch: ${d.why}.` : "It cannot be opened as a branch.",
    },
    canBranch: false,
    copy: { label: "Copy the apply command", text: d.apply_command },
  };
}

/** excludedNote says the files the upload left out stay as committed. */
export function excludedNote(n: number | undefined): string | undefined {
  if (!n || n <= 0) return undefined;
  return n === 1
    ? "1 file was not sent to the box (a secret, a link or too large); the branch keeps it as it is in your commit."
    : `${n} files were not sent to the box (secrets, links or too large); the branch keeps them as they are in your commit.`;
}

/** The plain words of a local copy's return state. */
const LOCAL_STATES: Record<string, (v: LocalReturn) => ReturnStatus> = {
  pending: (v) =>
    v.run_live
      ? { label: "Run still going", tone: "neutral" }
      : { label: "Bringing commits back", tone: "neutral", detail: "This happens a few seconds after the run ends." },
  returned: (v) => ({
    label: v.commits > 0 ? `${v.commits} commit${v.commits === 1 ? "" : "s"} came back` : "Commits came back",
    tone: "success",
    detail: v.ref ? `They are on ${v.ref}; your branch and working tree are unchanged.` : undefined,
  }),
  nothing_new: () => ({ label: "No new commits", tone: "neutral", detail: "The run made no commit to bring back." }),
  refused: (v) => ({ label: "Commits not brought back", tone: "danger", detail: v.reason || undefined }),
  unknown: (v) =>
    v.run_live
      ? { label: "Run still going", tone: "neutral" }
      : { label: "No record of a return", tone: "warn", detail: "Observer did not record whether this copy's commits came back." },
};

/** localReturnStatus is a local row's status line. */
export function localReturnStatus(v: LocalReturn): ReturnStatus {
  if (v.source === "worktree") {
    if (v.run_live) return { label: "Run still going", tone: "neutral" };
    return {
      label: v.branch ? "Branch kept in your repository" : "Kept",
      tone: "info",
      detail: v.kept || (v.branch ? `Branch ${v.branch}` : undefined),
    };
  }
  const rule = LOCAL_STATES[v.state ?? "unknown"] ?? LOCAL_STATES.unknown;
  return rule(v);
}

/** sourceLabel is a local row's workspace kind in plain words. */
export function sourceLabel(source: string): string {
  switch (source) {
    case "clone-local":
      return "Copy of a local folder";
    case "clone-remote":
      return "Copy cloned from a URL";
    case "worktree":
      return "Git worktree";
    default:
      return "Copy";
  }
}

/** The kind of one diff line, for its colour. */
export type DiffLineKind = "file" | "hunk" | "add" | "del" | "meta" | "context";

/** One preview line. */
export type DiffLine = { kind: DiffLineKind; text: string };

/** diffLineKind classifies one line of a unified diff. */
export function diffLineKind(line: string): DiffLineKind {
  if (line.startsWith("diff --git ")) return "file";
  if (line.startsWith("@@")) return "hunk";
  if (line.startsWith("+++ ") || line.startsWith("--- ")) return "meta";
  if (/^(index |new file mode|deleted file mode|old mode|new mode|similarity index|rename from|rename to|GIT binary patch|literal |delta |Binary files )/.test(line)) {
    return "meta";
  }
  if (line.startsWith("+")) return "add";
  if (line.startsWith("-")) return "del";
  return "context";
}

/** diffPreviewLines splits a diff's text into at most max classified lines,
 *  and says whether it stopped early. */
export function diffPreviewLines(text: string, max = 2000): { lines: DiffLine[]; more: boolean } {
  const all = text.split("\n");
  if (all.length > 0 && all[all.length - 1] === "") all.pop();
  const lines = all.slice(0, max).map((t) => ({ kind: diffLineKind(t), text: t }));
  return { lines, more: all.length > max };
}

/** fileStatsLabel sums a diff's files in plain words. */
export function fileStatsLabel(files: DiffFile[]): string {
  if (files.length === 0) return "No files listed";
  let added = 0;
  let deleted = 0;
  let binary = 0;
  for (const f of files) {
    if (f.binary) binary++;
    else {
      added += f.added;
      deleted += f.deleted;
    }
  }
  const parts = [`${files.length} file${files.length === 1 ? "" : "s"}`, `${added} added`, `${deleted} removed`];
  if (binary > 0) parts.push(`${binary} binary`);
  return parts.join(", ");
}

/** actionError reads a refused action's reason from its JSON body, else the
 *  body's text. */
export function actionError(body: string, fallback: string): string {
  try {
    const parsed = JSON.parse(body) as { error?: unknown };
    if (typeof parsed.error === "string" && parsed.error.trim() !== "") return parsed.error;
  } catch {
    // not JSON
  }
  const t = body.trim();
  return t !== "" ? t : fallback;
}

/** CopyTotals sizes the panel's copies: every clone copy, and those the
 *  "Remove all copies that are safe to remove" click may remove. */
export type CopyTotals = { count: number; bytes: number; candidates: number; candidateBytes: number };

/** copyTotals is the panel's copy summary (worktree rows are not copies). */
export function copyTotals(local: LocalReturn[]): CopyTotals {
  const t: CopyTotals = { count: 0, bytes: 0, candidates: 0, candidateBytes: 0 };
  for (const v of local) {
    if (v.source === "worktree" || !v.copy_dir) continue;
    t.count++;
    t.bytes += v.size_bytes;
    // The server's own removal verdict (the one rule the click applies,
    // cmd/observer sandboxCopyVerdict): a copy the click would keep is never
    // counted (D4).
    if (v.removable && v.safe_to_remove === true) {
      t.candidates++;
      t.candidateBytes += v.size_bytes;
    }
  }
  return t;
}

/** sizeLabel is a byte count in plain units. */
export function sizeLabel(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v >= 10 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}

/** removeSafeLabel is the one-click removal's button text. */
export function removeSafeLabel(t: CopyTotals): string {
  return `Remove all copies that are safe to remove (${t.candidates}, ${sizeLabel(t.candidateBytes)})`;
}

/** One copy the click removed or kept (cmd/observer copySweepOutcome). */
export type CopyOutcome = { id: string; origin?: string; bytes: number; reason?: string };

/** The click's answer (cmd/observer copyBulkResult). */
export type CopyBulkResult = { removed: CopyOutcome[]; kept: CopyOutcome[]; freed_bytes: number; left: number };

/** bulkResultLines are the plain words of the click's answer: what was
 *  removed and freed, each kept copy with its reason, and what is left for
 *  another click. */
export function bulkResultLines(r: CopyBulkResult): string[] {
  const lines: string[] = [];
  const n = r.removed.length;
  lines.push(n === 0 ? "No copy was removed." : `Removed ${n} cop${n === 1 ? "y" : "ies"}, freeing ${sizeLabel(r.freed_bytes)}.`);
  for (const k of r.kept) {
    lines.push(`Kept ${k.id}: ${k.reason || "the removal rules keep it"}.`);
  }
  if (r.left > 0) {
    lines.push(`${r.left} more cop${r.left === 1 ? "y was" : "ies were"} not checked this time; click again to check them.`);
  }
  return lines;
}

/** hasAnything reports whether the panel has a row to show. */
export function hasAnything(p: ReturnsPage | null | undefined): boolean {
  return !!p && (p.hosted.length > 0 || p.local.length > 0);
}
