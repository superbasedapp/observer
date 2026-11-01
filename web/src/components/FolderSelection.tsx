import { SinglePicker, Tooltip } from "@/components/primitives";
import type { ProjectRow } from "@/lib/types";

// FolderSelection.tsx holds the Terminals page's Folder Selection pieces
// (RERUN2 D5): the root picker and the observed-project suggestions, OS-aware
// from the node's own reported OS (/api/status.host_os, useHostOS), never a
// guess from the path or the browser.
//
// (b) The operator saved Folder Selection with only work2 added and the
// allow-list also gained an observed project. The page's only way a
// suggestion reaches the list without a click on its own "add" is Enter in
// the root picker, which committed the highlighted row: the first observed
// project whenever nothing had been moved to (the list opens on focus with
// it highlighted). The picker now runs with explicitPick: Enter commits the
// typed path, or a suggestion only after the arrow keys moved onto it.
//
// (c) The hint and the grey styling called every root that does not start
// with "/" foreign; on a Windows node a drive-letter root is the native one.

/** RootKind is how a root reads on the node's own OS. */
export type RootKind = "native" | "foreign" | "unknown";

/**
 * rootKind classifies a root for the node's OS (runtime.GOOS from
 * /api/status.host_os; null or "unknown" while it is not known, when no root
 * is called foreign). Windows: a drive-letter path (C:\ or C:/) is native,
 * a UNC or POSIX path foreign. Every other OS: a "/" path is native.
 */
export function rootKind(root: string, hostOS: string | null): RootKind {
  if (!hostOS || hostOS === "unknown") return "unknown";
  if (hostOS === "windows") return /^[A-Za-z]:[\\/]/.test(root) ? "native" : "foreign";
  return root.startsWith("/") ? "native" : "foreign";
}

/** folderSuggestionHint is the suggestions block's line for the node's OS. */
export function folderSuggestionHint(hostOS: string | null): string {
  const lead = "Suggested from observed projects - add one to allow-list it. Roots are validated on save; ";
  if (!hostOS || hostOS === "unknown") return lead + "a stale or symlink-mismatched root, or one this node cannot use, is rejected there, not here.";
  if (hostOS === "windows") return lead + "a network (UNC) or POSIX path, a stale or a symlink-mismatched root is rejected there, not here.";
  return lead + "a foreign (Windows/UNC), stale, or symlink-mismatched root is rejected there, not here.";
}

/** rootPlaceholder is the picker's placeholder for the node's OS. */
export function rootPlaceholder(hostOS: string | null): string {
  return hostOS === "windows" ? "Pick a project, or type C:\\absolute\\path" : "Pick a project, or type /absolute/path";
}

/** shortenFolder keeps the last two parts of a POSIX or a Windows path. */
export function shortenFolder(p: string): string {
  if (!p) return "-";
  const sep = p.includes("\\") && !p.includes("/") ? "\\" : "/";
  const parts = p.split(/[\\/]/).filter(Boolean);
  if (parts.length <= 2) return p;
  return "..." + sep + parts.slice(-2).join(sep);
}

/** sortSuggestions puts the node's native roots first (stable). */
export function sortSuggestions(projects: ProjectRow[], hostOS: string | null): ProjectRow[] {
  const rank = (r: ProjectRow) => (rootKind(r.root_path, hostOS) === "foreign" ? 1 : 0);
  return [...projects].sort((a, b) => rank(a) - rank(b));
}

/** rootsWithAdded is the allow-list after one explicit add (trimmed, once). */
export function rootsWithAdded(roots: string[], raw: string): string[] {
  const r = raw.trim();
  if (!r || roots.includes(r)) return roots;
  return [...roots, r];
}

/** FolderRootPicker is the root picker: suggestions plus a typed path, with
 *  explicitPick so Enter never adds an untouched suggestion. */
export function FolderRootPicker({
  suggestions,
  roots,
  value,
  onChange,
  disabled,
  hostOS,
  seenHint,
}: {
  suggestions: ProjectRow[];
  roots: string[];
  value: string;
  onChange: (v: string) => void;
  disabled?: boolean;
  hostOS: string | null;
  seenHint: (p: ProjectRow) => string;
}) {
  return (
    <SinglePicker
      className="flex-1"
      options={suggestions
        .filter((proj) => !roots.includes(proj.root_path))
        .map((proj) => ({ id: proj.root_path, label: shortenFolder(proj.root_path), sublabel: seenHint(proj) }))}
      value={value}
      disabled={disabled}
      onChange={onChange}
      allowFree
      explicitPick
      freeLabel="Use path"
      placeholder={rootPlaceholder(hostOS)}
      ariaLabel="Project root to allow"
    />
  );
}

/** FolderSuggestions is the observed-project list, each with its own add. */
export function FolderSuggestions({
  suggestions,
  roots,
  hostOS,
  writable,
  onAdd,
  seenHint,
}: {
  suggestions: ProjectRow[];
  roots: string[];
  hostOS: string | null;
  writable: boolean;
  onAdd: (root: string) => void;
  seenHint: (p: ProjectRow) => string;
}) {
  if (suggestions.length === 0) return null;
  return (
    <div className="mt-3 rounded-2 border border-line-2 bg-bg-3 p-2">
      <div className="mb-1.5 text-[11px] text-fg-3">{folderSuggestionHint(hostOS)}</div>
      <div className="max-h-[220px] space-y-1 overflow-auto">
        {suggestions.map((proj) => {
          const added = roots.includes(proj.root_path);
          const foreign = rootKind(proj.root_path, hostOS) === "foreign";
          return (
            <div key={proj.root_path} className="flex items-center gap-2" data-root-kind={rootKind(proj.root_path, hostOS)}>
              <code
                title={proj.root_path}
                className={`min-w-0 flex-1 truncate rounded-2 border border-line-2 bg-bg-0 px-2 py-1 font-mono text-[11px] ${
                  foreign ? "text-fg-3" : "text-fg-2"
                }`}
              >
                {shortenFolder(proj.root_path)}
              </code>
              <span className="hidden whitespace-nowrap text-[10px] text-fg-3 sm:inline">{seenHint(proj)}</span>
              {/* The wrapper carries the tooltip so it still shows while the
                  button is disabled ("added"). */}
              <Tooltip
                content={
                  foreign
                    ? `${proj.root_path} - not a path this node's OS uses; it will likely be rejected on save`
                    : proj.root_path
                }
              >
                <span className="inline-flex shrink-0">
                  <button
                    type="button"
                    disabled={!writable || added}
                    onClick={() => onAdd(proj.root_path)}
                    className={`shrink-0 rounded-2 border px-2 py-1 text-caption disabled:opacity-40 ${
                      added ? "border-line-2 bg-bg-2 text-fg-3" : "border-accent/50 bg-accent/15 text-accent hover:bg-accent/25"
                    }`}
                  >
                    {added ? "added" : "add"}
                  </button>
                </span>
              </Tooltip>
            </div>
          );
        })}
      </div>
    </div>
  );
}
