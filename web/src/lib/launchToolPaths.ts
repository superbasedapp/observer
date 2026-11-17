// launchToolPaths is the pure model behind Settings > Session attach > "Launch binary
// paths" (LaunchToolPathsCard.tsx): the [launch.tools.<tool>].path overrides
// that make `observer <tool>` run a specific program instead of resolving one.
// It owns the row view, the client-side path checks (mirroring the daemon's
// rule table in internal/intelligence/dashboard/launch_tool_paths.go, which
// stays the authority), the PUT body and the words.
//
// No imports, so it runs under the node test runner.

export const LAUNCH_TOOL_PATHS_PATH = "/api/launch/tool-paths";

/** One row of GET /api/launch/tool-paths. */
export type LaunchToolPathRow = { tool: string; path: string; exists: boolean };

/** GET /api/launch/tool-paths. */
export type LaunchToolPathsView = {
  paths: LaunchToolPathRow[];
  confirm_token?: string;
  config_etag?: string;
};

/** The longest path the daemon stores. */
export const LAUNCH_TOOL_PATH_MAX_BYTES = 4096;

/** A POSIX absolute path, a Windows drive path (C:\ or C:/) or a UNC share. */
export function isAbsolutePath(p: string): boolean {
  return p.startsWith("/") || /^[A-Za-z]:[\\/]/.test(p) || /^\\\\[^\\/]+[\\/][^\\/]+/.test(p);
}

/** The first thing wrong with a path in plain words, or "" when it looks fine. */
export function pathProblem(raw: string): string {
  const p = raw.trim();
  if (p === "") return "Enter the full path to the program.";
  if (new TextEncoder().encode(p).length > LAUNCH_TOOL_PATH_MAX_BYTES) {
    return `That path is longer than ${LAUNCH_TOOL_PATH_MAX_BYTES} bytes.`;
  }
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(p)) return "That path contains a control character.";
  if (!isAbsolutePath(p)) return "The path must be absolute (start at the drive or at /), not relative.";
  return "";
}

/** The PUT body: a path sets the override, null removes it. */
export function putBody(tool: string, path: string | null): { tool: string; path: string | null } {
  return { tool, path: path === null ? null : path.trim() };
}

/** A row as the card shows it. */
export type LaunchToolPathItem = LaunchToolPathRow & { nothingThere: boolean; note: string };

/** Rows sorted by tool, each with the pill flag and its sentence. */
export function pathItems(rows: readonly LaunchToolPathRow[] | null | undefined): LaunchToolPathItem[] {
  return [...(rows ?? [])]
    .sort((a, b) => a.tool.localeCompare(b.tool))
    .map((r) => ({
      ...r,
      nothingThere: !r.exists,
      note: r.exists
        ? "Launches use this program instead of looking one up."
        : "Nothing is there, so launches of this tool will not start. Change or remove the path.",
    }));
}

/** Tools offered for a new override: launchable ones without an override yet. */
export function addableTools(
  launchable: readonly string[] | null | undefined,
  rows: readonly LaunchToolPathRow[] | null | undefined,
): string[] {
  const have = new Set((rows ?? []).map((r) => r.tool));
  return [...new Set(launchable ?? [])].filter((t) => t && !have.has(t)).sort((a, b) => a.localeCompare(b));
}

/** The words under the card title. */
export const CARD_SUB =
  "By default Observer finds each tool on your PATH. Set a path here to launch a specific program instead. It applies to the next launch.";

/** The sentence after a successful save. */
export function savedWords(restartRequired: boolean, removed: boolean): string {
  const what = removed ? "Removed. Launches look the tool up again." : "Saved.";
  return restartRequired ? `${what} Restart the daemon to apply it.` : `${what} It applies to the next launch.`;
}
