// artifactFolders - the wire types and the plain-words helpers of the
// Scanners card's artifact folders row (OS and CI vulnerability scanning
// plan section 14.6, M3L-2 item 4; operator ruling 2026-11-05): a project's
// candidate build output folders, found by folder name and file header only,
// each off until the developer turns it on. GET and PUT
// /api/security/artifacts?project=<root hash>.

/** One candidate folder of a project. */
export type ArtifactFolder = {
  /** Relative to the project root, forward slashes. */
  dir: string;
  /** The developer turned it on: every scan of the project reads it. */
  enabled: boolean;
  /** On the default list (bin, dist, target/release). */
  default?: boolean;
  /** False for a folder turned on that no longer exists. */
  present: boolean;
  /** What the file headers say it holds ("2 ELF executables, 1 JAR"). */
  summary: string;
  counts?: Record<string, number>;
  bytes?: number;
  truncated?: boolean;
};

/** GET /api/security/artifacts. */
export type ArtifactFolders = {
  project: string;
  folders: ArtifactFolder[];
  /** What turning a folder on does (the CLI's words). */
  text: string;
  /** False where the SCALIBR driver, which reads artifacts, is not linked. */
  driver_compiled: boolean;
  confirm_token?: string;
};

/** artifactStateLine is a folder's state in words. */
export function artifactStateLine(f: ArtifactFolder): string {
  if (f.enabled && !f.present) return "on, but the folder is gone";
  return f.enabled ? "on: every scan reads it" : "off: never opened";
}

/** artifactCounts is how many folders are on and how many are offered. */
export function artifactCounts(v: Pick<ArtifactFolders, "folders">): { on: number; total: number } {
  return { on: v.folders.filter((f) => f.enabled).length, total: v.folders.length };
}

/** artifactHeading is the row's one-line state. */
export function artifactHeading(v: Pick<ArtifactFolders, "folders" | "driver_compiled">): string {
  if (!v.driver_compiled) return "The SCALIBR driver, which reads build artifacts, is not in this build.";
  const { on, total } = artifactCounts(v);
  if (total === 0) return "No build output folders found in this project.";
  return `${on} of ${total} folder${total === 1 ? "" : "s"} on. A folder is never opened until you turn it on.`;
}
