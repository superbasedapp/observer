// sandboxHostedUpload.ts is the pure half of the Hosted sandboxes panel's
// "folders that are not git repositories" block
// (components/sandboxHosted/HostedUploadFields.tsx, decision SBXD-8): the
// shipped default and the extra ignore patterns' editing and checks, the
// same rules the daemon's config validation applies on save
// (validateHostedUploadIgnore). No fetch and no React here.

/** The daemon's default for upload_non_git (on). */
export const UPLOAD_NON_GIT_DEFAULT = true;

/** The caps the daemon applies to the extra patterns. */
export const UPLOAD_IGNORE_MAX = 200;
export const UPLOAD_IGNORE_LEN = 256;

/** uploadNonGitOn reads the key, a daemon that predates it meaning the default. */
export function uploadNonGitOn(v: boolean | undefined): boolean {
  return v ?? UPLOAD_NON_GIT_DEFAULT;
}

/**
 * ignoreLines turns the textarea's text into the saved list: one pattern
 * per line, trimmed, blank lines dropped (the daemon trims and drops them
 * too).
 */
export function ignoreLines(text: string): string[] {
  return text
    .replace(/\r/g, "")
    .split("\n")
    .map((s) => s.trim())
    .filter((s) => s !== "");
}

/**
 * ignoreProblem is the first pattern the daemon would refuse, in plain
 * words, or null.
 */
export function ignoreProblem(list: string[]): string | null {
  if (list.length > UPLOAD_IGNORE_MAX) return `At most ${UPLOAD_IGNORE_MAX} patterns.`;
  for (const p of list) {
    if (p.length > UPLOAD_IGNORE_LEN) return `A pattern is longer than ${UPLOAD_IGNORE_LEN} characters.`;
    // eslint-disable-next-line no-control-regex
    if (/[\u0000-\u001f\u007f]/.test(p)) return "A pattern holds a control character.";
    if (p.startsWith("#")) return `"${p}" reads as a comment; write \\# for a name that starts with #.`;
    if (p === "!" || p === "/" || p === "!/") return `"${p}" names nothing.`;
  }
  return null;
}
