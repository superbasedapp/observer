// defaultWorkspace is the pure model behind the "Default workspace" card
// (DefaultWorkspaceCard.tsx) and the hosted sandbox consent step's folder
// picker: Observer's own scratch folder for steps that need a folder that is
// not one of your projects. The daemon owns the rules
// (internal/defaultworkspace, GET/PUT /api/workspace/default); this file
// mirrors only the shape checks so the card can answer before a round trip.
//
// Imports only another import-free lib file, so it runs under the node test
// runner.

import { isAbsolutePath } from "./launchToolPaths.ts";

export const DEFAULT_WORKSPACE_PATH = "/api/workspace/default";

/** GET /api/workspace/default. */
export type DefaultWorkspaceView = {
  /** The folder ("" only when no home folder resolves and none is set). */
  dir: string;
  /** dir is the built-in folder. */
  builtin: boolean;
  /** <home>/observer-workspace. */
  builtin_dir: string;
  /** The saved value; "" means the built-in folder. */
  configured: string;
  /** A folder is there now. */
  exists: boolean;
  /** Observer finished setting it up: its marker file and its own git
   *  repository, which the hosted consent screen needs. */
  ready: boolean;
  /** What keeps the folder from being used, in plain words; absent when it
   *  is ready, or missing and fine. */
  problem?: string;
  confirm_token?: string;
  config_etag?: string;
};

/** The longest path the daemon stores. */
export const DEFAULT_WORKSPACE_MAX_BYTES = 4096;

/** The first shape problem with a typed folder, or "" when it looks fine. */
export function folderProblem(raw: string): string {
  const p = raw.trim();
  if (p === "") return "Enter the full path of a folder.";
  if (new TextEncoder().encode(p).length > DEFAULT_WORKSPACE_MAX_BYTES) {
    return `That path is longer than ${DEFAULT_WORKSPACE_MAX_BYTES} bytes.`;
  }
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(p)) return "That path contains a control character.";
  if (!isAbsolutePath(p)) return "The folder must be a full path (start at the drive or at /), not a relative one.";
  return "";
}

/** The PUT body: a folder sets it, null goes back to the built-in folder. */
export function putBody(dir: string | null): { dir: string | null } {
  return { dir: dir === null ? null : dir.trim() };
}

/** The words under the card title. */
export const CARD_SUB =
  "A scratch folder Observer uses when a step needs a folder that is not one of your projects, so that work never lands in a project. Observer creates it when it starts, with a small marker file and its own git repository so the hosted consent screen can list it.";

/** The line under the current folder. */
export function statusLine(v: DefaultWorkspaceView): string {
  if (v.problem) return v.problem;
  const which = v.builtin ? "The built-in folder." : "A folder you chose.";
  return v.exists ? which : `${which} It is created the next time Observer starts or when you save it here.`;
}

/** The sentence after a successful save; a daemon warning (the folder is
 *  there but git could not set it up) replaces the "ready" words. */
export function savedWords(reset: boolean, warning?: string): string {
  if (warning) return `${reset ? "Back to the built-in folder." : "Saved."} ${warning}`;
  return reset ? "Back to the built-in folder." : "Saved. The folder is ready.";
}

/** The consent picker's label for the default workspace row. */
export const WORKSPACE_OPTION_LABEL = "Observer workspace";

/** The consent picker's note under the folder choice. */
export const CONSENT_FOLDER_NOTE =
  "Defaults to the Observer workspace, a scratch folder that is not one of your projects. Pick a project instead to agree to uploading that project. The consent screen lists exactly what would leave this machine; your home folder is never uploaded.";

/**
 * consentDefault is the folder the consent step starts on: the default
 * workspace when the daemon reports it ready (it passes the rules and is its
 * own git repository with the marker), else nothing (the person picks; a
 * project is never chosen for them).
 */
export function consentDefault(v: DefaultWorkspaceView | null | undefined): string {
  if (!v || !v.dir || v.problem || !v.ready) return "";
  return v.dir;
}
