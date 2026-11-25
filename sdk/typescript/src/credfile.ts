/**
 * The SDK-held credential file (plan 3.4; contract destination.md section
 * 6a): where `setup` keeps the member's SDK key on this computer, read by the
 * SDK itself, so an app needs no Observer and no environment variable.
 *
 * Path, first set wins:
 *
 * | OS | path |
 * | any | SUPERBASED_CREDENTIAL_FILE |
 * | Linux, macOS | `$XDG_CONFIG_HOME/superbased/sdk-credential`, else `~/.config/superbased/sdk-credential` |
 * | Windows | `%LOCALAPPDATA%\superbased\sdk-credential` |
 *
 * Format (contract section 6): the first line `<key_id>.<secret>`, then
 * `name=value` lines, at most 4096 bytes, printable ASCII, unknown names
 * ignored. Names read here: `gateway_url` (the only address the key is sent
 * to), `destination` (`online` or `both`), `dashboard_url` (links only, never
 * a place the key goes), `expires_at` (RFC 3339).
 *
 * Read rules. Unix: not a symlink, a regular file, no group or other bits,
 * owned by this user (section 6, unchanged). Windows (ruling R4): not a
 * reparse point, a regular file, under this user's %LOCALAPPDATA%; `setup`
 * gives it an owner-only DACL when it writes it, and the reader does not
 * check the DACL. The runtime never writes the file.
 */

import { closeSync, constants as fsConstants, fstatSync, lstatSync, openSync, readFileSync } from "node:fs";
import { posix, win32 } from "node:path";

import { trimSlash, type DestinationChoice } from "./config.js";

/** The variable that replaces the path (a different user, a test). */
export const CREDENTIAL_FILE_ENV = "SUPERBASED_CREDENTIAL_FILE";
/** The folder and file name under the per-OS config root. */
export const SDK_CREDENTIAL_DIR = "superbased";
export const SDK_CREDENTIAL_NAME = "sdk-credential";
/** The largest credential file read. */
export const CREDENTIAL_FILE_MAX = 4096;
/** Days before expiry the SDK starts saying so. */
export const EXPIRY_WARNING_DAYS = 14;

/** What the path ladder reads. */
export interface PathFacts {
  platform: string;
  env: Record<string, string | undefined>;
  home: string;
}

/** The SDK-held file's path for these facts (pure). */
export function sdkCredentialPath(f: PathFacts): string {
  const override = (f.env[CREDENTIAL_FILE_ENV] ?? "").trim();
  if (override) return override;
  if (f.platform === "win32") {
    // No LOCALAPPDATA: no default path (the file is absent).
    const base = (f.env.LOCALAPPDATA ?? "").trim();
    return base ? win32.join(base, SDK_CREDENTIAL_DIR, SDK_CREDENTIAL_NAME) : "";
  }
  const xdg = (f.env.XDG_CONFIG_HOME ?? "").trim();
  // The XDG spec ignores a relative XDG_CONFIG_HOME.
  const base = xdg && posix.isAbsolute(xdg) ? xdg : f.home ? posix.join(f.home, ".config") : "";
  return base ? posix.join(base, SDK_CREDENTIAL_DIR, SDK_CREDENTIAL_NAME) : "";
}

/** The folder the Windows reader requires the file to be under (%LOCALAPPDATA%). */
export function windowsCredentialRoot(f: PathFacts): string {
  return (f.env.LOCALAPPDATA ?? "").trim();
}

/** One credential record: a key and the addresses that travel with it. */
export interface CredentialRecord {
  /** `<key_id>.<secret>`. */
  key: string;
  keyId: string;
  /** The only address the key is sent to ("" when the file names none, or one that was refused). */
  gateway: string;
  /** `online` or `both` ("" when absent or refused). */
  destination: DestinationChoice | "";
  /** The dashboard base for links ("" when absent or refused). */
  dashboardUrl: string;
  /** RFC 3339 ("" when absent or refused). */
  expiresAt: string;
}

/** Why a file was refused (credential-file-cases.json `reasons`, a closed vocabulary). */
export type RefusedReason =
  | "symlink"
  | "not_regular"
  | "mode"
  | "owner"
  | "too_large"
  | "empty"
  | "bad_key_line"
  | "bad_name_line"
  | "reparse_point"
  | "outside_localappdata"
  | "unreadable";

/** The outcome of reading one file: a record, or why it was refused, and lines that were ignored. */
export interface CredentialRead {
  record: CredentialRecord | null;
  /** Why the file was refused, in words ("" when it was read or is absent). */
  error: string;
  /** Why it was refused, as a reason ("" when it was read or is absent). */
  reason: RefusedReason | "";
  /** Lines that were ignored, and why (the file itself was used). */
  warnings: string[];
  /** The names whose values were ignored (`gateway_url`, `destination`, `dashboard_url`, `expires_at`). */
  ignored: string[];
}

/** Whether a URL's host is loopback. */
function loopback(url: URL): boolean {
  const h = url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  return h === "localhost" || h === "::1" || /^127\.\d+\.\d+\.\d+$/.test(h);
}

/**
 * Why `url` is not a usable gateway base for the key ("" when it is): https
 * (or http to a loopback host), a host, no user info, query, fragment or path.
 */
export function gatewayProblem(url: string): string {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return `${JSON.stringify(url)} is not a URL`;
  }
  if ((u.protocol !== "http:" && u.protocol !== "https:") || !u.hostname) return `${JSON.stringify(url)} is not an http(s) address with a host`;
  if (u.username || u.password) return `${JSON.stringify(url)} carries a user name or password`;
  if (u.search || u.hash || (u.pathname !== "/" && u.pathname !== "")) return `${JSON.stringify(url)} is not a base address`;
  if (u.protocol !== "https:" && !loopback(u)) return `${JSON.stringify(url)} is plain http to a remote host`;
  return "";
}

/** Why `url` is not a usable dashboard base for links ("" when it is): https with a host, no user info, path, query or fragment. */
export function dashboardProblem(url: string): string {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return `${JSON.stringify(url)} is not a URL`;
  }
  if (u.protocol !== "https:" || !u.hostname) return `${JSON.stringify(url)} is not https`;
  if (u.username || u.password) return `${JSON.stringify(url)} carries a user name or password`;
  if (u.search || u.hash || (u.pathname !== "/" && u.pathname !== "")) return `${JSON.stringify(url)} is not a base address`;
  return "";
}

/**
 * Parse a credential file's text (contract section 6, plus section 6a's
 * names). The key line and the line shapes are strict (a bad one refuses the
 * file); a bad value of a known name only drops that name, with a warning.
 */
export function parseCredentialText(raw: string, path: string): CredentialRead {
  const refuse = (reason: RefusedReason, error: string): CredentialRead => ({ record: null, error, reason, warnings: [], ignored: [] });
  if (raw.length > CREDENTIAL_FILE_MAX) return refuse("too_large", `credential file ${path} is too large; refused`);
  if (raw.length === 0) return refuse("empty", `credential file ${path} is empty; refused`);
  const lines = (raw.endsWith("\n") ? raw.slice(0, -1) : raw).split("\n").map((l) => (l.endsWith("\r") ? l.slice(0, -1) : l));
  const bad = `credential file ${path} is not one <key_id>.<secret> line followed by name=value lines; refused`;
  const key = lines[0] ?? "";
  if (/[^ -~]/.test(key)) return refuse("bad_key_line", `credential file ${path} has non-ASCII content in its key line; refused`);
  if (!/^[^\s.]+\.\S+$/.test(key)) return refuse("bad_key_line", bad);
  const values: Record<string, string> = {};
  for (const line of lines.slice(1)) {
    if (/[^ -~\t]/.test(line)) return refuse("bad_name_line", `credential file ${path} has non-ASCII content; refused`);
    const eq = line.indexOf("=");
    if (eq <= 0) return refuse("bad_name_line", bad);
    values[line.slice(0, eq)] = line.slice(eq + 1).trim();
  }
  const warnings: string[] = [];
  const ignored: string[] = [];
  const drop = (name: string, why: string) => {
    ignored.push(name);
    warnings.push(`credential file ${path}: ${why}; it is ignored`);
  };
  const rec: CredentialRecord = { key, keyId: key.slice(0, key.indexOf(".")), gateway: "", destination: "", dashboardUrl: "", expiresAt: "" };
  if ("gateway_url" in values) {
    const problem = gatewayProblem(values.gateway_url);
    if (problem) drop("gateway_url", `the gateway address is not usable (${problem})`);
    else rec.gateway = trimSlash(values.gateway_url);
  }
  if ("destination" in values) {
    const d = values.destination.toLowerCase();
    if (d === "online" || d === "both") rec.destination = d;
    else drop("destination", `destination ${JSON.stringify(values.destination)} is not online or both`);
  }
  if ("dashboard_url" in values) {
    const problem = dashboardProblem(values.dashboard_url);
    if (problem) drop("dashboard_url", `the dashboard address is not usable (${problem})`);
    else rec.dashboardUrl = trimSlash(values.dashboard_url);
  }
  if ("expires_at" in values) {
    if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/.test(values.expires_at) && !Number.isNaN(Date.parse(values.expires_at))) {
      rec.expiresAt = values.expires_at;
    } else {
      drop("expires_at", `expires_at ${JSON.stringify(values.expires_at)} is not an RFC 3339 time with a zone`);
    }
  }
  return { record: rec, error: "", reason: "", warnings, ignored };
}

/** Normalised for a containment check: forward slashes, no trailing slash, case folded on Windows. */
function folded(p: string, platform: string): string {
  const s = p.split("\\").join("/").replace(/\/+$/, "");
  return platform === "win32" ? s.toLowerCase() : s;
}

/** Whether `path` is inside `root` (a containment check on the written paths). */
export function inside(path: string, root: string, platform: string): boolean {
  if (!root) return false;
  const p = folded(platform === "win32" ? win32.resolve(path) : posix.resolve(path), platform);
  const r = folded(platform === "win32" ? win32.resolve(root) : posix.resolve(root), platform);
  return p.startsWith(r + "/");
}

/** Options of {@link readCredentialRecord}. */
export interface ReadOptions {
  /** `process.platform` (tests pass `win32`). */
  platform?: string;
  /** Windows: the folder the file must be under (%LOCALAPPDATA%). */
  windowsRoot?: string;
  /** The uid the file must belong to (unix; default: this process's). */
  uid?: number;
  /**
   * Windows: whether the file's owner SID is this user's. Node has no API for
   * a file's owner SID, so by default it is not checked (the writer leaves the
   * file an owner-only DACL); a caller that can check passes this.
   */
  ownerIsSelf?: (path: string) => boolean;
}

/**
 * Read a credential file under the rules for this OS (see the module
 * comment). A missing file is `{ record: null, error: "" }`: no file is not
 * an error. Never throws.
 */
export function readCredentialRecord(path: string, opts: ReadOptions = {}): CredentialRead {
  const none: CredentialRead = { record: null, error: "", reason: "", warnings: [], ignored: [] };
  if (!path) return none;
  const platform = opts.platform ?? process.platform;
  const refuse = (reason: RefusedReason, error: string): CredentialRead => ({ record: null, error, reason, warnings: [], ignored: [] });
  try {
    let st;
    try {
      st = lstatSync(path);
    } catch (err) {
      if ((err as { code?: string }).code === "ENOENT") return none;
      throw err;
    }
    if (platform === "win32") {
      // Node reports symlinks and junctions (reparse points) as symbolic links.
      if (st.isSymbolicLink()) return refuse("reparse_point", `credential file ${path} is a reparse point (a link); refused`);
      if (!st.isFile()) return refuse("not_regular", `credential file ${path} is not a regular file; refused`);
      if (!inside(path, opts.windowsRoot ?? "", platform)) return refuse("outside_localappdata", `credential file ${path} is not under this user's %LOCALAPPDATA%; refused`);
      if (opts.ownerIsSelf && !opts.ownerIsSelf(path)) return refuse("owner", `credential file ${path} is not owned by this user; refused`);
    } else {
      if (st.isSymbolicLink()) return refuse("symlink", `credential file ${path} is a symlink; refused`);
      if (!st.isFile()) return refuse("not_regular", `credential file ${path} is not a regular file; refused`);
      if ((st.mode & 0o077) !== 0) return refuse("mode", `credential file ${path} is readable by others (mode ${(st.mode & 0o777).toString(8)}); refused`);
      const uid = opts.uid ?? (typeof process.getuid === "function" ? process.getuid() : -1);
      if (uid >= 0 && st.uid !== uid) return refuse("owner", `credential file ${path} is not owned by this user; refused`);
    }
    if (st.size > CREDENTIAL_FILE_MAX) return refuse("too_large", `credential file ${path} is too large; refused`);
    // Open without following a symlink swapped in after the lstat, and read the
    // descriptor that is checked.
    const fd = openSync(path, fsConstants.O_RDONLY | (platform === "win32" ? 0 : (fsConstants.O_NOFOLLOW ?? 0)));
    let raw: string;
    try {
      const fst = fstatSync(fd);
      if (!fst.isFile() || (platform !== "win32" && (fst.ino !== st.ino || fst.dev !== st.dev))) {
        return refuse("not_regular", `credential file ${path} changed while it was read; refused`);
      }
      raw = readFileSync(fd, "latin1");
    } finally {
      closeSync(fd);
    }
    return parseCredentialText(raw, path);
  } catch (err) {
    return refuse("unreadable", `credential file ${path}: ${(err as { code?: string }).code ?? String(err)}`);
  }
}

/** The SDK-held file as this process sees it: where it is and what reading it gave. */
export interface SdkFileState extends CredentialRead {
  path: string;
  /** The file exists (read or refused). */
  present: boolean;
}

/** Locate and read the SDK-held file for this process. Never throws. */
export function readSdkCredentialFile(env: Record<string, string | undefined>, home: string, platform: string = process.platform): SdkFileState {
  const facts: PathFacts = { platform, env, home };
  const path = sdkCredentialPath(facts);
  if (!path) return { path: "", present: false, record: null, error: "", reason: "", warnings: [], ignored: [] };
  const read = readCredentialRecord(path, { platform, windowsRoot: windowsCredentialRoot(facts) });
  return { path, present: !!(read.record || read.error), ...read };
}

/** Whether a key with this `expires_at` has expired at `now` (false when unknown). */
export function expired(expiresAt: string, now: number = Date.now()): boolean {
  const at = expiresAt ? Date.parse(expiresAt) : NaN;
  return !Number.isNaN(at) && at <= now;
}

/** The line to say about a key's expiry at `now` ("" when it is not within 14 days). */
export function expiryNote(expiresAt: string, path: string, now: number = Date.now()): string {
  if (!expiresAt) return "";
  const at = Date.parse(expiresAt);
  if (Number.isNaN(at)) return "";
  const fix = "run setup again to get a new one (`npx @superbased/sdk setup --online --replace`)";
  if (at <= now) return `your SDK key (${path}) expired on ${expiresAt}, so nothing is sent online; ${fix}`;
  const days = Math.ceil((at - now) / 86_400_000);
  if (days <= EXPIRY_WARNING_DAYS) return `your SDK key (${path}) expires on ${expiresAt}, in ${days} day${days === 1 ? "" : "s"}; ${fix}`;
  return "";
}
