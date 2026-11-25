/**
 * The one writer of the SDK-held credential file (plan 3.4): setup only; the
 * runtime SDK never writes it.
 *
 * Create the folder 0700, write a temporary file 0600 with O_EXCL |
 * O_NOFOLLOW, fsync it, rename it over the target, fsync the folder. On
 * Windows, `icacls` runs on the still-empty temporary file to give it an
 * owner-only DACL (this user, SYSTEM, Administrators; ruling R4,
 * destination.md 6a) and to make this user its owner, before the key is
 * written; when the owner cannot be set (an elevated terminal) nothing is
 * written ({@link OWNER_ROWS}). The reader does not check the DACL.
 * The key is never in argv, a log line or an error message.
 */

import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { closeSync, constants as fsConstants, fsyncSync, lstatSync, mkdirSync, openSync, renameSync, rmSync, unlinkSync, writeSync } from "node:fs";
import { dirname } from "node:path";

/** What goes in the file (the lines of contract fixture sdk-credential-file.json). */
export interface HeldRecord {
  key: string;
  gatewayUrl: string;
  destination: "online" | "both";
  dashboardUrl: string;
  expiresAt: string;
}

/** The file's bytes: the key line, then name=value lines, one newline at the end. Pure. */
export function credentialText(r: HeldRecord): string {
  const lines = [r.key, `gateway_url=${r.gatewayUrl}`, `destination=${r.destination}`];
  if (r.dashboardUrl) lines.push(`dashboard_url=${r.dashboardUrl}`);
  if (r.expiresAt) lines.push(`expires_at=${r.expiresAt}`);
  for (const l of lines) if (/[\r\n]/.test(l) || /[^ -~]/.test(l)) throw new Error("setup: a credential line is not one printable ASCII line; nothing was written");
  return lines.join("\n") + "\n";
}

/** The icacls argv that leaves `path` readable by this user, SYSTEM and Administrators only (well-known SIDs, so any locale). Pure. */
export function icaclsArgs(path: string, user: string): string[] {
  return [path, "/inheritance:r", "/grant:r", `${user}:F`, "*S-1-5-18:F", "*S-1-5-32-544:F"];
}

/**
 * The icacls argv that makes this user the file's owner. A file an elevated
 * process creates can be owned by BUILTIN\Administrators, and every SDK's
 * reader refuses a file whose owner SID is not the current user's. Pure.
 */
export function setOwnerArgs(path: string, user: string): string[] {
  return [path, "/setowner", user];
}

/** What the Windows steps on the empty temporary file came to. */
export interface OwnerFacts {
  platform: string;
  /** icacls set the owner-only DACL. */
  daclSet: boolean;
  /** icacls made this user the owner. */
  ownerSet: boolean;
}

/** The writer's decision: write, write and warn, or refuse (no key is written). */
export type OwnerDecision = { kind: "write" } | { kind: "warn"; message: string } | { kind: "refuse"; message: string };

interface OwnerRow {
  id: string;
  when: (f: OwnerFacts) => boolean;
  decide: (path: string) => OwnerDecision;
}

/**
 * The owner rule table (lead ruling, from L6: the readers check the owner
 * SID), walked top down. Unix needs no step: the file is created by this
 * uid, mode 0600.
 */
export const OWNER_ROWS: readonly OwnerRow[] = [
  { id: "unix", when: (f) => f.platform !== "win32", decide: () => ({ kind: "write" }) },
  {
    id: "owner_not_set",
    when: (f) => !f.ownerSet,
    decide: (path) => ({
      kind: "refuse",
      message: `could not make your account the owner of ${path} (a terminal run as administrator creates files owned by Administrators, which the SDKs refuse to read); run setup again from a normal, non-elevated terminal`,
    }),
  },
  {
    id: "dacl_not_set",
    when: (f) => !f.daclSet,
    decide: (path) => ({ kind: "warn", message: `could not limit ${path} to your account with icacls; it is in your own %LOCALAPPDATA%, but check its permissions` }),
  },
  { id: "both_set", when: () => true, decide: () => ({ kind: "write" }) },
];

/** Decide from the facts (pure). */
export function ownerDecision(f: OwnerFacts, path: string): OwnerDecision & { row: string } {
  for (const r of OWNER_ROWS) if (r.when(f)) return { ...r.decide(path), row: r.id };
  return { kind: "write", row: "none" };
}

/** Dependencies the writer takes (tests replace the Windows step). */
export interface WriteDeps {
  platform: string;
  /** The Windows account name for icacls (DOMAIN\user). */
  windowsUser: () => string;
  /** Run icacls; throws on failure. */
  icacls: (args: string[]) => void;
}

export const defaultWriteDeps: WriteDeps = {
  platform: process.platform,
  windowsUser: () => {
    const user = process.env.USERNAME ?? "";
    const domain = process.env.USERDOMAIN ?? "";
    return domain ? `${domain}\\${user}` : user;
  },
  icacls: (args) => {
    execFileSync("icacls", args, { stdio: "ignore", windowsHide: true, timeout: 15_000 });
  },
};

/**
 * Write the file atomically and owner-only. Returns a warning ("" when none):
 * on Windows, when icacls could not set the DACL (the file is still written).
 * Throws, writing nothing, when the owner cannot be set on Windows.
 * Throws with a message that names the path, never the content.
 */
export function writeCredentialFile(path: string, r: HeldRecord, deps: WriteDeps = defaultWriteDeps): string {
  const text = credentialText(r);
  const dir = dirname(path);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  // A link where the file goes is never followed: the rename replaces the link itself.
  try {
    if (lstatSync(dir).isSymbolicLink()) throw new Error(`setup: ${dir} is a link; refusing to write the credential there`);
  } catch (err) {
    if ((err as { code?: string }).code !== "ENOENT") throw err;
  }
  const tmp = `${path}.tmp-${process.pid}-${randomBytes(6).toString("hex")}`;
  const flags = fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | (deps.platform === "win32" ? 0 : (fsConstants.O_NOFOLLOW ?? 0));
  let fd = -1;
  let warning = "";
  try {
    fd = openSync(tmp, flags, 0o600);
    if (deps.platform === "win32") {
      // The owner-only DACL and this user as the owner go on the empty
      // temporary file, before the key is in it.
      closeSync(fd);
      fd = -1;
      const user = deps.windowsUser();
      const run = (args: string[]) => {
        try {
          deps.icacls(args);
          return true;
        } catch {
          return false;
        }
      };
      const facts: OwnerFacts = { platform: deps.platform, daclSet: run(icaclsArgs(tmp, user)), ownerSet: run(setOwnerArgs(tmp, user)) };
      const d = ownerDecision(facts, path);
      if (d.kind === "refuse") throw Object.assign(new Error(d.message), { refused: true });
      if (d.kind === "warn") warning = d.message;
      fd = openSync(tmp, fsConstants.O_WRONLY | fsConstants.O_TRUNC);
    }
    writeSync(fd, text, 0, "latin1");
    fsyncSync(fd);
    closeSync(fd);
    fd = -1;
    renameSync(tmp, path);
  } catch (err) {
    if (fd >= 0) {
      try {
        closeSync(fd);
      } catch {
        // ignore
      }
    }
    try {
      unlinkSync(tmp);
    } catch {
      // not there
    }
    if ((err as { refused?: boolean }).refused) throw new Error(`setup: ${(err as Error).message}`);
    throw new Error(`setup: could not write ${path}: ${(err as { code?: string }).code ?? (err instanceof Error ? err.message : "error")}`);
  }
  if (deps.platform !== "win32") {
    try {
      const dfd = openSync(dir, fsConstants.O_RDONLY);
      try {
        fsyncSync(dfd);
      } finally {
        closeSync(dfd);
      }
    } catch {
      // a folder fsync is best effort
    }
  }
  return warning;
}

/** Remove the file (setup --forget). Returns whether one was removed. */
export function removeCredentialFile(path: string): boolean {
  try {
    lstatSync(path);
  } catch {
    return false;
  }
  rmSync(path, { force: true });
  return true;
}
