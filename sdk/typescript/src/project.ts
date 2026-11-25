/**
 * The service name from the project (plan 3.2; sdk-api-surface.md section
 * 15). One ladder, first set wins:
 *
 * | # | source | `serviceNameSource` | normalised |
 * | 1 | the `serviceName` option (trimmed; blank is unset) | `argument` | no |
 * | 2 | SUPERBASED_SERVICE_NAME, OTEL_SERVICE_NAME, `service.name` in OTEL_RESOURCE_ATTRIBUTES | `env` | no |
 * | 3 | `name` of the nearest package.json at or above the entry script's folder, the npm scope dropped (`@acme/bot` is `bot`) | `manifest` | yes |
 * | 4 | the entry script's folder name, walking up past generic folders (`src`, `app`, `dist`, `build`, `bin`, `lib`) | `entry_dir` | yes |
 * | 5 | `custom-app` | `default` | no |
 *
 * Normalising (rungs 3 and 4): lowercase, every character outside
 * `[a-z0-9._-]` becomes `-`, runs of `-` become one, leading and trailing
 * `-`, `.` and `_` are trimmed, at most 64 characters (cut, then trimmed
 * again); an empty result skips the rung. Rung 3 stops at the first
 * package.json it finds (a nameless one skips to rung 4, no further search),
 * looks in at most 8 folders and never above the home folder or the root.
 * Rung 4 never names the service after the root or the home folder. With no
 * entry script, both start from the working directory.
 *
 * `serviceNameLadder` is pure over plain facts; `projectFacts` is the one
 * place that reads the disk (at most one file per folder) and never throws.
 */

import { readFileSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, sep } from "node:path";

/** The SDK's built-in service name. */
export const DEFAULT_SERVICE_NAME = "custom-app";
/** Folders that say nothing about the project, so the ladder looks one up. */
export const GENERIC_DIRS: readonly string[] = ["src", "app", "dist", "build", "bin", "lib"];
/** How many folders `projectFacts` climbs looking for a package.json. */
export const MANIFEST_SEARCH_DEPTH = 8;
/** The longest normalised project name. */
export const SERVICE_NAME_MAX = 64;

/** What the project says about itself (the ladder's rungs 3 and 4). */
export interface ProjectFacts {
  /** `name` of the nearest package.json at or above the entry script's folder ("" when none, or it has no name). */
  manifestName: string;
  /** The entry script's folder (or the working directory), as a path ("" when unknown). */
  entryDir: string;
  /** The user's home folder ("" when unknown): never a service name. */
  home?: string;
}

export type ServiceNameSource = "argument" | "env" | "manifest" | "entry_dir" | "default";

/** A project-derived name as a service name: lowercase, `[a-z0-9._-]`, at most 64 characters ("" when nothing is left). */
export function normaliseServiceName(raw: string): string {
  const s = raw
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/-{2,}/g, "-")
    .replace(/^[-._]+|[-._]+$/g, "");
  return s.slice(0, SERVICE_NAME_MAX).replace(/[-._]+$/g, "");
}

/** An npm package name without its scope (`@acme/bot` is `bot`). */
export function stripScope(name: string): string {
  const n = name.trim();
  return n.startsWith("@") && n.includes("/") ? n.slice(n.indexOf("/") + 1) : n;
}

function pathParts(p: string): string[] {
  return p.split(/[\\/]+/).filter(Boolean);
}

/**
 * The entry folder's name, generic folders walked up; "" when only the root,
 * a drive or the home folder (or a folder above it) is left.
 */
export function entryDirName(entryDir: string, home = ""): string {
  const parts = pathParts(entryDir);
  const homeParts = pathParts(home);
  const isHomeOrAbove = (n: number) => homeParts.length > 0 && n <= homeParts.length && parts.slice(0, n).join("/").toLowerCase() === homeParts.slice(0, n).join("/").toLowerCase();
  for (let i = parts.length - 1; i >= 0; i--) {
    const p = parts[i];
    if (/^[A-Za-z]:$/.test(p)) return ""; // a Windows drive
    if (isHomeOrAbove(i + 1)) return "";
    if (!GENERIC_DIRS.includes(p.toLowerCase())) return p;
  }
  return "";
}

function parseKv(raw: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  for (const member of (raw ?? "").split(",")) {
    const i = member.indexOf("=");
    if (i < 0) continue;
    let k = member.slice(0, i).trim();
    let v = member.slice(i + 1).trim();
    try {
      k = decodeURIComponent(k);
      v = decodeURIComponent(v);
    } catch {
      // keep as written
    }
    if (k) out[k] = v;
  }
  return out;
}

/** The ladder, pure: the name and the rung it came from. */
export function serviceNameLadder(
  explicit: string | undefined,
  env: Record<string, string | undefined>,
  project?: ProjectFacts | null,
): { name: string; source: ServiceNameSource } {
  if (explicit && explicit.trim()) return { name: explicit.trim(), source: "argument" };
  for (const k of ["SUPERBASED_SERVICE_NAME", "OTEL_SERVICE_NAME"]) {
    const v = (env[k] ?? "").trim();
    if (v) return { name: v, source: "env" };
  }
  const attr = (parseKv(env.OTEL_RESOURCE_ATTRIBUTES)["service.name"] ?? "").trim();
  if (attr) return { name: attr, source: "env" };
  if (project) {
    const fromManifest = normaliseServiceName(stripScope(project.manifestName));
    if (fromManifest) return { name: fromManifest, source: "manifest" };
    const fromDir = normaliseServiceName(entryDirName(project.entryDir, project.home ?? ""));
    if (fromDir) return { name: fromDir, source: "entry_dir" };
  }
  return { name: DEFAULT_SERVICE_NAME, source: "default" };
}

/**
 * The project facts for this process: the entry script (`process.argv[1]`,
 * real path), or the working directory when there is none, or when the entry
 * is a tool's own script inside node_modules (`next start`, `tsx`). Reads at
 * most one package.json per folder for at most 8 folders, never above the
 * home folder or the root, and stops at the first one it finds. Never throws.
 */
export function projectFacts(
  argv1: string | undefined = typeof process !== "undefined" ? process.argv?.[1] : undefined,
  cwd: string = typeof process !== "undefined" && typeof process.cwd === "function" ? process.cwd() : "",
  read: (path: string) => string = (p) => readFileSync(p, "utf8"),
  home: string = defaultHome(),
): ProjectFacts {
  try {
    let entry = "";
    if (argv1) {
      try {
        entry = realpathSync(argv1);
      } catch {
        entry = argv1;
      }
    }
    const inModules = (p: string) => p.split(sep).join("/").includes("/node_modules/");
    const start = entry && !inModules(entry) ? dirname(entry) : cwd;
    if (!start) return { manifestName: "", entryDir: "", home };
    const above = (dir: string) => !!home && dir.length < home.length && (home + sep).startsWith(dir.endsWith(sep) ? dir : dir + sep);
    let dir = start;
    let manifestName = "";
    for (let i = 0; i < MANIFEST_SEARCH_DEPTH; i++) {
      if (above(dir)) break;
      if (!inModules(dir + sep)) {
        let raw: string | null = null;
        let unreadable = false;
        try {
          raw = read(join(dir, "package.json"));
        } catch (err) {
          const code = (err as { code?: string }).code;
          unreadable = code !== undefined && code !== "ENOENT" && code !== "ENOTDIR";
        }
        if (unreadable) break; // there, but unreadable: the rung is skipped
        if (raw !== null) {
          // The first package.json decides: a nameless or unreadable one skips the rung.
          try {
            const pkg = JSON.parse(raw) as { name?: unknown };
            if (typeof pkg?.name === "string") manifestName = pkg.name.trim();
          } catch {
            manifestName = "";
          }
          break;
        }
      }
      if (home && dir === home) break;
      const up = dirname(dir);
      if (up === dir) break;
      dir = up;
    }
    return { manifestName, entryDir: start, home };
  } catch {
    return { manifestName: "", entryDir: "", home };
  }
}

function defaultHome(): string {
  try {
    return homedir();
  } catch {
    return "";
  }
}
