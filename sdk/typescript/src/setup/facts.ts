/**
 * The facts setup decides from, read from this computer (the I/O half of
 * plan.ts): the project folder, this machine's Observer (discovery, 500 ms,
 * loopback only), whether `observer` is on PATH, and the SDK-held file.
 * Node built-ins only; nothing here prints.
 */

import { spawn } from "node:child_process";
import { existsSync, readFileSync, statSync } from "node:fs";
import { delimiter, join } from "node:path";

import { TARGET_INFO } from "../targets.js";
import { ENTRY_GUESSES, LOCK_FILES, OTHER_MANIFESTS, type MachineFact, type PackageJson, type ProjectInput } from "./plan.js";
import { isLoopback, obj, type HttpFn } from "./net.js";

export const DISCOVERY_PATH = "/api/sdk/destination";
export const DEFAULT_NODE_URL = "http://127.0.0.1:8081";

/** Read what detection needs from the project folder. */
export function readProject(dir: string): ProjectInput {
  const names = ["package.json", ...LOCK_FILES.map(([f]) => f), ...OTHER_MANIFESTS.map(([f]) => f), ...ENTRY_GUESSES];
  const files = names.filter((n) => {
    try {
      return statSync(join(dir, n)).isFile();
    } catch {
      return false;
    }
  });
  let packageJson: PackageJson | null = null;
  try {
    const p = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
    packageJson = p && typeof p === "object" && !Array.isArray(p) ? (p as PackageJson) : null;
  } catch {
    packageJson = null;
  }
  const wanted = new Set(["@superbased/sdk", "next", ...TARGET_INFO.flatMap((t) => [...t.detect, t.package])]);
  const installed = [...wanted].filter((n) => existsSync(join(dir, "node_modules", ...n.split("/"), "package.json")));
  return { files, packageJson, installed };
}

/** Ask this machine's Observer (loopback only, 500 ms). Never throws. */
export async function discoverMachine(http: HttpFn, nodeUrl: string): Promise<MachineFact> {
  const none: MachineFact = { answers: false, signedIn: false, appsOn: false };
  try {
    if (!isLoopback(new URL(nodeUrl))) return none;
  } catch {
    return none;
  }
  try {
    const a = await http({ method: "GET", url: nodeUrl.replace(/\/+$/, "") + DISCOVERY_PATH, timeoutMs: 500 });
    const b = obj(a.body);
    if (a.status !== 200 || b.api_version !== 1) return none;
    return { answers: true, signedIn: b.signed_in === true, appsOn: obj(b.local).enabled !== false };
  } catch {
    return none;
  }
}

/** Whether an executable named `name` is on PATH (PATHEXT on Windows). */
export function onPath(name: string, env: Record<string, string | undefined>, platform: string = process.platform): boolean {
  const dirs = (env.PATH ?? env.Path ?? "").split(platform === "win32" ? ";" : delimiter).filter(Boolean);
  const exts = platform === "win32" ? (env.PATHEXT ?? ".EXE;.CMD;.BAT").split(";").filter(Boolean) : [""];
  for (const d of dirs) {
    for (const e of exts) {
      try {
        if (statSync(join(d, name + e.toLowerCase())).isFile() || statSync(join(d, name + e)).isFile()) return true;
      } catch {
        // not here
      }
    }
  }
  return false;
}

/**
 * Run the package manager (argv[0] is npm/pnpm/yarn/bun; every other word
 * is a checked package spec). Windows runs the .cmd shims through the shell,
 * which is safe only because plan.installArgv refuses any spec with a shell
 * character. Output goes to stderr so stdout stays the JSON lines.
 */
export function runInstall(argv: readonly string[], dir: string, platform: string = process.platform): Promise<number> {
  return new Promise((resolve) => {
    const cp = spawn(argv[0], argv.slice(1), { cwd: dir, stdio: ["ignore", 2, 2], shell: platform === "win32", windowsHide: true });
    cp.on("error", () => resolve(127));
    cp.on("exit", (code) => resolve(code ?? 1));
  });
}

/** Open a URL in the person's browser. Resolves whether a browser could be started. */
export function openBrowser(url: string, env: Record<string, string | undefined>, platform: string = process.platform): Promise<boolean> {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return Promise.resolve(false);
  }
  if (!(u.protocol === "https:" || (u.protocol === "http:" && isLoopback(u)))) return Promise.resolve(false);
  const href = u.href;
  let cmd: string;
  let args: string[];
  if (platform === "darwin") [cmd, args] = ["open", [href]];
  else if (platform === "win32") [cmd, args] = ["rundll32", ["url.dll,FileProtocolHandler", href]];
  else if (env.WSL_DISTRO_NAME) [cmd, args] = ["wslview", [href]];
  else if (env.DISPLAY || env.WAYLAND_DISPLAY) [cmd, args] = ["xdg-open", [href]];
  else return Promise.resolve(false);
  return new Promise((resolve) => {
    let settled = false;
    const done = (ok: boolean) => {
      if (!settled) {
        settled = true;
        resolve(ok);
      }
    };
    try {
      const cp = spawn(cmd, args, { detached: true, stdio: "ignore", windowsHide: true });
      cp.on("error", () => done(false));
      cp.on("spawn", () => {
        cp.unref();
        done(true);
      });
    } catch {
      done(false);
    }
  });
}
