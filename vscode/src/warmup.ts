// Windows warm-up of a newly adopted observer binary (lane shr-hookseam2,
// roadmap F0-3 revision 2.1, the JSP-2 laptop half).
//
// On Windows the FIRST run of a new executable costs about 2 s (p99 3.9 s)
// while Microsoft Defender scans it, and whichever process runs it first
// pays. After an extension update the adopted binary is a new file, and the
// daemon re-registers the AI tools' hooks to it, so the first hook could be
// the one that pays. This runs the adopted binary once in the background
// (`--version`, the flag every probe of this binary uses; there is no
// `version` subcommand), once per adopted path and version, never awaited by
// activation. It is a no-op off Windows, where there is no first-run scan.
//
// Note: resolveBinary's acceptance probe already runs `--version` on the
// adopted binary during activation (5 s timeout), so on today's adoption
// paths the scan is usually paid there; this run is bounded at 30 s, keeps
// working if a later adoption path skips the probe, and is remembered so it
// happens once per adopted binary, not on every activation.
//
// Pure apart from warmUpOnAdoption: the plan and the runner take their I/O
// as arguments, so the unit suite needs no vscode runtime.

import { execFile } from 'node:child_process';

/** The adopted binary, as resolveBinary returns it. */
export interface AdoptedBinary {
  path: string;
  version: string;
}

/** globalState key holding the last binary warmed on this machine. */
export const WARMUP_STATE_KEY = 'observer.warmedBinary';

/** Bound on the warm-up run: past the JSP-2 p99 with room. */
export const WARMUP_TIMEOUT_MS = 30_000;

/** The arguments the warm-up runs the binary with. */
export const WARMUP_ARGS: readonly string[] = ['--version'];

export interface WarmupDeps {
  platform: string;
  /** The key of the binary warmed last time, if any. */
  lastKey: string | undefined;
  remember: (key: string) => PromiseLike<void> | void;
  run: (bin: string, args: readonly string[], timeoutMs: number) => Promise<void>;
  log?: (line: string) => void;
}

export interface WarmupPlan {
  run: boolean;
  why: string;
}

/** warmupKey identifies one adopted binary: its path and version. */
export function warmupKey(b: AdoptedBinary): string {
  return `${b.path}|${b.version}`;
}

// The decision, walked top to bottom; the first matching row decides.
const WARMUP_RULES: ReadonlyArray<{
  when: (platform: string, key: string, lastKey: string | undefined) => boolean;
  plan: WarmupPlan;
}> = [
  { when: (p) => p !== 'win32', plan: { run: false, why: 'no first-run scan off Windows' } },
  { when: (_p, k) => k === '|', plan: { run: false, why: 'no adopted binary' } },
  {
    when: (_p, k, last) => k === last,
    plan: { run: false, why: 'this binary was already warmed' },
  },
  { when: () => true, plan: { run: true, why: 'a newly adopted binary on Windows' } },
];

/** planWarmup decides whether to warm the adopted binary. */
export function planWarmup(platform: string, key: string, lastKey: string | undefined): WarmupPlan {
  for (const r of WARMUP_RULES) {
    if (r.when(platform, key, lastKey)) return r.plan;
  }
  return { run: false, why: '' };
}

/**
 * warmUpAdoptedBinary runs the adopted binary once when planWarmup says so
 * and remembers it. It never rejects: the caller fires it with `void` and
 * never waits on it.
 */
export async function warmUpAdoptedBinary(b: AdoptedBinary, deps: WarmupDeps): Promise<boolean> {
  const key = warmupKey(b);
  const plan = planWarmup(deps.platform, key, deps.lastKey);
  if (!plan.run) return false;
  try {
    await deps.run(b.path, WARMUP_ARGS, WARMUP_TIMEOUT_MS);
  } catch {
    // A failed run still took the first-run scan; nothing to report.
  }
  try {
    await deps.remember(key);
  } catch {
    // Not remembering only means one more warm-up next activation.
  }
  deps.log?.(`Warmed the adopted binary ${b.path} (${b.version}) off the hook path.`);
  return true;
}

/** The slice of vscode.ExtensionContext the warm-up uses. */
export interface WarmupContext {
  globalState: {
    get<T>(key: string): T | undefined;
    update(key: string, value: unknown): PromiseLike<void>;
  };
}

/** runOnce runs bin with args and resolves when it exits, hidden, bounded. */
function runOnce(bin: string, args: readonly string[], timeoutMs: number): Promise<void> {
  return new Promise((resolve) => {
    execFile(bin, [...args], { timeout: timeoutMs, windowsHide: true }, () => resolve());
  });
}

/** warmUpOnAdoption wires warmUpAdoptedBinary to the extension's state. */
export function warmUpOnAdoption(
  ctx: WarmupContext,
  b: AdoptedBinary,
  log?: (line: string) => void,
): Promise<boolean> {
  return warmUpAdoptedBinary(b, {
    platform: process.platform,
    lastKey: ctx.globalState.get<string>(WARMUP_STATE_KEY),
    remember: (key) => ctx.globalState.update(WARMUP_STATE_KEY, key),
    run: runOnce,
    log,
  });
}
