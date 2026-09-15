// Pure helpers used by src/binary.ts.
//
// Kept in their own module so unit tests can import them without
// pulling in the `vscode` runtime (which only exists inside the
// Extension Development Host). resolveBinary + the download flow
// live in src/binary.ts where they belong; everything testable in
// isolation lives here.

import * as path from 'node:path';
import * as fs from 'node:fs/promises';
import * as fsSync from 'node:fs';
import * as crypto from 'node:crypto';
import * as https from 'node:https';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const exec = promisify(execFile);

export const PLATFORM_KEY = `${process.platform}-${process.arch}`;

// Mirrors the release asset names produced by
// .github/workflows/npm-release.yml (observer-v<version>-<asset>.{tar.gz,zip}).
// Keep this map in lock-step with the matrix in that workflow.
export const PLATFORM_TO_ASSET: Record<string, string> = {
  'linux-x64': 'linux-x64',
  'linux-arm64': 'linux-arm64',
  'darwin-x64': 'darwin-x64',
  'darwin-arm64': 'darwin-arm64',
  'win32-x64': 'win32-x64',
};

export function exeName(): string {
  return process.platform === 'win32' ? 'observer.exe' : 'observer';
}

export function parseSha256Sums(sums: string, target: string): string | undefined {
  for (const raw of sums.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const match = line.match(/^([0-9a-fA-F]{64})\s+\*?(\S+)$/);
    if (!match) continue;
    if (match[2] === target) return match[1].toLowerCase();
  }
  return undefined;
}

export async function sha256File(filePath: string): Promise<string> {
  const hash = crypto.createHash('sha256');
  await new Promise<void>((resolve, reject) => {
    const stream = fsSync.createReadStream(filePath);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('end', () => resolve());
    stream.on('error', reject);
  });
  return hash.digest('hex').toLowerCase();
}

export async function httpGetText(url: string): Promise<string> {
  return (await httpGet(url)).toString('utf8');
}

export async function httpGetFile(url: string, dest: string): Promise<void> {
  await fs.writeFile(dest, await httpGet(url));
}

export function httpGet(url: string, redirectsLeft = 5): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    https
      .get(
        url,
        { headers: { 'User-Agent': 'superbased-observer-vscode' } },
        (res) => {
          // GitHub Releases serves a 302 to its S3 bucket; follow.
          if (
            res.statusCode &&
            res.statusCode >= 300 &&
            res.statusCode < 400 &&
            res.headers.location
          ) {
            if (redirectsLeft <= 0) {
              res.resume();
              return reject(new Error(`Too many redirects fetching ${url}`));
            }
            res.resume();
            httpGet(res.headers.location, redirectsLeft - 1).then(resolve, reject);
            return;
          }
          if (res.statusCode !== 200) {
            res.resume();
            return reject(new Error(`HTTP ${res.statusCode} fetching ${url}`));
          }
          const chunks: Buffer[] = [];
          res.on('data', (chunk) => chunks.push(chunk));
          res.on('end', () => resolve(Buffer.concat(chunks)));
          res.on('error', reject);
        },
      )
      .on('error', reject);
  });
}

// VersionProbe distinguishes the two failure modes of `<bin> --version` that
// the candidate-acceptance logic must treat differently:
//   ok:false → the binary could NOT be executed at all (spawn EACCES/ENOENT,
//              ENOEXEC on a corrupt/quarantined file, non-zero exit). This is a
//              REJECTION signal: fall through to the next tier where possible.
//   ok:true  → it ran; `version` is the parsed semver, or 'unknown' when the
//              output was merely unparseable (still an acceptable binary).
export interface VersionProbe {
  ok: boolean;
  version: string;
  error?: string;
}

export async function probeVersion(binary: string): Promise<VersionProbe> {
  try {
    const { stdout } = await exec(binary, ['--version'], { timeout: 5_000 });
    const match = stdout.match(/v?(\d+\.\d+\.\d+)/);
    return { ok: true, version: match ? match[1] : 'unknown' };
  } catch (err) {
    return { ok: false, version: 'unknown', error: err instanceof Error ? err.message : String(err) };
  }
}

export async function readVersion(binary: string): Promise<string> {
  return (await probeVersion(binary)).version;
}

export async function fileExists(p: string): Promise<boolean> {
  try {
    await fs.access(p);
    return true;
  } catch {
    return false;
  }
}

// isExecutableFile is the candidate-acceptance probe: a usable observer binary
// must be a regular FILE (never a directory) and, on POSIX, hold the execute
// bit. Existence alone (fs.access F_OK, the old fileExists) accepted
// directories and non-executable garbage, which then won permanently over the
// bundled/PATH/download fallbacks (the MED this fixes). On Windows X_OK is
// meaningless — executability is decided by the extension in PATHEXT, which the
// `which` candidates already encode — so isFile is the whole test there.
export async function isExecutableFile(p: string): Promise<boolean> {
  try {
    const st = await fs.stat(p);
    if (!st.isFile()) return false;
    if (process.platform !== 'win32') {
      await fs.access(p, fsSync.constants.X_OK);
    }
    return true;
  } catch {
    return false;
  }
}

export async function readFileSafe(p: string): Promise<string | undefined> {
  try {
    return (await fs.readFile(p, 'utf8')).trim();
  } catch {
    return undefined;
  }
}

// which resolves a command against PATH (× PATHEXT on Windows). Every
// candidate is probed CONCURRENTLY — a Windows PATH can hold 60+ dirs and,
// with PATHEXT, hundreds of candidates; probing them sequentially serialised
// hundreds of fs.access callbacks behind other extensions' startup work and
// cost ~6–20s of activation latency in the field (GitHub #5). Firing them all
// at once and taking the lowest-index hit keeps PATH precedence identical while
// collapsing the wall-clock cost to a single round-trip. `exists` is injectable
// so tests can simulate a fake fs (variable-latency) layer; the default probe
// is isExecutableFile so a directory or non-executable file named `observer`
// earlier on PATH can never shadow a real binary further down.
export async function which(
  cmd: string,
  env: NodeJS.ProcessEnv = process.env,
  exists: (p: string) => Promise<boolean> = isExecutableFile,
): Promise<string | undefined> {
  const pathEnv = env.PATH || env.Path;
  if (!pathEnv) return undefined;
  const isWin = process.platform === 'win32';
  const exts = isWin
    ? (env.PATHEXT || '.EXE;.CMD;.BAT;.COM').split(';').filter(Boolean)
    : [''];
  const candidates: string[] = [];
  for (const dir of pathEnv.split(path.delimiter)) {
    if (!dir) continue;
    for (const ext of exts) {
      candidates.push(path.join(dir, `${cmd}${ext}`));
    }
  }
  if (candidates.length === 0) return undefined;
  const results = await Promise.all(candidates.map((c) => exists(c)));
  const idx = results.findIndex((ok) => ok);
  return idx === -1 ? undefined : candidates[idx];
}

// resolveLocalBinary picks the observer binary from the three LOCAL sources
// (explicit setting → bundled → PATH) without any download fallback, so it
// stays free of vscode / child_process and is unit-testable with injected
// probes. All I/O — the candidate probe (fileExists), the PATH scan (which)
// and the `--version` acceptance probe (probeVersion) — is injected per
// CLAUDE.md's "core logic pure, I/O injected" rule.
//
// Ordering (GitHub #5): the bundled, version-matched binary is checked BEFORE
// scanning PATH, because the PATH scan is the slow path and the bundled binary
// is always present and correct. `preferPathBinary` restores the historical
// PATH-first order for operators who deliberately run a newer self-built
// daemon. The explicit `observer.binary.path` setting always wins.
export interface LocalBinaryProbes {
  settingPath?: string;
  bundledPath: string;
  preferPathBinary: boolean;
  // Candidate-acceptance probe (real impl: isExecutableFile). Named fileExists
  // for continuity with the existing injection point; a candidate is only
  // accepted when this returns true AND probeVersion below reports ok.
  fileExists: (p: string) => Promise<boolean>;
  which: (cmd: string) => Promise<string | undefined>;
  // Version probe used as an acceptance gate (real impl: probeVersion). A
  // candidate whose `--version` can't be run is rejected so resolution falls
  // through to the next tier rather than accepting a corrupt binary.
  probeVersion: (p: string) => Promise<VersionProbe>;
}

export interface LocalBinaryHit {
  path: string;
  source: 'setting' | 'path' | 'bundled';
  version: string;
}

export interface LocalBinaryResolution {
  hit?: LocalBinaryHit;
  // Set when an explicit observer.binary.path was configured but rejected (not
  // an executable file, or its --version could not run). The caller surfaces
  // this to the user — the setting was requested explicitly, so an honest,
  // named failure is reported even though resolution still falls back to the
  // bundled/PATH/download tiers so the extension keeps working.
  settingError?: string;
}

// resolveLocalBinary picks the observer binary from the three LOCAL sources
// (explicit setting → bundled → PATH), gating each candidate on BOTH an
// executable-file check and a runnable `--version` probe. A candidate that
// exists but is a directory / non-executable / corrupt is rejected and
// resolution continues to the next tier instead of accepting it forever.
async function acceptCandidate(
  probes: LocalBinaryProbes,
  p: string,
  source: LocalBinaryHit['source'],
): Promise<LocalBinaryHit | undefined> {
  if (!(await probes.fileExists(p))) return undefined;
  const v = await probes.probeVersion(p);
  if (!v.ok) return undefined;
  return { path: p, source, version: v.version };
}

// CachedBinaryProbes injects the same acceptance I/O used everywhere else so
// the cached-download reuse decision stays pure and unit-testable without
// mocking fs globally.
export interface CachedBinaryProbes {
  binPath: string;
  sentinelPath: string;
  expectedVersion: string;
  // Candidate-acceptance probe (real impl: isExecutableFile). A cached path
  // that is a directory / non-executable / missing is rejected.
  isExecutableFile: (p: string) => Promise<boolean>;
  // Reads the sentinel version file (real impl: readFileSafe).
  readFileSafe: (p: string) => Promise<string | undefined>;
  // Runnable `--version` gate (real impl: probeVersion). A cached binary whose
  // --version can't run is rejected so we re-download instead of reusing junk.
  probeVersion: (p: string) => Promise<VersionProbe>;
}

export interface CachedBinaryDecision {
  // true → reuse the cached binary as-is.
  reuse: boolean;
  // Set on reuse: the version parsed from `--version` (the sentinel already
  // matched expectedVersion, so this is normally the same value).
  version?: string;
  // Set on rejection: why the cache was invalidated (for the log line).
  reason?: string;
}

// evaluateCachedBinary decides whether a previously downloaded binary in the
// per-version cache dir may be reused. The OLD gate accepted on
// `fileExists(binPath) && sentinel === version` — existence-only — so a
// directory / non-executable / corrupt cached binary bypassed BOTH acceptance
// gates, was never re-downloaded, and was re-selected every activation. This
// applies the SAME isExecutableFile + probeVersion gates the local-binary
// resolver uses: sentinel version must match AND the file must be an
// executable that actually runs. On any failure the caller invalidates the
// cache and falls through to a fresh download.
export async function evaluateCachedBinary(
  probes: CachedBinaryProbes,
): Promise<CachedBinaryDecision> {
  const sentinel = await probes.readFileSafe(probes.sentinelPath);
  if (sentinel !== probes.expectedVersion) {
    return {
      reuse: false,
      reason: `sentinel version ${sentinel ?? '(none)'} != ${probes.expectedVersion}`,
    };
  }
  if (!(await probes.isExecutableFile(probes.binPath))) {
    return { reuse: false, reason: `cached ${probes.binPath} is not an executable file` };
  }
  const v = await probes.probeVersion(probes.binPath);
  if (!v.ok) {
    return {
      reuse: false,
      reason: `cached ${probes.binPath} --version failed (${v.error ?? 'unknown'})`,
    };
  }
  return { reuse: true, version: v.version };
}

export async function resolveLocalBinary(
  probes: LocalBinaryProbes,
): Promise<LocalBinaryResolution> {
  const { settingPath, bundledPath, preferPathBinary } = probes;

  // 1. Explicit override — highest precedence, always first. On failure we
  //    record a named error (surfaced by the caller) but still fall through,
  //    so a broken setting doesn't leave the extension with no binary at all.
  let settingError: string | undefined;
  if (settingPath) {
    if (!(await probes.fileExists(settingPath))) {
      settingError = `observer.binary.path "${settingPath}" is not an executable file — ignoring it and falling back to the bundled/PATH binary.`;
    } else {
      const v = await probes.probeVersion(settingPath);
      if (v.ok) {
        return { hit: { path: settingPath, source: 'setting', version: v.version } };
      }
      settingError = `observer.binary.path "${settingPath}" could not be run (${
        v.error ?? '--version failed'
      }) — ignoring it and falling back to the bundled/PATH binary.`;
    }
  }

  const probeBundled = (): Promise<LocalBinaryHit | undefined> =>
    acceptCandidate(probes, bundledPath, 'bundled');
  const probePath = async (): Promise<LocalBinaryHit | undefined> => {
    const onPath = await probes.which('observer');
    return onPath ? acceptCandidate(probes, onPath, 'path') : undefined;
  };

  // 2 & 3. Bundled-first by default; PATH-first when the operator opts in.
  const order = preferPathBinary ? [probePath, probeBundled] : [probeBundled, probePath];
  for (const step of order) {
    const hit = await step();
    if (!hit) continue;
    // O7 GUARD (enterprise update management, plan §6 O7). The installed
    // binary always wins over the bundled one.
    //
    // A `binary`-method daemon can now UPDATE ITSELF: the org publishes a
    // signed manifest, the node swaps its own executable and reports the new
    // version. Without this guard an extension pinned to release N would keep
    // relaunching its OWN bundled copy over a node that just moved to N+1, and
    // the two would thrash - the daemon updating itself, the extension putting
    // the old one back on every activation.
    //
    // So when the BUNDLED copy won, probe PATH once more and hand back the
    // installed binary if it is strictly newer. Only STRICTLY newer: an equal
    // or unorderable version leaves the fast, always-present bundled copy in
    // place, which is what the bundled-first ordering was for.
    if (hit.source === 'bundled') {
      const installed = await probePath();
      if (installed && isStrictlyNewer(installed.version, hit.version)) {
        return { hit: installed, settingError };
      }
    }
    return { hit, settingError };
  }
  return { settingError };
}

// isStrictlyNewer reports whether `candidate` is a higher semver than
// `current`. It is the extension's ONLY version comparison and it is
// deliberately conservative: ANY uncertainty answers false.
//
// probeVersion returns the literal string 'unknown' when `--version` printed
// something it could not parse, and that value must never read as "newer" or
// as "older" - it is an absence of information, and the safe reading of an
// absence here is "do not switch away from the copy we shipped".
//
// It mirrors internal/update/semver.go and web/src/lib/version.ts: strip a
// leading "v", cut at the first pre-release/build separator, require three
// non-negative numeric parts.
export function isStrictlyNewer(candidate: string, current: string): boolean {
  const a = parseVersionCore(candidate);
  const b = parseVersionCore(current);
  if (!a || !b) return false;
  for (let i = 0; i < 3; i++) {
    if (a[i] > b[i]) return true;
    if (a[i] < b[i]) return false;
  }
  return false;
}

// parseVersionCore returns [major, minor, patch] or undefined.
function parseVersionCore(v: string): [number, number, number] | undefined {
  if (!v) return undefined;
  let core = v.trim();
  if (core.startsWith('v')) core = core.slice(1);
  const cut = core.search(/[-+]/);
  if (cut >= 0) core = core.slice(0, cut);
  const parts = core.split('.');
  if (parts.length < 3) return undefined;
  const out: number[] = [];
  for (let i = 0; i < 3; i++) {
    const n = Number(parts[i]);
    if (!Number.isInteger(n) || n < 0) return undefined;
    out.push(n);
  }
  return [out[0], out[1], out[2]];
}
