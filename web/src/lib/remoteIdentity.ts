// remoteIdentity.ts: which machine is this dashboard? (T-425)
//
// The instance switcher opens a REMOTE machine's own superbased dashboard in a
// new tab, over a loopback SSH forward (http://127.0.0.1:<port>). That tab
// looks exactly like the local dashboard, so an operator once read a remote
// box's (correct) refusal as a fault on their own machine (D-325: the
// sb-devbox dashboard, schema 121, was mistaken for demo node 1). This module
// is the one owner of the remote-view identity:
//
//   - the switcher appends a fragment naming the SSH profile it came through
//     (label + target) and the LOCAL build it was opened from;
//   - the remote page reads it once, keeps it for this origin (each forward
//     has its own loopback port, so its own origin), strips it from the
//     address bar, and pins it to the remote daemon's own hostname so a port
//     later reused by another forward cannot inherit it;
//   - the top bar chip, API error messages and the outdated-build flag all
//     read it from here.
//
// A fragment is never sent to any server; it is only read by this page.

/** What the switcher tells the remote tab about how it was opened. */
export type RemoteIdentity = {
  /** The SSH profile's display label (falls back to its name). */
  label: string;
  /** The profile's user@host:port line. */
  target: string;
  /** The local dashboard's build, for the outdated-build comparison. */
  localVersion?: string;
  /** The local dashboard's schema version. */
  localSchema?: number;
  /** The remote daemon's hostname, pinned on first sight (see module doc). */
  hostName?: string;
};

const FRAGMENT_KEY = "sb-remote";
export const REMOTE_IDENTITY_STORAGE_KEY = "sb_remote_identity_v1";

type Wire = { l?: string; t?: string; v?: string; s?: number };

function b64urlEncode(s: string): string {
  const bytes = new TextEncoder().encode(s);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(s: string): string {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

/** remoteFragment builds the `#sb-remote=...` fragment the switcher appends. */
export function remoteFragment(id: RemoteIdentity): string {
  const wire: Wire = { l: id.label, t: id.target };
  if (id.localVersion) wire.v = id.localVersion;
  if (id.localSchema) wire.s = id.localSchema;
  return `#${FRAGMENT_KEY}=${b64urlEncode(JSON.stringify(wire))}`;
}

/** parseRemoteFragment reads a location hash, or returns null when it is not ours. */
export function parseRemoteFragment(hash: string): RemoteIdentity | null {
  const prefix = `#${FRAGMENT_KEY}=`;
  if (!hash.startsWith(prefix)) return null;
  try {
    const wire = JSON.parse(b64urlDecode(hash.slice(prefix.length))) as Wire;
    const label = typeof wire.l === "string" ? wire.l.slice(0, 120) : "";
    if (!label) return null;
    return {
      label,
      target: typeof wire.t === "string" ? wire.t.slice(0, 200) : "",
      localVersion: typeof wire.v === "string" ? wire.v.slice(0, 64) : undefined,
      localSchema: typeof wire.s === "number" && Number.isFinite(wire.s) ? wire.s : undefined,
    };
  } catch {
    return null;
  }
}

/** pinHost decides what to keep once the remote daemon reports its hostname:
 *  the identity with the host pinned, or null when the stored identity was
 *  pinned to a DIFFERENT machine (a reused forward port) and must be dropped. */
export function pinHost(id: RemoteIdentity, hostName: string | undefined): RemoteIdentity | null {
  if (!hostName) return id;
  if (id.hostName && id.hostName !== hostName) return null;
  return id.hostName === hostName ? id : { ...id, hostName };
}

/** machineName is how copy names the machine: label, plus the hostname when it adds information. */
export function machineName(id: RemoteIdentity): string {
  if (id.hostName && id.hostName !== id.label) return `${id.label} (${id.hostName})`;
  return id.label;
}

function core(v: string): number[] | null {
  const m = /^v?(\d+)\.(\d+)\.(\d+)/.exec(v.trim());
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}

export type BuildVerdict = { outdated: boolean; reason: string };

/**
 * buildVerdict compares the remote daemon's build with the local one it was
 * opened from. Outdated when the remote release core (x.y.z) is older, or its
 * database schema is older. Unknown or non-comparable values are never
 * flagged (an honest "no verdict" rather than a guess).
 */
export function buildVerdict(
  remoteVersion: string | undefined,
  remoteSchema: number | undefined,
  localVersion: string | undefined,
  localSchema: number | undefined,
): BuildVerdict {
  const reasons: string[] = [];
  const r = remoteVersion ? core(remoteVersion) : null;
  const l = localVersion ? core(localVersion) : null;
  if (r && l) {
    for (let i = 0; i < 3; i++) {
      if (r[i] !== l[i]) {
        if (r[i] < l[i]) reasons.push(`build v${remoteVersion} is older than this machine's v${localVersion}`);
        break;
      }
    }
  }
  if (remoteSchema && localSchema && remoteSchema < localSchema) {
    reasons.push(`database schema ${remoteSchema} is older than this machine's ${localSchema}`);
  }
  return { outdated: reasons.length > 0, reason: reasons.join("; ") };
}

/** The local build the switcher compares a remote against. */
export type LocalBuild = { version?: string; schema?: number };

/** The InstanceInfo fields the switcher row reads (a structural subset). */
export type RemoteRow = {
  label: string;
  target: string;
  url?: string;
  remote_version?: string;
  remote_schema_version?: number;
  remote_host_name?: string;
  remote_probe_error?: string;
};

/**
 * remoteDashboardURL is the address the switcher opens: the forward's
 * loopback URL plus the fragment that lets the remote tab name its machine
 * and compare builds. Empty when the forward has no URL.
 */
export function remoteDashboardURL(row: RemoteRow, local: LocalBuild): string {
  if (!row.url) return "";
  const base = row.url.split("#")[0];
  return (
    base +
    remoteFragment({ label: row.label, target: row.target, localVersion: local.version, localSchema: local.schema })
  );
}

/**
 * remoteBuildLine is the switcher row's "which build is over there" line:
 * the remote's own version, schema and hostname, and whether it is older
 * than this machine. Null when the remote has not reported (a forward that
 * is down, or a probe that failed: remote_probe_error says why).
 */
export function remoteBuildLine(
  row: RemoteRow,
  local: LocalBuild,
): { text: string; outdated: boolean; reason: string } | null {
  if (!row.remote_version && !row.remote_schema_version) return null;
  const parts = [
    row.remote_version ? `v${row.remote_version}` : "version unknown",
    row.remote_schema_version ? `schema ${row.remote_schema_version}` : "",
    row.remote_host_name ? `host ${row.remote_host_name}` : "",
  ].filter(Boolean);
  const v = buildVerdict(row.remote_version, row.remote_schema_version, local.version, local.schema);
  return { text: `Remote build ${parts.join(", ")}`, outdated: v.outdated, reason: v.reason };
}

// --- browser storage (per origin = per forward) ---------------------------

function storage(): Storage | null {
  try {
    return typeof window !== "undefined" ? window.localStorage : null;
  } catch {
    return null;
  }
}

/** loadRemoteIdentity returns the identity stored for this origin, or null. */
export function loadRemoteIdentity(): RemoteIdentity | null {
  try {
    const raw = storage()?.getItem(REMOTE_IDENTITY_STORAGE_KEY);
    if (!raw) return null;
    const v = JSON.parse(raw) as RemoteIdentity;
    return v && typeof v.label === "string" && v.label ? v : null;
  } catch {
    return null;
  }
}

/** saveRemoteIdentity stores (or, with null, clears) the identity for this origin. */
export function saveRemoteIdentity(id: RemoteIdentity | null): void {
  try {
    const s = storage();
    if (!s) return;
    if (id) s.setItem(REMOTE_IDENTITY_STORAGE_KEY, JSON.stringify(id));
    else s.removeItem(REMOTE_IDENTITY_STORAGE_KEY);
  } catch {
    /* storage blocked: the chip simply shows nothing after a reload */
  }
}

/**
 * captureRemoteFragment is called once at boot: when the URL carries the
 * switcher's fragment, store it for this origin and strip it from the address
 * bar (replaceState, so history keeps the clean URL). Returns the identity in
 * force (from the fragment or from storage), or null on a local dashboard.
 */
export function captureRemoteFragment(): RemoteIdentity | null {
  if (typeof window === "undefined") return null;
  const fromHash = parseRemoteFragment(window.location.hash);
  if (fromHash) {
    saveRemoteIdentity(fromHash);
    try {
      const { pathname, search } = window.location;
      window.history.replaceState(window.history.state, "", pathname + search);
    } catch {
      /* best effort */
    }
    return fromHash;
  }
  return loadRemoteIdentity();
}

/** errorMachineSuffix is appended to API error messages on a remote view, so
 *  an error names the machine it came from. Empty on a local dashboard. */
export function errorMachineSuffix(): string {
  const id = loadRemoteIdentity();
  return id ? ` (on remote machine ${machineName(id)})` : "";
}
