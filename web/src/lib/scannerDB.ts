// scannerDB - the pure half of the Scanners card's OSV database accept
// (components security.scan.scalibr and security.scan.osv; operator ruling
// PT-19 (2): ask once, then automatic).
//
// Nothing is downloaded until the developer accepts once, here (a confirm
// dialog that shows the size and the source) or with `observer security
// scan db accept`; after that the refreshes are automatic. Before the
// accept the card says what is owed and never reads a project clean.
//
// The same card carries the OS release databases' one accept (OS-2, ruling
// Q1 (b)), the image driver and its picker (lane OS-2 T, plan section 6.7),
// Trivy's database accept, and the exploit data's state with FIRST's EPSS
// citation (plan section 14.7 item 5). Every accept is a human click in a
// dialog that shows its text first; a managed node has nothing to accept.

import type { PackageLookupStatus } from "./packageLookup.ts";

/** The download's state (GET /api/security/scanners `db`). */
export type ScannerDBStatus = {
  accepted: boolean;
  accepted_at?: string;
  accepted_on?: string;
  by?: string;
  approx_mb: number;
  source: string;
  text: string;
  managed: boolean;
  /** The download gate's first closed reason; absent when it may run. */
  blocked?: string;
  installed: number;
  /** The OS release databases (OS-2, ruling Q1 (b)); absent on an older daemon. */
  os?: ScannerOSDBStatus;
  /** The image OS package driver (lane OS-2 T); absent on an older daemon. */
  image?: ScannerImageStatus;
  /** The exploit data (CISA KEV and FIRST EPSS); absent on an older daemon. */
  exploit?: ScannerExploitStatus;
  /** The package lookup posture (lane RM-2); absent on an older daemon. */
  lookup?: PackageLookupStatus;
};

/** GET /api/security/scanners/db. */
export type ScannerDBResponse = { status: ScannerDBStatus; confirm_token?: string };

/** One distribution's approximate per-release download. */
export type ScannerOSDistroSize = { name: string; approx_mb: number };

/** One installed OS release database. */
export type ScannerOSRelease = {
  distro: string;
  version: string;
  artifact: string;
  epoch: string;
  source?: string;
  bytes: number;
  fetched_at?: string;
  checked_at?: string;
  last_error?: string;
  fixed_only?: boolean;
  known_gap?: string;
};

/** The OS release databases' one accept and what is installed (dashapi.ScannerOSDBStatus). */
export type ScannerOSDBStatus = {
  accepted: boolean;
  accepted_at?: string;
  accepted_on?: string;
  by?: string;
  /** The accept text (osvdb.OSConsentText), shown before the click. */
  text: string;
  source: string;
  sizes: ScannerOSDistroSize[];
  managed: boolean;
  blocked?: string;
  installed: ScannerOSRelease[];
  disk_bytes: number;
};

/** Trivy's database: its accept and the installed generation (dashapi.ScannerTrivyDBStatus). */
export type ScannerTrivyDBStatus = {
  accepted: boolean;
  accepted_at?: string;
  accepted_on?: string;
  by?: string;
  /** The accept text (osvdb.TrivyConsentText), shown before the click. */
  text: string;
  source: string;
  approx_download_mb: number;
  approx_disk_mb: number;
  managed: boolean;
  blocked?: string;
  installed: boolean;
  epoch?: string;
  updated_at?: string;
  next_update?: string;
  checked_at?: string;
  age_hours?: number;
  bytes?: number;
  last_error?: string;
};

/** The Trivy image driver's binary and database (dashapi.ScannerTrivyImageStatus). */
export type ScannerTrivyImageStatus = {
  selected: boolean;
  installed: boolean;
  pinned: boolean;
  decision?: string;
  tested_version: string;
  db: ScannerTrivyDBStatus;
};

/** The image OS package driver's state (dashapi.ScannerImageStatus). */
export type ScannerImageStatus = {
  /** The driver in force. */
  driver: string;
  /** The key's own value; absent for the default. */
  configured?: string;
  /** What an unset key reads as in this build. */
  default: string;
  /** The drivers this build compiles. */
  choices: string[];
  scalibr_compiled: boolean;
  trivy_compiled: boolean;
  trivy?: ScannerTrivyImageStatus;
};

/** GET /api/security/scanners/trivydb. */
export type ScannerTrivyDBResponse = { status: ScannerImageStatus; confirm_token?: string };

/** One exploit kind's install state (dashapi.ScannerExploitKind). */
export type ScannerExploitKind = {
  kind: string;
  name: string;
  installed: boolean;
  available: boolean;
  reason?: string;
  version?: string;
  source?: string;
  vouched_at?: string;
  bytes?: number;
  /** The node's last download attempt for the kind (RFC3339); absent before the first one. */
  checked_at?: string;
  /** Why that attempt brought no verified set; absent when it did. */
  last_error?: string;
  /** The fetch gate's reason when it was closed and nothing was asked. */
  blocked?: string;
};

/** The exploit data's state (dashapi.ScannerExploitStatus). */
export type ScannerExploitStatus = {
  kinds: ScannerExploitKind[];
  /** FIRST's EPSS citation; the daemon sets it only while the EPSS data is available. */
  epss_citation?: string;
  /** The KEV source line; set only while the KEV data is available. */
  kev_notice?: string;
};

export type ScannerDBStage = "managed" | "waiting" | "accepted";

/**
 * scannerDBStage is an accept's state: managed (the org mirror supplies the
 * databases, nothing to accept), waiting (no accept yet: nothing is
 * downloaded) or accepted. Null when the daemon does not report it. The
 * language, OS and Trivy accepts share it.
 */
export function scannerDBStage(s: { managed: boolean; accepted: boolean } | null | undefined): ScannerDBStage | null {
  if (!s) return null;
  if (s.managed) return "managed";
  return s.accepted ? "accepted" : "waiting";
}

/** acceptedWhere is "<when> (<surface>, <who>)" for an accept record. */
function acceptedWhere(s: { accepted_at?: string; accepted_on?: string; by?: string }): string {
  const when = s.accepted_at ? new Date(s.accepted_at).toLocaleString() : "";
  const who = s.by ? `, ${s.by}` : "";
  return `${when} (${s.accepted_on ?? "?"}${who})`;
}

/** scannerDBLine is the card's one line for the stage (no em dashes: copy rule). */
export function scannerDBLine(s: ScannerDBStatus): string {
  switch (scannerDBStage(s)) {
    case "managed":
      return "Managed node: the OSV databases come from your organization's mirror, not from the public bucket.";
    case "waiting":
      return `Databases not downloaded: accept to download about ${s.approx_mb} MB from ${s.source}. Until then dependencies show as not scanned.`;
    default:
      return `Database download accepted ${acceptedWhere(s)}; refreshes are automatic.`;
  }
}

/** scannerDBAcceptLabel is the dialog's accept button. */
export function scannerDBAcceptLabel(s: ScannerDBStatus): string {
  return `Accept and download about ${s.approx_mb} MB`;
}

/** megabytes is a byte count in whole MB (at least 1 for a non-empty file). */
export function megabytes(n: number | null | undefined): string {
  if (!n || n <= 0) return "0 MB";
  return `${Math.max(1, Math.round(n / 1_000_000))} MB`;
}

// ------------------------------------------------- OS release databases

/** osSizesLine is each distribution's largest release, in the table's order. */
export function osSizesLine(os: ScannerOSDBStatus): string {
  return (os.sizes ?? []).map((d) => `${d.name} up to ${d.approx_mb} MB`).join(", ");
}

/** osDBLine is the OS databases' one line for the stage. */
export function osDBLine(os: ScannerOSDBStatus): string {
  switch (scannerDBStage(os)) {
    case "managed":
      return "Managed node: the OS release databases come from your organization's mirror, so there is nothing to accept.";
    case "waiting":
      return `OS release databases not downloaded: accept to download, from ${os.source} only, the release each scanned image uses. Until then images show as not scanned.`;
    default: {
      const n = os.installed?.length ?? 0;
      const held =
        n === 0
          ? "no release downloaded yet (a scan fetches the one it needs)"
          : `${n} release${n === 1 ? "" : "s"} installed, ${megabytes(os.disk_bytes)} on disk`;
      return `OS database download accepted ${acceptedWhere(os)}; ${held}.`;
    }
  }
}

/** osReleaseNotes are an installed release's labels and its last refresh's failure. */
export function osReleaseNotes(r: ScannerOSRelease): string[] {
  const out: string[] = [];
  if (r.fixed_only) out.push("fixed issues only");
  if (r.known_gap) out.push(r.known_gap);
  if (r.last_error) out.push(`last refresh failed: ${r.last_error}`);
  return out;
}

// --------------------------------------------------------- image driver

/** The image drivers' names on the card. */
const IMAGE_DRIVER_NAMES: Readonly<Record<string, string>> = {
  scalibr: "OSV-SCALIBR (superbased's signed OS databases)",
  trivy: "Trivy (its own vulnerability database)",
};

/** imageDriverName is a driver's words. */
export function imageDriverName(d: string): string {
  return IMAGE_DRIVER_NAMES[d] ?? d;
}

/** The config key the picker writes. */
export const IMAGE_DRIVER_KEY = "security.scan.image.driver";

/** imageDriverOptions are the picker's options: the drivers this build compiles, the default marked. */
export function imageDriverOptions(img: ScannerImageStatus): { value: string; label: string }[] {
  return (img.choices ?? []).map((c) => ({
    value: c,
    label: c === img.default ? `${imageDriverName(c)} (default)` : imageDriverName(c),
  }));
}

/** imageDriverLine says which driver scans images and why. */
export function imageDriverLine(img: ScannerImageStatus): string {
  const choices = img.choices ?? [];
  if (choices.length === 0) return "No image driver is in this build: images cannot be scanned.";
  const why = img.configured ? "set in [security.scan.image] driver" : "this build's default";
  const only = choices.length === 1 ? "; it is the only image driver in this build" : "";
  return `Images are scanned with ${imageDriverName(img.driver)} (${why})${only}.`;
}

/**
 * imageDriverPatch is the single-key patch that moves the driver to next, or
 * null when next is the driver already in force or not one this build
 * compiles. `was` is the key's own value ("" for the default).
 */
export function imageDriverPatch(img: ScannerImageStatus, next: string): { key: string; value: string; was: string } | null {
  if (next === img.driver || !(img.choices ?? []).includes(next)) return null;
  return { key: IMAGE_DRIVER_KEY, value: next, was: img.configured ?? "" };
}

/** The osv-scanner row's "How to install" (GET /api/security/scanners
 *  osv_install, dashboard CLI parity plan B-CS3): the vendor's own ways, the
 *  same offer `observer security scan install-osv-scanner` prints. Observer
 *  installs nothing itself (decision D-766). */
export type OSVScannerInstall = {
  intro: string;
  docs_url: string;
  ways: { label: string; command?: string; url?: string; note?: string }[];
  outro: string;
};

/** The osv-scanner driver's component id. */
export const OSV_COMPONENT = "security.scan.osv";

/** osvInstallFor is the install offer a driver row shows: only the
 *  osv-scanner row, and only when the daemon sent an offer with a way. */
export function osvInstallFor(component: string, offer: OSVScannerInstall | null | undefined): OSVScannerInstall | null {
  if (component !== OSV_COMPONENT || !offer || (offer.ways ?? []).length === 0) return null;
  return offer;
}

/** trivyEngineLine is the Trivy driver's binary state. */
export function trivyEngineLine(t: ScannerTrivyImageStatus): string {
  if (!t.selected) {
    return "Trivy image driver off: turn it on with its switch above (it brings Trivy and the dependency checks with it).";
  }
  if (!t.installed) {
    return "Trivy is not installed: install it from the IaC scanners card on this tab (the same guided install as `observer security iac install --engine trivy`). Trivy image scans read not scanned.";
  }
  const pin = t.pinned ? "pinned" : "not pinned";
  const decision = t.decision ? `, ${t.decision}` : "";
  return `Trivy installed (${pin}${decision}); tested with ${t.tested_version}.`;
}

/** trivyDBLine is Trivy's database line for the stage. */
export function trivyDBLine(db: ScannerTrivyDBStatus): string {
  switch (scannerDBStage(db)) {
    case "managed":
      return "Managed node: your organization's mirror does not serve Trivy's database yet, so nothing is accepted or downloaded and Trivy image scans read not scanned.";
    case "waiting":
      return `Trivy's database not downloaded: accept to download about ${db.approx_download_mb} MB (about ${db.approx_disk_mb} MB on disk) from ${db.source}. Until then Trivy image scans read not scanned.`;
    default: {
      const built = db.updated_at ? `, built ${new Date(db.updated_at).toLocaleString()}` : "";
      const size = db.bytes ? `, ${megabytes(db.bytes)} on disk` : "";
      const held = db.installed
        ? `installed${built}${size}; refreshes are automatic`
        : "not downloaded yet (the next refresh or Trivy scan downloads it)";
      const failed = db.last_error ? ` Last refresh failed: ${db.last_error}.` : "";
      return `Trivy's database accepted ${acceptedWhere(db)}; ${held}.${failed}`;
    }
  }
}

/** trivyDBAcceptLabel is the Trivy dialog's accept button. */
export function trivyDBAcceptLabel(db: ScannerTrivyDBStatus): string {
  return `Accept and download about ${db.approx_download_mb} MB`;
}

// ---------------------------------------------------------- exploit data

/** Why an exploit kind is unavailable, in words (never "not exploited"). */
const EXPLOIT_REASON_WORDS: Readonly<Record<string, string>> = {
  not_installed: "not downloaded: it comes with the OSV databases after their accept",
  stale: "data unavailable: older than its age floor",
  file_mismatch: "data unavailable: the installed file does not match its record",
  unreadable: "data unavailable: this build cannot read it",
};

/** Why the fetch gate asked nothing, in words (the daemon's gate reasons). */
const EXPLOIT_BLOCKED_WORDS: Readonly<Record<string, string>> = {
  database_not_accepted: "it comes with the OSV databases after their accept",
  database_missing:
    "this node's database source does not carry it (an import-only or upstream-only source, or a managed node whose organization does not name its mirror)",
  feed_unavailable: "this build has no content-feed key to verify it, so nothing is fetched",
};

/** exploitFetchFailure is a kind's last failed download in words ("" when none failed). */
function exploitFetchFailure(k: ScannerExploitKind): string {
  if (!k.last_error) return "";
  const when = k.checked_at ? ` at ${new Date(k.checked_at).toLocaleString()}` : "";
  return `the last download${when} failed (${k.last_error})`;
}

/**
 * exploitKindLine is one exploit kind's state in words. A kind the node
 * tried and failed to download says so, rather than pointing at an accept
 * already given.
 */
export function exploitKindLine(k: ScannerExploitKind): string {
  const failed = exploitFetchFailure(k);
  if (k.available) {
    const version = k.version ? `, ${k.version}` : "";
    const vouched = k.vouched_at ? `, signed ${new Date(k.vouched_at).toLocaleDateString()}` : "";
    const kept = failed ? `; ${failed}, so the installed data stays in use` : "";
    return `${k.name}: installed${version}${vouched}${kept}`;
  }
  const blocked = k.blocked ? (EXPLOIT_BLOCKED_WORDS[k.blocked] ?? `not fetched (${k.blocked.replaceAll("_", " ")})`) : "";
  if (k.reason === "not_installed" && blocked) {
    return `${k.name}: not downloaded: ${blocked}`;
  }
  if (k.reason === "not_installed" && failed) {
    return `${k.name}: not downloaded: ${failed}; the next database refresh tries again`;
  }
  const words = EXPLOIT_REASON_WORDS[k.reason ?? ""] ?? "data unavailable";
  const why = blocked ? `; not refreshed: ${blocked}` : failed ? `; ${failed}` : "";
  return `${k.name}: ${words}${why}`;
}

/** exploitCitations are the lines shown under the exploit row: only what the daemon set. */
export function exploitCitations(x: ScannerExploitStatus): string[] {
  return [x.epss_citation, x.kev_notice].filter((v): v is string => Boolean(v));
}
