// packageLookup - the pure half of the Privacy page's "Package lookup" card
// and its first-run choice (OS and CI vulnerability scanning plan section
// 13.10, lane RM-2; GET and PUT /api/security/lookup).
//
// Observer checks a project's dependencies against known vulnerabilities in
// one of three ways the developer chooses: download the OSV databases and
// match here (local), look the dependencies up at superbased with no
// download (remote: a short hash prefix of each package name, never a name,
// a version or code), or both (local first, remote only for what local
// cannot answer). Every choice that sends or downloads data has its own
// consent, shown before the click, and an agent can give none of them. A
// managed node's organization decides: the card reads, with no controls.

/** One consent record's state (dashapi.LookupConsent). */
export type LookupConsent = {
  accepted: boolean;
  accepted_at?: string;
  accepted_on?: string;
  by?: string;
  /** The consent text, shown before the click. */
  text: string;
};

/** One shard set the verified manifest lists. */
export type LookupSet = { set: string; ecosystem: string; epoch: number; bits: number };

/** One driver's remote lookup support. */
export type LookupDriver = { driver: string; remote: boolean; note?: string };

/** The package lookup posture (dashapi.PackageLookupStatus). */
export type PackageLookupStatus = {
  /** "local", "remote", "both", or "" when nothing is chosen yet. */
  mode: string;
  configured: string;
  via: string;
  via_choices: string[];
  kinds: string[];
  kind_choices: string[];
  /** "withhold" or "send". */
  private: string;
  /** send AND its own consent recorded. */
  private_sending: boolean;
  managed: boolean;
  download: LookupConsent;
  remote: LookupConsent;
  remote_private: LookupConsent;
  /** Why a dependency scan would not run now. */
  blocked?: string;
  remote_blocked?: string;
  remote_hosts: string[];
  approx_mb: number;
  sets?: LookupSet[];
  cache_bytes: number;
  drivers: LookupDriver[];
  /** A managed node's org-decided posture (lane RM-3); absent on an individual node. */
  org?: OrgLookupStatus;
};

/** A managed node's org-decided package lookup posture (dashapi.OrgLookupStatus). */
export type OrgLookupStatus = {
  /** package_lookup = org_mirror in the org's signed security policy. */
  on: boolean;
  /** "withhold" or "send": the org's private-names rule. */
  private: string;
  kinds: string[];
  org_name?: string;
  /** The signed security policy document's version. */
  version: number;
  /** "org": the Privacy page's org-state label. */
  source: string;
};

/** GET /api/security/lookup. */
export type PackageLookupResponse = { status: PackageLookupStatus; confirm_token?: string };

/** One PUT /api/security/lookup (dashapi.PackageLookupChange). */
export type PackageLookupChange = {
  mode?: string;
  kinds?: string[];
  private?: string;
  accept_download?: boolean;
  accept_remote?: boolean;
  accept_private?: boolean;
  withdraw_remote?: boolean;
  withdraw_private?: boolean;
};

/** The route the card reads and writes. */
export const LOOKUP_ROUTE = "/api/security/lookup";

/** The card's plain-words opening, above every control (plan section 13.10). */
export const LOOKUP_INTRO =
  "Observer checks your dependencies against known vulnerabilities. It never sends source code. Depending on what you " +
  "choose below, either nothing leaves this machine except the download of public databases, or your packages are looked " +
  "up at superbased.app: a short hash prefix of each package name, never the name, the version or the code.";

/** One mode choice. */
export type LookupModeChoice = { id: "local" | "remote" | "both"; label: string; sends: string };

/** LOOKUP_MODES is the mode picker, with what each choice sends. */
export const LOOKUP_MODES: LookupModeChoice[] = [
  {
    id: "local",
    label: "Download the databases",
    sends:
      "Nothing about your projects. The databases are public files (about 300 MB at first); superbased.app and the OSV bucket see your IP address and the time.",
  },
  {
    id: "remote",
    label: "superbased lookup (no download)",
    sends:
      "A short hash prefix of each package name, shared by hundreds of other names; never a name, a version or code. superbased.app sees your IP address and the time.",
  },
  {
    id: "both",
    label: "Both: local first, superbased for the gaps",
    sends:
      "Nothing for an ecosystem a downloaded database answers; for the rest, the same hash prefixes as the superbased lookup.",
  },
];

/** The remote kinds' labels. */
export const LOOKUP_KIND_LABELS: Record<string, string> = {
  language: "Language packages (lockfiles)",
  actions: "GitHub Actions",
  os: "OS packages in container images",
};

/** The private-names switch's one sentence, said before the switch. */
export const LOOKUP_PRIVATE_NOTE =
  "Private and internal package names are withheld by default: never looked up, so the scan is never clean. A private name has no public advisory, but a name that also exists publicly (dependency confusion) can match one.";

/** firstRunNeeded: a fresh install has chosen neither the download nor the lookup. */
export function firstRunNeeded(st: PackageLookupStatus | null | undefined): boolean {
  return !!st && !st.managed && st.mode === "";
}

/** lookupModeLine is the posture in one line. */
export function lookupModeLine(st: PackageLookupStatus): string {
  if (st.managed) {
    if (!st.org?.on) return "Set by your organization: no package lookup leaves this machine; nothing is downloaded from or sent to a public host.";
    const server = st.org.org_name ? `your organization's server (${st.org.org_name})` : "your organization's server";
    return `Set by your organization: lookups go to ${server}, mirror mode; nothing is downloaded from or sent to a public host.`;
  }
  switch (st.mode) {
    case "":
      return "Not chosen yet: dependencies show as not scanned until you choose a download or the superbased lookup.";
    case "local":
      return st.download.accepted
        ? `Local: the OSV databases are downloaded and matched on this machine (accepted ${dateOf(st.download.accepted_at)} on the ${st.download.accepted_on ?? "cli"}).`
        : "Local: waiting for the database download's accept.";
    case "remote":
      return st.remote.accepted
        ? `superbased lookup, no download (accepted ${dateOf(st.remote.accepted_at)} on the ${st.remote.accepted_on ?? "cli"}).`
        : "superbased lookup chosen, but its consent is not recorded: dependencies show as not scanned.";
    case "both":
      return st.remote.accepted
        ? "Both: downloaded databases first, the superbased lookup only for the ecosystems with none."
        : "Both chosen, but the superbased lookup's consent is not recorded: only the downloaded databases match.";
  }
  return st.mode;
}

/** privateLine says whether private names are sent. */
export function privateLine(st: PackageLookupStatus): string {
  if (st.private_sending) return `Private package names are sent too (accepted ${dateOf(st.remote_private.accepted_at)}).`;
  if (st.private === "send") return "Private names: send chosen, but its consent is not recorded, so they are withheld.";
  return "Private package names are withheld.";
}

/** remoteDriverNotes are the drivers that cannot use a remote lookup yet. */
export function remoteDriverNotes(st: PackageLookupStatus): string[] {
  return (st.drivers ?? []).filter((d) => !d.remote && d.note).map((d) => d.note as string);
}

/** consentFor names the consent a mode needs that is not yet recorded, or null. */
export function consentFor(st: PackageLookupStatus, mode: string): "download" | "remote" | null {
  if (mode === "local") return st.download.accepted ? null : "download";
  if (mode === "remote" || mode === "both") return st.remote.accepted ? null : "remote";
  return null;
}

/** modeChange is the PUT body for choosing mode after the dialog for its consent (if any). */
export function modeChange(st: PackageLookupStatus, mode: string): PackageLookupChange {
  const need = consentFor(st, mode);
  const out: PackageLookupChange = { mode };
  if (need === "download") out.accept_download = true;
  if (need === "remote") out.accept_remote = true;
  return out;
}

/** privateChange is the PUT body for the private-names switch. */
export function privateChange(st: PackageLookupStatus, send: boolean): PackageLookupChange {
  if (!send) return { private: "withhold" };
  return st.remote_private.accepted ? { private: "send" } : { private: "send", accept_private: true };
}

/** kindsChange toggles one kind; it never leaves the list empty. */
export function kindsChange(st: PackageLookupStatus, kind: string, on: boolean): PackageLookupChange | null {
  const now = new Set(st.kinds ?? []);
  if (on) now.add(kind);
  else now.delete(kind);
  const next = (st.kind_choices ?? []).filter((k) => now.has(k));
  if (next.length === 0) return null;
  return { kinds: next };
}

/** cacheLine is the shard cache's size in plain words. */
export function cacheLine(bytes: number): string {
  if (!bytes) return "No shards cached yet.";
  if (bytes < 1 << 20) return `Shards cached on this machine: ${Math.max(1, Math.round(bytes / 1024))} KB.`;
  return `Shards cached on this machine: ${(bytes / (1 << 20)).toFixed(1)} MB.`;
}

function dateOf(at?: string): string {
  return at ? at.slice(0, 10) : "earlier";
}

/**
 * orgPostureLines are a managed node's read-only posture lines (lane RM-3):
 * what its organization's signed security policy decides, and its version.
 */
export function orgPostureLines(st: PackageLookupStatus): string[] {
  const o = st.org;
  if (!o) return ["Private package names: your organization's rule. Databases on this machine: from your organization's mirror only."];
  const lines: string[] = [];
  if (o.on) {
    lines.push(`Looked up: ${o.kinds.join(", ")}. The org server's mirror answers what its databases do not; this machine sends it only the shard digests your packages' hash prefixes fall in.`);
    lines.push(o.private === "send" ? "Private package names: looked up too (your organization's rule)." : "Private package names: withheld (your organization's rule).");
  } else {
    lines.push("The superbased lookup is off by your organization's policy: no package lookup leaves this machine.");
  }
  lines.push("Databases on this machine: from your organization's mirror only.");
  lines.push(`Security policy version ${o.version}${o.source === "org" ? " (org state)" : ""}.`);
  return lines;
}
