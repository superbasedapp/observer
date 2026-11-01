// opengrepCard - the pure half of the Code security page's Code rules card
// (component security.scan.opengrep, lane SEC-G2): the guided Opengrep
// install with its one-time size consent, and the rows the card shows
// (engine, verification, pack version and source, last run, schedule,
// isolation).
//
// Nothing is downloaded until the developer accepts once, in the card's
// dialog (which states the download and unpacked sizes) or with `observer
// security code install`; a new pin asks again. A managed node installs
// only from its org mirror and asks nothing. Copy rule: no em dashes.

/** GET /api/security/code/install `status`. */
export type OpengrepStatus = {
  selected: boolean;
  managed: boolean;
  blocked?: string;
  blocked_text?: string;
  source?: string;
  pin_from?: string;
  version?: string;
  os?: string;
  arch?: string;
  sha256?: string;
  url?: string;
  download_bytes?: number;
  tree_bytes?: number;
  tree_files?: number;
  consent_text?: string;
  consented: boolean;
  consented_at?: string;
  consented_on?: string;
  by?: string;
  installed: boolean;
  installed_at?: string;
  installing: boolean;
  last_error?: string;
  engine?: string;
  verification?: string;
  pack_version?: string;
  pack_source?: string;
  pack_freshness?: string;
  pack_note?: string;
  fetch_source?: string;
  fetch_at?: string;
  fetch_error?: string;
  last_run_at?: string;
  last_run_outcome?: string;
  last_run_labels?: string[];
  post_write: boolean;
  commit_diff: boolean;
  schedule_hours: number;
  isolation?: string;
};

/** The route's full answer. */
export type OpengrepResponse = { status: OpengrepStatus; confirm_token?: string };

export const OPENGREP_ROUTE = "/api/security/code/install";

export type OpengrepStage = "blocked" | "installing" | "installed" | "managed" | "waiting";

/** opengrepStage is the card's install state. */
export function opengrepStage(s: OpengrepStatus): OpengrepStage {
  if (s.installing) return "installing";
  if (s.installed || (s.engine && !s.blocked && !s.version)) return "installed";
  if (s.blocked) return "blocked";
  if (s.managed) return "managed";
  return "waiting";
}

/** mb renders bytes as "about N MB" ("less than 1 MB", "an unknown amount"). */
export function mb(n: number | undefined): string {
  if (!n || n <= 0) return "an unknown amount";
  if (n < 1_000_000) return "less than 1 MB";
  return `about ${Math.round(n / 1_000_000)} MB`;
}

/** opengrepInstallLine is the card's one line for the install state. */
export function opengrepInstallLine(s: OpengrepStatus): string {
  switch (opengrepStage(s)) {
    case "installing":
      return "Installing: downloading and checking the pinned release.";
    case "installed":
      return `Opengrep ${s.version ?? ""} is installed.`.replace("  ", " ");
    case "blocked":
      return s.blocked_text ?? `The install is blocked (${s.blocked}).`;
    case "managed":
      return `Managed node: Opengrep ${s.version ?? ""} comes from your organization's mirror, never the public release.`;
    default:
      return `Not installed: no process starts. The install downloads ${mb(s.download_bytes)} and unpacks ${mb(s.tree_bytes)} on first run, after you accept once.`;
  }
}

/** opengrepAcceptLabel is the dialog's accept button. */
export function opengrepAcceptLabel(s: OpengrepStatus): string {
  return s.managed ? "Install from the org mirror" : `Accept and download ${mb(s.download_bytes)}`;
}

/** opengrepScheduleLabel names the schedule picker's value. */
export function opengrepScheduleLabel(hours: number): string {
  if (hours <= 0) return "off";
  if (hours === 24) return "daily";
  if (hours === 168) return "weekly";
  return `every ${hours} hours`;
}

/** opengrepRows are the card's labelled rows, in order; empty values read "none". */
export function opengrepRows(s: OpengrepStatus): Array<[string, string]> {
  const pack = s.pack_version ? `${s.pack_version} (${s.pack_source === "imported" ? "signed update" : "built in"}${s.pack_freshness ? `, ${s.pack_freshness}` : ""})` : "";
  let fetch = "";
  if (s.fetch_at) {
    fetch = `${s.fetch_source ?? "?"} at ${new Date(s.fetch_at).toLocaleString()}`;
    if (s.fetch_error) fetch += ": failed, the installed pack stays in use (stale, never current)";
  }
  const run = s.last_run_at ? `${s.last_run_outcome ?? "?"} at ${new Date(s.last_run_at).toLocaleString()}${s.last_run_labels?.length ? ` (${s.last_run_labels.join(", ")})` : ""}` : "";
  const triggers = `after agent writes ${s.post_write ? "on" : "off"}, each new commit ${s.commit_diff ? "on" : "off"}, full scan ${opengrepScheduleLabel(s.schedule_hours)}`;
  const rows: Array<[string, string]> = [
    ["Engine", s.engine ?? ""],
    ["Verification", s.verification ?? ""],
    ["Rule pack", pack],
    ["Last content fetch", fetch],
    ["Last run", run],
    ["Triggers", triggers],
    ["Isolation", s.isolation ?? ""],
  ];
  return rows.map(([k, v]) => [k, v || "none"]);
}
