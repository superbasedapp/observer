// secCoverage is the pure half of the Code security page's Projects and
// Coverage tabs (redesign plan docs/plans/code-security-page-redesign-plan-
// 2026-11-06.md, sections 3.3, 3.8, 4.1, 4.5): it aggregates
// GET /api/security/coverage into per-ecosystem rows, per-reason groups with
// what the person can do, and per-project ecosystem lists; and it works out
// the Projects tab's search, idle filter and the one setup notice. No JSX, no
// fetch, no import of the page's setup-reason predicate: callers pass it in
// (lib/scannerProblems.isSetupReason), so these rules stay testable alone.
// Named secCoverage, not coverage, because lib/coverage.ts is the Tools
// page's coverage model.

import type { CoverageProject, CoverageResponse, CoverageRun, CoverageSupported, ScanStartBody } from "./codeSecurityApi.ts";
import { projectLabel, reasonWords, type ScanOnline, type ScanStep, type SecurityProject, type SecurityRun } from "./codeSecurity.ts";
import { onlineFix, onlineFixLabel, onlineReasonWords, onlineSends, type OnlineFix } from "./scanSteps.ts";

export type SetupPredicate = (reason?: string) => boolean;

// ---- reasons and what to do about them (a data table) ----

/** What a person can do about each gap reason; "" (unknown) is the words alone.
 *  needs_online_lookup is done from this tab (onlineCheckAction: a scan with
 *  online checks, once they are on in Scanners > Package checks), so turning
 *  the switch on alone is never offered as the fix. */
export const REASON_ACTIONS: Readonly<Record<string, string>> = {
  no_lockfile: "Commit a lockfile",
  unpinned_version: "Pin exact versions",
  no_extractor: "Not supported yet",
  needs_online_lookup: "Scan these projects with online checks",
  no_advisory_data: "No vulnerability data exists for this ecosystem",
  isolation_refused: "The isolated scan could not start for this project",
};

/** reasonAction is the action line of a gap reason, "" for an unknown one. */
export function reasonAction(reason: string): string {
  return REASON_ACTIONS[reason] ?? "";
}

/** reasonText is the server's words for a reason, else the reason spelled out. */
export function reasonText(cov: Pick<CoverageResponse, "reasons"> | null | undefined, reason: string): string {
  return cov?.reasons?.[reason] || reasonWords(reason) || "No reason recorded";
}

// A failed run's reason, in the phrase the Projects table shows after
// "failed". Anything not listed is the reason spelled out.
const FAILURE_PHRASES: Readonly<Record<string, string>> = {
  isolation_refused: "isolation refused the run",
};

/** failureWords is the short phrase for why a run failed or could not scan. */
export function failureWords(reason: string | undefined): string {
  if (!reason) return "";
  return FAILURE_PHRASES[reason] ?? reasonWords(reason);
}

// A setup reason, in the phrase the setup notice uses after the scanner's name.
const SETUP_PHRASES: Readonly<Record<string, string>> = {
  not_installed: "is not installed",
  disabled: "is turned off",
  not_enabled: "is not turned on",
  no_database: "has no database",
  database_missing: "has no database",
  not_in_build: "is not in this build",
};

/** The name a driver goes by in a sentence. */
export const DRIVER_NAMES: Readonly<Record<string, string>> = {
  scalibr: "scalibr",
  osv: "osv-scanner",
  opengrep: "Opengrep",
  native: "The built-in checks",
};

export function driverName(driver: string): string {
  return DRIVER_NAMES[driver] ?? driver;
}

// The label of a driver's state in a project row.
const DRIVER_LABELS: Readonly<Record<string, string>> = {
  scalibr: "Dependencies (scalibr)",
  osv: "Dependencies (osv)",
  opengrep: "Code rules (Opengrep)",
  native: "Built-in checks",
};

export function driverLabel(driver: string): string {
  return DRIVER_LABELS[driver] ?? driver;
}

// ---- Projects tab ----

export type SetupNotice = { driver: string; reason: string; projects: number };

/** setupNotices lists each (driver, setup reason) seen on any project's runs
 *  once, with how many projects it affects, most affected first. */
export function setupNotices(projects: readonly SecurityProject[], isSetup: SetupPredicate): SetupNotice[] {
  const m = new Map<string, SetupNotice>();
  for (const p of projects) {
    const seen = new Set<string>();
    for (const r of p.runs ?? []) {
      if (!r.reason || !isSetup(r.reason)) continue;
      const k = `${r.driver}|${r.reason}`;
      if (seen.has(k)) continue;
      seen.add(k);
      const cur = m.get(k) ?? { driver: r.driver, reason: r.reason, projects: 0 };
      cur.projects += 1;
      m.set(k, cur);
    }
  }
  return [...m.values()].sort((a, b) => b.projects - a.projects || a.driver.localeCompare(b.driver) || a.reason.localeCompare(b.reason));
}

/** setupNoticeLine is one notice as a sentence. */
export function setupNoticeLine(n: SetupNotice): string {
  const phrase = SETUP_PHRASES[n.reason] ?? `is not set up (${reasonWords(n.reason)})`;
  const who = n.projects === 1 ? "1 project was" : `${n.projects} projects were`;
  return `${driverName(n.driver)} ${phrase}, so ${who} not scanned with it.`;
}

/** problemRuns are the runs a project row names: failed or unscanned for a
 *  reason that is not a setup fact (those show once, in the notice). */
export function problemRuns(runs: readonly SecurityRun[], isSetup: SetupPredicate): SecurityRun[] {
  return runs.filter(
    (r) => (r.outcome === "failed" || r.outcome === "not_scanned" || r.outcome === "unknown") && !(r.reason && isSetup(r.reason)),
  );
}

/** problemRunText is "Dependencies (scalibr): failed (isolation refused the run)". */
export function problemRunText(r: Pick<SecurityRun, "driver" | "outcome" | "reason">): string {
  const why = failureWords(r.reason);
  return `${driverLabel(r.driver)}: ${reasonWords(r.outcome)}${why ? ` (${why})` : ""}`;
}

/** filterProjects applies the search (name or path, case-insensitive) and the
 *  idle switch; hiddenIdle counts the idle matches the switch left out. */
export function filterProjects(
  projects: readonly SecurityProject[],
  query: string,
  showIdle: boolean,
): { rows: SecurityProject[]; hiddenIdle: number } {
  const q = query.trim().toLowerCase();
  const matches = projects.filter((p) => {
    if (!q) return true;
    return projectLabel(p).toLowerCase().includes(q) || (p.root_path ?? "").toLowerCase().includes(q);
  });
  const rows = showIdle ? matches : matches.filter((p) => p.active);
  return { rows, hiddenIdle: matches.length - rows.length };
}

/** idleHiddenLine is "112 idle projects hidden", "" for none. */
export function idleHiddenLine(n: number): string {
  if (n <= 0) return "";
  return `${n} idle ${n === 1 ? "project" : "projects"} hidden`;
}

/** capList splits a list into the first cap items and the count left over. */
export function capList<T>(items: readonly T[], cap: number): { shown: T[]; more: number } {
  const c = Math.max(0, cap);
  return { shown: items.slice(0, c), more: Math.max(0, items.length - c) };
}

// ---- ecosystems per project ----

/** latestRuns keeps each driver's newest run of a project. */
export function latestRuns(runs: readonly CoverageRun[]): CoverageRun[] {
  const by = new Map<string, CoverageRun>();
  for (const r of runs) {
    const cur = by.get(r.driver);
    if (!cur || r.started_at > cur.started_at) by.set(r.driver, r);
  }
  return [...by.values()].sort((a, b) => a.driver.localeCompare(b.driver));
}

/** projectEcosystems is the sorted union of the ecosystems a project's latest
 *  runs scanned. */
export function projectEcosystems(p: Pick<CoverageProject, "runs">): string[] {
  const set = new Set<string>();
  for (const r of latestRuns(p.runs ?? [])) for (const e of r.scanned ?? []) set.add(e);
  return [...set].sort((a, b) => a.localeCompare(b));
}

/** ecosystemsByProject maps a project root hash to its scanned ecosystems. */
export function ecosystemsByProject(cov: Pick<CoverageResponse, "projects"> | null | undefined): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const p of cov?.projects ?? []) out[p.project_root_hash] = projectEcosystems(p);
  return out;
}

// ---- file to ecosystem ----

function patternRegExp(pattern: string): RegExp {
  const body = pattern.replace(/[.+^${}()|[\]\\?]/g, "\\$&").replaceAll("*", "[^/]*");
  return pattern.includes("/") ? new RegExp(`(^|/)${body}$`, "i") : new RegExp(`^${body}$`, "i");
}

/** fileMatches reports whether a path is one of the files a pattern names
 *  (a bare name or "*.ext" matches the file's name; a pattern with a "/"
 *  matches the path's tail). */
export function fileMatches(pattern: string, path: string): boolean {
  const norm = path.replaceAll("\\", "/");
  const target = pattern.includes("/") ? norm : norm.slice(norm.lastIndexOf("/") + 1);
  return patternRegExp(pattern).test(target);
}

/** ecosystemForPath is the first supported ecosystem whose files (read or
 *  found but unread) include the path, "" when none does. */
export function ecosystemForPath(path: string, supported: readonly CoverageSupported[]): string {
  for (const s of supported) {
    if ([...(s.files ?? []), ...(s.unread_files ?? [])].some((f) => fileMatches(f, path))) return s.ecosystem;
  }
  return "";
}

// ---- supported table ----

export type SupportNote = { tone: "neutral" | "warn"; text: string };

/** The online-only remark while this node's online check is open: the
 *  daemon's note says to turn the checks on, which is already done. */
export const ONLINE_ONLY_OPEN_NOTE = 'Online checks only: on here; a scan with "Also check online" reads these files';

/** supportNote is the honest remark on a supported row, null when none.
 *  onlineOpen is whether this node's online check is open (the scan view's
 *  gate), so an online-only row does not tell the person to turn on what is
 *  already on. */
export function supportNote(s: CoverageSupported, onlineOpen = false): SupportNote | null {
  if (!s.advisory_source) {
    // The note is the daemon's own words for why the ecosystem is not checked;
    // it is not always about missing data, so it is shown as it is.
    return { tone: "warn", text: s.note ? s.note.charAt(0).toUpperCase() + s.note.slice(1) : "No advisory data" };
  }
  if (s.online_only && onlineOpen) return { tone: "neutral", text: ONLINE_ONLY_OPEN_NOTE };
  if (s.online_only) return { tone: "warn", text: s.note ? `Online checks only (${s.note})` : "Online checks only" };
  if (s.note) return { tone: "neutral", text: s.note };
  return null;
}

// ---- in your projects ----

export type ProjectRef = { hash: string; name: string };

export type EcosystemRow = {
  ecosystem: string;
  /** The supported row, null for an ecosystem a scanner reported that the list does not carry. */
  supported: CoverageSupported | null;
  /** Projects where it was scanned. */
  scanned: ProjectRef[];
  /** Projects where its files were found but it was not scanned. */
  detectedOnly: ProjectRef[];
};

function ref(p: CoverageProject): ProjectRef {
  return { hash: p.project_root_hash, name: projectLabel({ name: p.name, project_root_hash: p.project_root_hash }) };
}

function byName(a: ProjectRef, b: ProjectRef): number {
  return a.name.localeCompare(b.name) || a.hash.localeCompare(b.hash);
}

/** ecosystemRows is one row per supported ecosystem (plus any ecosystem a run
 *  scanned that the supported list lacks), with the projects that had it
 *  scanned and those where it was only detected as skipped files. Rows with
 *  projects come first, most scanned first; the rest keep their order. */
export function ecosystemRows(cov: CoverageResponse): EcosystemRow[] {
  const rows = new Map<string, EcosystemRow>();
  for (const s of cov.supported ?? []) rows.set(s.ecosystem, { ecosystem: s.ecosystem, supported: s, scanned: [], detectedOnly: [] });
  const row = (eco: string): EcosystemRow => {
    let r = rows.get(eco);
    if (!r) {
      r = { ecosystem: eco, supported: null, scanned: [], detectedOnly: [] };
      rows.set(eco, r);
    }
    return r;
  };
  for (const p of cov.projects ?? []) {
    const scanned = new Set(projectEcosystems(p));
    for (const e of scanned) row(e).scanned.push(ref(p));
    const detected = new Set<string>();
    for (const r of latestRuns(p.runs ?? [])) {
      for (const f of r.skipped ?? []) {
        const e = ecosystemForPath(f.path, cov.supported ?? []);
        if (e && !scanned.has(e)) detected.add(e);
      }
    }
    for (const e of detected) row(e).detectedOnly.push(ref(p));
  }
  const all = [...rows.values()];
  for (const r of all) {
    r.scanned.sort(byName);
    r.detectedOnly.sort(byName);
  }
  const used = all.filter((r) => r.scanned.length + r.detectedOnly.length > 0);
  const unused = all.filter((r) => r.scanned.length + r.detectedOnly.length === 0);
  used.sort((a, b) => b.scanned.length - a.scanned.length || b.detectedOnly.length - a.detectedOnly.length || a.ecosystem.localeCompare(b.ecosystem));
  return [...used, ...unused];
}

/** detectedNotScanned is the ecosystems found only as skipped files in at
 *  least one project, with those projects. */
export function detectedNotScanned(cov: CoverageResponse): { ecosystem: string; projects: ProjectRef[] }[] {
  return ecosystemRows(cov)
    .filter((r) => r.detectedOnly.length > 0)
    .map((r) => ({ ecosystem: r.ecosystem, projects: r.detectedOnly }));
}

// ---- files we found but did not read ----

export type SkippedEntry = { hash: string; project: string; path: string; driver: string };

export type ReasonGroup = {
  reason: string;
  words: string;
  /** What the person can do, "" when the words say it all. */
  action: string;
  /** Files in the group, counting those past the API's per-run cap. */
  count: number;
  /** Files counted but not listed (the API lists at most 50 a run). */
  hidden: number;
  projects: number;
  /** The projects' root hashes, sorted (what a group action scans). */
  projectHashes: string[];
  entries: SkippedEntry[];
};

/** reasonGroups groups every project's latest skipped files by reason, most
 *  files first. A file two drivers both skipped is listed once. */
export function reasonGroups(cov: CoverageResponse): ReasonGroup[] {
  const groups = new Map<string, { entries: SkippedEntry[]; seen: Set<string>; hidden: number; projects: Set<string> }>();
  const g = (reason: string) => {
    let x = groups.get(reason);
    if (!x) {
      x = { entries: [], seen: new Set(), hidden: 0, projects: new Set() };
      groups.set(reason, x);
    }
    return x;
  };
  for (const p of cov.projects ?? []) {
    const name = projectLabel({ name: p.name, project_root_hash: p.project_root_hash });
    for (const r of latestRuns(p.runs ?? [])) {
      for (const f of r.skipped ?? []) {
        const x = g(f.reason || "unknown");
        const key = `${p.project_root_hash}|${f.path}`;
        x.projects.add(p.project_root_hash);
        if (x.seen.has(key)) continue;
        x.seen.add(key);
        x.entries.push({ hash: p.project_root_hash, project: name, path: f.path, driver: r.driver });
      }
      // Files past the API's per-run cap have no path or reason on record
      // here; they are counted under "unknown" so the total stays true.
      const extra = Math.max(0, (r.skipped_total ?? 0) - (r.skipped ?? []).length);
      if (extra > 0) {
        const x = g("unknown");
        x.hidden += extra;
        x.projects.add(p.project_root_hash);
      }
    }
  }
  const out: ReasonGroup[] = [];
  for (const [reason, x] of groups) {
    x.entries.sort((a, b) => a.project.localeCompare(b.project) || a.path.localeCompare(b.path));
    out.push({
      reason,
      words: reasonText(cov, reason),
      action: reasonAction(reason),
      count: x.entries.length + x.hidden,
      hidden: x.hidden,
      projects: x.projects.size,
      projectHashes: [...x.projects].sort((a, b) => a.localeCompare(b)),
      entries: x.entries,
    });
  }
  return out.sort((a, b) => b.count - a.count || a.reason.localeCompare(b.reason));
}

// ---- checking online-only files (dashboard CLI parity plan, decision P-1) ----

/** The reason a file only the online check can read carries. */
export const NEEDS_ONLINE = "needs_online_lookup";

/** What a "Check online" control does: start a scan of the projects with the
 *  dependency step and online checks; send the person to where the check is
 *  turned on; wait for the running scan; or nothing (no online check here). */
export type OnlineCheckAction =
  | { kind: "scan"; label: string; body: ScanStartBody; sends: string }
  | { kind: "setup"; label: string; why: string; fix: OnlineFix }
  | { kind: "busy"; label: string; why: string }
  | { kind: "none" };

type OnlineCheckInput = { online?: ScanOnline | null; steps: readonly ScanStep[]; projects: readonly string[]; running: boolean };

// ONLINE_CHECK_RULES: walked top-down, the first row that holds decides.
const ONLINE_CHECK_RULES: readonly { when: (o: OnlineCheckInput, step: ScanStep | undefined) => boolean; act: (o: OnlineCheckInput, step: ScanStep | undefined) => OnlineCheckAction }[] = [
  { when: (o) => o.projects.length === 0 || !o.online, act: () => ({ kind: "none" }) },
  {
    when: (_o, step) => !step || !step.ready,
    act: (_o, step) => ({
      kind: "setup",
      label: "Set up the dependency scanners in Scanners",
      why: step?.reason ? reasonWords(step.reason) : "The dependency scanners are not ready",
      fix: "scanners",
    }),
  },
  { when: (o) => !o.online!.open, act: (o) => onlineSetupAction(o.online!) },
  { when: (o) => o.running, act: () => ({ kind: "busy", label: "Check online", why: "A scan is running" }) },
  {
    when: () => true,
    act: (o) => ({
      kind: "scan",
      label: o.projects.length === 1 ? "Check online" : `Check ${o.projects.length} projects online`,
      body: { projects: [...o.projects], steps: [o.online!.step], online: true },
      sends: onlineSends(o.online!.relay),
    }),
  },
];

/** onlineSetupAction sends the person to where a closed online gate opens. */
function onlineSetupAction(online: ScanOnline): OnlineCheckAction {
  const fix = onlineFix(online.reason);
  return {
    kind: "setup",
    label: onlineFixLabel(fix) || "Online checks are not available here",
    why: onlineReasonWords(online.reason) || "Online checks are not available",
    fix,
  };
}

/** supportedOnlineAction is the control on a supported row whose ecosystem
 *  only the online check reads: a "Check online" of the projects that have
 *  that ecosystem's files, or, when none does, the way to turn the online
 *  check on while it is closed (the row's note says to; it should link). */
export function supportedOnlineAction(o: OnlineCheckInput): OnlineCheckAction {
  if (o.projects.length > 0) return onlineCheckAction(o);
  if (!o.online || o.online.open) return { kind: "none" };
  return onlineSetupAction(o.online);
}

/** onlineCheckAction is what a needs_online_lookup row's control does for
 *  these projects, given the node's online check, its scanner list and
 *  whether a scan runs. */
export function onlineCheckAction(o: OnlineCheckInput): OnlineCheckAction {
  const step = o.online ? o.steps.find((s) => s.id === o.online!.step) : undefined;
  for (const r of ONLINE_CHECK_RULES) if (r.when(o, step)) return r.act(o, step);
  return { kind: "none" };
}

/** needsOnline reports whether a project's latest runs left a file only the
 *  online check can read. */
export function needsOnline(p: Pick<CoverageProject, "runs">): boolean {
  return latestRuns(p.runs ?? []).some((r) => (r.skipped ?? []).some((f) => f.reason === NEEDS_ONLINE));
}

/** coverageSummary is the one line over the tab: how much was scanned. */
export function coverageSummary(cov: CoverageResponse): { projectsWithRuns: number; ecosystemsScanned: number; filesSkipped: number } {
  const eco = new Set<string>();
  let projectsWithRuns = 0;
  let filesSkipped = 0;
  for (const p of cov.projects ?? []) {
    const runs = latestRuns(p.runs ?? []);
    if (runs.length > 0) projectsWithRuns += 1;
    for (const e of projectEcosystems(p)) eco.add(e);
    for (const r of runs) filesSkipped += Math.max(r.skipped_total ?? 0, (r.skipped ?? []).length);
  }
  return { projectsWithRuns, ecosystemsScanned: eco.size, filesSkipped };
}

/** hasCoverage is false until some project has a recorded dependency run. */
export function hasCoverage(cov: CoverageResponse | null | undefined): boolean {
  return (cov?.projects ?? []).some((p) => (p.runs ?? []).length > 0);
}
