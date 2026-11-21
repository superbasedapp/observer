// codeSecurity.ts is the Code security page's pure model: the API shapes of
// /api/security/status, /findings, /findings/{id} and /scan, and the
// labels, links and orderings the page renders from them. No React, no
// fetch: unit-tested directly (codeSecurity.test.ts).
//
// The project rule (2026-11-02): a project is NAMED, never shown as its
// root hash. The page used to print the hash's first 12 characters, which
// read exactly like a git commit id; projectLabel is the one place a
// project row becomes text, and it falls back to "Unknown project" (plus a
// short hash) only for a hash no stored project names. A Findings project
// filter value the status read does not list reads "Project no longer
// tracked" (projectFilterLabel).

import type { SecurityException } from "./codeSecurityExceptions.ts";
import {
  EMPTY_FINDINGS_FILTERS,
  findingsApiParams,
  groupDrillDown,
  parseFindingsFilters,
  writeFindingsFilters,
  type FacetValue,
  type FindingGroup,
  type FindingLanguage,
  type FindingsFilters,
  type FindingsGroupBy,
  type FindingsPageExtra,
} from "./codeSecurityApi.ts";

/** One driver's newest scan run on a project. */
export type SecurityRun = {
  driver: string;
  scope: string;
  outcome: string;
  reason?: string;
  findings: number;
  started_at: string;
  duration_ms: number;
};

export type SecurityCount = { category: string; severity: string; n: number };

/** One row of GET /api/security/status. */
export type SecurityProject = {
  project_root_hash: string;
  project_id?: number;
  name: string;
  root_path?: string;
  last_session_at?: string;
  active: boolean;
  state: string;
  reason: string;
  blocking: number;
  open: number;
  counts: SecurityCount[];
  last_scan_at?: string;
  runs: SecurityRun[];
};

export type SecurityStatus = { module: string; projects: SecurityProject[] };

/** One row of GET /api/security/findings. */
export type SecurityFinding = {
  id: string;
  project_root_hash: string;
  rule_id: string;
  driver: string;
  category: string;
  severity: string;
  confidence: string;
  scope: string;
  baseline: string;
  status: string;
  rel_path: string;
  start_line: number;
  message: string;
  first_seen: string;
  last_seen: string;
  session_id?: string;
  tool?: string;
  /** "name@version" of a vulnerable dependency; only on category
   *  vulnerable_dependency rows. */
  package?: string;
  ecosystem?: string;
  /** The reachability tier (import level, or the Go symbol check's
   *  called / not_called); dependency rows only. */
  reach?: FindingReach;
  /** The CISA KEV and FIRST EPSS labels; dependency rows only. */
  exploit?: FindingExploit;
};

/** A dependency finding's reachability tier (view time). It ranks and
 *  labels only; neither "not_imported_directly" nor "not_called" ever means
 *  unreachable. "called" and "not_called" come from the Go symbol check of
 *  one binary the project built (source "govulncheck-binary") or one go.mod
 *  (source "govulncheck-source"), named by target; an approximate "called"
 *  is the Rust call-site name match (approximate set). */
export type FindingReach = {
  level: "called" | "imported" | "potentially_affected" | "not_called" | "not_imported_directly" | "unknown" | string;
  tests_only?: boolean;
  /** The tier rests on a name match (a Rust call site, a Python
   *  distribution's own name), not an exact one. */
  approximate?: boolean;
  source?: string;
  reason?: string;
  /** The binary or go.mod a called / not_called tier rests on. */
  target?: string;
  /** The listed function a "called" tier reached. */
  symbol?: string;
  /** Why a symbol check that covered the finding could not decide (the
   *  tier is then the import level's), e.g. "stripped_binary". */
  symbol_note?: string;
  /** The tier in words, e.g. "imported (go imports)". */
  label: string;
};

/** A dependency finding's exploit labels (view time). A kind that is not
 *  available is never read as "not exploited". */
export type FindingExploit = {
  kev_available: boolean;
  epss_available: boolean;
  kev?: { cve: string; date_added: string; ransomware?: boolean };
  epss?: { cve: string; score: number; percentile: number; model?: string; date?: string };
  /** The labels in words, most severe first ("Exploit data unavailable"
   *  when neither kind answered). */
  badges: string[];
  /** FIRST's citation: present whenever an EPSS value is shown. */
  epss_citation?: string;
  /** The KEV source line in plain words (no CISA branding). */
  kev_notice?: string;
};

/** The tone a signal label takes. */
export type SignalTone = "neutral" | "warn" | "danger";

/** One small label of a dependency finding: its text and tone. */
export type SignalLabel = { text: string; tone: SignalTone; title?: string };

/** REACH_TONE: a called function is a danger and an imported package, or a
 *  binary built with an affected release, is worth a look; an approximate
 *  called (a name match) reads as a look too (reachTone). The rest is
 *  neutral (unknown means unknown, not imported directly and not called
 *  are not "safe"). */
const REACH_TONE: Readonly<Record<string, SignalTone>> = { called: "danger", imported: "warn", potentially_affected: "warn" };

/** reachTone is a tier's tone: an approximate called is a name match, so warn. */
function reachTone(r: FindingReach): SignalTone {
  if (r.level === "called" && r.approximate) return "warn";
  return REACH_TONE[r.level] ?? "neutral";
}

/** BADGE_TONE: the exploit badge words (secexploit.Badges) to a tone, the
 *  first matching row wins; an unavailable label is neutral. */
const BADGE_TONE: readonly { match: RegExp; tone: SignalTone }[] = [
  { match: /^Exploited in the wild/, tone: "danger" },
  { match: /^Known ransomware/, tone: "danger" },
  { match: /^EPSS (\d|below)/, tone: "warn" },
];

/** reachWords is a tier as a short label ("imported, tests only",
 *  "called, approximate"). */
export function reachWords(r: FindingReach): string {
  const qual = (r.tests_only ? ", tests only" : "") + (r.approximate ? ", approximate" : "");
  switch (r.level) {
    case "called":
      return "called" + qual;
    case "imported":
      return "imported" + qual;
    case "not_called":
      return "not called";
    case "not_imported_directly":
      return "not imported directly";
    case "potentially_affected":
      // A Go binary's embedded standard library, matched by its Go version:
      // the binary may not use the affected code.
      return "potentially affected";
  }
  return "reach unknown";
}

/** findingSignalLabels are a dependency row's small labels: the exploit
 *  badges (KEV first) then the reach tier; none for any other finding. */
export function findingSignalLabels(f: Pick<SecurityFinding, "reach" | "exploit">): SignalLabel[] {
  const out: SignalLabel[] = [];
  for (const b of f.exploit?.badges ?? []) {
    out.push({ text: b, tone: BADGE_TONE.find((r) => r.match.test(b))?.tone ?? "neutral" });
  }
  if (f.reach) out.push({ text: reachWords(f.reach), tone: reachTone(f.reach), title: f.reach.label });
  return out;
}

/** GET /api/security/findings: one server-sorted page. */
export type FindingsPage = { findings: SecurityFinding[]; total: number; page: number; limit: number };

/** One reference link of an advisory. */
export type AdvisoryReference = { type?: string; url: string };

/** One affected range of an advisory (OSV semantics). */
export type AdvisoryRange = { introduced?: string; fixed?: string; last_affected?: string };

/** One advisory, read from the local OSV database at view time. */
export type DependencyAdvisory = {
  id: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  details_truncated?: boolean;
  published?: string;
  modified?: string;
  cwe?: string[];
  cvss?: string[];
  references?: AdvisoryReference[];
  ranges?: AdvisoryRange[];
  affected_symbols?: string[];
};

/** Why a dependency could not be located in its lockfile. */
export type LocationReason = "" | "not_found" | "file_too_large" | "unsupported_format" | "unreadable" | "outside_project";

/** One line of the lockfile excerpt; match marks the dependency line(s). */
export type LockfileContextLine = { line: number; text: string; match: boolean };

export type DependencyLocation = {
  rel_path: string;
  found: boolean;
  reason?: LocationReason;
  start_line?: number;
  end_line?: number;
  context?: LockfileContextLine[];
};

export type AdvisorySource = "local_database" | "not_in_local_database" | "database_not_installed";

/** The dependency block of a vulnerable_dependency finding detail. */
export type FindingDependency = {
  ecosystem: string;
  name: string;
  version: string;
  relationship?: "direct" | "transitive" | "";
  scope?: "runtime" | "dev" | "";
  introduced_by?: string[];
  location?: DependencyLocation;
  fixed_versions?: string[];
  suggested_version?: string;
  advisory_source: AdvisorySource;
  advisories?: DependencyAdvisory[];
};

/** GET /api/security/findings/{id}. */
export type SecurityFindingDetail = {
  finding: SecurityFinding;
  rule_pack?: string;
  driver_version?: string;
  fix_hint?: string;
  model?: string;
  attribution?: string;
  closed_at?: string;
  exception_id?: string;
  project?: { id: number; name: string; root_path: string };
  sightings: string[];
  commits: { sha: string; last_seen: string; remotes?: string[] }[];
  events: { kind: string; detail?: string; at: string }[];
  exceptions: SecurityException[];
  /** Present only for a vulnerable_dependency finding. */
  dependency?: FindingDependency;
};

/** One scanner "Scan now" can run. */
export type ScanStep = { id: string; label: string; ready: boolean; reason?: string };

/** One step's outcome on one project. online is set only on the step that
 *  can match online, when the job asked for online checks: "checked", or
 *  why it did not run (an online gate reason for that project). */
export type ScanResult = { id: string; label: string; outcome: string; reason?: string; findings: number; new: number; online?: string };

export type ScanJob = {
  id: string;
  state: "running" | "done" | "cancelled";
  scope: "project" | "all";
  started_at: string;
  finished_at?: string;
  total: number;
  done: number;
  /** The job asked the dependency step to also check online. */
  online?: boolean;
  current?: { project_root_hash: string; name: string; step: string };
  projects: { project_root_hash: string; project_id?: number; name: string; steps: ScanResult[] }[];
};

/** The online dependency check's state (GET /api/security/scan online,
 *  decision P-1 of docs/plans/dashboard-cli-parity-plan-2026-11-06.md):
 *  step is the scanner it applies to; open says it may run; reason is the
 *  first closed gate row (online_checks_off, disclosure_not_shown,
 *  online_needs_scalibr); relay marks a managed node (matching goes to the
 *  organization's relay, git submodules are not checked online). */
export type ScanOnline = { step: string; open: boolean; reason?: string; relay?: boolean };

/** GET /api/security/scan. online is absent where the build offers none
 *  (and on an older daemon). */
export type ScanView = { confirm_token: string; steps: ScanStep[]; online?: ScanOnline; job: ScanJob | null };

const HASH_CHARS = 8;

/** projectLabel is the text a project row shows: its name, else its root's
 *  last element, else "Unknown project" with a short hash. Never the bare
 *  hash. */
export function projectLabel(p: { name?: string; root_path?: string; project_root_hash: string }): string {
  if (p.name) return p.name;
  if (p.root_path) {
    const parts = p.root_path.split(/[\\/]+/).filter(Boolean);
    if (parts.length > 0) return parts[parts.length - 1];
  }
  return `Unknown project (${p.project_root_hash.slice(0, HASH_CHARS)})`;
}

/** projectFilterLabel names a project filter value (a root hash) by the
 *  status read's projects: the project's label when the read lists it.
 *  Once the read has answered without it (a stale link, or a project
 *  Observer holds no findings or scans for any more) it reads "Project no
 *  longer tracked" with the short hash; before the read answers (index
 *  null), projectLabel's own short-hash form. Never the bare value. */
export function projectFilterLabel(hash: string, index: ReadonlyMap<string, SecurityProject> | null): string {
  const p = index?.get(hash);
  if (p) return projectLabel(p);
  if (index) return `Project no longer tracked (${hash.slice(0, HASH_CHARS)})`;
  return projectLabel({ project_root_hash: hash });
}

/** projectHref is the Projects page detail of a project, null when the row
 *  names no stored project (render plain text, never a dead link). */
export function projectHref(projectId: number | undefined | null): string | null {
  if (!projectId) return null;
  return `/projects?project=${encodeURIComponent(String(projectId))}`;
}

/** commitHref opens one commit in the project drawer's Commits tab. */
export function commitHref(projectId: number | undefined | null, sha: string): string | null {
  if (!projectId || !sha) return null;
  return `/projects?project=${encodeURIComponent(String(projectId))}&dtab=commits&sha=${encodeURIComponent(sha)}`;
}

/** SECURITY_VERDICTS_HREF is where a commit or push the commit gate holds is
 *  approved: its verdict row on Security > Verdicts ("approve...", which
 *  opens the Approvals form). The Findings drawer has no approve of its own
 *  (dashboard CLI parity plan B-CS7); the CLI twin is `observer guard
 *  approve`. */
export const SECURITY_VERDICTS_HREF = "/security?tab=verdicts";

/** heldApproveHref is the approve link a finding's drawer shows: only for
 *  an open finding that holds a commit (the commit gate's case). */
export function heldApproveHref(f: { status: string }, commits: readonly unknown[]): string | null {
  return f.status === "open" && commits.length > 0 ? SECURITY_VERDICTS_HREF : null;
}

/** sessionHref is the Sessions page drawer of a session. */
export function sessionHref(sessionId: string | undefined | null): string | null {
  if (!sessionId) return null;
  return `/sessions?session=${encodeURIComponent(sessionId)}`;
}

/** findingWhere is a finding's location in one line. */
export function findingWhere(f: Pick<SecurityFinding, "rel_path" | "start_line">): string {
  if (!f.rel_path) return "the project";
  return f.start_line > 0 ? `${f.rel_path}:${f.start_line}` : f.rel_path;
}

const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/** severityRank orders severities worst first (unknown last). */
export function severityRank(s: string): number {
  return SEVERITY_RANK[s] ?? 9;
}

const STATE_RANK: Record<string, number> = { blocking: 0, dirty: 1, unknown: 2, clean: 3, absent: 4 };

/** sortProjects puts what needs attention first: blocking, then dirty, then
 *  the most open findings, then active before idle, then by name. */
export function sortProjects(rows: SecurityProject[]): SecurityProject[] {
  return [...rows].sort((a, b) => {
    const s = (STATE_RANK[a.state] ?? 5) - (STATE_RANK[b.state] ?? 5);
    if (s !== 0) return s;
    if (a.open !== b.open) return b.open - a.open;
    if (a.active !== b.active) return a.active ? -1 : 1;
    return projectLabel(a).localeCompare(projectLabel(b));
  });
}

/** worstSeverity is a project's worst open severity, "" when none. */
export function worstSeverity(counts: SecurityCount[]): string {
  let best = "";
  for (const c of counts) {
    if (c.n > 0 && (best === "" || severityRank(c.severity) < severityRank(best))) best = c.severity;
  }
  return best;
}

/** failingRuns are a project's drivers whose newest run failed or could
 *  not scan: the "last scan" cell names them, so an error is never hidden
 *  behind a time. */
export function failingRuns(runs: SecurityRun[]): SecurityRun[] {
  return runs.filter((r) => r.outcome === "failed" || r.outcome === "not_scanned" || r.outcome === "unknown");
}

/** reasonWords turns a snake_case reason into words. */
export function reasonWords(s: string | undefined): string {
  return (s ?? "").replaceAll("_", " ");
}

/** scanSummary is the page's headline numbers. */
export function scanSummary(rows: SecurityProject[]): {
  projects: number;
  blocking: number;
  open: number;
  failing: number;
  lastScanAt: string;
} {
  let blocking = 0;
  let open = 0;
  let failing = 0;
  let last = "";
  for (const p of rows) {
    if (p.state === "blocking") blocking++;
    open += p.open;
    if (failingRuns(p.runs).length > 0) failing++;
    if (p.last_scan_at && p.last_scan_at > last) last = p.last_scan_at;
  }
  return { projects: rows.length, blocking, open, failing, lastScanAt: last };
}

/** scanRunning reports a job that is still running. */
export function scanRunning(job: ScanJob | null | undefined): boolean {
  return job?.state === "running";
}

/** scanProgress is a job's done share, 0..1. */
export function scanProgress(job: ScanJob): number {
  if (job.total <= 0) return job.state === "running" ? 0 : 1;
  return Math.min(1, job.done / job.total);
}

/** scanJobLine is the one line a job shows. */
export function scanJobLine(job: ScanJob): string {
  const where = job.scope === "all" ? `${job.done} of ${job.total} projects` : job.projects[0]?.name ?? "the project";
  if (job.state === "running") {
    const on = job.current ? `: ${job.current.step} on ${job.current.name}` : "";
    return job.scope === "all" ? `Scanning ${where}${on}` : `Scanning ${where}${job.current ? `: ${job.current.step}` : ""}`;
  }
  const t = scanJobTotals(job);
  const tail = `${t.findings} finding(s), ${t.new} new${t.failed > 0 ? `, ${t.failed} step(s) failed` : ""}`;
  if (job.state === "cancelled") return `Cancelled after ${job.done} of ${job.total} project(s): ${tail}`;
  return `Scanned ${job.scope === "all" ? `${job.total} project(s)` : where}: ${tail}`;
}

/** scanJobTotals adds up a job's step results. */
export function scanJobTotals(job: ScanJob): { findings: number; new: number; failed: number; skipped: number } {
  let findings = 0;
  let fresh = 0;
  let failed = 0;
  let skipped = 0;
  for (const p of job.projects) {
    for (const s of p.steps) {
      findings += s.findings;
      fresh += s.new;
      if (s.outcome === "failed" || s.outcome === "busy") failed++;
      if (s.outcome === "skipped" || s.outcome === "not_scanned") skipped++;
    }
  }
  return { findings, new: fresh, failed, skipped };
}

/** scanToast is the toast a finished job raises, with its tone. */
export function scanToast(job: ScanJob): { text: string; variant: "success" | "warn" | "danger" | "info" } {
  const t = scanJobTotals(job);
  const variant = t.failed > 0 ? "danger" : job.state === "cancelled" ? "warn" : t.new > 0 ? "warn" : "success";
  return { text: scanJobLine(job), variant };
}

/** projectScanState is what one project's "Scan" button shows: whether
 *  this project is being scanned, or another job blocks it. */
export function projectScanState(job: ScanJob | null | undefined, hash: string): "idle" | "scanning" | "blocked" {
  if (!scanRunning(job)) return "idle";
  if (job?.current?.project_root_hash === hash) return "scanning";
  if (job?.scope === "project" && job.projects[0]?.project_root_hash === hash) return "scanning";
  return "blocked";
}

/** readySteps are the scanners a scan will run. */
export function readySteps(steps: ScanStep[]): ScanStep[] {
  return steps.filter((s) => s.ready);
}

// ---- Dependency finding detail ------------------------------------------

/** dependencyKindWords says how a package is used: "transitive, dev only",
 *  "direct, runtime", "direct". Empty when neither is known. */
export function dependencyKindWords(dep: Pick<FindingDependency, "relationship" | "scope">): string {
  const parts: string[] = [];
  if (dep.relationship === "direct" || dep.relationship === "transitive") parts.push(dep.relationship);
  if (dep.scope === "dev") parts.push("dev only");
  else if (dep.scope === "runtime") parts.push("runtime");
  return parts.join(", ");
}

/** dependencyPackage is the package as "name@version" (just the name when
 *  the version is unknown). */
export function dependencyPackage(dep: Pick<FindingDependency, "name" | "version">): string {
  return dep.version ? `${dep.name}@${dep.version}` : dep.name;
}

/** dependencyFixedIn is the fixed versions as one phrase, "" when none are
 *  known: "4.17.21", "4.17.21, 5.0.1". */
export function dependencyFixedIn(dep: Pick<FindingDependency, "fixed_versions">): string {
  return (dep.fixed_versions ?? []).join(", ");
}

/** lockfileLocationLabel is "path:line" when a line is known, else the path. */
export function lockfileLocationLabel(loc: Pick<DependencyLocation, "rel_path" | "start_line">): string {
  return loc.start_line && loc.start_line > 0 ? `${loc.rel_path}:${loc.start_line}` : loc.rel_path;
}

const LOCATION_REASON_WORDS: Record<string, string> = {
  not_found: "The package was not found in this file.",
  file_too_large: "The file is too large to show an excerpt.",
  unsupported_format: "This file format is not supported for line lookup.",
  unreadable: "The file could not be read.",
  outside_project: "The file is outside the project, so it is not shown.",
};

/** locationNotFoundWords is the one muted line shown when the lockfile line
 *  could not be located. */
export function locationNotFoundWords(reason: string | undefined): string {
  return LOCATION_REASON_WORDS[reason ?? ""] ?? "The line in the lockfile could not be located.";
}

/** findingWhereDetail is findingWhere, taking the lockfile line from the
 *  dependency location when the finding row itself carries none. */
export function findingWhereDetail(d: Pick<SecurityFindingDetail, "finding" | "dependency">): string {
  const f = d.finding;
  const line = f.start_line > 0 ? f.start_line : (d.dependency?.location?.start_line ?? 0);
  return findingWhere({ rel_path: f.rel_path, start_line: line });
}

/** advisoryRangeWords reads one affected range: "introduced 4.0.0, fixed
 *  4.17.21". An introduced of "0" means from the first release. */
export function advisoryRangeWords(r: AdvisoryRange): string {
  const parts: string[] = [];
  if (r.introduced) parts.push(r.introduced === "0" ? "affected from the first release" : `introduced ${r.introduced}`);
  if (r.fixed) parts.push(`fixed ${r.fixed}`);
  else if (r.last_affected) parts.push(`last affected ${r.last_affected}`);
  return parts.join(", ");
}

/** The advisory details collapse to this many lines until "Show more". */
export const ADVISORY_COLLAPSED_LINES = 6;
const ADVISORY_COLLAPSED_CHARS = 600;

/** advisoryDetailsCollapsible reports whether the details are long enough to
 *  need a "Show more" toggle. */
export function advisoryDetailsCollapsible(text: string): boolean {
  return text.split("\n").length > ADVISORY_COLLAPSED_LINES || text.length > ADVISORY_COLLAPSED_CHARS;
}

/** safeReference turns an advisory reference into an external link: http and
 *  https only (the text is third-party), with the host and the reference
 *  type for the label. Null for anything else. */
export function safeReference(ref: AdvisoryReference): { href: string; host: string; type: string } | null {
  let u: URL;
  try {
    u = new URL(ref.url);
  } catch {
    return null;
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") return null;
  return { href: u.toString(), host: u.host, type: (ref.type ?? "").toLowerCase() };
}

/** advisorySourceNote is the muted line shown in place of the Advisory
 *  section when the local OSV database gave no advisory; "" when it did. */
export function advisorySourceNote(source: AdvisorySource | string): string {
  switch (source) {
    case "not_in_local_database":
      return "This advisory is not in the local OSV database.";
    case "database_not_installed":
      return "The OSV database is not installed; accept its download on the Scanners card.";
    default:
      return "";
  }
}

// ---- Server paging -------------------------------------------------------

/** FINDINGS_PAGE_SIZE is the findings table's page size (API default). */
export const FINDINGS_PAGE_SIZE = 50;
/** PROJECTS_PAGE_SIZE is the projects table's client-side page size. */
export const PROJECTS_PAGE_SIZE = 25;

/** The findings columns the API can sort on, by column id. "rank" is the
 *  ranking rule (KEV first, then reach, then EPSS, then severity), which
 *  only ever reads most urgent first. */
export const FINDING_SORT_COLUMNS: readonly string[] = ["rank", "severity", "last_seen", "first_seen"];

/** FindingSort mirrors TanStack's SortingState. */
export type FindingSort = { id: string; desc: boolean }[];

/** The page's default order: the ranking rule, most urgent first. */
export const DEFAULT_FINDING_SORT: FindingSort = [{ id: "rank", desc: true }];

/** findingsSortParams maps the table's sort state to the API's sort/dir; an
 *  empty or unsortable state is the page default (the rank). The rank has
 *  one direction. */
export function findingsSortParams(sorting: FindingSort): { sort: string; dir: "asc" | "desc" } {
  const s = sorting[0];
  if (!s || !FINDING_SORT_COLUMNS.includes(s.id) || s.id === "rank") return { sort: "rank", dir: "desc" };
  return { sort: s.id, dir: s.desc ? "desc" : "asc" };
}

/** normalizeFindingSort keeps the rank in its one direction (a header click
 *  that would flip it to ascending keeps it descending). */
export function normalizeFindingSort(sorting: FindingSort): FindingSort {
  return sorting.map((s) => (s.id === "rank" ? { id: "rank", desc: true } : { id: s.id, desc: s.desc }));
}

// ---- Findings list: filters, paging, groups (redesign lane 2b) ------------
//
// The filters live in the page URL (codeSecurityApi.ts parse/write); the
// page and sort of each server-paged read live in component state here.
// A page number belongs to the filters it was paged under (filterKey), so a
// filter change reads page 1 at once, with no request for the old page
// number of the new result set; the sort is kept across filter changes.

/** FindingsListState is one server-paged read's sort and page, and the
 *  filters (findingsFilterKey) the page number belongs to. */
export type FindingsListState = { filterKey: string; page: number; sorting: FindingSort };

export type FindingsListAction =
  | { type: "sort"; sorting: FindingSort; filterKey: string }
  | { type: "page"; page: number; filterKey: string };

export const INITIAL_FINDINGS_LIST: FindingsListState = {
  filterKey: "",
  page: 1,
  sorting: DEFAULT_FINDING_SORT,
};

/** findingsListReducer: a sort change returns to page 1 (the old page
 *  number means nothing for the new order); a page move keeps the sort.
 *  Both record the filters they happened under. */
export function findingsListReducer(state: FindingsListState, a: FindingsListAction): FindingsListState {
  switch (a.type) {
    case "sort":
      return { filterKey: a.filterKey, sorting: a.sorting, page: 1 };
    case "page":
      return { ...state, filterKey: a.filterKey, page: Math.max(1, Math.floor(a.page) || 1) };
  }
}

/** findingsListPage is the page a state reads under these filters: its own
 *  page while the filters are the ones it was paged under, else page 1. */
export function findingsListPage(s: FindingsListState, filterKey: string): number {
  return s.filterKey === filterKey ? s.page : 1;
}

/** findingsFilterKey identifies a filter set for paging: two filter sets
 *  with the same key read the same rows. The grouping is not part of it
 *  (the list read ignores it; the group read adds it, findingGroupsKey). */
export function findingsFilterKey(f: FindingsFilters): string {
  return JSON.stringify(findingsApiParams(f));
}

/** findingsQueryParams is the GET /api/security/findings query of the
 *  filters and a paging state. */
export function findingsQueryParams(f: FindingsFilters, s: FindingsListState): Record<string, string | number | undefined> {
  const { sort, dir } = findingsSortParams(s.sorting);
  return {
    ...findingsApiParams(f),
    page: findingsListPage(s, findingsFilterKey(f)),
    limit: FINDINGS_PAGE_SIZE,
    sort,
    dir,
  };
}

/** A findings row as the redesigned list returns it. */
export type FindingsListRow = SecurityFinding & FindingLanguage;

/** GET /api/security/findings as the redesigned list reads it: the page,
 *  the language on each row, and reach_pending. */
export type FindingsListPage = Omit<FindingsPage, "findings"> & FindingsPageExtra & { findings: FindingsListRow[] };

/** FINDING_GROUPS_PAGE_SIZE is the grouped table's page size. */
export const FINDING_GROUPS_PAGE_SIZE = 50;

/** The grouped table's sortable columns (the API's sort values). */
export const FINDING_GROUP_SORT_COLUMNS: readonly string[] = ["severity", "count", "last_seen"];

/** The grouped table's default order: the worst severity first. */
export const DEFAULT_GROUP_SORT: FindingSort = [{ id: "severity", desc: true }];

export const INITIAL_GROUPS_LIST: FindingsListState = {
  filterKey: "",
  page: 1,
  sorting: DEFAULT_GROUP_SORT,
};

/** findingGroupsSortParams maps the grouped table's sort state to the
 *  API's sort/dir; an empty or unsortable state is the default (severity,
 *  worst first). */
export function findingGroupsSortParams(sorting: FindingSort): { sort: string; dir: "asc" | "desc" } {
  const s = sorting[0];
  if (!s || !FINDING_GROUP_SORT_COLUMNS.includes(s.id)) return { sort: "severity", dir: "desc" };
  return { sort: s.id, dir: s.desc ? "desc" : "asc" };
}

/** findingGroupsKey identifies one grouping of a filter set for paging. */
export function findingGroupsKey(by: Exclude<FindingsGroupBy, "none">, f: FindingsFilters): string {
  return `${by}|${findingsFilterKey(f)}`;
}

/** findingGroupsQueryParams is the GET /api/security/findings/groups query. */
export function findingGroupsQueryParams(
  by: Exclude<FindingsGroupBy, "none">,
  f: FindingsFilters,
  s: FindingsListState,
): Record<string, string | number | undefined> {
  const { sort, dir } = findingGroupsSortParams(s.sorting);
  return {
    by,
    ...findingsApiParams(f),
    page: findingsListPage(s, findingGroupsKey(by, f)),
    limit: FINDING_GROUPS_PAGE_SIZE,
    sort,
    dir,
  };
}

/** The filters that hold a list of values (the facet pickers and chips). */
export type FindingsListFilter = "severity" | "category" | "driver" | "ecosystem" | "language" | "project" | "baseline";

export const FINDINGS_LIST_FILTERS: readonly FindingsListFilter[] = [
  "severity",
  "category",
  "driver",
  "ecosystem",
  "language",
  "project",
  "baseline",
];

/** toggleFindingsFilter adds a value to one list filter, or removes it when
 *  it is already there (a facet chip's click). */
export function toggleFindingsFilter(f: FindingsFilters, key: FindingsListFilter, value: string): FindingsFilters {
  const cur = f[key];
  const next = cur.includes(value) ? cur.filter((v) => v !== value) : [...cur, value];
  return { ...f, [key]: next };
}

/** setFindingsFilter replaces one list filter's values (a picker's change). */
export function setFindingsFilter(f: FindingsFilters, key: FindingsListFilter, values: readonly string[]): FindingsFilters {
  return { ...f, [key]: [...new Set(values)] };
}

/** clearFindingsFilters drops every filter and keeps the grouping (a view
 *  choice, not a filter): status back to open, nothing else set. */
export function clearFindingsFilters(f: FindingsFilters): FindingsFilters {
  return { ...EMPTY_FINDINGS_FILTERS, group: f.group };
}

/** One active filter: what it is, and the filters with it removed. */
export type ActiveFindingsFilter = {
  id: string;
  field: FindingsListFilter | "status" | "rule" | "pkg" | "path" | "q";
  value: string;
  without: FindingsFilters;
};

/** activeFindingsFilters lists every filter in force, one entry per list
 *  value, in the bar's order; the status counts only when it is not the
 *  default (open). The grouping is not a filter. */
export function activeFindingsFilters(f: FindingsFilters): ActiveFindingsFilter[] {
  const out: ActiveFindingsFilter[] = [];
  for (const key of FINDINGS_LIST_FILTERS) {
    for (const v of f[key]) {
      out.push({ id: `${key}:${v}`, field: key, value: v, without: { ...f, [key]: f[key].filter((x) => x !== v) } });
    }
  }
  if (f.status !== EMPTY_FINDINGS_FILTERS.status) {
    out.push({ id: "status", field: "status", value: f.status, without: { ...f, status: EMPTY_FINDINGS_FILTERS.status } });
  }
  for (const key of ["rule", "pkg", "path", "q"] as const) {
    if (f[key]) out.push({ id: key, field: key, value: f[key], without: { ...f, [key]: "" } });
  }
  return out;
}

/** One option a facet picker shows: its value and count (null while the
 *  facets have not answered). */
export type FacetOption = { value: string; count: number | null };

/** visibleFacetOptions are the options a facet picker lists. With the
 *  facets in hand: every value with a count, plus any selected value with
 *  none (shown at zero, so it can be removed); zero-count values otherwise
 *  hidden. Before they answer (or when they failed): the known vocabulary
 *  plus the selection, uncounted. Most findings first, then by value. */
export function visibleFacetOptions(
  values: readonly FacetValue[] | null | undefined,
  selected: readonly string[],
  vocabulary: readonly string[] = [],
): FacetOption[] {
  const out = new Map<string, FacetOption>();
  if (values) {
    for (const v of values) if (v.count > 0) out.set(v.value, { value: v.value, count: v.count });
    for (const s of selected) if (!out.has(s)) out.set(s, { value: s, count: 0 });
  } else {
    for (const v of [...vocabulary, ...selected]) if (!out.has(v)) out.set(v, { value: v, count: null });
  }
  return [...out.values()].sort((a, b) => (b.count ?? -1) - (a.count ?? -1) || a.value.localeCompare(b.value));
}

/** updateFindingsSearch applies a filter change to a page's URL
 *  parameters, reading the filters from the same parameters (so a change
 *  never works from a stale copy) and keeping every other parameter (the
 *  tab, the open finding). */
export function updateFindingsSearch(prev: URLSearchParams, change: (f: FindingsFilters) => FindingsFilters): URLSearchParams {
  return writeFindingsFilters(prev, change(parseFindingsFilters(prev)));
}

/** findingsDrillDown is a group row's click: the page's URL parameters
 *  with the filters that list that group's findings, ungrouped. */
export function findingsDrillDown(prev: URLSearchParams, by: Exclude<FindingsGroupBy, "none">, g: FindingGroup): URLSearchParams {
  return updateFindingsSearch(prev, (f) => groupDrillDown(by, g, f));
}

/** lastPage is the last 1-based page of total rows. */
export function lastPage(total: number, limit: number): number {
  return Math.max(1, Math.ceil(total / Math.max(1, limit)));
}

/** pageSlice is one 1-based page of rows (page clamped into range). */
export function pageSlice<T>(rows: readonly T[], page: number, limit: number): T[] {
  const p = Math.min(Math.max(1, page), lastPage(rows.length, limit));
  return rows.slice((p - 1) * limit, p * limit);
}

/** sortProjectsBy orders the whole project list by one table column (project,
 *  state, open, last_scan), keeping the attention-first order of
 *  sortProjects among equal rows; no column is that default order itself. */
export function sortProjectsBy(rows: SecurityProject[], sorting: FindingSort): SecurityProject[] {
  const base = sortProjects(rows);
  const s = sorting[0];
  if (!s) return base;
  const dir = s.desc ? -1 : 1;
  const cmp = (a: SecurityProject, b: SecurityProject): number => {
    switch (s.id) {
      case "project":
        return projectLabel(a).localeCompare(projectLabel(b));
      case "state":
        return (STATE_RANK[a.state] ?? 5) - (STATE_RANK[b.state] ?? 5);
      case "open":
        return a.open - b.open;
      case "last_scan":
        return (a.last_scan_at ?? "").localeCompare(b.last_scan_at ?? "");
      default:
        return 0;
    }
  };
  return base.sort((a, b) => dir * cmp(a, b));
}
