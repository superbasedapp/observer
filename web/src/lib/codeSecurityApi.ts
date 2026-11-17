// codeSecurityApi is the one contract the Code security page's tabs share
// (redesign plan docs/plans/code-security-page-redesign-plan-2026-11-06.md,
// section 8): the shapes of the API reads the redesign added (findings
// filters, facets and groups, coverage, the scan request's scanner and
// project choice), and the findings filters' URL encoding, so the Overview
// can link into a filtered Findings view and a filtered view survives a
// reload or a shared link. Pure: no fetch, no React.

/** How the Findings tab groups its rows. "issue" is the same finding across
 *  projects: a dependency advisory on one package version, or any other
 *  rule on one path. "package" is dependency findings only. */
export type FindingsGroupBy = "none" | "issue" | "package" | "rule" | "project";

export const FINDINGS_GROUP_BYS: readonly FindingsGroupBy[] = ["issue", "package", "rule", "project", "none"];

/** The default grouping: one row per issue, however many worktrees repeat it. */
export const DEFAULT_FINDINGS_GROUP: FindingsGroupBy = "issue";

/** The default status filter. */
export const DEFAULT_FINDINGS_STATUS = "open";

/** FindingsFilters is the Findings tab's filter state. Lists are OR within a
 *  filter and AND across filters; an empty list does not filter. */
export type FindingsFilters = {
  severity: string[];
  /** Finding category ids (vulnerable_dependency, secret, ...): the "Type" filter. */
  category: string[];
  /** Driver ids (native, scalibr, osv, opengrep, ...): the "Scanner" filter. */
  driver: string[];
  /** Dependency ecosystems (npm, PyPI, Go, ...). */
  ecosystem: string[];
  /** Language ids from internal/seclang (go, typescript, ...). */
  language: string[];
  /** Project root hashes. */
  project: string[];
  /** One status; "" is every status. */
  status: string;
  /** Baseline values (new, pre_existing, ...). */
  baseline: string[];
  /** Exact rule id (a group drill-down). */
  rule: string;
  /** Exact dependency coordinate "name@version" (a group drill-down; pair with ecosystem). */
  pkg: string;
  /** Exact relative path (a group drill-down). */
  path: string;
  /** Free text over rule, message, path and a dependency's package. */
  q: string;
  group: FindingsGroupBy;
};

export const EMPTY_FINDINGS_FILTERS: FindingsFilters = {
  severity: [],
  category: [],
  driver: [],
  ecosystem: [],
  language: [],
  project: [],
  status: DEFAULT_FINDINGS_STATUS,
  baseline: [],
  rule: "",
  pkg: "",
  path: "",
  q: "",
  group: DEFAULT_FINDINGS_GROUP,
};

// The URL parameter of each filter. "st=all" is every status (an absent st
// is the default, open); "group=none" is the ungrouped list.
//
// None of these may be a name the global filter bar owns (lib/filterUrl.ts
// FILTER_PARAMS: window, since, until, tool, proj, model, search, gran):
// the bar reads its names on every page and writes them back on every
// navigation. The project filter was "proj" until 2026-11-06, so the bar's
// project (a root path) became a Findings chip nobody chose and could not
// remove, and a Findings project (a root hash) became the bar's project on
// the next page. codeSecurityApi.test.ts pins the two sets apart.
const LIST_PARAMS = {
  severity: "sev",
  category: "type",
  driver: "scanner",
  ecosystem: "eco",
  language: "lang",
  project: "project",
  baseline: "base",
} as const;
const TEXT_PARAMS = { rule: "rule", pkg: "pkg", path: "path", q: "q" } as const;
const STATUS_PARAM = "st";
const GROUP_PARAM = "group";
const ALL_STATUSES = "all";

/** FINDINGS_URL_PARAMS lists every URL parameter the filters own (a caller
 *  clearing the filters deletes these and nothing else). */
export const FINDINGS_URL_PARAMS: readonly string[] = [
  ...Object.values(LIST_PARAMS),
  ...Object.values(TEXT_PARAMS),
  STATUS_PARAM,
  GROUP_PARAM,
];

function splitList(v: string | null): string[] {
  if (!v) return [];
  return [...new Set(v.split(",").map((s) => s.trim()).filter(Boolean))];
}

/** parseFindingsFilters reads the filters from a page's URL parameters. */
export function parseFindingsFilters(params: URLSearchParams): FindingsFilters {
  const out: FindingsFilters = { ...EMPTY_FINDINGS_FILTERS };
  for (const [key, name] of Object.entries(LIST_PARAMS) as [keyof typeof LIST_PARAMS, string][]) {
    out[key] = splitList(params.get(name));
  }
  for (const [key, name] of Object.entries(TEXT_PARAMS) as [keyof typeof TEXT_PARAMS, string][]) {
    out[key] = (params.get(name) ?? "").trim();
  }
  const st = params.get(STATUS_PARAM);
  out.status = st == null ? DEFAULT_FINDINGS_STATUS : st === ALL_STATUSES ? "" : st;
  const g = params.get(GROUP_PARAM) as FindingsGroupBy | null;
  out.group = g && FINDINGS_GROUP_BYS.includes(g) ? g : DEFAULT_FINDINGS_GROUP;
  return out;
}

/** writeFindingsFilters returns prev with the filters' parameters replaced
 *  (defaults are left out, so a default view keeps a clean URL). */
export function writeFindingsFilters(prev: URLSearchParams, f: FindingsFilters): URLSearchParams {
  const next = new URLSearchParams(prev);
  for (const p of FINDINGS_URL_PARAMS) next.delete(p);
  for (const [key, name] of Object.entries(LIST_PARAMS) as [keyof typeof LIST_PARAMS, string][]) {
    if (f[key].length > 0) next.set(name, f[key].join(","));
  }
  for (const [key, name] of Object.entries(TEXT_PARAMS) as [keyof typeof TEXT_PARAMS, string][]) {
    if (f[key]) next.set(name, f[key]);
  }
  if (f.status !== DEFAULT_FINDINGS_STATUS) next.set(STATUS_PARAM, f.status === "" ? ALL_STATUSES : f.status);
  if (f.group !== DEFAULT_FINDINGS_GROUP) next.set(GROUP_PARAM, f.group);
  return next;
}

/** findingsHref is a link to the Findings tab with these filters (the
 *  Overview's and the Projects tab's way in). */
export function findingsHref(f: Partial<FindingsFilters>, path = "/code-security"): string {
  const params = writeFindingsFilters(new URLSearchParams({ tab: "findings" }), { ...EMPTY_FINDINGS_FILTERS, ...f });
  return `${path}?${params.toString()}`;
}

/** findingsApiParams is the filters as API query parameters (GET
 *  /api/security/findings, /findings/facets and /findings/groups). */
export function findingsApiParams(f: FindingsFilters): Record<string, string> {
  const out: Record<string, string> = {};
  const lists: [keyof FindingsFilters, string][] = [
    ["severity", "severity"],
    ["category", "category"],
    ["driver", "driver"],
    ["ecosystem", "ecosystem"],
    ["language", "language"],
    ["project", "project"],
    ["baseline", "baseline"],
  ];
  for (const [key, name] of lists) {
    const v = f[key] as string[];
    if (v.length > 0) out[name] = v.join(",");
  }
  out.status = f.status;
  if (f.rule) out.rule = f.rule;
  if (f.pkg) out.package = f.pkg;
  if (f.path) out.path = f.path;
  if (f.q) out.q = f.q;
  return out;
}

/** The facets GET /api/security/findings/facets returns. */
export type FindingsFacetKey = "severity" | "category" | "driver" | "ecosystem" | "language" | "project" | "status" | "baseline";

export type FacetValue = { value: string; count: number };

/** GET /api/security/findings/facets: each facet's counts apply every
 *  filter except the facet's own. */
export type FindingsFacets = {
  total: number;
  facets: Record<FindingsFacetKey, FacetValue[]>;
};

/** One row of GET /api/security/findings/groups. */
export type FindingGroup = {
  key: string;
  rule_id?: string;
  category?: string;
  ecosystem?: string;
  /** "name@version" of a dependency group. */
  package?: string;
  rel_path?: string;
  project_root_hash?: string;
  /** One representative message of the group's findings. */
  message?: string;
  count: number;
  projects: number;
  max_severity: string;
  first_seen: string;
  last_seen: string;
};

/** GET /api/security/findings/groups?by=. by_severity counts the groups (all
 *  of them, not the page) by their worst severity. */
export type FindingGroupsPage = {
  by: Exclude<FindingsGroupBy, "none">;
  groups: FindingGroup[];
  total: number;
  page: number;
  limit: number;
  by_severity: Record<string, number>;
};

/** groupDrillDown is the filters that list one group's findings. */
export function groupDrillDown(by: Exclude<FindingsGroupBy, "none">, g: FindingGroup, base: FindingsFilters): FindingsFilters {
  const f: FindingsFilters = { ...base, group: "none" };
  switch (by) {
    case "issue":
      f.rule = g.rule_id ?? "";
      if (g.package) {
        f.pkg = g.package;
        f.ecosystem = g.ecosystem ? [g.ecosystem] : f.ecosystem;
      } else {
        f.path = g.rel_path ?? "";
      }
      break;
    case "package":
      f.pkg = g.package ?? "";
      f.ecosystem = g.ecosystem ? [g.ecosystem] : f.ecosystem;
      break;
    case "rule":
      f.rule = g.rule_id ?? "";
      break;
    case "project":
      f.project = g.project_root_hash ? [g.project_root_hash] : f.project;
      break;
  }
  return f;
}

/** One supported ecosystem of GET /api/security/coverage. */
export type CoverageSupported = {
  ecosystem: string;
  /** The file names and patterns the scanners read for it. */
  files: string[];
  /** Its files Observer finds but nothing reads: a manifest checked only
   *  through its lockfile, a file with no extractor, or one no database
   *  covers. A scan reports each as a gap. Absent from older daemons. */
  unread_files?: string[];
  /** Driver ids that read it (scalibr, osv). */
  drivers: string[];
  /** Where its advisories come from ("OSV npm"); "" when none (Conan, vcpkg). */
  advisory_source: string;
  database_installed: boolean;
  online_only: boolean;
  note?: string;
};

/** One dependency driver's latest recorded run on one project. */
export type CoverageRun = {
  driver: string;
  started_at: string;
  outcome: string;
  reason?: string;
  files_scanned: number;
  /** The ecosystems the run scanned. */
  scanned: string[];
  /** Files it found but did not read, with the reason (at most 50; skipped_total counts all). */
  skipped: { path: string; reason: string }[];
  skipped_total: number;
};

export type CoverageProject = {
  project_root_hash: string;
  project_id?: number;
  name: string;
  active: boolean;
  runs: CoverageRun[];
};

/** GET /api/security/coverage. reasons maps each gap reason to its words. */
export type CoverageResponse = {
  supported: CoverageSupported[];
  projects: CoverageProject[];
  reasons: Record<string, string>;
  /** "What is checked": one row per checking family (absent on an older daemon). */
  families?: CoverageFamily[];
};

/** One checking family of the coverage read: its components and state
 *  (on, off, not_selected, not_in_build). */
export type CoverageFamily = {
  family: string;
  label: string;
  components: string[];
  state: string;
  note?: string;
};

/** POST /api/security/scan's start body: exactly one of project, projects or
 *  all; steps empty or absent runs every ready scanner; online asks the
 *  dependency step to also check online (refused while the online gate is
 *  closed, or without that step). */
export type ScanStartBody = {
  project?: string;
  projects?: string[];
  all?: boolean;
  steps?: string[];
  online?: boolean;
};

/** The fields the redesign added to the scan job (lib/codeSecurity.ts
 *  ScanJob has the rest). */
export type ScanJobTiming = {
  /** The scanner step ids this job runs. */
  steps?: string[];
  current?: { project_root_hash: string; name: string; step: string; step_id?: string; started_at?: string };
};

/** The fields the redesign added to each step result. */
export type ScanResultTiming = { started_at?: string; duration_ms?: number };

/** The fields the redesign added to a findings row and page. */
export type FindingLanguage = { language?: string };
export type FindingsPageExtra = {
  /** Some dependency rows' reachability is still being worked out in the
   *  background; refetch shortly for the final labels and order. */
  reach_pending?: boolean;
};
