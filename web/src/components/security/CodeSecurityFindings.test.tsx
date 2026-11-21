// Component tests of the Code security page's Findings tab (redesign lane
// 2b: pages/codesecurity/FindingsTab, FindingsFilterBar,
// FindingGroupsTable), rendered with react-dom/server under node's test
// runner (scripts/test-components.mjs, no DOM).
//
// The tab's reads go through the node's one query cache (lib/useApi
// apiCache). Each test primes the cache with the answer for exactly the
// request the URL's filters should produce, then renders the tab at that
// URL: the rows show only when the tab asked for that request, so the
// render proves the URL -> API params path end to end. Clicks cannot be
// simulated without a DOM; the click handlers are the pure functions tested
// in lib/codeSecurityFindings.test.ts (updateFindingsSearch for a facet
// click, findingsDrillDown for a group row).

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import { FindingsTab } from "@/pages/codesecurity/FindingsTab";
import { FindingsFilterBar } from "@/pages/codesecurity/FindingsFilterBar";
import { FindingGroupsTable } from "@/pages/codesecurity/FindingGroupsTable";
import { FINDING_GROUPS_PATH, FINDINGS_FACETS_PATH, FINDINGS_PATH } from "@/pages/codesecurity/useFindingsList";
import { apiCache, type ApiState } from "@/lib/useApi";
import { buildUrl } from "@/lib/api";
import {
  findingGroupsQueryParams,
  findingsQueryParams,
  INITIAL_FINDINGS_LIST,
  INITIAL_GROUPS_LIST,
  type FindingsListPage,
  type SecurityProject,
  type SecurityStatus,
} from "@/lib/codeSecurity";
import {
  EMPTY_FINDINGS_FILTERS,
  findingsApiParams,
  parseFindingsFilters,
  type FindingGroup,
  type FindingGroupsPage,
  type FindingsFacets,
} from "@/lib/codeSecurityApi";

const consoleError = console.error;
console.error = (...args: unknown[]) => {
  if (typeof args[0] === "string" && args[0].includes("useLayoutEffect does nothing on the server")) return;
  consoleError(...args);
};

const HASH = "9afe4a86fa816d7b0a3fd01f80c25cbc449770305d468251aa8f1ed1c6d0b018";
const OTHER = "f0291b30a69afb1097ff664423afc98c27da82659e501bd7bf1a974d98611ae3";

function api<T>(data: T | null, over: Partial<ApiState<T>> = {}): ApiState<T> {
  return {
    data,
    loading: false,
    error: null,
    reload: () => {},
    isStale: false,
    isRefreshing: false,
    updatedAt: 1,
    denied: false,
    status: null,
    deniedPermission: null,
    notInstalled: null,
    ...over,
  };
}

const projects: SecurityProject[] = [
  {
    project_root_hash: HASH,
    project_id: 345,
    name: "superbased-observer",
    root_path: "/mnt/d/programsx/superbased-observer",
    active: true,
    state: "dirty",
    reason: "open_findings",
    blocking: 0,
    open: 3,
    counts: [],
    runs: [],
  },
];

const status = api<SecurityStatus>({ module: "active", projects });

function facetsOf(total: number, over: Partial<FindingsFacets["facets"]> = {}): FindingsFacets {
  return {
    total,
    facets: {
      severity: [],
      category: [],
      driver: [],
      ecosystem: [],
      language: [],
      project: [],
      status: [],
      baseline: [],
      ...over,
    },
  };
}

/** prime stores data as the cached answer of path with params. */
async function prime<T>(path: string, params: Record<string, string | number | undefined>, data: T): Promise<void> {
  await apiCache.fetch(buildUrl(path, params), async () => data);
}

function renderAt(url: string): string {
  return renderToStaticMarkup(
    <MemoryRouter initialEntries={[url]}>
      <FindingsTab status={status} />
    </MemoryRouter>,
  );
}

test("the ungrouped tab reads the list and the counts its URL names", async () => {
  const url = "/code-security?tab=findings&sev=high&type=secret&group=none";
  const filters = parseFindingsFilters(new URLSearchParams(url.split("?")[1]));
  const page: FindingsListPage = {
    findings: [
      {
        id: "01M6EQX6X4TKEKR3VTVFJ2D36H",
        project_root_hash: HASH,
        rule_id: "secret.secret_assignment",
        driver: "native",
        category: "secret",
        severity: "high",
        confidence: "high",
        scope: "post_write",
        baseline: "new",
        status: "open",
        rel_path: "web2/src/lib/linkToken.ts",
        start_line: 72,
        message: "A secret_assignment secret is in this file.",
        first_seen: "2026-11-02T18:21:22Z",
        last_seen: "2026-11-02T18:21:29Z",
        session_id: "sess-abcdef123456",
        language: "typescript",
      },
    ],
    total: 1,
    page: 1,
    limit: 50,
    reach_pending: true,
  };
  await prime(FINDINGS_PATH, findingsQueryParams(filters, INITIAL_FINDINGS_LIST), page);
  await prime(
    FINDINGS_FACETS_PATH,
    findingsApiParams(filters),
    facetsOf(1, {
      severity: [
        { value: "critical", count: 0 },
        { value: "high", count: 1 },
        { value: "low", count: 4 },
      ],
      category: [
        { value: "secret", count: 1 },
        { value: "vulnerable_dependency", count: 0 },
      ],
      driver: [{ value: "native", count: 1 }],
      project: [{ value: HASH, count: 1 }],
      status: [
        { value: "open", count: 1 },
        { value: "false_positive", count: 2 },
        { value: "accepted_risk", count: 0 },
      ],
    }),
  );
  const html = renderAt(url);
  // The row shows: the tab asked for exactly the primed request.
  assert.match(html, /A secret_assignment secret is in this file\./);
  assert.match(html, /href="\/projects\?project=345"/);
  assert.match(html, /href="\/sessions\?session=sess-abcdef123456"/);
  assert.match(html, /web2\/src\/lib\/linkToken\.ts:72/);
  // The row says its type and language in words.
  assert.match(html, /secret\.secret_assignment · Secret · TypeScript/);
  // The count line, from the list's total.
  assert.match(html, />1 finding</);
  // The severity chips carry their counts; a zero-count severity is hidden.
  assert.match(html, /data-testid="code-security-severity-high"/);
  assert.match(html, /data-testid="code-security-severity-low"/);
  assert.doesNotMatch(html, /data-testid="code-security-severity-critical"/);
  assert.match(html, /aria-pressed="true"[^>]*data-testid="code-security-severity-high"/);
  // The filters in force are chips, with Clear filters.
  assert.match(html, /Severity: High/);
  assert.match(html, /Type: Secret/);
  assert.match(html, /Clear filters/);
  // A picker with nothing to pick and nothing picked is not drawn.
  assert.doesNotMatch(html, /data-testid="code-security-filter-ecosystem"/);
  assert.match(html, /data-testid="code-security-filter-driver"/);
  // Below 640 px the filters fold behind a counted button.
  assert.match(html, /Filters \(2\)/);
  // The reach note, quietly.
  assert.match(html, /Reachability is still being checked, so the order may change/);
  // No mascot in a working surface.
  assert.doesNotMatch(html, /superbased mascot/);
});

test("the grouped tab reads the groups and counts issues and findings", async () => {
  const url = "/code-security?tab=findings&eco=npm";
  const filters = parseFindingsFilters(new URLSearchParams(url.split("?")[1]));
  assert.equal(filters.group, "issue");
  const group: FindingGroup = {
    key: "GHSA-35jh-r3h4-6jhm|npm|lodash@4.17.20",
    rule_id: "GHSA-35jh-r3h4-6jhm",
    category: "vulnerable_dependency",
    ecosystem: "npm",
    package: "lodash@4.17.20",
    message: "lodash@4.17.20 has a known vulnerability.",
    count: 20,
    projects: 20,
    max_severity: "high",
    first_seen: "2026-11-01T00:00:00Z",
    last_seen: "2026-11-06T00:00:00Z",
  };
  const groups: FindingGroupsPage = { by: "issue", groups: [group], total: 399, page: 1, limit: 50, by_severity: { high: 399 } };
  await prime(FINDING_GROUPS_PATH, findingGroupsQueryParams("issue", filters, INITIAL_GROUPS_LIST), groups);
  await prime(FINDINGS_FACETS_PATH, findingsApiParams(filters), facetsOf(5137, { ecosystem: [{ value: "npm", count: 5137 }] }));
  const html = renderAt(url);
  assert.match(html, /399 issues \(5,137 findings\)/);
  assert.match(html, /lodash@4\.17\.20 has a known vulnerability\./);
  assert.match(html, /GHSA-35jh-r3h4-6jhm · lodash@4\.17\.20 · npm/);
  // The grouped table's columns.
  assert.match(html, />Issue</);
  assert.match(html, />Projects</);
  assert.match(html, />Findings</);
  // The ungrouped list was not read.
  assert.doesNotMatch(html, /code-security-finding-package/);
});

test("before any read answers, the tab names what it loads, over the skeleton", () => {
  const html = renderAt("/code-security?tab=findings&lang=rust");
  assert.match(html, /data-testid="named-loading"/);
  assert.doesNotMatch(html, /superbased mascot/);
});

// The global filter bar writes its project (a root path) as proj= on every
// page it follows the user to. It is not a Findings filter: no chip, no
// "Unknown project (/mnt/d/p)".
test("the global project selection does not become a Findings filter", () => {
  const html = renderAt("/code-security?tab=findings&proj=%2Fmnt%2Fd%2Fprogramsx%2Fsuperbased-observer");
  assert.doesNotMatch(html, /data-testid="code-security-findings-active"/);
  assert.doesNotMatch(html, /Unknown project|no longer tracked|\/mnt\/d\/p/);
});

test("the filter bar names projects, counts options and keeps a chosen zero-count value", () => {
  const filters = { ...EMPTY_FINDINGS_FILTERS, project: [OTHER], baseline: ["pre_existing"] };
  const facets = facetsOf(9, {
    project: [
      { value: HASH, count: 9 },
      { value: OTHER, count: 0 },
    ],
    baseline: [
      { value: "new", count: 9 },
      { value: "pre_existing", count: 0 },
    ],
    language: [{ value: "go", count: 9 }],
  });
  const render = (projectsLoaded: boolean) =>
    renderToStaticMarkup(
      <MemoryRouter>
        <FindingsFilterBar filters={filters} facets={api(facets)} projects={projects} projectsLoaded={projectsLoaded} onChange={() => {}} />
      </MemoryRouter>,
    );
  const html = render(true);
  // A chosen project the status read does not list reads "Project no
  // longer tracked", never a hash (removing it: codeSecurityApi.test.ts).
  assert.match(html, /Project: Project no longer tracked \(f0291b30\)/);
  // Before the status read answers it is not called untracked.
  assert.match(render(false), /Project: Unknown project \(f0291b30\)/);
  assert.match(html, /Baseline: Pre-existing/);
  assert.match(html, /Filters \(2\)/);
  // The language picker is drawn (it counts something); the ecosystem one is not.
  assert.match(html, /data-testid="code-security-filter-language"/);
  assert.doesNotMatch(html, /data-testid="code-security-filter-ecosystem"/);
  // Each drawn picker (project, language, baseline) reads as a dropdown,
  // not a text box: a closed combobox with a chevron and a pointer cursor.
  assert.equal((html.match(/role="combobox" aria-haspopup="listbox" aria-expanded="false"/g) ?? []).length, 3);
  assert.equal((html.match(/data-picker-chevron/g) ?? []).length, 3);
  assert.doesNotMatch(html, /cursor-text/);
  // The search box and the grouping are always in view.
  assert.match(html, /data-testid="code-security-findings-search"/);
  assert.match(html, /Group by/);
  for (const label of ["Issue", "Package", "Rule", "Project", "None"]) assert.match(html, new RegExp(`>${label}<`));
});

test("the groups table names each grouping's rows and drops the project count for project groups", () => {
  const g: FindingGroup = {
    key: "k",
    rule_id: "secret.x",
    category: "secret",
    ecosystem: "npm",
    package: "left-pad@1.0.0",
    project_root_hash: HASH,
    message: "A secret is in this file.",
    count: 3,
    projects: 2,
    max_severity: "critical",
    first_seen: "2026-11-01T00:00:00Z",
    last_seen: "2026-11-06T00:00:00Z",
  };
  const page: FindingGroupsPage = { by: "package", groups: [g], total: 1, page: 1, limit: 50, by_severity: {} };
  const render = (by: "package" | "rule" | "project") =>
    renderToStaticMarkup(
      <MemoryRouter>
        <FindingGroupsTable
          by={by}
          groups={api({ ...page, by })}
          projects={projects}
          page={1}
          sorting={[{ id: "severity", desc: true }]}
          onPage={() => {}}
          onSorting={() => {}}
          onDrill={() => {}}
          emptyHint="No findings match these filters."
          loadingLabel="Loading packages"
        />
      </MemoryRouter>,
    );
  const pkg = render("package");
  assert.match(pkg, />left-pad@1\.0\.0</);
  assert.match(pkg, />Package</);
  assert.match(pkg, />Projects</);
  const rule = render("rule");
  assert.match(rule, /secret\.x · Secret/);
  const proj = render("project");
  assert.match(proj, />superbased-observer</);
  assert.doesNotMatch(proj, />Projects</);
});
