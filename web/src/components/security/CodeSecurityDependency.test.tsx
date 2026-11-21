// Component tests of the dependency-finding detail (pages/codesecurity/
// DependencyDetail), the server-paged Findings card and the client-paged
// Projects card, rendered with react-dom/server under node's test runner
// (scripts/test-components.mjs, no DOM). Clicking "next page" is covered by
// the pure findingsListReducer / findingsQueryParams tests in
// lib/codeSecurityDependency.test.ts; here the rendered pager and rows are
// checked for the page the card is given.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import { DefinitionList } from "@shared/primitives/DefinitionList";
import {
  AdvisorySections,
  DependencyRows,
  DependencySections,
  DependencySignalRows,
} from "@/pages/codesecurity/DependencyDetail";
import { FindingsCard } from "@/pages/codesecurity/FindingsCard";
import { ProjectsCard } from "@/pages/codesecurity/ProjectsCard";
import type { ApiState } from "@/lib/useApi";
import type {
  FindingDependency,
  SecurityFinding,
  SecurityFindingDetail,
  SecurityProject,
  SecurityStatus,
} from "@/lib/codeSecurity";

function api<T>(data: T): ApiState<T> {
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
  };
}

const dep: FindingDependency = {
  ecosystem: "npm",
  name: "lodash",
  version: "4.17.20",
  relationship: "transitive",
  scope: "dev",
  introduced_by: ["webpack@5.1.0", "tool@1.0.0"],
  location: {
    rel_path: "package-lock.json",
    found: true,
    start_line: 88,
    end_line: 90,
    context: [
      { line: 87, text: '    "node_modules/lodash": {', match: false },
      { line: 88, text: '      "version": "4.17.20",', match: true },
      { line: 89, text: '      "resolved": "https://registry.npmjs.org/lodash"', match: false },
    ],
  },
  fixed_versions: ["4.17.19", "4.17.21"],
  suggested_version: "4.17.21",
  advisory_source: "local_database",
  advisories: [
    {
      id: "GHSA-35jh-r3h4-6jhm",
      aliases: ["CVE-2021-23337"],
      summary: "Command injection in lodash",
      details: "Line one <b>not html</b>\n**not markdown**",
      details_truncated: true,
      published: "2021-02-15T00:00:00Z",
      cwe: ["CWE-94"],
      cvss: ["CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"],
      ranges: [{ introduced: "0", fixed: "4.17.21" }],
      affected_symbols: ["template"],
      references: [
        { type: "ADVISORY", url: "https://github.com/advisories/GHSA-35jh-r3h4-6jhm" },
        { type: "WEB", url: "javascript:alert(1)" },
      ],
    },
  ],
};

function finding(over: Partial<SecurityFinding> = {}): SecurityFinding {
  return {
    id: "f1",
    project_root_hash: "h1",
    rule_id: "dep.osv",
    driver: "osv",
    category: "vulnerable_dependency",
    severity: "high",
    confidence: "high",
    scope: "scheduled",
    baseline: "new",
    status: "open",
    rel_path: "package-lock.json",
    start_line: 0,
    message: "A package is vulnerable.",
    first_seen: "2026-11-02T18:21:22Z",
    last_seen: "2026-11-02T18:21:29Z",
    ...over,
  };
}

function detail(over: Partial<SecurityFindingDetail> = {}): SecurityFindingDetail {
  return { finding: finding(), sightings: [], commits: [], events: [], exceptions: [], ...over };
}

test("a dependency finding shows the package rows", () => {
  const html = renderToStaticMarkup(
    <DefinitionList>
      <DependencyRows dep={dep} />
    </DefinitionList>,
  );
  assert.match(html, /lodash@4\.17\.20/);
  assert.match(html, /npm/);
  assert.match(html, /transitive, dev only/);
  assert.match(html, /webpack@5\.1\.0/);
  assert.match(html, /tool@1\.0\.0/);
  // Fixed in lists every version and highlights the suggested one.
  assert.match(html, /4\.17\.19/);
  assert.match(html, /data-testid="code-security-suggested-version"[^>]*>4\.17\.21</);
});

test("the lockfile section numbers the lines and tints the match", () => {
  const html = renderToStaticMarkup(<DependencySections detail={detail({ dependency: dep })} />);
  assert.match(html, /In the lockfile/);
  assert.match(html, /package-lock\.json:88/);
  assert.match(html, /<span[^>]*>87<\/span>/);
  // Exactly the matched line carries the tint and the match marker.
  assert.equal((html.match(/data-match="true"/g) ?? []).length, 1);
  assert.match(html, /bg-warn-soft[^>]*data-match="true"[^>]*><span[^>]*>88<\/span>/);
  assert.match(html, /&quot;version&quot;: &quot;4\.17\.20&quot;/);
});

test("a lockfile that cannot be located says why in one muted line", () => {
  const html = renderToStaticMarkup(
    <DependencySections
      detail={detail({
        dependency: { ...dep, location: { rel_path: "yarn.lock", found: false, reason: "file_too_large" } },
      })}
    />,
  );
  assert.match(html, /In the lockfile/);
  assert.match(html, /yarn\.lock/);
  assert.match(html, /too large/);
  assert.doesNotMatch(html, /code-security-lockfile-excerpt/);
});

test("the advisory section is plain text with safe external links", () => {
  const html = renderToStaticMarkup(<DependencySections detail={detail({ dependency: dep })} />);
  assert.match(html, /Advisory/);
  assert.match(html, /From the local OSV database/);
  assert.match(html, /GHSA-35jh-r3h4-6jhm/);
  assert.match(html, /CVE-2021-23337/);
  assert.match(html, /Command injection in lodash/);
  assert.match(html, /CWE-94/);
  assert.match(html, /CVSS:3\.1\/AV:N/);
  assert.match(html, /affected from the first release, fixed 4\.17\.21/);
  assert.match(html, /template/);
  assert.match(html, /was truncated/);
  assert.match(html, /published/);
  // Third-party text is escaped and kept as plain text.
  assert.match(html, /whitespace-pre-wrap/);
  assert.match(html, /Line one &lt;b&gt;not html&lt;\/b&gt;/);
  assert.doesNotMatch(html, /<b>not html/);
  // The https reference is an external link; the javascript: one is dropped.
  assert.match(html, /href="https:\/\/github\.com\/advisories\/GHSA-35jh-r3h4-6jhm"[^>]*target="_blank"[^>]*rel="noopener noreferrer nofollow"/);
  assert.doesNotMatch(html, /javascript:/);
  // Short details have nothing to expand.
  assert.doesNotMatch(html, /Show more/);
});

test("long advisory details start collapsed with a Show more toggle", () => {
  const long = Array.from({ length: 12 }, (_, i) => `line ${i}`).join("\n");
  const html = renderToStaticMarkup(
    <AdvisorySections dep={{ ...dep, advisories: [{ id: "GHSA-x", details: long }] }} />,
  );
  assert.match(html, /line-clamp-6/);
  assert.match(html, /Show more/);
});

test("without a local advisory the drawer says so honestly instead of a section", () => {
  for (const [source, text] of [
    ["not_in_local_database", /not in the local OSV database/],
    ["database_not_installed", /OSV database is not installed/],
  ] as const) {
    const html = renderToStaticMarkup(
      <DependencySections detail={detail({ dependency: { ...dep, location: undefined, advisory_source: source, advisories: undefined } })} />,
    );
    assert.match(html, text);
    assert.doesNotMatch(html, /<h3/);
    assert.doesNotMatch(html, /From the local OSV database/);
  }
});

test("a non-dependency finding renders no lockfile or advisory headings", () => {
  const html = renderToStaticMarkup(<DependencySections detail={detail({ finding: finding({ category: "secret" }) })} />);
  assert.equal(html, "");
});

const projects: SecurityProject[] = Array.from({ length: 30 }, (_, i) => ({
  project_root_hash: `hash${String(i).padStart(2, "0")}`,
  project_id: i + 1,
  name: `project-${String(i).padStart(2, "0")}`,
  active: true,
  state: "clean",
  reason: "",
  blocking: 0,
  open: 0,
  counts: [],
  runs: [],
}));

test("the Projects card pages 25 at a time over the whole list", () => {
  const html = renderToStaticMarkup(
    <MemoryRouter>
      <ProjectsCard status={api<SecurityStatus>({ module: "active", projects })} onScanProject={() => {}} onShowFindings={() => {}} />
    </MemoryRouter>,
  );
  assert.equal((html.match(/href="\/projects\?project=/g) ?? []).length, 25);
  assert.match(html, /1-25 of\s*30/);
  assert.match(html, /page 1 \/ 2/);
});

test("the Projects card shows no pager for a list that fits one page", () => {
  const html = renderToStaticMarkup(
    <MemoryRouter>
      <ProjectsCard status={api<SecurityStatus>({ module: "active", projects: projects.slice(0, 25) })} onScanProject={() => {}} onShowFindings={() => {}} />
    </MemoryRouter>,
  );
  assert.doesNotMatch(html, /page 1 \//);
});

function renderFindings(page: number, rows: SecurityFinding[], total: number) {
  return renderToStaticMarkup(
    <MemoryRouter>
      <FindingsCard
        findings={api({ findings: rows, total, page, limit: 50 })}
        projects={[]}
        onOpen={() => {}}
        page={page}
        sorting={[{ id: "severity", desc: true }]}
        onPage={() => {}}
        onSorting={() => {}}
      />
    </MemoryRouter>,
  );
}

test("the Findings card shows the server page and total, and the package under a dependency row", () => {
  const html = renderFindings(2, [finding({ package: "lodash@4.17.20", ecosystem: "npm" }), finding({ id: "f2", category: "secret", rule_id: "secret.x" })], 120);
  assert.match(html, /51-100 of\s*120/);
  assert.match(html, /page 2 \/ 3/);
  // The package shows once, on the dependency row only.
  assert.equal((html.match(/code-security-finding-package/g) ?? []).length, 1);
  assert.match(html, /lodash@4\.17\.20/);
  // First seen is a column now, beside Last seen.
  assert.match(html, /First seen/);
  assert.match(html, /Last seen/);
});

test("the drawer shows the reach tier and the exploit labels with FIRST's citation", () => {
  const html = renderToStaticMarkup(
    <DefinitionList>
      <DependencySignalRows
        finding={{
          reach: { level: "not_imported_directly", source: "go imports", label: "not imported directly (go imports)" },
          exploit: {
            kev_available: true,
            epss_available: true,
            kev: { cve: "CVE-2021-44228", date_added: "2021-12-10" },
            epss: { cve: "CVE-2021-44228", score: 0.944, percentile: 1 },
            badges: ["Exploited in the wild (CISA KEV, added 2021-12-10)", "EPSS 0.944, top 1 percent"],
            epss_citation: "EPSS scores: FIRST, Exploit Prediction Scoring System (EPSS), https://www.first.org/epss",
            kev_notice: "Known exploited vulnerabilities: the CISA Known Exploited Vulnerabilities catalog (CC0 1.0). Observer is not affiliated with or endorsed by CISA.",
          },
        }}
      />
    </DefinitionList>,
  );
  assert.match(html, /not imported directly \(go imports\)/);
  assert.match(html, /may still be reached through another dependency/);
  assert.match(html, /Exploited in the wild \(CISA KEV, added 2021-12-10\)/);
  assert.match(html, /EPSS 0\.944, top 1 percent/);
  assert.match(html, /code-security-epss-citation[^>]*>EPSS scores: FIRST/);
  assert.match(html, /not affiliated with or endorsed by CISA/);
  // No CISA logo or seal: text only.
  assert.doesNotMatch(html, /<img|<svg[^>]*cisa/i);
});

test("the drawer marks an approximate called tier as a name match and never says 'not called'", () => {
  const html = renderToStaticMarkup(
    <DefinitionList>
      <DependencySignalRows
        finding={{
          reach: { level: "called", approximate: true, source: "codeintel-rust-callsite", label: "called, approximate (codeintel-rust-callsite)" },
        }}
      />
    </DefinitionList>,
  );
  assert.match(html, /called, approximate \(codeintel-rust-callsite\)/);
  assert.match(html, /matched by name, not a resolved call/);
  assert.doesNotMatch(html, /not called/i);
});

test("the drawer explains a not-called tier from the Go symbol check, never 'unreachable'", () => {
  const html = renderToStaticMarkup(
    <DefinitionList>
      <DependencySignalRows
        finding={{
          reach: { level: "not_called", source: "govulncheck-binary", target: "bin/app", label: "not called (govulncheck-binary, bin/app)" },
        }}
      />
    </DefinitionList>,
  );
  assert.match(html, /not called \(govulncheck-binary, bin\/app\)/);
  assert.match(html, /Tests, other build tags and other platforms are outside the check/);
  assert.doesNotMatch(html, /unreachable/i);
});

test("the drawer says exploit data is unavailable, never 'not exploited', and shows no citation without a score", () => {
  const html = renderToStaticMarkup(
    <DefinitionList>
      <DependencySignalRows
        finding={{
          reach: { level: "unknown", reason: "no_import_mapping", label: "unknown (no import mapping for this ecosystem)" },
          exploit: { kev_available: false, epss_available: false, badges: ["Exploit data unavailable"] },
        }}
      />
    </DefinitionList>,
  );
  assert.match(html, /Exploit data unavailable/);
  assert.doesNotMatch(html, /not exploited/i);
  assert.doesNotMatch(html, /code-security-epss-citation/);
  // A finding with neither signal renders no rows.
  assert.equal(renderToStaticMarkup(<DependencySignalRows finding={{}} />), "");
});

test("the Findings card shows a dependency row's exploit and reach labels in the rank column", () => {
  const html = renderFindings(1, [
    finding({
      package: "lodash@4.17.20",
      ecosystem: "npm",
      reach: { level: "imported", label: "imported (go imports)" },
      exploit: {
        kev_available: true,
        epss_available: true,
        epss: { cve: "CVE-2021-44228", score: 0.944, percentile: 1 },
        badges: ["Exploited in the wild (CISA KEV, added 2021-12-10)", "EPSS 0.944, top 1 percent"],
        epss_citation: "EPSS scores: FIRST, Exploit Prediction Scoring System (EPSS), https://www.first.org/epss",
      },
    }),
    finding({ id: "f2", category: "secret", rule_id: "secret.x" }),
  ], 2);
  assert.match(html, /Exploit and reach/);
  assert.equal((html.match(/code-security-signal-labels/g) ?? []).length, 1);
  assert.match(html, /Exploited in the wild/);
});

test("the Findings card cites FIRST under a list showing an EPSS score, and not otherwise", () => {
  const scored = renderFindings(1, [
    finding({ exploit: { kev_available: true, epss_available: true, badges: ["EPSS 0.92, top 1 percent"], epss_citation: "EPSS scores: FIRST" } }),
  ], 1);
  assert.match(scored, /code-security-list-epss-citation[^>]*>EPSS scores: FIRST/);
  const unscored = renderFindings(1, [finding({ exploit: { kev_available: false, epss_available: false, badges: ["Exploit data unavailable"] } })], 1);
  assert.doesNotMatch(unscored, /code-security-list-epss-citation/);
});
