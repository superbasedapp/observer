// Component tests of the Code security page's Projects card and Findings
// card (web/src/pages/codesecurity), rendered with react-dom/server under
// node's test runner (scripts/test-components.mjs). The regression they pin:
// the page listed a project as the first 12 characters of its root hash,
// which read as a git commit id, and linked nothing. A row now names its
// project and links it to the Projects page detail, a finding links its
// project and its session, and a row with no project is plain text.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import { ProjectsCard } from "@/pages/codesecurity/ProjectsCard";
import { FindingsCard } from "@/pages/codesecurity/FindingsCard";
import type { ApiState } from "@/lib/useApi";
import type { SecurityFinding, SecurityProject, SecurityStatus } from "@/lib/codeSecurity";

const HASH = "9afe4a86fa816d7b0a3fd01f80c25cbc449770305d468251aa8f1ed1c6d0b018";
const ORPHAN = "f0291b30a69afb1097ff664423afc98c27da82659e501bd7bf1a974d98611ae3";

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
    counts: [{ category: "secret", severity: "high", n: 3 }],
    last_scan_at: "2026-11-02T18:21:22Z",
    runs: [{ driver: "scalibr", scope: "scheduled", outcome: "failed", reason: "child exited", findings: 0, started_at: "", duration_ms: 0 }],
  },
  { project_root_hash: ORPHAN, name: "", active: false, state: "unknown", reason: "project_not_found", blocking: 0, open: 1, counts: [], runs: [] },
];

test("a project row names and links its project, never a bare hash", () => {
  const html = renderToStaticMarkup(
    <MemoryRouter>
      <ProjectsCard status={api<SecurityStatus>({ module: "active", projects })} onScanProject={() => {}} onShowFindings={() => {}} />
    </MemoryRouter>,
  );
  assert.match(html, /href="\/projects\?project=345"[^>]*>superbased-observer</);
  assert.match(html, /Unknown project \(f0291b30\)/);
  assert.doesNotMatch(html, new RegExp(`>${HASH.slice(0, 12)}<`));
  assert.doesNotMatch(html, new RegExp(`>${ORPHAN.slice(0, 12)}<`));
  // The failing scanner is named beside the last scan, not hidden.
  assert.match(html, /scalibr\): failed \(child exited\)/);
  // A row with no project row has no Scan action and no link.
  assert.equal((html.match(/href="\/projects\?project=/g) ?? []).length, 1);
});

test("a finding row links its project and its session", () => {
  const findings: SecurityFinding[] = [
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
    },
  ];
  const html = renderToStaticMarkup(
    <MemoryRouter>
      <FindingsCard
        findings={api({ findings, total: 1, page: 1, limit: 50 })}
        projects={projects}
        onOpen={() => {}}
        page={1}
        sorting={[{ id: "severity", desc: true }]}
        onPage={() => {}}
        onSorting={() => {}}
      />
    </MemoryRouter>,
  );
  assert.match(html, /href="\/projects\?project=345"/);
  assert.match(html, /href="\/sessions\?session=sess-abcdef123456"/);
  assert.match(html, /web2\/src\/lib\/linkToken\.ts:72/);
  // The project filter moved to the Findings tab's filter bar, which names
  // its projects too (CodeSecurityFindings.test.tsx).
});
