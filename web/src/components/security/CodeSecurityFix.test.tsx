// Component tests of "Fix with an agent" (docs/plans/fix-findings-with-
// agent-plan-2026-11-13.md): the row, group and header buttons, the fix
// plan dialog, the Fix attempts panel and the New terminal dialog's task
// mode, rendered with react-dom/server under node's test runner
// (scripts/test-components.mjs, no DOM). Clicks cannot be simulated; the
// query a button builds and the request task mode posts are the pure
// functions pinned in src/lib/securityFix.test.ts (fixPlanQuery,
// taskLaunchRequest, taskPickerItems), and these prove the components
// render what those build from.

import { test } from "node:test";
import assert from "node:assert/strict";
import { PassThrough } from "node:stream";
import type { ReactElement } from "react";
import { renderToPipeableStream, renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import { FindingsCard } from "@/pages/codesecurity/FindingsCard";
import { FindingGroupsTable } from "@/pages/codesecurity/FindingGroupsTable";
import { FixWithAgentDialog } from "@/pages/codesecurity/FixWithAgentDialog";
import { FixAttemptsPanel } from "@/pages/codesecurity/FixAttemptsPanel";
import { NewTerminalDialog } from "@/components/NewTerminalDialog";
import { apiCache, type ApiState } from "@/lib/useApi";
import { INITIAL_FINDINGS_LIST, INITIAL_GROUPS_LIST, type FindingsListPage } from "@/lib/codeSecurity";
import { EMPTY_FINDINGS_FILTERS, type FindingGroupsPage } from "@/lib/codeSecurityApi";
import { FIX_ATTEMPTS_PATH, fixPlanPath, fixTaskFor, type FixAttemptsResponse, type FixPlan, type FixSelection } from "@/lib/securityFix";

const consoleError = console.error;
console.error = (...args: unknown[]) => {
  if (typeof args[0] === "string" && args[0].includes("useLayoutEffect does nothing on the server")) return;
  consoleError(...args);
};

function renderAll(el: ReactElement): Promise<string> {
  return new Promise((resolve, reject) => {
    let html = "";
    const sink = new PassThrough();
    sink.on("data", (c) => (html += c.toString()));
    sink.on("end", () => resolve(html));
    const s = renderToPipeableStream(el, {
      onAllReady() {
        s.pipe(sink);
      },
      onShellError: reject,
      onError: reject,
    });
  });
}

function api<T>(data: T | null): ApiState<T> {
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

const row = {
  id: "F-OPEN",
  project_root_hash: "h1",
  rule_id: "GHSA-aaaa",
  driver: "osv",
  category: "vulnerable_dependency",
  severity: "high",
  confidence: "high",
  scope: "scan",
  baseline: "new",
  status: "open",
  rel_path: "package-lock.json",
  message: "lodash 4.17.20 has a known vulnerability.",
  first_seen: "2026-11-02T18:21:22Z",
  last_seen: "2026-11-02T18:21:29Z",
};

const page: FindingsListPage = {
  findings: [row, { ...row, id: "F-CLOSED", status: "suppressed", message: "A suppressed one." }],
  total: 2,
  page: 1,
  limit: 50,
} as FindingsListPage;

function card(onFix?: (id: string) => void): string {
  return renderToStaticMarkup(
    <MemoryRouter>
      <FindingsCard
        findings={api(page)}
        projects={[]}
        onOpen={() => {}}
        page={1}
        sorting={INITIAL_FINDINGS_LIST.sorting}
        onPage={() => {}}
        onSorting={() => {}}
        onFix={onFix}
      />
    </MemoryRouter>,
  );
}

test("an ungrouped open finding row carries Fix with an agent; a closed one does not", () => {
  const html = card(() => {});
  const buttons = html.match(/data-testid="code-security-fix-finding"/g) ?? [];
  assert.equal(buttons.length, 1);
  assert.match(html, /aria-label="Fix with an agent"/);
});

test("without onFix the findings list renders no fix column (unchanged)", () => {
  assert.doesNotMatch(card(), /code-security-fix-finding/);
});

test("every group row carries Fix with an agent", () => {
  const groups: FindingGroupsPage = {
    by: "issue",
    groups: [
      { key: "a", rule_id: "GHSA-1", package: "vite@5.0.2", ecosystem: "npm", count: 3, projects: 2, max_severity: "high", first_seen: "", last_seen: "" },
      { key: "b", rule_id: "secret.x", rel_path: "a.ts", count: 1, projects: 1, max_severity: "low", first_seen: "", last_seen: "" },
    ],
    total: 2,
    page: 1,
    limit: 50,
    by_severity: {},
  };
  const html = renderToStaticMarkup(
    <MemoryRouter>
      <FindingGroupsTable
        by="issue"
        groups={api(groups)}
        projects={[]}
        page={1}
        sorting={INITIAL_GROUPS_LIST.sorting}
        onPage={() => {}}
        onSorting={() => {}}
        onDrill={() => {}}
        emptyHint=""
        loadingLabel=""
        onFix={() => {}}
      />
    </MemoryRouter>,
  );
  assert.equal((html.match(/data-testid="code-security-fix-group"/g) ?? []).length, 2);
});

const plan: FixPlan = {
  confirm_token: "tok",
  total: 5,
  truncated: false,
  projects: [
    { project_root_hash: "h1", name: "api", root_path: "/home/u/api", on_disk: true, findings: 3, listed: 3, prompt: "Fix these Code security findings in api." },
    { project_root_hash: "h2", name: "gone", root_path: "/home/u/gone", on_disk: false, findings: 2, listed: 2, prompt: "Fix gone." },
  ],
  seeds: { "claude-code": "leading_positional", hermes: "none" },
};

test("the fix plan lists projects by count, disables one not on this machine and previews the first one's task", async () => {
  const sel: FixSelection = { kind: "group", by: "issue", group: { key: "k", rule_id: "GHSA-1", count: 5, projects: 2, max_severity: "high", first_seen: "", last_seen: "" }, filters: EMPTY_FINDINGS_FILTERS };
  await apiCache.fetch(fixPlanPath(sel), async () => plan);
  const html = renderToStaticMarkup(
    <MemoryRouter>
      <FixWithAgentDialog selection={sel} subtitle="Group: GHSA-1" onClose={() => {}} />
    </MemoryRouter>,
  );
  assert.match(html, /5 open findings in 2 projects/);
  assert.equal((html.match(/data-testid="code-security-fix-project"/g) ?? []).length, 2);
  assert.match(html, /Not on this machine: a launch here would be refused/);
  assert.match(html, /<input type="radio"[^>]*disabled=""/);
  assert.match(html, /data-testid="code-security-fix-prompt"/);
  assert.match(html, /Fix these Code security findings in api\./);
  assert.doesNotMatch(html, /Fix gone\./);
  // Outside the dock provider (this test), Choose agent cannot open a terminal.
  assert.match(html, /Choose agent/);
  assert.match(html, /data-help-id="card.code_security_fix_plan"/);
});

test("the attempts panel shows each attempt's state and a rescan for its project", async () => {
  const r: FixAttemptsResponse = {
    attempts: [
      {
        id: "a1",
        created_at: "2026-11-13T10:00:00Z",
        tool: "claude-code",
        project_root_hash: "h1",
        project_name: "api",
        handle: "t",
        seeded: true,
        total: 3,
        open: 1,
        cleared: false,
        findings: [
          { id: "f1", rule_id: "CVE-2026-1", status: "open" },
          { id: "f2", rule_id: "GHSA-x", status: "not_reproduced" },
          { id: "f3", rule_id: "GHSA-y", status: "fixed_verified" },
        ],
      },
    ],
  };
  await apiCache.fetch(FIX_ATTEMPTS_PATH, async () => r);
  const html = renderToStaticMarkup(
    <MemoryRouter>
      <FixAttemptsPanel onRescan={() => {}} />
    </MemoryRouter>,
  );
  assert.match(html, /1 of 3 still open/);
  assert.match(html, /1 open · 1 cleared on rescan · 1 verified fixed/);
  assert.match(html, /Rescan project/);
  assert.match(html, /CVE-2026-1/);
});

function taskDialog(withTask: boolean): ReactElement {
  const task = fixTaskFor({ kind: "finding", id: "F-OPEN" }, plan, plan.projects[0]);
  return (
    <MemoryRouter>
      <NewTerminalDialog onClose={() => {}} onLaunched={() => {}} task={withTask ? task : undefined} />
    </MemoryRouter>
  );
}

test("task mode shows the task, fixes the folder and drops the folder picker", async () => {
  const html = await renderAll(taskDialog(true));
  assert.match(html, /data-testid="new-terminal-task"/);
  assert.match(html, /Fix 3 Code security findings/);
  assert.match(html, /data-testid="new-terminal-task-folder"[^>]*>\/home\/u\/api</);
  assert.doesNotMatch(html, /Project root <span/);
  assert.doesNotMatch(html, /id="new-terminal-system"/);
  assert.match(html, /data-help-id="glossary.task_seed"/);
});

test("outside task mode the dialog keeps its folder picker and shows no task", async () => {
  const html = await renderAll(taskDialog(false));
  assert.doesNotMatch(html, /new-terminal-task/);
  assert.match(html, /Project root <span/);
});
