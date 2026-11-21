// Component tests of the observe-only process findings list in the session
// detail's Processes section (ProcessesSection.tsx FindingsList), rendered
// with react-dom/server: identical findings fold into one row with a count,
// and the rows page.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import { FindingsList } from "./ProcessesSection";
import type { ProcessFinding } from "@/lib/types";

function f(exe: string, i: number): ProcessFinding {
  return {
    rule_id: "process.executable_from_tmp",
    severity: "warn",
    process_key: `${exe}-${i}`,
    session_id: "s",
    exe_basename: exe,
    detail: "executable runs from a scratch location (tmp)",
    timestamp: new Date(Date.parse("2026-11-03T10:00:00Z") + i * 1000).toISOString(),
  };
}

const render = (findings: ProcessFinding[]) =>
  renderToStaticMarkup(
    <MemoryRouter>
      <FindingsList findings={findings} onSelectProc={() => {}} />
    </MemoryRouter>,
  );

test("identical findings fold into one row with a count", () => {
  const html = render([f("db.test.exe", 1), f("db.test.exe", 2), f("db.test.exe", 3), f("api.test.exe", 4)]);
  assert.match(html, /4 findings in 2 kinds/);
  assert.match(html, /×3/);
  assert.equal((html.match(/db\.test\.exe/g) ?? []).length, 1, "db.test.exe is one row");
  assert.match(html, /Show each/);
  assert.match(html, /Show process/, "a single finding links its process");
  assert.doesNotMatch(html, /of 2/, "two rows need no pager");
});

test("more than ten kinds page, ten rows a page", () => {
  const findings = Array.from({ length: 25 }, (_, i) => f(`t${String(i).padStart(2, "0")}.test.exe`, i));
  const html = render(findings);
  assert.match(html, /1-10 of 25/);
  assert.equal((html.match(/\.test\.exe/g) ?? []).length, 10);
});
