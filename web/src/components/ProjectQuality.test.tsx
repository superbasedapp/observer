// Component tests of the Projects detail Quality tab
// (components/projectdetail/QualityTab.tsx), rendered with
// react-dom/server under node's test runner (scripts/test-components.mjs).
// The rule they pin: a metric the server did not measure renders "not
// measured" with the server's reason, never 0%, and a measured one names
// its source and its age.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import { QualityView } from "@/components/projectdetail/QualityTab";
import type { ProjectQuality } from "@/lib/codeQuality";

const NOW = Date.parse("2026-11-04T12:00:00Z");

function base(): ProjectQuality {
  return {
    project_id: 7,
    enabled: true,
    measured_at: "2026-11-04T12:00:00Z",
    coverage: {
      state: "no_report",
      reason: "No coverage report found at the default locations.",
      lines: 0,
      covered: 0,
      reports: [],
      problems: [],
      least_covered: [],
      locations: [{ path: "coverage/lcov.info", format: "lcov", writer: "Jest" }],
    },
    duplication: {
      state: "codeintel_off",
      reason: "Not measured: code intelligence is off.",
      eligible_symbols: 0,
      cloned_symbols: 0,
      eligible_lines: 0,
      cloned_lines: 0,
      groups: 0,
      top_groups: [],
      skipped_buckets: 0,
      indexed_files: 0,
      stale: false,
      truncated: false,
      method: { min_lines: 6, min_shared_bands: 6, total_bands: 12, kinds: ["function", "method"] },
    },
    complexity: {
      state: "codeintel_off",
      reason: "Not measured: code intelligence is off.",
      functions: 0,
      over: 0,
      p50: 0,
      p90: 0,
      max: 0,
      per_language: [],
      top: [],
      counted_files: 0,
      pending_files: 0,
      uncounted_files: 0,
      uncounted_langs: [],
      indexed_files: 0,
      stale: false,
      truncated: false,
      method: { threshold: 10, kinds: ["function", "method"] },
    },
    history: [],
    trend: { coverage: { days: 0 }, duplication: { days: 0 }, complexity: { days: 0 } },
    window_days: 30,
  };
}

// A day recorded before complexity was.
const noCx = { complexity_state: "" as const, complexity_functions: 0, complexity_p90: 0, complexity_max: 0 };

function render(q: ProjectQuality): string {
  return renderToStaticMarkup(
    <MemoryRouter>
      <QualityView q={q} now={NOW} />
    </MemoryRouter>,
  );
}

test("not-measured metrics say why and show no percentage", () => {
  const html = render(base());
  assert.match(html, /not measured/);
  assert.match(html, /code intelligence is off/);
  assert.match(html, /No coverage report found/);
  assert.match(html, /Looked for: coverage\/lcov\.info/);
  assert.match(html, /No daily points yet/);
  assert.doesNotMatch(html, /0\.0%/);
});

// The StatCard headline animates its number from 0 (it renders 0 under
// react-dom/server), so these cases assert the sub-lines and sections.
test("measured coverage names the report and its age; the trend reads the window", () => {
  const q = base();
  q.coverage = {
    ...q.coverage,
    state: "measured",
    reason: "Line coverage from the project's own report files.",
    lines: 200,
    covered: 150,
    percent: 75,
    newest_report_at: "2026-11-02T12:00:00Z",
    reports: [
      { path: "coverage/lcov.info", format: "lcov", modified_at: "2026-11-02T12:00:00Z", lines: 200, covered: 150, files: 3, use: "counted" },
      {
        path: "coverage/cobertura-coverage.xml",
        format: "cobertura",
        modified_at: "2026-11-02T12:00:00Z",
        lines: 200,
        covered: 150,
        files: 3,
        use: "same_run",
        same_run_as: "coverage/lcov.info",
      },
    ],
    problems: [{ path: "web/coverage.xml", kind: "unrecognized" }],
    least_covered: [{ path: "src/a.ts", report: "coverage/lcov.info", lines: 40, covered: 4, percent: 10 }],
  };
  q.history = [
    { day: "2026-11-01", measured_at: "", coverage_state: "measured", coverage_percent: 70, coverage_lines: 100, dup_state: "codeintel_off", dup_cloned_lines: 0, dup_groups: 0, ...noCx },
    { day: "2026-11-04", measured_at: "", coverage_state: "measured", coverage_percent: 75, coverage_lines: 200, dup_state: "codeintel_off", dup_cloned_lines: 0, dup_groups: 0, ...noCx },
  ];
  q.trend.coverage = { days: 2, from: 70, to: 75, delta: 5, from_day: "2026-11-01", to_day: "2026-11-04" };
  const html = render(q);
  assert.match(html, /75\.0%/);
  assert.match(html, /150 of 200 lines, 1 report; newest report 2 days ago/);
  assert.match(html, /same test run as coverage\/lcov\.info/);
  assert.match(html, /not a coverage format Observer reads/);
  assert.match(html, /src\/a\.ts/);
  assert.match(html, /\+5\.0 pts since 2026-11-01 \(2 measured days\)/);
  assert.match(html, /code intelligence off/);
});

test("measured duplication lists groups and states the method", () => {
  const q = base();
  q.duplication = {
    ...q.duplication,
    state: "measured",
    reason: "",
    eligible_symbols: 50,
    cloned_symbols: 2,
    eligible_lines: 1000,
    cloned_lines: 40,
    groups: 1,
    line_share: 4,
    indexed_files: 12,
    last_indexed_at: "2026-11-04T11:00:00Z",
    stale: true,
    top_groups: [{ size: 2, lines: 40, members: [{ name: "parseA", file: "a.go", start_line: 1, end_line: 20 }, { name: "parseB", file: "b.go", start_line: 5, end_line: 24 }] }],
  };
  const html = render(q);
  assert.match(html, /40 of 1,000 function lines in 1 near-clone group; indexed 1 hour ago; from the last index/);
  assert.match(html, /parseA/);
  assert.match(html, /share at least 6 of 12 MinHash bands/);
});

test("an off feature says how to turn it on", () => {
  const q = base();
  q.enabled = false;
  q.coverage.state = "off";
  q.duplication.state = "off";
  const html = render(q);
  // Plain words on the page; the config key sits behind the technical
  // details tooltip (docs/app-design-system.md "Copy rules").
  assert.match(html, /under More settings/);
  assert.match(html, /Technical details for the quality metrics switch/);
  assert.doesNotMatch(html, /<code>\[projects\]/);
  // The control comes first, as a link (lane L5).
  assert.match(html, /href="\/settings\?section=intelligence"/);
});

test("measured complexity lists the most complex functions and states the method", () => {
  const q = base();
  q.complexity = {
    ...q.complexity,
    state: "measured",
    reason: "",
    functions: 120,
    over: 6,
    over_share: 5,
    mean: 3.1,
    p50: 2,
    p90: 7,
    max: 31,
    per_language: [
      { lang: "go", functions: 100, over: 5, p90: 7, max: 31 },
      { lang: "python", functions: 20, over: 1, p90: 6, max: 12 },
    ],
    top: [{ name: "dispatch", kind: "function", lang: "go", file: "cmd/run.go", start_line: 10, end_line: 200, complexity: 31 }],
    counted_files: 40,
    pending_files: 2,
    uncounted_files: 1,
    uncounted_langs: ["elixir"],
    indexed_files: 43,
    last_indexed_at: "2026-11-04T11:00:00Z",
  };
  q.history = [
    { day: "2026-11-03", measured_at: "", coverage_state: "no_report", coverage_lines: 0, dup_state: "codeintel_off", dup_cloned_lines: 0, dup_groups: 0, complexity_state: "count_pending", complexity_functions: 0, complexity_p90: 0, complexity_max: 0 },
    { day: "2026-11-04", measured_at: "", coverage_state: "no_report", coverage_lines: 0, dup_state: "codeintel_off", dup_cloned_lines: 0, dup_groups: 0, complexity_state: "measured", complexity_over_share: 5, complexity_functions: 120, complexity_p90: 7, complexity_max: 31 },
  ];
  q.trend.complexity = { days: 1, from: 5, to: 5, from_day: "2026-11-04", to_day: "2026-11-04" };
  const html = render(q);
  assert.match(html, /Functions over complexity 10/);
  assert.match(html, /6 of 120 functions; p90 7, max 31; indexed 1 hour ago/);
  assert.match(html, /dispatch/);
  assert.match(html, /cmd\/run\.go<\/span>:10-200/);
  assert.match(html, /python · 1 of 20 over 10/);
  assert.match(html, /2 files wait for the next index pass; 1 file has no counter \(elixir\)/);
  assert.match(html, /5\.0%/);
  assert.match(html, /waiting for the next index/);
  assert.match(html, /one measured day in this window, no trend yet/);
});

test("complexity waiting for a recount says so, with no number", () => {
  const q = base();
  q.complexity = {
    ...q.complexity,
    state: "count_pending",
    reason: "Not counted yet: the index was built before complexity counting was on.",
    pending_files: 12,
  };
  const html = render(q);
  assert.match(html, /Not counted yet/);
  assert.match(html, /12 files wait for the next index pass/);
  assert.doesNotMatch(html, /Most complex functions/);
});
