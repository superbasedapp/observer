import assert from "node:assert/strict";
import test from "node:test";

import {
  changeText,
  complexityFilesNote,
  complexityHeadline,
  coverageHeadline,
  duplicationHeadline,
  formatLabel,
  isMeasured,
  pct,
  problemText,
  stateLabel,
  type QualityComplexity,
  type QualityCoverage,
  type QualityDuplication,
} from "./codeQuality.ts";

function coverage(over: Partial<QualityCoverage> = {}): QualityCoverage {
  return {
    state: "measured",
    reason: "",
    lines: 200,
    covered: 150,
    percent: 75,
    reports: [],
    problems: [],
    least_covered: [],
    locations: [],
    ...over,
  };
}

function duplication(over: Partial<QualityDuplication> = {}): QualityDuplication {
  return {
    state: "measured",
    reason: "",
    eligible_symbols: 10,
    cloned_symbols: 2,
    eligible_lines: 100,
    cloned_lines: 12,
    groups: 1,
    line_share: 12,
    top_groups: [],
    skipped_buckets: 0,
    indexed_files: 4,
    stale: false,
    truncated: false,
    method: { min_lines: 6, min_shared_bands: 6, total_bands: 12, kinds: ["function", "method"] },
    ...over,
  };
}

test("a not-measured metric never reads as a number", () => {
  assert.equal(coverageHeadline(coverage()), "75.0%");
  assert.equal(coverageHeadline(coverage({ state: "no_report", percent: undefined })), "not measured");
  // Even a stray percent on a not-measured state is not shown.
  assert.equal(coverageHeadline(coverage({ state: "off", percent: 0 })), "not measured");
  assert.equal(duplicationHeadline(duplication()), "12.0%");
  assert.equal(duplicationHeadline(duplication({ state: "codeintel_off" })), "not measured");
});

test("isMeasured and stateLabel", () => {
  assert.equal(isMeasured("measured"), true);
  assert.equal(isMeasured("no_report"), false);
  assert.equal(stateLabel("codeintel_off"), "code intelligence off");
  assert.equal(stateLabel("count_pending"), "waiting for the next index");
  assert.equal(stateLabel("no_supported_files"), "no counted language");
  assert.equal(stateLabel(""), "—");
  assert.equal(stateLabel("something_new"), "something_new");
});

test("pct formats a 0-100 value and dashes an absent one", () => {
  assert.equal(pct(12.345), "12.3%");
  assert.equal(pct(undefined), "—");
  assert.equal(pct(Number.NaN), "—");
});

test("changeText never invents a trend", () => {
  assert.equal(changeText({ days: 0 }), "no measured days in this window");
  assert.equal(changeText({ days: 1, from: 40, to: 40, from_day: "2026-11-01" }), "one measured day in this window, no trend yet");
  assert.equal(
    changeText({ days: 5, from: 40, to: 43.25, delta: 3.25, from_day: "2026-10-01", to_day: "2026-11-01" }),
    "+3.3 pts since 2026-10-01 (5 measured days)",
  );
  assert.equal(changeText({ days: 2, from: 40, to: 38, delta: -2, from_day: "2026-10-01" }), "−2.0 pts since 2026-10-01 (2 measured days)");
});

test("problemText and formatLabel", () => {
  assert.equal(problemText("symlink"), "a symbolic link, not followed");
  assert.equal(problemText("other"), "other");
  assert.equal(formatLabel("gocover"), "Go coverprofile");
  assert.equal(formatLabel("x"), "x");
});

function complexity(over: Partial<QualityComplexity> = {}): QualityComplexity {
  return {
    state: "measured",
    reason: "",
    functions: 40,
    over: 2,
    over_share: 5,
    p50: 2,
    p90: 6,
    max: 14,
    per_language: [],
    top: [],
    counted_files: 10,
    pending_files: 0,
    uncounted_files: 0,
    uncounted_langs: [],
    indexed_files: 10,
    stale: false,
    truncated: false,
    method: { threshold: 10, kinds: ["function", "method"] },
    ...over,
  };
}

test("complexityHeadline never reads a not-measured state as a number", () => {
  assert.equal(complexityHeadline(complexity()), "5.0%");
  assert.equal(complexityHeadline(complexity({ state: "count_pending", over_share: 0 })), "not measured");
  assert.equal(complexityHeadline(complexity({ state: "no_supported_files" })), "not measured");
});

test("complexityFilesNote names what the figure leaves out", () => {
  assert.equal(complexityFilesNote(complexity()), "");
  assert.equal(complexityFilesNote(complexity({ pending_files: 1 })), "1 file waits for the next index pass");
  assert.equal(
    complexityFilesNote(complexity({ pending_files: 3, uncounted_files: 2, uncounted_langs: ["elixir", "go"] })),
    "3 files wait for the next index pass; 2 files have no counter (elixir, go): heuristic parser or a language without a rule table",
  );
  assert.equal(
    complexityFilesNote(complexity({ uncounted_files: 1 })),
    "1 file has no counter: heuristic parser or a language without a rule table",
  );
});
