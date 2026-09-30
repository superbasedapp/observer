import assert from "node:assert/strict";
import test from "node:test";

import {
  AMBIGUOUS_INVOCATIONS_NOTE,
  cellsForSkill,
  commitStatusLabel,
  currentCaveat,
  currentLabel,
  headLabel,
  invocationLabel,
  invokedEventLabel,
  observedLabel,
  sessionsForSkill,
  UNMATCHED_INVOCATIONS_NOTE,
  versionLabel,
} from "./skills.ts";
import type {
  ProjectSkill,
  ProjectSkillsResponse,
  SkillCell,
  SkillHead,
  SkillObserved,
  SkillSpan,
} from "./types.ts";

// -----------------------------------------------------------------------------
// fixtures
// -----------------------------------------------------------------------------

function skill(overrides: Partial<ProjectSkill> = {}): ProjectSkill {
  return {
    key: "project:review-checklist",
    scope: "project",
    dir: ".claude/skills/review-checklist",
    name: "review-checklist",
    names: ["review-checklist"],
    present: true,
    tools: ["claude-code"],
    ambiguous: false,
    current: {
      in_git: "committed",
      worktree: "",
      head_version: "a1b2c3d4",
      cannot_match: "",
    },
    moved_from: null,
    versions: [
      {
        id: "a1b2c3d4",
        blob_oid: "a1b2c3d4e5f6",
        ordinal: 1,
        first_seen: "2026-08-01T00:00:00Z",
        introduced_by: null,
        reintroduced_in: [],
        in_commits: true,
        observed_first: "2026-08-01T00:00:00Z",
        observed_last: "2026-08-10T00:00:00Z",
        sessions_available: 3,
        invocations: 2,
      },
      {
        id: "b2c3d4e5",
        blob_oid: "b2c3d4e5f6a7",
        ordinal: 2,
        first_seen: "2026-08-11T00:00:00Z",
        introduced_by: null,
        reintroduced_in: [],
        in_commits: true,
        observed_first: "2026-08-11T00:00:00Z",
        observed_last: "2026-09-01T00:00:00Z",
        sessions_available: 5,
        invocations: 1,
      },
    ],
    commits: [],
    invocations: { measurable: true, count: 0, last: "" },
    ...overrides,
  };
}

function observed(overrides: Partial<SkillObserved> = {}): SkillObserved {
  return { state: "unknown", version: "", changed: [], line_endings: false, source: "", reason: "", ...overrides };
}

function head(overrides: Partial<SkillHead> = {}): SkillHead {
  return { state: "n/a", version: "", sha: "", candidates: [], reason: "", ...overrides };
}

// -----------------------------------------------------------------------------
// versionLabel
// -----------------------------------------------------------------------------

test("versionLabel: renders ordinal + id for a known version", () => {
  assert.equal(versionLabel(skill(), "a1b2c3d4"), "#1 a1b2c3d4");
  assert.equal(versionLabel(skill(), "b2c3d4e5"), "#2 b2c3d4e5");
});

test("versionLabel: falls back to the bare id when not found on the skill", () => {
  assert.equal(versionLabel(skill(), "deadbeef"), "deadbeef");
});

test("versionLabel: empty id renders as empty string", () => {
  assert.equal(versionLabel(skill(), ""), "");
});

// -----------------------------------------------------------------------------
// observedLabel
// -----------------------------------------------------------------------------

test("observedLabel: observed renders the resolved version label, tone ok", () => {
  const l = observedLabel(skill(), observed({ state: "observed", version: "a1b2c3d4" }));
  assert.equal(l.text, "#1 a1b2c3d4");
  assert.equal(l.tone, "ok");
  assert.equal(l.tip, undefined);
});

test("observedLabel: observed with line_endings adds a CRLF note", () => {
  const l = observedLabel(
    skill(),
    observed({ state: "observed", version: "a1b2c3d4", line_endings: true }),
  );
  assert.match(l.tip ?? "", /CRLF/);
});

test("observedLabel: changed_during_session chains resolved versions with arrows", () => {
  const l = observedLabel(
    skill(),
    observed({ state: "changed_during_session", changed: ["a1b2c3d4", "b2c3d4e5"] }),
  );
  assert.equal(l.text, "changed: #1 a1b2c3d4 -> #2 b2c3d4e5");
  assert.equal(l.tone, "warn");
});

test("observedLabel: changed_during_session renders state words as copy, never raw tokens", () => {
  const l = observedLabel(
    skill(),
    observed({ state: "changed_during_session", changed: ["a1b2c3d4", "absent", "unreadable", "home_unresolved"] }),
  );
  assert.equal(
    l.text,
    "changed: #1 a1b2c3d4 -> not present -> unreadable -> unknown (home not resolved)",
  );
});

test("observedLabel: a first snapshot after the start is never 'available at start'", () => {
  const l = observedLabel(
    skill(),
    observed({ state: "observed_after_start", version: "a1b2c3d4", source: "resume" }),
  );
  assert.equal(l.text, "not captured at start");
  assert.equal(l.tone, "muted");
  assert.match(l.tip ?? "", /First seen at resume: #1 a1b2c3d4/);
});

test("observedLabel: a sub-agent's not_captured names the sub-agent reason", () => {
  const l = observedLabel(skill(), observed({ state: "not_captured", reason: "subagent" }));
  assert.equal(l.text, "not captured (sub-agent)");
  assert.match(l.tip ?? "", /never fire SessionStart/);
});

test("observedLabel: not_captured carries the honesty tooltip", () => {
  const l = observedLabel(skill(), observed({ state: "not_captured" }));
  assert.equal(l.text, "not captured");
  assert.equal(l.tone, "muted");
  assert.match(l.tip ?? "", /Unknown, not absent/);
});

test("observedLabel: unknown / absent / home_unresolved / not_measurable render their fixed copy", () => {
  assert.equal(observedLabel(skill(), observed({ state: "unknown" })).text, "unknown");
  assert.equal(observedLabel(skill(), observed({ state: "absent" })).text, "not present");
  assert.equal(
    observedLabel(skill(), observed({ state: "home_unresolved" })).text,
    "unknown (home not resolved)",
  );
  assert.equal(
    observedLabel(skill(), observed({ state: "not_measurable" })).text,
    "not measurable",
  );
});

test("observedLabel: n/a renders a dash with the not-read tooltip", () => {
  const l = observedLabel(skill(), observed({ state: "n/a" }));
  assert.equal(l.text, "-");
  assert.match(l.tip ?? "", /does not read this skill directory/);
});

// -----------------------------------------------------------------------------
// headLabel
// -----------------------------------------------------------------------------

test("headLabel: committed renders the resolved version label, tone ok", () => {
  const l = headLabel(skill(), head({ state: "committed", version: "b2c3d4e5" }));
  assert.equal(l.text, "#2 b2c3d4e5");
  assert.equal(l.tone, "ok");
});

test("headLabel: head_moved_near_start lists candidates", () => {
  const l = headLabel(
    skill(),
    head({ state: "head_moved_near_start", candidates: ["deadbeef", "feedface"] }),
  );
  assert.equal(l.text, "HEAD moved near start (deadbeef, feedface)");
  assert.equal(l.tone, "warn");
});

test("headLabel: same-second moves say so, and a reason token never reaches the page raw", () => {
  const l = headLabel(
    skill(),
    head({ state: "head_moved_near_start", reason: "same_second", candidates: ["deadbeef", "feedface"] }),
  );
  assert.equal(l.text, "HEAD moved several times in one second (deadbeef, feedface)");
  assert.match(l.tip ?? "", /one-second resolution/);
  const skew = headLabel(skill(), head({ state: "head_moved_near_start", reason: "skew" }));
  assert.match(skew.tip ?? "", /clock-skew margin/);
});

test("headLabel: head_moved_near_start with no candidates omits the parens", () => {
  const l = headLabel(skill(), head({ state: "head_moved_near_start" }));
  assert.equal(l.text, "HEAD moved near start");
});

test("headLabel: the fixed-copy states render verbatim", () => {
  assert.equal(headLabel(skill(), head({ state: "absent_in_commit" })).text, "not in that commit");
  assert.equal(
    headLabel(skill(), head({ state: "reflog_unavailable" })).text,
    "unknown (no reflog for that time)",
  );
  assert.equal(headLabel(skill(), head({ state: "pending" })).text, "pending");
  assert.equal(headLabel(skill(), head({ state: "commit_unavailable" })).text, "commit gone");
  assert.equal(
    headLabel(skill(), head({ state: "git_unavailable" })).text,
    "git history unavailable",
  );
  assert.equal(
    headLabel(skill(), head({ state: "not_in_project_git" })).text,
    "not in this project's git",
  );
  assert.equal(headLabel(skill(), head({ state: "n/a" })).text, "-");
});

// -----------------------------------------------------------------------------
// currentLabel / currentCaveat
// -----------------------------------------------------------------------------

test("currentLabel: committed with a clean worktree", () => {
  const l = currentLabel(skill({ current: { in_git: "committed", worktree: "", head_version: "a1b2c3d4", cannot_match: "" } }));
  assert.equal(l.text, "committed");
  assert.equal(l.tone, "ok");
});

test("currentLabel: committed + modified/deleted/renamed_away/unmerged worktree reads uncommitted changes", () => {
  for (const worktree of ["modified", "deleted", "renamed_away", "unmerged"] as const) {
    const l = currentLabel(
      skill({ current: { in_git: "committed", worktree, head_version: "a1b2c3d4", cannot_match: "" } }),
    );
    assert.equal(l.text, "committed (uncommitted changes)", `worktree=${worktree}`);
    assert.equal(l.tone, "warn", `worktree=${worktree}`);
  }
});

test("currentLabel: not_committed + untracked/ignored/added each get distinct copy", () => {
  const base = { in_git: "not_committed" as const, head_version: "", cannot_match: "" as const };
  assert.equal(
    currentLabel(skill({ current: { ...base, worktree: "untracked" } })).text,
    "not in git (untracked)",
  );
  assert.equal(
    currentLabel(skill({ current: { ...base, worktree: "ignored" } })).text,
    "not in git (ignored)",
  );
  assert.equal(
    currentLabel(skill({ current: { ...base, worktree: "added" } })).text,
    "staged, not committed",
  );
});

test("currentLabel: removed / not_in_project_git / unknown render their fixed copy", () => {
  const mk = (in_git: "removed" | "not_in_project_git" | "unknown") =>
    currentLabel(skill({ current: { in_git, worktree: "", head_version: "", cannot_match: "" } }));
  assert.equal(mk("removed").text, "removed");
  assert.equal(mk("not_in_project_git").text, "home directory (not in project git)");
  assert.equal(mk("unknown").text, "unknown");
});

test("currentCaveat: null when versions can be matched, a string otherwise", () => {
  assert.equal(currentCaveat(skill()), null);
  const s = skill({
    current: { in_git: "committed", worktree: "", head_version: "a1b2c3d4", cannot_match: "symlink" },
  });
  assert.match(currentCaveat(s) ?? "", /cannot be matched to commits/);
});

// -----------------------------------------------------------------------------
// invocationLabel
// -----------------------------------------------------------------------------

test("invocationLabel: not measurable never renders as zero", () => {
  const l = invocationLabel(skill({ invocations: { measurable: false, count: 0, last: "" } }));
  assert.equal(l.text, "not measurable");
  assert.notEqual(l.text, "0");
});

test("invocationLabel: measurable with zero renders none captured, not zero", () => {
  const l = invocationLabel(skill({ invocations: { measurable: true, count: 0, last: "" } }));
  assert.equal(l.text, "none captured");
});

test("invocationLabel: measurable with a count renders the number", () => {
  const l = invocationLabel(skill({ invocations: { measurable: true, count: 4, last: "2026-09-01T00:00:00Z" } }));
  assert.equal(l.text, "4");
  assert.equal(l.tone, "ok");
});

// -----------------------------------------------------------------------------
// invokedEventLabel
// -----------------------------------------------------------------------------

test("invokedEventLabel: version resolves through versionLabel", () => {
  const l = invokedEventLabel(skill(), { at: "2026-09-01T00:00:00Z", state: "version", version: "b2c3d4e5" });
  assert.equal(l.text, "#2 b2c3d4e5");
  assert.equal(l.tone, "ok");
});

test("invokedEventLabel: version_not_captured / not_measurable / unknown render fixed copy", () => {
  const mk = (state: "version_not_captured" | "not_measurable" | "unknown") =>
    invokedEventLabel(skill(), { at: "", state, version: "" });
  assert.equal(mk("version_not_captured").text, "invoked (version not captured)");
  assert.equal(mk("not_measurable").text, "invoked (not measurable)");
  assert.equal(mk("unknown").text, "invoked (unknown version)");
});

// -----------------------------------------------------------------------------
// commitStatusLabel
// -----------------------------------------------------------------------------

test("commitStatusLabel: covers every status letter", () => {
  assert.equal(commitStatusLabel("A"), "added");
  assert.equal(commitStatusLabel("M"), "modified");
  assert.equal(commitStatusLabel("D"), "deleted");
  assert.equal(commitStatusLabel(""), "");
  assert.equal(commitStatusLabel("?"), "not certain");
});

// -----------------------------------------------------------------------------
// sessionsForSkill / cellsForSkill
// -----------------------------------------------------------------------------

function makeResponse(spans: SkillSpan[], cells: SkillCell[]): ProjectSkillsResponse {
  return {
    project_id: 1,
    root_path: "/repo",
    window_days: 30,
    truncated: false,
    capture: {
      observed_since: "",
      snapshot_capable: {},
      invocations_measurable: {},
      git: {
        state: "not_scanned",
        scanned_at: "",
        reflog_since: "",
        shallow: false,
        ignore_case: false,
        object_format: "",
        error: "",
        probe_unknown: [],
      },
    },
    skills: [],
    sessions: [],
    spans,
    cells,
    unmatched_invocations: [],
    ambiguous_invocations: [],
  };
}

test("sessionsForSkill: filters to one skill and reverses to newest-first", () => {
  const spans: SkillSpan[] = [
    { skill_key: "project:a", from_session: "s1", to_session: "s1", from: "t1", to: "t1", sessions: 1, observed: observed(), head: head() },
    { skill_key: "project:b", from_session: "s2", to_session: "s2", from: "t2", to: "t2", sessions: 1, observed: observed(), head: head() },
    { skill_key: "project:a", from_session: "s3", to_session: "s3", from: "t3", to: "t3", sessions: 1, observed: observed(), head: head() },
  ];
  const resp = makeResponse(spans, []);
  const result = sessionsForSkill(resp, "project:a");
  assert.deepEqual(result.map((s) => s.from_session), ["s3", "s1"]);
});

test("cellsForSkill: filters to the requested skill only", () => {
  const cells: SkillCell[] = [
    { skill_key: "project:a", session_id: "s1", observed: observed(), head: head(), invoked: [] },
    { skill_key: "project:b", session_id: "s2", observed: observed(), head: head(), invoked: [] },
  ];
  const resp = makeResponse([], cells);
  const result = cellsForSkill(resp, "project:a");
  assert.equal(result.length, 1);
  assert.equal(result[0].session_id, "s1");
});

// -----------------------------------------------------------------------------
// static copy constants
// -----------------------------------------------------------------------------

test("static notes are non-empty honest copy, not placeholders", () => {
  assert.match(UNMATCHED_INVOCATIONS_NOTE, /plugin skills/);
  assert.match(AMBIGUOUS_INVOCATIONS_NOTE, /not attributed/);
});

test("currentLabel: a staged rename target reads staged, not committed", () => {
  const l = currentLabel(
    skill({ current: { in_git: "not_committed", worktree: "renamed", head_version: "", cannot_match: "" } }),
  );
  assert.equal(l.text, "staged, not committed");
});

test("no user-facing label carries an em-dash", () => {
  const texts = [
    observedLabel(skill(), observed({ state: "observed_after_start", source: "compact" })),
    observedLabel(skill(), observed({ state: "not_captured", reason: "subagent" })),
    headLabel(skill(), head({ state: "head_moved_near_start", reason: "same_second" })),
    headLabel(skill(), head({ state: "git_unavailable", reason: "not_scanned" })),
  ].flatMap((l) => [l.text, l.tip ?? ""]);
  for (const t of texts) assert.ok(!t.includes("\u2014"), t);
});
