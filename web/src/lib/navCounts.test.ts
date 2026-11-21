import { test } from "node:test";
import assert from "node:assert/strict";
import { NAV_GROUPS } from "./nav.ts";
import { NAV_COUNT_IDS, NO_NAV_COUNTS, UNBADGED_NAV_IDS, navCounts, openIssuesTitle } from "./navCounts.ts";
import type { SnapshotCounts, StatusSnapshot } from "./types.ts";

// A snapshot from a current daemon: every count present, each one distinct
// so a badge reading the wrong field shows.
function snapshot(counts: Partial<SnapshotCounts> = {}, tools = 3): StatusSnapshot {
  return {
    db_path: "/tmp/x.db",
    db_size_bytes: 0,
    schema_version: 1,
    recent_failures_24h: 0,
    per_tool_last_seen: Array.from({ length: tools }, (_, i) => ({
      tool: `t${i}`,
      last_seen_at: "2026-11-07T10:00:00Z",
      action_count: 1,
    })),
    counts: {
      projects: 373,
      sessions: 5200,
      actions: 90000,
      api_turns: 1200,
      file_state: 640,
      failure_context: 12,
      action_excerpts: 52000,
      token_usage: 33000,
      cache_events: 410,
      suggestions: 7,
      guard_events: 88,
      router_decisions: 19,
      live_sessions: 2,
      active_sessions_24h: 14,
      project_patterns: 0,
      plan_accounts: 2,
      benchmark_runs: 4,
      open_issues: { total: 195, critical: 20, high: 175 },
      ...counts,
    },
  };
}

test("each badge reads its own count", () => {
  const got = navCounts(snapshot());
  const cases: { id: string; value: number }[] = [
    { id: "overview", value: 14 },
    { id: "live", value: 2 },
    { id: "sessions", value: 5200 },
    { id: "actions", value: 90000 },
    { id: "projects", value: 373 },
    { id: "security", value: 88 },
    { id: "code-security", value: 195 },
    { id: "search", value: 52000 },
    { id: "cost", value: 1200 },
    { id: "plans", value: 2 },
    { id: "analysis", value: 33000 },
    { id: "tools", value: 3 },
    { id: "compression", value: 52000 },
    { id: "cache", value: 410 },
    { id: "suggestions", value: 7 },
    { id: "routing", value: 19 },
    { id: "benchmarks", value: 4 },
    { id: "discovery", value: 640 },
    // The defect this table pins: Patterns showed the projects count (373).
    { id: "patterns", value: 0 },
  ];
  for (const c of cases) {
    assert.equal(got[c.id]?.value, c.value, c.id);
  }
  assert.deepEqual(Object.keys(got).sort(), cases.map((c) => c.id).sort());
});

test("each title says what its badge counts", () => {
  const got = navCounts(snapshot({ live_sessions: 1 }));
  const cases: { id: string; title: string }[] = [
    { id: "live", title: "1 session active in the last 15 minutes" },
    { id: "overview", title: "14 sessions active in the last 24 hours" },
    { id: "code-security", title: "195 open issues (20 critical, 175 high)" },
    { id: "sessions", title: "5,200 in total, all time" },
    { id: "patterns", title: "0 in total, all time" },
    { id: "plans", title: "2 in total, all time" },
  ];
  for (const c of cases) {
    assert.equal(got[c.id]?.title, c.title, c.id);
  }
});

test("openIssuesTitle counts issues the way the page header does", () => {
  const cases: { total: number; critical: number; high: number; want: string }[] = [
    { total: 5, critical: 1, high: 2, want: "5 open issues (1 critical, 2 high)" },
    { total: 1, critical: 0, high: 1, want: "1 open issue (0 critical, 1 high)" },
    { total: 0, critical: 0, high: 0, want: "0 open issues (0 critical, 0 high)" },
    { total: 1234, critical: 10, high: 200, want: "1,234 open issues (10 critical, 200 high)" },
  ];
  for (const c of cases) {
    assert.equal(openIssuesTitle(c), c.want);
  }
});

test("a count an older daemon omits hides its badge", () => {
  const cases: { field: keyof SnapshotCounts; id: string }[] = [
    { field: "live_sessions", id: "live" },
    { field: "active_sessions_24h", id: "overview" },
    { field: "guard_events", id: "security" },
    { field: "router_decisions", id: "routing" },
    { field: "project_patterns", id: "patterns" },
    { field: "plan_accounts", id: "plans" },
    { field: "benchmark_runs", id: "benchmarks" },
    { field: "open_issues", id: "code-security" },
  ];
  for (const c of cases) {
    const s = snapshot();
    delete (s.counts as Partial<SnapshotCounts>)[c.field];
    const got = navCounts(s);
    assert.equal(got[c.id], undefined, `${c.id} without ${c.field}`);
    // Every other badge still shows.
    assert.equal(Object.keys(got).length, NAV_COUNT_IDS.length - 1, c.id);
  }
});

test("no snapshot is no badges", () => {
  assert.equal(navCounts(undefined), NO_NAV_COUNTS);
  assert.equal(navCounts(null), NO_NAV_COUNTS);
});

test("a zero is a badge, not an absence", () => {
  const got = navCounts(snapshot({ open_issues: { total: 0, critical: 0, high: 0 }, active_sessions_24h: 0 }));
  assert.equal(got["code-security"]?.value, 0);
  assert.equal(got.overview?.value, 0);
});

test("every Monitor, Analyze and Optimize page is badged or says why not", () => {
  const badged = new Set(NAV_COUNT_IDS);
  for (const g of NAV_GROUPS) {
    for (const it of g.items) {
      if (g.id === "configure") {
        assert.ok(!badged.has(it.id), `${it.id}: the Configure group stays unbadged`);
        assert.equal(UNBADGED_NAV_IDS[it.id], undefined, it.id);
        continue;
      }
      const reason = UNBADGED_NAV_IDS[it.id];
      assert.ok(badged.has(it.id) !== (reason != null), `${it.id}: badged xor an unbadged reason`);
    }
  }
  // No rule names an id the nav does not have.
  const navIds = new Set(NAV_GROUPS.flatMap((g) => g.items.map((i) => i.id)));
  for (const id of [...NAV_COUNT_IDS, ...Object.keys(UNBADGED_NAV_IDS)]) {
    assert.ok(navIds.has(id), `${id} is not a nav item`);
  }
});

test("badge rules follow nav order", () => {
  const order = NAV_GROUPS.flatMap((g) => g.items.map((i) => i.id));
  const positions = NAV_COUNT_IDS.map((id) => order.indexOf(id));
  assert.deepEqual(positions, [...positions].sort((a, b) => a - b));
});
