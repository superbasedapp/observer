import assert from "node:assert/strict";
import test from "node:test";

import {
  COVERAGE_HREF,
  NEXT_RULE_NAMES,
  connectedToolsHref,
  countLine,
  coverageChips,
  coverageStatus,
  coverageSummary,
  coverageView,
  defaultFilter,
  filterRows,
  fmtAgo,
  isLocalOnlyRefusal,
  nextStep,
  rowsFromFirstRun,
  rowsFromToolsStatus,
  sortRows,
  type CoverageRow,
} from "./coverage.ts";
import type { FirstRunResponse, FirstRunTool } from "./firstRun.ts";
import type { ToolsStatusResponse } from "./types";

const ft = (over: Partial<FirstRunTool> = {}): FirstRunTool => ({
  tool: "tool-a",
  name: "Tool A",
  detected: true,
  detected_path: "/home/u/.tool-a",
  enabled: true,
  watcher_active: true,
  history: { state: "done", files_found: 4, files_processed: 4, files_failed: 0 },
  sessions: 3,
  projects: 2,
  ...over,
});

const row = (over: Partial<CoverageRow> = {}): CoverageRow => ({ ...rowsFromFirstRun(resp([ft()]))[0], ...over });

function resp(tools: FirstRunTool[], over: Partial<FirstRunResponse> = {}): FirstRunResponse {
  return {
    auto_open: false,
    seen: true,
    install: "existing",
    watcher_running: true,
    capture: { state: "done", files_found: 4, files_processed: 4, files_failed: 0 },
    tools,
    supported_not_found: 0,
    supported: tools.length,
    sessions: 3,
    project_count: 2,
    projects: [],
    generated_at: "2026-10-21T10:00:00Z",
    ...over,
  };
}

const notFound = (over: Partial<FirstRunTool> = {}) =>
  ft({
    tool: "tool-z",
    name: "Tool Z",
    detected: false,
    detected_path: undefined,
    watcher_active: false,
    sessions: 0,
    projects: 0,
    history: { state: "waiting", files_found: 0, files_processed: 0, files_failed: 0 },
    ...over,
  });

test("status: one case per rule, in table order", () => {
  const cases: Array<[Partial<CoverageRow>, string, string]> = [
    [{ found: false }, "not_found", "Not found"],
    [{ enabled: false }, "off", "Capture off"],
    [{ history: { state: "failed", files_found: 2, files_processed: 1, files_failed: 1 } }, "attention", "Could not read"],
    [{ history: { state: "not_running", files_found: 0, files_processed: 0, files_failed: 0 } }, "attention", "Not running"],
    [{ history: { state: "scanning", files_found: 9, files_processed: 2, files_failed: 0 } }, "reading", "Reading history"],
    [{}, "capturing", "Capturing"],
    [{ watcherActive: false }, "idle", "Not capturing"],
  ];
  for (const [over, state, label] of cases) {
    const s = coverageStatus(row(over));
    assert.equal(s.state, state, JSON.stringify(over));
    assert.equal(s.label, label);
  }
});

test("a tool captured only by hooks or the proxy still counts as capturing", () => {
  assert.equal(coverageStatus(row({ watcherActive: false, hooks: { registered: true } })).state, "capturing");
  assert.equal(coverageStatus(row({ watcherActive: false, proxy: { registered: true } })).state, "capturing");
});

test("next step: one case per rule, in table order, and none once connected", () => {
  const hooksOff = { registered: false, detail: "would register 4 events" };
  const wiring = (hooks: boolean, route: boolean) => ({
    hooks: { register: hooks, remove: false },
    mcp: { register: false, remove: false },
    route: { register: route, remove: false },
  });
  const cases: Array<[string, Partial<CoverageRow>, string, string?]> = [
    ["not found, guided install offered", { found: false, launchable: true }, "install"],
    ["not found", { found: false, launchable: false }, "note"],
    ["capture off", { enabled: false }, "link", "/settings?section=tools"],
    ["history could not be read", { history: { state: "failed", reason: "bad file", files_found: 1, files_processed: 0, files_failed: 1 } }, "link", "/settings?section=tools&tool=tool-a&open=doctor"],
    ["watcher not running", { history: { state: "not_running", files_found: 0, files_processed: 0, files_failed: 0 } }, "note"],
    ["hooks not registered", { hooks: hooksOff, wiring: wiring(true, false) }, "link", "/settings?section=tools&tool=tool-a&open=setup"],
    ["proxy not routed", { proxy: { registered: false }, wiring: wiring(false, true) }, "link", "/settings?section=tools&tool=tool-a&open=setup"],
  ];
  assert.deepEqual(cases.map((c) => c[0]), [...NEXT_RULE_NAMES]);
  for (const [name, over, kind, href] of cases) {
    const step = nextStep(row(over));
    assert.ok(step, name);
    assert.equal(step.kind, kind, name);
    if (href) assert.equal(step.kind === "link" && step.href, href, name);
    assert.doesNotMatch(JSON.stringify(step), /[–—]/, `${name}: no en or em dashes`);
  }
  // Connected: hooks on, proxy routed (or none to route): nothing to do.
  assert.equal(nextStep(row({ hooks: { registered: true }, proxy: { registered: true }, wiring: wiring(true, true) })), null);
  // A hook surface Observer does not register is not a next step.
  assert.equal(nextStep(row({ hooks: { registered: false, no_hooks: true }, wiring: wiring(true, false) })), null);
  // Without a wiring offer there is nothing to click, even when hooks are off.
  assert.equal(nextStep(row({ hooks: hooksOff })), null);
  // A partial registration says so.
  const partial = nextStep(row({ hooks: { registered: false, partial: true }, wiring: wiring(true, false) }));
  assert.equal(partial?.kind === "link" && partial.label, "Finish hooks");
});

test("chips: the capture paths of a found tool; none for a tool not found", () => {
  const r = row({
    hooks: { registered: true, detail: "4 events registered" },
    mcp: { registered: false, detail: "not registered" },
    proxy: { registered: false },
  });
  assert.deepEqual(
    coverageChips(r).map((c) => [c.key, c.label, c.tone]),
    [
      ["files", "Session files", "success"],
      ["hooks", "Hooks on", "success"],
      ["mcp", "MCP off", "neutral"],
      ["proxy", "Proxy not routed", "neutral"],
    ],
  );
  assert.deepEqual(coverageChips(row({ found: false })), []);
  // n/a is left out: no MCP format, no hook surface, no route.
  const bare = coverageChips(row({ hooks: { registered: false, no_hooks: true } }));
  assert.deepEqual(bare.map((c) => c.key), ["files"]);
  assert.equal(coverageChips(row({ hooks: { registered: true, via_plugin: true } }))[1].label, "Hooks on (plugin)");
});

test("rows from the owner-local read keep every fact; not-found tools are listed", () => {
  const rows = rowsFromFirstRun(
    resp([ft({ launchable: true, last_seen_at: "2026-10-21T09:00:00Z" }), notFound({ launchable: true })]),
  );
  assert.equal(rows.length, 2);
  assert.equal(rows[0].found, true);
  assert.equal(rows[0].lastSeenAt, "2026-10-21T09:00:00Z");
  assert.equal(rows[1].found, false);
  assert.equal(rows[1].launchable, true);
  assert.equal(nextStep(rows[1])?.kind, "install");
});

test("rows from the remote fallback: unknown stays null, never zero; no install offered", () => {
  const d: ToolsStatusResponse = {
    generated_at: "2026-10-21T10:00:00Z",
    tools: [
      { tool: "tool-a", detected: true, enabled: true, action_count: 12, hooks: { registered: true } },
      { tool: "tool-z", detected: false, enabled: true, action_count: 0 },
    ],
  };
  const rows = rowsFromToolsStatus(d, (t) => t.toUpperCase());
  assert.equal(rows[0].name, "TOOL-A");
  assert.equal(rows[0].sessions, null);
  assert.equal(rows[0].history, null);
  assert.equal(rows[0].actions, 12);
  assert.equal(coverageStatus(rows[0]).state, "capturing");
  assert.equal(rows[1].launchable, false);
  assert.equal(nextStep(rows[1])?.kind, "note");
  assert.equal(countLine(rows[0]), "12 actions");
});

test("summary: detected and capturing counts, catalog size from the server", () => {
  const rows = rowsFromFirstRun(
    resp([
      ft(),
      ft({ tool: "tool-b", name: "Tool B", enabled: false }),
      ft({ tool: "tool-c", name: "Tool C", history: { state: "scanning", files_found: 9, files_processed: 1, files_failed: 0 } }),
      notFound(),
    ]),
  );
  const s = coverageSummary(rows, 45);
  assert.deepEqual(
    { supported: s.supported, found: s.found, capturing: s.capturing, attention: s.attention, notFound: s.notFound },
    { supported: 45, found: 3, capturing: 2, attention: 1, notFound: 42 },
  );
  assert.equal(s.headline, "3 of 45 supported tools detected, 2 capturing");
  assert.equal(coverageSummary(rows).supported, 4, "no server count: the rows");
});

test("sort: attention first, then capturing by activity, not found last by name", () => {
  const rows = sortRows(
    rowsFromFirstRun(
      resp([
        notFound({ tool: "z", name: "Zeta" }),
        ft({ tool: "a", name: "Alpha", sessions: 1 }),
        ft({ tool: "b", name: "Beta", sessions: 9 }),
        notFound({ tool: "c", name: "Charlie" }),
        ft({ tool: "d", name: "Delta", history: { state: "failed", files_found: 1, files_processed: 0, files_failed: 1 } }),
      ]),
    ),
  );
  assert.deepEqual(rows.map((r) => r.name), ["Delta", "Beta", "Alpha", "Charlie", "Zeta"]);
});

test("filter and its default", () => {
  const rows = rowsFromFirstRun(resp([ft(), notFound()]));
  assert.equal(filterRows(rows, "found").length, 1);
  assert.equal(filterRows(rows, "not_found").length, 1);
  assert.equal(filterRows(rows, "all").length, 2);
  assert.equal(defaultFilter(rows), "found");
  assert.equal(defaultFilter(rowsFromFirstRun(resp([notFound()]))), "all");
});

test("view: loading, error, ready, and the remote viewer states", () => {
  const none = { data: null, loading: true, error: null };
  const name = (t: string) => t;
  assert.equal(coverageView(none, none, name).kind, "loading");
  assert.deepEqual(coverageView({ data: null, loading: false, error: new Error("boom"), status: 500 }, none, name), {
    kind: "error",
    message: "boom",
  });
  const ready = coverageView({ data: resp([ft(), notFound()]), loading: false, error: null }, none, name);
  assert.equal(ready.kind, "ready");
  if (ready.kind === "ready") {
    assert.equal(ready.source, "local");
    assert.equal(ready.summary.found, 1);
    assert.equal(ready.moving, false);
  }
  const scanning = coverageView(
    { data: resp([ft()], { capture: { state: "scanning", files_found: 4, files_processed: 1, files_failed: 0 } }), loading: false, error: null },
    none,
    name,
  );
  assert.equal(scanning.kind === "ready" && scanning.moving, true);

  const refused = { data: null, loading: false, error: new Error("403 forbidden: route is reachable only from the local dashboard"), status: 403 };
  assert.equal(isLocalOnlyRefusal(refused), true);
  assert.equal(coverageView(refused, none, name).kind, "loading", "waits for the fallback");
  const fb = { data: { generated_at: "", tools: [{ tool: "tool-a", detected: true, enabled: true, action_count: 2 }] }, loading: false, error: null };
  const remote = coverageView(refused, fb, name);
  assert.equal(remote.kind === "ready" && remote.source, "remote");
  assert.equal(
    coverageView(refused, { data: null, loading: false, error: new Error("403 denied"), status: 403 }, name).kind,
    "local_only",
  );
});

test("small formatters", () => {
  const now = Date.parse("2026-10-21T10:00:00Z");
  assert.equal(fmtAgo(undefined, now), null);
  assert.equal(fmtAgo("garbage", now), null);
  assert.equal(fmtAgo("2026-10-21T09:59:40Z", now), "just now");
  assert.equal(fmtAgo("2026-10-21T09:30:00Z", now), "30 min ago");
  assert.equal(fmtAgo("2026-10-21T05:00:00Z", now), "5 h ago");
  assert.equal(fmtAgo("2026-10-11T10:00:00Z", now), "10 days ago");
  assert.equal(countLine(row()), "3 sessions, 2 projects");
  assert.equal(countLine(row({ sessions: 1, projects: 0 })), "1 session");
  assert.equal(countLine(row({ sessions: 0 })), "No sessions yet");
  assert.equal(connectedToolsHref(), "/settings?section=tools");
  assert.equal(COVERAGE_HREF, "/tools?tab=coverage");
});
