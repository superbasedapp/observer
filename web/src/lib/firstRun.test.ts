import assert from "node:assert/strict";
import test from "node:test";

import {
  captureChips,
  closeFirstRun,
  closeMarksSeen,
  closedThisVisit,
  decideFirstRun,
  firstRunSnapshot,
  firstRunView,
  headline,
  historyBadge,
  markClosedThisVisit,
  openFirstRun,
  progressRatio,
  resetFirstRunUi,
  seenRequestInit,
  shouldAutoOpen,
  shouldPoll,
  sortTools,
  subscribeFirstRun,
  toolBadge,
  tourHeld,
  type FirstRunResponse,
  type FirstRunTool,
} from "./firstRun.ts";

const tool = (over: Partial<FirstRunTool> = {}): FirstRunTool => ({
  tool: "claude-code",
  name: "Claude Code",
  detected: true,
  detected_path: "/home/u/.claude/projects",
  enabled: true,
  watcher_active: true,
  history: { state: "done", files_found: 3, files_processed: 3, files_failed: 0 },
  sessions: 3,
  projects: 1,
  ...over,
});

const resp = (over: Partial<FirstRunResponse> = {}): FirstRunResponse => ({
  auto_open: true,
  seen: false,
  install: "fresh",
  watcher_running: true,
  capture: { state: "scanning", files_found: 10, files_processed: 4, files_failed: 0 },
  tools: [tool()],
  supported_not_found: 30,
  sessions: 3,
  project_count: 1,
  projects: [{ name: "alpha", root: "/work/alpha", sessions: 3, tools: ["claude-code"] }],
  generated_at: "2026-10-20T09:00:00Z",
  ...over,
});

const noDash = (s: string) => assert.ok(!/[–—]/.test(s), `copy has an en or em dash: ${s}`);

test("loading: no data, no error", () => {
  assert.deepEqual(firstRunView({ data: null, loading: true, error: null }), { kind: "loading" });
});

test("error: no data and a failed read", () => {
  const v = firstRunView({ data: null, loading: false, error: new Error("403 forbidden") });
  assert.equal(v.kind, "error");
  assert.equal(v.kind === "error" && v.message, "403 forbidden");
});

test("a failed refresh keeps the last data on screen", () => {
  const v = firstRunView({ data: resp(), loading: false, error: new Error("blip") });
  assert.equal(v.kind, "ready");
});

test("in progress: ratio and headline from the capture counts", () => {
  const v = firstRunView({ data: resp(), loading: false, error: null });
  assert.equal(v.kind, "ready");
  if (v.kind !== "ready") return;
  assert.equal(v.phase, "scanning");
  assert.equal(v.ratio, 0.4);
  assert.match(v.headline, /4 of 10 files/);
  assert.match(v.detail, /3 sessions across 1 project captured so far/);
  noDash(v.headline);
  noDash(v.detail);
});

test("in progress before any file is found: indeterminate", () => {
  const v = firstRunView({
    data: resp({ capture: { state: "scanning", files_found: 0, files_processed: 0, files_failed: 0 } }),
    loading: false,
    error: null,
  });
  assert.equal(v.kind === "ready" && v.ratio, null);
  assert.equal(v.kind === "ready" && v.headline, "Looking for your past sessions");
});

test("done: full bar and a past-tense headline", () => {
  const v = firstRunView({
    data: resp({ capture: { state: "done", files_found: 10, files_processed: 10, files_failed: 0 } }),
    loading: false,
    error: null,
  });
  assert.equal(v.kind, "ready");
  if (v.kind !== "ready") return;
  assert.equal(v.ratio, 1);
  assert.equal(v.headline, "Your past history is captured");
});

test("nothing detected: the empty state with the not-found count", () => {
  const v = firstRunView({ data: resp({ tools: [], sessions: 0, project_count: 0, projects: [] }), loading: false, error: null });
  assert.deepEqual(v, { kind: "empty", watcherRunning: true, supportedNotFound: 30 });
});

test("every headline is plain copy without dashes", () => {
  for (const state of ["idle", "scanning", "done", "stopped", "not_running"] as const) {
    for (const sessions of [0, 5]) {
      const h = headline(resp({ sessions, capture: { state, files_found: 2, files_processed: 1, files_failed: 0 } }));
      noDash(h.headline);
      noDash(h.detail);
    }
  }
});

test("progressRatio clamps and treats unknown totals as indeterminate", () => {
  assert.equal(progressRatio(0, 0, 0), null);
  assert.equal(progressRatio(4, 1, 1), 0.5);
  assert.equal(progressRatio(2, 5, 0), 1);
  assert.equal(progressRatio(Number.NaN, 1, 0), null);
});

test("history badges cover every state and fall back for unknown ones", () => {
  assert.deepEqual(historyBadge("done"), { label: "Captured", tone: "success" });
  assert.deepEqual(historyBadge("failed"), { label: "Could not read", tone: "danger" });
  assert.deepEqual(historyBadge("brand-new"), { label: "brand-new", tone: "neutral" });
});

test("a finished pass that found nothing says so instead of Captured", () => {
  const empty = tool({ sessions: 0, history: { state: "done", files_found: 0, files_processed: 0, files_failed: 0 } });
  assert.deepEqual(toolBadge(empty), { label: "No history yet", tone: "neutral" });
  assert.deepEqual(toolBadge(tool()), { label: "Captured", tone: "success" });
});

test("capture chips: files, hooks and proxy, leaving out what a tool lacks", () => {
  const chips = captureChips(
    tool({
      hooks: { registered: true, detail: "9 events registered" },
      proxy: { registered: false },
    }),
  );
  assert.deepEqual(
    chips.map((c) => [c.key, c.label, c.tone]),
    [
      ["files", "Session files", "success"],
      ["hooks", "Hooks on", "success"],
      ["proxy", "Proxy not routed", "neutral"],
    ],
  );
  const bare = captureChips(tool({ watcher_active: false, hooks: { registered: false, no_hooks: true } }));
  assert.deepEqual(bare.map((c) => c.key), ["files"]);
  assert.equal(bare[0].tone, "neutral");
  for (const c of chips) noDash(c.title);
});

test("sortTools puts moving tools first, then by sessions", () => {
  const sorted = sortTools([
    tool({ tool: "a", name: "A", sessions: 1 }),
    tool({ tool: "b", name: "B", sessions: 9 }),
    tool({ tool: "c", name: "C", history: { state: "scanning", files_found: 1, files_processed: 0, files_failed: 0 } }),
  ]);
  assert.deepEqual(sorted.map((t) => t.tool), ["c", "b", "a"]);
});

test("polling runs while the capture can still change", () => {
  assert.equal(shouldPoll(null), true);
  assert.equal(shouldPoll(resp()), true);
  assert.equal(shouldPoll(resp({ capture: { state: "idle", files_found: 0, files_processed: 0, files_failed: 0 } })), true);
  assert.equal(shouldPoll(resp({ capture: { state: "done", files_found: 1, files_processed: 1, files_failed: 0 } })), false);
  assert.equal(shouldPoll(resp({ watcher_running: false })), false);
});

test("closing marks seen only once the capture finished", () => {
  assert.equal(closeMarksSeen(resp()), false);
  assert.equal(closeMarksSeen(resp({ capture: { state: "done", files_found: 1, files_processed: 1, files_failed: 0 } })), true);
  assert.equal(closeMarksSeen(null), false);
});

test("auto-open follows the daemon unless closed this visit", () => {
  assert.equal(shouldAutoOpen(resp(), false), true);
  assert.equal(shouldAutoOpen(resp(), true), false);
  assert.equal(shouldAutoOpen(resp({ auto_open: false }), false), false);
  assert.equal(shouldAutoOpen(null, false), false);
});

test("the visit flag survives a throwing storage", () => {
  const store = new Map<string, string>();
  const ok = { getItem: (k: string) => store.get(k) ?? null, setItem: (k: string, v: string) => void store.set(k, v) };
  assert.equal(closedThisVisit(ok), false);
  markClosedThisVisit(ok);
  assert.equal(closedThisVisit(ok), true);
  const broken = {
    getItem: () => {
      throw new Error("denied");
    },
    setItem: () => {
      throw new Error("denied");
    },
  };
  assert.equal(closedThisVisit(broken), false);
  markClosedThisVisit(broken);
  assert.equal(closedThisVisit(null), false);
});

test("the seen POST carries JSON and the confirm header", () => {
  const init = seenRequestInit(true, "tok");
  assert.equal(init.method, "POST");
  assert.deepEqual(init.headers, { "Content-Type": "application/json", "X-Observer-Confirm": "tok" });
  assert.equal(init.body, '{"seen":true}');
});

test("the ui store: decide once, reopen, close, and hold the tour meanwhile", () => {
  resetFirstRunUi();
  let calls = 0;
  const off = subscribeFirstRun(() => calls++);
  assert.equal(tourHeld(firstRunSnapshot()), true);
  decideFirstRun(false);
  assert.deepEqual(firstRunSnapshot(), { decided: true, open: false });
  assert.equal(tourHeld(firstRunSnapshot()), false);
  decideFirstRun(true); // a second decision is ignored
  assert.equal(firstRunSnapshot().open, false);
  openFirstRun();
  assert.equal(tourHeld(firstRunSnapshot()), true);
  closeFirstRun();
  assert.equal(firstRunSnapshot().open, false);
  assert.equal(calls, 3);
  off();
  resetFirstRunUi();
});
