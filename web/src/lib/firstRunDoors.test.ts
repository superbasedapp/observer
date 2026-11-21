import assert from "node:assert/strict";
import test from "node:test";

import type { FirstRunResponse, FirstRunTool } from "./firstRun.ts";
import {
  DOOR_RULES,
  GLANCE_FACTS,
  WELCOME_BAND_DISMISS_KEY,
  activeLine,
  doorOf,
  glanceFacts,
  honestLine,
  monotonic,
  readBandDismissed,
  revealCounters,
  revealPhase,
  startAgentTool,
  toolList,
  toolsWithSessions,
  writeBandDismissed,
  type GlanceResponse,
  type Money,
} from "./firstRunDoors.ts";

// firstRunDoors.test.ts pins the Overview welcome band's decisions (local
// dashboard first-run design, section 8 steps 0 and 1): which door, the one
// honest line, the tool "Start a coding agent" preselects, the reveal's
// counters, and the settled card's facts with their honesty rules.

const brief = (over: Partial<FirstRunResponse> = {}): FirstRunResponse => ({
  auto_open: false,
  seen: false,
  install: "fresh",
  watcher_running: true,
  capture: { state: "done", files_found: 0, files_processed: 0, files_failed: 0 },
  tools: [],
  supported_not_found: 0,
  sessions: 0,
  project_count: 0,
  projects: [],
  generated_at: "2026-11-18T00:00:00Z",
  ...over,
});

const tool = (over: Partial<FirstRunTool> = {}): FirstRunTool => ({
  tool: "claude-code",
  name: "Claude Code",
  detected: true,
  enabled: true,
  watcher_active: true,
  history: { state: "done", files_found: 0, files_processed: 0, files_failed: 0 },
  sessions: 0,
  projects: 0,
  launchable: true,
  ...over,
});

// ---- doors: one case per rule row --------------------------------------------

test("door rules, one case per row", () => {
  const cases: Array<{ rule: string; input: Parameters<typeof doorOf>[0]; door: string }> = [
    { rule: "connect hand-off waiting", input: { brief: brief({ sessions: 9 }), handoffActive: true, dismissed: false }, door: "hidden" },
    { rule: "dismissed in this browser", input: { brief: brief({ sessions: 9 }), handoffActive: false, dismissed: true }, door: "hidden" },
    { rule: "no first-run read", input: { brief: null, handoffActive: false, dismissed: false }, door: "hidden" },
    { rule: "sessions captured", input: { brief: brief({ sessions: 3 }), handoffActive: false, dismissed: false }, door: "history" },
    {
      rule: "history files found, being read",
      input: {
        brief: brief({ capture: { state: "scanning", files_found: 4, files_processed: 0, files_failed: 0 } }),
        handoffActive: false,
        dismissed: false,
      },
      door: "history",
    },
    {
      rule: "watcher still looking",
      input: {
        brief: brief({ capture: { state: "idle", files_found: 0, files_processed: 0, files_failed: 0 } }),
        handoffActive: false,
        dismissed: false,
      },
      door: "looking",
    },
    { rule: "nothing here", input: { brief: brief(), handoffActive: false, dismissed: false }, door: "fresh" },
  ];
  assert.deepEqual(
    cases.map((c) => c.rule),
    DOOR_RULES.map((r) => r.name),
    "every rule row has a case",
  );
  for (const c of cases) assert.equal(doorOf(c.input), c.door, c.rule);
});

test("a stopped watcher with nothing captured is a fresh machine, not looking", () => {
  const b = brief({ watcher_running: false, capture: { state: "not_running", files_found: 0, files_processed: 0, files_failed: 0 } });
  assert.equal(doorOf({ brief: b, handoffActive: false, dismissed: false }), "fresh");
});

test("reveal phase follows the watcher's real first pass", () => {
  assert.equal(revealPhase(null), "settled");
  assert.equal(revealPhase(brief({ capture: { state: "scanning", files_found: 2, files_processed: 1, files_failed: 0 } })), "revealing");
  assert.equal(revealPhase(brief({ capture: { state: "idle", files_found: 0, files_processed: 0, files_failed: 0 } })), "revealing");
  assert.equal(revealPhase(brief()), "settled");
  assert.equal(
    revealPhase(brief({ watcher_running: false, capture: { state: "scanning", files_found: 2, files_processed: 1, files_failed: 0 } })),
    "settled",
  );
});

// ---- the honest line ----------------------------------------------------------

test("tool lists name two, then count the rest", () => {
  assert.equal(toolList([]), "");
  assert.equal(toolList(["Claude Code"]), "Claude Code");
  assert.equal(toolList(["Claude Code", "Codex"]), "Claude Code and Codex");
  assert.equal(toolList(["Claude Code", "Codex", "Cursor", "Gemini CLI"]), "Claude Code, Codex and 2 more");
});

test("honest line per door", () => {
  const done = brief({ sessions: 1204 });
  assert.equal(honestLine("history", done, ["Claude Code", "Codex"]), "We found 1,204 sessions from Claude Code and Codex on this machine.");
  assert.equal(honestLine("history", done, []), "We found 1,204 sessions on this machine.");
  const scanning = brief({ sessions: 1, capture: { state: "scanning", files_found: 9, files_processed: 2, files_failed: 0 } });
  assert.equal(honestLine("history", scanning, ["Codex"]), "We found 1 session from Codex so far.");
  const none = brief({ capture: { state: "scanning", files_found: 9, files_processed: 0, files_failed: 0 } });
  assert.equal(honestLine("history", none, []), "We found AI coding history on this machine. Reading it now.");
  assert.equal(honestLine("looking", brief(), []), "Looking for AI coding history on this machine.");
  assert.equal(honestLine("fresh", brief(), []), "No AI coding history here yet.");
  assert.equal(honestLine("hidden", brief(), []), "");
});

test("tools with sessions, most first", () => {
  const got = toolsWithSessions([
    tool({ tool: "codex", name: "Codex", sessions: 2 }),
    tool({ tool: "cursor", name: "Cursor", sessions: 0 }),
    tool({ tool: "claude-code", name: "Claude Code", sessions: 40 }),
  ]);
  assert.deepEqual(got.map((t) => t.tool), ["claude-code", "codex"]);
});

// ---- Start a coding agent -------------------------------------------------------

test("start agent preselects the most-used launchable tool", () => {
  assert.equal(startAgentTool(null), null);
  assert.equal(startAgentTool([]), null);
  assert.equal(
    startAgentTool([
      tool({ tool: "claude-code", sessions: 3 }),
      tool({ tool: "codex", sessions: 40 }),
      tool({ tool: "cursor", sessions: 900, launchable: false }),
    ]),
    "codex",
  );
});

test("with no sessions, a detected tool in the suggested order wins", () => {
  assert.equal(
    startAgentTool([
      tool({ tool: "opencode" }),
      tool({ tool: "gemini-cli" }),
      tool({ tool: "zed", detected: true }),
    ]),
    "gemini-cli",
  );
  assert.equal(startAgentTool([tool({ tool: "codex", detected: false, sessions: 0 })]), null, "not found, never used: no preselect");
});

// ---- the reveal's counters -------------------------------------------------------

test("counters come from one real reading", () => {
  const c = revealCounters(
    brief({ sessions: 12, project_count: 3, capture: { state: "scanning", files_found: 40, files_processed: 9, files_failed: 1 } }),
  );
  assert.deepEqual(c, { sessions: 12, projects: 3, filesRead: 9, filesFound: 40, ratio: 0.25 });
  assert.equal(revealCounters(brief({ capture: { state: "done", files_found: 0, files_processed: 0, files_failed: 0 } })).ratio, 1);
  assert.equal(revealCounters(brief({ capture: { state: "idle", files_found: 0, files_processed: 0, files_failed: 0 } })).ratio, null);
  assert.equal(revealCounters(null).sessions, 0);
});

test("monotonic never steps a counter back between readings", () => {
  assert.equal(monotonic(null, 5), 5);
  assert.equal(monotonic(5, 3), 5);
  assert.equal(monotonic(5, 8), 8);
});

// ---- the settled card -------------------------------------------------------------

const dollars: Money = { format: (usd) => `$${usd.toFixed(2)}`, dollars: true };
const tokensView: Money = { format: (_usd, tok) => `${tok} tok`, dollars: false };

const glance = (over: Partial<GlanceResponse> = {}): GlanceResponse => ({
  window_days: 30,
  sessions: 1204,
  project_count: 37,
  recent_sessions: 80,
  tools: [
    { tool: "claude-code", name: "Claude Code", sessions: 1000 },
    { tool: "codex", name: "Codex", sessions: 204 },
  ],
  top_model: { model: "claude-sonnet-4-6", turns: 480, share: 0.48, models: 4 },
  spend: { state: "priced", usd: 312.4, tokens: 900, priced_tokens: 800, priced_turns: 90, unpriced_turns: 0, estimated: true },
  busiest_project: { name: "app", root: "/w/app", sessions: 212 },
  rereads: 2310,
  generated_at: "2026-11-18T00:00:00Z",
  ...over,
});

test("glance facts, in order, with their caveats", () => {
  const facts = glanceFacts(glance(), dollars);
  assert.deepEqual(facts.map((f) => f.key), GLANCE_FACTS.map((r) => r.key));
  const by = Object.fromEntries(facts.map((f) => [f.key, f]));
  assert.equal(by.sessions!.value, "1,204");
  assert.equal(by.sessions!.sub, "across 2 tools · 37 projects");
  assert.equal(by.model!.value, "claude-sonnet-4-6");
  assert.equal(by.model!.sub, "48% of turns, last 30 days");
  assert.equal(by.spend!.label, "Spend, last 30 days");
  assert.equal(by.spend!.value, "$312.40 est.");
  assert.equal(by.project!.value, "app");
  assert.equal(by.rereads!.value, "2,310");
  assert.equal(by.rereads!.href, "/discovery");
});

test("spend: unpriced turns are named apart and never counted as $0", () => {
  const mixed = glanceFacts(
    glance({ spend: { state: "priced", usd: 1, tokens: 9, priced_tokens: 5, priced_turns: 2, unpriced_turns: 3, estimated: true } }),
    dollars,
  ).find((f) => f.key === "spend")!;
  assert.match(mixed.sub, /3 turns on models with no price are not counted/);
  const unpriced = glanceFacts(
    glance({ spend: { state: "unpriced", usd: 0, tokens: 9, priced_tokens: 0, priced_turns: 0, unpriced_turns: 4, estimated: false } }),
    dollars,
  ).find((f) => f.key === "spend")!;
  assert.equal(unpriced.value, "price unknown");
  assert.doesNotMatch(unpriced.value, /\$0/);
});

test("spend: recorded cost carries no est., none leaves the fact out", () => {
  const rec = glanceFacts(
    glance({ spend: { state: "priced", usd: 2, tokens: 9, priced_tokens: 9, priced_turns: 1, unpriced_turns: 0, estimated: false } }),
    dollars,
  ).find((f) => f.key === "spend")!;
  assert.equal(rec.value, "$2.00");
  const none = glanceFacts(
    glance({ spend: { state: "none", usd: 0, tokens: 0, priced_tokens: 0, priced_turns: 0, unpriced_turns: 0, estimated: false } }),
    dollars,
  );
  assert.equal(none.find((f) => f.key === "spend"), undefined);
});

test("spend in the token usage view shows every turn's tokens, no dollars, no est.", () => {
  const f = glanceFacts(glance(), tokensView).find((x) => x.key === "spend")!;
  assert.equal(f.label, "Token usage, last 30 days");
  assert.equal(f.value, "900 tok");
});

test("a fact with nothing true to say is left out", () => {
  const facts = glanceFacts(
    glance({ top_model: undefined, busiest_project: undefined, rereads: 0, tools: [], project_count: 0 }),
    dollars,
  );
  assert.deepEqual(facts.map((f) => f.key), ["sessions", "spend"]);
  assert.equal(facts[0]!.sub, "");
  assert.deepEqual(glanceFacts(null, dollars), []);
  assert.deepEqual(glanceFacts(glance({ sessions: 0, spend: { ...glance().spend, state: "none" } }), dollars).map((f) => f.key), ["model", "project", "rereads"]);
});

test("active line names the tool and project only, and says when", () => {
  assert.equal(activeLine(null), "");
  assert.equal(activeLine(glance()), "");
  assert.equal(activeLine(glance({ active_now: { tool: "claude-code", name: "Claude Code", project: "app" } })), "Claude Code was working in app in the last 15 minutes.");
  assert.equal(activeLine(glance({ active_now: { tool: "codex", name: "Codex" } })), "Codex was working in the last 15 minutes.");
});

// ---- Not now -------------------------------------------------------------------------

test("dismissal is per browser and survives broken storage", () => {
  const m = new Map<string, string>();
  const s = { getItem: (k: string) => m.get(k) ?? null, setItem: (k: string, v: string) => void m.set(k, v) };
  assert.equal(readBandDismissed(s), false);
  writeBandDismissed(s);
  assert.equal(m.get(WELCOME_BAND_DISMISS_KEY), "1");
  assert.equal(readBandDismissed(s), true);
  const broken = {
    getItem: () => {
      throw new Error("denied");
    },
    setItem: () => {
      throw new Error("denied");
    },
  };
  assert.equal(readBandDismissed(broken), false);
  assert.doesNotThrow(() => writeBandDismissed(broken));
  assert.equal(readBandDismissed(null), false);
});
