// Pins the live ribbon's model (lib/ribbon.ts): one case per row of every
// rule table (gate, chip, strip, layout, cost, receipt, toast), plus the
// honesty helpers (time labels, pulse on real advance only, the dock
// mapping, the minimise preference that survives broken storage).
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  CHIP_RULES,
  COST_RULES,
  GATE_RULES,
  LAYOUT_RULES,
  RECEIPT_RULES,
  RIBBON_DOT,
  RIBBON_MINIMISED_KEY,
  STRIP_RULES,
  TOAST_RULES,
  actionsText,
  advancedSessions,
  chipView,
  costCell,
  dockTokenFor,
  firstCaptureToastAllowed,
  fmtMinutes,
  freshness,
  lastActivityMap,
  modelText,
  readMinimised,
  receiptLines,
  receiptVisible,
  shouldPollDetail,
  startToolFor,
  stripLayout,
  stripOpen,
  timeText,
  tokensText,
  totalCostCell,
  writeMinimised,
  type ChipInput,
  type GateInput,
  type ReceiptInput,
  type RibbonReceipt,
  type RibbonSession,
  type StripInput,
  type ToastInput,
} from "./ribbon.ts";
import { liveDotProps } from "./liveSignals.ts";

const NOW = Date.parse("2026-11-18T12:00:00Z");
const ago = (ms: number) => new Date(NOW - ms).toISOString();

function session(over: Partial<RibbonSession> = {}): RibbonSession {
  return {
    session_id: "s1",
    tool: "claude-code",
    project: "app",
    model: "claude-sonnet-4-6",
    model_count: 1,
    tokens: 18_200,
    cost_usd: 0.06,
    cost_estimated: false,
    cost_recorded: true,
    price_unknown: false,
    turns: 3,
    actions_total: 14,
    started_at: ago(12 * 60_000),
    last_activity: ago(5_000),
    ...over,
  };
}

// ---------------------------------------------------------------- gate

test("GATE_RULES: one case per row", () => {
  const base: GateInput = { liveHidden: false, enabled: true, statusLive: 0, dockRunning: false, detailLive: 0 };
  const cases: [string, GateInput, boolean][] = [
    ["org hid Live", { ...base, liveHidden: true, statusLive: 3, dockRunning: true }, false],
    ["switched off", { ...base, enabled: false, statusLive: 3 }, false],
    ["dock running skips the lagging count", { ...base, dockRunning: true }, true],
    ["nav count says live", { ...base, statusLive: 2 }, true],
    ["last detail still live", { ...base, detailLive: 1 }, true],
    ["quiet machine", base, false],
  ];
  assert.equal(cases.length, GATE_RULES.length);
  for (const [name, input, want] of cases) assert.equal(shouldPollDetail(input), want, name);
  // Unknown enabled (first read pending) does not block the gate.
  assert.equal(shouldPollDetail({ ...base, enabled: null, statusLive: 1 }), true);
});

// ---------------------------------------------------------------- chip

test("CHIP_RULES: one case per row, with the exact copy", () => {
  const base: ChipInput = { off: false, handoffWaiting: false, live: 0, stripOpen: false, canLaunch: true };
  const cases: [string, ChipInput, ReturnType<typeof chipView>][] = [
    ["off", { ...base, off: true, live: 2 }, { kind: "hidden" }],
    ["hand-off waiting, idle", { ...base, handoffWaiting: true }, { kind: "hidden" }],
    ["idle owner", base, { kind: "idle", text: "No agent running", action: "Start one" }],
    ["strip open", { ...base, live: 2, stripOpen: true }, { kind: "hidden" }],
    ["live, folded", { ...base, live: 2 }, { kind: "live", text: "2 live" }],
  ];
  assert.equal(cases.length, CHIP_RULES.length);
  for (const [name, input, want] of cases) assert.deepEqual(chipView(input), want, name);
  // A viewer without the launch capability gets no "Start one".
  assert.deepEqual(chipView({ ...base, canLaunch: false }), { kind: "idle", text: "No agent running", action: null });
  // During the hand-off a real live session still shows.
  assert.deepEqual(chipView({ ...base, handoffWaiting: true, live: 1 }), { kind: "live", text: "1 live" });
});

// ---------------------------------------------------------------- strip

test("STRIP_RULES: one case per row", () => {
  const base: StripInput = { off: false, live: 1, minimised: false, wide: true };
  const cases: [string, StripInput, boolean][] = [
    ["off", { ...base, off: true }, false],
    ["nothing live", { ...base, live: 0 }, false],
    ["minimised", { ...base, minimised: true }, false],
    ["phone width", { ...base, wide: false }, false],
    ["live", base, true],
  ];
  assert.equal(cases.length, STRIP_RULES.length);
  for (const [name, input, want] of cases) assert.equal(stripOpen(input), want, name);
});

test("LAYOUT_RULES: one case per row", () => {
  const s = (id: string) => session({ session_id: id });
  const one = stripLayout([s("a")], 1, 3);
  assert.deepEqual([one.mode, one.shown.map((x) => x.session_id), one.more], ["single", ["a"], 0]);
  const three = stripLayout([s("a"), s("b"), s("c")], 3, 3);
  assert.deepEqual([three.mode, three.shown.length, three.more], ["segments", 3, 0]);
  const five = stripLayout([s("a"), s("b"), s("c"), s("d"), s("e")], 5, 3);
  assert.deepEqual([five.mode, five.shown.map((x) => x.session_id), five.more], ["collapsed", ["a", "b"], 3]);
  assert.equal(LAYOUT_RULES.length, 3);
  // Narrow: two sessions already collapse, showing the newest one.
  const narrow = stripLayout([s("a"), s("b")], 2, 1);
  assert.deepEqual([narrow.mode, narrow.shown.length, narrow.more], ["collapsed", 1, 1]);
  // active_count beyond the returned sessions still counts in "+N".
  assert.equal(stripLayout([s("a"), s("b"), s("c"), s("d")], 12, 3).more, 10);
});

// ---------------------------------------------------------------- cells

test("COST_RULES: one case per row, never $0 for an unpriced model", () => {
  const cases: [string, Partial<RibbonSession>, "usd" | "tokens", ReturnType<typeof costCell>][] = [
    ["no tokens kept here", { cost_recorded: false, turns: 0 }, "usd", { kind: "text", text: "cost not recorded", muted: true }],
    ["no turn yet", { turns: 0, cost_usd: 0 }, "usd", { kind: "text", text: "no tokens yet", muted: true }],
    ["token display mode", {}, "tokens", { kind: "hidden" }],
    ["nothing priced", { price_unknown: true, cost_usd: 0 }, "usd", { kind: "text", text: "price unknown", muted: true }],
    ["estimated", { cost_estimated: true, cost_usd: 0.18 }, "usd", { kind: "text", text: "$0.18 est.", muted: false }],
    ["recorded", { cost_usd: 1.2 }, "usd", { kind: "text", text: "$1.20", muted: false }],
  ];
  assert.equal(cases.length, COST_RULES.length);
  for (const [name, over, mode, want] of cases) assert.deepEqual(costCell(session(over), mode), want, name);
  // A partly unpriced session with a real cost still says est., and a cost
  // under a cent never rounds to $0.00.
  assert.deepEqual(costCell(session({ price_unknown: true, cost_usd: 0.2 })), { kind: "text", text: "$0.20 est.", muted: false });
  assert.deepEqual(costCell(session({ cost_usd: 0.004 })), { kind: "text", text: "<$0.01", muted: false });
});

test("totalCostCell sums priced sessions only, est. if any is", () => {
  const total = totalCostCell([
    session({ cost_usd: 0.18 }),
    session({ cost_usd: 1.2, cost_estimated: true }),
    session({ cost_recorded: false, turns: 0, cost_usd: 0 }),
  ]);
  assert.deepEqual(total, { kind: "text", text: "$1.38 est.", muted: false });
  assert.deepEqual(totalCostCell([session({ cost_recorded: false, turns: 0 })]), { kind: "hidden" });
  assert.deepEqual(totalCostCell([session()], "tokens"), { kind: "hidden" });
});

test("tokens, model and actions labels", () => {
  assert.equal(tokensText(session()), "18.2K tok");
  assert.equal(tokensText(session({ turns: 0 })), null);
  assert.equal(modelText(session()), "claude-sonnet-4-6");
  assert.equal(modelText(session({ model_count: 2 })), "claude-sonnet-4-6 +1");
  assert.equal(modelText(session({ model: undefined })), null);
  assert.equal(actionsText(session()), null);
  assert.equal(actionsText(session({ cost_recorded: false, actions_total: 14 })), "14 actions");
  assert.equal(actionsText(session({ cost_recorded: false, actions_total: 1 })), "1 action");
});

test("time labels: running from the start, quiet after 2 minutes", () => {
  assert.equal(fmtMinutes(30_000), "<1 m");
  assert.equal(fmtMinutes(12 * 60_000), "12 m");
  assert.equal(fmtMinutes(60 * 60_000), "1 h");
  assert.equal(fmtMinutes(65 * 60_000), "1 h 5 m");
  assert.equal(timeText(session(), NOW), "running 12 m");
  assert.equal(timeText(session({ last_activity: ago(4 * 60_000) }), NOW), "quiet 4 m");
});

test("freshness drives the dot: ping, still, grey", () => {
  assert.equal(freshness(session({ last_activity: ago(10_000) }), NOW), "active");
  assert.equal(freshness(session({ last_activity: ago(60_000) }), NOW), "recent");
  assert.equal(freshness(session({ last_activity: ago(3 * 60_000) }), NOW), "quiet");
  assert.equal(freshness(session({ last_activity: "garbage" }), NOW), "quiet");
  assert.deepEqual(liveDotProps(RIBBON_DOT, "active"), { tone: "success" });
  assert.deepEqual(liveDotProps(RIBBON_DOT, "recent"), { tone: "success", still: true });
  assert.deepEqual(liveDotProps(RIBBON_DOT, "quiet"), { tone: "idle", still: true });
});

// ---------------------------------------------------------------- pulse

test("advancedSessions pulses only on a real advance", () => {
  const first = [session({ session_id: "a", last_activity: ago(20_000) })];
  assert.equal(advancedSessions(null, first).size, 0, "first reading never pulses");
  const prev = lastActivityMap(first);
  assert.equal(advancedSessions(prev, first).size, 0, "same reading does not pulse");
  const moved = [session({ session_id: "a", last_activity: ago(1_000) }), session({ session_id: "b" })];
  assert.deepEqual([...advancedSessions(prev, moved)], ["a"], "a new session arrives, it does not pulse");
  const back = [session({ session_id: "a", last_activity: ago(60_000) })];
  assert.equal(advancedSessions(prev, back).size, 0, "an older reading does not pulse");
});

// ---------------------------------------------------------------- receipt

test("RECEIPT_RULES: one case per row", () => {
  const r = { session_id: "s" } as RibbonReceipt;
  const base: ReceiptInput = { receipt: r, ribbonOn: true, isRemote: false, dismissed: false, demo: false };
  const cases: [string, ReceiptInput, boolean][] = [
    ["nothing fired", { ...base, receipt: null }, false],
    ["ribbon off", { ...base, ribbonOn: false }, false],
    ["demo", { ...base, demo: true }, false],
    ["remote viewer", { ...base, isRemote: true }, false],
    ["closed", { ...base, dismissed: true }, false],
    ["show", base, true],
  ];
  assert.equal(cases.length, RECEIPT_RULES.length);
  for (const [name, input, want] of cases) assert.equal(receiptVisible(input), want, name);
});

test("receiptLines reads the numbers and the work, zero parts left out", () => {
  const r: RibbonReceipt = {
    session_id: "s",
    tool: "claude-code",
    model: "claude-sonnet-4-6",
    tokens: 18_200,
    cost_usd: 0.06,
    cost_estimated: true,
    cost_recorded: true,
    price_unknown: false,
    turns: 1,
    files_read: 6,
    edits: 0,
    commands: 2,
  };
  assert.deepEqual(receiptLines(r), {
    stats: "claude-sonnet-4-6 · 18.2K tokens · $0.06 est.",
    work: "6 files read · 2 commands",
  });
  assert.deepEqual(receiptLines({ ...r, files_read: 0, commands: 0 }).work, null);
  assert.equal(
    receiptLines({ ...r, cost_recorded: false, turns: 0, model: undefined }).stats,
    "cost not recorded",
  );
});

test("TOAST_RULES: one case per row", () => {
  const base: ToastInput = { answered: true, supported: true, ribbonOn: true };
  const cases: [string, ToastInput, boolean][] = [
    ["not answered", { ...base, answered: false }, false],
    ["older daemon", { ...base, supported: false }, true],
    ["ribbon off", { ...base, ribbonOn: false }, true],
    ["receipt owns it", base, false],
  ];
  assert.equal(cases.length, TOAST_RULES.length);
  for (const [name, input, want] of cases) assert.equal(firstCaptureToastAllowed(input), want, name);
});

// ---------------------------------------------------------------- actions

test("dockTokenFor: own id first, then the terminal link, else null", () => {
  const dock = [
    { token: "t1", sessionId: "" },
    { token: "t2", sessionId: "s2" },
  ];
  assert.equal(dockTokenFor("s2", dock, {}), "t2");
  assert.equal(dockTokenFor("s1", dock, { t1: "s1" }), "t1");
  assert.equal(dockTokenFor("s9", dock, { t1: "s1" }), null);
});

test("startToolFor picks the most used tool, else the dialog default", () => {
  assert.equal(startToolFor([{ tool: "codex", action_count: 3 }, { tool: "claude-code", action_count: 40 }]), "claude-code");
  assert.equal(startToolFor([]), null);
  assert.equal(startToolFor(undefined), null);
});

// ---------------------------------------------------------------- storage

test("the minimise preference survives broken storage", () => {
  const mem = new Map<string, string>();
  const store = {
    getItem: (k: string) => mem.get(k) ?? null,
    setItem: (k: string, v: string) => void mem.set(k, v),
    removeItem: (k: string) => void mem.delete(k),
  };
  assert.equal(readMinimised(store), false);
  writeMinimised(store, true);
  assert.equal(mem.get(RIBBON_MINIMISED_KEY), "1");
  assert.equal(readMinimised(store), true);
  writeMinimised(store, false);
  assert.equal(readMinimised(store), false);
  const broken = {
    getItem: () => {
      throw new Error("blocked");
    },
    setItem: () => {
      throw new Error("blocked");
    },
    removeItem: () => {
      throw new Error("blocked");
    },
  };
  assert.equal(readMinimised(broken), false);
  assert.doesNotThrow(() => writeMinimised(broken, true));
  assert.equal(readMinimised(null), false);
});
