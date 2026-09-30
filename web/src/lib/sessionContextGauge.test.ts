// Pins the node session gauge mapping (lib/sessionContextGauge.ts): the
// daemon's context_gauge wins when present, an older daemon falls back to the
// client computation, and a nil ratio / over_window is unknown - never 0% or
// 100%. One case per CONTEXT_GAUGE_RULES row, per source.
import { test } from "node:test";
import assert from "node:assert/strict";
import { CONTEXT_GAUGE_RULES, budgetNoun, contextGaugeModel, knownRatio } from "./sessionContextGauge.ts";

test("rules are ordered no_prefix, measured, over_window, no_ceiling", () => {
  assert.deepEqual(
    CONTEXT_GAUGE_RULES.map((r) => r.state),
    ["no_prefix", "measured", "over_window", "no_ceiling"],
  );
});

test("server: no prefix -> no_prefix, observed carried through", () => {
  const m = contextGaugeModel({ gauge: { used_tokens: 0, observed: true } });
  assert.equal(m.state, "no_prefix");
  assert.equal(m.source, "server");
  assert.equal(m.observed, true);
  assert.equal(m.ratio, null);
});

test("server: measured uses the server ratio and budget, not a client division", () => {
  const m = contextGaugeModel({
    gauge: { used_tokens: 50_000, budget_tokens: 200_000, budget_source: "model_window", ratio: 0.3 },
    prefixTokens: 1,
    contextBudgetTokens: 2,
  });
  assert.equal(m.state, "measured");
  assert.equal(m.ratio, 0.3);
  assert.equal(m.budget, 200_000);
  assert.equal(m.budgetSource, "model_window");
  assert.equal(m.used, 50_000);
});

test("server: over_window with a nil ratio is unknown, never 100%", () => {
  const m = contextGaugeModel({
    gauge: { used_tokens: 300_000, budget_tokens: 200_000, budget_source: "model_window", ratio: null, over_window: true },
  });
  assert.equal(m.state, "over_window");
  assert.equal(m.ratio, null);
  assert.equal(m.budget, 0);
});

test("server: prefix without a ceiling is no_ceiling (unknown), never 0%", () => {
  const m = contextGaugeModel({ gauge: { used_tokens: 12_000, ratio: null } });
  assert.equal(m.state, "no_ceiling");
  assert.equal(m.ratio, null);
});

test("server: a ratio without a budget is not a measurement", () => {
  const m = contextGaugeModel({ gauge: { used_tokens: 12_000, ratio: 0.5 } });
  assert.equal(m.state, "no_ceiling");
  assert.equal(m.ratio, null);
});

test("server: gauge wins even when it reports nothing and the client has data", () => {
  const m = contextGaugeModel({ gauge: { used_tokens: 0 }, prefixTokens: 5_000, contextBudgetTokens: 10_000 });
  assert.equal(m.state, "no_prefix");
  assert.equal(m.source, "server");
});

test("client fallback (older daemon): prefix over reported budget", () => {
  const m = contextGaugeModel({ prefixTokens: 5_000, hasShape: true, contextBudgetTokens: 20_000 });
  assert.equal(m.source, "client");
  assert.equal(m.state, "measured");
  assert.equal(m.ratio, 0.25);
  assert.equal(m.budget, 20_000);
  assert.equal(m.budgetSource, "reported");
});

test("client fallback: no budget is no_ceiling; no prefix is no_prefix", () => {
  assert.equal(contextGaugeModel({ prefixTokens: 5_000 }).state, "no_ceiling");
  assert.equal(contextGaugeModel({ prefixTokens: 5_000 }).ratio, null);
  const none = contextGaugeModel({ hasShape: false });
  assert.equal(none.state, "no_prefix");
  assert.equal(none.observed, false);
});

test("client fallback: an overfull prefix clamps to the budget share of 1 (legacy behaviour)", () => {
  assert.equal(contextGaugeModel({ prefixTokens: 30_000, contextBudgetTokens: 20_000 }).ratio, 1);
});

test("knownRatio: non-finite / missing are unknown; finite clamps to 0..1", () => {
  assert.equal(knownRatio(undefined), null);
  assert.equal(knownRatio(null), null);
  assert.equal(knownRatio(Number.NaN), null);
  assert.equal(knownRatio(1.4), 1);
  assert.equal(knownRatio(-1), 0);
  assert.equal(knownRatio(0.42), 0.42);
});

test("budgetNoun names the ceiling's source", () => {
  assert.equal(budgetNoun("model_window"), "context window");
  assert.equal(budgetNoun("reported"), "budget");
  assert.equal(budgetNoun(""), "budget");
});
