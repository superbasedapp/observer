// Component tests of the predictor card's run-out projection
// (sessiondetail/LimitProjection.tsx over lib/limitProjection.ts): one test
// per UI state - a fresh reading, a stale reading whose window has reset,
// no reading, a budget in force, no budget - plus the token display mode.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import {
  BudgetProjectionSection,
  LimitProjectionList,
  ProjectionBlock,
} from "@/components/sessiondetail/LimitProjection";
import { projectionHeadline, pct, trendText, sourceLabel } from "@/lib/limitProjection";
import { setCostDisplayMode } from "@shared/lib/format";
import type { PredictProjection, Projection } from "@/lib/types";

const NOW = Date.UTC(2026, 10, 9, 12, 0, 0);
const S = NOW / 1000;
const H = 3600;

const usage = { tokens: 4_000_000, input: 400_000, cache_read: 3_200_000, cache_write: 200_000, output: 200_000, reasoning: 0, cost_usd: 40, turns: 60, sessions: 2 };

const liveWeekly: Projection = {
  kind: "limit",
  key: "weekly",
  state: "live",
  unit: "fraction",
  token_def: "all",
  source: "proxy",
  observed_at_unix: S - 60,
  reading_age_sec: 60,
  window_start_unix: S - 72 * H,
  resets_at_unix: S + 96 * H,
  length_sec: 168 * H,
  elapsed_frac: 72 / 168,
  seconds_to_reset: 96 * H,
  used_frac: 0.4,
  used_frac_est: 0.4,
  left_frac: 0.6,
  used: usage,
  capacity_tokens_est: 10_000_000,
  capacity_usd_est: 100,
  left_tokens: 6_000_000,
  left_usd: 60,
  left_tokens_is_estimate: true,
  left_usd_is_estimate: true,
  burn: { frac_per_hour: 0.4 / 72, frac_per_day: 0.4 / 3, tokens_per_hour: 55_555, tokens_per_day: 1_333_333, usd_per_hour: 0.55, usd_per_day: 13.33, basis_hours: 72 },
  pace: { elapsed_frac: 0.43, used_frac: 0.4, delta: -0.03, verdict: "on_pace" },
  run_out: { lasts_until_reset: true, projected_left_at_reset_frac: 0.067, safe_per_day_frac: 0.15, safe_per_day_tokens: 1_500_000, safe_per_day_usd: 15 },
  sessions: { count: 2, this_tokens: 1_000_000, this_usd: 10, this_share: 0.25, avg_tokens: 2_000_000, avg_usd: 20 },
  more_sessions_est: 3,
  more_prompts: { low: 30, mid: 60, high: 120, basis: "usd" },
  trend: { prev_start_unix: S - 240 * H, prev_end_unix: S - 72 * H, prev_tokens: 7_000_000, prev_usd: 70, prev_sessions: 3, rate_change: 0.33 },
  mix: { input: 0.1, cache_read: 0.8, cache_write: 0.05, output: 0.05, reasoning: 0 },
  top_models: [{ name: "claude-sonnet", tokens: 3_000_000, usd: 30, share: 0.75 }, { name: "claude-opus", tokens: 1_000_000, usd: 10, share: 0.25 }],
  top_projects: [{ name: "/src/app", tokens: 3_000_000, usd: 30, share: 0.75 }, { name: "/src/lib", tokens: 1_000_000, usd: 10, share: 0.25 }],
  five_hour_windows_left: 19,
  confidence: "high",
  notes: ["local_only"],
};

const EM_DASH = String.fromCharCode(0x2014);
const EN_DASH = String.fromCharCode(0x2013);

const noDashes = (html: string) => {
  assert.ok(!html.includes(EM_DASH), "no em dash in UI copy");
  assert.ok(!html.includes(EN_DASH), "no en dash in UI copy");
};

test("a fresh reading leads with lasts-until-reset and lists every stat behind All stats", () => {
  const html = renderToStaticMarkup(<ProjectionBlock p={liveWeekly} countedTools={["claude-code"]} allOpen nowMs={NOW} />);
  for (const want of [
    /Weekly limit/,
    /Lasts until reset, about 7% left/,
    /60%/, // left
    /All stats/,
    /Burn per day/,
    /Safe per day/,
    /Sessions in window/,
    /about 3/, // more sessions
    /about 60 \(30 to 120\)/, // prompts
    /19 before the weekly reset/,
    /33% faster than the previous window/,
    /cache reads 80%/,
    /claude-sonnet 75%/,
    /app 75%/,
    /proxy headers/,
    /high, from 60 turns over 72h/,
    /est\./,
    /claude-code sessions captured here/,
  ]) {
    assert.match(html, want);
  }
  noDashes(html);
});

test("a run-out before reset is a warning headline", () => {
  const p: Projection = { ...liveWeekly, run_out: { runs_out_at_unix: S + 48 * H, safe_per_day_frac: 0.1 }, pace: { elapsed_frac: 0.43, used_frac: 0.6, delta: 0.17, verdict: "ahead" } };
  const h = projectionHeadline(p, NOW);
  assert.equal(h.tone, "warn");
  assert.match(h.text, /^Weekly limit runs out .+ at this rate$/);
  const html = renderToStaticMarkup(<ProjectionBlock p={p} allOpen nowMs={NOW} />);
  assert.match(html, /17 pts faster than an even spread/);
});

test("a stale reading whose window has reset is not projected from", () => {
  // The operator's screenshot: the last reading is 22 days old.
  const p: Projection = {
    kind: "limit",
    key: "weekly",
    state: "reset_inferred",
    unit: "fraction",
    token_def: "all",
    source: "proxy",
    observed_at_unix: S - 22 * 24 * H,
    reading_age_sec: 22 * 24 * H,
    window_start_unix: S - 24 * H,
    resets_at_unix: S + 144 * H,
    window_inferred: true,
    elapsed_frac: 1 / 7,
    used: { ...usage, tokens: 1_200_000, cost_usd: 12 },
    burn: { frac_per_hour: 0, frac_per_day: 0, tokens_per_hour: 50_000, tokens_per_day: 1_200_000, usd_per_hour: 0.5, usd_per_day: 12, basis_hours: 24 },
    notes: ["reading_stale", "window_reset", "window_inferred"],
  };
  const html = renderToStaticMarkup(<ProjectionBlock p={p} allOpen nowMs={NOW} />);
  assert.match(html, /Last reading 22 days ago; that window has reset/);
  assert.match(html, /Route a session through the proxy to refresh it/);
  assert.match(html, /window inferred/);
  assert.match(html, /Used here/);
  assert.ok(!/runs out/.test(html), "no run-out from a reset reading");
  assert.ok(!/% left/.test(html), "no share left from a reset reading");
  noDashes(html);
});

test("a reset 5-hour reading shows only the reset sentence", () => {
  const p: Projection = { kind: "limit", key: "5h", state: "reset", unit: "fraction", token_def: "all", observed_at_unix: S - 3 * H, used_frac: 0.5, used: { ...usage, tokens: 0, cost_usd: 0, turns: 0, sessions: 0 }, notes: ["window_reset"] };
  const html = renderToStaticMarkup(<ProjectionBlock p={p} nowMs={NOW} />);
  assert.match(html, /that window has reset/);
  assert.ok(!html.includes("Used</span>"), "no stat grid");
});

test("under an hour of data says so instead of a rate", () => {
  const p: Projection = { ...liveWeekly, key: "5h", burn: undefined, run_out: undefined, pace: undefined, more_prompts: undefined, notes: ["not_enough_data"], confidence: "" };
  const h = projectionHeadline(p, NOW);
  assert.equal(h.text, "60% left; not enough data for a rate yet");
  const html = renderToStaticMarkup(<ProjectionBlock p={p} allOpen nowMs={NOW} />);
  assert.match(html, /Not yet/);
  assert.match(html, /Under an hour into the window/);
});

test("no reading renders nothing beyond the gauge", () => {
  assert.equal(renderToStaticMarkup(<LimitProjectionList projection={{ limits: [], budgets: [] }} />), "");
  assert.equal(renderToStaticMarkup(<LimitProjectionList />), "");
});

const tokenBudget: Projection = {
  kind: "budget",
  key: "monthly",
  state: "live",
  unit: "tokens",
  token_def: "input_output",
  origin: "org",
  scope: "team:core",
  enforcement: "hard",
  window_start_unix: S - 204 * H,
  resets_at_unix: S + 516 * H,
  elapsed_frac: 0.28,
  used_frac: 0.8,
  used_frac_est: 0.8,
  left_frac: 0.2,
  cap: 20_000,
  spent: 16_000,
  used: { ...usage, tokens: 12_000 },
  left_tokens: 4_000,
  left_usd: 0.8,
  left_usd_is_estimate: true,
  burn: { frac_per_hour: 0.8 / 204, frac_per_day: 0.094, tokens_per_hour: 59, tokens_per_day: 1_411, usd_per_hour: 0.01, usd_per_day: 0.2, basis_hours: 204 },
  pace: { elapsed_frac: 0.28, used_frac: 0.8, delta: 0.52, verdict: "ahead" },
  run_out: { runs_out_at_unix: S + 51 * H, safe_per_day_frac: 0.009 },
  notes: ["timezone_assumed_utc", "other_machines"],
};

test("a token-only budget reads in tokens and says who enforces it", () => {
  const proj: PredictProjection = { limits: [], budgets: [tokenBudget] };
  const html = renderToStaticMarkup(<BudgetProjectionSection projection={proj} allOpen nowMs={NOW} />);
  assert.match(html, /Budget/);
  assert.match(html, /Org monthly budget runs out/);
  assert.match(html, /16K tok/);
  assert.match(html, /about 4K tok/);
  assert.match(html, /team core/);
  assert.match(html, /blocks at 100%/);
  assert.match(html, /Spend includes your other machines/);
  noDashes(html);
});

test("no budget in force renders nothing, never under budget", () => {
  const html = renderToStaticMarkup(<BudgetProjectionSection projection={{ limits: [liveWeekly], budgets: [] }} />);
  assert.equal(html, "");
});

test("the token display mode shows tokens and no dollars", () => {
  setCostDisplayMode("tokens");
  try {
    const html = renderToStaticMarkup(<ProjectionBlock p={liveWeekly} allOpen nowMs={NOW} />);
    assert.ok(!html.includes("$"), "no dollar figure in the token display mode");
    assert.match(html, /6M tok/);
    noDashes(html);
  } finally {
    setCostDisplayMode("usd");
  }
});

test("wording helpers", () => {
  assert.equal(pct(0.004), "<1%");
  assert.equal(pct(undefined), "");
  assert.equal(sourceLabel("plans:claude.statusline"), "Plans & limits, status line");
  assert.equal(sourceLabel("transcript"), "session log");
  assert.equal(trendText({ ...liveWeekly, trend: { ...liveWeekly.trend!, prev_tokens: 0 } }), "new: nothing captured in the previous window");
  assert.equal(trendText({ ...liveWeekly, trend: { ...liveWeekly.trend!, rate_change: -0.02 } }), "about the same rate as the previous window");
});
