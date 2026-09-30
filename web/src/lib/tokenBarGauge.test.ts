// Pins the pure halves of the WS10 showcase pieces: the shared TokenBar model
// (unknown buckets get no segment and no row, a known zero is a row but no
// segment, all-unknown draws nothing), the GaugeStat threshold table (unknown
// is neutral and announced as unknown, never 0%) and the Live page heartbeat
// freshness table.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  TOKEN_BUCKETS,
  tokenBarModel,
  tokenShareText,
} from "../../../shared/primitives/tokenBarModel.ts";
import {
  GAUGE_BANDS,
  gaugeAriaLabel,
  gaugeTone,
  gaugeVariant,
  knownRatio,
} from "../../../shared/components/sessiondetail/gaugeStat.ts";
import {
  HEARTBEAT_BANDS,
  HEARTBEAT_DOT,
  freshnessState,
  liveDotProps,
} from "./liveSignals.ts";

test("TOKEN_BUCKETS: four buckets in the fixed order, each on a --tok-* colour", () => {
  assert.deepEqual(
    TOKEN_BUCKETS.map((b) => b.key),
    ["netInput", "cacheRead", "cacheWrite", "output"],
  );
  for (const b of TOKEN_BUCKETS) assert.match(b.color, /^var\(--tok-(net|read|write|out)\)$/);
});

test("tokenBarModel: shares, zero rows, unknown buckets", () => {
  const cases: {
    name: string;
    in: Parameters<typeof tokenBarModel>[0];
    known: string[];
    segments: string[];
    total: number;
  }[] = [
    { name: "all four", in: { netInput: 10, cacheRead: 60, cacheWrite: 10, output: 20 }, known: ["netInput", "cacheRead", "cacheWrite", "output"], segments: ["netInput", "cacheRead", "cacheWrite", "output"], total: 100 },
    { name: "known zero is a row, not a segment", in: { netInput: 5, cacheRead: 0, cacheWrite: 0, output: 5 }, known: ["netInput", "cacheRead", "cacheWrite", "output"], segments: ["netInput", "output"], total: 10 },
    { name: "null bucket is unknown", in: { netInput: 5, cacheRead: null, output: 5 }, known: ["netInput", "output"], segments: ["netInput", "output"], total: 10 },
    { name: "negative / NaN are unknown", in: { netInput: -1, cacheRead: Number.NaN, cacheWrite: 3 }, known: ["cacheWrite"], segments: ["cacheWrite"], total: 3 },
    { name: "zero total: rows, empty track", in: { netInput: 0, cacheRead: 0, cacheWrite: 0, output: 0 }, known: ["netInput", "cacheRead", "cacheWrite", "output"], segments: [], total: 0 },
    { name: "all unknown: nothing", in: {}, known: [], segments: [], total: 0 },
  ];
  for (const c of cases) {
    const m = tokenBarModel(c.in);
    assert.deepEqual(m.known.map((r) => r.key), c.known, c.name);
    assert.deepEqual(m.segments.map((r) => r.key), c.segments, c.name);
    assert.equal(m.total, c.total, c.name);
    for (const r of m.known) assert.ok(r.share >= 0 && r.share <= 1, c.name);
  }
  const m = tokenBarModel({ netInput: 10, cacheRead: 60, cacheWrite: 10, output: 20 });
  assert.equal(m.segments.find((r) => r.key === "cacheRead")?.share, 0.6);
});

test("tokenShareText: whole percent, a sliver is <1%, zero is 0%", () => {
  assert.equal(tokenShareText(0.6), "60%");
  assert.equal(tokenShareText(0.004), "<1%");
  assert.equal(tokenShareText(0), "0%");
  assert.equal(tokenShareText(Number.NaN), "0%");
});

test("gaugeTone: band table rows, unknown is neutral", () => {
  const cases: [number | null | undefined, string][] = [
    [0.95, "danger"],
    [0.9, "danger"],
    [0.89, "warn"],
    [0.7, "warn"],
    [0.5, "accent"],
    [0, "accent"],
    [1.4, "danger"], // clamped
    [null, "neutral"],
    [undefined, "neutral"],
    [Number.NaN, "neutral"],
  ];
  for (const [r, tone] of cases) assert.equal(gaugeTone(r), tone, String(r));
  assert.equal(GAUGE_BANDS[GAUGE_BANDS.length - 1].atLeast, Number.NEGATIVE_INFINITY);
});

test("gaugeVariant: worst known ring wins; all unknown keeps accent chrome", () => {
  assert.equal(gaugeVariant([0.2, 0.95]), "danger");
  assert.equal(gaugeVariant([0.75, null]), "warn");
  assert.equal(gaugeVariant([null, undefined]), "accent");
  assert.equal(gaugeVariant([]), "accent");
});

test("gaugeAriaLabel / knownRatio: unknown is announced as unknown, never 0%", () => {
  assert.equal(gaugeAriaLabel("5h window", 0.42), "5h window: 42% used");
  assert.equal(gaugeAriaLabel("5h window", null), "5h window: unknown");
  assert.equal(gaugeAriaLabel("5h window", Number.NaN), "5h window: unknown");
  assert.equal(knownRatio(-0.2), 0);
  assert.equal(knownRatio(undefined), null);
});

test("freshnessState + HEARTBEAT_DOT: the Live card heartbeat", () => {
  const now = Date.parse("2026-09-28T12:00:00Z");
  const at = (secAgo: number) => new Date(now - secAgo * 1000).toISOString();
  const cases: [string | null | undefined, string | null][] = [
    [at(5), "beating"],
    [at(60), "beating"],
    [at(61), "warm"],
    [at(300), "warm"],
    [at(301), "quiet"],
    [new Date(now + 30_000).toISOString(), "beating"], // clock skew reads as now
    ["not a time", null],
    ["", null],
    [null, null],
  ];
  for (const [iso, state] of cases) assert.equal(freshnessState(HEARTBEAT_BANDS, iso, now), state, String(iso));
  // Every state the bands can produce has a dot row with a label.
  for (const b of HEARTBEAT_BANDS) {
    assert.ok(HEARTBEAT_DOT[b.state], b.state);
    assert.ok(HEARTBEAT_DOT[b.state].label, b.state);
  }
  assert.deepEqual(liveDotProps(HEARTBEAT_DOT, "beating"), { tone: "success", label: "Active in the last minute" });
  assert.deepEqual(liveDotProps(HEARTBEAT_DOT, "warm").still, true);
  assert.deepEqual(liveDotProps(HEARTBEAT_DOT, null), { tone: "idle" });
});
