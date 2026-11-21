// Pins shared/lib/processLayout.ts, the pure model behind the session-detail
// "Call stack" view: placing processes on the time axis, the honest end kinds
// (running / exit not seen), the spawn chain, keyboard moves, failed-chain
// filtering, sibling folding, lane packing and the "Skip quiet" time scale.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  FOLD_MIN_GROUP,
  STACK_KEYS,
  barTier,
  brushDomain,
  buildTimeScale,
  centreAt,
  chartKeyAction,
  clampDomain,
  clipSpan,
  defaultWindowSpan,
  fmtSpan,
  fmtZoom,
  initialDomain,
  isWholeSession,
  minSpanFor,
  panBy,
  resizeEdge,
  wheelIntent,
  zoomAround,
  zoomLevel,
  buildUnits,
  captureGaps,
  chainOf,
  defaultWindow,
  failedChainKeys,
  fmtOffset,
  indexProcesses,
  isAgentProcess,
  isFailedProcess,
  linearTicks,
  moveSelection,
  overviewBuckets,
  packLanes,
  peakConcurrency,
  parentNotCaptured,
  siblingSignature,
  stackText,
  stepInList,
  turnMarkers,
  zoomWindow,
  type ChartKeyAction,
  type StackUnit,
  type WheelLike,
} from "../../../shared/lib/processLayout.ts";
import type { ProcessNodeLike } from "../../../shared/lib/types.ts";

const T0 = Date.parse("2026-10-15T14:02:11Z");
const iso = (sec: number) => new Date(T0 + sec * 1000).toISOString();

function P(key: string, sec: number, durSec: number | null, extra: Partial<ProcessNodeLike> = {}, children: ProcessNodeLike[] = []): ProcessNodeLike {
  return {
    process_key: key,
    pid: 1000 + key.length,
    ppid: 1,
    exe: key,
    attribution_source: "inherited",
    attribution_confidence: "high",
    exited: durSec != null,
    exit_code: 0,
    duration_ms: durSec == null ? 0 : durSec * 1000,
    started_at: iso(sec),
    children,
    ...extra,
  };
}

// claude (running) > bash "npm test" (exit 1) > npm > node (exit 1) > 3 workers
function sample(): ProcessNodeLike[] {
  return [
    P("claude", 0, null, { attribution_source: "bridge", ppid: 0, last_seen_at: iso(1080) }, [
      P("bash1", 60, 0.2, { turn_index: 2, message_id: "msg_a" }, [P("git", 60.05, 0.15)]),
      P("bash2", 200, 48, { exit_code: 1, turn_index: 6, message_id: "msg_b" }, [
        P("npm", 200.2, 47, { exit_code: 1 }, [
          P("vitest", 200.5, 46, { exit_code: 1 }, [
            P("w1", 202, 30, { argv_preview: "node forks.js 1" }),
            P("w2", 202.1, 44, { argv_preview: "node forks.js 2" }),
            P("w3", 202.2, 38, { argv_preview: "node forks.js 3" }),
          ]),
        ]),
      ]),
      P("rg", 140, 0.05, { pid: 0, attribution_source: "action_correlation", turn_index: 4 }),
      P("dev", 700, null, { last_seen_at: iso(1080), turn_index: 12 }),
    ]),
  ];
}
const NOW = T0 + 1080 * 1000;

test("indexProcesses places start, end and end kind", () => {
  const idx = indexProcesses(sample(), NOW);
  const cases: Array<[string, number, number, string]> = [
    ["claude", 0, 1080, "running"],
    ["bash2", 200, 248, "exited"],
    ["w2", 202.1, 246.1, "exited"],
    ["rg", 140, 140.05, "exited"],
    ["dev", 700, 1080, "running"],
  ];
  for (const [key, s, e, kind] of cases) {
    const it = idx.byKey.get(key)!;
    assert.equal(it.start, T0 + s * 1000, `${key} start`);
    assert.equal(Math.round(it.end), Math.round(T0 + e * 1000), `${key} end`);
    assert.equal(it.endKind, kind, `${key} end kind`);
  }
  assert.equal(idx.byKey.get("w3")!.depth, 4);
  assert.equal(idx.minStart, T0);
  assert.equal(idx.byKey.get("rg")!.derived, true);
});

test("a never-exited process unseen past the stale window is 'exit not seen'", () => {
  const roots = [P("old", 0, null, { last_seen_at: iso(30) })];
  const later = T0 + 30_000 + 6 * 60_000;
  const it = indexProcesses(roots, later).byKey.get("old")!;
  assert.equal(it.endKind, "unseen");
  assert.equal(it.end, T0 + 30_000);
  // Seen recently: still running to now.
  const fresh = indexProcesses(roots, T0 + 60_000).byKey.get("old")!;
  assert.equal(fresh.endKind, "running");
  assert.equal(fresh.end, T0 + 60_000);
});

test("a row with no start time takes its parent's start", () => {
  const roots = [P("a", 10, 5, {}, [P("b", 0, 1, { started_at: undefined })])];
  const b = indexProcesses(roots, NOW).byKey.get("b")!;
  assert.equal(b.timeKnown, false);
  assert.equal(b.start, T0 + 10_000);
});

test("isFailedProcess", () => {
  const rows: Array<[Partial<ProcessNodeLike>, boolean]> = [
    [{ exited: true, exit_code: 0 }, false],
    [{ exited: true, exit_code: 2 }, true],
    [{ exited: true, exit_code: 0, exit_signal: 9 }, true],
    [{ exited: false, exit_code: 1 }, false],
    [{ pid: 0, attribution_source: "action_correlation", exit_code: 1, exited: false }, true],
    [{ pid: 0, attribution_source: "action_correlation", exit_code: 0 }, false],
  ];
  for (const [over, want] of rows) assert.equal(isFailedProcess(P("x", 0, 1, over)), want, JSON.stringify(over));
});

test("chainOf runs innermost first up to the root", () => {
  const idx = indexProcesses(sample(), NOW);
  assert.deepEqual(chainOf(idx, "w3").map((i) => i.key), ["w3", "vitest", "npm", "bash2", "claude"]);
  assert.deepEqual(chainOf(idx, null), []);
  assert.deepEqual(chainOf(idx, "nope"), []);
});

test("moveSelection follows the keyboard table", () => {
  const idx = indexProcesses(sample(), NOW);
  assert.equal(STACK_KEYS.ArrowUp, "parent");
  const cases: Array<[string | null, string, string | null]> = [
    ["w2", "parent", "vitest"],
    ["vitest", "firstChild", "w1"],
    ["w2", "prevSibling", "w1"],
    ["w2", "nextSibling", "w3"],
    ["w3", "nextSibling", "w3"], // nowhere to go: stay
    ["claude", "parent", "claude"],
    [null, "firstChild", "claude"],
    ["bash1", "nextSibling", "rg"], // siblings ordered by start time
  ];
  for (const [from, move, want] of cases) {
    assert.equal(moveSelection(idx, from, move as never), want, `${from} ${move}`);
  }
  // Restricted to a visible set, moves skip hidden siblings.
  const vis = new Set(["claude", "bash2", "dev"]);
  assert.equal(moveSelection(idx, "bash2", "nextSibling", vis), "dev");
});

test("stepInList", () => {
  const keys = ["a", "b", "c"];
  const cases: Array<[string | null, number, string | null]> = [
    ["b", 1, "c"],
    ["c", 1, "c"],
    ["a", -1, "a"],
    [null, 1, "a"],
    [null, -1, "c"],
    ["zz", 1, "a"],
  ];
  for (const [k, d, want] of cases) assert.equal(stepInList(keys, k, d), want);
  assert.equal(stepInList([], "a", 1), "a");
});

test("failedChainKeys keeps failures, their ancestors and their subtrees", () => {
  const idx = indexProcesses(sample(), NOW);
  const keep = failedChainKeys(idx);
  for (const k of ["claude", "bash2", "npm", "vitest", "w1", "w2", "w3"]) assert.ok(keep.has(k), k);
  for (const k of ["bash1", "git", "rg", "dev"]) assert.ok(!keep.has(k), k);
});

function bigSession(workers: number): ProcessNodeLike[] {
  const ws = Array.from({ length: workers }, (_, i) =>
    P(`w${i}`, 10 + i * 0.01, 5, { exe: "node", argv_preview: `node forks.js ${i}` }, i === 0 ? [P("esb", 11, 1)] : []),
  );
  return [P("root", 0, null, {}, [P("vitest", 9, 20, { exe: "node", argv_preview: "node vitest run" }, ws)])];
}

test("buildUnits folds big identical sibling groups, but never the selection's", () => {
  const n = FOLD_MIN_GROUP + 4;
  const idx = indexProcesses(bigSession(n), T0 + 60_000);
  const units = buildUnits(idx, { fold: true });
  const groups = units.filter((u): u is Extract<StackUnit, { kind: "group" }> => u.kind === "group");
  assert.equal(groups.length, 1);
  assert.equal(groups[0].members.length, n);
  assert.equal(groups[0].hiddenBelow, 1); // the esbuild under worker 0
  assert.ok(!units.some((u) => u.key === "esb"));
  // Selecting a member (or something under one) keeps its group open.
  const open = buildUnits(idx, { fold: true, selectedKey: "esb" });
  assert.ok(open.every((u) => u.kind === "process"));
  // An expanded group stays open; a small session never folds by default.
  const expanded = buildUnits(idx, { fold: true, expanded: new Set([groups[0].key]) });
  assert.ok(expanded.every((u) => u.kind === "process"));
  assert.ok(buildUnits(idx).every((u) => u.kind === "process"));
  assert.equal(siblingSignature(idx.byKey.get("w1")!.node), siblingSignature(idx.byKey.get("w9")!.node));
});

test("packLanes stacks overlapping siblings into extra lanes", () => {
  const idx = indexProcesses(sample(), NOW);
  const units = buildUnits(idx);
  const lay = packLanes(units);
  const depth4 = lay.bands.find((b) => b.depth === 4)!;
  assert.equal(depth4.lanes, 3); // three concurrent workers
  const rows = new Set(["w1", "w2", "w3"].map((k) => lay.row.get(k)));
  assert.equal(rows.size, 3);
  // Depth 1: bash1 / rg / bash2 run one after another, dev runs after them too.
  assert.equal(lay.bands.find((b) => b.depth === 1)!.lanes, 1);
  assert.equal(lay.rows, lay.bands.reduce((a, b) => a + b.lanes, 0));
});

test("buildTimeScale linear and Skip quiet", () => {
  const idx = indexProcesses(sample(), NOW);
  const dom: [number, number] = [idx.minStart, idx.maxEnd];
  const lin = buildTimeScale(idx.items, dom, { collapse: false });
  assert.equal(lin.x(dom[0]), 0);
  assert.equal(lin.x(dom[1]), 1);
  assert.equal(lin.x(T0 + 540_000), 0.5);

  const q = buildTimeScale(idx.items, dom, { collapse: true, sessionSpanMs: dom[1] - dom[0] });
  assert.ok(q.collapsed);
  assert.ok(q.gaps.length >= 2, "quiet stretches between commands are squeezed");
  // Nothing short-lived alive during a gap.
  for (const g of q.gaps) {
    const mid = (g.a + g.b) / 2;
    const busy = idx.items.some((it) => it.end - it.start < 270_000 && it.start <= mid && it.end >= mid);
    assert.ok(!busy, "gap overlaps a short-lived process");
  }
  // Monotonic and spans 0..1.
  let prev = -1;
  for (let t = dom[0]; t <= dom[1]; t += 7_000) {
    const v = q.x(t);
    assert.ok(v >= prev - 1e-9);
    prev = v;
  }
  assert.equal(q.x(dom[0]), 0);
  assert.equal(Math.round(q.x(dom[1]) * 1e6), 1e6);
  // The test run takes far more of the width than on the linear scale.
  const w = (s: ReturnType<typeof buildTimeScale>) => s.x(T0 + 248_000) - s.x(T0 + 200_000);
  assert.ok(w(q) > 3 * w(lin));
  // Inside an active stretch time stays proportional.
  const a = q.x(T0 + 210_000) - q.x(T0 + 205_000);
  const b = q.x(T0 + 220_000) - q.x(T0 + 210_000);
  assert.ok(Math.abs(b - 2 * a) < 1e-9);
});

test("linearTicks and fmtOffset", () => {
  const ticks = linearTicks([0, 600_000], 6);
  assert.equal(ticks[1] - ticks[0], 120_000);
  const cases: Array<[number, string]> = [
    [0, "+0:00"],
    [42_000, "+0:42"],
    [725_000, "+12:05"],
    [3_900_000, "+1h05m"],
  ];
  for (const [ms, want] of cases) assert.equal(fmtOffset(ms), want);
});

test("turnMarkers: first process per turn, carrying its message id", () => {
  const idx = indexProcesses(sample(), NOW);
  const m = turnMarkers(idx);
  assert.deepEqual(
    m.map((t) => [t.turn, (t.at - T0) / 1000, t.messageId ?? null]),
    [
      [2, 60, "msg_a"],
      [4, 140, null],
      [6, 200, "msg_b"],
      [12, 700, null],
    ],
  );
});

test("overviewBuckets, defaultWindow and zoomWindow", () => {
  const idx = indexProcesses(sample(), NOW);
  const ob = overviewBuckets(idx, 10);
  assert.equal(ob.counts.reduce((a, b) => a + b, 0), idx.items.length);
  assert.equal(ob.failures.reduce((a, b) => a + b, 0), 3);
  const w = defaultWindow(idx, null, 120_000);
  const lastStart = Math.max(...idx.items.map((it) => it.start));
  const end = Math.min(idx.maxEnd, Math.max(idx.minStart + 120_000, lastStart + 12_000));
  assert.deepEqual(w, [end - 120_000, end]);
  assert.ok(w[0] <= lastStart && lastStart <= w[1], "the most recent start is in the window");
  // The running "dev" server and the agent stretch the session to NOW; the
  // window must not open on that tail where nothing new started.
  assert.ok(w[1] < idx.maxEnd, "the window does not open on the quiet running tail");
  const ws = defaultWindow(idx, "w2", 120_000);
  assert.ok(ws[0] <= T0 + 200_000 && ws[1] >= T0 + 248_000);
  const z = zoomWindow(idx, "w2")!;
  assert.ok(z[0] < T0 + 200_000 && z[1] > T0 + 248_000 && z[1] - z[0] < 60_000);
  assert.equal(zoomWindow(idx, null), null);
});

test("captureGaps, parentNotCaptured and isAgentProcess", () => {
  const roots = [
    P("agent", 0, null, { attribution_source: "bridge", ppid: 1 }),
    P("orphan", 5, 1, { ppid: 4410 }), // inherited, but its parent is not in the rows
    P("relay", 5, 1, { is_boundary: true, ppid: 1 }),
    P("old", 6, null, { last_seen_at: iso(7), attribution_source: "env_token" }),
    P("rg", 7, 0.1, { pid: 0, attribution_source: "action_correlation" }),
  ];
  const idx = indexProcesses(roots, T0 + 3_600_000);
  assert.deepEqual(captureGaps(idx), { exitNotSeen: 1, toolLogOnly: 1, parentNotCaptured: 1 });
  const cases: Array<[string, boolean]> = [
    ["orphan", true],
    ["agent", false],
    ["relay", false],
    ["rg", false],
  ];
  for (const [k, want] of cases) assert.equal(parentNotCaptured(idx, idx.byKey.get(k)!), want, k);
  // A nested inherited process has its parent: not an orphan.
  const nested = indexProcesses(sample(), NOW);
  assert.equal(captureGaps(nested).parentNotCaptured, 0);
  assert.equal(isAgentProcess(idx.byKey.get("agent")!.node), true);
  assert.equal(isAgentProcess(idx.byKey.get("orphan")!.node), false);
});

test("stackText", () => {
  const idx = indexProcesses(sample(), NOW);
  const text = stackText(chainOf(idx, "w2"), "session abc");
  const lines = text.split("\n");
  assert.equal(lines.length, 6);
  assert.match(lines[0], /^#0 w2 pid \d+ exit 0  node forks.js 2$/);
  assert.match(lines[3], /^#3 bash2 pid \d+ exit 1$/);
  assert.match(lines[4], /^#4 claude pid \d+ running$/);
  assert.equal(lines[5], "#5 session abc");
});

test("a command repeated one after another never folds; a fan-out does", () => {
  const seq = Array.from({ length: 20 }, (_, i) =>
    P(`b${i}`, 10 + i * 30, 2, { exe: "bash", argv_preview: `bash -c "git diff ${i}"` }),
  );
  const idx = indexProcesses([P("root", 0, null, {}, seq)], T0 + 900_000);
  assert.ok(buildUnits(idx, { fold: true }).every((u) => u.kind === "process"));
  const cases: Array<[Array<[number, number]>, number]> = [
    [[[0, 10], [10, 20], [20, 30]], 1], // back to back: ends are exclusive
    [[[0, 10], [5, 15], [6, 7]], 3],
    [[], 0],
  ];
  for (const [spans, want] of cases) {
    assert.equal(peakConcurrency(spans.map(([start, end]) => ({ start, end }))), want);
  }
});

// ---------------------------------------------------------------------------
// Zoom and pan: the visible domain helpers.
// ---------------------------------------------------------------------------

const B: [number, number] = [0, 100_000]; // a 100 s session

test("clampDomain keeps the window inside the session and at least the minimum span", () => {
  const cases: Array<[string, [number, number], number, [number, number]]> = [
    ["inside stays", [10_000, 20_000], 250, [10_000, 20_000]],
    ["before the start shifts right", [-5_000, 5_000], 250, [0, 10_000]],
    ["after the end shifts left", [95_000, 105_000], 250, [90_000, 100_000]],
    ["wider than the session is the session", [-1, 200_000], 250, [0, 100_000]],
    ["narrower than the minimum grows around its centre", [50_000, 50_100], 1_000, [49_550, 50_550]],
    ["a too-narrow window at the edge grows inward", [0, 10], 1_000, [0, 1_000]],
    ["ends in either order", [20_000, 10_000], 250, [10_000, 20_000]],
  ];
  for (const [name, d, min, want] of cases) assert.deepEqual(clampDomain(d, B, min), want, name);
});

test("zoomAround keeps the anchor in place and respects the limits", () => {
  const cases: Array<[string, [number, number], number, number, [number, number]]> = [
    ["zoom in 2x around the centre", [0, 100_000], 50_000, 2, [25_000, 75_000]],
    ["zoom in 2x around the left edge", [0, 100_000], 0, 2, [0, 50_000]],
    ["zoom in 4x around 80%", [0, 100_000], 80_000, 4, [60_000, 85_000]],
    ["zoom out past the session fits it", [40_000, 60_000], 50_000, 0.01, [0, 100_000]],
    ["zoom out near an edge shifts inside", [0, 20_000], 5_000, 0.5, [0, 40_000]],
    ["never narrower than the minimum", [49_000, 51_000], 50_000, 1_000, [49_875, 50_125]],
    ["a bad factor is no change", [10_000, 30_000], 20_000, Number.NaN, [10_000, 30_000]],
  ];
  for (const [name, d, anchor, f, want] of cases) assert.deepEqual(zoomAround(d, anchor, f, B, 250), want, name);
  // The anchor's fraction is unchanged by an unclamped zoom.
  const z = zoomAround([20_000, 60_000], 30_000, 3, B, 250);
  assert.ok(Math.abs((30_000 - z[0]) / (z[1] - z[0]) - 0.25) < 1e-9);
});

test("panBy, centreAt and brushDomain", () => {
  const pans: Array<[string, [number, number], number, [number, number]]> = [
    ["later", [10_000, 20_000], 5_000, [15_000, 25_000]],
    ["earlier", [10_000, 20_000], -5_000, [5_000, 15_000]],
    ["stops at the start", [10_000, 20_000], -50_000, [0, 10_000]],
    ["stops at the end", [80_000, 90_000], 50_000, [90_000, 100_000]],
    ["the whole session cannot move", [0, 100_000], 10_000, [0, 100_000]],
  ];
  for (const [name, d, delta, want] of pans) assert.deepEqual(panBy(d, delta, B), want, name);
  assert.deepEqual(centreAt([0, 10_000], 50_000, B), [45_000, 55_000]);
  assert.deepEqual(centreAt([0, 10_000], 99_000, B), [90_000, 100_000]);
  const brushes: Array<[number, number, [number, number]]> = [
    [10_000, 30_000, [10_000, 30_000]],
    [30_000, 10_000, [10_000, 30_000]],
    [-5_000, 5_000, [0, 5_000]],
    [40_000, 40_010, [39_880, 40_130]], // grown to the 250 ms minimum
  ];
  for (const [a, b, want] of brushes) assert.deepEqual(brushDomain(a, b, B, 250), want, `${a}..${b}`);
});

test("resizeEdge moves one handle and stops at the minimum and the session", () => {
  const cases: Array<[string, "start" | "end", number, [number, number]]> = [
    ["start earlier", "start", 5_000, [5_000, 30_000]],
    ["start past the end stops short", "start", 40_000, [29_000, 30_000]],
    ["start before the session", "start", -10_000, [0, 30_000]],
    ["end later", "end", 60_000, [10_000, 60_000]],
    ["end before the start stops short", "end", 0, [10_000, 11_000]],
    ["end after the session", "end", 500_000, [10_000, 100_000]],
  ];
  for (const [name, edge, t, want] of cases) {
    assert.deepEqual(resizeEdge([10_000, 30_000], edge, t, B, 1_000), want, name);
  }
});

test("minSpanFor, zoomLevel, isWholeSession, fmtZoom and fmtSpan", () => {
  assert.equal(minSpanFor([0, 100_000]), 250);
  assert.equal(minSpanFor([0, 4_140_000]), 414);
  assert.equal(minSpanFor([0, 100]), 100);
  assert.equal(zoomLevel([0, 100_000], B), 1);
  assert.equal(zoomLevel([0, 25_000], B), 4);
  assert.equal(isWholeSession([0, 100_000], B), true);
  assert.equal(isWholeSession([0, 99_000], B), false);
  const zooms: Array<[number, string]> = [
    [1, "1×"],
    [1.04, "1×"],
    [6.24, "6.2×"],
    [9.96, "10×"],
    [42.4, "42×"],
  ];
  for (const [z, want] of zooms) assert.equal(fmtZoom(z), want, String(z));
  const spans: Array<[number, string]> = [
    [850, "850ms"],
    [4_200, "4.2s"],
    [42_000, "42s"],
    [348_000, "5m48s"],
    [300_000, "5m"],
    [660_000, "11m"],
    [4_140_000, "1h09m"],
  ];
  for (const [ms, want] of spans) assert.equal(fmtSpan(ms), want, String(ms));
});

test("wheelIntent: Ctrl zooms, Shift and sideways pan, a plain scroll is the page's", () => {
  const w = (over: Partial<WheelLike>): WheelLike => ({
    deltaX: 0,
    deltaY: 0,
    deltaMode: 0,
    ctrlKey: false,
    metaKey: false,
    shiftKey: false,
    ...over,
  });
  const cases: Array<[string, WheelLike, "zoomIn" | "zoomOut" | number | null]> = [
    ["plain vertical scroll", w({ deltaY: 100 }), null],
    ["plain vertical with a little sideways", w({ deltaY: 100, deltaX: 10 }), null],
    ["nothing at all", w({}), null],
    ["ctrl wheel up zooms in", w({ deltaY: -100, ctrlKey: true }), "zoomIn"],
    ["ctrl wheel down zooms out", w({ deltaY: 100, ctrlKey: true }), "zoomOut"],
    ["cmd wheel zooms", w({ deltaY: -100, metaKey: true }), "zoomIn"],
    ["pinch (ctrl, small delta) zooms", w({ deltaY: -3, ctrlKey: true }), "zoomIn"],
    ["shift wheel pans by the vertical delta", w({ deltaY: 40, shiftKey: true }), 40],
    ["shift wheel on a sideways mouse", w({ deltaX: -30, shiftKey: true }), -30],
    ["sideways wheel pans", w({ deltaX: 25, deltaY: 3 }), 25],
    ["line mode is scaled to pixels", w({ deltaX: 2, deltaMode: 1 }), 32],
  ];
  for (const [name, e, want] of cases) {
    const got = wheelIntent(e);
    if (want === null) assert.equal(got, null, name);
    else if (typeof want === "number") assert.deepEqual(got, { kind: "pan", px: want }, name);
    else {
      assert.equal(got?.kind, "zoom", name);
      const f = (got as { factor: number }).factor;
      assert.ok(want === "zoomIn" ? f > 1 : f < 1, `${name}: factor ${f}`);
    }
  }
  // One mouse notch is a moderate step, and a huge delta is capped.
  const notch = (wheelIntent(w({ deltaY: -100, ctrlKey: true })) as { factor: number }).factor;
  assert.ok(notch > 1.3 && notch < 1.7);
  const huge = (wheelIntent(w({ deltaY: -5_000, ctrlKey: true })) as { factor: number }).factor;
  assert.ok(huge < 2.5);
});

test("chartKeyAction maps zoom keys and Shift+arrows, leaves the rest", () => {
  const cases: Array<[string, Parameters<typeof chartKeyAction>[1], ChartKeyAction | null]> = [
    ["+", {}, "zoomIn"],
    ["=", {}, "zoomIn"],
    ["+", { shiftKey: true }, "zoomIn"], // + is Shift and = on most layouts
    ["-", {}, "zoomOut"],
    ["0", {}, "fit"],
    ["ArrowLeft", { shiftKey: true }, "panLeft"],
    ["ArrowRight", { shiftKey: true }, "panRight"],
    ["ArrowLeft", {}, null], // a plain arrow moves the selection
    ["ArrowUp", { shiftKey: true }, null],
    ["=", { ctrlKey: true }, null], // the browser keeps its own page zoom
    ["0", { metaKey: true }, null],
    ["a", {}, null],
  ];
  for (const [key, mods, want] of cases) {
    assert.equal(chartKeyAction(key, mods), want, `${key} ${JSON.stringify(mods)}`);
  }
});

test("initialDomain: a window for a large session, the whole span otherwise", () => {
  const small = indexProcesses(sample(), NOW);
  assert.deepEqual(initialDomain(small, null, 1200), [small.minStart, small.maxEnd]);
  const kids = Array.from({ length: 160 }, (_, i) => P(`c${i}`, i * 25, 2));
  const big = indexProcesses([P("root", 0, 4_000, {}, kids)], T0 + 4_000_000);
  const d = initialDomain(big, null, 1600);
  // A twelfth of the session (at least five minutes), the most recent stretch.
  assert.equal(d[1], big.maxEnd);
  assert.ok(Math.abs(d[1] - d[0] - (big.maxEnd - big.minStart) / 12) < 1);
  // Narrower on a phone.
  const p = initialDomain(big, null, 375);
  assert.ok(p[1] - p[0] < d[1] - d[0]);
  const cases: Array<[number, number, number]> = [
    [4_140_000, 1600, 345_000],
    [4_140_000, 500, 172_500],
    [4_140_000, 100, 103_500],
    [60_000, 1600, 60_000],
  ];
  for (const [span, px, want] of cases) assert.equal(defaultWindowSpan(span, px), want, `${span}@${px}`);
});

test("barTier and clipSpan", () => {
  const tiers: Array<[number, string]> = [
    [1, "tick"],
    [3.9, "tick"],
    [4, "bare"],
    [20, "bare"],
    [35.9, "bare"],
    [36, "label"],
    [400, "label"],
  ];
  for (const [px, want] of tiers) assert.equal(barTier(px), want, String(px));
  type Clip = { a: number; b: number; cutStart: boolean; cutEnd: boolean };
  const clips: Array<[number, number, [number, number], Clip]> = [
    [10, 20, [0, 100], { a: 10, b: 20, cutStart: false, cutEnd: false }],
    [-50, 20, [0, 100], { a: 0, b: 20, cutStart: true, cutEnd: false }],
    [50, 200, [0, 100], { a: 50, b: 100, cutStart: false, cutEnd: true }],
    [-5, 500, [0, 100], { a: 0, b: 100, cutStart: true, cutEnd: true }],
  ];
  for (const [s, e, d, want] of clips) assert.deepEqual(clipSpan(s, e, d), want, `${s}..${e}`);
});

test("buildTimeScale invert undoes x on both scales", () => {
  const idx = indexProcesses(sample(), NOW);
  const dom: [number, number] = [idx.minStart, idx.maxEnd];
  for (const collapse of [false, true]) {
    const s = buildTimeScale(idx.items, dom, { collapse, sessionSpanMs: dom[1] - dom[0] });
    assert.equal(s.invert(0), dom[0]);
    assert.equal(Math.round(s.invert(1)), dom[1]);
    for (const t of [T0 + 60_000, T0 + 210_000, T0 + 230_500, T0 + 700_000]) {
      // Outside squeezed gaps the round trip is exact.
      if (s.gaps.some((g) => t > g.a && t < g.b)) continue;
      assert.ok(Math.abs(s.invert(s.x(t)) - t) < 1, `collapse=${collapse} t=${t - T0}`);
    }
    assert.equal(s.invert(-1), dom[0]);
  }
});
