// Tests of the process capture limits model (processCapture.ts): the key
// table against the Settings spec, the draft -> estimate query, the data
// volume estimate model, the capture line words, the rolled-up grouping and
// the tree window merge.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  CAPTURE_CONFIG_KEYS,
  CAPTURE_FIELDS,
  budgetHit,
  captureDraft,
  captureDraftQuery,
  captureKeyLabel,
  captureLine,
  captureLineParts,
  countNodes,
  deltaPill,
  estimateModel,
  mergeWindows,
  oldestStartedAt,
  parseEstimate,
  parseSummary,
  rollupPage,
  rollupTotals,
  servicesRunning,
  sortRollups,
  summaryOutcome,
  windowNote,
} from "./processCapture.ts";
import { SECTION_SPECS } from "../pages/settings/sectionSpecs.ts";
import type { ProcessNode, ProcessSummaryResponse, ProcessSummaryRollup } from "./types.ts";

const PLAN_KEYS = [
  "enabled",
  "budget.per_tool_call",
  "budget.per_session",
  "budget.per_minute",
  "services.track",
  "services.detach_after_minutes",
  "services.exemplars_per_service",
  "services.tail_minutes",
  "services.extra_basenames",
  "fold.enabled",
  "fold.extra_basenames",
  "metrics.ring_min_lifetime_seconds",
  "rollups.bucket_seconds",
  "unattributed.pending_hours",
  "unattributed.mode",
];

test("the key table is exactly plan 9.1 and prefixes to full TOML paths", () => {
  assert.deepEqual(CAPTURE_FIELDS.map((f) => f.key), PLAN_KEYS);
  assert.equal(CAPTURE_CONFIG_KEYS[1], "observer.process.capture.budget.per_tool_call");
  assert.equal(new Set(CAPTURE_FIELDS.map((f) => f.path.join("."))).size, PLAN_KEYS.length);
});

test("every Settings capture field is in the key table and every key has a Settings field", () => {
  const groups = SECTION_SPECS.process.groups ?? [];
  const spec = new Set<string>();
  for (const g of groups) {
    // Capture groups live under Observer.Process.Capture[.Sub].
    if (g.path.length < 3 || g.path[2] !== "Capture") continue;
    assert.equal(g.hideWhenAbsent, true, `${g.id} hides on a daemon without the keys`);
    for (const f of g.fields) spec.add([...g.path.slice(3), f.id].join("."));
  }
  const table = new Set(CAPTURE_FIELDS.map((f) => f.path.join(".")));
  assert.deepEqual([...spec].sort(), [...table].sort());
  // The field kinds agree.
  for (const g of groups.filter((x) => x.path[2] === "Capture")) {
    for (const f of g.fields) {
      const def = CAPTURE_FIELDS.find((d) => d.path.join(".") === [...g.path.slice(3), f.id].join("."));
      assert.equal(f.kind, def?.kind, `${g.id}.${f.id}`);
    }
  }
});

const DRAFT = {
  Enabled: true,
  Capture: {
    Enabled: true,
    Budget: { PerToolCall: 150, PerSession: 5000, PerMinute: 300 },
    Services: { Track: false, DetachAfterMinutes: 10, ExemplarsPerService: 20, TailMinutes: 30, ExtraBasenames: ["my-dev", "other"] },
    Fold: { Enabled: true, ExtraBasenames: [] },
    Metrics: { RingMinLifetimeSeconds: 30 },
    Rollups: { BucketSeconds: 60 },
    Unattributed: { PendingHours: 24, Mode: "drop" },
  },
};

test("captureDraftQuery sends the dotted keys, lists comma-joined, an emptied list empty", () => {
  const q = new URLSearchParams(captureDraftQuery(DRAFT) ?? "");
  assert.equal(q.get("enabled"), "true");
  assert.equal(q.get("budget.per_tool_call"), "150");
  assert.equal(q.get("services.track"), "false");
  assert.equal(q.get("services.extra_basenames"), "my-dev,other");
  assert.equal(q.get("fold.extra_basenames"), "", "an emptied list is sent so it overrides a saved one");
  assert.equal(q.has("fold.extra_basenames"), true);
  assert.equal(q.get("unattributed.mode"), "drop");
  assert.equal(q.get("metrics.ring_min_lifetime_seconds"), "30");
});

test("captureDraftQuery is null without capture config (older daemon)", () => {
  assert.equal(captureDraftQuery({ Enabled: true }), null);
  assert.equal(captureDraftQuery(null), null);
  assert.equal(captureDraft({ Capture: "x" }), null);
});

test("captureKeyLabel names a key, bare or prefixed, and falls back to the key", () => {
  assert.equal(captureKeyLabel("budget.per_session"), "Runs kept per session");
  assert.equal(captureKeyLabel("observer.process.capture.fold.enabled"), "Fold routine helpers");
  assert.equal(captureKeyLabel("something.new"), "something.new");
});

test("deltaPill: green when it falls, amber when it rises, neutral when flat", () => {
  assert.deepEqual(deltaPill(1000, 250), { tone: "success", text: "-75%" });
  assert.deepEqual(deltaPill(1000, 1500), { tone: "warn", text: "+50%" });
  assert.deepEqual(deltaPill(1000, 1000), { tone: "neutral", text: "no change" });
  assert.deepEqual(deltaPill(0, 10), { tone: "warn", text: "new" });
  assert.deepEqual(deltaPill(0, 0), { tone: "neutral", text: "no change" });
  assert.deepEqual(deltaPill(10000, 10001), { tone: "neutral", text: "no change" }, "a 0.01% move is not a change");
  assert.equal(deltaPill(1000, 995).text, "-0.5%");
});

const ESTIMATE = {
  basis: { days: 7, sessions: 41, observed_rows: 310000 },
  current: { rows_per_day: 44000, bytes_per_day: 30_000_000 },
  projected: { rows_per_day: 4400, bytes_per_day: 3_000_000, rollup_rows_per_day: 600, org_rows_per_day: 2100 },
  by_setting: [
    { key: "budget.per_session", rows_per_day: 44000 },
    { key: "fold.enabled", rows_per_day: 52000 },
    { key: "budget.per_tool_call", rows_per_day: 9000 },
    { key: "services.track", rows_per_day: 44000 },
  ],
};

test("estimateModel orders settings by size of change and tones the pills", () => {
  const m = estimateModel(parseEstimate(ESTIMATE));
  assert.equal(m.hasHistory, true);
  assert.equal(m.basisText, "from the last 7 days, 41 sessions, 310,000 stored processes");
  assert.deepEqual(m.rows.pill, { tone: "success", text: "-90%" });
  assert.deepEqual(m.bytes.pill, { tone: "success", text: "-90%" });
  assert.equal(m.rollupRowsPerDay, 600);
  assert.equal(m.orgRowsPerDay, 2100);
  assert.deepEqual(m.settings.map((s) => s.key), ["budget.per_tool_call", "fold.enabled", "budget.per_session", "services.track"]);
  const [a, b, c] = m.settings;
  assert.equal(a.pill.tone, "success");
  assert.equal(b.pill.tone, "warn");
  assert.equal(c.pill.tone, "neutral");
  assert.equal(b.label, "Fold routine helpers");
  // The bar is the share of the largest value shown (52,000), never over 100.
  assert.equal(Math.round(b.barPct), 100);
  assert.ok(a.barPct > 0 && a.barPct < b.barPct);
});

test("estimateModel: no stored runs is 'not enough history', not a zero estimate", () => {
  const m = estimateModel(parseEstimate({ ...ESTIMATE, basis: { days: 0, sessions: 0, observed_rows: 0 } }));
  assert.equal(m.hasHistory, false);
});

test("parseEstimate tolerates a partial or odd body", () => {
  const e = parseEstimate({ basis: { days: "x" }, by_setting: [{ key: "a" }, { rows_per_day: 3 }, 7] });
  assert.equal(e.basis.days, 0);
  assert.deepEqual(e.by_setting, [{ key: "a", rows_per_day: 0 }]);
  assert.equal(parseEstimate(null).projected.org_rows_per_day, 0);
  assert.equal(estimateModel(e).settings[0].barPct, 0);
});

const SUM: ProcessSummaryResponse = {
  observed: 92428,
  kept: 3412,
  folded: 61203,
  rolled_up: 24880,
  service_kept: 2933,
  service_rolled_up: 0,
  dropped: 0,
  budget: { hit: true },
};

test("captureLine reads the way the System tab says it", () => {
  assert.equal(captureLine(SUM), "Kept 3,412 of 92,428 · 61,203 folded · 24,880 rolled up · 2,933 service rows · budget hit");
});

test("captureLine leaves zero parts out and adds the rare ones", () => {
  const s = { ...SUM, folded: 0, rolled_up: 0, service_kept: 0, budget: { hit: false } };
  assert.equal(captureLine(s), "Kept 3,412 of 92,428");
  assert.deepEqual(captureLineParts({ ...s, dropped: 5, service_rolled_up: 9 }), [
    "Kept 3,412 of 92,428",
    "9 service rolled up",
    "5 dropped",
  ]);
});

test("a numeric budget hit counts; a legacy session says it predates capture limits", () => {
  assert.equal(budgetHit({ ...SUM, budget: { hit: 3 } }), true);
  assert.equal(budgetHit({ ...SUM, budget: { hit: 0 } }), false);
  assert.equal(budgetHit({ ...SUM, budget: undefined }), false);
  assert.equal(captureLine({ ...SUM, legacy: true }), "Captured before capture limits");
});

test("parseSummary defaults counts to 0 and lists to empty", () => {
  const s = parseSummary({ kept: 5, services: [{ root_key: "k" }, "x"], legacy: true });
  assert.equal(s.observed, 0);
  assert.equal(s.kept, 5);
  assert.equal(s.services?.length, 1);
  assert.deepEqual(s.rollups, []);
  assert.equal(s.legacy, true);
  assert.equal(parseSummary(undefined).legacy, false);
});

test("summaryOutcome: 200 carries the body and ETag, 304 unchanged, 404 unavailable", () => {
  const ok = summaryOutcome(200, '"abc"', { kept: 1 });
  assert.equal(ok.kind, "ok");
  if (ok.kind === "ok") {
    assert.equal(ok.etag, '"abc"');
    assert.equal(ok.data.kept, 1);
  }
  assert.deepEqual(summaryOutcome(304, null, null), { kind: "not_modified" });
  assert.deepEqual(summaryOutcome(404, null, null), { kind: "unavailable" });
  assert.deepEqual(summaryOutcome(500, null, null), { kind: "error", status: 500 });
});

test("servicesRunning: a service seen in the last two minutes keeps the poll going", () => {
  const now = Date.parse("2026-11-04T12:00:00Z");
  assert.equal(servicesRunning([{ root_key: "a", exe: "x", last_seen: "2026-11-04T11:59:00Z" }], now), true);
  assert.equal(servicesRunning([{ root_key: "a", exe: "x", last_seen: "2026-11-04T11:50:00Z" }], now), false);
  assert.equal(servicesRunning([{ root_key: "a", exe: "x" }], now), false);
  assert.equal(servicesRunning(undefined, now), false);
});

function roll(kind: string, count: number, exe = "x"): ProcessSummaryRollup {
  return { group_kind: kind, exe_basename: exe, count, failed_count: count > 100 ? 2 : 0 };
}

test("rollups group by kind in display order, biggest first", () => {
  const sorted = sortRollups([roll("unattributed", 9), roll("fold", 5), roll("budget", 7), roll("fold", 50), roll("zzz", 1), roll("service", 3)]);
  assert.deepEqual(sorted.map((r) => `${r.group_kind}:${r.count}`), ["budget:7", "fold:50", "fold:5", "service:3", "unattributed:9", "zzz:1"]);
  assert.deepEqual(rollupTotals(sorted).map((t) => [t.kind, t.groups, t.count]), [
    ["budget", 1, 7],
    ["fold", 2, 55],
    ["service", 1, 3],
    ["unattributed", 1, 9],
    ["zzz", 1, 1],
  ]);
  assert.equal(rollupTotals(sorted)[4].label, "zzz");
});

test("a rollup page opens with its group heading and repeats it where the kind changes", () => {
  const sorted = sortRollups(Array.from({ length: 12 }, (_, i) => roll(i < 7 ? "fold" : "budget", 100 - i)));
  const p1 = rollupPage(sorted, 1, 10);
  assert.equal(p1.length, 10);
  assert.deepEqual(p1.filter((r) => r.heading).map((r) => r.heading), ["Over budget", "Folded helpers"]);
  const p2 = rollupPage(sorted, 2, 10);
  assert.equal(p2.length, 2);
  assert.equal(p2[0].heading, "Folded helpers", "a page never opens without a heading");
  assert.equal(p2[1].heading, undefined);
});

function node(key: string, startedAt: string, children: ProcessNode[] = []): ProcessNode {
  return {
    process_key: key,
    pid: 1,
    ppid: 0,
    exe: key,
    attribution_source: "x",
    attribution_confidence: "high",
    exited: true,
    exit_code: 0,
    duration_ms: 1,
    started_at: startedAt,
    children,
  };
}

test("tree windows: oldest start, node count, and a merge that keeps a boundary row once", () => {
  const newest = [node("c", "2026-11-04T10:00:00Z", [node("c1", "2026-11-04T10:00:01Z")]), node("b", "2026-11-04T09:00:00Z")];
  const earlier = [[node("b", "2026-11-04T09:00:00Z"), node("a", "2026-11-04T08:00:00Z")]];
  assert.equal(countNodes(newest), 3);
  assert.equal(oldestStartedAt(newest), "2026-11-04T09:00:00Z");
  assert.equal(oldestStartedAt([]), null);
  const merged = mergeWindows(earlier, newest);
  assert.deepEqual(merged.map((n) => n.process_key), ["a", "b", "c"]);
  assert.equal(merged[2].children.length, 1);
  assert.equal(oldestStartedAt(merged), "2026-11-04T08:00:00Z");
});

test("windowNote says 'of N' only when there is more than is shown", () => {
  assert.equal(windowNote(2000, 9150), "Showing the most recent 2,000 of 9,150");
  assert.equal(windowNote(2000, 2000), "Showing the most recent 2,000");
  assert.equal(windowNote(2000, undefined), "Showing the most recent 2,000");
});
