import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

// Viewer zone for the formatter cases: IST (+5:30, no DST) so a bucket is
// visibly not on a UTC hour. Set before the formatters are built.
process.env.TZ = "Asia/Kolkata";

const g = await import("../../../shared/lib/granularity.ts");

// Pins shared/lib/granularity.ts to the ONE fixture internal/timebucket's Go
// tests also read (shared/lib/granularity.fixture.json): the table, the Auto
// rule, the point count and the allowed set must agree across Go and TS.
type Fixture = {
  max_points: number;
  table: { gran: string; step_ms: number; auto_max_span_ms: number; always_allowed: boolean }[];
  choose: { name: string; span_ms: number | null; want: string }[];
  points: { span_ms: number; gran: string; want: number }[];
  allowed: { name: string; span_ms: number | null; want: string[] }[];
};
const fx = JSON.parse(
  readFileSync(new URL("../../../shared/lib/granularity.fixture.json", import.meta.url), "utf8"),
) as Fixture;
const span = (ms: number | null) => (ms == null ? Infinity : ms);

test("table matches the fixture", () => {
  assert.equal(g.MAX_POINTS, fx.max_points);
  assert.deepEqual(
    g.GRANULARITY_TABLE.map((r) => ({
      gran: r.gran,
      step_ms: r.stepMs,
      auto_max_span_ms: r.autoMaxSpanMs,
      always_allowed: r.alwaysAllowed,
    })),
    fx.table,
  );
});

for (const c of fx.choose) {
  test(`chooseGranularity: ${c.name}`, () => {
    assert.equal(g.chooseGranularity(span(c.span_ms)), c.want);
  });
}

for (const c of fx.points) {
  test(`pointCount(${c.span_ms}, ${c.gran})`, () => {
    assert.equal(g.pointCount(c.span_ms, c.gran as never), c.want);
  });
}

for (const c of fx.allowed) {
  test(`allowedGranularities: ${c.name}`, () => {
    assert.deepEqual(g.allowedGranularities(span(c.span_ms)), c.want);
  });
}

test("effectiveChoice drops a choice the span no longer allows", () => {
  assert.equal(g.effectiveChoice("5m", 3_600_000), "5m");
  assert.equal(g.effectiveChoice("5m", 30 * 86_400_000), "auto");
  assert.equal(g.effectiveChoice("1h", 3_600_000, g.DAILY_ONLY), "auto");
  assert.equal(g.effectiveChoice("auto", 3_600_000), "auto");
});

test("resolveGranularity walks Auto down to what the surface serves", () => {
  assert.equal(g.resolveGranularity("auto", 3_600_000), "5m");
  assert.equal(g.resolveGranularity("auto", 3_600_000, g.DAILY_ONLY), "1d");
  assert.equal(g.resolveGranularity("auto", 365 * 86_400_000, g.DAILY_ONLY), "1w");
  assert.equal(g.resolveGranularity("1d", 3_600_000), "1d");
});

test("fmtBucket per granularity (viewer zone IST)", () => {
  // 2026-09-29T08:30:00Z = 14:00 IST.
  assert.equal(g.fmtBucket("2026-09-29T14:00:00+05:30", "1h"), "Sep 29, 14:00");
  assert.equal(g.fmtBucket("2026-09-29T08:30:00Z", "1h", "tick"), "14:00");
  assert.equal(g.fmtBucket(Date.parse("2026-09-29T08:35:00Z"), "5m", "tick"), "14:05");
  // Local midnight tick shows the date.
  assert.equal(g.fmtBucket("2026-09-29T00:00:00+05:30", "1h", "tick"), "Sep 29");
  // A day key is the LOCAL date, never shifted.
  assert.equal(g.fmtBucket("2026-09-29", "1d"), "Sep 29");
  assert.equal(g.fmtBucket("2026-09-28", "1w"), "Week of Sep 28");
  assert.equal(g.fmtBucket("2026-09-28", "1w", "tick"), "Sep 28");
  assert.equal(g.fmtBucket("not a date", "1d"), "not a date");
});

test("bucketTime reads a day key as local midnight", () => {
  const ms = g.bucketTime("2026-09-29");
  const d = new Date(ms);
  assert.equal(d.getDate(), 29);
  assert.equal(d.getHours(), 0);
});

test("titles derive the unit", () => {
  assert.equal(g.perBucketTitle("Spend", "1h"), "Spend per hour");
  assert.equal(g.perBucketTitle("Actions", "5m"), "Actions per 5 min");
  assert.equal(g.perBucketTitle("Spend", "1w"), "Spend per week");
});

test("asGranularity accepts the legacy bucket values", () => {
  assert.equal(g.asGranularity("hour"), "1h");
  assert.equal(g.asGranularity("day"), "1d");
  assert.equal(g.asGranularity("5m"), "5m");
  assert.equal(g.asGranularity(undefined), "1d");
});

test("parseGranChoice", () => {
  assert.equal(g.parseGranChoice("auto"), "auto");
  assert.equal(g.parseGranChoice("1h"), "1h");
  assert.equal(g.parseGranChoice("2h"), null);
});

test("fmtBucket reads an epoch-ms string (numeric axis tooltip label)", () => {
  const ms = Date.parse("2026-09-29T08:30:00Z");
  assert.equal(g.fmtBucket(String(ms), "1h"), "Sep 29, 14:00");
});

test("dayTicks: midnight ticks only for a multi-day sub-day grid (IST)", async () => {
  const { dayTicks } = await import("../../../shared/charts/common.ts");
  const start = Date.parse("2026-09-27T18:30:00Z"); // 00:00 IST Sep 28
  const hourly = Array.from({ length: 72 }, (_, i) => ({ t: start + i * 3_600_000 }));
  assert.deepEqual(dayTicks(hourly, "1h", "t"), [start, start + 86_400_000, start + 2 * 86_400_000]);
  assert.equal(dayTicks(hourly.slice(0, 12), "1h", "t"), undefined);
  assert.equal(dayTicks(hourly, "1d", "t"), undefined);
  const long = Array.from({ length: 83 * 24 }, (_, i) => ({ t: start + i * 3_600_000 }));
  const ticks = dayTicks(long, "1h", "t")!;
  assert.ok(ticks.length <= 10 && ticks.length >= 8, `thinned to ${ticks.length}`);
});
