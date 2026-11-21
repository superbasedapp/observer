import assert from "node:assert/strict";
import test from "node:test";

import {
  CACHE_HEALTH_DEFAULTS,
  cacheHealthFullParams,
  cacheHealthInputErrors,
  cacheHealthVerdict,
  gradingGateFailed,
  type CacheHealthFullResponse,
} from "./cacheHealth.ts";

test("the cache page alarms only when the grading gate fails on enough events", () => {
  // The live shape that used to raise a yellow strip: huge diagnostic
  // counters, gate passed. No alarm.
  assert.equal(gradingGateFailed({ graded_events: 504_452, min_events_threshold: 200, gate_passed: true }), false);
  // Too few events to judge: no alarm either way.
  assert.equal(gradingGateFailed({ graded_events: 19, min_events_threshold: 200, gate_passed: false }), false);
  // Enough events and the gate failed: alarm.
  assert.equal(gradingGateFailed({ graded_events: 500, min_events_threshold: 200, gate_passed: false }), true);
  assert.equal(gradingGateFailed(null), false);
});

// B-R1: the Full report's inputs, one case per rule.
test("the full report sends full=1 and only the thresholds that differ", () => {
  assert.deepEqual(cacheHealthFullParams(CACHE_HEALTH_DEFAULTS), { full: "1" });
  assert.deepEqual(
    cacheHealthFullParams({ minEvents: 50, maxRatePct: 10, maxRewriteReadRatio: 5, maxCauseSharePct: 50 }),
    { full: "1", min_events: "50", max_rate: "0.1", max_rewrite_read_ratio: "5", max_cause_share: "0.5" },
  );
});

test("the inputs refuse what the server would clamp", () => {
  assert.deepEqual(cacheHealthInputErrors(CACHE_HEALTH_DEFAULTS), []);
  const bad = cacheHealthInputErrors({ minEvents: 0.5, maxRatePct: 120, maxRewriteReadRatio: 0, maxCauseSharePct: Number.NaN });
  assert.equal(bad.length, 4);
  assert.match(bad[0], /Minimum graded events: use a whole number from 1/);
  assert.match(bad[1], /Maximum mispredict rate: use from 0 to 100/);
});

test("the verdict reads like the command: judge, pass, fail", () => {
  const base: CacheHealthFullResponse = {
    graded_events: 300,
    min_events_threshold: 200,
    gate_passed: true,
    mispredicts: 3,
    mispredict_rate: 0.01,
    max_rate_threshold: 0.05,
  };
  assert.equal(cacheHealthVerdict(base).tone, "success");
  assert.match(cacheHealthVerdict(base).text, /Gate passes: 3 mispredicts in 300 graded events \(1\.0%, limit 5\.0%\)/);
  assert.equal(cacheHealthVerdict({ ...base, gate_passed: false, mispredict_rate: 0.2 }).tone, "danger");
  const thin = cacheHealthVerdict({ ...base, graded_events: 19 });
  assert.equal(thin.tone, "neutral");
  assert.match(thin.text, /Not enough to judge: 19 graded events, the gate needs 200/);
});
