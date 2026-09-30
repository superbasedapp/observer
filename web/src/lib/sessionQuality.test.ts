import assert from "node:assert/strict";
import test from "node:test";

import {
  freshnessNote,
  qualityBand,
  qualityComponents,
  unscoredMessage,
  type SessionQualityLike,
} from "../../../shared/lib/sessionQuality.ts";

// The node SessionDetailPanel's Overview tab renders the shared QualityPanel
// over GET /api/session/<id>/quality. These pin the honesty rules the panel
// relies on: never-scored is not zero, an unrecorded component is not zero,
// and a score taken before newer actions says so.

function q(over: Partial<SessionQualityLike>): SessionQualityLike {
  return {
    session_id: "s-1",
    scored: true,
    quality_score: 0.8,
    redundancy_ratio: 0.25,
    error_rate: 0.1,
    exploration_efficiency: 0.5,
    continuity_score: 0.9,
    scored_action_count: 40,
    current_action_count: 40,
    weights: { redundancy: 0.4, error: 0.3, exploration: 0.2, continuity: 0.1 },
    auto: { enabled: true, idle_minutes: 30 },
    ...over,
  };
}

test("qualityBand walks the band table top-down", () => {
  const cases: [number, string][] = [
    [1, "Strong"],
    [0.8, "Strong"],
    [0.79, "Fair"],
    [0.6, "Fair"],
    [0.59, "Weak"],
    [0, "Weak"],
  ];
  for (const [score, label] of cases) {
    assert.equal(qualityBand(score).label, label, `score ${score}`);
  }
});

test("qualityComponents inverts redundancy and errors and sums to the score", () => {
  const comps = qualityComponents(q({}));
  assert.deepEqual(comps.map((c) => c.key), ["redundancy", "error", "exploration", "continuity"]);
  assert.equal(comps[0].goodness, 0.75);
  assert.equal(comps[1].goodness, 0.9);
  const total = comps.reduce((s, c) => s + (c.points ?? 0), 0);
  // 0.4*0.75 + 0.3*0.9 + 0.2*0.5 + 0.1*0.9 = 0.76
  assert.ok(Math.abs(total - 0.76) < 1e-9, `total ${total}`);
});

test("an unrecorded component has no goodness and no points, never zero", () => {
  const comps = qualityComponents(q({ exploration_efficiency: undefined, continuity_score: undefined }));
  const expl = comps.find((c) => c.key === "exploration")!;
  assert.equal(expl.goodness, undefined);
  assert.equal(expl.points, undefined);
  assert.equal(expl.weight, 0.2);
});

test("unscoredMessage names why there is no score", () => {
  const cases: [Partial<SessionQualityLike>, RegExp][] = [
    [{ scored: false, current_action_count: 0 }, /no tool actions/],
    [{ scored: false, auto: { enabled: true, idle_minutes: 30 } }, /idle for 30 minutes/],
    [{ scored: false, auto: { enabled: true, idle_minutes: 1 } }, /idle for 1 minute\./],
    [{ scored: false, auto: { enabled: false, idle_minutes: 30 } }, /Automatic scoring is off/],
  ];
  for (const [over, re] of cases) {
    assert.match(unscoredMessage(q(over)), re);
  }
});

test("freshnessNote flags a score older than the session's activity", () => {
  assert.equal(freshnessNote(q({})), null);
  assert.equal(freshnessNote(q({ scored: false })), null);
  assert.match(freshnessNote(q({ current_action_count: 43 }))!, /before 3 newer actions\. It refreshes/);
  assert.match(freshnessNote(q({ current_action_count: 41, auto: { enabled: false, idle_minutes: 30 } }))!, /before 1 newer action\.$/);
  assert.match(freshnessNote(q({ scored_action_count: undefined }))!, /earlier version/);
});
