import assert from "node:assert/strict";
import test from "node:test";

import { TOUR_STEPS, TOUR_STEP_IDS } from "./tour.ts";

// tour.test.ts pins the first-run tour's five places (local dashboard
// first-run design, section 5): every step anchors to its nav item and
// walks to its page, so the tour shows real places, never a centered card.

test("the tour is five steps, in order", () => {
  assert.deepEqual(TOUR_STEP_IDS, ["overview", "sessions", "cost", "terminals", "security"]);
});

test("every step anchors to its nav item and names its page", () => {
  const paths: Record<string, string> = {
    overview: "/",
    sessions: "/sessions",
    cost: "/cost",
    terminals: "/terminals",
    security: "/security",
  };
  for (const s of TOUR_STEPS) {
    assert.equal(s.target, `[data-tour="nav-${s.id}"]`, s.id);
    assert.equal(s.path, paths[s.id], s.id);
    assert.ok(s.title.length > 0 && s.body.length > 0, s.id);
    // Brand: "superbased" is always lowercase.
    assert.ok(!/Superbased|SuperBased|SUPERBASED/.test(s.title + s.body), s.id);
  }
});
