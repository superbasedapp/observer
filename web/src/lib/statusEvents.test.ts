// Pins shared/lib/statusEvents.ts: the Messages-table marker for status
// readings (rate_limit) folded onto a message (internal/sessionmsg/status.go).
import { test } from "node:test";
import assert from "node:assert/strict";
import { statusMarker } from "../../../shared/lib/statusEvents.ts";

test("no changed reading -> no marker (the per-turn Rate limit row is gone)", () => {
  assert.equal(statusMarker({}), null);
  assert.equal(statusMarker({ status_events: [], status_event_count: 7 }), null);
  assert.equal(statusMarker({ status_events: null }), null);
});

test("node reading: summary label, reason lines, unchanged count", () => {
  const m = statusMarker({
    status_events: [
      { action_type: "rate_limit", ts: "t1", reason: "first", summary: "7d 9% · plan prolite" },
      { action_type: "rate_limit", ts: "t2", reason: "used_percent", summary: "7d 10% · plan prolite" },
    ],
    status_event_count: 5,
  });
  assert.deepEqual(m, {
    label: "7d 10% · plan prolite",
    lines: [
      "Rate limit first reading: 7d 9% · plan prolite",
      "Rate limit usage changed: 7d 10% · plan prolite",
      "3 unchanged readings folded",
    ],
    limited: false,
  });
});

test("org reading (no body): generic label; a hit is flagged", () => {
  assert.deepEqual(statusMarker({ status_events: [{ action_type: "rate_limit", ts: "t", reason: "first" }] }), {
    label: "rate limit updated",
    lines: ["Rate limit first reading"],
    limited: false,
  });
  const hit = statusMarker({
    status_events: [{ action_type: "rate_limit", ts: "t", reason: "status", limited: true }],
    status_event_count: 1,
  });
  assert.equal(hit?.label, "rate limit hit");
  assert.equal(hit?.limited, true);
  assert.deepEqual(hit?.lines, ["Rate limit status changed: limited"]);
});
