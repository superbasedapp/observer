import assert from "node:assert/strict";
import test from "node:test";

import { readFileSync } from "node:fs";

import {
  eligibleNow,
  shareHistoryCrossEnrolmentWarning,
  shareHistoryProgress,
  shareHistoryPreviewLine,
} from "./shareHistory.ts";

const tables = (...eligible: number[]) => eligible.map((e, i) => ({ table: `t${i}`, historical: 100, eligible: e }));

test("eligibleNow sums every table's not-yet-shared rows", () => {
  assert.equal(eligibleNow(null), 0);
  assert.equal(eligibleNow([]), 0);
  assert.equal(eligibleNow(tables(3, 4, 5)), 12);
});

test("shareHistoryProgress counts what the push loop has sent since the rewind", () => {
  const rows: { name: string; started: number; now: number; want: { sent: number; ratio: number; done: boolean } }[] = [
    { name: "just rewound", started: 120, now: 120, want: { sent: 0, ratio: 0, done: false } },
    { name: "half way", started: 120, now: 60, want: { sent: 60, ratio: 0.5, done: false } },
    { name: "drained", started: 120, now: 0, want: { sent: 120, ratio: 1, done: true } },
    // New activity after the rewind can push the waiting count above the
    // starting point: never a negative count or a ratio past the ends.
    { name: "new activity outruns the push", started: 120, now: 150, want: { sent: 0, ratio: 0, done: false } },
    { name: "an empty corpus is done at once", started: 0, now: 0, want: { sent: 0, ratio: 1, done: true } },
  ];
  for (const r of rows) {
    assert.deepEqual(shareHistoryProgress(r.started, r.now, true), r.want, r.name);
  }
});

test("shareHistoryProgress never reads a pre-rewind overview as done", () => {
  // Right after the rewind the page still holds the overview read BEFORE it,
  // where nothing was waiting: that must read as just started, not done.
  assert.deepEqual(shareHistoryProgress(160, 0, false), { sent: 0, ratio: 0, done: false });
  assert.deepEqual(shareHistoryProgress(160, 0, true), { sent: 160, ratio: 1, done: true });
});

test("shareHistoryPreviewLine says what a confirm will ship, in plain words", () => {
  assert.equal(
    shareHistoryPreviewLine({ eligible: 2, would_unlock: 1500, total: 1502, rewound: false }),
    "1,500 older rows are not shared yet. Sharing history sends them on the next push cycles, along with the 2 already waiting.",
  );
  assert.equal(
    shareHistoryPreviewLine({ eligible: 0, would_unlock: 1, total: 1, rewound: false }),
    "1 older row is not shared yet. Sharing history sends it on the next push cycles.",
  );
  assert.equal(
    shareHistoryPreviewLine({ eligible: 7, would_unlock: 0, total: 7, rewound: false }),
    "Everything captured on this machine is already shared or waiting to ship. There is no older history to send.",
  );
  for (const r of [
    { eligible: 2, would_unlock: 1500, total: 1502, rewound: false },
    { eligible: 0, would_unlock: 0, total: 0, rewound: false },
  ]) {
    assert.ok(!/[\u2014`]/.test(shareHistoryPreviewLine(r)), "no em dash or CLI backticks in UI copy");
  }
});

test("Share history says what goes and what stays before the confirm (M3-12, D-273, D-43)", () => {
  const w = shareHistoryCrossEnrolmentWarning("Acme");
  assert.match(w, /previous enrolment/);
  assert.match(w, /another organization stay on this machine/);
  assert.match(w, /personal use/);
  assert.match(w, /go to Acme/);
  assert.doesNotMatch(w, new RegExp("[" + String.fromCharCode(0x2013, 0x2014) + "]"));
  const card = readFileSync(new URL("../pages/settings/EnrolmentSection.tsx", import.meta.url), "utf8");
  assert.match(card, /shareHistoryCrossEnrolmentWarning\(orgDisplayLabel\(ov\.org_display\)\)/);
  assert.match(card, /including personal use from before this machine first connected/);
});
