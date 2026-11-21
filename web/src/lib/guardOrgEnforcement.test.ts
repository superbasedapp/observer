import assert from "node:assert/strict";
import test from "node:test";

import {
  CHAIN_REPAIR_STEPS,
  chainApplyNote,
  chainApplyReady,
  chainRepairSteps,
  guardChainSub,
  guardEnforcedSub,
  guardOrgLine,
  guardPostureValue,
} from "./guardOrgEnforcement.ts";

// FU-235: the posture, Mode and verdict tiles account for the rules the
// organization's policy enforces whatever the local mode. FU-236: the audit
// tile names the repair path when maintenance explains the break.

const ORG = {
  enforced_rules: ["R-101"],
  locks_every_rule: true,
  line: "observe locally; 1 rule enforced by your organization (R-101); your organization locks every rule on this node, so local exceptions do not apply",
};

const postureCases = [
  { name: "posture: disabled guard", sum: { enabled: false, mode: "observe" }, want: "disabled" },
  { name: "posture: no org layer", sum: { enabled: true, mode: "observe" }, want: "observe" },
  { name: "posture: org layer present", sum: { enabled: true, mode: "observe", org: ORG }, want: "observe locally" },
  { name: "posture: null org from an older daemon", sum: { enabled: true, mode: "enforce", org: null }, want: "enforce" },
];
for (const c of postureCases) {
  test(c.name, () => assert.equal(guardPostureValue(c.sum), c.want));
}

const lineCases = [
  { name: "org line: absent", org: undefined, want: null },
  { name: "org line: blank", org: { ...ORG, line: "  " }, want: null },
  { name: "org line: the daemon's words", org: ORG, want: ORG.line },
];
for (const c of lineCases) {
  test(c.name, () => assert.equal(guardOrgLine(c.org), c.want));
}

const enforcedCases = [
  { name: "enforced: nothing", counts: { enforced: 0 }, want: "0 enforced (blocked or deferred)" },
  { name: "enforced: older daemon, no split", counts: { enforced: 3 }, want: "3 enforced (blocked or deferred)" },
  {
    name: "enforced: the organization's share",
    counts: { enforced: 3, enforced_by_org: 2 },
    want: "3 enforced (blocked or deferred), 2 by your organization's policy",
  },
];
for (const c of enforcedCases) {
  test(c.name, () => assert.equal(guardEnforcedSub(c.counts), c.want));
}

const chainCases = [
  { name: "chain: intact", chain: { ok: true, checked: 10 }, want: "10 rows verified (tamper-evident, SHA-256 chained)" },
  {
    name: "chain: broken, nothing recoverable",
    chain: { ok: false, checked: 10, divergence_id: 4 },
    want: "first divergence at id 4 - Verify audit chain on the Coverage tab walks it",
  },
  {
    name: "chain: broken by maintenance",
    chain: { ok: false, checked: 10, divergence_id: 1, actionless_rewritten: 3 },
    want: "first divergence at id 1; 3 rows lost their action id to routine maintenance, which Repair audit chain on the Coverage tab can prove and restore (dry run first)",
  },
  {
    name: "chain: one maintenance row",
    chain: { ok: false, checked: 10, divergence_id: 1, actionless_rewritten: 1 },
    want: "first divergence at id 1; 1 row lost its action id to routine maintenance, which Repair audit chain on the Coverage tab can prove and restore (dry run first)",
  },
  {
    name: "chain: broken links point at the repair",
    chain: { ok: false, checked: 10, divergence_id: 5, breaks: { "broken link": 2 } },
    want: "first divergence at id 5 - Repair audit chain on the Coverage tab shows what it can fix",
  },
];
for (const c of chainCases) {
  test(c.name, () => assert.equal(guardChainSub(c.chain), c.want));
}

// B-G8: the chain repair card's model. No line sends the user to a terminal.
test("chainRepairSteps picks the repairs for what the walk found, in the daemon's order", () => {
  const kinds = (chain: Parameters<typeof chainRepairSteps>[0]) => chainRepairSteps(chain).map((s) => s.kind);
  assert.deepEqual(kinds({ ok: true, checked: 3 }), []);
  assert.deepEqual(kinds({ ok: false, checked: 3, divergence_id: 2 }), []);
  assert.deepEqual(kinds({ ok: false, checked: 3, actionless_rewritten: 1 }), ["repair-anchors"]);
  assert.deepEqual(kinds({ ok: false, checked: 3, breaks: { "broken link": 1 } }), ["dedup-events", "relink-gaps"]);
  assert.deepEqual(kinds({ ok: false, checked: 3, actionless_rewritten: 2, breaks: { "broken link": 1, "rewritten row": 2 } }), [
    "repair-anchors",
    "dedup-events",
    "relink-gaps",
  ]);
  assert.deepEqual(
    CHAIN_REPAIR_STEPS.map((s) => s.kind),
    ["repair-anchors", "dedup-events", "relink-gaps"],
  );
});

test("an apply is offered only after its own dry run finished", () => {
  assert.equal(chainApplyReady("relink-gaps", {}), false);
  assert.equal(chainApplyReady("relink-gaps", { "relink-gaps": { mode: "guard:relink-gaps", status: "running" } }), false);
  assert.equal(chainApplyReady("relink-gaps", { "relink-gaps": { mode: "guard:relink-gaps", status: "failed" } }), false);
  assert.equal(chainApplyReady("relink-gaps", { "dedup-events": { mode: "guard:dedup-events", status: "done" } }), false);
  assert.equal(chainApplyReady("relink-gaps", { "relink-gaps": { mode: "guard:relink-gaps", status: "done" } }), true);
});

test("an apply's confirm note says rows are rewritten and asks for a backup first", () => {
  for (const step of CHAIN_REPAIR_STEPS) {
    const note = chainApplyNote(step);
    assert.match(note, /rewrites rows in observer\.db/);
    assert.match(note, /Settings > Storage/);
    assert.ok(!/observer guard|run `/.test(note + step.finds + step.rewrites), `CLI pointer in ${step.kind}`);
  }
});
