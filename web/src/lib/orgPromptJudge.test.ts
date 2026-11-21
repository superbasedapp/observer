import assert from "node:assert/strict";
import test from "node:test";
import { judgeHeadline, judgeTiles, type OrgPromptJudgeStatus } from "./orgPromptJudge.ts";

const on: OrgPromptJudgeStatus = {
  available: true,
  active: true,
  managed: true,
  version: 3,
  scope: "user_prompts",
  mode: "enforce",
  strict: true,
  enforced: true,
  fail_closed: true,
  unreachable: "the prompt is refused (strict, enforced)",
  counts: { deny: 2, flag: 5, ask: 1 },
};

test("headline: unavailable, individual, managed off, on", () => {
  assert.equal(judgeHeadline({ available: false, reason: "no daemon" }).text, "no daemon");
  assert.match(judgeHeadline({ available: true, active: false, managed: false }).text, /not an organization-managed machine/);
  assert.match(judgeHeadline({ available: true, active: false, managed: true, off_reason: "node_lane is off" }).text, /node_lane is off/);
  assert.match(judgeHeadline(on).text, /refuses prompts/);
  assert.match(judgeHeadline({ ...on, enforced: false }).text, /refuses nothing/);
});

test("tiles appear only while active and count refusals and flags", () => {
  assert.deepEqual(judgeTiles({ available: true, active: false }), []);
  const tiles = judgeTiles(on);
  const by = Object.fromEntries(tiles.map((t) => [t.label, t]));
  assert.equal(by["Refused (24h)"].value, "2");
  assert.equal(by["Flagged (24h)"].value, "6");
  assert.equal(by["If the daemon cannot answer"].value, "Prompt refused");
  assert.equal(by["Reads"].value, "Your prompts");
  assert.equal(judgeTiles({ ...on, scope: "all_calls", fail_closed: false }).find((t) => t.label === "Reads")?.tone, "warn");
});
