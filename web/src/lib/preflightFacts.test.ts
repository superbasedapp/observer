import assert from "node:assert/strict";
import test from "node:test";

import { preflightFacts } from "./preflightFacts.ts";
import type { ToolPreflight } from "./types.ts";

const base: ToolPreflight = {
  tool: "codex",
  verdict: "ok",
  can_install: false,
  // The server's free-text notes are present but must never be echoed.
  notes: ["codex is a #!/usr/bin/env node shim; node is not found anywhere on the merged PATH"],
};

const cases: Array<{ name: string; over: Partial<ToolPreflight>; want: string[] }> = [
  { name: "no structured facts -> nothing (notes are never echoed)", over: {}, want: [] },
  {
    name: "stale config override",
    over: { config_override: "missing", verdict: "not_found" },
    want: ["Nothing is at the binary path set for this tool. Change or remove it in Settings > Session attach (Launch binary paths)."],
  },
  {
    name: "config override used",
    over: { config_override: "used" },
    want: ["Uses the binary path set in Settings > Session attach (Launch binary paths)."],
  },
  {
    name: "missing interpreter",
    over: { missing_interpreter: "node" },
    want: ["It needs node, which isn't installed, so it will fail to start."],
  },
  {
    name: "install program missing",
    over: { install_needs_program: "npm" },
    want: ["The install command needs npm, which isn't installed yet."],
  },
  {
    name: "unverified packaged app",
    over: { install_unverified: true },
    want: ["SuperBased can't confirm it's installed. The launch will tell you if it isn't."],
  },
];
cases.push(
  {
    name: "T-685: a predicted hard-budget refusal says why and what to do",
    over: { budget_launch: { reason: "The org's hard budget will stop this launch: no route.", remedy: "What to do: ask your org admin." } },
    want: ["The org's hard budget will stop this launch: no route. What to do: ask your org admin."],
  },
  {
    name: "T-685: a missing route config says how to set it up",
    over: { route_setup: "Set up a provider in the tool first." },
    want: ["Set up a provider in the tool first."],
  },
);
for (const c of cases) {
  test(`preflightFacts: ${c.name}`, () => {
    assert.deepEqual(preflightFacts("codex", { ...base, ...c.over }), c.want);
  });
}

test("facts follow table order", () => {
  const got = preflightFacts("codex", { ...base, missing_interpreter: "node", install_needs_program: "npm" });
  assert.equal(got.length, 2);
  assert.match(got[0], /needs node/);
  assert.match(got[1], /needs npm/);
});

test("null preflight -> no facts", () => {
  assert.deepEqual(preflightFacts("codex", null), []);
});

test("T-396: an outside_range launch runtime is the first fact, and never a blocker", () => {
  const sentence = "Codex declares Node.js >=20 <23. This machine has 24.1.0, which that range leaves out, so the tool may fail to start.";
  const got = preflightFacts("codex", {
    ...base,
    missing_interpreter: "node",
    launch_runtime: { runtime: "node", display: "Node.js", min: "20", have: "24.1.0", status: "outside_range", range: ">=20 <23", summary: sentence },
  });
  assert.deepEqual(got.slice(0, 1), [sentence]);
  assert.equal(got.length, 2);
  assert.deepEqual(
    preflightFacts("codex", { ...base, launch_runtime: { runtime: "node", display: "Node.js", min: "20", status: "too_old" } }),
    [],
  );
});

test("T-685: the budget refusal is the first fact", () => {
  const got = preflightFacts("codex", {
    ...base,
    missing_interpreter: "node",
    budget_launch: { reason: "Refused.", remedy: "What to do: ask." },
  });
  assert.equal(got[0], "Refused. What to do: ask.");
  assert.match(got[1], /needs node/);
});
