// componentTurnOn: one case per outcome row and per button state (ruling
// SBXD-9), plus the call sequence the Turn it on button sends.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  TURN_ON_OUTCOME_RULES,
  turnOnComponent,
  turnOnOutcome,
  turnOnView,
  type TurnOnFacts,
  type TurnOnPreview,
  type TurnOnState,
} from "./componentTurnOn.ts";

const preview = (p: Partial<TurnOnPreview> = {}): TurnOnPreview => ({
  activated: ["terminals.sandbox"],
  refused: [],
  managed_refused: [],
  fingerprint: "fp1",
  ...p,
});

const outcomeCases: { name: string; facts: TurnOnFacts; want: TurnOnState }[] = [
  {
    name: "the change is made only on this machine's own dashboard",
    facts: { error: "forbidden: route is reachable only from the local dashboard", localOnly: true },
    want: {
      phase: "refused",
      reason: "Turning it on is done from this machine's own dashboard, not from a remote view. Open the dashboard on this machine and try again.",
    },
  },
  { name: "a call failed", facts: { error: " preview failed " }, want: { phase: "refused", reason: "preview failed" } },
  {
    name: "the organization decides",
    facts: { preview: preview({ managed_by: "Acme", managed_refused: ["add terminals.sandbox: not in the policy"] }) },
    want: {
      phase: "refused",
      reason: "Acme decides which components run on this machine: add terminals.sandbox: not in the policy. Request it from your organization.",
    },
  },
  {
    name: "every part of the change was refused",
    facts: { preview: preview({ activated: [], refused: ["terminals.sandbox: blocked by a requirement"] }) },
    want: { phase: "refused", reason: "terminals.sandbox: blocked by a requirement" },
  },
  { name: "it was already on", facts: { preview: preview({ activated: [], no_change: true }) }, want: { phase: "done" } },
  { name: "not applied yet", facts: { preview: preview() }, want: { phase: "working" } },
  {
    name: "applied, and an activated component waits for a restart",
    facts: { preview: preview(), applied: true, restartClass: { "terminals.sandbox": "restart" } },
    want: { phase: "needs_restart" },
  },
  { name: "applied", facts: { preview: preview(), applied: true, restartClass: { "terminals.sandbox": "soft" } }, want: { phase: "done" } },
];

test("every outcome row has a case, in table order", () => {
  assert.deepEqual(
    outcomeCases.map((c) => c.name),
    TURN_ON_OUTCOME_RULES.map((r) => r.name),
  );
});

for (const c of outcomeCases) {
  test(`outcome: ${c.name}`, () => {
    assert.deepEqual(turnOnOutcome(c.facts), c.want);
  });
}

test("organization refusal without a name says your organization", () => {
  assert.match(turnOnOutcome({ preview: preview({ managed_refused: ["x"] }) }).reason ?? "", /^Your organization decides/);
});

const viewCases: { state: TurnOnState; label: string; disabled: boolean; line: RegExp | null; alert: boolean }[] = [
  { state: { phase: "idle" }, label: "Turn it on", disabled: false, line: null, alert: false },
  { state: { phase: "working" }, label: "Turning it on...", disabled: true, line: null, alert: false },
  { state: { phase: "done" }, label: "Turned on", disabled: true, line: /^Turned on\. Its settings show here next\.$/, alert: false },
  { state: { phase: "needs_restart" }, label: "Turned on", disabled: true, line: /after the next restart\.$/, alert: false },
  { state: { phase: "refused", reason: "No." }, label: "Turn it on", disabled: false, line: /^No\.$/, alert: true },
];

for (const c of viewCases) {
  test(`view: ${c.state.phase}`, () => {
    const v = turnOnView(c.state);
    assert.equal(v.label, c.label);
    assert.equal(v.disabled, c.disabled);
    assert.equal(v.alert, c.alert);
    if (c.line) assert.match(v.line ?? "", c.line);
    else assert.equal(v.line, null);
  });
}

test("refused with no reason still says something", () => {
  assert.equal(turnOnView({ phase: "refused" }).line, "It could not be turned on here.");
});

type Call = { path: string; body: unknown };

function fakePost(replies: Record<string, unknown>) {
  const calls: Call[] = [];
  const post = async (path: string, body: unknown) => {
    calls.push({ path, body });
    const r = replies[path];
    if (r instanceof Error) throw r;
    return r;
  };
  return { calls, post };
}

const readError = (e: unknown) => ({
  message: e instanceof Error ? e.message : String(e),
  localOnly: /local dashboard/.test(String(e)),
});

test("turnOnComponent previews then applies under the preview's fingerprint", async () => {
  const { calls, post } = fakePost({ "/api/components/preview": preview(), "/api/components/apply": { wrote: true } });
  const got = await turnOnComponent("terminals.sandbox", post, readError);
  assert.deepEqual(got, { phase: "done" });
  assert.deepEqual(calls, [
    { path: "/api/components/preview", body: { change: { add: ["terminals.sandbox"] } } },
    { path: "/api/components/apply", body: { change: { add: ["terminals.sandbox"] }, fingerprint: "fp1", skip_teardown: false } },
  ]);
});

test("turnOnComponent reports needs restart from the catalog's restart class", async () => {
  const { post } = fakePost({ "/api/components/preview": preview(), "/api/components/apply": {} });
  assert.deepEqual(await turnOnComponent("terminals.sandbox", post, readError, { "terminals.sandbox": "restart" }), {
    phase: "needs_restart",
  });
});

test("turnOnComponent never applies a refused, managed or unchanged preview", async () => {
  for (const p of [preview({ activated: [], refused: ["no"] }), preview({ managed_refused: ["no"] }), preview({ activated: [], no_change: true })]) {
    const { calls, post } = fakePost({ "/api/components/preview": p });
    await turnOnComponent("terminals.sandbox", post, readError);
    assert.equal(calls.length, 1, JSON.stringify(p));
  }
});

test("turnOnComponent says a failed preview or apply in plain words", async () => {
  const remote = fakePost({ "/api/components/preview": new Error("forbidden: route is reachable only from the local dashboard") });
  assert.match((await turnOnComponent("terminals.sandbox", remote.post, readError)).reason ?? "", /this machine's own dashboard/);
  const stale = fakePost({
    "/api/components/preview": preview(),
    "/api/components/apply": new Error("the selection changed since the preview; preview again"),
  });
  assert.deepEqual(await turnOnComponent("terminals.sandbox", stale.post, readError), {
    phase: "refused",
    reason: "the selection changed since the preview; preview again",
  });
});
