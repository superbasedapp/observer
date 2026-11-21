import assert from "node:assert/strict";
import test from "node:test";

import {
  activeNotices,
  budgetWarningLabel,
  isBlocked,
  newerBudgetStatus,
  newNotices,
  noticeMessage,
  parseIdList,
  pickBudgetWarning,
  rememberIds,
  subjectLabel,
  TOASTED_CAP,
  type BudgetEffect,
  type BudgetNotice,
  type BudgetStatus,
} from "./budgetWarning.ts";

function notice(over: Partial<BudgetNotice>): BudgetNotice {
  return {
    id: "n1",
    window: "daily",
    unit: "usd",
    period: "2026-10-02",
    threshold: 0.8,
    ratio: 0.85,
    spent: 0.64,
    cap: 0.75,
    scope: "member:dev",
    enforcement: "report",
    crossed_at: "2026-10-02T10:00:00Z",
    level: "warning",
    message: "Org daily budget (you, warning only): 85% used. Requests are not blocked.",
    ...over,
  };
}

function status(active: BudgetNotice[], available = true): BudgetStatus {
  return { available, written_at: "2026-10-02T10:00:00Z", windows: [], active };
}

test("pickBudgetWarning renders nothing when unavailable, empty or missing", () => {
  assert.equal(pickBudgetWarning(null), null);
  assert.equal(pickBudgetWarning(undefined), null);
  assert.equal(pickBudgetWarning({ available: false, active: [notice({})] }), null);
  assert.equal(pickBudgetWarning(status([])), null);
  assert.equal(pickBudgetWarning({ available: true, active: null }), null);
});

test("pickBudgetWarning shows the top notice with the rest counted", () => {
  const v = pickBudgetWarning(
    status([
      notice({ id: "w", level: "warning", ratio: 0.9 }),
      notice({ id: "x", level: "exceeded", ratio: 1.68, window: "monthly" }),
    ]),
  );
  assert.ok(v);
  assert.equal(v.top.id, "x");
  assert.deepEqual(v.others.map((n) => n.id), ["w"]);
  assert.equal(v.tone, "danger");
  assert.equal(v.blocked, false);
  assert.equal(v.label, "Budget exceeded (report only)");
});

test("pickBudgetWarning skips dismissed notices", () => {
  const s = status([
    notice({ id: "x", level: "exceeded", ratio: 1.2 }),
    notice({ id: "w", level: "warning" }),
  ]);
  const v = pickBudgetWarning(s, new Set(["x"]));
  assert.ok(v);
  assert.equal(v.top.id, "w");
  assert.equal(v.tone, "warn");
  assert.equal(v.others.length, 0);
  assert.equal(pickBudgetWarning(s, new Set(["x", "w"])), null);
});

test("hard + exceeded says requests are blocked", () => {
  const v = pickBudgetWarning(
    status([notice({ id: "h", level: "exceeded", enforcement: "hard", ratio: 1.1 })]),
  );
  assert.ok(v);
  assert.equal(v.blocked, true);
  assert.match(v.label, /blocked/);
});

test("budgetWarningLabel / isBlocked table", () => {
  // The label names the state: blocked, exceeded but not blocked (warning
  // only / report only), or approaching. It never says "exceeded" while the
  // reading is under the cap, whatever level the payload carries (node 1,
  // 2026-10-06: "Budget exceeded" at 11% after the admin raised the cap).
  const rows: [string, BudgetNotice["level"], number | undefined, string, boolean][] = [
    ["report", "warning", 0.8, "Approaching budget", false],
    ["soft", "warning", 0.9, "Approaching budget", false],
    ["hard", "warning", 0.9, "Approaching budget: blocks at 100%", false],
    ["report", "exceeded", 1.2, "Budget exceeded (report only)", false],
    ["soft", "exceeded", 1.01, "Budget exceeded (warning only)", false],
    ["hard", "exceeded", 1.33, "Budget exceeded: requests blocked", true],
    ["hard", "exceeded", 0.9996, "Budget exceeded: requests blocked", true],
    ["soft", "exceeded", 0.110238, "Approaching budget", false],
    ["hard", "exceeded", 0.5, "Approaching budget: blocks at 100%", false],
    ["soft", "exceeded", undefined, "Budget exceeded (warning only)", false],
  ];
  for (const [enforcement, level, ratio, label, blocked] of rows) {
    assert.equal(budgetWarningLabel({ enforcement, level, ratio }), label, `${enforcement}/${level}/${ratio}`);
    assert.equal(isBlocked({ enforcement, level, ratio }), blocked, `${enforcement}/${level}/${ratio}`);
    assert.doesNotMatch(label, /[\u2013\u2014]/);
  }
});

test("budgetWarningLabel / isBlocked follow what THIS machine does (2026-11-18)", () => {
  // A $0.01 hard org cap on a machine in observe mode said "requests
  // blocked" while nothing was blocked. With the daemon's effect and blocked
  // bits, the label says what the machine does; never "blocked" unless the
  // daemon says this machine refuses the reading.
  const rows: [BudgetEffect, boolean, BudgetNotice["level"], number, string, boolean][] = [
    ["warn_observe", false, "exceeded", 42, "Budget exceeded (warning only on this machine)", false],
    ["warn_guard_off", false, "exceeded", 1.5, "Budget exceeded (warning only on this machine)", false],
    ["warn_observe", false, "warning", 0.8, "Approaching budget (warning only on this machine)", false],
    ["blocks", true, "exceeded", 1.5, "Budget exceeded: requests blocked", true],
    ["blocks_proxied", true, "exceeded", 1.5, "Budget exceeded: proxied requests blocked", true],
    // Over only with other machines' spend (flag-only baseline): not yet.
    ["blocks", false, "exceeded", 1.5, "Budget exceeded (not blocked yet)", false],
    ["blocks", false, "warning", 0.9, "Approaching budget: blocks at 100%", false],
    // A stale blocked bit under the cap is never "blocked".
    ["blocks", true, "exceeded", 0.5, "Approaching budget: blocks at 100%", false],
  ];
  for (const [effect, blocked, level, ratio, label, isB] of rows) {
    const n = { enforcement: "hard", level, ratio, effect, blocked };
    assert.equal(budgetWarningLabel(n), label, `${effect}/${blocked}/${level}/${ratio}`);
    assert.equal(isBlocked(n), isB, `${effect}/${blocked}/${level}/${ratio}`);
  }
});

test("activeNotices drops malformed rows and keeps server order on ties", () => {
  const got = activeNotices({
    available: true,
    active: [
      notice({ id: "a", ratio: 0.9 }),
      { ...notice({ id: "" }) },
      { ...notice({ id: "nomsg", message: "" }) },
      { ...notice({ id: "badlevel" }), level: "ok" as unknown as "warning" },
      null as unknown as BudgetNotice,
      notice({ id: "b", ratio: 0.9 }),
    ],
  });
  assert.deepEqual(got.map((n) => n.id), ["a", "b"]);
});

test("newNotices returns only ids not toasted before", () => {
  const s = status([notice({ id: "a" }), notice({ id: "b", level: "exceeded", ratio: 1.1 })]);
  assert.deepEqual(newNotices(s, new Set()).map((n) => n.id), ["b", "a"]);
  assert.deepEqual(newNotices(s, new Set(["b"])).map((n) => n.id), ["a"]);
  assert.deepEqual(newNotices(s, new Set(["a", "b"])), []);
  assert.deepEqual(newNotices({ available: false, active: [notice({})] }, new Set()), []);
});

test("rememberIds dedupes, moves re-seen ids newest and caps", () => {
  assert.deepEqual(rememberIds(["a", "b"], ["c"]), ["a", "b", "c"]);
  assert.deepEqual(rememberIds(["a", "b"], ["a"]), ["b", "a"]);
  assert.deepEqual(rememberIds(["a"], ["b", "b"]), ["a", "b"]);
  const many = Array.from({ length: TOASTED_CAP }, (_, i) => `id${i}`);
  const next = rememberIds(many, ["new"]);
  assert.equal(next.length, TOASTED_CAP);
  assert.equal(next[0], "id1");
  assert.equal(next[next.length - 1], "new");
  assert.deepEqual(rememberIds(["a", "b", "c"], ["d"], 2), ["c", "d"]);
});

test("noticeMessage: token display mode never shows a dollar cap's amounts", () => {
  const exceeded = notice({
    level: "exceeded",
    ratio: 1.2,
    spent: 0.9,
    cap: 0.75,
    enforcement: "soft",
    message: "Org daily budget (you, warning only): 120% used - $0.90 of $0.75. Requests are not blocked.",
  });
  // Dollar mode: the server's sentence, verbatim.
  assert.equal(noticeMessage(exceeded, "usd"), exceeded.message);
  // Token mode: the share of the budget stays, the dollar figures go.
  const tok = noticeMessage(exceeded, "tokens");
  assert.equal(tok, "Org daily budget (you, warning only): 120% used of the budget. Requests are not blocked.");
  assert.doesNotMatch(tok, /\$/);
  // Thousands separators in the dollar figures are handled too.
  const big = notice({ message: "Org monthly budget (your team, blocking): 96% used - $1,200.00 of $1,250.00. Requests will be blocked at 100%." });
  assert.equal(
    noticeMessage(big, "tokens"),
    "Org monthly budget (your team, blocking): 96% used of the budget. Requests will be blocked at 100%.",
  );
});

test("noticeMessage: a sentence the daemon already rendered for token display is shown verbatim", () => {
  const n = notice({
    level: "exceeded",
    ratio: 1.2,
    enforcement: "soft",
    message: "Org daily budget (you, warning only): 120% used of the budget. Requests are not blocked.",
  });
  assert.equal(noticeMessage(n, "tokens"), n.message);
});

test("noticeMessage: a token cap reads the same in both modes", () => {
  const n = notice({ unit: "tokens", message: "Org daily budget (you, report only): 80% used - 960,000 tokens of 1,200,000 tokens. Requests are not blocked." });
  assert.equal(noticeMessage(n, "tokens"), n.message);
  assert.equal(noticeMessage(n, "usd"), n.message);
});

test("noticeMessage: the fallback names a per-tool or per-model cap (Sol A5-04)", () => {
  const tool = notice({
    level: "exceeded", enforcement: "hard", ratio: 1.05, window: "daily", subject: "tool:codex",
    message: "Spent $0.79 against $0.75.",
  });
  const got = noticeMessage(tool, "tokens");
  assert.equal(got, "Org daily budget for tool codex: 105% used of the budget. Further proxied requests, and the next prompt or tool call in tools with a pre-send hook, are blocked.");
  assert.doesNotMatch(got, /\$/);
  const model = notice({ ratio: 0.9, window: "monthly", subject: "model:gpt-5", message: "Spent $9 against $10." });
  assert.equal(noticeMessage(model, "tokens"), "Org monthly budget for model gpt-5: 90% used of the budget.");
  // The daemon's own subject sentence keeps its subject through the clause rewrite.
  const rendered = notice({
    subject: "tool:codex",
    message: "Org daily budget for tool codex (you, warning only): 80% used - $8.00 of $10.00. Requests are not blocked.",
  });
  assert.equal(
    noticeMessage(rendered, "tokens"),
    "Org daily budget for tool codex (you, warning only): 80% used of the budget. Requests are not blocked.",
  );
});

test("subjectLabel mirrors the daemon's SubjectLabel", () => {
  assert.equal(subjectLabel(undefined), "");
  assert.equal(subjectLabel(""), "");
  assert.equal(subjectLabel("tool:claude-code"), "tool claude-code");
  assert.equal(subjectLabel("model:gpt-5"), "model gpt-5");
  assert.equal(subjectLabel("odd"), "odd");
});

test("noticeMessage: an unrecognised dollar sentence falls back to a percentage-only line", () => {
  const n = notice({ level: "exceeded", enforcement: "hard", ratio: 1.05, window: "daily", message: "Spent $0.79 against $0.75." });
  const got = noticeMessage(n, "tokens");
  assert.equal(got, "Org daily budget: 105% used of the budget. Further proxied requests, and the next prompt or tool call in tools with a pre-send hook, are blocked.");
  assert.doesNotMatch(got, /\$/);
});

test("parseIdList tolerates garbage", () => {
  assert.deepEqual(parseIdList(null), []);
  assert.deepEqual(parseIdList(""), []);
  assert.deepEqual(parseIdList("{not json"), []);
  assert.deepEqual(parseIdList('{"a":1}'), []);
  assert.deepEqual(parseIdList('["a",1,"b",null]'), ["a", "b"]);
});

test("node 1: a stale exceeded notice under its cap is a warning, not a danger strip", () => {
  const v = pickBudgetWarning(
    status([
      notice({
        id: "monthly-tokens-2026-10-1",
        window: "monthly",
        unit: "tokens",
        level: "exceeded",
        enforcement: "soft",
        threshold: 1,
        ratio: 0.110238,
        spent: 1102379,
        cap: 10000000,
        scope: "team:t1",
        message: "Org monthly budget (your team, warning only): 11% used - 1,102,379 tokens of 10,000,000 tokens. Requests are not blocked.",
      }),
    ]),
  );
  assert.ok(v);
  assert.equal(v.tone, "warn");
  assert.equal(v.blocked, false);
  assert.doesNotMatch(v.label, /exceeded/i);
});

test("newerBudgetStatus keeps whichever status was written last (T-206)", () => {
  const older: BudgetStatus = { available: true, written_at: "2026-10-08T10:00:00Z" };
  const newer: BudgetStatus = { available: true, written_at: "2026-10-08T10:00:05Z" };
  assert.equal(newerBudgetStatus(null, null), null);
  assert.equal(newerBudgetStatus(null, older), older);
  assert.equal(newerBudgetStatus(older, null), older);
  assert.equal(newerBudgetStatus(older, newer), newer, "a newer poll wins over a dropped stream");
  assert.equal(newerBudgetStatus(newer, older), newer, "the stream wins over an older poll");
  assert.equal(newerBudgetStatus(newer, newer), newer);
  const unparsed: BudgetStatus = { available: false };
  assert.equal(newerBudgetStatus(unparsed, older), older);
  assert.equal(newerBudgetStatus(older, unparsed), older);
});

// A failed budget pull is visible on the machine (budget enforce consistency,
// 2026-11-19): what went wrong in words, since when, when it last worked.
test("budgetFetchNotice names a failed pull, and stays quiet on an answer", async () => {
  const { budgetFetchNotice, guardModeLink, GUARD_MODE_LINK } = await import("./budgetWarning.ts");
  const now = new Date("2026-11-19T12:00:00Z");
  const failed = budgetFetchNotice(
    { available: true, fetch: { state: "unreachable", failing_since: "2026-11-19T11:40:00Z", last_ok_at: "2026-11-19T09:00:00Z" } },
    now,
  );
  assert.ok(failed);
  assert.match(failed.text, /could not get your organization's budgets since 20 min ago: the request failed/);
  assert.match(failed.text, /last got them 3 h ago/);
  assert.doesNotMatch(failed.text, /\b[a-z]+_[a-z_]+\b/);
  for (const state of ["ok", "disabled", "no_budget", "not_enrolled"]) {
    assert.equal(budgetFetchNotice({ available: true, fetch: { state } }, now), null, state);
  }
  assert.equal(budgetFetchNotice({ available: true }, now), null);
  assert.equal(budgetFetchNotice(null, now), null);
  assert.match(budgetFetchNotice({ available: true, fetch: { state: "auth_failed" } }, now)!.text, /has not got them since/);
  // The warning-only-here notice links to Guard mode.
  assert.equal(guardModeLink({ enforcement: "hard", effect: "warn_observe" } as never), GUARD_MODE_LINK);
  assert.equal(guardModeLink({ enforcement: "hard", effect: "warn_guard_off" } as never), GUARD_MODE_LINK);
  assert.equal(guardModeLink({ enforcement: "hard", effect: "blocks" } as never), null);
});

// U-33 (UI review 2026-11-21): a fresh organization with no policy signing
// key answers every budget pull 409 (channel_off), the explicit "no budget"
// included, because it cannot sign anything. A machine no organization cap
// governs gets no warning; a machine whose cap stopped refreshing does.
test("budgetFetchNotice: channel_off warns only while an organization cap is in force (U-33)", async () => {
  const { budgetFetchNotice } = await import("./budgetWarning.ts");
  const now = new Date("2026-11-21T12:00:00Z");
  const fetch = { state: "channel_off", failing_since: "2026-11-21T11:59:00Z" };
  assert.equal(budgetFetchNotice({ available: true, fetch }, now), null, "fresh org, no budget: no warning");
  assert.equal(budgetFetchNotice({ available: true, windows: [], fetch }, now), null);
  const cap = { window: "day", unit: "usd", period: "calendar_day", cap: 10, spent: 1, ratio: 0.1, scope: "member", enforcement: "soft", level: "ok", crossed: 0 };
  const held = budgetFetchNotice({ available: true, windows: [cap as never], fetch }, now);
  assert.ok(held, "a cap in force that stopped refreshing still warns");
  assert.match(held.text, /cannot sign budgets yet/);
  // Every other failure warns with or without caps.
  assert.ok(budgetFetchNotice({ available: true, fetch: { state: "unreachable" } }, now));
});
