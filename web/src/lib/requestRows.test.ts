// Pins how the Requests page reads a request (demo findings #20, #27, #28).
import { test } from "node:test";
import assert from "node:assert/strict";
import { requestAsk, requestOutcome, shortId, splitRequests, RECENT_FINISHED_DAYS, type RequestRowInput } from "./requestRows.ts";
import type { RequestableBudget } from "./requestBudgets.ts";

const DAY = 86400 * 1e9;
const now = Date.UTC(2026, 10, 10, 12, 0, 0) * 1e6;
const granted = (grant: Partial<NonNullable<RequestRowInput["grant"]>>, extra: Partial<RequestRowInput> = {}): RequestRowInput => ({
  id: 5,
  kind: "raise_budget",
  status: "granted",
  created_at: new Date((now - DAY) / 1e6).toISOString(),
  resolved_at: new Date((now - DAY) / 1e6).toISOString(),
  grant: { id: 3, type: "budget_increase", status: "active", starts_at_ns: now - DAY, expires_at_ns: now + 7 * DAY, subject_kind: "member", ...grant },
  ...extra,
});

test("a live grant reads granted with the time left", () => {
  const o = requestOutcome(granted({}), now);
  assert.equal(o.status, "granted");
  assert.equal(o.tone, "success");
  assert.match(o.answer, /^Granted as G-3, until .* \(7d left\)$/);
  assert.equal(o.finished, false);
});

test("a revoked grant reads revoked, with when and the admin's reason (#27)", () => {
  const at = now - 2 * 3600 * 1e9;
  const o = requestOutcome(granted({ status: "revoked", revoked_at_ns: at, revoke_reason: "budget deleted" }), now);
  assert.equal(o.status, "revoked");
  assert.equal(o.tone, "danger");
  assert.ok(o.answer.startsWith("Granted as G-3, revoked by your organization on "), o.answer);
  assert.ok(o.answer.endsWith("Reason: budget deleted"), o.answer);
  assert.ok(!o.answer.includes("left"), o.answer);
  assert.equal(o.finished, true);
  assert.equal(o.finishedAtNs, at);
});

test("a grant an extension replaced reads replaced, not revoked", () => {
  const at = now - 2 * 3600 * 1e9;
  const cases: { name: string; grant: Partial<NonNullable<RequestRowInput["grant"]>>; status: string; answer: RegExp }[] = [
    {
      name: "replaced, with when",
      grant: { status: "revoked", revoked_at_ns: at, revoke_reason: "superseded by G-6" },
      status: "replaced",
      answer: /^Granted as G-3, replaced by G-6 on .+$/,
    },
    { name: "replaced, no time", grant: { status: "revoked", revoke_reason: "superseded by G-6" }, status: "replaced", answer: /^Granted as G-3, replaced by G-6$/ },
    {
      name: "a reason that only mentions superseded stays a revoke",
      grant: { status: "revoked", revoke_reason: "superseded by the new policy" },
      status: "revoked",
      answer: /^Granted as G-3, revoked by your organization\. Reason: superseded by the new policy$/,
    },
  ];
  for (const c of cases) {
    const o = requestOutcome(granted(c.grant), now);
    assert.equal(o.status, c.status, c.name);
    assert.match(o.answer, c.answer, c.name);
    assert.ok(!o.answer.includes("Reason: superseded by G-"), c.name);
    assert.equal(o.finished, true, c.name);
  }
  const o = requestOutcome(granted({ status: "revoked", revoked_at_ns: at, revoke_reason: "superseded by G-6" }), now);
  assert.equal(o.tone, "neutral");
  assert.equal(o.finishedAtNs, at);
});

test("a revoke from a server that sends no time or reason still reads revoked", () => {
  const o = requestOutcome(granted({ status: "revoked" }), now);
  assert.equal(o.status, "revoked");
  assert.equal(o.answer, "Granted as G-3, revoked by your organization");
});

test("a grant past its end reads expired, never 0m left, whatever the server last said", () => {
  for (const status of ["active", "expired"]) {
    const o = requestOutcome(granted({ status, expires_at_ns: now - 1e9 }), now);
    assert.equal(o.status, "expired", status);
    assert.match(o.answer, /^Granted as G-3, expired /);
    assert.ok(!o.answer.includes("left"), o.answer);
  }
});

test("an exhausted grant reads used up", () => {
  const o = requestOutcome(granted({ status: "exhausted", max_uses: 3 }), now);
  assert.equal(o.status, "used up");
  assert.equal(o.answer, "Granted as G-3, all 3 uses spent");
});

test("the last minute reads under a minute, not 0m", () => {
  const o = requestOutcome(granted({ expires_at_ns: now + 20e9 }), now);
  assert.match(o.answer, /\(under a minute left\)$/);
});

test("a request without a grant keeps its own status and note", () => {
  const o = requestOutcome({ id: 1, kind: "other", status: "declined", created_at: "2026-11-01T00:00:00Z", resolution_note: "not this quarter" }, now);
  assert.deepEqual([o.status, o.tone, o.answer, o.finished], ["declined", "danger", "not this quarter", true]);
  const open = requestOutcome({ id: 2, kind: "other", status: "open", created_at: "2026-11-01T00:00:00Z" }, now);
  assert.equal(open.finished, false);
});

const budget: RequestableBudget = { budget_id: "ed5ae4537978df4a2059a40141a4a230", scope: "member:u1", period: "calendar_month", cap_usd: 2000 };

test("a budget increase names its budget, keeping the id in the tooltip (#20)", () => {
  const r = granted({}, { request_type: "budget_increase", target: budget.budget_id, payload: { budget_id: budget.budget_id, delta_usd: 500 } });
  const a = requestAsk(r, [budget], true);
  assert.equal(a.detail, ": Your budget, monthly, 2000.00 USD (+500.00 USD)");
  assert.equal(a.title, `budget ${budget.budget_id}`);
  assert.ok(!a.detail.includes(budget.budget_id));
});

test("a budget increase reads base plus increase on every row, live grant or not", () => {
  // The budget as this machine holds it while G-3 raises it: the cap is the
  // raised one, the base travels beside it.
  const raised: RequestableBudget = { ...budget, cap_usd: 2500, grant_id: 3, base_cap_usd: 2000, grant_expires_at_ns: now + 7 * DAY };
  const payload = { budget_id: budget.budget_id, delta_usd: 500 };
  const want = ": Your budget, monthly, 2000.00 USD (+500.00 USD)";
  const cases: { name: string; r: RequestRowInput; budgets: RequestableBudget[] }[] = [
    { name: "active, raised by this grant", r: granted({}, { request_type: "budget_increase", payload }), budgets: [raised] },
    {
      name: "active, raised by a later grant",
      r: granted({}, { request_type: "budget_increase", payload }),
      budgets: [{ ...raised, grant_id: 9, cap_usd: 3000 }],
    },
    { name: "revoked, budget back at its base", r: granted({ status: "revoked" }, { request_type: "budget_increase", payload }), budgets: [budget] },
    {
      name: "expired, budget back at its base",
      r: granted({ expires_at_ns: now - DAY }, { request_type: "budget_increase", payload }),
      budgets: [budget],
    },
    { name: "open, nothing granted yet", r: { id: 9, kind: "raise_budget", status: "open", created_at: "", request_type: "budget_increase", payload }, budgets: [budget] },
  ];
  for (const c of cases) assert.equal(requestAsk(c.r, c.budgets, true).detail, want, c.name);
  const tokens: RequestableBudget = { ...budget, cap_usd: undefined, cap_tokens: 1_500_000, grant_id: 3, base_cap_tokens: 1_000_000 };
  const r = granted({}, { request_type: "budget_increase", payload: { budget_id: budget.budget_id, delta_tokens: 500_000 } });
  assert.equal(requestAsk(r, [tokens], true).detail, `: Your budget, monthly, 1.0M tokens (+${(500_000).toLocaleString()} tokens)`);
});

test("an unknown budget falls back to a short id", () => {
  const r = granted({}, { request_type: "budget_increase", target: budget.budget_id });
  const a = requestAsk(r, [], true);
  assert.equal(a.detail, ` ${shortId(budget.budget_id)}`);
  assert.equal(a.detail, " ed5ae453…");
  assert.match(a.title ?? "", /ed5ae4537978df4a2059a40141a4a230/);
});

test("dollars stay hidden where the org shows token usage", () => {
  const r = granted({}, { request_type: "budget_increase", payload: { budget_id: budget.budget_id, delta_usd: 500 } });
  assert.equal(requestAsk(r, [budget], false).detail, ": Your budget, monthly, a spend cap");
});

test("other asks keep the rule or target", () => {
  assert.equal(requestAsk({ id: 1, kind: "other", status: "open", created_at: "", payload: { rule_id: "R-170" } }, [], true).detail, " R-170");
  assert.equal(requestAsk({ id: 1, kind: "allow_tool", status: "open", created_at: "", target: "codex" }, [], true).detail, " codex");
});

test("finished requests older than the recent window fold into History (#28)", () => {
  const old = new Date((now - (RECENT_FINISHED_DAYS + 1) * DAY) / 1e6).toISOString();
  const recent = new Date((now - DAY) / 1e6).toISOString();
  const rows: RequestRowInput[] = [
    { id: 1, kind: "other", status: "open", created_at: old },
    { id: 2, kind: "other", status: "declined", created_at: old, resolved_at: old },
    { id: 3, kind: "other", status: "withdrawn", created_at: recent, resolved_at: recent },
    granted({ status: "revoked", revoked_at_ns: now - (RECENT_FINISHED_DAYS + 2) * DAY }, { id: 4 }),
    granted({ status: "revoked", revoked_at_ns: now - DAY }, { id: 5 }),
    granted({}, { id: 6, created_at: old, resolved_at: old }),
    granted({ expires_at_ns: now - (RECENT_FINISHED_DAYS + 1) * DAY }, { id: 7 }),
    { id: 8, kind: "other", status: "lapsed", created_at: old },
  ];
  const { current, history } = splitRequests(rows, now);
  assert.deepEqual(current.map((r) => r.id), [1, 3, 5, 6]);
  assert.deepEqual(history.map((r) => r.id), [2, 4, 7, 8]);
});
