// Pins the Requests page's "Exceptions in force on this machine" card: a live
// budget increase (budget rail) is an exception in force beside the grant-rail
// grants, worded as base plus increase (round-3 demo bug).
import { test } from "node:test";
import assert from "node:assert/strict";
import { budgetIncreaseWhat, exceptionRows, grantScope, grantWhat, type ExceptionGrant } from "./exceptionsInForce.ts";
import type { RequestableBudget } from "./requestBudgets.ts";

const DAY = 86400 * 1e9;
const now = Date.UTC(2026, 10, 10, 12, 0, 0) * 1e6;
const types = [
  { id: "budget_increase", label: "Budget increase" },
  { id: "guard_exemption", label: "Guard exemption" },
  { id: "tool_allow", label: "Tool access" },
];
const raised: RequestableBudget = {
  budget_id: "ed5ae4537978df4a2059a40141a4a230",
  scope: "member:u1",
  period: "calendar_month",
  cap_usd: 100010,
  grant_id: 6,
  base_cap_usd: 100000,
  grant_expires_at_ns: now + 3 * DAY,
};
const plain: RequestableBudget = { budget_id: "b-day", scope: "member:u1", period: "calendar_day", cap_tokens: 200_000 };
const exemption: ExceptionGrant = {
  grant: { id: 2, type: "guard_exemption", effect: "exempt", rule_id: "R-170", expires_at_ns: now + DAY },
  uses_used: 0,
  honoured: true,
};
const stale: ExceptionGrant = { grant: { id: 4, type: "tool_allow", target: "codex" }, uses_used: 0, honoured: false, reason: "stale" };

test("a budget increase reads base plus increase", () => {
  const cases: { name: string; b: RequestableBudget; dollars: boolean; want: string }[] = [
    { name: "dollars", b: raised, dollars: true, want: "Budget increase: Your budget, monthly, 100000.00 USD (+10.00 USD)" },
    { name: "token usage display hides dollars", b: raised, dollars: false, want: "Budget increase: Your budget, monthly, a spend cap" },
    {
      name: "tokens",
      b: { budget_id: "b-t", scope: "member:u1", period: "calendar_month", cap_tokens: 1_500_000, grant_id: 7, base_cap_tokens: 1_000_000 },
      dollars: true,
      want: `Budget increase: Your budget, monthly, 1.0M tokens (+${(500_000).toLocaleString()} tokens)`,
    },
  ];
  for (const c of cases) assert.equal(budgetIncreaseWhat(c.b, types, c.dollars), c.want, c.name);
});

test("the card lists what is in force on both rails, then what is not", () => {
  const cases: {
    name: string;
    grants: ExceptionGrant[];
    budgets: RequestableBudget[];
    want: { key: string; what: string; honoured: boolean; expiresAtNs?: number }[];
  }[] = [
    { name: "nothing at all reads no exceptions", grants: [], budgets: [plain], want: [] },
    {
      name: "a live budget increase alone is an exception in force",
      grants: [],
      budgets: [plain, raised],
      want: [
        { key: "budget-6", what: "Budget increase: Your budget, monthly, 100000.00 USD (+10.00 USD)", honoured: true, expiresAtNs: now + 3 * DAY },
      ],
    },
    {
      name: "a budget increase past its end on this clock is gone",
      grants: [],
      budgets: [{ ...raised, grant_expires_at_ns: now - 1e9 }],
      want: [],
    },
    {
      name: "a perpetual budget increase has no end",
      grants: [],
      budgets: [{ ...raised, grant_expires_at_ns: undefined }],
      want: [{ key: "budget-6", what: "Budget increase: Your budget, monthly, 100000.00 USD (+10.00 USD)", honoured: true }],
    },
    {
      name: "grant-rail in force, then budget increases, then not in force",
      grants: [stale, exemption],
      budgets: [raised],
      want: [
        { key: "grant-2", what: "Guard exemption: R-170", honoured: true, expiresAtNs: now + DAY },
        { key: "budget-6", what: "Budget increase: Your budget, monthly, 100000.00 USD (+10.00 USD)", honoured: true, expiresAtNs: now + 3 * DAY },
        { key: "grant-4", what: "Tool access: codex", honoured: false },
      ],
    },
    {
      name: "a grant both rails name is listed once",
      grants: [{ grant: { id: 6, type: "budget_increase" }, uses_used: 0, honoured: true }],
      budgets: [raised],
      want: [{ key: "grant-6", what: "Budget increase", honoured: true }],
    },
  ];
  for (const c of cases) {
    const got = exceptionRows(c.grants, c.budgets, types, now, true).map((r) => ({
      key: r.key,
      what: r.what,
      honoured: r.honoured,
      ...(r.expiresAtNs ? { expiresAtNs: r.expiresAtNs } : {}),
    }));
    assert.deepEqual(got, c.want, c.name);
  }
});

test("grantWhat names a grant by rule, then target, then type", () => {
  assert.equal(grantWhat({ type: "guard_exemption", rule_id: "R-1" }, types), "Guard exemption: R-1");
  assert.equal(grantWhat({ type: "tool_allow", target: "codex" }, types), "Tool access: codex");
  assert.equal(grantWhat({ type: "unknown_type" }, types), "unknown_type");
});

test("a guard exemption says how far it reaches", () => {
  const cases: { name: string; grant: ExceptionGrant["grant"]; want: string }[] = [
    { name: "rule-wide everywhere", grant: { id: 1, type: "guard_exemption", rule_id: "S-793" }, want: "" },
    { name: "rule-wide in one project", grant: { id: 11, type: "guard_exemption", rule_id: "S-793", project_root_hash: "p1" }, want: "one project" },
    {
      name: "one exact command (the operand wins over its class)",
      grant: { id: 8, type: "guard_exemption", rule_id: "S-793", command_class: "/shell_exec", operand_hash: "e59e", project_root_hash: "p1" },
      want: "one exact command, one project",
    },
    { name: "one command class", grant: { id: 2, type: "guard_exemption", rule_id: "S-793", command_class: "/shell_exec" }, want: "one kind of command" },
    { name: "one lane", grant: { id: 3, type: "guard_exemption", rule_id: "S-793", lane: "prompt" }, want: "prompt lane only" },
    { name: "lane all is every lane", grant: { id: 4, type: "guard_exemption", rule_id: "S-793", lane: "all" }, want: "" },
  ];
  for (const c of cases) assert.equal(grantScope(c.grant), c.want, c.name);
});

test("a grant another grant in force already covers says which", () => {
  // The machine in the 2026-11-13 report: S-793 held three times.
  const g = (id: number, extra: Partial<ExceptionGrant["grant"]>, covered_by?: number, honoured = true): ExceptionGrant => ({
    grant: { id, type: "guard_exemption", effect: "exempt", rule_id: "S-793", project_root_hash: "p1", ...extra },
    uses_used: 0,
    honoured,
    covered_by,
  });
  const rows = exceptionRows([g(8, { operand_hash: "e59e" }, 11), g(11, {}), g(15, {}, 11), g(20, {}, 11, false)], [], types, now, true);
  assert.deepEqual(
    rows.map((r) => ({ id: r.grantId, scope: r.scope, coveredBy: r.coveredBy })),
    [
      { id: 8, scope: "one exact command, one project", coveredBy: 11 },
      { id: 11, scope: "one project", coveredBy: undefined },
      { id: 15, scope: "one project", coveredBy: 11 },
      // A grant that is not in force is not "the same as" anything.
      { id: 20, scope: "one project", coveredBy: undefined },
    ],
  );
});
