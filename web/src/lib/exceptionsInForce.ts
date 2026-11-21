// exceptionsInForce.ts - the Requests page's "Exceptions in force on this
// machine" card (round-3 demo bug: a live budget increase was missing and the
// card read "No exceptions"). Pure: no React, no fetch.
//
// An exception reaches a node on one of two rails, and the card lists both:
//   - the grant rail (GET /api/requests `grants`): guard exemptions, tools,
//     models, features, pages, config edits, components; each with whether
//     the node honours it now and why not;
//   - the budget rail (GET /api/requests `budgets`): a budget increase is
//     folded into the budget's cap the org signs, so it never appears on the
//     grant rail. A budget carrying grant_id is raised by that grant right
//     now (the daemon already dropped one past its end), and it reads as base
//     plus increase, the same words its request row uses.

import { budgetName } from "./requestRows.ts";
import { baseBudget, grantIncrease, increaseWords, type RequestableBudget } from "./requestBudgets.ts";

/** ExceptionGrant is one grant-rail grant as GET /api/requests sends it. */
export type ExceptionGrant = {
  grant: {
    id: number;
    type: string;
    effect?: string;
    rule_id?: string;
    lane?: string;
    command_class?: string;
    operand_hash?: string;
    project_root_hash?: string;
    target?: string;
    expires_at_ns?: number;
    max_uses?: number;
  };
  uses_used: number;
  honoured: boolean;
  reason?: string;
  /** Another grant in force that already gives everything this one gives. */
  covered_by?: number;
};

/** ExceptionType is the label table the card names a grant's type from. */
export type ExceptionType = { id: string; label: string };

/** ExceptionRow is one line of the card. */
export type ExceptionRow = {
  key: string;
  grantId: number;
  /** What it allows or raises, after the type's label. */
  what: string;
  effect?: string;
  /** When it ends (absent: no expiry). */
  expiresAtNs?: number;
  maxUses?: number;
  usesUsed: number;
  honoured: boolean;
  /** Why it is not in force (accessgrant reason), when it is not. */
  reason?: string;
  /** The raw id behind a named detail, for the tooltip. */
  title?: string;
  /** How far a guard exemption reaches, when it is narrower than the whole
   *  rule ("one exact command, one project"). A grant that reads the same as
   *  another but reaches less is not the same exception. */
  scope?: string;
  /** The grant in force that already gives everything this one gives. */
  coveredBy?: number;
};

/** BUDGET_INCREASE is the request type a budget-rail grant answers. */
export const BUDGET_INCREASE = "budget_increase";

function typeLabel(type: string, types: readonly ExceptionType[]): string {
  return types.find((t) => t.id === type)?.label ?? type;
}

/** grantWhat names a grant-rail grant: its type's label, then its rule or
 *  target. */
export function grantWhat(g: { type: string; rule_id?: string; target?: string }, types: readonly ExceptionType[]): string {
  const label = typeLabel(g.type, types);
  if (g.rule_id) return `${label}: ${g.rule_id}`;
  if (g.target) return `${label}: ${g.target}`;
  return label;
}

/** SCOPE_RULES is the table a guard exemption's reach is worded from, in the
 *  order the words appear. The narrowest command pin wins its row (an exact
 *  command is also a command class). */
const SCOPE_RULES: { holds: (g: ExceptionGrant["grant"]) => boolean; words: (g: ExceptionGrant["grant"]) => string }[] = [
  { holds: (g) => Boolean(g.operand_hash), words: () => "one exact command" },
  { holds: (g) => !g.operand_hash && Boolean(g.command_class), words: () => "one kind of command" },
  { holds: (g) => Boolean(g.lane) && g.lane !== "all", words: (g) => `${g.lane} lane only` },
  { holds: (g) => Boolean(g.project_root_hash), words: () => "one project" },
];

/** grantScope words how far a grant reaches; "" when it reaches everything
 *  its type and rule name. */
export function grantScope(g: ExceptionGrant["grant"]): string {
  return SCOPE_RULES.filter((r) => r.holds(g))
    .map((r) => r.words(g))
    .join(", ");
}

/** budgetIncreaseWhat names a budget a live grant raised, as base plus
 *  increase: "Budget increase: Your budget, monthly, 100000.00 USD
 *  (+10.00 USD)". */
export function budgetIncreaseWhat(b: RequestableBudget, types: readonly ExceptionType[], dollars: boolean): string {
  const inc = grantIncrease(b);
  return `${typeLabel(BUDGET_INCREASE, types)}: ${budgetName(baseBudget(b), dollars)}${increaseWords(inc.tokens, inc.usd, dollars)}`;
}

/** budgetIncreasesInForce lists the budget increases raising a budget at
 *  nowNs, one per grant: a grant past its end on this clock is gone (the
 *  enforcer reverts it without a fetch), and a grant the grant rail already
 *  lists is not listed twice. */
export function budgetIncreasesInForce(
  budgets: readonly RequestableBudget[],
  types: readonly ExceptionType[],
  nowNs: number,
  dollars: boolean,
  listed: ReadonlySet<number> = new Set(),
): ExceptionRow[] {
  const out: ExceptionRow[] = [];
  const seen = new Set(listed);
  for (const b of budgets) {
    if (!b.grant_id || seen.has(b.grant_id)) continue;
    if (b.grant_expires_at_ns && b.grant_expires_at_ns <= nowNs) continue;
    seen.add(b.grant_id);
    out.push({
      key: `budget-${b.grant_id}`,
      grantId: b.grant_id,
      what: budgetIncreaseWhat(b, types, dollars),
      expiresAtNs: b.grant_expires_at_ns || undefined,
      usesUsed: 0,
      honoured: true,
      title: `budget ${b.budget_id}`,
    });
  }
  return out;
}

/** exceptionRows is the whole card: grant-rail grants in force, then budget
 *  increases in force, then grant-rail grants not in force. Empty means
 *  "No exceptions". */
export function exceptionRows(
  grants: readonly ExceptionGrant[],
  budgets: readonly RequestableBudget[],
  types: readonly ExceptionType[],
  nowNs: number,
  dollars: boolean,
): ExceptionRow[] {
  const row = (g: ExceptionGrant): ExceptionRow => ({
    key: `grant-${g.grant.id}`,
    grantId: g.grant.id,
    what: grantWhat(g.grant, types),
    effect: g.grant.effect,
    expiresAtNs: g.grant.expires_at_ns,
    maxUses: g.grant.max_uses,
    usesUsed: g.uses_used,
    honoured: g.honoured,
    reason: g.reason,
    scope: grantScope(g.grant) || undefined,
    coveredBy: g.honoured && g.covered_by ? g.covered_by : undefined,
  });
  const listed = new Set(grants.map((g) => g.grant.id));
  return [
    ...grants.filter((g) => g.honoured).map(row),
    ...budgetIncreasesInForce(budgets, types, nowNs, dollars, listed),
    ...grants.filter((g) => !g.honoured).map(row),
  ];
}
