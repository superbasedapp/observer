// requestBudgets.ts - the budget picker on a budget-increase request (T-523,
// D-334; the request/grant lane's Q4 before it). A developer on an
// org-managed node never types a budget id: the options are the budgets the
// node's verified budget rail names (GET /api/requests `budgets`), each with
// what the node measured against it this period, and the picker defaults to
// the one that ran out. Picking none leaves the choice to the organization:
// the org server fills in the caller's one fitting budget, else the approver
// picks. Pure: no React, no fetch.

export type BudgetLevel = "ok" | "warning" | "exceeded";

export type RequestableBudget = {
  budget_id: string;
  scope: string;
  period: string;
  subject?: { kind: string; id: string };
  cap_tokens?: number;
  cap_usd?: number;
  timezone?: string;
  enforcement?: string;
  /** false for a pool shared with others (org, team, an org-wide tool or
   *  model): a grant cannot raise it for one member, so the request asks the
   *  approver to raise it for everyone. Absent on an older daemon, which
   *  only ever listed grantable budgets. */
  grantable?: boolean;
  /** The worst warning level measured against it this period. */
  level?: BudgetLevel;
  ratio?: number;
  /** How far spend is past the cap, per unit (rounded up). */
  over_tokens?: number;
  over_usd?: number;
  /** When the budget's current period ends (a budget increase lasts at most
   *  until then, D-081). */
  period_end_ns?: number;
  /** The org budget-increase grant raising this budget right now (absent
   *  when none does, or on an older daemon). While it is set, cap_tokens /
   *  cap_usd are the RAISED caps and base_cap_tokens / base_cap_usd the
   *  budget's own; grant_expires_at_ns is when the increase ends (absent for
   *  a perpetual one). */
  grant_id?: number;
  base_cap_tokens?: number;
  base_cap_usd?: number;
  grant_expires_at_ns?: number;
};

const PERIOD_WORDS: Record<string, string> = {
  calendar_month: "monthly",
  calendar_day: "daily",
  rolling_30d: "rolling 30 days",
};

/** scopeWords names whose budget it is, as the developer reads it. */
export function scopeWords(scope: string): string {
  if (scope === "org") return "Organization budget";
  if (scope.startsWith("member:")) return "Your budget";
  if (scope.startsWith("team:")) return `Team budget (${scope.slice("team:".length)})`;
  if (scope.startsWith("tool:")) return `Organization budget for tool ${scope.slice("tool:".length)}`;
  if (scope.startsWith("model:")) return `Organization budget for model ${scope.slice("model:".length)}`;
  return "Budget";
}

/** isGrantable: a daemon that predates the flag listed only grantable ones. */
export function isGrantable(b: RequestableBudget): boolean {
  return b.grantable !== false;
}

function compactTokens(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(0)}k`;
  return String(n);
}

/** capWords is the cap in its own unit: tokens first (the unit a token cap
 *  is authored in), else USD. `dollars` is the cost display mode
 *  (dollarsShown()): on a token-usage org policy, or one still pending
 *  (D-013 / D-179), a dollar-only cap reads "a spend cap" with no amount. */
export function capWords(b: RequestableBudget, dollars: boolean): string {
  if (b.cap_tokens) return `${compactTokens(b.cap_tokens)} tokens`;
  if (b.cap_usd) return dollars ? `${b.cap_usd.toFixed(2)} USD` : "a spend cap";
  return "no cap";
}

/** baseBudget is b at its own caps: a budget a live budget-increase grant
 *  raised reads its base, so a surface can name it as base plus increase
 *  ("100000.00 USD (+10.00 USD)") without counting the increase twice. A
 *  budget no grant raises is returned as it is. */
export function baseBudget(b: RequestableBudget): RequestableBudget {
  if (!b.grant_id) return b;
  return { ...b, cap_tokens: b.base_cap_tokens, cap_usd: b.base_cap_usd };
}

/** increaseWords is an increase in its own unit, with a leading space:
 *  " (+500,000 tokens)" or " (+10.00 USD)"; tokens first, dollars only where
 *  the org shows dollars (D-013 / D-179); "" for none. */
export function increaseWords(tokens: number | undefined, usd: number | undefined, dollars: boolean): string {
  if (tokens && tokens > 0) return ` (+${tokens.toLocaleString()} tokens)`;
  if (usd && usd > 0.005 && dollars) return ` (+${usd.toFixed(2)} USD)`;
  return "";
}

/** grantIncrease is how much a live budget-increase grant raises b, per
 *  unit (zero when no grant raises it). */
export function grantIncrease(b: RequestableBudget): { tokens: number; usd: number } {
  if (!b.grant_id) return { tokens: 0, usd: 0 };
  const tokens = b.cap_tokens && b.base_cap_tokens ? Math.max(0, b.cap_tokens - b.base_cap_tokens) : 0;
  const usd = b.cap_usd && b.base_cap_usd ? Math.max(0, b.cap_usd - b.base_cap_usd) : 0;
  return { tokens, usd };
}

/** levelWords is the budget's state this period with the current use, so the
 *  prefilled pick says how much of the cap is used ("exceeded (120% used)",
 *  "85% used"); "" when unmeasured. A reading under the cap is never called
 *  exceeded, whatever level an older daemon reported. */
export function levelWords(b: RequestableBudget): string {
  const pct = typeof b.ratio === "number" && Number.isFinite(b.ratio) && b.ratio > 0 ? Math.round(b.ratio * 100) : undefined;
  if (b.level === "exceeded" && (pct === undefined || pct >= 100)) {
    return pct === undefined ? "exceeded" : `exceeded (${pct}% used)`;
  }
  return pct === undefined ? "" : `${pct}% used`;
}

/** budgetOptionLabel is one option of the picker, e.g.
 *  "Your budget, monthly, 1.0M tokens, exceeded" or
 *  "Team budget (eng), daily, for tool codex, 200k tokens (shared)". */
export function budgetOptionLabel(b: RequestableBudget, dollars: boolean): string {
  const parts = [scopeWords(b.scope), PERIOD_WORDS[b.period] ?? b.period];
  if (b.subject) parts.push(`for ${b.subject.kind} ${b.subject.id}`);
  parts.push(capWords(b, dollars));
  const level = levelWords(b);
  if (level) parts.push(level);
  const label = parts.join(", ");
  return isGrantable(b) ? label : `${label} (shared)`;
}

/** NO_BUDGET is the picker's "let the organization pick" value. */
export const NO_BUDGET = "";

/** budgetOptions is the picker's option list: one option per budget, then
 *  the organization's choice. */
export function budgetOptions(budgets: readonly RequestableBudget[], dollars: boolean): { value: string; label: string }[] {
  return [
    ...budgets.map((b) => ({ value: b.budget_id, label: budgetOptionLabel(b, dollars) })),
    { value: NO_BUDGET, label: "Not sure: let the organization pick" },
  ];
}

const LEVEL_ORDER: Record<string, number> = { exceeded: 2, warning: 1 };

/** defaultBudgetId is the picker's starting choice: the asked-for budget when
 *  the node knows it; else the one that ran out (your own before a shared
 *  pool, then the furthest over); else your only budget; else the
 *  organization picks. */
export function defaultBudgetId(budgets: readonly RequestableBudget[], asked?: string): string {
  if (asked && budgets.some((b) => b.budget_id === asked)) return asked;
  const ranked = budgets
    .filter((b) => (LEVEL_ORDER[b.level ?? ""] ?? 0) > 0)
    .map((b, i) => ({ b, i }))
    .sort(
      (x, y) =>
        (LEVEL_ORDER[y.b.level ?? ""] ?? 0) - (LEVEL_ORDER[x.b.level ?? ""] ?? 0) ||
        Number(isGrantable(y.b)) - Number(isGrantable(x.b)) ||
        (y.b.ratio ?? 0) - (x.b.ratio ?? 0) ||
        x.i - y.i,
    );
  if (ranked.length > 0) return ranked[0]!.b.budget_id;
  const own = budgets.filter(isGrantable);
  return own.length === 1 ? own[0]!.budget_id : NO_BUDGET;
}

/** budgetAmountFields says which amount fields the dialog offers for the
 *  picked budget: its own units only (a delta in a unit the budget has no cap
 *  in is refused at the approver), and never dollars where the org shows
 *  developers token usage (D-013 / D-179). With no budget picked, tokens and
 *  (when shown) dollars. */
export function budgetAmountFields(picked: RequestableBudget | undefined, dollars: boolean): { tokens: boolean; usd: boolean } {
  if (!picked) return { tokens: true, usd: dollars };
  return { tokens: Boolean(picked.cap_tokens), usd: dollars && Boolean(picked.cap_usd) };
}

/** budgetDeltaHelp is the help line under the amount, or the line that
 *  stands in for it when the dialog can offer no amount field. */
export function budgetDeltaHelp(dollars: boolean, picked: RequestableBudget | undefined): string | undefined {
  const f = budgetAmountFields(picked, dollars);
  if (!f.tokens && !f.usd) {
    return "This budget is a spend cap. Say in your message how much more you need; the approver sets the amount.";
  }
  if (!dollars && !picked) return "Ask in tokens. The approver can also raise a spend cap and sets the amount.";
  return undefined;
}

/** budgetPickNote explains a pick the developer should understand before
 *  sending: a shared pool, or no budget known at all. */
export function budgetPickNote(picked: RequestableBudget | undefined, known: number): string | undefined {
  if (picked && !isGrantable(picked)) {
    return "This budget is shared with others, so a grant cannot raise it for you alone. Your request asks the approver to raise it for everyone, or to answer you.";
  }
  if (known === 0) {
    return "This machine has not received your organization's budgets yet, so the organization picks which of your budgets to raise.";
  }
  return undefined;
}

/** BudgetSuggestion is what the dialog prefills for a picked budget (T-522):
 *  the window until the period ends (the most a budget increase may last,
 *  D-081) and the amount spend is over the cap, in the units the dialog
 *  offers. */
export type BudgetSuggestion = { duration_s?: number; delta_tokens?: number; delta_usd?: number };

/** budgetSuggestion prefills a request for b at nowNs; empty when nothing is
 *  known. The amount over brings spend back to exactly the cap; the developer
 *  can ask for more. */
export function budgetSuggestion(b: RequestableBudget | undefined, dollars: boolean, nowNs: number): BudgetSuggestion {
  if (!b) return {};
  const out: BudgetSuggestion = {};
  const left = b.period_end_ns ? Math.floor((b.period_end_ns - nowNs) / 1e9) : 0;
  if (left > 0) out.duration_s = left;
  const f = budgetAmountFields(b, dollars);
  if (f.tokens && b.over_tokens && b.over_tokens > 0) out.delta_tokens = b.over_tokens;
  if (f.usd && b.over_usd && b.over_usd > 0) out.delta_usd = b.over_usd;
  return out;
}

/** budgetDurationOptions are the "For how long?" choices for a budget
 *  increase: the fixed presets that end before the period does, then "until
 *  the period ends" when the period end is known. */
export function budgetDurationOptions(
  presets: readonly { value: string; label: string }[],
  periodLeftS: number | undefined,
  human: (s: number) => string,
): { value: string; label: string }[] {
  if (!periodLeftS || periodLeftS <= 0) return [...presets];
  return [
    ...presets.filter((p) => Number(p.value) < periodLeftS),
    { value: String(periodLeftS), label: `Until this budget period ends (${human(periodLeftS)})` },
  ];
}
