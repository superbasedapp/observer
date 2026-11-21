// The organization's app budgets on this machine (Plane A W4-1): the pure
// words of OrgAppBudgetCard. The org authors caps on its app's end users and
// services on its Budgets page; the signed budget pull delivers them here,
// where the admission check applies them. An end user is shown only as the
// org-bound key's prefix: the raw id never reaches the machine.

/** One org app cap, as GET /api/obs/admission/budget returns it. */
export type OrgAppCap = {
  scope: "end_user" | "service" | "end_user_service" | string;
  end_user?: string;
  service?: string;
  period: string;
  cap_usd?: number;
  cap_tokens?: number;
  enforcement: "soft" | "hard" | string;
  budget_id?: string;
};

const PERIOD_WORDS: Record<string, string> = { calendar_day: "per day", calendar_month: "per month" };

/** orgAppCapWho names what one cap applies to, in plain words. */
export function orgAppCapWho(c: OrgAppCap): string {
  const user = c.end_user === "*" ? "each end user" : `end user ${c.end_user ?? ""}…`;
  const svc = c.service === "*" ? "each service" : `service ${c.service ?? ""}`;
  if (c.scope === "end_user") return user;
  if (c.scope === "service") return svc;
  return `${user} of ${svc}`;
}

/** orgAppCapLimit renders the cap in its own unit(s); usd is the page's own
 *  money formatter (format.ts fmtUSD), injected so this file stays pure. */
export function orgAppCapLimit(c: OrgAppCap, usd: (v: number) => string): string {
  const parts: string[] = [];
  if (c.cap_usd) parts.push(usd(c.cap_usd));
  if (c.cap_tokens) parts.push(`${c.cap_tokens.toLocaleString()} tokens`);
  return `${parts.join(" / ")} ${PERIOD_WORDS[c.period] ?? c.period}`;
}

/** orgAppBudgetLead is the card's one sentence about how the caps apply. */
export function orgAppBudgetLead(applied: boolean, authoritative: boolean, count: number): string {
  if (!applied) {
    return "Your organization's app budgets apply on this machine once it gets the org budget (Settings > Account).";
  }
  if (count === 0) return "Your organization sets no app budgets.";
  return authoritative
    ? "Set by your organization. On this managed machine they replace the per-user caps above."
    : "Set by your organization. They apply where they are lower than this machine's own caps.";
}
