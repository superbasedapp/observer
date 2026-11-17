// requestRows.ts - how the Requests page reads one of the developer's own
// requests (demo findings #20, #27, #28, 2026-11-10). Pure: no React, no
// fetch.
//
//   - requestOutcome: the row's status and answer. A request's own status
//     records the DECISION ("granted") and never moves on: the org changes
//     only the grant when it revokes one (one writer of org_requests). So a
//     granted row reads its grant's live state: revoked (when, and the
//     admin's reason), expired (past its end, whatever the server last said),
//     every use spent, or starts later. A grant an extension replaced reads
//     "replaced by G-<n>" (lib/grantRevokeReason), not revoked.
//   - requestAsk: the ask in words. A budget increase names the budget from
//     the budgets this machine holds from its organization ("Your budget,
//     monthly, 2000.00 USD") instead of its 32-hex id, which stays in the
//     tooltip; an unknown budget falls back to a short id. The budget reads
//     at its base cap, then the increase asked, whether or not a grant is
//     raising it right now.
//   - splitRequests: open and recent rows first, finished rows older than
//     RECENT_FINISHED_DAYS folded into History. Nothing is deleted.

import { baseBudget, capWords, increaseWords, scopeWords, type RequestableBudget } from "./requestBudgets.ts";
import { replacedBy, revokeReasonWords } from "./grantRevokeReason.ts";

export type Tone = "neutral" | "success" | "warn" | "danger" | "info" | "accent";

export type RequestGrantSummary = {
  id: number;
  type: string;
  effect?: string;
  status: string;
  starts_at_ns: number;
  expires_at_ns?: number;
  max_uses?: number;
  subject_kind: string;
  /** Absent from a server that predates them. */
  revoked_at_ns?: number;
  revoke_reason?: string;
};

export type RequestRowInput = {
  id: number;
  kind: string;
  target?: string;
  status: string;
  created_at: string;
  resolved_at?: string;
  resolution_note?: string;
  request_type?: string;
  payload?: { rule_id?: string; budget_id?: string; delta_tokens?: number; delta_usd?: number; target?: string };
  grant?: RequestGrantSummary;
};

export type RequestOutcome = {
  /** The status pill's word. */
  status: string;
  tone: Tone;
  /** The answer column ("" when there is nothing to say). */
  answer: string;
  /** Whether the request is finished (nothing more will happen to it). */
  finished: boolean;
  /** When it finished, ns since the epoch (0 when unknown or not finished). */
  finishedAtNs: number;
};

const STATUS_TONE: Record<string, Tone> = {
  open: "info",
  granted: "success",
  declined: "danger",
  withdrawn: "neutral",
  lapsed: "neutral",
  resolved: "neutral",
  revoked: "danger",
  replaced: "neutral",
  expired: "neutral",
  "used up": "neutral",
};

/** Request statuses that end a request without a grant. */
const FINISHED_STATUSES = new Set(["declined", "withdrawn", "lapsed", "resolved"]);

function humanLeft(seconds: number): string {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return h > 0 ? `${d}d ${h}h` : `${d}d`;
  if (h > 0) return m > 0 ? `${h}h ${m}m` : `${h}h`;
  if (m > 0) return `${m}m`;
  return "under a minute";
}

function when(ns: number): string {
  return new Date(ns / 1e6).toLocaleString();
}

function parseTimeNs(s: string | undefined): number {
  if (!s) return 0;
  const ms = Date.parse(s);
  return Number.isFinite(ms) ? ms * 1e6 : 0;
}

/** grantRule is one row of the granted-request table: the first row whose
 *  test holds decides the outcome (CLAUDE.md #5). */
type GrantRule = {
  test: (g: RequestGrantSummary, nowNs: number) => boolean;
  outcome: (g: RequestGrantSummary, nowNs: number) => Omit<RequestOutcome, "tone"> & { tone?: Tone };
};

const GRANT_RULES: GrantRule[] = [
  {
    // An extension: the organization replaced the grant with a new one (it
    // stores this as a revoke, reason "superseded by G-<n>"). Nothing was
    // taken away, so it reads replaced, not revoked.
    test: (g) => g.status === "revoked" && replacedBy(g.revoke_reason) !== undefined,
    outcome: (g) => {
      let answer = `Granted as G-${g.id}, ${revokeReasonWords(g.revoke_reason!)}`;
      if (g.revoked_at_ns) answer += ` on ${when(g.revoked_at_ns)}`;
      return { status: "replaced", answer, finished: true, finishedAtNs: g.revoked_at_ns ?? 0 };
    },
  },
  {
    test: (g) => g.status === "revoked",
    outcome: (g) => {
      let answer = `Granted as G-${g.id}, revoked by your organization`;
      if (g.revoked_at_ns) answer += ` on ${when(g.revoked_at_ns)}`;
      if (g.revoke_reason) answer += `. Reason: ${revokeReasonWords(g.revoke_reason)}`;
      return { status: "revoked", answer, finished: true, finishedAtNs: g.revoked_at_ns ?? 0 };
    },
  },
  {
    // Past its end on this machine's clock, whatever the server last said.
    test: (g, now) => g.status === "expired" || (!!g.expires_at_ns && g.expires_at_ns <= now),
    outcome: (g) => ({
      status: "expired",
      answer: g.expires_at_ns ? `Granted as G-${g.id}, expired ${when(g.expires_at_ns)}` : `Granted as G-${g.id}, expired`,
      finished: true,
      finishedAtNs: g.expires_at_ns ?? 0,
    }),
  },
  {
    test: (g) => g.status === "exhausted",
    outcome: (g) => ({
      status: "used up",
      answer: g.max_uses ? `Granted as G-${g.id}, all ${g.max_uses} uses spent` : `Granted as G-${g.id}, every use spent`,
      finished: true,
      finishedAtNs: 0,
    }),
  },
  {
    test: (g, now) => g.status === "scheduled" || g.starts_at_ns > now,
    outcome: (g) => ({ status: "granted", answer: `Granted as G-${g.id}, starts ${when(g.starts_at_ns)}`, finished: false, finishedAtNs: 0 }),
  },
  {
    test: () => true,
    outcome: (g, now) => ({
      status: "granted",
      answer: g.expires_at_ns
        ? `Granted as G-${g.id}, until ${when(g.expires_at_ns)} (${humanLeft(Math.round((g.expires_at_ns - now) / 1e9))} left)`
        : `Granted as G-${g.id}, no expiry`,
      finished: false,
      finishedAtNs: 0,
    }),
  },
];

/** requestOutcome is the status pill and answer line of one request. */
export function requestOutcome(r: RequestRowInput, nowNs: number): RequestOutcome {
  if (r.grant) {
    const g = r.grant;
    const rule = GRANT_RULES.find((x) => x.test(g, nowNs))!;
    const o = rule.outcome(g, nowNs);
    if (o.finished && !o.finishedAtNs) o.finishedAtNs = parseTimeNs(r.resolved_at) || parseTimeNs(r.created_at);
    return { ...o, tone: o.tone ?? STATUS_TONE[o.status] ?? "neutral" };
  }
  const finished = FINISHED_STATUSES.has(r.status);
  return {
    status: r.status,
    tone: STATUS_TONE[r.status] ?? "neutral",
    answer: r.resolution_note ?? "",
    finished,
    finishedAtNs: finished ? parseTimeNs(r.resolved_at) || parseTimeNs(r.created_at) : 0,
  };
}

const PERIOD_WORDS: Record<string, string> = {
  calendar_month: "monthly",
  calendar_day: "daily",
  rolling_30d: "rolling 30 days",
};

/** shortId keeps an opaque id readable: its first 8 characters. */
export function shortId(id: string): string {
  return id.length > 12 ? `${id.slice(0, 8)}…` : id;
}

/** budgetName names a budget the way the picker does, without the current
 *  use: "Your budget, monthly, 2000.00 USD". */
export function budgetName(b: RequestableBudget, dollars: boolean): string {
  const parts = [scopeWords(b.scope), PERIOD_WORDS[b.period] ?? b.period];
  if (b.subject) parts.push(`for ${b.subject.kind} ${b.subject.id}`);
  parts.push(capWords(b, dollars));
  return parts.join(", ");
}

function amountAsked(p: RequestRowInput["payload"], dollars: boolean): string {
  return p ? increaseWords(p.delta_tokens, p.delta_usd, dollars) : "";
}

export type RequestAsk = {
  /** The detail after the type's label ("" for none), with a leading space. */
  detail: string;
  /** The raw id behind a named detail, for the tooltip. */
  title?: string;
};

/** requestAsk is what the request asked for, after its type's label. */
export function requestAsk(r: RequestRowInput, budgets: readonly RequestableBudget[], dollars: boolean): RequestAsk {
  if (r.request_type === "budget_increase") {
    const id = r.payload?.budget_id || r.target || "";
    const b = id ? budgets.find((x) => x.budget_id === id) : undefined;
    const amount = amountAsked(r.payload, dollars);
    // The budget's own cap, then the ask: a budget a live grant raised (this
    // request's or another) reads its base, never base plus the increase
    // twice ("100000.00 USD (+10.00 USD)", not "100010.00 USD (+10.00 USD)").
    if (b) return { detail: `: ${budgetName(baseBudget(b), dollars)}${amount}`, title: `budget ${id}` };
    if (id) return { detail: ` ${shortId(id)}${amount}`, title: `budget ${id} (not among the budgets this machine holds now)` };
    return { detail: amount };
  }
  if (r.payload?.rule_id) return { detail: ` ${r.payload.rule_id}` };
  if (r.target) return { detail: ` ${r.target}` };
  return { detail: "" };
}

/** RECENT_FINISHED_DAYS is how long a finished request stays in the main
 *  list before it folds into History. */
export const RECENT_FINISHED_DAYS = 7;

/** splitRequests keeps open requests, live grants and recently finished
 *  requests in the main list and folds older finished ones into History,
 *  both in the order given. */
export function splitRequests<T extends RequestRowInput>(rows: readonly T[], nowNs: number): { current: T[]; history: T[] } {
  const cutoff = nowNs - RECENT_FINISHED_DAYS * 86400 * 1e9;
  const current: T[] = [];
  const history: T[] = [];
  for (const r of rows) {
    const o = requestOutcome(r, nowNs);
    if (o.finished && o.finishedAtNs > 0 && o.finishedAtNs < cutoff) history.push(r);
    else current.push(r);
  }
  return { current, history };
}
