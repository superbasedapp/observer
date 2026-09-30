// reprice.ts - pure helpers for the Settings -> Pricing "Re-price stored
// costs" card (gap PRICE-REPRICE-1). Wire shapes mirror the node dashboard
// JSON contract for /api/reprice/{status,plan,apply,revert}. Only relative
// `.ts` imports, so it runs under plain node:test.

import type { Tone } from "../../../shared/lib/tone.ts";
import { fmtInt, fmtUSD } from "../../../shared/lib/format.ts";

// ---------------------------------------------------------------- wire types

/** Which price table is in force: org rates, the public feed, or the built-in seed. */
export type RepricePricingSource = "org" | "feed" | "seed";

export type RepricePricingView = {
  source: RepricePricingSource | string;
  version: number;
  description: string;
};

/** FilterBody - since/until are "YYYY-MM-DD" or RFC3339; absent = unbounded. */
export type RepriceFilterBody = {
  since?: string;
  until?: string;
  model?: string;
};

export type RepriceTableLine = {
  table: string;
  scanned: number;
  changed: number;
  old_usd: number;
  new_usd: number;
};

export type RepriceModelLine = {
  model: string;
  changed: number;
  old_usd: number;
  new_usd: number;
};

export type RepriceSummary = {
  scanned: number;
  changed: number;
  filled: number;
  old_usd: number;
  new_usd: number;
  delta_usd: number;
  skipped: Record<string, number> | null;
  tables: RepriceTableLine[] | null;
  models: RepriceModelLine[] | null;
};

export type RepriceOrgNote = {
  enrolled: boolean;
  resend_queued: number;
  resend_below_floor: number;
  note: string;
};

export type RepricePlanView = {
  since: string;
  until: string;
  model: string;
  pricing: RepricePricingView;
  digest: string;
  rule_version: number;
  summary: RepriceSummary;
  org?: RepriceOrgNote | null;
};

export type RepriceRunView = {
  id: number;
  kind: "apply" | "revert" | string;
  created_at: string;
  actor: string;
  since: string;
  until: string;
  model: string;
  rule_version: number;
  pricing_source: string;
  pricing_version: number;
  scanned: number;
  changed: number;
  filled: number;
  cas_missed: number;
  old_usd: number;
  new_usd: number;
  delta_usd: number;
  reverts_run: number;
  reverted_by_run: number;
  status: string;
};

export type RepriceStatusResponse = {
  confirm_token: string;
  pricing: RepricePricingView;
  runs: RepriceRunView[] | null;
};

// ---------------------------------------------------------------- inputs

/** The card's raw form state (date inputs yield "YYYY-MM-DD" or ""). */
export type RepriceInputs = {
  since: string;
  until: string;
  model: string;
};

export const EMPTY_INPUTS: RepriceInputs = { since: "", until: "", model: "" };

const DAY_RE = /^\d{4}-\d{2}-\d{2}$/;

/**
 * buildFilterBody turns the form into the wire FilterBody: trimmed, and an
 * empty field is OMITTED (the server reads absent as unbounded).
 */
export function buildFilterBody(inputs: RepriceInputs): RepriceFilterBody {
  const out: RepriceFilterBody = {};
  const since = inputs.since.trim();
  const until = inputs.until.trim();
  const model = inputs.model.trim();
  if (since) out.since = since;
  if (until) out.until = until;
  if (model) out.model = model;
  return out;
}

/**
 * applyBody is the apply POST for a shown dry run: the window the server
 * RESOLVED for that dry run (its absolute since / until / model, echoed on the
 * plan) plus its digest, verbatim. Sending the plan's own bounds rather than
 * the form's is what makes a relative window ("7d") apply to the very rows the
 * dry run counted: the server re-resolves a relative bound against its clock
 * on every request, so the form's text would name a later instant and the
 * digest would never match (the CLI applies the same way).
 */
export function applyBody(plan: RepricePlanView): RepriceFilterBody & { digest: string } {
  const out: RepriceFilterBody & { digest: string } = { digest: plan.digest };
  if (plan.since) out.since = plan.since;
  if (plan.until) out.until = plan.until;
  if (plan.model) out.model = plan.model;
  return out;
}

/**
 * inputsKey identifies a normalized filter, so Apply is only offered for the
 * exact filter the shown dry run was computed for.
 */
export function inputsKey(inputs: RepriceInputs): string {
  const b = buildFilterBody(inputs);
  return [b.since ?? "", b.until ?? "", b.model ?? ""].join("|");
}

/**
 * filterProblem returns a human reason the filter cannot be sent, or null.
 * Only checks what the browser can know (shape and order of the dates).
 */
export function filterProblem(inputs: RepriceInputs): string | null {
  const b = buildFilterBody(inputs);
  if (b.since && !DAY_RE.test(b.since)) return "Since must be a date (YYYY-MM-DD).";
  if (b.until && !DAY_RE.test(b.until)) return "Until must be a date (YYYY-MM-DD).";
  if (b.since && b.until && b.since > b.until) return "Since is after until.";
  return null;
}

/**
 * sinceForDays is the "last N days" preset: the local calendar day N days
 * before `now`, as "YYYY-MM-DD". N <= 0 (or not finite) means all time: "".
 */
export function sinceForDays(days: number, now: Date): string {
  if (!Number.isFinite(days) || days <= 0) return "";
  const d = new Date(now.getFullYear(), now.getMonth(), now.getDate() - Math.floor(days));
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  return `${d.getFullYear()}-${mm}-${dd}`;
}

/** SINCE_PRESETS - the quick window buttons, in display order (0 = all time). */
export const SINCE_PRESETS: { label: string; days: number }[] = [
  { label: "Last 7 days", days: 7 },
  { label: "Last 30 days", days: 30 },
  { label: "Last 90 days", days: 90 },
  { label: "All time", days: 0 },
];

// ---------------------------------------------------------------- money

/**
 * fmtRepriceUSD formats a stored total with the shared currency formatter:
 * 2 decimals, escalating to 4 for a non-zero sub-cent amount so a small
 * correction never reads as $0.00.
 */
export function fmtRepriceUSD(n: number | null | undefined): string {
  if (n == null || !Number.isFinite(n)) return fmtUSD(n);
  return fmtUSD(n, n !== 0 && Math.abs(n) < 0.01);
}

/** fmtSignedUSD is a delta: "+$1.24", "-$0.30", "$0.00". */
export function fmtSignedUSD(n: number | null | undefined): string {
  if (n == null || !Number.isFinite(n)) return fmtUSD(n);
  const s = fmtRepriceUSD(n);
  return n > 0 ? `+${s}` : s;
}

/** deltaWord says which way stored spend moves. */
export function deltaWord(n: number): string {
  if (n > 0) return "higher";
  if (n < 0) return "lower";
  return "no change";
}

/** fmtOldNew renders "old -> new" for a total. */
export function fmtOldNew(oldUSD: number, newUSD: number): string {
  return `${fmtRepriceUSD(oldUSD)} -> ${fmtRepriceUSD(newUSD)}`;
}

// ---------------------------------------------------------------- skipped reasons

/**
 * SKIP_REASONS - the planner's skip reasons with their human labels, in the
 * planner's own order (internal/reprice). A reason the card does not know yet
 * still renders, under its raw key, after these.
 */
export const SKIP_REASONS: { reason: string; label: string }[] = [
  { reason: "source_reported", label: "Reported by the tool or vendor, kept" },
  { reason: "no_model", label: "No model recorded, left as is" },
  { reason: "no_timestamp", label: "No usable timestamp, left as is" },
  { reason: "no_price", label: "No price known, left unknown" },
  { reason: "invalid_price", label: "Price could not be computed, left as is" },
  { reason: "fast_tier_unknown", label: "Fast-mode rate unknown, left as is" },
  { reason: "unchanged", label: "Already at the right price" },
];

/** skipLabel is the human label for one skip reason (raw key when unknown). */
export function skipLabel(reason: string): string {
  return SKIP_REASONS.find((r) => r.reason === reason)?.label ?? reason.replace(/_/g, " ");
}

/** skippedRows lists the non-zero skip counts, known reasons first in table order. */
export function skippedRows(
  skipped: Record<string, number> | null | undefined,
): { reason: string; label: string; count: number }[] {
  if (!skipped) return [];
  const known = new Set(SKIP_REASONS.map((r) => r.reason));
  const rows = SKIP_REASONS.filter((r) => (skipped[r.reason] ?? 0) > 0).map((r) => ({
    ...r,
    count: skipped[r.reason],
  }));
  const extra = Object.keys(skipped)
    .filter((k) => !known.has(k) && skipped[k] > 0)
    .sort()
    .map((k) => ({ reason: k, label: skipLabel(k), count: skipped[k] }));
  return [...rows, ...extra];
}

// ---------------------------------------------------------------- plan

/** planHeadline is the one-line dry-run result. */
export function planHeadline(s: RepriceSummary): string {
  if (s.scanned === 0) return "No stored rows in this window.";
  const rows = `${fmtInt(s.scanned)} row${s.scanned === 1 ? "" : "s"} scanned`;
  if (s.changed === 0) return `${rows} - nothing would change.`;
  const filled = s.filled > 0 ? ` (${fmtInt(s.filled)} without a cost before)` : "";
  return `${rows} - ${fmtInt(s.changed)} would change${filled}.`;
}

/**
 * canApply: Apply is offered only for a shown dry run that would change
 * something AND was computed for the filter currently in the form.
 */
export function canApply(
  plan: RepricePlanView | null,
  planKey: string | null,
  currentKey: string,
): boolean {
  return plan !== null && planKey === currentKey && plan.summary.changed > 0 && plan.digest !== "";
}

/**
 * planChangedFrom reads a 409 apply answer. It returns the server's fresh
 * plan when the body is `{"error":"plan_changed","plan":{...}}`, else null.
 */
export function planChangedFrom(status: number, body: string): RepricePlanView | null {
  if (status !== 409 || !body) return null;
  try {
    const parsed = JSON.parse(body) as { error?: string; plan?: RepricePlanView };
    if (parsed?.error === "plan_changed" && parsed.plan && typeof parsed.plan === "object") {
      return parsed.plan;
    }
  } catch {
    // not JSON - fall through
  }
  return null;
}

/** serverErrorText pulls `{"error": "..."}` out of an error body, else the raw text. */
export function serverErrorText(body: string): string {
  try {
    const parsed = JSON.parse(body) as { error?: unknown };
    if (parsed && typeof parsed.error === "string" && parsed.error) return parsed.error;
  } catch {
    // not JSON
  }
  return body.trim();
}

// ---------------------------------------------------------------- runs

/** windowLabel renders a run or plan window: "all time", "from X", "until Y", "X to Y". */
export function windowLabel(since: string, until: string): string {
  const a = dayOf(since);
  const b = dayOf(until);
  if (!a && !b) return "all time";
  if (a && !b) return `from ${a}`;
  if (!a && b) return `until ${b}`;
  return a === b ? a : `${a} to ${b}`;
}

function dayOf(s: string | null | undefined): string {
  const t = (s ?? "").trim();
  return DAY_RE.test(t.slice(0, 10)) ? t.slice(0, 10) : t;
}

/** Run statuses that can never be reverted, whatever the server calls a done apply. */
const NON_REVERTIBLE_STATUS = new Set(["reverted", "failed", "error", "refused", "running"]);

/** canRevert: an apply run that has not been reverted (a revert run never is). */
export function canRevert(run: RepriceRunView): boolean {
  return (
    run.kind === "apply" &&
    !(run.reverted_by_run > 0) &&
    !NON_REVERTIBLE_STATUS.has(run.status) &&
    run.changed > 0
  );
}

/** RUN_STATUS_TONE - run status -> Pill tone (unknown statuses are neutral). */
export const RUN_STATUS_TONE: Record<string, Tone> = {
  applied: "success",
  reverted: "neutral",
  failed: "danger",
  error: "danger",
  running: "info",
};

/** runStatus is the run's status pill: a reverted apply says which run undid it. */
export function runStatus(run: RepriceRunView): { text: string; tone: Tone } {
  if (run.kind === "apply" && run.reverted_by_run > 0) {
    return { text: `reverted by #${run.reverted_by_run}`, tone: "neutral" };
  }
  const text = run.status || "unknown";
  return { text, tone: RUN_STATUS_TONE[text] ?? "neutral" };
}

/** runKindLabel: "re-price" for an apply, "revert of #N" for a revert. */
export function runKindLabel(run: RepriceRunView): string {
  if (run.kind === "revert") return run.reverts_run > 0 ? `revert of #${run.reverts_run}` : "revert";
  if (run.kind === "apply") return "re-price";
  return run.kind;
}
