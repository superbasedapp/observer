/**
 * The AI Apps gateway's plan refusal (sdk/contract/plan-refusal-cases.json).
 *
 * The org's AI Apps gateway (OTLP `/v1/traces` and the SDK control API
 * `/v1/sdk/*`) refuses ingest when the organization's plan does not include
 * AI Apps (HTTP 403 `plan_required`) or this month's allowance is used up
 * (HTTP 429 `planea_events_quota_exceeded` / `planea_bytes_quota_exceeded`).
 * Every such refusal carries `upgradeUrl`: where the organization's billing
 * owner changes the plan. {@link parsePlanRefusal} is the one pure parser;
 * the SDK calls it wherever it sees a response body, and keeps the last
 * refusal for `diagnostics().planRefusal`.
 */

export const PLAN_REQUIRED = "plan_required";
export const EVENTS_QUOTA_EXCEEDED = "planea_events_quota_exceeded";
export const BYTES_QUOTA_EXCEEDED = "planea_bytes_quota_exceeded";
/** The AI gateway's monthly request allowance (the same refusal shape). */
export const AIGW_QUOTA_EXCEEDED = "aigw_requests_quota_exceeded";

/** What a plan refusal is: `plan_required` (HTTP 403) or `allowance_exceeded` (HTTP 429). */
export type PlanRefusalKind = "plan_required" | "allowance_exceeded";

/** A plan's allowance: AI Apps events and GB a month, and the AI gateway's requests a month and concurrent calls. An axis left out: no cap (or the refusal did not name it). */
export interface PlanAllowance {
  eventsMonthly?: number;
  gbMonthly?: number;
  requestsMonthly?: number;
  concurrency?: number;
}

/** A catalog plan: the plan in force, or one on offer (with its allowance). */
export interface PlanInfo {
  name: string;
  version: number;
  label: string;
  allowance?: PlanAllowance;
}

/** The monthly quota a 429 refusal is about. `resetsAt` is RFC 3339. */
export interface PlanQuota {
  quota: string;
  unit: string;
  used: number;
  limit: number;
  resetsAt: string;
}

/** The fields of a plan refusal. */
export interface PlanRefusalFields {
  code: string;
  status: number;
  message: string;
  upgradeUrl: string;
  capability: string;
  plan?: PlanInfo;
  allowance?: PlanAllowance;
  plans: PlanInfo[];
  quota?: PlanQuota;
  /** The Retry-After header in ms (a 429), when it had one. */
  retryAfterMs?: number;
}

/**
 * The organization's plan refused AI Apps ingest. `code` is the gateway's
 * error code, `status` the HTTP status (403 or 429), `message` the gateway's
 * explanation and `upgradeUrl` where the organization's billing owner
 * changes the plan. `capability` names what was refused; `plan` is the plan
 * in force, `allowance` the org's monthly allowance and `plans` the plans
 * that include more (each may be absent). A 429 also carries `quota` and
 * `retryAfterMs`.
 *
 * The calls that reject keep rejecting with their own error
 * (`PromptFetchError`, `ExperimentError`), with this one as its
 * `planRefusal` (and its `cause`), so an existing `catch` keeps working. The
 * calls that never reject carry it (`ScoreResult.planRefusal`,
 * `Verdict.planRefusal`, `ExperimentResult.planRefusal`), and
 * `diagnostics().planRefusal` keeps the last one, export included.
 */
export class PlanRefusalError extends Error implements PlanRefusalFields {
  readonly kind: PlanRefusalKind;
  readonly code: string;
  readonly status: number;
  readonly upgradeUrl: string;
  readonly capability: string;
  readonly plan?: PlanInfo;
  readonly allowance?: PlanAllowance;
  readonly plans: PlanInfo[];
  readonly quota?: PlanQuota;
  readonly retryAfterMs?: number;

  constructor(kind: PlanRefusalKind, f: PlanRefusalFields) {
    super(f.message);
    this.name = "PlanRefusalError";
    this.kind = kind;
    this.code = f.code;
    this.status = f.status;
    this.upgradeUrl = f.upgradeUrl;
    this.capability = f.capability;
    if (f.plan) this.plan = f.plan;
    if (f.allowance) this.allowance = f.allowance;
    this.plans = f.plans;
    if (f.quota) this.quota = f.quota;
    if (f.retryAfterMs !== undefined) this.retryAfterMs = f.retryAfterMs;
  }

  /** The fields as plain values (what `JSON.stringify` and diagnostics show). */
  toJSON(): PlanRefusalFields & { kind: PlanRefusalKind } {
    const out: PlanRefusalFields & { kind: PlanRefusalKind } = {
      kind: this.kind,
      code: this.code,
      status: this.status,
      message: this.message,
      upgradeUrl: this.upgradeUrl,
      capability: this.capability,
      plans: this.plans,
    };
    if (this.plan) out.plan = this.plan;
    if (this.allowance) out.allowance = this.allowance;
    if (this.quota) out.quota = this.quota;
    if (this.retryAfterMs !== undefined) out.retryAfterMs = this.retryAfterMs;
    return out;
  }
}

/** HTTP 403 `plan_required`: the plan does not include AI Apps ingest, or includes no allowance. */
export class PlanRequiredError extends PlanRefusalError {
  constructor(f: PlanRefusalFields) {
    super("plan_required", f);
    this.name = "PlanRequiredError";
  }
}

/** HTTP 429 over the plan's monthly AI Apps allowance (events or bytes); `quota` says which and when it resets. */
export class AllowanceExceededError extends PlanRefusalError {
  constructor(f: PlanRefusalFields) {
    super("allowance_exceeded", f);
    this.name = "AllowanceExceededError";
  }
}

/** code -> the status it rides on and the class. One row per code. */
const CODES: Record<string, { status: number; make: (f: PlanRefusalFields) => PlanRefusalError }> = {
  [PLAN_REQUIRED]: { status: 403, make: (f) => new PlanRequiredError(f) },
  [EVENTS_QUOTA_EXCEEDED]: { status: 429, make: (f) => new AllowanceExceededError(f) },
  [BYTES_QUOTA_EXCEEDED]: { status: 429, make: (f) => new AllowanceExceededError(f) },
  [AIGW_QUOTA_EXCEEDED]: { status: 429, make: (f) => new AllowanceExceededError(f) },
};

/** The headers a parser may be given: a fetch `Headers`, or a plain record (any letter case). */
export type HeadersLike = Headers | Record<string, string | string[] | undefined> | null | undefined;

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const str = (v: unknown): string => (typeof v === "string" ? v : "");
const int = (v: unknown): number | undefined => (typeof v === "number" && Number.isInteger(v) ? v : undefined);

function allowanceOf(v: unknown): PlanAllowance | undefined {
  if (!isObj(v)) return undefined;
  const out: PlanAllowance = {};
  const e = int(v.events_monthly);
  const g = int(v.gb_monthly);
  const r = int(v.requests_monthly);
  const c = int(v.concurrency);
  if (e !== undefined) out.eventsMonthly = e;
  if (g !== undefined) out.gbMonthly = g;
  if (r !== undefined) out.requestsMonthly = r;
  if (c !== undefined) out.concurrency = c;
  return out;
}

function planOf(v: unknown, withAllowance: boolean): PlanInfo | undefined {
  if (!isObj(v) || !str(v.name)) return undefined;
  const out: PlanInfo = { name: str(v.name), version: int(v.version) ?? 0, label: str(v.label) };
  const a = withAllowance ? allowanceOf(v.allowance) : undefined;
  if (a) out.allowance = a;
  return out;
}

function quotaOf(v: unknown): PlanQuota | undefined {
  if (!isObj(v)) return undefined;
  return { quota: str(v.quota), unit: str(v.unit), used: int(v.used) ?? 0, limit: int(v.limit) ?? 0, resetsAt: str(v.resets_at) };
}

function header(h: HeadersLike, name: string): string {
  if (!h) return "";
  if (typeof (h as Headers).get === "function") return (h as Headers).get(name) ?? "";
  for (const [k, v] of Object.entries(h as Record<string, unknown>)) {
    if (k.toLowerCase() === name) return Array.isArray(v) ? String(v[0] ?? "") : typeof v === "string" ? v : "";
  }
  return "";
}

function retryAfterMs(h: HeadersLike): number | undefined {
  const v = header(h, "retry-after").trim();
  return /^\d+$/.test(v) ? Number(v) * 1000 : undefined;
}

function bodyOf(body: unknown): unknown {
  if (typeof body === "string") return body.trim() ? JSON.parse(body) : undefined;
  if (body instanceof Uint8Array) return bodyOf(new TextDecoder("utf-8", { fatal: true }).decode(body));
  return body;
}

/** The line a refusal shows when the gateway sent no message. */
export function defaultPlanRefusalMessage(code: string, upgradeUrl: string): string {
  if (code === AIGW_QUOTA_EXCEEDED) {
    return `AI gateway calls were refused by the organization's plan (${code}); its billing owner can change the plan at ${upgradeUrl}`;
  }
  return `AI Apps ingest was refused by the organization's plan (${code}); its billing owner can change the plan at ${upgradeUrl}`;
}

/**
 * The plan refusal in one HTTP answer, or null. `body` is the decoded JSON,
 * or the raw body (a string or bytes). A plan refusal is a 403
 * `plan_required` or a 429 `planea_events_quota_exceeded` /
 * `planea_bytes_quota_exceeded` / `aigw_requests_quota_exceeded` (the AI
 * gateway's allowance) whose body carries a non-empty
 * `upgrade_url`; anything else, malformed input included, is null. Never
 * throws.
 */
export function parsePlanRefusal(status: number, body: unknown, headers?: HeadersLike): PlanRefusalError | null {
  try {
    if (status !== 403 && status !== 429) return null;
    const o = bodyOf(body);
    if (!isObj(o)) return null;
    const code = str(o.error);
    const row = Object.prototype.hasOwnProperty.call(CODES, code) ? CODES[code] : undefined;
    const upgradeUrl = str(o.upgrade_url).trim();
    if (!row || row.status !== status || !upgradeUrl) return null;
    const f: PlanRefusalFields = {
      code,
      status,
      message: str(o.message).trim() || defaultPlanRefusalMessage(code, upgradeUrl),
      upgradeUrl,
      capability: str(o.capability),
      plans: (Array.isArray(o.plans) ? o.plans : []).map((p) => planOf(p, true)).filter((p): p is PlanInfo => p !== undefined),
    };
    const plan = planOf(o.plan, false);
    const allowance = allowanceOf(o.allowance);
    const quota = quotaOf(o.quota);
    const retry = retryAfterMs(headers);
    if (plan) f.plan = plan;
    if (allowance) f.allowance = allowance;
    if (quota) f.quota = quota;
    if (retry !== undefined) f.retryAfterMs = retry;
    return row.make(f);
  } catch {
    return null;
  }
}

// --- the last refusal, for diagnostics() ------------------------------------------

/** How often (ms) the SDK may write its one-line plan-refusal warning. */
export const PLAN_REFUSAL_LOG_INTERVAL_MS = 60_000;

export const planRefusalStats: { last: PlanRefusalError | null; at: number; loggedAt: number } = { last: null, at: 0, loggedAt: 0 };

export function resetPlanRefusal(): void {
  Object.assign(planRefusalStats, { last: null, at: 0, loggedAt: 0 });
}

/**
 * Keep `r` as the last refusal (`diagnostics().planRefusal`). With `logAs`
 * (what was refused, e.g. "trace export"), write ONE warning line, at most
 * once a minute: the message and the upgrade URL. True when it logged.
 */
export function notePlanRefusal(r: PlanRefusalError, logAs = "", now = Date.now()): boolean {
  planRefusalStats.last = r;
  planRefusalStats.at = now;
  if (!logAs || now - planRefusalStats.loggedAt < PLAN_REFUSAL_LOG_INTERVAL_MS) return false;
  planRefusalStats.loggedAt = now;
  try {
    console.warn(`@superbased/sdk: ${logAs} refused by the organization's plan: ${r.message.split(/\s+/).join(" ")} (upgrade: ${r.upgradeUrl})`);
  } catch {
    // a broken console must not break the host
  }
  return true;
}
