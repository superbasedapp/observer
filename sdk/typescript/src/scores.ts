/**
 * Scores and feedback (W3-1; contract `contracts/scores.md`, lane B7; the
 * API is sdk-api-surface.md section 7.1, the same as Python's).
 *
 * A score is one judgement about one trace or one span: a name, a value, who
 * produced it, an optional comment. Feedback is a score an end user of the
 * app gave. Both are written through the SDK control API to every target of
 * the destination in force: online `POST <org>/v1/sdk/scores` (scope
 * `sdk:write`), local `POST <machine>/api/obs/scores`, `both` to each with
 * the same `id`, so the stored score id is the same on both sides. They land
 * on the existing owners (org annotations, machine `obs_eval_scores`); the
 * SDK adds no store of its own.
 *
 * The id makes a write idempotent: the SDK mints `sdk_<32 hex>` when you
 * give none and reuses it on its one retry, so a retried write never doubles
 * a score.
 *
 * Nothing throws: a score the scorecore rules refuse (a bad name, a kind
 * that disagrees with the value, no trace) resolves with `ok: false` and an
 * error naming the contract's code, before any call; network and server
 * failures resolve the same way. flush() waits for pending writes.
 */

import { apiTimeout, call, noTargetReason, retryable, targets, track, type ControlOptions, type Route } from "./control.js";
import type { PlanRefusalError } from "./planrefusal.js";
import { getCurrentTraceId } from "./spans.js";
import { destinationKnown } from "./runtime.js";

export const SCORES_ROUTE: Route = { online: "/scores", local: "/api/obs/scores" };

/** numeric, boolean or categorical; inferred from the value's type when not given. */
export type ScoreKind = "numeric" | "boolean" | "categorical";
export const SCORE_KINDS: readonly ScoreKind[] = ["numeric", "boolean", "categorical"];
export const DEFAULT_FEEDBACK_NAME = "user_feedback";

const NAME = /^[a-z0-9_.-]{1,64}$/;
const ID = /^[A-Za-z0-9_.:-]{1,128}$/;
const TRACE = /^[0-9a-f]{32}$/;
const SPAN = /^[0-9a-f]{16}$/;
const MAX_VALUE_BYTES = 120;
const MAX_COMMENT_BYTES = 2000;
const MAX_SCORER_NAME = 64;
const MAX_SCORER_VERSION = 32;

export interface ScoreOptions extends ControlOptions {
  /** Defaults to the active trace. */
  traceId?: string;
  /** Score one span of the trace; unset, the score is trace-level (also inside a span, as in Python). */
  spanId?: string;
  comment?: string;
  /** The value kind; must agree with the value's type (`kind_mismatch` otherwise). */
  kind?: ScoreKind;
  /** The automated scorer that produced the value (1-64 chars). */
  scorer?: string;
  /** Its version (1-32 chars; default "1" when `scorer` is set), so two versions' results coexist. */
  scorerVersion?: string;
  /** An experiment run id: ties the score to that run. */
  runId?: string;
  /** The idempotency id (default `sdk_<32 hex>`, fresh per call). */
  scoreId?: string;
  /** When the judgement was made (default: the server's receive time). */
  timestamp?: Date | string;
}

/** One destination's outcome. */
export interface ScoreDestinationResult {
  ok: boolean;
  status: number;
  /** The stored score id (`sc_...`) this destination returned ("" when it did not accept). */
  id: string;
  error: string;
}

export interface ScoreResult {
  /** True when EVERY destination accepted the score (as in Python). */
  ok: boolean;
  /** The stored score id (`sc_...`) the first accepting destination returned. */
  id: string;
  /** The idempotency id that was sent. */
  clientId: string;
  /** Each destination's outcome, by name (`local`, `online`). */
  destinations: Record<string, ScoreDestinationResult>;
  /** Every problem: validation (`<code>: <message>`) or per destination (`<name>: <error>`). */
  errors: string[];
  /** Set when the org's plan refused the score (its `message` and `upgradeUrl` say why and where to fix it). */
  planRefusal?: PlanRefusalError;
}

/** A score the rules refuse (contract scores.md section 1; the code is the contract's). */
export class ScoreError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(`${code}: ${message}`);
    this.name = "ScoreError";
  }
}

function kindOf(value: unknown): ScoreKind {
  if (typeof value === "boolean") return "boolean";
  if (typeof value === "number") return "numeric";
  if (typeof value === "string") return "categorical";
  throw new ScoreError("invalid_value", `value must be a number, a boolean or a string, got ${value === null ? "null" : typeof value}`);
}

const bytes = (s: string) => new TextEncoder().encode(s).length;

function randomHex32(): string {
  const c = (globalThis as { crypto?: { getRandomValues?: (a: Uint8Array) => Uint8Array } }).crypto;
  const a = new Uint8Array(16);
  if (c?.getRandomValues) c.getRandomValues(a);
  else for (let i = 0; i < a.length; i++) a[i] = Math.floor(Math.random() * 256);
  return [...a].map((b) => b.toString(16).padStart(2, "0")).join("");
}

interface BuildOptions extends ScoreOptions {
  source?: "sdk" | "feedback";
}

/**
 * The wire score object (scores.md section 1), validated with the scorecore
 * rules. Throws ScoreError naming the contract's code (`score()` turns that
 * into a result; this is exported for tests and advanced callers).
 */
export function buildScore(name: string, value: unknown, o: BuildOptions = {}): Record<string, unknown> {
  const n = String(name ?? "")
    .trim()
    .toLowerCase();
  if (!NAME.test(n)) throw new ScoreError("invalid_name", `name ${JSON.stringify(name)} must be 1-64 chars of a-z 0-9 _ . -`);
  const inferred = kindOf(value);
  if (o.kind !== undefined && o.kind !== inferred) {
    if (!SCORE_KINDS.includes(o.kind)) throw new ScoreError("kind_mismatch", `kind ${JSON.stringify(o.kind)} is not numeric, boolean or categorical`);
    throw new ScoreError("kind_mismatch", `kind ${o.kind} does not match a ${typeof value} value`);
  }
  let v = value as number | string | boolean;
  if (inferred === "numeric" && !Number.isFinite(v)) throw new ScoreError("invalid_value", `value ${String(v)} is not a finite number`);
  if (inferred === "categorical") {
    const t = String(v).trim();
    if (!t || bytes(t) > MAX_VALUE_BYTES || /[\r\n]/.test(t)) {
      throw new ScoreError("invalid_value", `a categorical value must be 1-${MAX_VALUE_BYTES} bytes on one line`);
    }
    v = t;
  }
  const tid = (o.traceId || getCurrentTraceId()).trim().toLowerCase();
  if (!tid) throw new ScoreError("invalid_trace_id", "no traceId given and no current span");
  if (!TRACE.test(tid) || /^0+$/.test(tid)) throw new ScoreError("invalid_trace_id", `traceId ${JSON.stringify(o.traceId)} must be 32 hex characters, not all zero`);
  const sid = (o.spanId ?? "").trim().toLowerCase();
  if (sid && (!SPAN.test(sid) || /^0+$/.test(sid))) throw new ScoreError("invalid_span_id", `spanId ${JSON.stringify(o.spanId)} must be 16 hex characters`);
  if (o.comment != null && bytes(String(o.comment)) > MAX_COMMENT_BYTES) throw new ScoreError("comment_too_long", `comment is over ${MAX_COMMENT_BYTES} bytes`);
  const cid = o.scoreId || `sdk_${randomHex32()}`;
  if (!ID.test(cid)) throw new ScoreError("invalid_id", `scoreId ${JSON.stringify(o.scoreId)} must be 1-128 chars of A-Z a-z 0-9 _ . : -`);
  const source = o.source ?? "sdk";
  if (source !== "sdk" && source !== "feedback") throw new ScoreError("invalid_source", `source ${JSON.stringify(source)} must be sdk or feedback`);
  const out: Record<string, unknown> = { id: cid, trace_id: tid, name: n, value: v, kind: inferred, source };
  if (sid) out.span_id = sid;
  if (o.comment) out.comment = String(o.comment);
  if (o.scorer) {
    if (o.scorer.length > MAX_SCORER_NAME || (o.scorerVersion && o.scorerVersion.length > MAX_SCORER_VERSION)) {
      throw new ScoreError("bad_request", "scorer name is 1-64 chars and version 1-32");
    }
    out.scorer = { name: o.scorer, version: o.scorerVersion || "1" };
  }
  if (o.runId) out.run_id = String(o.runId);
  if (o.timestamp) out.timestamp = o.timestamp instanceof Date ? o.timestamp.toISOString() : o.timestamp;
  return out;
}

function readAnswer(body: unknown): { accepted: Map<number, string>; rejected: Map<number, string> } {
  const b = (body && typeof body === "object" ? body : {}) as Record<string, unknown>;
  const arr = (v: unknown) => (Array.isArray(v) ? v.filter((x) => x && typeof x === "object") : []) as Record<string, unknown>[];
  const accepted = new Map<number, string>();
  const rejected = new Map<number, string>();
  for (const a of arr(b.accepted)) accepted.set(typeof a.index === "number" ? a.index : 0, typeof a.id === "string" ? a.id : "");
  for (const r of arr(b.rejected)) {
    const msg = `${String(r.error ?? "rejected")}: ${String(r.message ?? "")}`.replace(/: $/, "");
    rejected.set(typeof r.index === "number" ? r.index : 0, msg);
  }
  return { accepted, rejected };
}

let lastLog = 0;
function logFailure(res: ScoreResult): void {
  const now = Date.now();
  if (now - lastLog < 60_000) return;
  lastLog = now;
  try {
    console.warn(`@superbased/sdk: a score was not stored: ${res.errors.join("; ") || "unknown"}`);
  } catch {
    // ignore
  }
}

function write(name: string, value: unknown, o: BuildOptions): Promise<ScoreResult> {
  let body: Record<string, unknown>;
  try {
    body = buildScore(name, value, o);
  } catch (err) {
    const res: ScoreResult = { ok: false, id: "", clientId: "", destinations: {}, errors: [err instanceof Error ? err.message : String(err)] };
    logFailure(res);
    return Promise.resolve(res);
  }
  const res: ScoreResult = { ok: false, id: "", clientId: body.id as string, destinations: {}, errors: [] };
  // The body (and the trace it scores) is fixed now; the target waits for the
  // destination (review E-33).
  const work = destinationKnown().then(() => send(body, res, o));
  return track(work);
}

function send(body: Record<string, unknown>, res: ScoreResult, o: BuildOptions): Promise<ScoreResult> {
  const ts = targets("write", o);
  if (!ts.length) {
    res.errors.push(noTargetReason());
    logFailure(res);
    return Promise.resolve(res);
  }
  const timeoutMs = apiTimeout(o);
  return Promise.all(
    ts.map(async (t) => {
      let r = await call(t, "POST", SCORES_ROUTE, { body, timeoutMs });
      if (retryable(r)) r = await call(t, "POST", SCORES_ROUTE, { body, timeoutMs });
      const ans = readAnswer(r.body);
      const ok = r.ok && ans.accepted.has(0) && !ans.rejected.has(0);
      const error = ok ? "" : ans.rejected.get(0) || `${r.status ? `HTTP ${r.status} ` : ""}${r.error}${r.message ? `: ${r.message}` : ""}`;
      return { name: t.name, out: { ok, status: r.status, id: ok ? (ans.accepted.get(0) ?? "") : "", error }, refusal: ok ? undefined : r.planRefusal };
    }),
  ).then((rows) => {
    for (const { name: n, out, refusal } of rows) {
      res.destinations[n] = out;
      if (out.ok) res.id = res.id || out.id;
      else res.errors.push(`${n}: ${out.error}`);
      if (refusal) res.planRefusal ??= refusal;
    }
    res.ok = rows.length > 0 && rows.every((r) => r.out.ok);
    if (!res.ok) logFailure(res);
    return res;
  });
}

/**
 * Attach a score to a trace (or one span of it). Never throws.
 *
 * ```ts
 * await score("faithfulness", 0.92, { traceId, scorer: "judge", scorerVersion: "3" });
 * ```
 */
export function score(name: string, value: number | string | boolean, opts: ScoreOptions = {}): Promise<ScoreResult> {
  return write(name, value, { ...opts, source: "sdk" });
}

export interface FeedbackOptions extends Omit<ScoreOptions, "kind" | "scorer" | "scorerVersion" | "runId"> {
  /** The score name (default `user_feedback`). */
  name?: string;
}

/**
 * Record an end user's feedback on a trace: a score with source `feedback`.
 * 👍/👎 as true/false, a rating as a number, or a label. Call it from the
 * request that receives the reaction (for example the backend route the
 * `@superbased/feedback-widget` posts to), with the trace id your app got
 * from `getCurrentTraceId()` when it answered. Never throws.
 */
export function feedback(value: number | string | boolean, opts: FeedbackOptions = {}): Promise<ScoreResult> {
  const { name, ...rest } = opts;
  return write(name || DEFAULT_FEEDBACK_NAME, value, { ...rest, source: "feedback" });
}
