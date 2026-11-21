/**
 * Prompt registry client (W3-3; contract `contracts/prompts.md`, lane B8).
 *
 * - Fetch: online `GET <org>/v1/sdk/prompts/{name}` (scope `sdk:read`),
 *   local `GET <machine>/api/obs/sdk/prompts/{name}`; `both` prefers online
 *   and falls back to local. `?label=` or `?version=`, never both; neither is
 *   `label=production`.
 * - Cache per (endpoint, name, selector): fresh for `cacheTtlMs` (default
 *   60 s, `SUPERBASED_PROMPT_CACHE_TTL_MS`). After that the cached prompt is
 *   returned at once and revalidated in the background with `If-None-Match`
 *   (stale-while-revalidate); a 304 renews it, a 404 drops it, any other
 *   failure keeps serving it.
 * - A first fetch that fails throws {@link PromptNotFound}, unless you pass a
 *   `fallback`, which is returned marked `isFallback` and never cached.
 * - `compile(values)` fills `{{name}}` placeholders in one pass (a value is
 *   never re-scanned) and throws {@link PromptCompileError} naming every
 *   missing variable. `prompt.compile()`, `getPrompt()` inside a span and
 *   `withLlmSpan(..., { promptRef })` stamp `sbo.prompt.name`,
 *   `sbo.prompt.version` and (for a label fetch) `sbo.prompt.label` on the
 *   span. A fallback stamps nothing.
 */

import { createHash } from "node:crypto";

import { trace, type Span } from "@opentelemetry/api";

import { K } from "./attrs.js";
import { apiTimeout, call, noTargetReason, targets, track, type ControlOptions, type ControlResponse, type Target } from "./control.js";
import { getCurrentAttributes } from "./context.js";
import { destinationKnown, runtime } from "./runtime.js";

export const DEFAULT_PROMPT_LABEL = "production";
export const PROMPT_LABELS = ["production", "staging"] as const;

export interface ChatMessage {
  role: string;
  content: string;
}

export type PromptBody = string | ChatMessage[];

export interface GetPromptOptions extends ControlOptions {
  /** `production` (default) or `staging`. Exclusive with `version`. */
  label?: string;
  /** An exact version number. Exclusive with `label`. */
  version?: number;
  /** Cache freshness in ms (default: the promptCacheTtlMs setting, 60 000). 0 revalidates on every call. */
  cacheTtlMs?: number;
  /** Returned (marked isFallback, never cached) when the prompt cannot be fetched and nothing is cached. */
  fallback?: PromptBody;
  /**
   * The end user that picks the side of a staged rollout (prompts.md v2
   * section 9.2). Default: the current trace's user (`propagateAttributes`
   * / `identify`). Only its SHA-256 is sent.
   */
  user?: string;
  /** The session that picks the side when there is no user. Default: the current trace's session. */
  sessionId?: string;
}

/** A label's staged rollout as the server reported it (prompts.md v2 section 9.3). */
export interface PromptRollout {
  baseVersion: number;
  candidateVersion: number;
  percent: number;
  /** Which side this key was served: `candidate`, `base` or `unkeyed`. */
  cohort: "candidate" | "base" | "unkeyed";
  /** Which key decided: `user`, `session` or "". */
  key: "user" | "session" | "";
  salt: string;
}

/** The base of every prompt error (contract sdk-api-surface.md section 7.3). */
export class PromptError extends Error {
  constructor(
    message: string,
    readonly status = 0,
    readonly code = "",
  ) {
    super(message);
    this.name = "PromptError";
  }
}

/** Thrown when no destination has the prompt (404 / not implemented everywhere) and there is no fallback. */
export class PromptNotFound extends PromptError {
  constructor(message: string, status = 0, code = "") {
    super(message, status, code);
    this.name = "PromptNotFound";
  }
}

/** Thrown when a destination failed otherwise (transport, timeout, 5xx, a bad body) and there is no fallback. */
export class PromptFetchError extends PromptError {
  constructor(message: string, status = 0, code = "") {
    super(message, status, code);
    this.name = "PromptFetchError";
  }
}

/** Thrown by compile() when a placeholder has no value; `missing` is sorted. */
export class PromptCompileError extends PromptError {
  constructor(readonly missing: string[]) {
    super(`prompt variables missing: ${missing.join(", ")}`, 0, "missing_variables");
    this.name = "PromptCompileError";
  }
}

const PLACEHOLDER = /\{\{[ \t]*([A-Za-z_][A-Za-z0-9_]*)[ \t]*\}\}/g;

/** The distinct placeholder names in a body, sorted by byte order. */
export function promptVariables(body: PromptBody): string[] {
  const texts = typeof body === "string" ? [body] : body.map((m) => m.content);
  const names = new Set<string>();
  for (const t of texts) for (const m of t.matchAll(PLACEHOLDER)) names.add(m[1]);
  return [...names].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

function valueText(v: unknown): string {
  return typeof v === "string" ? v : JSON.stringify(v);
}

/** Fill placeholders in one left-to-right pass; throws PromptCompileError naming every missing name. */
export function compilePrompt(body: PromptBody, values: Record<string, unknown>): PromptBody {
  const missing = promptVariables(body).filter((n) => !Object.prototype.hasOwnProperty.call(values, n) || values[n] === undefined);
  if (missing.length) throw new PromptCompileError(missing);
  // null renders as JSON null ("null"), as Python json.dumps(None) does (R-B19).
  const one = (t: string) => t.replace(PLACEHOLDER, (_w, name: string) => valueText(values[name]));
  return typeof body === "string" ? one(body) : body.map((m) => ({ ...m, content: one(m.content) }));
}

/** Registry fields Python's Prompt also carries (contract prompts.md). */
export interface PromptDetails {
  /** How the registry resolved it: `label:<name>` or `version:<n>` ("" for a fallback). */
  resolvedBy?: string;
  /** The version's commit message ("" when none). */
  commitMessage?: string;
  /** When the version was created (RFC 3339 UTC; "" for a fallback). */
  createdAt?: string;
  /** Where this copy came from: `online`, `local` or `fallback`. */
  source?: string;
}

/** A fetched (or fallback) prompt. */
export class Prompt {
  /** How the registry resolved it: `label:<name>` or `version:<n>` ("" for a fallback). */
  readonly resolvedBy: string;
  /** The version's commit message ("" when none). */
  readonly commitMessage: string;
  /** When the version was created (RFC 3339 UTC; "" for a fallback). */
  readonly createdAt: string;
  /** Where this copy came from: `online`, `local` or `fallback` ("" when built by hand). */
  readonly source: string;

  constructor(
    readonly name: string,
    readonly version: number,
    /** The label it was resolved by ("" for a version fetch or a fallback). */
    readonly label: string,
    readonly type: "text" | "chat",
    readonly prompt: PromptBody,
    /** Model parameters or other config stored with the version (`{}` when none). */
    readonly config: Record<string, unknown> = {},
    /** The labels that point at this version now. */
    readonly labels: string[] = [],
    /** `sha256:<hex>` of the version's canonical content. */
    readonly digest = "",
    /** True when this is the caller's fallback, not a registry copy. */
    readonly isFallback = false,
    /** The label's staged rollout, when it has one (the version above is the one SERVED). */
    readonly rollout: PromptRollout | null = null,
    details: PromptDetails = {},
  ) {
    this.resolvedBy = details.resolvedBy ?? "";
    this.commitMessage = details.commitMessage ?? "";
    this.createdAt = details.createdAt ?? "";
    this.source = details.source ?? (isFallback ? "fallback" : "");
  }

  /** Which rollout side served this copy (`candidate`, `base`, `unkeyed`), "" when the label has no rollout. */
  get cohort(): string {
    return this.rollout?.cohort ?? "";
  }

  /** The body of a text prompt ("" for a chat prompt). */
  get text(): string {
    return typeof this.prompt === "string" ? this.prompt : "";
  }

  /** The messages of a chat prompt ([] for a text prompt). */
  get messages(): ChatMessage[] {
    return typeof this.prompt === "string" ? [] : this.prompt.map((m) => ({ ...m }));
  }

  /** The placeholder names, sorted. */
  get variables(): string[] {
    return promptVariables(this.prompt);
  }

  /** Fill the variables and stamp the active span. A text prompt gives a string, a chat prompt a message list. */
  compile(values: Record<string, unknown> = {}): PromptBody {
    const out = compilePrompt(this.prompt, values);
    this.stamp();
    return out;
  }

  /** Stamp this prompt's identity on `span` (default: the active span). Fallbacks stamp nothing. */
  stamp(span: Span | undefined = trace.getActiveSpan()): void {
    if (!span || this.isFallback) return;
    try {
      if (!span.isRecording()) return;
      span.setAttribute(K.promptName, this.name);
      if (this.version) span.setAttribute(K.promptVersion, this.version);
      if (this.label) span.setAttribute(K.promptLabel, this.label);
      if (this.rollout) span.setAttribute(K.promptCohort, this.rollout.cohort);
    } catch {
      // ignore
    }
  }
}

function isMessages(v: unknown): v is ChatMessage[] {
  return Array.isArray(v) && v.every((m) => m && typeof m === "object" && typeof (m as ChatMessage).content === "string" && typeof (m as ChatMessage).role === "string");
}

/** Parse a registry 200 body into a Prompt; null when it is not one. `source`: the destination that answered. */
export function parsePrompt(body: unknown, fallbackName = "", source = ""): Prompt | null {
  if (body === null || typeof body !== "object" || Array.isArray(body)) return null;
  const d = body as Record<string, unknown>;
  let prompt: PromptBody;
  if (typeof d.prompt === "string") prompt = d.prompt;
  else if (isMessages(d.prompt)) prompt = d.prompt.map((m) => ({ role: m.role, content: m.content }));
  else return null;
  const resolved = typeof d.resolved_by === "string" ? d.resolved_by : "";
  const label = resolved.startsWith("label:") ? resolved.slice("label:".length) : "";
  const version = typeof d.version === "number" && Number.isInteger(d.version) ? d.version : 0;
  const ro = d.rollout && typeof d.rollout === "object" && !Array.isArray(d.rollout) ? (d.rollout as Record<string, unknown>) : null;
  const int = (v: unknown) => (typeof v === "number" && Number.isInteger(v) ? v : 0);
  const rollout: PromptRollout | null =
    ro && typeof ro.salt === "string" && ["candidate", "base", "unkeyed"].includes(String(ro.cohort))
      ? {
          baseVersion: int(ro.base_version),
          candidateVersion: int(ro.candidate_version),
          percent: int(ro.percent),
          cohort: ro.cohort as PromptRollout["cohort"],
          key: ro.key === "user" || ro.key === "session" ? ro.key : "",
          salt: ro.salt,
        }
      : null;
  return new Prompt(
    typeof d.name === "string" && d.name ? d.name : fallbackName,
    version,
    label,
    d.type === "chat" || Array.isArray(prompt) ? "chat" : "text",
    prompt,
    d.config && typeof d.config === "object" && !Array.isArray(d.config) ? (d.config as Record<string, unknown>) : {},
    Array.isArray(d.labels) ? d.labels.map(String) : [],
    typeof d.digest === "string" ? d.digest : "",
    false,
    rollout,
    {
      resolvedBy: resolved,
      commitMessage: typeof d.commit_message === "string" ? d.commit_message : "",
      createdAt: typeof d.created_at === "string" ? d.created_at : "",
      source,
    },
  );
}

interface Entry {
  prompt: Prompt;
  etag: string;
  fetchedAt: number;
  refreshing: Promise<void> | null;
  /** The cohort query that filled this entry (revalidated with the same key, section 9.4). */
  query: string;
}

/**
 * The cache: per (destination, name, selector) a group of at most three
 * entries keyed by side (prompts.md v2 section 9.4): `all` for an answer
 * with no rollout, else the side the answer names (`candidate`, `base`,
 * `unkeyed`).
 */
const cache = new Map<string, Map<string, Entry>>();

/** Lowercase hex SHA-256 of a string's UTF-8 bytes (what the SDK sends as user_hash / session_hash). */
export function cohortHash(id: string): string {
  return createHash("sha256").update(id, "utf8").digest("hex");
}

/**
 * The rollout bucket of a subject (`user:<hash>` / `session:<hash>`):
 * uint32 big-endian of the first 4 bytes of SHA-256(salt + "|" + subject),
 * mod 100 (rolloutcore.HashBucket; pinned by sdk/contract/prompt-rollout-cases.json).
 */
export function rolloutBucket(salt: string, subject: string): number {
  return createHash("sha256").update(`${salt}|${subject}`, "utf8").digest().readUInt32BE(0) % 100;
}

interface Cohort {
  /** `user:<hash>`, `session:<hash>` or "" (unkeyed). */
  subject: string;
  /** The query parameter that carries it ("" when unkeyed). */
  query: string;
}

function cohortOf(opts: GetPromptOptions, sel: string): Cohort {
  if (sel.startsWith("version=")) return { subject: "", query: "" }; // a version fetch names its version
  const cur = getCurrentAttributes() as { user?: string; sessionId?: string };
  const user = opts.user ?? cur.user ?? "";
  if (user) {
    const h = cohortHash(user);
    return { subject: `user:${h}`, query: `&user_hash=${h}` };
  }
  const session = opts.sessionId ?? cur.sessionId ?? "";
  if (session) {
    const h = cohortHash(session);
    return { subject: `session:${h}`, query: `&session_hash=${h}` };
  }
  return { subject: "", query: "" };
}

const sideOf = (p: Prompt) => p.rollout?.cohort ?? "all";
const rolloutSig = (p: Prompt) => (p.rollout ? `${p.rollout.candidateVersion}|${p.rollout.percent}|${p.rollout.salt}` : "");

/** The side this cohort is served from a group (section 9.4): bucket with a cached rollout, else `all`. */
function sideFor(group: Map<string, Entry>, c: Cohort): string {
  const withRollout = [...group.values()].find((e) => e.prompt.rollout);
  if (!withRollout) return "all";
  if (!c.subject) return "unkeyed";
  const r = withRollout.prompt.rollout!;
  return rolloutBucket(r.salt, c.subject) < r.percent ? "candidate" : "base";
}

/** Store an answer under the side it names; a changed rollout drops the other sides. */
function store(key: string, p: Prompt, etag: string, query: string): void {
  let group = cache.get(key);
  if (!group) cache.set(key, (group = new Map()));
  const sig = rolloutSig(p);
  for (const [side, e] of group) if (rolloutSig(e.prompt) !== sig) group.delete(side);
  group.set(sideOf(p), { prompt: p, etag, fetchedAt: Date.now(), refreshing: null, query });
}

export function clearPromptCache(): void {
  cache.clear();
}

/** How many entries the prompt cache holds (tests and diagnostics). */
export function promptCacheSize(): number {
  let n = 0;
  for (const g of cache.values()) n += g.size;
  return n;
}

function selector(opts: GetPromptOptions): string {
  if (opts.version !== undefined && opts.label !== undefined) {
    throw new TypeError("@superbased/sdk: getPrompt takes label or version, not both");
  }
  if (opts.version !== undefined) {
    if (!Number.isInteger(opts.version) || opts.version < 1) throw new RangeError("@superbased/sdk: prompt version must be a positive integer");
    return `version=${opts.version}`;
  }
  const label = opts.label || DEFAULT_PROMPT_LABEL;
  if (!(PROMPT_LABELS as readonly string[]).includes(label)) {
    throw new RangeError(`@superbased/sdk: prompt label must be one of ${PROMPT_LABELS.join(", ")}, got ${JSON.stringify(label)}`);
  }
  return `label=${label}`;
}

/** The envelope codes that mean "this server has no such prompt" (contract prompts.md). */
const NOT_FOUND_CODES = new Set(["prompt_not_found", "version_not_found", "label_not_set", "not_implemented"]);

/** The prompt name rule (contract sdk-api-surface.md section 7.3). */
const PROMPT_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

function envelopeCode(r: ControlResponse): string {
  const b = r.body;
  return b && typeof b === "object" && typeof (b as { error?: unknown }).error === "string" ? (b as { error: string }).error : "";
}

/**
 * Whether a response means "this server has no such prompt": a 404 or 501
 * with a not-found code, or without an envelope (an older machine or org
 * stub with no registry route). The same rule as Python's `_not_found`.
 */
function notFound(r: ControlResponse): boolean {
  if (r.status !== 404 && r.status !== 501) return false;
  const code = envelopeCode(r);
  return !code || NOT_FOUND_CODES.has(code);
}

function describe(r: ControlResponse): string {
  if (r.status === 501 || (r.status === 404 && !envelopeCode(r))) return `${r.target}: this server has no prompt registry`;
  return `${r.target}: ${r.status ? `HTTP ${r.status} ` : ""}${r.error}${r.message ? `: ${r.message}` : ""}`;
}

/** One GET of the prompt on one destination (never rejects). */
function fetchOne(t: Target, name: string, sel: string, opts: GetPromptOptions, etag: string, query = ""): Promise<ControlResponse> {
  const n = encodeURIComponent(name);
  const route = { online: `/prompts/${n}?${sel}${query}`, local: `/api/obs/sdk/prompts/${n}?${sel}${query}` };
  return call(t, "GET", route, { headers: etag ? { "If-None-Match": etag } : {}, timeoutMs: apiTimeout(opts), quiet404: true });
}

/**
 * The cache key: ONE destination (its name and base URL), the name and the
 * selector. Each destination keeps its own entry and revalidates against
 * itself only, so under `both` a gateway that blips during revalidation
 * can never drop a prompt the machine (or the gateway itself) served
 * (review finding R-B08; Python keys the same way).
 */
function keyOf(t: Target, name: string, sel: string): string {
  return JSON.stringify([t.name, t.base, name, sel]);
}

/**
 * Revalidate one entry against the destination that served it, with its
 * stored ETag: 304 renews it, 200 replaces it, that destination's own 404
 * (a not-found code, or no registry) drops it, and any other failure keeps
 * serving the cached copy (the failure is logged by `call`, at most once a
 * minute).
 */
function refresh(key: string, side: string, t: Target, name: string, sel: string, opts: GetPromptOptions, e: Entry): Promise<void> {
  if (e.refreshing) return e.refreshing;
  e.refreshing = track(
    fetchOne(t, name, sel, opts, e.etag, e.query).then((r) => {
      if (r.status === 304) {
        e.fetchedAt = Date.now();
        return;
      }
      if (r.ok) {
        const p = parsePrompt(r.body, name, t.name);
        if (p) {
          const group = cache.get(key);
          if (group && sideOf(p) !== side) group.delete(side); // this key's side changed
          store(key, p, r.etag, e.query);
        }
        return; // a 200 that is not a prompt keeps the cached copy
      }
      if (notFound(r)) {
        const group = cache.get(key);
        group?.delete(side);
        if (group && !group.size) cache.delete(key);
      }
    }),
  ).finally(() => {
    e.refreshing = null;
  });
  return e.refreshing;
}

function stampIfInSpan(p: Prompt): Prompt {
  p.stamp();
  return p;
}

/**
 * Get a prompt from the registry.
 *
 * ```ts
 * const p = await getPrompt("support-reply", { fallback: "Answer: {{question}}" });
 * const text = p.compile({ question }); // also stamps the active span
 * ```
 *
 * The destinations are asked in order (`both`: the gateway, then the
 * machine); the first one holding a cached copy serves it, else the first
 * one that answers 200. Fresh for `cacheTtlMs`; stale, the cached copy is
 * returned at once and revalidated in the background against the same
 * destination (`cacheTtlMs: 0` revalidates before returning). With nothing
 * cached and no destination answering: `fallback` when given, else
 * `PromptNotFound` (every destination said not found) or `PromptFetchError`.
 */
export async function getPrompt(name: string, opts: GetPromptOptions = {}): Promise<Prompt> {
  if (typeof name !== "string" || !PROMPT_NAME.test(name)) {
    throw new TypeError(`@superbased/sdk: prompt name ${JSON.stringify(name)} must match ${PROMPT_NAME.source}`);
  }
  const sel = selector(opts);
  const ttl = Math.max(0, opts.cacheTtlMs ?? runtime.settings?.promptCacheTtlMs ?? envTtl());
  const errors: string[] = [];
  let allNotFound = true;
  let last: ControlResponse | null = null;
  const cohort = cohortOf(opts, sel);
  await destinationKnown();
  const sides = targets("read", opts);
  // A degraded online has no target: that is a fetch failure (the reason
  // says why), never "not found" (contract section 6; as Python).
  if (!sides.length) allNotFound = false;
  for (const t of sides) {
    const key = keyOf(t, name, sel);
    const group = cache.get(key);
    const side = group ? sideFor(group, cohort) : "";
    const hit = group?.get(side);
    if (hit) {
      if (Date.now() - hit.fetchedAt < ttl) return stampIfInSpan(hit.prompt);
      if (ttl > 0) {
        void refresh(key, side, t, name, sel, opts, hit); // stale-while-revalidate
        return stampIfInSpan(hit.prompt);
      }
      await refresh(key, side, t, name, sel, opts, hit);
      const now = cache.get(key)?.get(sideFor(cache.get(key) ?? new Map(), cohort));
      if (now) return stampIfInSpan(now.prompt);
      // this destination dropped it (its own 404): ask the next one
      continue;
    }
    const r = await fetchOne(t, name, sel, opts, "", cohort.query);
    last = r;
    if (r.ok && r.status !== 304) {
      const p = parsePrompt(r.body, name, t.name);
      if (p) {
        store(key, p, r.etag, cohort.query);
        return stampIfInSpan(p);
      }
      allNotFound = false;
      errors.push(`${t.name}: the body is not a prompt`);
      continue;
    }
    if (notFound(r)) {
      errors.push(describe(r));
      continue;
    }
    allNotFound = false;
    errors.push(describe(r));
  }
  if (opts.fallback !== undefined) {
    const type = Array.isArray(opts.fallback) ? "chat" : "text";
    return new Prompt(name, 0, "", type, opts.fallback, {}, [], "", true);
  }
  const detail = errors.join("; ") || noTargetReason();
  if (allNotFound) throw new PromptNotFound(`prompt ${JSON.stringify(name)} (${sel}) not found: ${detail}`, last?.status ?? 0, last?.error ?? "no_target");
  throw new PromptFetchError(`prompt ${JSON.stringify(name)} (${sel}) could not be fetched: ${detail}`, last?.status ?? 0, last?.error ?? "");
}

function envTtl(): number {
  const raw = ((typeof process !== "undefined" ? process.env.SUPERBASED_PROMPT_CACHE_TTL_MS : "") ?? "").trim();
  const n = Number(raw);
  return raw && Number.isFinite(n) && n >= 0 ? n : 60_000;
}
