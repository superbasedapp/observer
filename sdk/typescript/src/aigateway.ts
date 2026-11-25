/**
 * AI gateway helpers (hosted AI gateway arc L-172, lane L8; the shared cases
 * are `sdk/contract/ai-gateway-cases.json`).
 *
 * The AI gateway is the proxy an app's model calls go through on their way
 * to the provider: it prices each call exactly, holds the app's budgets and
 * applies the organization's model, egress and admission rules. It runs in
 * three places with one client shape:
 *
 * - the organization's address, `https://<org host>/ai/<upstream>` (hosted,
 *   or a self-hosted server with its path lane);
 * - any address you name (a self-hosted gateway on its own listener);
 * - this machine's app lane, `http://127.0.0.1:8820/up/<lane>`.
 *
 * {@link gatewayBaseUrl} resolves which one applies; {@link openAIOptions}
 * and {@link anthropicOptions} are the options for `new OpenAI(...)` and
 * `new Anthropic(...)`; {@link parseGatewayRefusal} reads a refusal.
 */

import { resolveSettings, type Env, type Settings } from "./config.js";
import { gatewayFetch } from "./cost.js";
import { discoverDestination, isLoopbackUrl, type Discovered } from "./destination.js";
import { parsePlanRefusal, PLAN_REQUIRED, AIGW_QUOTA_EXCEEDED, type HeadersLike, type PlanRefusalError } from "./planrefusal.js";
import { runtime } from "./runtime.js";

/** The client families (seam S4's `upstreams[].client`). */
export type GatewayProvider = "openai" | "anthropic" | "azure_openai";

export const AI_GATEWAY_URL_ENV = "SUPERBASED_AI_GATEWAY_URL";
export const AI_GATEWAY_KEY_ENV = "SUPERBASED_AI_GATEWAY_KEY";
export const GATEWAY_UPSTREAM_HEADER = "X-SBO-Upstream";

/** Where a base URL came from. */
export type GatewaySource = "argument" | "env" | "org" | "machine";

/** Why no base URL could be resolved ({@link GatewayNotConfiguredError.problem}). */
export type GatewayProblem = "unknown_provider" | "bad_upstream" | "upstream_required" | "bad_url" | "not_configured" | "no_key";

/** Where a model client sends its calls. */
export interface GatewayEndpoint {
  /** The client's base URL option. */
  baseUrl: string;
  source: GatewaySource;
  /** The upstream id ("" when the address names none). */
  upstream: string;
  /** The `X-SBO-Upstream` value the client must send ("" when none: the org address and the machine lane carry the upstream in the path). */
  upstreamHeader: string;
}

/** No usable AI gateway address (or key). */
export class GatewayNotConfiguredError extends Error {
  readonly problem: GatewayProblem;
  constructor(problem: GatewayProblem, message: string) {
    super(message);
    this.name = "GatewayNotConfiguredError";
    this.problem = problem;
  }
}

/** client family -> the path its base URL ends in and the upstream used when none is named. One row per family. */
const PROVIDERS: Record<string, { suffix: string; upstream: string }> = {
  openai: { suffix: "/v1", upstream: "openai" },
  anthropic: { suffix: "", upstream: "anthropic" },
  azure_openai: { suffix: "", upstream: "" },
};

/** A pooled upstream id (plan section 3.4); v1 and v1beta read as provider paths. */
const UPSTREAM_RE = /^[a-z0-9][a-z0-9-]{0,31}$/;
const RESERVED = new Set(["v1", "v1beta"]);
const AI_PATH_LANE = "/ai";

/**
 * "" when `raw` is a usable gateway address: http(s), a host, no user info,
 * query or fragment, plain http only to a loopback host (the AI gateway key
 * travels with every call).
 */
export function gatewayUrlProblem(raw: string): string {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return `${JSON.stringify(raw)} is not a URL`;
  }
  if ((u.protocol !== "http:" && u.protocol !== "https:") || !u.hostname) return `${JSON.stringify(raw)} is not an http(s) address with a host`;
  if (u.username || u.password || /^[a-z]+:\/\/[^/]*@/i.test(raw)) return `${JSON.stringify(raw)} carries a user name or password`;
  if (u.search || u.hash || /[?#]/.test(raw)) return `${JSON.stringify(raw)} carries a query or fragment`;
  if (u.protocol === "http:" && !isLoopbackUrl(raw)) return `${JSON.stringify(raw)} is plain http to a remote host`;
  return "";
}

const trimSlash = (s: string) => s.replace(/\/+$/, "");

function withSuffix(base: string, suffix: string): string {
  const b = trimSlash(base);
  return !suffix || b.endsWith(suffix) ? b : b + suffix;
}

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

/** The base URL of the lane named `upstream` in the discovery answer's `local.app_lanes` ("" when none is usable). */
function machineLane(local: unknown, upstream: string): string {
  const lanes = isObj(local) ? local.app_lanes : undefined;
  if (!Array.isArray(lanes)) return "";
  for (const lane of lanes) {
    if (!isObj(lane)) continue;
    const { id, base_url: base } = lane;
    if (typeof id !== "string" || typeof base !== "string" || id !== upstream || !base) continue;
    if (gatewayUrlProblem(base) || !isLoopbackUrl(base)) continue;
    return trimSlash(base);
  }
  return "";
}

/** The pure resolver's inputs; `local` loads the discovery answer's `local` object only when it is needed. */
export interface GatewayResolveInput {
  provider: string;
  upstream?: string | null;
  url?: string | null;
  env?: string | null;
  destination: string;
  orgUrl: string;
  local?: () => unknown;
}

/** The pure resolver's answer: the endpoint, or the problem and a message. */
export type GatewayResolution = { endpoint: GatewayEndpoint; problem: ""; message: "" } | { endpoint: null; problem: GatewayProblem; message: string };

/** The pure resolver (contract base_url cases). */
export function resolveGatewayEndpoint(input: GatewayResolveInput): GatewayResolution {
  const fail = (problem: GatewayProblem, message: string): GatewayResolution => ({ endpoint: null, problem, message });
  const fam = (input.provider ?? "").trim().toLowerCase();
  const row = Object.prototype.hasOwnProperty.call(PROVIDERS, fam) ? PROVIDERS[fam] : undefined;
  if (!row) return fail("unknown_provider", `the AI gateway helpers know the clients openai, anthropic and azure_openai, not ${JSON.stringify(input.provider)}`);
  const named = (input.upstream ?? "").trim();
  if (named && (!UPSTREAM_RE.test(named) || RESERVED.has(named))) {
    return fail("bad_upstream", `upstream ${JSON.stringify(named)} is not an upstream id (lower-case letters, digits and -, at most 32, not v1 or v1beta)`);
  }
  const up = named || row.upstream;
  for (const [value, source, origin] of [
    [input.url, "argument", "the AI gateway URL"],
    [input.env, "env", AI_GATEWAY_URL_ENV],
  ] as const) {
    const v = (value ?? "").trim();
    if (!v) continue;
    const problem = gatewayUrlProblem(v);
    if (problem) return fail("bad_url", `${origin} is not usable: ${problem}`);
    return { endpoint: { baseUrl: withSuffix(v, row.suffix), source, upstream: named, upstreamHeader: named }, problem: "", message: "" };
  }
  const notConfigured =
    `no AI gateway address for ${fam}: pass the URL, set ${AI_GATEWAY_URL_ENV}, use destination online with the ` +
    "organization's address (SUPERBASED_ORG_URL or `observer sdk sign-in`), or add an app lane on this machine (`observer apps lane add`)";
  if (input.destination === "online") {
    const org = trimSlash((input.orgUrl ?? "").trim());
    if (!org || gatewayUrlProblem(org)) return fail("not_configured", notConfigured);
    if (!up) return fail("upstream_required", `the ${fam} client has no default upstream: name one`);
    return { endpoint: { baseUrl: `${org}${AI_PATH_LANE}/${up}${row.suffix}`, source: "org", upstream: up, upstreamHeader: "" }, problem: "", message: "" };
  }
  if (input.destination === "local" || input.destination === "both") {
    if (!up) return fail("upstream_required", `the ${fam} client has no default upstream: name one`);
    const base = machineLane(input.local ? input.local() : undefined, up);
    if (base) return { endpoint: { baseUrl: base + row.suffix, source: "machine", upstream: up, upstreamHeader: "" }, problem: "", message: "" };
  }
  return fail("not_configured", notConfigured);
}

function env(): Env {
  return (typeof process !== "undefined" ? process.env : {}) as Env;
}

/** The machine's discovery answers, asked once per node URL for the life of the process. */
const discoveries = new Map<string, Promise<Discovered | null>>();

function discovered(s: Settings): Promise<Discovered | null> {
  if (!s.discover) return Promise.resolve(null);
  let p = discoveries.get(s.nodeUrl);
  if (!p) {
    p = discoverDestination(s.nodeUrl, s.discoverTimeoutMs).then((r) => r.found);
    discoveries.set(s.nodeUrl, p);
  }
  return p;
}

/** Forget the cached discovery answers and recorded refusals (tests only). */
export function _resetGatewayForTests(): void {
  discoveries.clear();
  recorded.clear();
}

/** Options for {@link gatewayEndpoint}, {@link gatewayBaseUrl} and the client option builders. */
export interface GatewayOptions {
  /** The upstream id (default: the provider's, openai or anthropic). */
  upstream?: string;
  /** The gateway's address for the client, without the provider's API path. Wins over everything else. */
  url?: string;
}

/**
 * Where a model client of the given family sends its calls, first set wins:
 * `url`; `SUPERBASED_AI_GATEWAY_URL`; the organization's address
 * (`<org url>/ai/<upstream>`) when the destination is `online`; this
 * machine's app lane for the upstream (from its loopback discovery answer)
 * when the destination is `local` or `both`. The destination is init()'s
 * once it is known, else the environment's (then the machine's). Rejects
 * with {@link GatewayNotConfiguredError} when nothing applies: it never falls
 * back to the provider itself, which would skip every rule the gateway applies.
 */
export async function gatewayEndpoint(provider: GatewayProvider | string, opts: GatewayOptions = {}): Promise<GatewayEndpoint> {
  await runtime.ready;
  const e = env();
  const s = runtime.settings ?? resolveSettings(e);
  let destination: string = runtime.destination || s.destination;
  let found: Discovered | null | undefined;
  const ask = async () => {
    if (found === undefined) found = await discovered(s);
    return found;
  };
  if (!destination) {
    const d = await ask();
    destination = d?.destination || (s.orgUrl && s.apiKey ? "online" : "local");
  }
  // The pure resolver reads the lanes synchronously: ask the machine first
  // when it can be needed.
  const needLane = !(opts.url ?? "").trim() && !(e[AI_GATEWAY_URL_ENV] ?? "").trim() && (destination === "local" || destination === "both");
  if (needLane) await ask();
  const r = resolveGatewayEndpoint({
    provider,
    upstream: opts.upstream,
    url: opts.url,
    env: e[AI_GATEWAY_URL_ENV],
    destination,
    orgUrl: s.orgUrl,
    local: () => (found ? { app_lanes: found.appLanes } : undefined),
  });
  if (!r.endpoint) throw new GatewayNotConfiguredError(r.problem, r.message);
  return r.endpoint;
}

/** The base URL to give a model client of the given family: {@link gatewayEndpoint}'s `baseUrl`. A string second argument is the upstream. */
export async function gatewayBaseUrl(provider: GatewayProvider | string, opts: GatewayOptions | string = {}): Promise<string> {
  return (await gatewayEndpoint(provider, typeof opts === "string" ? { upstream: opts } : opts)).baseUrl;
}

/** The AI gateway key from `SUPERBASED_AI_GATEWAY_KEY` ("" when unset). */
export function gatewayKey(): string {
  return (env()[AI_GATEWAY_KEY_ENV] ?? "").trim();
}

type FetchLike = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

/** Options for `new OpenAI(...)` or `new Anthropic(...)`. */
export interface GatewayClientOptions {
  baseURL: string;
  /** Left out on this machine's app lane: the client reads the provider's own key variable, which the lane forwards. */
  apiKey?: string;
  fetch: FetchLike;
  defaultHeaders?: Record<string, string>;
}

/** {@link openAIOptions} / {@link anthropicOptions} input. */
export interface GatewayClientInput extends GatewayOptions {
  /** The key (default: SUPERBASED_AI_GATEWAY_KEY; the provider's own on the machine lane). */
  apiKey?: string;
  /** The fetch to wrap (default: the global fetch). */
  fetch?: FetchLike;
}

/**
 * The key a model client sends to an endpoint, by the rule every SDK shares
 * (sdk/contract/ai-gateway-cases.json, api_key): `apiKey` when given; on this
 * machine's app lane undefined (the client sends the provider's own key, which
 * the lane forwards); else SUPERBASED_AI_GATEWAY_KEY; on a loopback address
 * with no gateway key undefined. A remote gateway with no gateway key throws
 * GatewayNotConfiguredError("no_key"), so the provider's own key is never sent
 * there. {@link openAIOptions} and {@link anthropicOptions} apply it.
 */
export function gatewayClientKey(ep: GatewayEndpoint, apiKey?: string): string | undefined {
  if (apiKey) return apiKey;
  if (ep.source === "machine") return undefined;
  const key = gatewayKey();
  if (key) return key;
  if (isLoopbackUrl(ep.baseUrl)) return undefined;
  throw new GatewayNotConfiguredError("no_key", `no AI gateway key for ${ep.baseUrl}: set ${AI_GATEWAY_KEY_ENV} or pass apiKey`);
}

/** Refusals the client fetch saw, by request id (most recent last), for {@link gatewayRefusal}. */
const recorded = new Map<string, GatewayRefusalError>();
const RECORDED_MAX = 64;

function record(r: GatewayRefusalError): void {
  if (!r.requestId) return;
  recorded.delete(r.requestId);
  recorded.set(r.requestId, r);
  while (recorded.size > RECORDED_MAX) recorded.delete(recorded.keys().next().value as string);
}

/** gatewayFetch, without redirects (every call carries the key), recording each refusal it sees. */
function clientFetch(base?: FetchLike): FetchLike {
  const f = gatewayFetch(base);
  return async (input, init) => {
    const resp = await f(input, { ...(init ?? {}), redirect: init?.redirect ?? "manual" });
    if (resp.status >= 400) {
      try {
        const r = parseGatewayRefusal(resp.status, await resp.clone().text(), resp.headers);
        if (r) record(r);
      } catch {
        // the client reads the body itself
      }
    }
    return resp;
  };
}

async function clientOptions(provider: GatewayProvider, input: GatewayClientInput): Promise<GatewayClientOptions> {
  const ep = await gatewayEndpoint(provider, input);
  const out: GatewayClientOptions = { baseURL: ep.baseUrl, fetch: clientFetch(input.fetch) };
  const key = gatewayClientKey(ep, input.apiKey);
  if (key !== undefined) out.apiKey = key;
  if (ep.upstreamHeader) out.defaultHeaders = { [GATEWAY_UPSTREAM_HEADER]: ep.upstreamHeader };
  return out;
}

/**
 * Options for `new OpenAI(...)` pointed at the AI gateway
 * ({@link gatewayEndpoint}): `baseURL`, the key (`apiKey`, else
 * `SUPERBASED_AI_GATEWAY_KEY`; on this machine's app lane the provider's own
 * `OPENAI_API_KEY`, which a remote gateway never receives) and a `fetch` that
 * sends the app identity headers, a request id and the active span's
 * `traceparent` (`gatewayFetch`) and follows no redirect. Rejects with
 * {@link GatewayNotConfiguredError} when there is no address or key.
 *
 *     const openai = new OpenAI(await openAIOptions());
 */
export function openAIOptions(input: GatewayClientInput = {}): Promise<GatewayClientOptions> {
  return clientOptions("openai", input);
}

/** Options for `new Anthropic(...)` pointed at the AI gateway, as {@link openAIOptions} (the provider's own key on the machine lane is `ANTHROPIC_API_KEY`). */
export function anthropicOptions(input: GatewayClientInput = {}): Promise<GatewayClientOptions> {
  return clientOptions("anthropic", input);
}

// --- refusals ------------------------------------------------------------------------

/** What an AI gateway refusal is. */
export type GatewayRefusalKind = "budget_exceeded" | "model_not_allowed" | "admission_denied" | "plan_required" | "quota_exceeded" | "other";

/** code -> the status it rides on and the kind. One row per code; any other code, or a code on another status, is "other". */
const KINDS: Record<string, { status: number; kind: GatewayRefusalKind }> = {
  budget_exceeded: { status: 402, kind: "budget_exceeded" },
  model_not_allowed: { status: 403, kind: "model_not_allowed" },
  admission_denied: { status: 403, kind: "admission_denied" },
  [PLAN_REQUIRED]: { status: 403, kind: "plan_required" },
  [AIGW_QUOTA_EXCEEDED]: { status: 429, kind: "quota_exceeded" },
};

const known = (code: string) => Object.prototype.hasOwnProperty.call(KINDS, code);

/** The cap a 402 refusal names, in the cap's own unit. A `remaining` below zero is how far calls already let through went past the cap; null means the body did not say. */
export interface GatewayBudget {
  level: string | null;
  scopeId: string | null;
  unit: string | null;
  remaining: number | null;
  cap: number | null;
  estimated: boolean;
}

/** The fields of an AI gateway refusal. */
export interface GatewayRefusalFields {
  kind: GatewayRefusalKind;
  code: string;
  status: number;
  message: string;
  requestId: string;
  retryAfterMs?: number;
  budget?: GatewayBudget;
  planRefusal?: PlanRefusalError;
}

/**
 * The AI gateway refused a model call. `kind` is `budget_exceeded` (402),
 * `model_not_allowed`, `admission_denied`, `plan_required` (403),
 * `quota_exceeded` (429, the organization's monthly allowance) or `other`;
 * `code` the gateway's reason; `requestId` its `X-SBO-Request-Id`. `budget`
 * is set for a budget refusal, `planRefusal` for a plan refusal that names
 * where to change the plan.
 */
export class GatewayRefusalError extends Error implements GatewayRefusalFields {
  readonly kind: GatewayRefusalKind;
  readonly code: string;
  readonly status: number;
  readonly requestId: string;
  readonly retryAfterMs?: number;
  readonly budget?: GatewayBudget;
  readonly planRefusal?: PlanRefusalError;

  constructor(f: GatewayRefusalFields) {
    super(f.message);
    this.name = "GatewayRefusalError";
    this.kind = f.kind;
    this.code = f.code;
    this.status = f.status;
    this.requestId = f.requestId;
    if (f.retryAfterMs !== undefined) this.retryAfterMs = f.retryAfterMs;
    if (f.budget) this.budget = f.budget;
    if (f.planRefusal) this.planRefusal = f.planRefusal;
  }
}

const sstr = (v: unknown): string => (typeof v === "string" ? v.trim() : "");

function header(h: HeadersLike, name: string): string {
  if (!h) return "";
  if (typeof (h as Headers).get === "function") return ((h as Headers).get(name) ?? "").trim();
  const want = name.toLowerCase();
  for (const [k, v] of Object.entries(h as Record<string, unknown>)) {
    if (k.toLowerCase() === want) return (Array.isArray(v) ? String(v[0] ?? "") : typeof v === "string" ? v : "").trim();
  }
  return "";
}

function bodyOf(body: unknown): unknown {
  if (typeof body === "string") return body.trim() ? JSON.parse(body) : undefined;
  if (body instanceof Uint8Array) return bodyOf(new TextDecoder("utf-8", { fatal: true }).decode(body));
  return body;
}

function budgetOf(o: Record<string, unknown>): GatewayBudget {
  const unit = typeof o.unit === "string" ? o.unit : null;
  const num = (v: unknown) => (typeof v === "number" && Number.isFinite(v) ? v : null);
  const fields = unit === "usd" ? ["remaining_usd", "cap_usd"] : unit === "tokens" ? ["remaining_tokens", "cap_tokens"] : null;
  return {
    level: typeof o.level === "string" ? o.level : null,
    scopeId: typeof o.scope_id === "string" ? o.scope_id : null,
    unit,
    remaining: fields ? num(o[fields[0]]) : null,
    cap: fields ? num(o[fields[1]]) : null,
    estimated: o.estimated === true,
  };
}

/**
 * The AI gateway refusal in one HTTP answer, or null. `body` is the decoded
 * JSON, or the raw body (a string or bytes). A gateway refusal is a non-2xx
 * answer whose JSON object body carries the gateway's top-level `reason` (or
 * a plan refusal's code as a top-level string `error`); a provider's own
 * error the gateway relays as is, malformed input included, is null. Never
 * throws.
 */
export function parseGatewayRefusal(status: number, body: unknown, headers?: HeadersLike): GatewayRefusalError | null {
  try {
    if (typeof status !== "number" || status < 400) return null;
    const o = bodyOf(body);
    if (!isObj(o)) return null;
    const errStr = sstr(o.error);
    const code = sstr(o.reason) || (known(errStr) ? errStr : "");
    if (!code) return null;
    const row = known(code) ? KINDS[code] : undefined;
    const errObj = isObj(o.error) ? o.error : null;
    const message = sstr(errObj?.message) || sstr(o.message) || (errStr && errStr !== code ? errStr : "") || `the AI gateway refused the call (${code})`;
    const retry = header(headers, "retry-after");
    const f: GatewayRefusalFields = {
      kind: row && row.status === status ? row.kind : "other",
      code,
      status,
      message,
      requestId: header(headers, "x-sbo-request-id") || header(headers, "request-id") || header(headers, "x-request-id"),
    };
    if (/^\d+$/.test(retry)) f.retryAfterMs = Number(retry) * 1000;
    if (code === "budget_exceeded") f.budget = budgetOf(o);
    if (code === PLAN_REQUIRED || code === AIGW_QUOTA_EXCEEDED) {
      // The plan detail is the planrefusal body's top-level fields; its parser reads the code from a string error.
      const norm: Record<string, unknown> = { ...o, error: code };
      if (!sstr(norm.message)) norm.message = message;
      const p = parsePlanRefusal(status, norm, headers);
      if (p) f.planRefusal = p;
    }
    return new GatewayRefusalError(f);
  } catch {
    return null;
  }
}

/** {@link parseGatewayRefusal} over a fetch `Response` (its body is read from a clone). Never rejects. */
export async function gatewayRefusalFromResponse(resp: Response): Promise<GatewayRefusalError | null> {
  try {
    if (resp.status < 400) return null;
    return parseGatewayRefusal(resp.status, await resp.clone().text(), resp.headers);
  } catch {
    return null;
  }
}

/**
 * The AI gateway refusal behind a model SDK's error, or null: the one a
 * client built with {@link openAIOptions} / {@link anthropicOptions} saw for
 * that request id, else the error's own body when it kept the whole body (the
 * Anthropic SDK does; the OpenAI SDK keeps only its `error` object, read when
 * its `code` is a gateway code). Never throws.
 */
export function gatewayRefusal(err: unknown): GatewayRefusalError | null {
  try {
    if (!isObj(err)) return null;
    const headers = (err.headers ?? null) as HeadersLike;
    const status = typeof err.status === "number" ? err.status : 0;
    const id = header(headers, "x-sbo-request-id") || header(headers, "request-id") || header(headers, "x-request-id");
    const seen = id ? recorded.get(id) : undefined;
    if (seen) return seen;
    const body = err.error;
    if (isObj(body)) {
      const whole = parseGatewayRefusal(status, body, headers);
      if (whole) return whole;
      if (known(sstr(body.code))) return parseGatewayRefusal(status, { error: body, reason: sstr(body.code) }, headers);
    }
    return null;
  } catch {
    return null;
  }
}
