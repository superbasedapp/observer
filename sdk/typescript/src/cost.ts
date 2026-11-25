/**
 * Exact cost, the SDK side (W4-2; contract `contracts/cost-source.md`, lane
 * C2; the Python twin is `get_trace_cost`, lane C5).
 *
 * - `getTraceCost(traceId)`: where a trace's cost came from, span by span:
 *   `costSource` (`gateway_exact`, `proxy_exact`, `computed`, `reported`, or
 *   `""` = unpriced), every number kept, and the exact-minus-reported
 *   delta. Online: `GET <org>/v1/sdk/traces/{id}/cost` (scope `sdk:read`);
 *   local: `GET <machine>/api/obs/trace/{id}` (its `cost` object); `both`:
 *   the org first, then the machine. `null` when no destination has the
 *   trace (or none answered).
 * - The join key: the org AI gateway answers every inference with
 *   `X-SBO-Request-Id` and honours one the client sends. `gatewayFetch()`
 *   wraps `fetch` for a client pointed at the gateway: it sends an id when
 *   the caller set none and stamps the id the gateway answered with on the
 *   active span as `request_id` (contract section 4 rule 1), so the span
 *   joins the gateway's exact record. `stampGatewayRequestId` does the
 *   stamp for a response you got some other way.
 *
 * Never throws for a transport or server failure (resolves null, counted in
 * `diagnostics()`); a bad trace id is a TypeError.
 */

import { trace, type Span } from "@opentelemetry/api";

import { K } from "./attrs.js";
import { serviceName } from "./admit.js";
import type { Env } from "./config.js";
import { getCurrentAttributes } from "./context.js";
import { getTraceparent } from "./propagation.js";
import { apiTimeout, call, newId, targets, type ControlOptions } from "./control.js";
import { destinationKnown, runtime } from "./runtime.js";

/** Where a span's cost came from (contract section 1); `""` is unpriced. */
export type CostSource = "gateway_exact" | "proxy_exact" | "computed" | "reported" | "";

/** Every value, in precedence order (contract section 2), then unpriced. */
export const COST_SOURCES: readonly CostSource[] = ["gateway_exact", "proxy_exact", "computed", "reported", ""];

/** The display label every cost cell prints (contract section 1). */
export const COST_SOURCE_LABELS: Readonly<Record<string, string>> = {
  gateway_exact: "Gateway exact",
  proxy_exact: "Proxy exact",
  computed: "Computed",
  reported: "Reported",
  "": "Unpriced",
};

/** Whether a source is one of the exact family (`gateway_exact`, `proxy_exact`). */
export function isExactCost(source: string): boolean {
  return source === "gateway_exact" || source === "proxy_exact";
}

/** The response header that carries (and accepts) the gateway's request id. */
export const GATEWAY_REQUEST_ID_HEADER = "X-SBO-Request-Id";

/** A trace's cost label (contract section 5). */
export interface CostProvenance {
  /** `gateway_exact`, `proxy_exact`, `computed`, `reported`, `mixed` or `unpriced`. */
  label: string;
  /** False when a cost-bearing span is unpriced, so the total leaves something out ("partial"). */
  complete: boolean;
  sources: { gatewayExact: number; proxyExact: number; computed: number; reported: number; unpriced: number };
}

/** One cost-bearing span (contract section 6); a number is null where it is absent. */
export interface SpanCost {
  spanId: string;
  model: string;
  /** null when `costSource` is "" (unpriced): never show it as $0. */
  costUsd: number | null;
  costSource: CostSource;
  reportedUsd: number | null;
  computedUsd: number | null;
  exactUsd: number | null;
  /** Exact minus reported; set only when the source is exact and the span reported a cost. */
  costDeltaUsd: number | null;
  gatewayRequestId: string;
}

/** A trace's cost, span by span (contract section 6, camelCased). */
export interface TraceCost {
  traceId: string;
  /** The sum of the priced spans; null when nothing is priced. */
  costUsd: number | null;
  costProvenance: CostProvenance;
  /** Cost-bearing spans only, in start order. */
  spans: SpanCost[];
  /** Which destination answered: `online` (the org) or `local` (this machine). */
  destination: "online" | "local";
}

const TRACE = /^[0-9a-f]{32}$/;

function obj(v: unknown): Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
}
const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);
const str = (v: unknown): string => (typeof v === "string" ? v : "");
const count = (v: unknown): number => (typeof v === "number" && Number.isFinite(v) ? v : 0);

function source(v: unknown): CostSource {
  const s = str(v);
  return (COST_SOURCES as readonly string[]).includes(s) ? (s as CostSource) : "";
}

/** Parse a TraceCost body (org response or the machine's `cost` object); null when it is not one. */
export function parseTraceCost(body: unknown, destination: "online" | "local", wantTrace = ""): TraceCost | null {
  const b = obj(body);
  if (!("trace_id" in b) && !("spans" in b) && !("cost_provenance" in b)) return null;
  const p = obj(b.cost_provenance);
  const src = obj(p.sources);
  const spans = Array.isArray(b.spans) ? b.spans : [];
  return {
    traceId: str(b.trace_id) || wantTrace,
    costUsd: num(b.cost_usd),
    costProvenance: {
      label: str(p.label) || "unpriced",
      complete: p.complete !== false,
      sources: {
        gatewayExact: count(src.gateway_exact),
        proxyExact: count(src.proxy_exact),
        computed: count(src.computed),
        reported: count(src.reported),
        unpriced: count(src.unpriced),
      },
    },
    spans: spans.map((raw) => {
      const s = obj(raw);
      const cs = source(s.cost_source);
      return {
        spanId: str(s.span_id),
        model: str(s.model),
        costUsd: cs ? num(s.cost_usd) : null,
        costSource: cs,
        reportedUsd: num(s.reported_usd),
        computedUsd: num(s.computed_usd),
        exactUsd: num(s.exact_usd),
        costDeltaUsd: num(s.cost_delta_usd),
        gatewayRequestId: str(s.gateway_request_id),
      };
    }),
    destination,
  };
}

/**
 * Where a trace's cost came from, span by span. `traceId` defaults to the
 * current trace; with no trace it resolves null without a call. Resolves
 * null when no destination has the trace or none answered; rejects only
 * with a RangeError for a trace id that is not 32 hex characters (or all
 * zero), as Python raises ValueError.
 */
export async function getTraceCost(traceId?: string, opts: ControlOptions = {}): Promise<TraceCost | null> {
  let id: string;
  if (traceId === undefined || traceId === null) {
    const ctx = trace.getActiveSpan()?.spanContext();
    id = ctx && TRACE.test(ctx.traceId) && !/^0+$/.test(ctx.traceId) ? ctx.traceId : "";
    if (!id) return null;
  } else {
    id = String(traceId).trim().toLowerCase();
    if (!TRACE.test(id) || /^0+$/.test(id)) throw new RangeError(`@superbased/sdk: trace id ${JSON.stringify(traceId)} must be 32 hex characters, not all zero`);
  }
  const route = { online: `/traces/${id}/cost`, local: `/api/obs/trace/${id}` };
  await destinationKnown();
  for (const t of targets("read", opts)) {
    const r = await call(t, "GET", route, { timeoutMs: apiTimeout(opts), quiet404: true });
    if (!r.ok || r.status === 304) continue;
    const body = t.name === "local" ? obj(r.body).cost : r.body;
    const parsed = parseTraceCost(body, t.name, id);
    if (parsed) return parsed;
  }
  return null;
}

/** The gateway's request id from a Response, a Headers object or a plain header record ("" when absent). */
export function gatewayRequestId(from: unknown): string {
  if (!from || typeof from !== "object") return "";
  const h = (from as { headers?: unknown }).headers ?? from;
  if (h && typeof (h as { get?: unknown }).get === "function") return ((h as Headers).get(GATEWAY_REQUEST_ID_HEADER) ?? "").trim();
  for (const [k, v] of Object.entries(h as Record<string, unknown>)) {
    if (k.toLowerCase() === GATEWAY_REQUEST_ID_HEADER.toLowerCase()) return String(Array.isArray(v) ? v[0] : v).trim();
  }
  return "";
}

/**
 * Stamp the gateway's request id (from a response or its headers) on `span`
 * (default: the active span) as `request_id`, the exact join key. A no-op
 * when there is no id or no recording span. Returns the id.
 */
export function stampGatewayRequestId(from: unknown, span?: Span): string {
  const id = gatewayRequestId(from);
  const sp = span ?? trace.getActiveSpan();
  if (id && sp?.isRecording()) sp.setAttribute(K.requestId, id);
  return id;
}

type FetchLike = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

/** The headers the org AI gateway reads a hosted app's end user and service from (its app budget scopes). */
const GATEWAY_USER_HEADER = "X-Superbased-User";
const GATEWAY_SERVICE_HEADER = "X-Superbased-Service";
/** The gateway ignores a longer value (internal/aigateway/gwhttp maxAppIDLen). */
const MAX_APP_ID_LEN = 512;

/** Set an app identity header unless the request has one; skip an empty, too long or non-header-safe value. Never throws. */
function setAppHeader(headers: Headers, name: string, value: string): void {
  const v = value.trim();
  if (!v || headers.has(name) || new TextEncoder().encode(v).length > MAX_APP_ID_LEN) return;
  try {
    headers.set(name, v);
  } catch {
    // a value fetch cannot send as a header (non-Latin-1): leave it out
  }
}

/**
 * A `fetch` for a client that calls the org AI gateway (`new OpenAI({
 * baseURL: <gateway>, fetch: gatewayFetch() })`): it sends an
 * `X-SBO-Request-Id` when the request carries none, and stamps the id the
 * gateway answered with on the span that is active when the call is made
 * (an instrumentation's LLM span), so the span joins the gateway's exact
 * cost record. It also names the app's end user and service
 * (`X-Superbased-User`, `X-Superbased-Service`), which the gateway's app
 * budget caps reserve against, and sends the active span's `traceparent`: the per-request user (propagateAttributes /
 * identify, else init's user) and the service name admit() sends. A header
 * the request already carries is kept. Pass it only to a client pointed at
 * the gateway: the end user is PII, and the gateway never forwards these
 * headers upstream.
 */
export function gatewayFetch(base?: FetchLike): FetchLike {
  const f: FetchLike = base ?? ((i, n) => fetch(i, n));
  return async (input, init) => {
    const span = trace.getActiveSpan();
    const headers = new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined));
    if (!headers.has(GATEWAY_REQUEST_ID_HEADER)) headers.set(GATEWAY_REQUEST_ID_HEADER, `sdk-${newId()}`);
    setAppHeader(headers, GATEWAY_USER_HEADER, getCurrentAttributes().user || runtime.settings?.user || "");
    setAppHeader(headers, GATEWAY_SERVICE_HEADER, serviceName((typeof process !== "undefined" ? process.env : {}) as Env));
    // The span active when the call is made, so the organization joins the call to it even without the request id.
    if (!headers.has("traceparent")) {
      const tp = getTraceparent();
      if (tp) headers.set("traceparent", tp);
    }
    const sent = headers.get(GATEWAY_REQUEST_ID_HEADER) ?? "";
    const resp = await f(input, { ...(init ?? {}), headers });
    const got = gatewayRequestId(resp) || sent;
    if (got && span?.isRecording()) span.setAttribute(K.requestId, got);
    return resp;
  };
}
