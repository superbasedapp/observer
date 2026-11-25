/**
 * The SDK control API client: scores, prompts, datasets and experiments are
 * not OTLP, so they go over JSON HTTP to the same places spans go.
 *
 * - online: `<orgUrl>/v1/sdk/<path>` on the org or SaaS gateway, with the
 *   SDK key as `Authorization: Bearer` (lane A5, `internal/orgserver/sdkapi`).
 * - local: this machine's Observer dashboard API (`nodeUrl`), on the
 *   route the owning lane names (B7 scores and experiments, B8 prompts). The
 *   org key is never sent there.
 *
 * Writes go to every target of the destination in force (`both` writes to
 * both, each independently); reads try online first, then local.
 *
 * Never rejects: every call resolves to a {@link ControlResponse}. Failures
 * are counted in `diagnostics()` and logged at most once a minute.
 */

import { ONLINE_FIX, type Settings } from "./config.js";
import { fetchBounded, startTimer, transportDetail } from "./http.js";
import { notePlanRefusal, parsePlanRefusal, type PlanRefusalError } from "./planrefusal.js";
import { runtime } from "./runtime.js";

/** Header the SDK control API versions on (`sdkapi`). */
export const SDK_API_VERSION_HEADER = "X-SBO-SDK-API-Version";
export const SDK_API_VERSION = "1";
/** Path prefix on the org gateway. */
export const ONLINE_CONTROL_PREFIX = "/v1/sdk";

export type TargetName = "local" | "online";

/** Where a control call may go; every field falls back to the `init()` settings and env. */
export interface ControlOptions {
  /** Org or SaaS gateway base URL. Env: SUPERBASED_ORG_URL. */
  orgUrl?: string;
  /** SDK key for the gateway. Env: SUPERBASED_API_KEY. */
  apiKey?: string;
  /** This machine's Observer dashboard API. Env: SUPERBASED_NODE_URL. */
  nodeUrl?: string;
  /** Force one target instead of following the destination. */
  target?: TargetName;
  /** Extra request headers (sent to the online target only). */
  headers?: Record<string, string>;
  /** Per-request timeout in ms (default: the apiTimeoutMs setting, 5000). */
  timeoutMs?: number;
}

export interface Target {
  name: TargetName;
  /** Origin plus prefix: `<orgUrl>/v1/sdk` or `<nodeUrl>`. */
  base: string;
  headers: Record<string, string>;
}

/** A route on each side: the online path under /v1/sdk and the machine's own path. */
export interface Route {
  online: string;
  local: string;
}

export interface ControlResponse {
  target: TargetName;
  url: string;
  /** HTTP status (0 when no response arrived). */
  status: number;
  ok: boolean;
  /** Parsed JSON body (undefined when none or not JSON). */
  body: unknown;
  etag: string;
  /** The error envelope's `error` code, or a client-side reason (`transport`, `timeout`, `bad_response`). */
  error: string;
  message: string;
  /** The org's plan refusal (403 `plan_required`, or a 429 over the plan's allowance), when this answer is one. */
  planRefusal?: PlanRefusalError;
}

export const controlStats = {
  calls: 0,
  failures: 0,
  lastError: "",
  lastErrorAt: 0,
  lastLoggedAt: 0,
  unlogged: 0,
};

const inflight = new Set<Promise<unknown>>();

/** Track a background control call so flush() can wait for it. */
export function track<T>(p: Promise<T>): Promise<T> {
  inflight.add(p);
  void p.finally(() => inflight.delete(p)).catch(() => undefined);
  return p;
}

/** Settles when every tracked control call has settled. */
export function controlIdle(): Promise<void> {
  return Promise.allSettled([...inflight]).then(() => undefined);
}

export function resetControlForTests(): void {
  inflight.clear();
  Object.assign(controlStats, { calls: 0, failures: 0, lastError: "", lastErrorAt: 0, lastLoggedAt: 0, unlogged: 0 });
}

function env(): Record<string, string | undefined> {
  return (typeof process !== "undefined" ? process.env : {}) as Record<string, string | undefined>;
}

const trim = (u: string) => u.replace(/\/+$/, "");

/** The effective settings for a call: init's (with what discovery filled in), then env. */
function base(opts: ControlOptions): Pick<Settings, "orgUrl" | "apiKey" | "nodeUrl" | "onlineHeaders" | "apiTimeoutMs"> {
  const s = runtime.settings;
  const e = env();
  return {
    orgUrl: trim(opts.orgUrl ?? s?.orgUrl ?? (e.SUPERBASED_ORG_URL ?? "").trim()),
    apiKey: opts.apiKey ?? s?.apiKey ?? (e.SUPERBASED_API_KEY ?? "").trim(),
    nodeUrl: trim(opts.nodeUrl ?? s?.nodeUrl ?? ((e.SUPERBASED_NODE_URL ?? "").trim() || "http://127.0.0.1:8081")),
    onlineHeaders: { ...(opts.headers ?? {}) },
    apiTimeoutMs: s?.apiTimeoutMs ?? 5000,
  };
}

/** The default per-call timeout. */
export function apiTimeout(opts: ControlOptions): number {
  return opts.timeoutMs ?? base(opts).apiTimeoutMs;
}

function online(opts: ControlOptions): Target | null {
  const b = base(opts);
  if (!b.orgUrl || !(b.apiKey || Object.keys(b.onlineHeaders).some((h) => h.toLowerCase() === "authorization"))) return null;
  const headers: Record<string, string> = { ...b.onlineHeaders };
  if (b.apiKey && !Object.keys(headers).some((h) => h.toLowerCase() === "authorization")) headers.Authorization = `Bearer ${b.apiKey}`;
  return { name: "online", base: b.orgUrl + ONLINE_CONTROL_PREFIX, headers };
}

function local(opts: ControlOptions): Target {
  return { name: "local", base: base(opts).nodeUrl, headers: {} };
}

/**
 * The targets a call goes to, in order, online first. `write` = every
 * target of the destination; `read` = the same list, and the caller stops at
 * the first answer. `online` needs a gateway URL and a credential (contract
 * destination.md section 7); without them `online` has no target and `both`
 * keeps only the machine.
 */
export function targets(kind: "read" | "write", opts: ControlOptions = {}): Target[] {
  const on = online(opts);
  const lo = local(opts);
  if (opts.target === "online") return on ? [on] : [];
  if (opts.target === "local") return [lo];
  const dest = runtime.destination;
  if (dest === "local") return [lo];
  if (dest === "online") return on ? [on] : [];
  // Online first for reads and writes alike (contract section 6; Python's order).
  if (dest === "both") return [...(on ? [on] : []), lo];
  // No destination chosen (a caller-supplied exporter, or before init): online when configured, else local.
  return on ? [on] : [lo];
}

/** Why there is no target for a call ("" when there is one). */
export function noTargetReason(): string {
  return `no destination for this call: online needs a gateway URL and an SDK credential (${ONLINE_FIX})`;
}

/** The URL path of `route` on target `t`. */
export function pathOn(t: Target, route: Route): string {
  return t.name === "online" ? route.online : route.local;
}

function noteFailure(r: ControlResponse): void {
  controlStats.failures += 1;
  controlStats.unlogged += 1;
  controlStats.lastError = `${r.target} ${r.url}: ${r.status ? `HTTP ${r.status} ` : ""}${r.error}${r.message ? `: ${r.message}` : ""}`.slice(0, 500);
  controlStats.lastErrorAt = Date.now();
  const now = Date.now();
  if (runtime.settings?.debug || now - controlStats.lastLoggedAt >= 60_000) {
    const n = controlStats.unlogged;
    controlStats.unlogged = 0;
    controlStats.lastLoggedAt = now;
    try {
      console.warn(`@superbased/sdk: ${n} control API call(s) failed; last: ${controlStats.lastError}`);
    } catch {
      // ignore
    }
  }
}

/** One HTTP call to one target. Never rejects. */
export async function call(
  t: Target,
  method: "GET" | "POST",
  path: string | Route,
  opts: { body?: unknown; headers?: Record<string, string>; timeoutMs?: number; quiet404?: boolean } = {},
): Promise<ControlResponse> {
  controlStats.calls += 1;
  const url = t.base + (typeof path === "string" ? path : pathOn(t, path));
  const out: ControlResponse = { target: t.name, url, status: 0, ok: false, body: undefined, etag: "", error: "", message: "" };
  const ms = opts.timeoutMs ?? runtime.settings?.apiTimeoutMs ?? 5000;
  const timer = startTimer(ms, true);
  try {
    const headers: Record<string, string> = {
      Accept: "application/json",
      [SDK_API_VERSION_HEADER]: SDK_API_VERSION,
      ...t.headers,
      ...(opts.headers ?? {}),
    };
    let payload: string | undefined;
    if (opts.body !== undefined) {
      headers["Content-Type"] = "application/json";
      payload = JSON.stringify(opts.body);
    }
    // fetchBounded never follows a redirect (R-B26): a 3xx comes back as a refused response below.
    const sent = await fetchBounded(url, { method, headers, body: payload }, timer);
    if ("failed" in sent) {
      out.error = timer.timedOut() ? "timeout" : "transport";
      out.message = timer.timedOut() ? `timed out after ${ms}ms` : transportDetail(sent.failed);
      noteFailure(out);
      return out;
    }
    const resp = sent.resp;
    out.status = resp.status;
    out.etag = resp.headers.get("etag") ?? "";
    let text = "";
    try {
      text = await resp.text();
    } catch (err) {
      out.error = timer.timedOut() ? "timeout" : "transport";
      out.message = String(err);
      noteFailure(out);
      return out;
    }
    if (text) {
      try {
        out.body = JSON.parse(text);
      } catch {
        out.body = undefined;
      }
    }
    out.ok = resp.ok || resp.status === 304;
    if (resp.type === "opaqueredirect" || (resp.status >= 300 && resp.status < 400 && resp.status !== 304)) {
      out.ok = false;
      out.status = resp.status;
      out.error = "redirect_refused";
      out.message = `the server answered a redirect${resp.headers.get("location") ? ` to ${resp.headers.get("location")}` : ""}; control calls follow none`;
      noteFailure(out);
      return out;
    }
    if (!out.ok) {
      const b = (out.body ?? {}) as Record<string, unknown>;
      out.error = typeof b.error === "string" ? b.error : `http_${resp.status}`;
      out.message = typeof b.message === "string" ? b.message : "";
      const refusal = parsePlanRefusal(resp.status, out.body ?? text, resp.headers);
      if (refusal) {
        out.planRefusal = refusal;
        notePlanRefusal(refusal); // diagnostics(); the call reports it its own way
      }
      if (!(opts.quiet404 && resp.status === 404)) noteFailure(out);
    }
    return out;
  } catch (err) {
    out.error = "bad_response";
    out.message = String(err);
    noteFailure(out);
    return out;
  } finally {
    timer.clear();
  }
}

/** A random id for idempotent writes (a retried write carries the same id). */
export function newId(): string {
  const c = (globalThis as { crypto?: { randomUUID?: () => string } }).crypto;
  if (c?.randomUUID) return c.randomUUID();
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (ch) => {
    const r = (Math.random() * 16) | 0;
    return (ch === "x" ? r : (r & 0x3) | 0x8).toString(16);
  });
}

/**
 * Whether a failed response is worth one retry (transport, timeout, 429,
 * 5xx). A 429 over the plan's allowance is not: it holds until the plan
 * changes or the month turns.
 */
export function retryable(r: ControlResponse): boolean {
  return !r.ok && !r.planRefusal && (r.status === 0 || r.status === 429 || r.status >= 500);
}
