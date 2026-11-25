/**
 * `admit()`: the input-admission pre-flight check (admission spec §6.1).
 *
 * Never throws or rejects. Any failure (transport, timeout, HTTP error, a body
 * that is not a JSON object, a field of the wrong type) yields a degraded
 * verdict that admits (fail open, the default) or denies (`failClosed`).
 */

import { trace } from "@opentelemetry/api";

import { envFlag, onlineUsable, resolveServiceName, type Env } from "./config.js";
import { getCurrentAttributes } from "./context.js";
import { isLoopbackUrl } from "./destination.js";
import { fetchBounded, startTimer, transportDetail, type RequestTimer } from "./http.js";
import { notePlanRefusal, parsePlanRefusal, type PlanRefusalError } from "./planrefusal.js";
import { destinationKnown, runtime } from "./runtime.js";

/** Default admission-check endpoint: this machine's Observer API on the dashboard port. */
export const DEFAULT_ADMISSION_ENDPOINT = "http://127.0.0.1:8081/api/obs/admission/check";
/** The path of a machine's admission check. */
const MACHINE_ADMISSION_PATH = "/api/obs/admission/check";
/** Path of the org SDK control API's admission endpoint, under an org URL. */
export const SDK_ADMIT_PATH = "/v1/sdk/admit";
/**
 * Default client timeout (ms). Longer than the server's 10 s judge budget, so
 * the client does not fail open on a request the server would still decide.
 * A server that advertises a recommended timeout (the
 * `recommended_client_timeout_ms` body field or the
 * `X-SBO-Recommended-Timeout-Ms` header, sent by both the org SDK control API
 * and the local machine) overrides it for later calls.
 */
export const DEFAULT_ADMIT_TIMEOUT_MS = 12_000;

/**
 * The advertised-timeout names, canonical first. The second of each pair is
 * the pre-release spelling, still read so an older server keeps working.
 */
export const TIMEOUT_HEADERS = ["x-sbo-recommended-timeout-ms", "x-superbased-admit-timeout-ms"] as const;
export const TIMEOUT_FIELDS = ["recommended_client_timeout_ms", "recommended_timeout_ms"] as const;

/** Client-side degraded reasons (`Verdict.degraded`). Server values pass through. */
export const Degraded = {
  /** HTTP 403/404: admission is off on the server or not permitted. */
  UNAVAILABLE: "admission-unavailable",
  TIMEOUT: "client-timeout",
  TRANSPORT: "client-transport",
  HTTP_ERROR: "client-http-error",
  BAD_RESPONSE: "client-bad-response",
  /**
   * The organization answered mode `off`: it has no admission policy, so it
   * made no decision (live finding L-05, ruling D29). Under destination `both`
   * the SDK then asks this machine; otherwise the verdict is degraded.
   */
  ADMISSION_OFF: "admission-off",
} as const;

/** The result of an {@link admit} check. */
export interface Verdict {
  /**
   * What the app should honour. In `observe` mode the server always returns
   * `true` and records the shadow verdict; in `enforce` mode it returns the
   * real decision (`ask`/`deny` → `false`, `flag` still admits).
   */
  allowed: boolean;
  /** The raw decision, one of: allow / flag / ask / deny. */
  decision: string;
  severity: string;
  /** The criterion id that fired, if any. */
  criterion: string;
  /** A short string to surface to the user on a block. */
  reason: string;
  mode: string;
  /** What enforce mode WOULD decide, so you can measure before flipping. */
  enforceDecision: string;
  /** Empty for a clean decision; otherwise why it is not one (see {@link Degraded}). */
  degraded: string;
  /** Whether the server consulted its LLM judge (server field `judge_used`). */
  judgeUsed: boolean;
  /** Server-side decision latency; for a client-degraded verdict, the client's elapsed time (`latency_ms`). */
  latencyMs: number;
  /** The server's id for the recorded verdict, when it returns one. */
  verdictId: string;
  /** HTTP status of the response (0 when none arrived). */
  httpStatus: number;
  /** Detail for a client-degraded verdict. */
  error: string;
  /**
   * Set when the org's plan refused the check (its `message` and
   * `upgradeUrl` say why and where to fix it); the verdict is degraded as
   * for any other refusal.
   */
  planRefusal?: PlanRefusalError;
}

export interface AdmitOptions {
  /** The app's tenant. Defaults to the request scope's (`propagateAttributes`), then `init`'s. */
  tenant?: string;
  /** The app's end user. Defaults to the request scope's, then `init`'s. */
  user?: string;
  /** The app's session. Defaults to the request scope's `sessionId`, then `init`'s. */
  session?: string;
  /** Defaults to the active span's trace id. */
  traceId?: string;
  requestId?: string;
  /** Full admission URL. Defaults to $SUPERBASED_ADMISSION_ENDPOINT, then the destination (see resolveTarget), then this machine. */
  endpoint?: string;
  /** Org base URL; the check goes to `<orgUrl>/v1/sdk/admit`. Env: SUPERBASED_ORG_URL. */
  orgUrl?: string;
  /**
   * SDK credential, sent as `Authorization: Bearer`. Env: SUPERBASED_API_KEY.
   * Only an explicit `apiKey` goes to a loopback endpoint; the configured key
   * rides only to an org URL or an explicit remote endpoint.
   */
  apiKey?: string;
  /** Extra or overriding request headers. */
  headers?: Record<string, string>;
  /** Per-call timeout in ms. Default: the server-advertised timeout, else 12000. */
  timeoutMs?: number;
  /** Deny when no decision could be obtained. Env: SUPERBASED_ADMISSION_FAIL_CLOSED. Default false. */
  failClosed?: boolean;
}

const advertised = new Map<string, number>();

// --- saying so when admit() could not decide (review E-39) -------------------
//
// admit() fails open (the contract), but never silently: every degraded
// verdict is counted for diagnostics(), and one console.warn per cause per
// minute names the cause and the fix. Python does the same (logging).

/** How often (ms) admit() may warn about the same cause. */
export const DEGRADED_LOG_INTERVAL_MS = 60_000;

/** [cause, lowest status, highest status, what to fix, where]: the first matching row wins; 0..999 matches any status; where is "machine" (the check went to a machine's admission path) or "" for any address. Python has the same table. */
const FIXES: ReadonlyArray<[string, number, number, string, string]> = [
  [
    Degraded.UNAVAILABLE,
    404,
    404,
    "this machine has no admission check: update Observer (a current machine answers allow while no admission policy is set), or turn admission on",
    "machine",
  ],
  [Degraded.HTTP_ERROR, 300, 399, "the address redirects, and admit() never follows a redirect (the key must not move hosts): use the final URL", ""],
  [Degraded.HTTP_ERROR, 401, 401, "the SDK key was refused: check apiKey / SUPERBASED_API_KEY, or sign in again", ""],
  [Degraded.UNAVAILABLE, 403, 403, "the key may not run admission checks, or admission is off for this app", ""],
  [Degraded.UNAVAILABLE, 404, 404, "no admission check at this address: point orgUrl / SUPERBASED_ORG_URL at the AI Apps gateway (not the dashboard), or turn admission on", ""],
  [Degraded.HTTP_ERROR, 429, 429, "the server is rate limiting admission checks", ""],
  [Degraded.HTTP_ERROR, 0, 999, "the admission server answered with an error", ""],
  [Degraded.TIMEOUT, 0, 999, "no answer within the timeout: raise timeoutMs, or check the server", ""],
  [Degraded.TRANSPORT, 0, 999, "nothing answered at this address: check the URL and that Observer is running", ""],
  [Degraded.BAD_RESPONSE, 0, 999, "the address did not answer like an admission check: check the URL", ""],
  [Degraded.ADMISSION_OFF, 0, 999, "your organization has no admission policy for AI Apps (mode off): ask an admin to turn admission on, or use destination both so this machine's policy applies", ""],
];

/** What to fix for a degraded verdict ("" for a server-side reason). */
export function degradedFix(cause: string, status: number, url = ""): string {
  const machine = isMachineAdmission(url);
  for (const [c, lo, hi, fix, at] of FIXES) {
    if (c === cause && status >= lo && status <= hi && (!at || (at === "machine") === machine)) return fix;
  }
  return "";
}

/** Whether url is a machine's admission check (its path). */
function isMachineAdmission(url: string): boolean {
  try {
    return new URL(url).pathname.replace(/\/+$/, "").endsWith(MACHINE_ADMISSION_PATH);
  } catch {
    return false;
  }
}

/** Process-wide admit() counters, read by diagnostics(). */
export const admitStats = { degraded: 0, lastError: "", lastErrorAt: 0, loggedAt: new Map<string, number>() };

export function resetAdmitStats(): void {
  admitStats.degraded = 0;
  admitStats.lastError = "";
  admitStats.lastErrorAt = 0;
  admitStats.loggedAt.clear();
}

/** scheme://host[:port]/path of a URL: no user info, no query. */
function where(url: string): string {
  try {
    const u = new URL(url);
    return `${u.protocol}//${u.host}${u.pathname}`;
  } catch {
    return "the admission address";
  }
}

function noteDegraded(v: Verdict, url: string): void {
  try {
    const detail = v.httpStatus ? `HTTP ${v.httpStatus}` : v.error || v.degraded;
    let fix = degradedFix(v.degraded, v.httpStatus, url);
    if (v.planRefusal) {
      // The org's plan refused it: its own words and where to fix it.
      fix = `${v.planRefusal.message.split(/\s+/).join(" ")} (upgrade: ${v.planRefusal.upgradeUrl})`;
      notePlanRefusal(v.planRefusal);
    }
    const outcome = v.allowed ? "admitted (fail open)" : "denied (failClosed)";
    const msg =
      `admit() got no decision${url ? ` from ${where(url)}` : ""} (${v.degraded}: ${detail}); the message was ${outcome}` +
      (fix ? `. Fix: ${fix}` : "");
    const now = Date.now();
    admitStats.degraded += 1;
    admitStats.lastError = msg.slice(0, 500);
    admitStats.lastErrorAt = now;
    const key = `${v.degraded}:${v.httpStatus}`;
    if (!runtime.settings?.debug && now - (admitStats.loggedAt.get(key) ?? -Infinity) < DEGRADED_LOG_INTERVAL_MS) return;
    admitStats.loggedAt.set(key, now);
    console.warn(`@superbased/sdk: ${msg}`);
  } catch {
    // reporting never breaks admit()
  }
}

/** Forget server-advertised timeouts (tests). */
export function resetAdvertisedTimeouts(): void {
  advertised.clear();
}

/** The server-advertised timeout remembered for url, in ms (tests). */
export function advertisedTimeoutMs(url: string): number | undefined {
  return advertised.get(url);
}

/** The first of names whose get(name) is neither null nor undefined. */
function firstPresent(get: (name: string) => unknown, names: readonly string[]): unknown {
  for (const n of names) {
    const v = get(n);
    if (v !== null && v !== undefined) return v;
  }
  return undefined;
}

function str(d: Record<string, unknown>, k: string): string {
  const v = d[k];
  return typeof v === "string" ? v : "";
}

function num(d: Record<string, unknown>, k: string): number {
  const v = d[k];
  return typeof v === "number" && Number.isFinite(v) ? Math.trunc(v) : 0;
}

function rememberTimeout(url: string, raw: unknown): void {
  if (raw == null || typeof raw === "boolean") return;
  const ms = Number(raw);
  if (Number.isFinite(ms) && ms >= 100 && ms <= 120_000) advertised.set(url, ms);
}

/** Normalize a parsed response body into a Verdict; null when it is not one. */
export function parseVerdict(body: unknown): Verdict | null {
  if (body === null || typeof body !== "object" || Array.isArray(body)) return null;
  const d = body as Record<string, unknown>;
  if (typeof d.allowed !== "boolean") return null;
  const vid = d.verdict_id ?? d.id;
  return {
    allowed: d.allowed,
    decision: str(d, "decision") || (d.allowed ? "allow" : "deny"),
    severity: str(d, "severity"),
    criterion: str(d, "criterion"),
    reason: str(d, "reason"),
    mode: str(d, "mode"),
    enforceDecision: str(d, "enforce_decision"),
    degraded: str(d, "degraded"),
    judgeUsed: d.judge_used === true,
    latencyMs: num(d, "latency_ms"),
    verdictId: typeof vid === "string" || (typeof vid === "number" && Number.isFinite(vid)) ? String(vid) : "",
    httpStatus: 0,
    error: "",
  };
}

/**
 * Where the check goes and whether the SDK key rides with it (contract
 * destination.md section 8): an explicit `endpoint` / `orgUrl` wins, then
 * SUPERBASED_ADMISSION_ENDPOINT; after init, the destination decides (`local`
 * the machine, `online` / `both` with a usable gateway the org, degraded the
 * machine); before init, SUPERBASED_ORG_URL, else the machine. The configured
 * key is sent to the org, or to a remote endpoint you named, never to a
 * loopback address (only an explicit `apiKey` goes there).
 */
function resolveTarget(opts: AdmitOptions, env: Env): Target {
  if (opts.endpoint) return { url: opts.endpoint, sendKey: !isLoopbackUrl(opts.endpoint), org: "" };
  if (opts.orgUrl) return { url: opts.orgUrl.replace(/\/+$/, "") + SDK_ADMIT_PATH, sendKey: true, org: "named" };
  const ep = (env.SUPERBASED_ADMISSION_ENDPOINT ?? "").trim();
  if (ep) return { url: ep, sendKey: !isLoopbackUrl(ep), org: "" };
  const s = runtime.settings;
  const machine = machineAdmissionUrl();
  if (s && runtime.destinationSource) {
    if ((runtime.destination === "online" || runtime.destination === "both") && s.orgUrl && onlineUsable(s)) {
      return { url: s.orgUrl + SDK_ADMIT_PATH, sendKey: true, org: "plan" };
    }
    if (runtime.destination) return { url: machine, sendKey: false, org: "" };
  }
  const org = (env.SUPERBASED_ORG_URL ?? "").trim();
  if (org) return { url: org.replace(/\/+$/, "") + SDK_ADMIT_PATH, sendKey: true, org: "named" };
  return { url: machine, sendKey: false, org: "" };
}

/** Where the check goes; `org` says whether it is the org init's destination chose (plan) or one the caller named. */
interface Target {
  url: string;
  sendKey: boolean;
  org: "" | "plan" | "named";
}

/** This machine's admission check: the one discovery advertised (loopback only), else the machine URL's route. */
function machineAdmissionUrl(): string {
  const s = runtime.settings;
  return runtime.admissionUrl || (s ? s.nodeUrl + MACHINE_ADMISSION_PATH : DEFAULT_ADMISSION_ENDPOINT);
}

function activeTraceId(): string {
  try {
    const ctx = trace.getActiveSpan()?.spanContext();
    if (ctx && /^[0-9a-f]{32}$/.test(ctx.traceId) && !/^0+$/.test(ctx.traceId)) return ctx.traceId;
  } catch {
    // ignore
  }
  return "";
}

function stampSpan(v: Verdict): void {
  try {
    const sp = trace.getActiveSpan();
    if (!sp || !sp.isRecording()) return;
    sp.setAttribute("sbo.admission.allowed", v.allowed);
    sp.setAttribute("sbo.admission.decision", v.decision);
    if (v.verdictId) sp.setAttribute("sbo.admission.verdict_id", v.verdictId);
    if (v.degraded) sp.setAttribute("sbo.admission.degraded", v.degraded);
  } catch {
    // ignore
  }
}

function degraded(cause: string, failClosed: boolean, started: number, httpStatus = 0, error = ""): Verdict {
  return {
    allowed: !failClosed,
    decision: failClosed ? "deny" : "allow",
    severity: "",
    criterion: "",
    reason: failClosed ? "admission check unavailable" : "",
    mode: "",
    enforceDecision: "",
    degraded: cause,
    judgeUsed: false,
    latencyMs: Math.round(Date.now() - started),
    verdictId: "",
    httpStatus,
    error: error.slice(0, 300),
  };
}

/**
 * The `service.name` the app's spans carry: the resource of the last span
 * the SDK saw (its own provider's, or the app's when attached), else the
 * configured name (serviceName, SUPERBASED_SERVICE_NAME, OTEL_SERVICE_NAME,
 * OTEL_RESOURCE_ATTRIBUTES, custom-app). OpenTelemetry's `unknown_service`
 * default is no name.
 */
export function serviceName(env: Env): string {
  const seen = runtime.resourceService.trim();
  if (seen && !seen.startsWith("unknown_service")) return seen;
  return runtime.settings?.serviceName || resolveServiceName(undefined, env);
}

/**
 * Check an incoming user message against the app's admission policy BEFORE
 * running the agent, and get an allow/flag/ask/deny verdict.
 *
 * ```ts
 * const v = await admit(userMessage, { user: "alice", session: "s1" });
 * if (!v.allowed) return v.reason; // or route to a human on `ask`
 * ```
 *
 * Never rejects. When no decision can be obtained it admits, unless
 * `failClosed` is set; `degraded` says why.
 */
export async function admit(message: string, opts: AdmitOptions = {}): Promise<Verdict> {
  const started = Date.now();
  const env = (typeof process !== "undefined" ? process.env : {}) as Env;
  const failClosed = opts.failClosed ?? envFlag(env, ["SUPERBASED_ADMISSION_FAIL_CLOSED"], false);
  let url = DEFAULT_ADMISSION_ENDPOINT;
  try {
    // The org or the machine is known only once discovery answered (review E-33).
    await destinationKnown();
    const target = resolveTarget(opts, env);
    url = target.url;
    // Identity: the argument, else the request scope (propagateAttributes),
    // else init's process-wide value (contract section 2), as in Python.
    const cur = getCurrentAttributes();
    const s = runtime.settings;
    const payload = JSON.stringify({
      text: message == null ? "" : String(message),
      tenant: opts.tenant || cur.tenant || s?.tenant || "",
      user: opts.user || cur.user || s?.user || "",
      session: opts.session || cur.sessionId || s?.sessionId || "",
      // service.name: service-scoped budget caps bind on it, on the machine
      // and on the org.
      service: serviceName(env),
      trace_id: opts.traceId ?? activeTraceId(),
      request_id: opts.requestId ?? "",
    });
    const key = opts.apiKey ?? (target.sendKey ? (runtime.settings?.apiKey || env.SUPERBASED_API_KEY || "") : "");
    let v = await post(url, key, payload, opts, failClosed, started);
    if (target.org && !v.degraded && v.mode === "off") {
      // The org has no admission policy, so it made no decision (L-05).
      // Under destination both, this machine's policy decides (the key never
      // goes there); otherwise the verdict says nothing decided.
      if (target.org === "plan" && runtime.destination === "both") {
        url = machineAdmissionUrl();
        v = await post(url, "", payload, { ...opts, headers: withoutAuthorization(opts.headers) }, failClosed, started);
      } else {
        v = degraded(Degraded.ADMISSION_OFF, failClosed, started, v.httpStatus, "the organization answered mode off");
        noteDegraded(v, url);
      }
    }
    stampSpan(v);
    return v;
  } catch (err) {
    // The last line of defence: never reject into the host.
    const v = degraded(Degraded.BAD_RESPONSE, failClosed, started, 0, String(err));
    stampSpan(v);
    noteDegraded(v, url);
    return v;
  }
}

function withoutAuthorization(h: Record<string, string> | undefined): Record<string, string> | undefined {
  if (!h) return h;
  return Object.fromEntries(Object.entries(h).filter(([k]) => k.toLowerCase() !== "authorization"));
}

/** One admission request to url; a failure is a counted degraded verdict. The caller stamps the span. */
async function post(url: string, key: string, payload: string, opts: AdmitOptions, failClosed: boolean, started: number): Promise<Verdict> {
  const fail = (cause: string, status = 0, error = "", refusal?: PlanRefusalError): Verdict => {
    const v = degraded(cause, failClosed, started, status, error);
    if (refusal) v.planRefusal = refusal;
    noteDegraded(v, url);
    return v;
  };
  // The org's plan refusal in a 403 / 429 answer (its body, read within the deadline), else null.
  const refusalOf = async (resp: Response): Promise<PlanRefusalError | null> => {
    if (resp.status !== 403 && resp.status !== 429) return null;
    try {
      return parsePlanRefusal(resp.status, await resp.text(), resp.headers);
    } catch {
      return null;
    }
  };
  let timer: RequestTimer | undefined;
  try {
    const timeoutMs = opts.timeoutMs ?? advertised.get(url) ?? DEFAULT_ADMIT_TIMEOUT_MS;
    const headers: Record<string, string> = { "Content-Type": "application/json", Accept: "application/json" };
    if (key) headers.Authorization = `Bearer ${key}`;
    if (opts.headers) Object.assign(headers, opts.headers);
    timer = startTimer(timeoutMs, false);
    const sent = await fetchBounded(url, { method: "POST", headers, body: payload }, timer);
    if ("failed" in sent) {
      if (timer.timedOut()) return fail(Degraded.TIMEOUT, 0, `timed out after ${timeoutMs}ms`);
      return fail(Degraded.TRANSPORT, 0, transportDetail(sent.failed));
    }
    const resp = sent.resp;
    rememberTimeout(url, firstPresent((n) => resp.headers.get(n), TIMEOUT_HEADERS));
    const refusal = await refusalOf(resp);
    if (refusal) {
      const cause = resp.status === 403 ? Degraded.UNAVAILABLE : Degraded.HTTP_ERROR;
      return fail(cause, resp.status, `HTTP ${resp.status} ${refusal.code}: ${refusal.message}`, refusal);
    }
    if (resp.status === 403 || resp.status === 404) {
      void resp.body?.cancel().catch(() => undefined);
      return fail(Degraded.UNAVAILABLE, resp.status, `HTTP ${resp.status}`);
    }
    if (!resp.ok) {
      void resp.body?.cancel().catch(() => undefined);
      return fail(Degraded.HTTP_ERROR, resp.status, `HTTP ${resp.status}`);
    }
    let text: string;
    try {
      text = await resp.text();
    } catch (err) {
      if (timer.timedOut()) return fail(Degraded.TIMEOUT, resp.status, `timed out after ${timeoutMs}ms`);
      return fail(Degraded.TRANSPORT, resp.status, String(err));
    }
    let body: unknown;
    try {
      body = JSON.parse(text);
    } catch (err) {
      return fail(Degraded.BAD_RESPONSE, resp.status, String(err));
    }
    const v = parseVerdict(body);
    if (!v) {
      const kind = body === null ? "null" : Array.isArray(body) ? "array" : typeof body;
      return fail(
        Degraded.BAD_RESPONSE,
        resp.status,
        kind === "object" ? "response field 'allowed' is missing or not a boolean" : `response body is ${kind}, not an object`,
      );
    }
    const fields = body as Record<string, unknown>;
    rememberTimeout(url, firstPresent((n) => fields[n], TIMEOUT_FIELDS));
    v.httpStatus = resp.status;
    return v;
  } catch (err) {
    return fail(Degraded.BAD_RESPONSE, 0, String(err));
  } finally {
    timer?.clear();
  }
}
