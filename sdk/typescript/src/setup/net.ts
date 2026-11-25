/**
 * setup's one HTTP call: bounded, never follows a redirect (a key or a grant
 * must not ride to a host it was not sent to), JSON in and out. Node
 * built-ins only (the global fetch). Injected into the phases as `HttpFn`, so
 * tests replace it with loopback stubs.
 */

/** One answer: the status, the parsed JSON body (null when not JSON), and the headers setup reads. */
export interface HttpAnswer {
  status: number;
  body: unknown;
  retryAfter: string;
  setCookie: string;
}

export interface HttpRequest {
  method: "GET" | "POST";
  url: string;
  headers?: Record<string, string>;
  body?: unknown;
  timeoutMs?: number;
}

export type HttpFn = (req: HttpRequest) => Promise<HttpAnswer>;

/** A transport failure (no answer): the cause, never the request. */
export class TransportError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TransportError";
  }
}

/** The default HttpFn: fetch with a timeout, no redirects. Throws TransportError when no answer came. */
export const httpFetch: HttpFn = async (req) => {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), req.timeoutMs ?? 10_000);
  timer.unref?.();
  try {
    const headers: Record<string, string> = { Accept: "application/json", ...(req.headers ?? {}) };
    let body: string | undefined;
    if (req.body !== undefined) {
      body = JSON.stringify(req.body);
      headers["Content-Type"] = "application/json";
    }
    let resp: Response;
    try {
      resp = await fetch(req.url, { method: req.method, headers, body, redirect: "manual", signal: controller.signal });
    } catch (err) {
      const cause = (err as { cause?: { code?: string } }).cause;
      throw new TransportError(controller.signal.aborted ? "timed out" : (cause?.code ?? "no answer"));
    }
    const text = await resp.text().catch(() => "");
    let parsed: unknown = null;
    try {
      parsed = text ? JSON.parse(text) : null;
    } catch {
      parsed = null;
    }
    return { status: resp.status, body: parsed, retryAfter: resp.headers.get("retry-after") ?? "", setCookie: resp.headers.get("set-cookie") ?? "" };
  } finally {
    clearTimeout(timer);
  }
};

/** A plain object view of a JSON body ({} when it is not an object). */
export function obj(v: unknown): Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
}

/** A string field ("" when absent or not a string). */
export function str(o: Record<string, unknown>, k: string): string {
  return typeof o[k] === "string" ? (o[k] as string) : "";
}

/** Seconds from a Retry-After header (seconds form only), clamped to [1, max]; `def` when absent or unreadable. */
export function retryAfterSeconds(raw: string, def: number, max = 60): number {
  const n = Number(raw.trim());
  if (!raw.trim() || !Number.isFinite(n) || n < 0) return def;
  return Math.min(max, Math.max(1, Math.ceil(n)));
}

/** Whether a URL's host is loopback. */
export function isLoopback(url: URL): boolean {
  const h = url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  return h === "localhost" || h === "::1" || /^127\.\d+\.\d+\.\d+$/.test(h);
}

/** Whether `raw` is https, or http to this machine (tests and the local Observer). */
export function secureOrLoopback(raw: string): boolean {
  try {
    const u = new URL(raw);
    return (u.protocol === "https:" && !!u.hostname) || (u.protocol === "http:" && isLoopback(u));
  } catch {
    return false;
  }
}
