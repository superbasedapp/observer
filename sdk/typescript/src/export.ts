/**
 * Export plumbing: a failure-counting exporter wrapper, the one switchable
 * span processor the SDK adds, bounded flush/shutdown and diagnostics.
 *
 * Re-running `init()` swaps the processor's delegate (a BatchSpanProcessor
 * per destination over a CountingExporter) instead of creating another
 * provider, so spans are never exported twice or lost to an orphan.
 */

import type { AttributeValue, Context } from "@opentelemetry/api";
import type { ReadableSpan, Span, SpanExporter, SpanProcessor } from "@opentelemetry/sdk-trace-base";

import { K } from "./attrs.js";
import { normalizeTags, scopeAttributes } from "./context.js";
import { noteExported, noteRefused } from "./firsttrace.js";
import { notePlanRefusal, parsePlanRefusal, planRefusalStats } from "./planrefusal.js";
import { runtime } from "./runtime.js";
import { applyPolicy, policyStats, type ExportPolicy } from "./policy.js";

/** How often (ms) the SDK may write its one-line export-failure summary. */
export const FAILURE_LOG_INTERVAL_MS = 60_000;

interface ExportResultLike {
  code: number; // 0 = SUCCESS, 1 = FAILED (@opentelemetry/core ExportResultCode)
  error?: Error;
}

/** Process-wide export counters, read by diagnostics(). */
export const stats = {
  handedSpans: 0,
  exportedSpans: 0,
  failedExports: 0,
  droppedSpans: 0,
  abandonedSpans: 0,
  lastError: "",
  lastErrorAt: 0,
  lastLoggedAt: 0,
  unloggedFailures: 0,
  debug: false,
};

export function resetStats(): void {
  Object.assign(stats, {
    handedSpans: 0,
    exportedSpans: 0,
    failedExports: 0,
    droppedSpans: 0,
    abandonedSpans: 0,
    lastError: "",
    lastErrorAt: 0,
    lastLoggedAt: 0,
    unloggedFailures: 0,
  });
}

function pending(): number {
  return Math.max(0, stats.handedSpans - stats.exportedSpans - stats.droppedSpans - stats.abandonedSpans);
}

function noteError(message: string): void {
  stats.lastError = message.slice(0, 500);
  stats.lastErrorAt = Date.now();
}

function describe(err: unknown): string {
  if (err instanceof Error) {
    const code = (err as { code?: unknown }).code;
    return `${err.name}: ${err.message}${code ? ` (${String(code)})` : ""}`;
  }
  return String(err);
}

/**
 * A failed export's plan refusal: the OTLP/HTTP exporter fails a non-retried
 * status (a 403) with an error carrying the status (`code`) and the body
 * (`data`). When the org's plan refused it, keep the refusal for
 * `diagnostics().planRefusal` and write one warning line (message and
 * upgrade URL) at most once a minute. A retried status (a 429) reaches here
 * without its body, so an allowance refusal on export is not seen here.
 */
export function noteExportRefusal(err: unknown): boolean {
  const e = err as { code?: unknown; data?: unknown } | undefined;
  if (!e || typeof e.code !== "number" || typeof e.data !== "string") return false;
  const refusal = parsePlanRefusal(e.code, e.data);
  if (!refusal) return false;
  notePlanRefusal(refusal, "trace export");
  return true;
}

/** Write at most one summary line per interval. Returns true when written. */
export function maybeLogFailures(now = Date.now()): boolean {
  if (stats.unloggedFailures === 0) return false;
  if (!stats.debug && now - stats.lastLoggedAt < FAILURE_LOG_INTERVAL_MS) return false;
  const n = stats.unloggedFailures;
  stats.unloggedFailures = 0;
  stats.lastLoggedAt = now;
  try {
    console.warn(
      `@superbased/sdk: ${n} trace export(s) failed since the last report ` +
        `(${stats.droppedSpans} spans dropped in total); last error: ${stats.lastError || "unknown"}`,
    );
  } catch {
    // a broken console must not break the host
  }
  return true;
}

/**
 * Wraps a SpanExporter: never throws, counts failures and dropped spans. With
 * `leg` (the destination it exports to), a successful export of a root span
 * may write the process's first-trace line (firsttrace.ts).
 */
export class CountingExporter implements SpanExporter {
  constructor(
    private readonly inner: SpanExporter,
    private readonly leg?: "local" | "online",
  ) {}

  export(spans: ReadableSpan[], resultCallback: (result: ExportResultLike) => void): void {
    const n = spans.length;
    let done = false;
    const finish = (result: ExportResultLike): void => {
      if (done) return;
      done = true;
      const late = Math.min(stats.abandonedSpans, n);
      stats.abandonedSpans -= late;
      if (result.code === 0) {
        stats.droppedSpans -= late; // a timed-out flush wrote these off; they made it
        stats.exportedSpans += n;
        if (this.leg) noteExported(spans, this.leg);
      } else {
        if (late === 0) {
          stats.failedExports += 1;
          stats.unloggedFailures += 1;
        }
        stats.droppedSpans += n - late;
        noteError(result.error ? describe(result.error) : "export failed");
        if (noteExportRefusal(result.error) && this.leg) noteRefused(spans, planRefusalStats.last);
        else if (this.leg) noteExported(spans, this.leg, false);
        maybeLogFailures();
      }
      try {
        resultCallback(result);
      } catch {
        // the processor's callback must not escape either
      }
    };
    try {
      this.inner.export(spans, finish);
    } catch (err) {
      finish({ code: 1, error: err instanceof Error ? err : new Error(String(err)) });
    }
  }

  async shutdown(): Promise<void> {
    try {
      await this.inner.shutdown();
    } catch (err) {
      noteError(describe(err));
    }
  }

  async forceFlush(): Promise<void> {
    try {
      await this.inner.forceFlush?.();
    } catch (err) {
      noteError(describe(err));
    }
  }
}

/** A promise that settles within `ms` (true = finished in time); never rejects. */
export function bounded(p: Promise<unknown>, ms: number): Promise<boolean> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(false), ms);
    timer.unref?.();
    p.then(
      () => {
        clearTimeout(timer);
        resolve(true);
      },
      (err) => {
        clearTimeout(timer);
        noteError(describe(err));
        resolve(true);
      },
    );
  });
}

/** A flush/shutdown ran out of time: count it and write off what is pending. */
export function noteTimeout(op: string, ms: number): void {
  const p = pending();
  stats.failedExports += 1;
  stats.abandonedSpans += p;
  stats.droppedSpans += p;
  stats.unloggedFailures += 1;
  noteError(
    `${op} timed out after ${ms}ms with ${p} span(s) not exported` + (stats.lastError ? `; exporter: ${stats.lastError}` : ""),
  );
}

/**
 * How many counted destinations a delegate hands each span to (review E-31):
 * each destination's CountingExporter counts a span as exported or dropped on
 * its own, so a span handed to two destinations is handed twice. A delegate
 * with no `legs` is one destination; a console-only one has 0.
 */
export function legsOf(p: SpanProcessor | null): number {
  const n = (p as { legs?: unknown } | null)?.legs;
  return typeof n === "number" && Number.isInteger(n) && n >= 0 ? n : 1;
}

/** Two or more processors as one delegate. */
export class Fanout implements SpanProcessor {
  /** The number of counted destinations (diagnostics' pending figure). */
  readonly legs: number;
  constructor(
    private readonly procs: SpanProcessor[],
    legs?: number,
  ) {
    this.legs = legs ?? procs.length;
  }
  onStart(span: Span, ctx: Context): void {
    for (const p of this.procs) p.onStart(span, ctx);
  }
  onEnd(span: ReadableSpan): void {
    for (const p of this.procs) p.onEnd(span);
  }
  // allSettled: one destination failing must not cut short the wait for the
  // others (D18 "both"); the first failure is re-raised once all are done.
  async forceFlush(): Promise<void> {
    settle(await Promise.allSettled(this.procs.map((p) => p.forceFlush())));
  }
  async shutdown(): Promise<void> {
    settle(await Promise.allSettled(this.procs.map((p) => p.shutdown())));
  }
}

function settle(results: PromiseSettledResult<void>[]): void {
  const bad = results.find((r): r is PromiseRejectedResult => r.status === "rejected");
  if (bad) throw bad.reason;
}

/** The one span processor the SDK adds. Forwards to a replaceable delegate,
 * stamps identity attributes the provider's resource does not carry and the
 * per-request attributes in scope, and applies the export policy. */
export class SwitchableProcessor implements SpanProcessor {
  private delegate: SpanProcessor | null = null;
  private stamp: Record<string, AttributeValue> = {};
  shutdownTimeoutMs = 2000;
  policy: ExportPolicy = { captureContent: true, maxContentChars: 0 };

  get active(): boolean {
    return this.delegate !== null;
  }

  get current(): SpanProcessor | null {
    return this.delegate;
  }

  swap(delegate: SpanProcessor | null, stamp: Record<string, AttributeValue>): SpanProcessor | null {
    const old = this.delegate;
    this.delegate = delegate;
    this.stamp = { ...stamp };
    return old;
  }

  onStart(span: Span, ctx: Context): void {
    const d = this.delegate;
    if (!d) return;
    try {
      const svc = (span as unknown as { resource?: { attributes?: Record<string, unknown> } }).resource?.attributes?.["service.name"];
      if (typeof svc === "string") runtime.resourceService = svc;
      const existing = (span as unknown as { attributes?: Record<string, unknown> }).attributes ?? {};
      const scoped = scopeAttributes();
      for (const [k, v] of Object.entries(scoped)) if (v !== undefined && !(k in existing)) span.setAttribute(k, v);
      for (const [k, v] of Object.entries(this.stamp)) {
        if (k === K.tags) {
          // Init tags and scope tags are unioned, never one over the other.
          const asList = (x: unknown): unknown[] => (Array.isArray(x) ? x : []);
          span.setAttribute(k, normalizeTags(asList(v), asList(scoped[k]), asList(existing[k])));
        } else if (!(k in existing) && !(k in scoped)) span.setAttribute(k, v);
      }
      d.onStart(span, ctx);
    } catch {
      // never break span creation
    }
  }

  onEnd(span: ReadableSpan): void {
    const d = this.delegate;
    if (!d) return;
    let out: ReadableSpan | null = span;
    try {
      out = applyPolicy(span, this.policy);
    } catch {
      // a policy that cannot run must not leak content: export without it
      try {
        out = applyPolicy(span, { captureContent: false, maxContentChars: 0 });
      } catch {
        out = null;
      }
    }
    if (!out) return;
    stats.handedSpans += legsOf(d);
    try {
      d.onEnd(out);
    } catch {
      // never break span end
    }
  }

  async forceFlush(): Promise<void> {
    const d = this.delegate;
    if (!d) return;
    if (!(await bounded(d.forceFlush(), this.shutdownTimeoutMs))) noteTimeout("flush", this.shutdownTimeoutMs);
  }

  /** Called when the HOLDING provider shuts down: close our delegate, bounded. */
  async shutdown(): Promise<void> {
    const old = this.swap(null, {});
    if (old) await shutdownBounded(old, this.shutdownTimeoutMs);
  }
}

export async function flushBounded(p: SpanProcessor, ms: number): Promise<boolean> {
  const droppedBefore = stats.droppedSpans;
  const ok = await bounded(p.forceFlush(), ms);
  if (!ok) noteTimeout("flush", ms);
  return ok && pending() === 0 && stats.droppedSpans === droppedBefore;
}

export async function shutdownBounded(p: SpanProcessor, ms: number): Promise<boolean> {
  const ok = await bounded(p.shutdown(), ms);
  if (!ok) noteTimeout("shutdown", ms);
  return ok;
}

export function snapshot(): Record<string, number | string> {
  return {
    sampledOutSpans: policyStats.sampledOut,
    filteredSpans: policyStats.filtered,
    shouldExportErrors: policyStats.shouldExportErrors,
    maskErrors: policyStats.maskErrors,
    lastHookError: policyStats.lastHookError,
    pendingSpans: pending(),
    exportedSpans: stats.exportedSpans,
    failedExports: stats.failedExports,
    droppedSpans: stats.droppedSpans,
    lastError: stats.lastError,
    lastErrorAt: stats.lastErrorAt,
  };
}
