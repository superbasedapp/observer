/**
 * W3C trace-context helpers (contract sdk-api-surface.md section 4), for
 * joining a trace across a process boundary the SDK does not instrument (a
 * queue message, a job, a hand-rolled HTTP call). They always use the W3C
 * propagators, whatever global propagator the host has configured.
 *
 * `inject()` also writes `baggage` when per-request values were set with
 * `propagateAttributes({ ..., asBaggage: true })`; `continueTrace()` restores
 * them into the attribute scope on the other side.
 */

import { context, propagation, trace, type Context, type TextMapGetter } from "@opentelemetry/api";
import { W3CBaggagePropagator, W3CTraceContextPropagator } from "@opentelemetry/core";

import { K } from "./attrs.js";
import { currentScope, runWithScope, SCALAR_KEYS, Scope, type PropagateOptions } from "./context.js";

const traceContext = new W3CTraceContextPropagator();
const baggageProp = new W3CBaggagePropagator();

/** A header bag: a plain object (string or string[] values) or a fetch `Headers`. */
export type Carrier = Record<string, string | string[] | undefined> | { get(name: string): string | null };

const getter: TextMapGetter<Carrier> = {
  keys(c) {
    const fe = (c as { forEach?: unknown }).forEach;
    if (typeof (c as { get?: unknown }).get === "function" && typeof fe === "function") {
      const out: string[] = [];
      (c as unknown as { forEach(cb: (v: string, k: string) => void): void }).forEach((_v, k) => out.push(k));
      return out;
    }
    return Object.keys(c);
  },
  get(c, key) {
    if (typeof (c as { get?: unknown }).get === "function") {
      return (c as { get(name: string): string | null }).get(key) ?? undefined;
    }
    const rec = c as Record<string, string | string[] | undefined>;
    const want = key.toLowerCase();
    const hit = Object.keys(rec).find((k) => k.toLowerCase() === want);
    return hit === undefined ? undefined : rec[hit];
  },
};

function withScopeBaggage(ctx: Context): Context {
  const scope = currentScope();
  if (!scope.baggage) return ctx;
  const entries: Record<string, { value: string }> = {};
  for (const [k, v] of Object.entries(scope.scalars)) entries[k] = { value: v };
  if (scope.tags.length) entries[K.tags] = { value: scope.tags.join(",") };
  for (const [k, v] of Object.entries(scope.metadata)) entries[K.metadataPrefix + k] = { value: v };
  const existing = propagation.getBaggage(ctx);
  let bag = existing ?? propagation.createBaggage();
  for (const [k, e] of Object.entries(entries)) bag = bag.setEntry(k, e);
  return propagation.setBaggage(ctx, bag);
}

/**
 * Write `traceparent` (+ `tracestate`, + `baggage` when per-request values
 * were set `asBaggage`) for the current context into `carrier` (a new object
 * when omitted) and return it.
 *
 * ```ts
 * await queue.send({ body, headers: inject() });
 * ```
 */
export function inject<T extends Record<string, string>>(carrier?: T): T {
  const out = (carrier ?? {}) as T;
  try {
    const ctx = withScopeBaggage(context.active());
    const setter = {
      set(c: T, k: string, v: string) {
        (c as Record<string, string>)[k] = v;
      },
    };
    traceContext.inject(ctx, out, setter);
    baggageProp.inject(ctx, out, setter);
  } catch {
    // never break the caller
  }
  return out;
}

/** The context the W3C headers in `carrier` describe (case-insensitive); the active context when there are none. */
export function extract(carrier: Carrier): Context {
  const base = context.active();
  try {
    return baggageProp.extract(traceContext.extract(base, carrier ?? {}, getter), carrier ?? {}, getter);
  } catch {
    return base;
  }
}

function scopeFromBaggage(ctx: Context): Scope | null {
  const bag = propagation.getBaggage(ctx);
  if (!bag) return null;
  const reverse = Object.fromEntries(Object.entries(SCALAR_KEYS).map(([name, key]) => [key, name]));
  const opts: PropagateOptions = { asBaggage: true };
  const meta: Record<string, string> = {};
  let any = false;
  for (const [key, entry] of bag.getAllEntries()) {
    if (key in reverse) {
      (opts as Record<string, unknown>)[reverse[key]] = entry.value;
      any = true;
    } else if (key === K.tags) {
      opts.tags = entry.value.split(",");
      any = true;
    } else if (key.startsWith(K.metadataPrefix)) {
      meta[key.slice(K.metadataPrefix.length)] = entry.value;
      any = true;
    }
  }
  if (!any) return null;
  if (Object.keys(meta).length) opts.metadata = meta;
  return currentScope().merged(opts);
}

/**
 * Run `fn` as part of the trace `carrier` names (spans inside join the
 * caller's trace), restoring per-request values the caller sent as baggage.
 */
export function continueTrace<T>(carrier: Carrier, fn: () => T): T {
  const ctx = extract(carrier);
  const scope = scopeFromBaggage(ctx);
  const run = () => context.with(ctx, fn);
  return scope ? runWithScope(scope, run) : run();
}

/** The `traceparent` value of the active span ("" outside a span). */
export function getTraceparent(): string {
  if (!trace.getActiveSpan()) return "";
  const out: Record<string, string> = {};
  try {
    traceContext.inject(context.active(), out, {
      set(c, k, v) {
        (c as Record<string, string>)[k] = v;
      },
    });
  } catch {
    return "";
  }
  return out.traceparent ?? "";
}
