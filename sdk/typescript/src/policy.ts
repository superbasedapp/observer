/**
 * Export-time policy, applied by the SDK's span processor to every span it
 * exports (the SDK's own and any instrumentation's), in this order
 * (contract sdk-api-surface.md section 5):
 *
 * 1. Head sampling by trace id (`sampleRate`). When the SDK owns the
 *    provider this is the provider's sampler (`SwitchableSampler`,
 *    parent-based by default); when the SDK is attached to a host provider
 *    the host's sampler stays in charge and the same trace-id ratio is
 *    applied to what the SDK exports. A trace is kept when the low 64 bits of
 *    its id are below `round(rate * 2^64)` (the OTel TraceIdRatioBased rule
 *    as the Python SDK applies it), so every service and both SDKs agree.
 * 2. `shouldExport(span)`: false drops the span (`filteredSpans`). A hook
 *    that throws keeps the span (no silent loss) and counts
 *    `shouldExportErrors`.
 * 3. Content rules on every content attribute, on the span and its events:
 *    `captureContent` off removes it; otherwise `mask(value, key)` rewrites
 *    it (null / undefined drops it; a hook that throws drops it and counts
 *    `maskErrors`, never exporting the value unmasked), then the value is
 *    clipped to `maxContentChars`.
 *
 * The original span is never changed: the SDK exports a copy when a content
 * rule changes something, so a host's other processors see the original.
 */

import { SamplingDecision, type Attributes, type AttributeValue, type Context, type Link, type SpanKind } from "@opentelemetry/api";
import { AlwaysOffSampler, AlwaysOnSampler, ParentBasedSampler, type ReadableSpan, type Sampler, type SamplingResult } from "@opentelemetry/sdk-trace-base";

import { isContentKey } from "./attrs.js";

/** Rewrite one content value before export. Return null / undefined to drop it. */
export type MaskFn = (value: AttributeValue, key: string) => unknown;

/** Decide whether a finished span is exported. */
export type ShouldExportFn = (span: ReadableSpan) => boolean;

export const TRUNCATED_MARK = "…[truncated]";

export interface ExportPolicy {
  captureContent: boolean;
  maxContentChars: number;
  mask?: MaskFn;
  shouldExport?: ShouldExportFn;
  /** Applied only when a host's sampler made the decision (attached mode); undefined = export every recorded span. */
  exportRatio?: number;
  /** Tracer scopes of model client libraries whose own spans are dropped (vendor.ts). */
  dropScopePrefixes?: string[];
}

export const policyStats = {
  sampledOut: 0,
  filtered: 0,
  shouldExportErrors: 0,
  maskErrors: 0,
  vendorSpansDropped: 0,
  usageNetInputCorrected: 0,
  lastHookError: "",
};

export function resetPolicyStats(): void {
  Object.assign(policyStats, {
    sampledOut: 0,
    filtered: 0,
    shouldExportErrors: 0,
    maskErrors: 0,
    vendorSpansDropped: 0,
    usageNetInputCorrected: 0,
    lastHookError: "",
  });
}

function hookError(counter: "shouldExportErrors" | "maskErrors", what: string, err: unknown): void {
  policyStats[counter] += 1;
  const e = err instanceof Error ? `${err.name}: ${err.message}` : String(err);
  policyStats.lastHookError = `${what}: ${e}`.slice(0, 500);
}

const TWO_64 = 2n ** 64n;

/** The trace-id ratio bound: kept when the low 64 bits are below it. */
export function ratioBound(rate: number): bigint {
  const r = Math.max(0, Math.min(1, rate));
  if (r >= 1) return TWO_64;
  return BigInt(Math.round(r * Number(TWO_64)));
}

/** Whether the trace with this id is kept at `rate` (deterministic, the same in both SDKs). */
export function keepTrace(traceId: string, rate: number): boolean {
  if (!(rate < 1)) return true;
  if (!(rate > 0)) return false;
  const low = traceId.length >= 16 ? traceId.slice(-16) : traceId;
  let n: bigint;
  try {
    n = BigInt("0x" + (low || "0"));
  } catch {
    return true;
  }
  return n < ratioBound(rate);
}

/** The trace-id ratio root sampler, with the cross-SDK rule above. */
export class RatioSampler implements Sampler {
  constructor(readonly rate: number) {}
  shouldSample(_ctx: Context, traceId: string): SamplingResult {
    return { decision: keepTrace(traceId, this.rate) ? SamplingDecision.RECORD_AND_SAMPLED : SamplingDecision.NOT_RECORD };
  }
  toString(): string {
    return `SuperbasedRatio{${this.rate}}`;
  }
}

/** The sampler of a provider the SDK owns; a later `init()` swaps the rate in place. */
export class SwitchableSampler implements Sampler {
  private inner: Sampler = new AlwaysOnSampler();
  rate = 1;
  set(rate: number, parentBased: boolean): void {
    this.rate = rate;
    const root: Sampler = rate >= 1 ? new AlwaysOnSampler() : rate <= 0 ? new AlwaysOffSampler() : new RatioSampler(rate);
    this.inner = parentBased ? new ParentBasedSampler({ root }) : root;
  }
  shouldSample(ctx: Context, traceId: string, name: string, kind: SpanKind, attrs: Attributes, links: Link[]): SamplingResult {
    const r = this.inner.shouldSample(ctx, traceId, name, kind, attrs, links);
    if (r.decision === SamplingDecision.NOT_RECORD) policyStats.sampledOut += 1;
    return r;
  }
  toString(): string {
    return `SuperbasedSampler{${this.inner.toString()}}`;
  }
}

export function clipContent(value: AttributeValue, max: number): AttributeValue {
  if (max > 0 && typeof value === "string" && value.length > max) return value.slice(0, max) + TRUNCATED_MARK;
  return value;
}

function isAttrValue(v: unknown): v is AttributeValue {
  if (typeof v === "string" || typeof v === "number" || typeof v === "boolean") return true;
  return Array.isArray(v) && v.every((x) => x == null || ["string", "number", "boolean"].includes(typeof x));
}

/** One content attribute: [keep, new value]. */
function contentValue(key: string, value: AttributeValue, p: ExportPolicy): [boolean, AttributeValue | undefined] {
  if (!p.captureContent) return [false, undefined];
  let v: AttributeValue = value;
  if (p.mask) {
    let out: unknown;
    try {
      out = p.mask(value, key);
    } catch (err) {
      hookError("maskErrors", `mask(${key})`, err);
      return [false, undefined];
    }
    if (out === null || out === undefined) return [false, undefined];
    v = isAttrValue(out) ? out : String(out);
  }
  return [true, clipContent(v, p.maxContentChars)];
}

/** New attributes when a content rule changes `attrs`; null when none does. */
export function rewriteAttributes(attrs: Attributes | undefined, p: ExportPolicy): Attributes | null {
  if (!attrs) return null;
  let out: Attributes | null = null;
  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined || !isContentKey(key)) continue;
    const [keep, next] = contentValue(key, value, p);
    if (keep && next === value) continue;
    out ??= { ...attrs };
    if (keep) out[key] = next;
    else delete out[key];
  }
  return out;
}

function needsContentRules(p: ExportPolicy): boolean {
  return !p.captureContent || !!p.mask || p.maxContentChars > 0;
}

function copySpan(span: ReadableSpan, attributes: Attributes, events: ReadableSpan["events"]): ReadableSpan {
  return {
    name: span.name,
    kind: span.kind,
    spanContext: () => span.spanContext(),
    parentSpanContext: span.parentSpanContext,
    startTime: span.startTime,
    endTime: span.endTime,
    status: span.status,
    attributes,
    links: span.links,
    events,
    duration: span.duration,
    ended: span.ended,
    resource: span.resource,
    instrumentationScope: span.instrumentationScope,
    droppedAttributesCount: span.droppedAttributesCount,
    droppedEventsCount: span.droppedEventsCount,
    droppedLinksCount: span.droppedLinksCount,
  };
}

/** The span to export: `span` itself, or a copy with rewritten content. */
export function applyContentRules(span: ReadableSpan, p: ExportPolicy): ReadableSpan {
  if (!needsContentRules(p)) return span;
  try {
    const attrs = rewriteAttributes(span.attributes, p);
    let events = span.events;
    let changed = false;
    if (span.events?.length) {
      events = span.events.map((ev) => {
        const a = rewriteAttributes(ev.attributes, p);
        if (!a) return ev;
        changed = true;
        return { ...ev, attributes: a };
      });
    }
    if (!attrs && !changed) return span;
    return copySpan(span, attrs ?? span.attributes, changed ? events : span.events);
  } catch (err) {
    // A span the rules cannot process is exported without its content, never with it unmasked.
    hookError("maskErrors", "content rules", err);
    const strip = (a: Attributes | undefined): Attributes =>
      Object.fromEntries(Object.entries(a ?? {}).filter(([k]) => !isContentKey(k))) as Attributes;
    return copySpan(span, strip(span.attributes), (span.events ?? []).map((ev) => ({ ...ev, attributes: strip(ev.attributes) })));
  }
}

/** The whole policy: the span to export, or null to drop it (counted). */
export function applyPolicy(span: ReadableSpan, p: ExportPolicy): ReadableSpan | null {
  if (p.dropScopePrefixes?.length) {
    const scope = span.instrumentationScope?.name ?? "";
    if (scope && p.dropScopePrefixes.some((pre) => scope.startsWith(pre))) {
      policyStats.vendorSpansDropped += 1;
      return null;
    }
  }
  if (p.exportRatio !== undefined && p.exportRatio < 1 && !keepTrace(span.spanContext().traceId, p.exportRatio)) {
    policyStats.sampledOut += 1;
    return null;
  }
  if (p.shouldExport) {
    let keep = true;
    try {
      keep = p.shouldExport(span) !== false;
    } catch (err) {
      hookError("shouldExportErrors", "shouldExport", err);
      keep = true;
    }
    if (!keep) {
      policyStats.filtered += 1;
      return null;
    }
  }
  return applyContentRules(span, p);
}
