// planeaMap - maps the machine's /api/obs/* rows onto the shared Plane A
// component shapes (shared/components/planea/types.ts). Pure: no React, no
// fetch, so planeaMap.test.ts runs under `node --test`.
//
// The machine's span row keeps "not reported" as null (internal/obs/store
// SpanRow); the shared inspector draws token counts as numbers, so a null
// count becomes 0 and the token total follows the one rule everywhere: a
// reported total wins, else input + output (F16). A null COST stays null: it
// is how the inspector tells a span nothing priced (a tool or agent span
// with no model call reads a dash) from a /usr/bin/bash.00 one (FR-M19). Content is stored raw on this machine unless
// [observability].store_content is off, in which case only the hash is kept.

import type {
  PlaneAContentEntry,
  PlaneACostProvenance,
  PlaneAEvalChip,
  PlaneASpan,
} from "../../../shared/components/planea/types.ts";
import type { TraceInspectorData } from "../../../shared/components/planea/inspector.tsx";
import type { AppScore, AppSpanCost, AppTraceDetail } from "./planeaApi.ts";
import { parseCostDetail, type CostDetail } from "../../../shared/components/planea/costSource.ts";

const n = (v: number | null | undefined): number => (typeof v === "number" && Number.isFinite(v) ? v : 0);
const nullable = (v: number | null | undefined): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);

/** traceCost is the trace's cost and its provenance as ONE pair (FR-M07):
 *  the TraceCost the server computed together (cost.cost_usd with
 *  cost.cost_provenance, proxy_exact where this machine's proxy served the
 *  call), else, from a daemon that predates it, the stored total with the
 *  detail's provenance. Never the stored total beside the effective label. */
export function traceCost(d: AppTraceDetail): { usd: number | null; provenance: PlaneACostProvenance | null } {
  if (d.cost) return { usd: nullable(d.cost.cost_usd), provenance: d.cost.cost_provenance ?? null };
  return { usd: nullable(d.trace.cost_usd), provenance: d.cost_provenance ?? null };
}

/** inspectorData maps one trace detail (and the trace's scores, when read)
 *  onto the shared TraceInspectorView's input. */
export function inspectorData(d: AppTraceDetail, scores: readonly AppScore[] = []): TraceInspectorData {
  const costs = new Map((d.cost?.spans ?? []).map((c) => [c.span_id, c] as const));
  const total = traceCost(d);
  const spans: PlaneASpan[] = d.spans.map((s) => {
    const input = n(s.input_tokens);
    const output = n(s.output_tokens);
    const en = d.enrichments?.[s.span_id];
    const c = costs.get(s.span_id);
    return {
      span_id: s.span_id,
      parent_span_id: s.parent_span_id,
      kind: s.kind,
      name: s.name,
      started_at: s.started_at,
      ended_at: s.ended_at,
      duration_ms: n(s.duration_ms),
      status: s.status,
      model: s.model,
      provider: s.provider,
      input_tokens: input,
      output_tokens: output,
      cache_read_tokens: n(s.cache_read_tokens),
      cache_write_tokens: n(s.cache_write_tokens),
      total_tokens: input + output,
      // W4-2: the TraceCost's effective source wins (proxy_exact when this
      // machine's proxy served the call), with every kept number.
      cost_usd: nullable(c ? c.cost_usd : s.cost_usd),
      cost_source: c ? c.cost_source : s.cost_source,
      cost_detail: c ? spanCostDetail(c, s.cost_detail) : s.cost_detail,
      cost_delta_usd: c?.cost_delta_usd ?? null,
      request_id: s.request_id,
      ...(en ? { enrichment: en } : {}),
    };
  });
  rollUpParentCosts(spans);
  return {
    trace: {
      status: d.trace.status,
      duration_ms: n(d.trace.duration_ms),
      cost_usd: total.usd,
      total_tokens: n(d.trace.total_tokens),
      started_at: d.trace.started_at,
      source: d.trace.source,
      session_id: d.trace.session_id,
    },
    cost_provenance: total.provenance,
    spans,
    trace_evals: scores.map(scoreChip),
  };
}

/** The span kinds that make a model call (internal/spanprice.CostKind,
 *  L-03): only these carry a cost of their own. */
const MODEL_CALL_KINDS = new Set(["", "llm", "embedding"]);

/** The cost_source a rolled-up parent span carries: not a price source of
 *  its own, so the cell reads "$x child spans" (U-10). */
export const CHILD_SPANS_SOURCE = "child spans";

/** rollUpParentCosts (U-10): a span that makes no model call (an agent,
 *  chain or tool span) and has no cost of its own used to read "Unpriced"
 *  beside its priced LLM child. It now carries the summed cost of its
 *  priced model-call descendants, labelled CHILD_SPANS_SOURCE. Only
 *  model-call spans are summed, so nested parents never count a call twice;
 *  a parent with no priced descendant is left as it is. In place. */
export function rollUpParentCosts(spans: PlaneASpan[]): void {
  const kids = new Map<string, PlaneASpan[]>();
  for (const s of spans) {
    if (!s.parent_span_id) continue;
    const list = kids.get(s.parent_span_id);
    if (list) list.push(s);
    else kids.set(s.parent_span_id, [s]);
  }
  const priced = (s: PlaneASpan) =>
    MODEL_CALL_KINDS.has(s.kind ?? "") && (s.cost_source ?? "") !== "" && typeof s.cost_usd === "number";
  const sum = (id: string, seen: Set<string>): { usd: number; n: number } => {
    let usd = 0;
    let n = 0;
    for (const c of kids.get(id) ?? []) {
      if (seen.has(c.span_id)) continue; // a malformed cycle never loops
      seen.add(c.span_id);
      if (priced(c)) {
        usd += c.cost_usd ?? 0;
        n++;
      }
      const sub = sum(c.span_id, seen);
      usd += sub.usd;
      n += sub.n;
    }
    return { usd, n };
  };
  for (const s of spans) {
    if (MODEL_CALL_KINDS.has(s.kind ?? "") || (s.cost_source ?? "") !== "") continue;
    const r = sum(s.span_id, new Set([s.span_id]));
    if (r.n === 0) continue;
    s.cost_usd = r.usd;
    s.cost_source = CHILD_SPANS_SOURCE;
    s.cost_detail = undefined;
  }
}

/** scoreChip draws one score as an eval chip: the label is the score's
 *  display value, the number its numeric value (0 when categorical). */
export function scoreChip(s: AppScore): PlaneAEvalChip {
  return {
    name: s.name,
    label: s.value,
    score: n(s.value_num),
    ...(s.span_id ? { span_id: s.span_id } : {}),
  };
}

/** contentBySpan groups the detail's stored bodies by span. A row with an
 *  empty body kept only its hash (store_content off). */
export function contentBySpan(d: AppTraceDetail): Record<string, PlaneAContentEntry[]> {
  const out: Record<string, PlaneAContentEntry[]> = {};
  for (const c of d.content ?? []) {
    (out[c.span_id] ??= []).push({
      span_id: c.span_id,
      kind: c.kind,
      content_hash: c.content_hash,
      content: c.content,
      has_raw: c.content !== "",
      timestamp: c.time,
    });
  }
  return out;
}

/** spanCostDetail folds a TraceCost span's numbers into the stored detail,
 *  so the drawer shows the exact figure under its own key (W4-2). */
export function spanCostDetail(c: AppSpanCost, stored: unknown): CostDetail {
  const d: CostDetail = { ...parseCostDetail(stored) };
  if (c.reported_usd != null) d.reported = c.reported_usd;
  if (c.computed_usd != null) d.computed = c.computed_usd;
  if (c.exact_usd != null) {
    if (c.cost_source === "gateway_exact") d.gateway_exact = c.exact_usd;
    else d.proxy_exact = c.exact_usd;
  }
  if (c.cost_delta_usd != null) d.delta_reported = c.cost_delta_usd;
  return d;
}
