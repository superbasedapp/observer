import type { ReactNode } from "react";
import { Pill } from "../../primitives/Pill";
import { usePlaneAMoney } from "./money";
import {
  AGGREGATE_COST_TITLE,
  costSourceRow,
  deltaSign,
  isPriced,
  JOIN_RULES,
  NO_MODEL_CALLS,
  parseCostDetail,
  provenanceText,
  provenanceTitle,
  type CostProvenance,
} from "./costSource";

// costCell - every Plane A cost cell says where its number came from (W4-2,
// lane C2; contracts/cost-source.md section 7). The figure still goes
// through the app's money slot (money.tsx); these cells add the label, and
// an unpriced cell prints "Unpriced", never $0.

/** PlaneACostCell is one span's cost and its source. */
export function PlaneACostCell({
  usd,
  tokens,
  source,
}: {
  usd: number | null | undefined;
  tokens?: number;
  source: string | null | undefined;
}) {
  const slot = usePlaneAMoney();
  const row = costSourceRow(source);
  const v = typeof usd === "number" && Number.isFinite(usd) ? usd : null;
  if (!isPriced(source) && (v === null || v === 0)) {
    return (
      <span className="text-fg-3" title={row.help}>
        Unpriced
      </span>
    );
  }
  const facts = tokens === undefined ? { usd: v ?? 0 } : { usd: v ?? 0, tokens };
  return (
    <span className="inline-flex items-baseline gap-1" title={isPriced(source) ? row.help : "This cost carries no source label."}>
      {slot.node(facts)}
      <span className="text-[10px] text-fg-3">{isPriced(source) ? row.short : "source unknown"}</span>
    </span>
  );
}

/** PlaneATraceCostCell is a trace's total and its provenance label. */
export function PlaneATraceCostCell({
  usd,
  tokens,
  provenance,
}: {
  /** The trace total; null when no span of it is priced (the server never
   *  sends 0 for an unpriced trace, L-06). */
  usd: number | null;
  tokens?: number;
  provenance: CostProvenance | null | undefined;
}) {
  const slot = usePlaneAMoney();
  const title = provenanceTitle(provenance);
  if (usd === null || (provenance?.label === "unpriced" && !usd) || provenance?.label === NO_MODEL_CALLS) {
    return (
      <span className="text-fg-3" title={title}>
        {provenance?.label === NO_MODEL_CALLS ? "No model calls" : "Unpriced"}
      </span>
    );
  }
  const facts = tokens === undefined ? { usd } : { usd, tokens };
  return (
    <span className="inline-flex items-baseline gap-1" title={title}>
      {slot.node(facts)}
      <span className="text-[10px] text-fg-3">{provenanceText(provenance)}</span>
    </span>
  );
}

/** PlaneAAggregateCost is a summed cost (a group, a day, a model): its
 *  tooltip says it totals priced spans only. */
export function PlaneAAggregateCost({ usd, tokens }: { usd: number; tokens?: number }) {
  const slot = usePlaneAMoney();
  return <span title={AGGREGATE_COST_TITLE}>{slot.node(tokens === undefined ? { usd } : { usd, tokens })}</span>;
}

/** The span facts the cost breakdown reads. */
export interface PlaneACostFacts {
  cost_usd: number | null;
  cost_source: string;
  total_tokens?: number;
  cost_detail?: unknown;
  cost_delta_usd?: number | null;
  gateway_request_id?: string;
}

/** PlaneACostBreakdown is the span drawer's cost block: the source, every
 *  kept number and the exact-vs-reported delta. */
export function PlaneACostBreakdown({ span }: { span: PlaneACostFacts }) {
  const money = usePlaneAMoney().text;
  const row = costSourceRow(span.cost_source);
  const d = parseCostDetail(span.cost_detail);
  const exact = d.gateway_exact ?? d.proxy_exact;
  const delta = span.cost_delta_usd ?? d.delta_reported;
  const usd = (v: number) => money({ usd: v });
  const lines: { label: string; value: ReactNode; title?: string }[] = [];
  lines.push({
    label: "Cost",
    value: isPriced(span.cost_source) && span.cost_usd != null ? usd(span.cost_usd) : "Unpriced",
  });
  if (exact !== undefined) lines.push({ label: row.exact ? row.label : "Exact", value: usd(exact) });
  if (d.computed !== undefined) lines.push({ label: "Computed", value: usd(d.computed) });
  if (d.reported !== undefined) lines.push({ label: "Reported", value: usd(d.reported) });
  if (typeof delta === "number") {
    lines.push({
      label: "Exact vs reported",
      value: `${deltaSign(delta)}${usd(Math.abs(delta))}`,
      title: delta > 0 ? "The app reported less than the call cost." : "The app reported more than the call cost.",
    });
  }
  if (d.delta_computed !== undefined) {
    lines.push({ label: "Exact vs computed", value: `${deltaSign(d.delta_computed)}${usd(Math.abs(d.delta_computed))}` });
  }
  if (d.gateway_requests && d.gateway_requests > 1) lines.push({ label: "Gateway requests", value: String(d.gateway_requests) });
  const gwReq = span.gateway_request_id || d.gateway_request_ids?.[0];
  if (gwReq) lines.push({ label: "Gateway request", value: <span className="font-mono text-[11px]">{gwReq}</span> });
  if (d.join_rule) lines.push({ label: "Joined by", value: JOIN_RULES[d.join_rule] ?? d.join_rule });
  if (d.rate_card_version) lines.push({ label: "Rate card", value: d.rate_card_version });
  return (
    <div className="rounded-2 border border-line-2 bg-bg-2 p-2.5 text-[12px]">
      <div className="mb-1 flex items-center gap-1.5">
        <span className="font-semibold text-fg-2">Cost source</span>
        <span title={row.help}>
          <Pill variant={row.tone}>{row.label}</Pill>
        </span>
      </div>
      {lines.map((l) => (
        <div key={l.label} className="flex items-center justify-between gap-3 py-0.5" title={l.title}>
          <span className="text-fg-3">{l.label}</span>
          <span className="min-w-0 truncate text-right text-fg-1">{l.value}</span>
        </div>
      ))}
    </div>
  );
}
