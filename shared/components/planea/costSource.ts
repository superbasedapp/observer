// costSource - the honesty vocabulary of every Plane A cost cell (W4-2,
// lane C2; docs/plans/plane-a-sdk-buildout/contracts/cost-source.md). Pure:
// no React, no fetch, so the machine's node --test suite covers it
// (web/src/lib/planeaCostSource.test.ts).
//
// One table owns the cost_source values, their labels and tones; the cells
// (costCell.tsx) and the span drawer read it. A cost with no source is
// "Unpriced" and is never drawn as $0.

import type { Tone } from "../../lib/tone";

/** The closed cost_source vocabulary; "" is unpriced. */
export type CostSource = "gateway_exact" | "proxy_exact" | "computed" | "reported" | "";

/** One vocabulary row. */
export interface CostSourceRow {
  label: string;
  short: string;
  tone: Tone;
  exact: boolean;
  help: string;
}

/** COST_SOURCES is contract section 1, one row per value. */
export const COST_SOURCES: Readonly<Record<string, CostSourceRow>> = {
  gateway_exact: {
    label: "Gateway exact",
    short: "exact",
    tone: "success",
    exact: true,
    help: "The org AI gateway served this call: tokens it observed on the provider's response, priced at the gateway rate card.",
  },
  proxy_exact: {
    label: "Proxy exact",
    short: "exact",
    tone: "success",
    exact: true,
    help: "This machine's proxy served this call: tokens it observed on the provider's response, priced by the machine's cost engine.",
  },
  computed: {
    label: "Computed",
    short: "computed",
    tone: "info",
    exact: false,
    help: "The span's own token counts priced by the price book.",
  },
  reported: {
    label: "Reported",
    short: "reported",
    tone: "warn",
    exact: false,
    help: "The cost the instrumentation reported. Used only because the model is not in the price book.",
  },
  "": {
    label: "Unpriced",
    short: "unpriced",
    tone: "neutral",
    exact: false,
    help: "Nothing priced this span: the model is not in the price book and no cost was reported.",
  },
};

/** costSourceRow returns the row of a value; an unknown value reads as its
 *  own label, neutral (unknown means unknown, never a guess). */
export function costSourceRow(source: string | null | undefined): CostSourceRow {
  const s = source ?? "";
  return (
    COST_SOURCES[s] ?? { label: s, short: s, tone: "neutral", exact: false, help: "An unrecognised cost source." }
  );
}

/** isPriced reports whether a cost has a source (a priced figure). */
export function isPriced(source: string | null | undefined): boolean {
  return (source ?? "") !== "";
}

/** The trace provenance (contract section 5). */
export interface CostProvenance {
  label: string;
  complete: boolean;
  sources: Record<string, number>;
}

/** provenanceText is a trace cell's label: the source label, "Mixed", or
 *  "Unpriced", plus "partial" when a cost-bearing span is unpriced. An
 *  absent provenance reads "source unknown" (the server sent none). */
export function provenanceText(p: CostProvenance | null | undefined): string {
  if (!p) return "source unknown";
  if (p.label === NO_MODEL_CALLS) return "No model calls";
  const base = p.label === "mixed" ? "Mixed" : p.label === "unpriced" ? "Unpriced" : costSourceRow(p.label).label;
  return p.complete || p.label === "unpriced" ? base : `${base}, partial`;
}

/** NO_MODEL_CALLS is the label of a trace that made no model call (no
 *  cost-bearing span, no span naming a model): nothing to price, which is
 *  not the same as unpriced (live finding L-21). */
export const NO_MODEL_CALLS = "no_model_calls";

/** provenanceTitle is the trace cell's tooltip: the count per source. */
export function provenanceTitle(p: CostProvenance | null | undefined): string {
  if (!p) return "The server did not say where this trace's cost came from.";
  const parts = Object.entries(p.sources)
    .filter(([, n]) => n > 0)
    .map(([k, n]) => `${n} ${k === "unpriced" ? "unpriced" : costSourceRow(k).label.toLowerCase()}`);
  if (p.label === NO_MODEL_CALLS) return "This trace made no model call, so it has no cost.";
  const head = parts.length ? `Cost-bearing spans: ${parts.join(", ")}.` : "No cost-bearing spans.";
  return p.complete ? head : `${head} The total leaves the unpriced spans out.`;
}

/** The parsed cost_detail (contract section 3). Every field is optional. */
export interface CostDetail {
  reported?: number;
  computed?: number;
  gateway_exact?: number;
  proxy_exact?: number;
  base_source?: string;
  delta_reported?: number;
  delta_computed?: number;
  gateway_request_ids?: string[];
  gateway_requests?: number;
  rate_card_version?: string;
  join_rule?: string;
}

/** parseCostDetail accepts the org's JSON text or the machine's object;
 *  anything else is an empty detail. */
export function parseCostDetail(raw: unknown): CostDetail {
  let v: unknown = raw;
  if (typeof raw === "string") {
    if (!raw.trim()) return {};
    try {
      v = JSON.parse(raw);
    } catch {
      return {};
    }
  }
  if (!v || typeof v !== "object" || Array.isArray(v)) return {};
  return v as CostDetail;
}

/** JOIN_RULES labels the gateway join rule (contract section 4). */
export const JOIN_RULES: Readonly<Record<string, string>> = {
  request_id: "request id",
  traceparent: "trace context (the span)",
  traceparent_parent: "trace context (its HTTP call)",
  proxy_request_id: "proxy request id",
};

/** signedUsd renders a delta with its sign; the figure itself goes through
 *  the app's money slot. */
export function deltaSign(v: number): string {
  return v > 0 ? "+" : v < 0 ? "-" : "";
}

/** AGGREGATE_COST_TITLE is the tooltip of a summed cost cell (a group, a
 *  day, a model): it never claims to total the unpriced spans. */
export const AGGREGATE_COST_TITLE =
  "Sum of priced spans (exact, computed or reported). Unpriced spans are not counted.";
