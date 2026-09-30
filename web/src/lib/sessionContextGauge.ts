// sessionContextGauge - the pure half of the node session detail's "Context
// window used" gauge (LiveHeroBand's ContextWindowCard and the cockpit's
// context-fill meter).
//
// The daemon now derives the gauge server-side (internal/sessiongauge, the
// ONE derivation the org drawer also calls) and ships it as the additive
// `context_gauge` on GET /api/session/<id>. When it is present the UI reads
// it verbatim; an older daemon without the field falls back to the previous
// client computation (predict's prefix over detail.context_budget_tokens).
// The mapping mirrors web2/src/lib/orgSessionGauges.ts.
//
// UNKNOWN IS UNKNOWN: a nil ratio (no ceiling, or a prefix larger than the
// catalog window, over_window) is `ratio: null`, which the gauge draws as an
// empty ring that says unknown - never 0% and never a clamped 100%.

/** ContextGaugeWire mirrors sessiongauge.ContextGauge on the node wire. */
export interface ContextGaugeWire {
  used_tokens: number;
  /** Turns were observed for the session (distinguishes "nothing yet" from
   *  "observed, but no cached prefix"). Absent on the oldest payloads. */
  observed?: boolean;
  model?: string;
  budget_tokens?: number | null;
  /** "reported" (the session carried its own budget) or "model_window" (the
   *  model catalog's context window). */
  budget_source?: "reported" | "model_window" | string;
  ratio?: number | null;
  /** The prefix exceeds the catalog context window, so the real limit is
   *  not known (ratio is null). */
  over_window?: boolean;
}

/** The inputs the gauge can come from: the server gauge, or the legacy
 *  client pieces for an older daemon. */
export interface ContextGaugeInput {
  gauge?: ContextGaugeWire | null;
  /** Legacy: predict.estimate.prefix_tokens. */
  prefixTokens?: number | null;
  /** Legacy: predict.estimate.has_shape. */
  hasShape?: boolean | null;
  /** Legacy: detail.context_budget_tokens. */
  contextBudgetTokens?: number | null;
}

/** The gauge's honest state. */
export type ContextGaugeState =
  /** No prefix number at all. */
  | "no_prefix"
  /** Prefix and ceiling known: the ring fills to `ratio`. */
  | "measured"
  /** Prefix larger than the catalog window: the real limit is unknown. */
  | "over_window"
  /** Prefix known, no ceiling to measure against. */
  | "no_ceiling";

export interface ContextGaugeModel {
  state: ContextGaugeState;
  /** Where the numbers came from. */
  source: "server" | "client";
  used: number;
  observed: boolean;
  /** Ceiling tokens; 0 when unknown. */
  budget: number;
  budgetSource: string;
  /** 0..1 share, or null = unknown. */
  ratio: number | null;
}

/** knownRatio is a finite 0..1 share, else null (unknown). */
export function knownRatio(r: number | null | undefined): number | null {
  if (r == null || !Number.isFinite(r)) return null;
  return Math.min(1, Math.max(0, r));
}

type Facts = { used: number; ratio: number | null; budget: number; overWindow: boolean };

// CONTEXT_GAUGE_RULES - ordered, first match wins.
export const CONTEXT_GAUGE_RULES: readonly { state: ContextGaugeState; when: (f: Facts) => boolean }[] = [
  { state: "no_prefix", when: (f) => f.used <= 0 },
  { state: "measured", when: (f) => f.ratio != null && f.budget > 0 },
  { state: "over_window", when: (f) => f.overWindow },
  { state: "no_ceiling", when: () => true },
];

function pickState(f: Facts): ContextGaugeState {
  for (const r of CONTEXT_GAUGE_RULES) if (r.when(f)) return r.state;
  return "no_ceiling";
}

/** contextGaugeModel resolves the gauge from the server field when present,
 *  else from the legacy client pieces. */
export function contextGaugeModel(input: ContextGaugeInput): ContextGaugeModel {
  const g = input.gauge;
  if (g) {
    const used = Math.max(0, g.used_tokens ?? 0);
    const ratio = knownRatio(g.ratio);
    const budget = g.budget_tokens != null && g.budget_tokens > 0 ? g.budget_tokens : 0;
    const overWindow = g.over_window === true;
    const state = pickState({ used, ratio, budget, overWindow });
    return {
      state,
      source: "server",
      used,
      observed: g.observed === true,
      budget: state === "measured" ? budget : 0,
      budgetSource: g.budget_source ?? "",
      ratio: state === "measured" ? ratio : null,
    };
  }
  const used = Math.max(0, input.prefixTokens ?? 0);
  const budget = input.contextBudgetTokens != null && input.contextBudgetTokens > 0 ? input.contextBudgetTokens : 0;
  const ratio = budget > 0 && used > 0 ? Math.min(1, used / budget) : null;
  const state = pickState({ used, ratio, budget, overWindow: false });
  return {
    state,
    source: "client",
    used,
    observed: input.hasShape === true,
    budget: state === "measured" ? budget : 0,
    budgetSource: state === "measured" ? "reported" : "",
    ratio: state === "measured" ? ratio : null,
  };
}

/** budgetNoun names where the ceiling came from. */
export function budgetNoun(source: string): string {
  return source === "model_window" ? "context window" : "budget";
}
