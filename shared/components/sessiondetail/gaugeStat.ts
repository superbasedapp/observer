import type { Tone } from "../../lib/tone";

// gaugeStat - the pure half of <GaugeStat>: the ratio -> tone threshold table,
// the headline tone of a multi-ring tile, and each ring's accessible name.
// Decision logic as data (CLAUDE.md #5). Type-only imports, so
// web/src/lib/gaugeStat.test.ts runs it under plain node.
//
// Unknown means unknown: a null / undefined / non-finite ratio is UNKNOWN,
// takes the neutral tone, draws an empty ring and is announced as "unknown",
// never as 0%.

/** One row of an ordered threshold table: the first row the ratio reaches wins. */
export type GaugeBand = { atLeast: number; tone: Tone };

// GAUGE_BANDS - a fill ratio (context window used, share of a rate-limit
// window spent): 90% and over danger, 70% and over warn, else accent.
export const GAUGE_BANDS: readonly GaugeBand[] = [
  { atLeast: 0.9, tone: "danger" },
  { atLeast: 0.7, tone: "warn" },
  { atLeast: Number.NEGATIVE_INFINITY, tone: "accent" },
];

/** A ratio is known when it is a finite number (clamped to 0..1 on use). */
export function knownRatio(ratio: number | null | undefined): number | null {
  return ratio != null && Number.isFinite(ratio) ? Math.max(0, Math.min(1, ratio)) : null;
}

/** gaugeTone walks a band table; an unknown ratio is neutral. */
export function gaugeTone(
  ratio: number | null | undefined,
  bands: readonly GaugeBand[] = GAUGE_BANDS,
): Tone {
  const r = knownRatio(ratio);
  if (r == null) return "neutral";
  for (const b of bands) if (r >= b.atLeast) return b.tone;
  return "neutral";
}

/** The HeroStat-style chrome a gauge tile takes. */
export type GaugeVariant = "accent" | "warn" | "danger";

// GAUGE_VARIANT - tone -> tile chrome. A tile whose rings are all unknown keeps
// the calm accent chrome, like a HeroStat reading "n/a" beside it.
const GAUGE_VARIANT: Readonly<Record<Tone, GaugeVariant>> = {
  danger: "danger",
  warn: "warn",
  accent: "accent",
  neutral: "accent",
  success: "accent",
  info: "accent",
};

/**
 * gaugeVariant is the tile chrome for a set of rings: the tone of the ring
 * closest to its ceiling (the one that will actually stop the operator).
 */
export function gaugeVariant(
  ratios: readonly (number | null | undefined)[],
  bands: readonly GaugeBand[] = GAUGE_BANDS,
): GaugeVariant {
  let worst: number | null = null;
  for (const r of ratios) {
    const k = knownRatio(r);
    if (k != null && (worst == null || k > worst)) worst = k;
  }
  return GAUGE_VARIANT[gaugeTone(worst, bands)];
}

/** gaugeAriaLabel names one ring for assistive tech: "<name>: 72% used" or "<name>: unknown". */
export function gaugeAriaLabel(name: string, ratio: number | null | undefined): string {
  const r = knownRatio(ratio);
  return r == null ? `${name}: unknown` : `${name}: ${Math.round(r * 100)}% used`;
}
