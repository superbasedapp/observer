import type { Tone } from "./tone.ts";

// convergence - the pure tone bands and share math behind a convergence ring
// (shared/primitives/ConvergenceRing.tsx): a share that should reach 100%
// (policy ACK convergence, a rollout's progress, preflight readiness). Moved
// here from web2/src/lib/liveSignals.ts when ConvergenceRing was promoted into
// shared/, so the shared primitive never imports an app; web2's liveSignals
// re-exports these names unchanged. Decision logic as data (CLAUDE.md #5).
//
// Pure (a type-only import, erased under --experimental-strip-types), so an
// app's node:test can import it by relative path.

/** One row of an ordered threshold table: the first row the value reaches wins. */
export type ToneBand = { atLeast: number; tone: Tone };

// CONVERGENCE_BANDS - complete is success, anything short of it is still
// converging (accent), never a failure by itself.
export const CONVERGENCE_BANDS: readonly ToneBand[] = [
  { atLeast: 1, tone: "success" },
  { atLeast: Number.NEGATIVE_INFINITY, tone: "accent" },
];

/** bandTone walks an ordered band table; a non-finite value is neutral. */
export function bandTone(bands: readonly ToneBand[], value: number): Tone {
  if (!Number.isFinite(value)) return "neutral";
  for (const b of bands) if (value >= b.atLeast) return b.tone;
  return "neutral";
}

/**
 * shareRatio is part / whole clamped to 0..1, or null (unknown: render no
 * ring or meter) when the whole is not a positive finite number or the part
 * is not finite.
 */
export function shareRatio(part: number | null | undefined, whole: number | null | undefined): number | null {
  if (part == null || whole == null) return null;
  if (!Number.isFinite(part) || !Number.isFinite(whole) || whole <= 0) return null;
  return Math.max(0, Math.min(1, part / whole));
}
