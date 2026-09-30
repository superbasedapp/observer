import { ProgressRing } from "./ProgressRing";
import { CONVERGENCE_BANDS, bandTone, shareRatio } from "../lib/convergence";

// ConvergenceRing - a share that should reach 100% (policy ACK convergence,
// preflight gates green, nodes capable, an update ring's bucket) as a
// ProgressRing toned by CONVERGENCE_BANDS (shared/lib/convergence.ts). A zero
// or unknown denominator draws nothing: 0 of 0 is not "converged", it is
// unknown. Promoted from web2 (web2/src/components/ConvergenceRing.tsx is now
// a re-export shim). Pure: no fetch, state or router.
//
// `pct` picks where the percentage goes: "inside" the ring (a larger ring,
// e.g. a StatCard corner), "beside" it, or "none" when the caller already
// prints the n/m.
export function ConvergenceRing({
  part,
  whole,
  label,
  pct = "beside",
  size,
}: {
  part: number | null | undefined;
  whole: number | null | undefined;
  /** Accessible name; the n of m and the percentage are appended. A
   *  function receives the percentage and returns the whole name (for a
   *  share that is already a percentage). */
  label: string | ((pct: number) => string);
  pct?: "inside" | "beside" | "none";
  size?: number;
}) {
  const ratio = shareRatio(part, whole);
  if (ratio == null) return null;
  const p = Math.round(ratio * 100);
  const inside = pct === "inside";
  const ring = (
    <ProgressRing
      ratio={ratio}
      tone={bandTone(CONVERGENCE_BANDS, ratio)}
      size={size ?? (inside ? 34 : 16)}
      stroke={inside ? 4 : 3}
      label={typeof label === "function" ? label(p) : `${label}: ${part} of ${whole} (${p}%)`}
    >
      {inside ? `${p}%` : undefined}
    </ProgressRing>
  );
  if (pct !== "beside") return <span className="inline-flex">{ring}</span>;
  return (
    <span className="inline-flex items-center gap-1 text-[11px] tabular-nums text-fg-3">
      {ring}
      <span aria-hidden>{p}%</span>
    </span>
  );
}
