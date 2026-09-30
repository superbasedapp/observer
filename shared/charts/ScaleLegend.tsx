import clsx from "clsx";
import type { ReactNode } from "react";

// ScaleLegend: the low -> high swatch ramp under an intensity chart (the
// hour heatmaps, the hour bars), so a viewer can map a cell's shade back to
// a magnitude. The chart passes the SAME colour function it paints its marks
// with (`colorAt`, intensity 0..1), so the legend can never drift from the
// cells. `stops` are the intensities sampled, left to right; `low` / `high`
// label the two ends (a dollar figure, or "low" / "high" when the scale is
// not linear enough for a number to be honest in between).
//
// Pure: no state, no fetch. The ramp is decorative (aria-hidden); the two
// end labels carry the meaning, and `label` names the whole scale for
// assistive tech.
export function ScaleLegend({
  colorAt,
  low,
  high,
  stops = [0, 0.25, 0.5, 0.75, 1],
  label,
  className,
}: {
  /** The chart's own mark colour for an intensity in [0, 1]. */
  colorAt: (intensity: number) => string;
  low: ReactNode;
  high: ReactNode;
  /** Intensities to sample, left to right. */
  stops?: readonly number[];
  /** Accessible name for the scale, e.g. "Cost colour scale". */
  label?: string;
  className?: string;
}) {
  return (
    <div
      role={label ? "group" : undefined}
      aria-label={label}
      className={clsx("flex items-center gap-1.5 text-[9.5px] text-fg-4", className)}
    >
      <span className="font-mono tabular-nums">{low}</span>
      <span aria-hidden className="flex h-2.5 items-stretch gap-px">
        {stops.map((s, i) => (
          <span
            key={i}
            className="w-3 rounded-[1px]"
            style={{ background: colorAt(s) }}
          />
        ))}
      </span>
      <span className="font-mono tabular-nums">{high}</span>
    </div>
  );
}
