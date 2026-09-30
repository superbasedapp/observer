import clsx from "clsx";
import { TONE_COLOR, type Tone } from "../lib/tone";
import { layoutMeterSegments, meterSegmentsSummary } from "../lib/meterSegments";

/** One fill of a stacked Meter. */
export type MeterSegment = {
  /** This segment's share of the whole track, 0..1. */
  value: number;
  /** Names the segment in the accessible summary (e.g. "Input"). */
  label: string;
  tone?: Tone;
  /** A raw CSS colour (a --tool-* / family var) instead of a tone. */
  color?: string;
};

// Meter: the one horizontal fill bar (share of a cap, a usage allowance, a
// version's share of the fleet). The fill animates `transform: scaleX` from
// the left edge, never `width` (sb-bar-grow on mount, a transform transition
// on later data changes; reduced motion renders the final length). The ratio
// is clamped to 0..1; a non-finite ratio renders an empty track, never NaN.
//
// Stacked form: pass `segments` to draw several fills side by side in one
// track (layout in lib/meterSegments.ts). Each segment is a full-width layer
// moved to its start with `translateX` and grown with `scaleX`, so nothing
// animates width; the move eases on the motion tokens, which collapse to 0
// under reduced motion. The track carries one accessible summary (role img)
// naming every segment's share. Without `segments` the single-fill path is
// unchanged.
export function Meter({
  ratio,
  segments,
  tone = "accent",
  color,
  label,
  className,
  trackClassName = "h-1.5",
  track = "bg-bg-3",
}: {
  /** Filled share, 0..1. Ignored when `segments` is given. */
  ratio?: number;
  /** Stacked fills, left to right. */
  segments?: MeterSegment[];
  tone?: Tone;
  /** A raw CSS colour (a --tool-* / family var) instead of a tone. */
  color?: string;
  /** Accessible name, e.g. "Share of cap used". */
  label?: string;
  className?: string;
  /** Track height / radius classes (default a 6px pill). */
  trackClassName?: string;
  /** Track colour class (default bg-bg-3; bg-bg-4 on a raised surface). */
  track?: "bg-bg-3" | "bg-bg-4" | "bg-line-2";
}) {
  if (segments) {
    return (
      <div
        className={clsx("relative overflow-hidden rounded-pill", track, trackClassName, className)}
        role="img"
        aria-label={meterSegmentsSummary(segments, label)}
      >
        {layoutMeterSegments(segments).map((l) => {
          const s = segments[l.index];
          return (
            <div
              key={l.index}
              aria-hidden
              className="absolute inset-0"
              style={{
                transform: `translateX(${l.start * 100}%)`,
                transition: "transform var(--dur-slow) var(--ease-out)",
              }}
            >
              <div
                className="sb-bar-grow h-full w-full origin-left"
                style={{ transform: `scaleX(${l.share})`, background: s.color ?? TONE_COLOR[s.tone ?? tone] }}
              />
            </div>
          );
        })}
      </div>
    );
  }
  const fill = Math.max(0, Math.min(1, Number.isFinite(ratio) ? (ratio as number) : 0));
  return (
    <div
      className={clsx("overflow-hidden rounded-pill", track, trackClassName, className)}
      role={label ? "meter" : undefined}
      aria-valuemin={label ? 0 : undefined}
      aria-valuemax={label ? 100 : undefined}
      aria-valuenow={label ? Math.round(fill * 100) : undefined}
      aria-label={label}
      aria-hidden={label ? undefined : true}
    >
      <div
        className="sb-bar-grow h-full w-full origin-left rounded-pill"
        style={{ transform: `scaleX(${fill})`, background: color ?? TONE_COLOR[tone] }}
      />
    </div>
  );
}
