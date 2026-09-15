import clsx from "clsx";
import { Tooltip } from "./Tooltip";

// DensityBar — segmented horizontal bar that splits a unit value
// (`total`) across multiple labelled buckets. Width per segment is
// proportional to the bucket value; leftover capacity (when `total`
// is less than the table-wide max) renders as a faint trailing rail
// so the user reads each row's bar both as a stacked breakdown AND
// as a magnitude relative to the worst offender in the table.
//
// Matches the design treatment in `design/page-discovery.jsx` Top
// files re-read — multi-color segments (red / orange / accent /
// rail) for cross-thread / stale / fresh / capacity.

export type DensitySegment = {
  // Segment value in the same unit as `total`. Negative values are
  // treated as zero.
  value: number;
  // CSS color (or var) for the segment fill.
  color: string;
  // Optional accessible label for the segment (tooltip + title text).
  label?: string;
};

export function DensityBar({
  segments,
  // Per-row total. Sum of segments should usually equal `total`; any
  // delta becomes the trailing rail (capacity not filled by segments).
  total,
  // Largest `total` across all rows in the surrounding table.
  // Drives the bar's relative width — short rows render thinner so
  // the magnitude of larger rows is visually obvious. Defaults to
  // `total` (every row fills the full track).
  max,
  width = 140,
  height = 8,
  className,
  title,
}: {
  segments: DensitySegment[];
  total: number;
  max?: number;
  width?: number;
  height?: number;
  className?: string;
  title?: React.ReactNode;
}) {
  const denom = Math.max(1, max ?? total);
  // Each segment renders proportionally to the table-wide max so two
  // bars from different rows compare directly. The trailing rail is
  // (max - total) / max of the track width.
  const filledPct = Math.min(100, (Math.max(0, total) / denom) * 100);
  const bar = (
    <div
      className={clsx(
        "relative inline-block overflow-hidden rounded-pill bg-bg-3",
        title && "cursor-help",
        className,
      )}
      style={{ width, height }}
      tabIndex={title ? 0 : undefined}
    >
      <div
        className="absolute inset-y-0 left-0 flex"
        style={{ width: `${filledPct}%` }}
      >
        {segments.map((seg, i) => {
          const v = Math.max(0, seg.value);
          if (v <= 0) return null;
          const pctOfFilled =
            total > 0 ? (v / Math.max(1, total)) * 100 : 0;
          const segNode = (
            <span
              className="block h-full"
              style={{
                width: `${pctOfFilled}%`,
                background: seg.color,
              }}
            />
          );
          if (!seg.label) return <span key={i}>{segNode}</span>;
          return (
            <Tooltip key={i} content={seg.label}>
              {segNode}
            </Tooltip>
          );
        })}
      </div>
    </div>
  );
  if (!title) return bar;
  return <Tooltip content={title}>{bar}</Tooltip>;
}
