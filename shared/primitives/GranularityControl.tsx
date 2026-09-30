import clsx from "clsx";
import {
  allowedGranularities,
  effectiveChoice,
  granularityLabel,
  granularityUnit,
  type GranChoice,
  type Granularity,
} from "../lib/granularity";
import { SegmentedControl, type Segment } from "./SegmentedControl";

// GranularityControl is the small per-card bucket picker every time-series
// chart carries: Auto plus ONLY the granularities the window span allows
// (the 2000-point cap) and the surface can serve (`only`, e.g. DAILY_ONLY for
// a chart fed by a day-grained summary, which also shows the honest
// "daily data only" note instead of offering a fake hour).
//
// Pure presentational: the owner (the app's filter state) persists the
// choice in the URL (`gran=`). A choice the current span no longer allows
// renders as Auto (effectiveChoice) - the same rule the fetch uses, so the
// control never shows a selection the chart is not drawing.
/** The note a card shows when the server bucketed in UTC (tz_fallback). */
export const TZ_FALLBACK_NOTE = "UTC buckets (zone unavailable)";

export function GranularityControl({
  value,
  onChange,
  spanMs,
  only,
  resolved,
  tzFallback,
  className,
}: {
  value: GranChoice;
  onChange: (g: GranChoice) => void;
  /** The window span in ms (Infinity for an unbounded window). */
  spanMs: number;
  /** Restrict the choices (a daily-summary surface passes DAILY_ONLY). */
  only?: readonly Granularity[];
  /** The granularity the server actually served, shown on the Auto tooltip. */
  resolved?: Granularity | null;
  /**
   * The server could not use the viewer's zone and bucketed in UTC instead
   * (the response's `tz_fallback`): the card says so rather than silently
   * drawing UTC days/hours as if they were local.
   */
  tzFallback?: boolean;
  className?: string;
}) {
  const allowed = allowedGranularities(spanMs, only);
  const current = effectiveChoice(value, spanMs, only);
  const options: Segment<GranChoice>[] = [
    { value: "auto", label: granularityLabel("auto") },
    ...allowed.map((g) => ({ value: g as GranChoice, label: granularityLabel(g) })),
  ];
  const dailyOnly = !!only && only.every((g) => g === "1d" || g === "1w");
  return (
    <span
      className={clsx("inline-flex items-center gap-1.5", className)}
      title={resolved ? `Bucketed per ${granularityUnit(resolved)}` : undefined}
    >
      <SegmentedControl<GranChoice>
        size="sm"
        options={options}
        value={current}
        onChange={onChange}
      />
      {dailyOnly && <span className="text-[10.5px] text-fg-3">daily data only</span>}
      {tzFallback && (
        <span
          className="text-[10.5px] text-fg-3"
          title="The server could not use your time zone, so buckets follow UTC."
        >
          {TZ_FALLBACK_NOTE}
        </span>
      )}
    </span>
  );
}
