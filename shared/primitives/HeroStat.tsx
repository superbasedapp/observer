import clsx from "clsx";
import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { Sparkline } from "./Sparkline";
import { StatDelta, type StatDeltaValue } from "./StatDelta";
import { useHelpSlot } from "./helpSlot";
import { AnimatedValue, Aurora, staleClass } from "./Motion";

// HeroStat — wide hero KPI tile for page-leading metrics like
// Compression's "Total compression savings" and Discovery's
// "Estimated waste". Layout intent matches
// `design/page-compression.jsx` + `design/page-discovery.jsx`: 2-3×
// the width of a StatCard, beefier value font, multi-line sub-text,
// saturated radial gradient. Designed to sit alongside a strip of
// regular StatCards in the same row.

export type HeroStatVariant = "accent" | "danger" | "warn";

export type HeroStatProps = {
  label: string;
  value: ReactNode;
  unit?: ReactNode;
  sub?: ReactNode;
  variant?: HeroStatVariant;
  helpId?: string;
  icon?: ReactNode;
  cornerPill?: ReactNode;
  spark?: number[];
  sparkColor?: string;
  loading?: boolean;
  /** Dim while the value belongs to the previous filter. */
  stale?: boolean;
  /** Paint the drifting brand aurora behind the tile (a page's lead KPI). */
  aurora?: boolean;
  /**
   * "corner" (default): the small trend at the bottom right. "wide": a
   * full-width trend band along the bottom that draws itself in - for a
   * large lead tile with room to spare.
   */
  sparkMode?: "corner" | "wide";
  /**
   * Period-over-period delta, rendered like StatCard's (cost-aware: up =
   * danger, down = success): a signed fraction (0.12 = +12%) or a guarded
   * delta (web2 `format.computeDelta`).
   */
  delta?: StatDeltaValue;
  /** Text after the delta when `deltaPrior` is absent. */
  deltaLabel?: string;
  /** Concrete prior-period value (`vs prior $6,073.08`); wins over deltaLabel. */
  deltaPrior?: ReactNode;
  /** When set, the tile is a <Link> to this route and lifts on hover. */
  linkTo?: string;
  /** Accessible name for the link (defaults to the tile's text). */
  linkLabel?: string;
  className?: string;
};

export function HeroStat({
  label,
  value,
  unit,
  sub,
  variant = "accent",
  helpId,
  icon,
  cornerPill,
  spark,
  sparkColor,
  loading,
  stale,
  aurora,
  sparkMode = "corner",
  delta,
  deltaLabel,
  deltaPrior,
  linkTo,
  linkLabel,
  className,
}: HeroStatProps) {
  const renderHelp = useHelpSlot();
  const valueColor =
    variant === "danger"
      ? "text-danger"
      : variant === "warn"
        ? "text-warn"
        : "text-accent";
  const borderColor =
    variant === "danger"
      ? "border-danger/40"
      : variant === "warn"
        ? "border-warn/40"
        : "border-accent/40";
  const gradient =
    variant === "danger"
      ? "radial-gradient(circle at 100% 0%, color-mix(in srgb, var(--danger-soft) 92%, transparent), transparent 58%)"
      : variant === "warn"
        ? "radial-gradient(circle at 100% 0%, color-mix(in srgb, var(--warn-soft) 92%, transparent), transparent 58%)"
        : "radial-gradient(circle at 100% 0%, color-mix(in srgb, var(--accent-soft) 92%, transparent), transparent 58%)";
  const defaultSparkColor =
    sparkColor ??
    (variant === "danger"
      ? "var(--danger)"
      : variant === "warn"
        ? "var(--warn)"
        : "var(--accent)");
  const rootClass = clsx(
    "relative flex min-h-[140px] flex-col overflow-hidden rounded-3 border bg-bg-2 px-5 py-4",
    borderColor,
    linkTo && "sb-lift",
    staleClass(stale),
    className,
  );
  const hasDelta = delta != null || deltaPrior != null;
  const inner = (
    <>
      {aurora && <Aurora />}
      <span
        aria-hidden
        className="pointer-events-none absolute inset-0"
        style={{ background: gradient }}
      />
      <div
        className={clsx(
          "relative flex min-h-0 flex-1 flex-col",
          // Theme-aware shimmer (motion.css), not Tailwind's opacity pulse.
          loading && "animate-shimmer overflow-hidden",
        )}
      >
        <div className="flex items-start justify-between gap-2">
          <div className="flex items-center gap-1.5 text-[10.5px] font-semibold uppercase tracking-[0.08em] text-fg-3">
            {icon && <span className="text-fg-3">{icon}</span>}
            {label}
            {helpId && renderHelp(helpId)}
            {loading && (
              <span
                aria-label="loading"
                className="ml-0.5 inline-block h-1.5 w-1.5 animate-pulse rounded-full bg-accent"
              />
            )}
          </div>
          {cornerPill && <div className="shrink-0">{cornerPill}</div>}
        </div>
        <div className="mt-2 flex items-baseline gap-2">
          <span
            className={clsx(
              "text-[44px] font-bold leading-[1.02] tracking-[-0.03em]",
              valueColor,
            )}
          >
            <AnimatedValue value={value} />
          </span>
          {unit && (
            <span className="text-[18px] font-medium text-fg-2">{unit}</span>
          )}
        </div>
        {hasDelta ? (
          // The delta row: StatCard's order (delta, prior or label, sub).
          <div
            className={clsx(
              "mt-2 flex flex-wrap items-center gap-x-2 gap-y-0.5 text-[12px] leading-snug text-fg-3",
              sparkMode === "corner" && "pr-[100px]",
            )}
          >
            <StatDelta delta={delta} deltaLabel={deltaLabel} deltaPrior={deltaPrior} />
            {sub && <span>{sub}</span>}
          </div>
        ) : (
          sub && (
            <div
              className={clsx(
                "mt-2 text-[12px] leading-snug text-fg-3",
                sparkMode === "corner" && "pr-[100px]",
              )}
            >
              {sub}
            </div>
          )
        )}
      </div>
      {spark && spark.length >= 2 && sparkMode === "wide" && (
        <div aria-hidden className="pointer-events-none relative -mx-5 -mb-4 mt-auto pt-4">
          <Sparkline
            data={spark}
            color={defaultSparkColor}
            width={400}
            height={72}
            strokeWidth={1.8}
            stretch
            reveal
          />
        </div>
      )}
      {spark && spark.length >= 2 && sparkMode === "corner" && (
        <div
          aria-hidden
          className="pointer-events-none absolute bottom-3 right-4 opacity-[0.85]"
        >
          <Sparkline
            data={spark}
            color={defaultSparkColor}
            width={88}
            height={32}
          />
        </div>
      )}
    </>
  );
  if (linkTo) {
    return (
      <Link to={linkTo} aria-label={linkLabel} className={rootClass}>
        {inner}
      </Link>
    );
  }
  return <div className={rootClass}>{inner}</div>;
}
