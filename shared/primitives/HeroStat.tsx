import clsx from "clsx";
import type { ReactNode } from "react";
import { Sparkline } from "./Sparkline";
import { useHelpSlot } from "./helpSlot";

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
  return (
    <div
      className={clsx(
        "relative flex min-h-[140px] flex-col overflow-hidden rounded-3 border bg-bg-2 px-5 py-4",
        borderColor,
        className,
      )}
    >
      <span
        aria-hidden
        className="pointer-events-none absolute inset-0"
        style={{ background: gradient }}
      />
      <div
        className={clsx(
          "relative flex min-h-0 flex-1 flex-col",
          loading && "animate-pulse",
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
            {value}
          </span>
          {unit && (
            <span className="text-[18px] font-medium text-fg-2">{unit}</span>
          )}
        </div>
        {sub && (
          <div className="mt-2 pr-[100px] text-[12px] leading-snug text-fg-3">
            {sub}
          </div>
        )}
      </div>
      {spark && spark.length >= 2 && (
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
    </div>
  );
}
