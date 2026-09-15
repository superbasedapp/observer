import clsx from "clsx";
import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { Sparkline } from "./Sparkline";
import { useHelpSlot } from "./helpSlot";

export type StatCardProps = {
  label: string;
  value: ReactNode;
  unit?: string;
  sub?: ReactNode;
  // Signed fraction: 0.12 = +12%. Color follows design's cost-aware
  // convention (`design/app.css:442-443`): UP renders danger-red,
  // DOWN renders success-green — because every dashboard tile here
  // measures cost or volume where "up" is the worse outcome. Pages
  // that want the opposite sense (e.g. cache savings) can flip the
  // sign upstream when computing the delta.
  delta?: number;
  deltaLabel?: string;
  // Concrete prior-period value rendered after the delta %. Example:
  // `vs prior 30d $6,073.08`. Layered on top of `deltaLabel` when both
  // are passed (deltaPrior wins).
  deltaPrior?: ReactNode;
  spark?: number[];
  sparkColor?: string;
  warn?: boolean;
  accent?: boolean;
  className?: string;
  // Help registry id. When set, renders a ? indicator after the
  // label that opens the help drawer scrolled to this entry.
  helpId?: string;
  // Optional glyph anchored left of the label (matches design's
  // `design/primitives.jsx:55-63` — icon inline with label).
  icon?: ReactNode;
  // Optional status capsule anchored top-right of the card (e.g.
  // `window 30d`, `all systems nominal`).
  cornerPill?: ReactNode;
  // When set, wraps the card in a <Link>. Hover lifts the card.
  linkTo?: string;
  // Surface in-flight state — when true, a small pulsing dot appears
  // next to the label and the value shimmers slightly so the user
  // sees the data is mid-refresh. Drives off the parent useApi's
  // `loading` flag.
  loading?: boolean;
  children?: ReactNode;
};

export function StatCard(props: StatCardProps) {
  const { linkTo, className, accent, warn, spark, sparkColor, loading, ...rest } = props;
  // Design intent (design/app.css:404-459):
  //   .stat { position: relative; overflow: hidden }
  //   .stat.accent::before / .stat.warn::before — radial gradient at top right
  //   .stat .spark { position: absolute; right: 12px; bottom: 12px;
  //                  width: 80px; height: 28px; opacity: 0.85 }
  // We mirror both — the gradient is rendered as an absolutely-positioned
  // pointer-events-none span so it composes with the link wrapper, and the
  // sparkline floats bottom-right of the card rather than stacking under
  // the sub row (the earlier layout, which made sub+spark fight for room).
  const wrapperClass = clsx(
    "relative flex min-h-[104px] flex-col gap-1 overflow-hidden rounded-3 border bg-bg-2 px-4 py-3 transition-colors",
    accent
      ? "border-accent/40"
      : warn
        ? "border-warn/30"
        : "border-line-2 hover:border-line-3",
    linkTo && "hover:bg-bg-3",
    className,
  );
  // Per-variant top-right radial overlay. Even the default variant gets
  // a faint accent wash now (per operator feedback: "all headline cards
  // should have a nice gradient"), so neutral tiles read with depth too
  // — just at a lower intensity so the loud accent/warn variants still
  // pop on Cost / Discovery / Compression hero tiles.
  const overlayGradient = accent
    ? "radial-gradient(circle at 100% 0%, var(--accent-soft), transparent 62%)"
    : warn
      ? "radial-gradient(circle at 100% 0%, var(--warn-soft), transparent 62%)"
      : "radial-gradient(circle at 100% 0%, color-mix(in srgb, var(--accent-soft) 35%, transparent), transparent 70%)";
  const inner = (
    <>
      <span
        aria-hidden
        className="pointer-events-none absolute inset-0"
        style={{ background: overlayGradient }}
      />
      <div
        className={clsx(
          "relative flex min-h-0 flex-1 flex-col gap-1",
          loading && "animate-pulse",
        )}
      >
        <Body {...rest} loading={loading} />
      </div>
      {spark && spark.length >= 2 && (
        <div
          aria-hidden
          className="pointer-events-none absolute bottom-2.5 right-3 opacity-[0.85]"
        >
          <Sparkline data={spark} color={sparkColor} width={80} height={28} />
        </div>
      )}
    </>
  );
  if (linkTo) {
    return (
      <Link to={linkTo} className={wrapperClass}>
        {inner}
      </Link>
    );
  }
  return <div className={wrapperClass}>{inner}</div>;
}

function Body({
  label,
  value,
  unit,
  sub,
  delta,
  deltaLabel,
  deltaPrior,
  helpId,
  icon,
  cornerPill,
  loading,
  children,
}: Omit<
  StatCardProps,
  "linkTo" | "className" | "warn" | "accent" | "spark" | "sparkColor"
>) {
  const renderHelp = useHelpSlot();
  // Design's cost-aware delta coloring: UP = danger (cost went up),
  // DOWN = success (cost went down). `design/app.css:442-443`.
  const deltaColor =
    delta == null || !Number.isFinite(delta)
      ? "text-fg-3"
      : delta > 0
        ? "text-danger"
        : delta < 0
          ? "text-success"
          : "text-fg-3";
  return (
    <>
      <div className="flex items-start justify-between gap-2">
        {/* The label carries an overwhelming flex-shrink weight so it
            absorbs (by wrapping to its min-content — the longest word)
            essentially ALL horizontal shrink first, freeing width for
            the pill. Its default min-width:auto floors it at the
            longest word, so the label wraps but never clips. */}
        <div className="flex [flex-shrink:9999] items-center gap-1.5 text-[10px] font-semibold uppercase tracking-[0.06em] text-fg-3">
          {icon && <span className="text-fg-3">{icon}</span>}
          {label}
          {helpId && renderHelp(helpId)}
          {loading && (
            <span
              aria-label="loading"
              className="ml-0.5 inline-block h-1 w-1 animate-pulse rounded-full bg-accent"
            />
          )}
        </div>
        {/* The pill shrinks only as a LAST resort — once the label has
            frozen at its min-content, any remaining overflow lands
            here. min-w-0 lets the flex item shrink below its content;
            the inline-block + max-w-full + truncate on the pill itself
            renders the ellipsis. Short pills ("all systems nominal",
            "window 30d") keep their natural width; only a very long
            label ("window Jul 14 → Jul 16") that can't fit even beside
            a fully-wrapped label truncates. */}
        {cornerPill && (
          <div className="min-w-0 shrink [&>*]:inline-block [&>*]:max-w-full [&>*]:truncate [&>*]:align-bottom">
            {cornerPill}
          </div>
        )}
      </div>
      <div className="mt-1 flex items-baseline gap-1.5 text-fg-0">
        <span className="text-[34px] font-bold leading-[1.05] tracking-[-0.025em]">
          {value}
        </span>
        {unit && (
          <span className="text-[16px] font-medium text-fg-2">{unit}</span>
        )}
      </div>
      {(sub || delta != null || deltaPrior != null) && (
        <div className="mt-1.5 flex flex-wrap items-center gap-x-2 gap-y-0.5 pr-[88px] text-[11px] text-fg-3">
          {delta != null && Number.isFinite(delta) && (
            <span
              className={clsx(
                "inline-flex items-center gap-0.5 font-semibold",
                deltaColor,
              )}
            >
              {delta > 0 ? "↑" : delta < 0 ? "↓" : "·"}
              {(Math.abs(delta) * 100).toFixed(1)}%
            </span>
          )}
          {deltaPrior != null ? (
            <span>{deltaPrior}</span>
          ) : (
            deltaLabel && <span>{deltaLabel}</span>
          )}
          {sub && <span>{sub}</span>}
        </div>
      )}
      {children}
    </>
  );
}
