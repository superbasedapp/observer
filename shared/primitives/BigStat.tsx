import type { ReactNode } from "react";
import clsx from "clsx";

// BigStat is the large session-detail KPI tile used above the tab strip.
// Values and provenance captions stay app-owned; this component owns their
// shared visual hierarchy.
export type BigStatProps = {
  label: string;
  value: ReactNode;
  sub?: ReactNode;
  subTitle?: string;
  warn?: boolean;
  accent?: boolean;
  muted?: boolean;
  icon?: ReactNode;
};

export function BigStat({
  label,
  value,
  sub,
  subTitle,
  warn,
  accent,
  muted,
  icon,
}: BigStatProps) {
  return (
    <div
      className={clsx(
        "relative flex flex-col gap-1 overflow-hidden rounded-3 border bg-bg-2 px-4 py-3.5",
        accent
          ? "border-accent/40 ring-1 ring-accent-ring"
          : warn
            ? "border-warn/40"
            : "border-line-2",
      )}
    >
      <span
        aria-hidden
        className="pointer-events-none absolute inset-0"
        style={{
          background: warn
            ? "radial-gradient(circle at 100% 0%, var(--warn-soft), transparent 60%)"
            : accent
              ? "radial-gradient(circle at 100% 0%, var(--accent-soft), transparent 60%)"
              : "radial-gradient(circle at 100% 0%, color-mix(in srgb, var(--accent-soft) 30%, transparent), transparent 70%)",
        }}
      />
      <div className="relative">
        <span className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-[0.08em] text-fg-3">
          {icon && <span className="text-fg-3">{icon}</span>}
          {label}
        </span>
        <span
          className={clsx(
            "mt-0.5 block text-[34px] font-bold leading-[1.05] tracking-[-0.02em]",
            warn ? "text-warn" : muted ? "text-fg-2" : "text-fg-0",
          )}
        >
          {value}
        </span>
        {sub && (
          <span
            className={clsx(
              "mt-1 block text-[11px]",
              muted ? "text-fg-4" : "text-fg-3",
              subTitle && "cursor-help",
            )}
            title={subTitle}
          >
            {sub}
          </span>
        )}
      </div>
    </div>
  );
}
