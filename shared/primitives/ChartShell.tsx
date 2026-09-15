import clsx from "clsx";
import type { ReactNode } from "react";

export function ChartShell({
  title,
  sub,
  right,
  className,
  bodyClassName,
  children,
}: {
  title: ReactNode;
  sub?: ReactNode;
  right?: ReactNode;
  className?: string;
  bodyClassName?: string;
  children: ReactNode;
}) {
  return (
    <section
      className={clsx(
        "flex flex-col gap-3 rounded-3 border border-line-2 bg-bg-2 p-4",
        className,
      )}
    >
      {/* Below lg the header stacks (title row, then the `right` slot
          full-width beneath) so a wide `right` — e.g. Sessions' 240px
          filter input — can't squeeze the title into a one-word-per-line
          column on a phone. At lg+ it is the exact prior single row. */}
      <header className="flex flex-col gap-2 lg:flex-row lg:items-start lg:justify-between lg:gap-3">
        <div className="min-w-0">
          <h3 className="text-[13px] font-semibold text-fg-0">{title}</h3>
          {sub && <p className="mt-0.5 text-[11px] text-fg-3">{sub}</p>}
        </div>
        {right && <div className="lg:shrink-0">{right}</div>}
      </header>
      <div className={clsx("min-h-0 flex-1", bodyClassName)}>{children}</div>
    </section>
  );
}
