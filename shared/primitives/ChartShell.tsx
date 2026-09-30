import clsx from "clsx";
import type { ReactNode } from "react";
import { UpdatingBadge, staleClass } from "./Motion";
import type { LucideIcon } from "lucide-react";
import { Icon } from "./Icon";

export function ChartShell({
  title,
  icon,
  sub,
  right,
  className,
  bodyClassName,
  stale,
  updating,
  children,
}: {
  title: ReactNode;
  /** Optional lucide glyph before the title (drawn through <Icon>). */
  icon?: LucideIcon;
  sub?: ReactNode;
  right?: ReactNode;
  className?: string;
  bodyClassName?: string;
  /** Body dims: its data belongs to the previous filter (new one in flight). */
  stale?: boolean;
  /** Shows the small "Updating" chip in the header (revalidating). */
  updating?: boolean;
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
          <h3 className="flex flex-wrap items-center gap-2 text-[13px] font-semibold text-fg-0">
            {icon && <Icon icon={icon} size="md" className="shrink-0 text-fg-3" />}
            {title}
            <UpdatingBadge show={!!(updating || stale)} />
          </h3>
          {sub && <p className="mt-0.5 text-[11px] text-fg-3">{sub}</p>}
        </div>
        {right && <div className="lg:shrink-0">{right}</div>}
      </header>
      <div className={clsx("min-h-0 flex-1", staleClass(stale), bodyClassName)}>
        {children}
      </div>
    </section>
  );
}
