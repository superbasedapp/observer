import clsx from "clsx";
import type { ReactNode } from "react";
import { useHelpSlot } from "./helpSlot";
import type { LucideIcon } from "lucide-react";
import { Icon } from "./Icon";

export function PageHeader({
  title,
  icon,
  sub,
  helpId,
  right,
  className,
}: {
  title: string;
  /** Optional lucide glyph in a soft accent tile before the title. */
  icon?: LucideIcon;
  sub?: ReactNode;
  helpId?: string;
  right?: ReactNode;
  className?: string;
}) {
  const renderHelp = useHelpSlot();
  return (
    <header
      className={clsx("flex items-start justify-between gap-4", className)}
    >
      <div className="flex min-w-0 items-start gap-3">
        {icon && (
          <span
            aria-hidden
            className="mt-0.5 grid h-9 w-9 shrink-0 place-items-center rounded-3 border border-accent/25 bg-accent-soft text-accent"
          >
            <Icon icon={icon} size="lg" />
          </span>
        )}
        <div className="min-w-0">
        <h1 className="flex items-center text-[22px] font-semibold leading-tight tracking-[-0.02em] text-fg-0">
          {title}
          {helpId && <span className="ml-2">{renderHelp(helpId)}</span>}
        </h1>
        {sub && (
          <p className="mt-1 max-w-3xl text-[12.5px] leading-snug text-fg-3">
            {sub}
          </p>
        )}
        </div>
      </div>
      {right && <div className="shrink-0">{right}</div>}
    </header>
  );
}
