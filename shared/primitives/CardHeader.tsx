import clsx from "clsx";
import type { ReactNode } from "react";
import type { LucideIcon } from "lucide-react";
import { Icon } from "./Icon";

// CardHeader: the one title row for a hand-built panel ({icon, title, sub,
// right}). It replaces the ~100 hand-rolled `mb-1 text-sm font-medium
// text-fg-1` titles in the org dashboard, so every panel title has the same
// size, weight, icon slot and right-aligned action slot. Use Card / ChartShell
// when the whole panel chrome is wanted; CardHeader is the header alone.
export function CardHeader({
  icon,
  title,
  sub,
  right,
  className,
}: {
  icon?: LucideIcon;
  title: ReactNode;
  sub?: ReactNode;
  right?: ReactNode;
  className?: string;
}) {
  return (
    <div className={clsx("mb-3 flex items-start justify-between gap-3", className)}>
      <div className="min-w-0">
        <h3 className="flex items-center gap-1.5 text-[13px] font-semibold text-fg-0">
          {icon && <Icon icon={icon} size="md" className="shrink-0 text-fg-3" />}
          <span className="min-w-0">{title}</span>
        </h3>
        {sub && <p className="mt-0.5 text-[11.5px] leading-snug text-fg-3">{sub}</p>}
      </div>
      {right && <div className="flex shrink-0 items-center gap-2">{right}</div>}
    </div>
  );
}
