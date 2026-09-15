import clsx from "clsx";
import type { ReactNode } from "react";
import { useHelpSlot } from "./helpSlot";

export function PageHeader({
  title,
  sub,
  helpId,
  right,
  className,
}: {
  title: string;
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
      {right && <div className="shrink-0">{right}</div>}
    </header>
  );
}
