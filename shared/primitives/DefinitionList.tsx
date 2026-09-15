import clsx from "clsx";
import type { ReactNode } from "react";

export function DefinitionList({ children, className }: { children: ReactNode; className?: string }) {
  return <dl className={clsx("text-[12px]", className)}>{children}</dl>;
}

export function DefinitionRow({ label, value }: { label: ReactNode; value: ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-3 py-1.5">
      <dt className="min-w-0 flex-1 text-fg-3">{label}</dt>
      <dd className="min-w-0 max-w-[50%] shrink-0 break-words text-right font-medium text-fg-1">{value}</dd>
    </div>
  );
}
