import clsx from "clsx";
import type { ReactNode } from "react";
import { Tooltip } from "@shared/primitives/Tooltip";

// RawIdHint keeps the raw wire value behind a human label reachable (a
// consent purpose id, a retention state, a feature id, an exact timestamp):
// the shared themed Tooltip on hover AND keyboard focus, in place of the
// browser's native `title=` hint, which is unthemed and never shows on focus.
export function RawIdHint({
  id,
  children,
  className,
}: {
  id: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <Tooltip content={<span className="break-all font-mono">{id}</span>}>
      <span
        tabIndex={0}
        className={clsx(
          "rounded-1 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent-ring",
          className,
        )}
      >
        {children}
      </span>
    </Tooltip>
  );
}
