import type { ReactNode } from "react";
import { InlineLoading } from "@/components/primitives";
import { useDeferredShow } from "@shared/lib/useDeferredShow";

// NamedLoading is the Code security page's loading line: it says WHAT is
// loading ("Loading findings: 5,230 open across 27 projects") above the
// slot's own skeleton, and after a few seconds an honest slow line, so a
// wait is never a bare shimmer (redesign plan section 4.3). It follows the
// shared timing rules (useDeferredShow: nothing for 300 ms, so a fast read
// shows only the skeleton's own flash, then at least 600 ms on screen).
// Working surface: a spinner and text, never the mascot (the Obs contract
// in shared/primitives/Obs.tsx keeps Obs out of tables and forms).

/** How long a load runs before the slow line shows. */
export const NAMED_LOADING_SLOW_MS = 3000;

export function NamedLoading({
  active,
  label,
  slowLine,
  children,
}: {
  active: boolean;
  /** What is loading, in words. */
  label: string;
  /** Shown once the load has run NAMED_LOADING_SLOW_MS; omit for none. */
  slowLine?: ReactNode;
  /** The slot's own skeleton, shown under the line while active. */
  children?: ReactNode;
}) {
  const { show, slow } = useDeferredShow(active, { slowMs: NAMED_LOADING_SLOW_MS });
  if (!active) return null;
  return (
    <div className="space-y-2" data-testid="named-loading">
      {show && (
        <div className="flex flex-wrap items-center gap-2 text-[12.5px] text-fg-2">
          <InlineLoading label={label} size="md" className="text-fg-2" />
          {slow && slowLine ? <span className="text-fg-3">{slowLine}</span> : null}
        </div>
      )}
      {children}
    </div>
  );
}
