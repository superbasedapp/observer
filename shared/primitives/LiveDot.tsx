import clsx from "clsx";
import { liveDotSizeClass, type LiveDotSize } from "../lib/liveDotSize";

// LiveDot — a status dot with a pinging halo for "live" states (a running
// session, a connected node, a streaming terminal, an enrolled collector).
// tone="idle" renders a still grey dot (stopped / stale) with no halo, so the
// animation itself carries the meaning "this is happening now". CSS in
// shared/styles/motion.css (.sb-live-dot); reduced motion keeps the dot, drops
// the halo. `still` keeps a tone but drops the halo, for a state worth
// colouring that is not happening now (paused, an error that already ended).
export type LiveTone = "success" | "warn" | "danger" | "info" | "accent" | "idle";
export type { LiveDotSize };

export function LiveDot({
  tone = "success",
  still,
  label,
  size = "md",
  className,
}: {
  tone?: LiveTone;
  /** Colour without the ping halo. */
  still?: boolean;
  /** Accessible text, e.g. "Live" or "Disconnected". */
  label?: string;
  /** Dot size from lib/liveDotSize.ts (sm 6px / md 8px, the default / lg 10px). */
  size?: LiveDotSize;
  className?: string;
}) {
  return (
    <span
      className={clsx("sb-live-dot", liveDotSizeClass(size), className)}
      data-tone={tone}
      data-still={still || undefined}
      role={label ? "status" : undefined}
      aria-label={label}
      aria-hidden={label ? undefined : true}
    />
  );
}
