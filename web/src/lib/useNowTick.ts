import { useEffect, useState } from "react";

/**
 * useNowTick re-renders on a fixed interval so live countdowns/elapsed
 * displays advance between the slower data polls that drive them. Paused
 * while the tab is hidden (same policy as useApi) so a backgrounded panel
 * does no needless work.
 *
 * Extracted from cockpit/CockpitContent.tsx (where it first shipped) so a
 * SECOND "elapsed since mount" surface — TerminalSessionModal's uncorrelated
 * note — doesn't compute Date.now() directly at render time, which never
 * re-renders on its own and freezes the displayed elapsed at whatever value
 * happened to be current on the last poll-driven render (observed live as a
 * "Waiting 0s" panel that never advances).
 */
export function useNowTick(intervalMs: number): number {
  const [now, setNow] = useState<number>(() => Date.now());
  useEffect(() => {
    const id = window.setInterval(() => {
      if (typeof document !== "undefined" && document.visibilityState === "hidden") return;
      setNow(Date.now());
    }, intervalMs);
    return () => window.clearInterval(id);
  }, [intervalMs]);
  return now;
}
