import { useEffect, useLayoutEffect, useRef, useState, type ReactNode } from "react";
import { createMountQueue, type MountQueue } from "../lib/mountQueue";

// One page-wide queue: every chart slot on screen takes turns for its FIRST
// mount (shared/lib/mountQueue.ts has the why and the ordering rules). Null
// outside a browser, where content renders at once.
const queue: MountQueue | null =
  typeof window === "undefined"
    ? null
    : createMountQueue({
        setTimeout: (fn, ms) => window.setTimeout(fn, ms),
        clearTimeout: (h) => window.clearTimeout(h as number),
      });

/**
 * MountTurn renders `fallback` until this slot's turn in the page-wide mount
 * queue, then `children` for the rest of its life. Only the first mount
 * waits: a data refresh, a filter change that keeps the content mounted, or
 * any later re-render goes straight through. Used by ChartState so charts
 * that resolve together mount one per task instead of in one long task.
 */
export function MountTurn({ fallback, children }: { fallback: ReactNode; children: ReactNode }) {
  const [turn, setTurn] = useState(queue ? 0 : -1);
  const cancelRef = useRef<(() => void) | null>(null);
  useEffect(() => {
    if (!queue) return;
    cancelRef.current = queue.request((t) => setTurn(t));
    return () => {
      cancelRef.current?.();
      cancelRef.current = null;
    };
  }, []);
  // The content for this turn has committed: hand the turn on. The next
  // turn starts in a later macrotask (mountQueue), so input can run between.
  useLayoutEffect(() => {
    if (turn > 0) queue?.done(turn);
  }, [turn]);
  return <>{turn === 0 ? fallback : children}</>;
}
