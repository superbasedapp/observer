import { useEffect, useRef } from "react";
import { advanceArrivals, isArrival, type ArrivalState } from "@/lib/liveSignals";

/**
 * useArrivals returns a predicate that is true for a list key that arrived
 * after the list's first settled render (a new row on a live poll), so the
 * caller can give just that row `sb-fade-up`. `active` is false while the
 * data on screen is not current (no response yet, or a stale response from
 * the previous filter / page): the baseline is dropped and re-taken from the
 * next current list, so a filter change or first load never animates the
 * whole list. State is read during render and advanced after each commit.
 */
export function useArrivals(keys: readonly string[], active: boolean): (key: string) => boolean {
  const ref = useRef<ArrivalState | null>(null);
  useEffect(() => {
    ref.current = active ? advanceArrivals(ref.current, keys) : null;
  });
  const state = active ? ref.current : null;
  return (key: string) => isArrival(state, key);
}
