// arrivals: which list rows arrived after a list's first settled render,
// so a live poll's new row can fade in (sb-fade-up) without re-animating
// the whole list. Shared by both dashboards (useArrivals is the hook over
// it). Pure, no imports, so each app's liveSignals.test.ts runs it under
// plain node.

/**
 * ArrivalState remembers a list's keys as of the last commit and which of
 * them arrived after the baseline, so a newly arrived row can fade in once
 * without re-animating the whole list on every poll.
 */
export type ArrivalState = { seen: ReadonlySet<string>; arrived: ReadonlySet<string> };

/**
 * advanceArrivals folds one committed key list into the state. With no prior
 * state the keys become the baseline (nothing arrives on the first render).
 * A key arrives when it was not seen at the last commit, and stays arrived
 * while it remains in the list (so its class is never removed mid-animation);
 * a key that leaves is forgotten.
 */
export function advanceArrivals(prev: ArrivalState | null, keys: readonly string[]): ArrivalState {
  if (!prev) return { seen: new Set(keys), arrived: new Set() };
  const arrived = new Set<string>();
  for (const k of keys) if (!prev.seen.has(k) || prev.arrived.has(k)) arrived.add(k);
  return { seen: new Set(keys), arrived };
}

/** isArrival reports whether `key` arrived after the baseline (false with no baseline). */
export function isArrival(state: ArrivalState | null, key: string): boolean {
  if (!state) return false;
  return !state.seen.has(key) || state.arrived.has(key);
}
