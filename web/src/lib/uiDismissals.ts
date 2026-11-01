// uiDismissals - dashboard notices the owner dismissed for good, kept on the
// daemon (WINNODE2 16b). The product tour and the "Review components" card
// used to remember a dismissal in the browser's own storage only, so they
// came back on every reload in a browser whose storage did not persist (a
// broken profile, a fresh automation profile, a second browser). The daemon
// now keeps the dismissal beside its database (GET /api/firstrun lists it;
// POST /api/firstrun/seen {"dismiss": key} records it), and the browser's
// own storage stays the fast path. Pure: no fetch here (the caller posts
// dismissRequestInit), pinned by uiDismissals.test.ts.

/** The closed set of notice keys the daemon accepts. */
export type UiNotice = "tour" | "components_setup";

let known: ReadonlySet<string> = new Set();
let confirmToken = "";
const listeners = new Set<() => void>();

function emit() {
  for (const l of listeners) l();
}

/** noteServerDismissals records what the daemon reported (the first-run read). */
export function noteServerDismissals(keys: readonly string[] | null | undefined, token?: string): void {
  if (token) confirmToken = token;
  const next = new Set(known);
  for (const k of keys ?? []) next.add(k);
  if (next.size === known.size) return;
  known = next;
  emit();
}

/** markDismissedLocally records a dismissal before the daemon confirms it. */
export function markDismissedLocally(key: UiNotice): void {
  if (known.has(key)) return;
  known = new Set([...known, key]);
  emit();
}

/** isDismissed reports a notice dismissed for good on this node. */
export function isDismissed(key: UiNotice): boolean {
  return known.has(key);
}

/** The confirm token the dismissal POST echoes (from the first-run read). */
export function dismissConfirmToken(): string {
  return confirmToken;
}

/** The dismissal POST: JSON plus the owner-local confirm header (T-530). */
export function dismissRequestInit(key: UiNotice, token: string): RequestInit {
  return {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Observer-Confirm": token },
    body: JSON.stringify({ dismiss: key }),
  };
}

export function subscribeDismissals(l: () => void): () => void {
  listeners.add(l);
  return () => listeners.delete(l);
}

/** A snapshot value that changes whenever the set does (useSyncExternalStore). */
export function dismissalsSnapshot(): ReadonlySet<string> {
  return known;
}

/** Test seam: back to the initial state. */
export function resetDismissals(): void {
  known = new Set();
  confirmToken = "";
  listeners.clear();
}
