import { useEffect, useRef, useState } from "react";
import { HIGHLIGHT_MS, revealTarget } from "./scrollHighlight";

/**
 * useScrollHighlight reveals the element with `id` once, when `active` turns
 * true (the link names it): it opens a collapsed disclosure around it,
 * scrolls it into view and returns true for HIGHLIGHT_MS so the caller adds
 * HIGHLIGHT_CLASS. Mount it in the target's own component: a lazily loaded
 * card exists only after the page's own hash scroll ran, so the target
 * reveals itself once it renders. The open state is set on the element, never
 * held in React, so the person can still close it. `nonce` (the router
 * location's key) reveals it again when the same link is followed again.
 */
export function useScrollHighlight(id: string, active: boolean, nonce = ""): boolean {
  const [on, setOn] = useState(false);
  const done = useRef<string | null>(null);
  useEffect(() => {
    if (!active || typeof document === "undefined") return;
    const key = `${id}|${nonce}`;
    if (done.current === key) return;
    const el = document.getElementById(id);
    if (!el) return;
    done.current = key;
    revealTarget(el as HTMLElement & { open?: boolean });
    setOn(true);
  }, [id, active, nonce]);
  // The highlight clears itself; its own effect, so a re-run of the reveal
  // effect (a dependency change, StrictMode) never leaves it on.
  useEffect(() => {
    if (!on) return;
    const t = window.setTimeout(() => setOn(false), HIGHLIGHT_MS);
    return () => window.clearTimeout(t);
  }, [on]);
  return on;
}
