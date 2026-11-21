// scrollHighlight: the one rule for a settings link that lands on one card or
// row (lane UI, SBXD smaller items): the target opens if it is a collapsed
// disclosure, scrolls into view and carries a short highlight, so the person
// sees which card the link meant. Pure (no React, no DOM types beyond the
// element methods it is handed) so scrollHighlight.test.ts runs under
// `node --test`; the hook is lib/useScrollHighlight.ts.

/** How long the highlight stays on the target (the session drawer's message
 *  focus uses the same 3 s). */
export const HIGHLIGHT_MS = 3000;

/** The classes a highlighted target carries (the accent focus ring). */
export const HIGHLIGHT_CLASS = "ring-2 ring-accent-ring";

/** hashNames reports whether a location hash ("#hosted-sandboxes") names the
 *  element id ("hosted-sandboxes"). An empty id never matches. */
export function hashNames(hash: string, id: string): boolean {
  if (!id) return false;
  let h = hash.startsWith("#") ? hash.slice(1) : hash;
  try {
    h = decodeURIComponent(h);
  } catch {
    // A malformed escape is compared as written.
  }
  return h === id;
}

/** The element methods revealTarget uses (an HTMLElement in the browser). */
export type RevealTarget = {
  tagName: string;
  open?: boolean;
  parentElement: RevealTarget | null;
  scrollIntoView: (opts: { block: "start" | "center"; behavior: "smooth" | "auto" }) => void;
};

/**
 * revealTarget opens the target when it is a <details> and every collapsed
 * <details> around it (a scroll to a closed disclosure's body lands on
 * nothing), then scrolls it into view. Returns how many disclosures it
 * opened.
 */
export function revealTarget(el: RevealTarget): number {
  let opened = 0;
  for (let n: RevealTarget | null = el; n; n = n.parentElement) {
    if (n.tagName.toUpperCase() === "DETAILS" && !n.open) {
      n.open = true;
      opened++;
    }
  }
  el.scrollIntoView({ block: "start", behavior: "smooth" });
  return opened;
}
