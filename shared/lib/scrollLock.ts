// Scroll lock shared by the overlay primitives. DOM-only, no React.

// lockScroll stops the page behind an overlay (SlideOver, Modal) from
// scrolling: `body` plus every ancestor of the panel that is itself a
// vertical scroll container (web2's shell scrolls <main>, not the document). Returns the undo, which
// restores each element's previous inline overflow exactly.
export function lockScroll(panel: HTMLElement | null): () => void {
  const targets: HTMLElement[] = [document.body];
  for (let el = panel?.parentElement ?? null; el && el !== document.body; el = el.parentElement) {
    const oy = window.getComputedStyle(el).overflowY;
    if ((oy === "auto" || oy === "scroll") && el.scrollHeight > el.clientHeight) targets.push(el);
  }
  const prev = targets.map((el) => el.style.overflow);
  for (const el of targets) el.style.overflow = "hidden";
  return () => {
    targets.forEach((el, i) => {
      el.style.overflow = prev[i];
    });
  };
}
