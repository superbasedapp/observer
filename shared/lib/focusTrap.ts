// Focus-trap helpers for modal surfaces (SlideOver).
//
// trapTarget is the pure decision: given the panel's focusable elements in
// DOM order, the currently focused element and the Tab direction, it returns
// the element focus should wrap to, or null to let the browser move focus
// normally. It never touches the DOM, so it runs under node --test.
//
// Rules, in order:
//   1. nothing focusable       -> null (the caller keeps focus on the panel)
//   2. focus is not on an item  -> first item (Shift+Tab: last item). This
//      covers the panel container itself, which holds focus right after open.
//   3. Tab on the last item     -> first item
//   4. Shift+Tab on the first   -> last item
//   5. anything else            -> null (normal browser order inside the panel)
export function trapTarget<T>(items: readonly T[], active: T | null, shift: boolean): T | null {
  if (items.length === 0) return null;
  const first = items[0];
  const last = items[items.length - 1];
  const idx = active == null ? -1 : items.indexOf(active);
  if (idx === -1) return shift ? last : first;
  if (!shift && idx === items.length - 1) return first;
  if (shift && idx === 0) return last;
  return null;
}

// FOCUSABLE_SELECTOR lists the elements a Tab key can land on. Visibility and
// `inert` are checked separately by focusableWithin.
export const FOCUSABLE_SELECTOR = [
  "a[href]",
  "area[href]",
  "button:not([disabled])",
  "input:not([disabled]):not([type='hidden'])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  "iframe",
  "[contenteditable='true']",
  "[tabindex]:not([tabindex='-1'])",
].join(",");

// focusableWithin returns the tabbable, rendered elements inside root in DOM
// order. Browser-only (it reads layout); callers guard for a DOM.
export function focusableWithin(root: HTMLElement): HTMLElement[] {
  return Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)).filter(
    (el) =>
      el.tabIndex >= 0 &&
      el.getClientRects().length > 0 &&
      el.closest("[inert]") === null &&
      el.closest("[aria-hidden='true']") === null,
  );
}
