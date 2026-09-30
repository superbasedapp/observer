import { useEffect, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import clsx from "clsx";
import { X } from "lucide-react";
import { Icon } from "./Icon";
import { Tooltip } from "./Tooltip";
import { DUR, prefersReducedMotion } from "../lib/motion";
import { focusableWithin, trapTarget } from "../lib/focusTrap";
import { lockScroll } from "../lib/scrollLock";

// Right-side slide-over drawer with backdrop - the ONE owner for web/ and
// web2/ (web2's fork was folded in here; its additive `bodyClassName` and
// `footer` slots came with it).
//
// Behaviour:
//   - Escape closes; clicking the backdrop closes.
//   - Modal focus: focus moves into the panel on open, Tab / Shift+Tab wrap
//     inside it (a real focus trap, not just an initial focus), and focus
//     returns to the element that opened it when it closes.
//   - Scroll lock: the page behind does not scroll. That is `body` in web/
//     (the document scrolls) but web2's shell scrolls `<main>`, so every
//     scrolling ancestor of the panel is locked too, not only `body`.
//
// Motion is CSS-owned (shared/styles/tokens.css --dur-* / --ease-*), so
// prefers-reduced-motion collapses it to zero through the tokens and neither
// app pulls framer-motion in for the drawer. The panel stays mounted through
// the exit transition, then unmounts.
//
// Width defaults to 880px; pages can pass a larger value, and
// SessionDetailPanel passes 1400. We clamp to min(width, 96vw) via
// max-width on the panel container so even on narrow viewports the
// panel stays inside the window.
export function SlideOver({
  open,
  onClose,
  title,
  subtitle,
  children,
  width = 880,
  zIndex,
  bodyClassName = "",
  footer,
}: {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  subtitle?: ReactNode;
  children: ReactNode;
  width?: number;
  /**
   * Base stacking level for the scrim; the panel sits at `zIndex + 2`.
   *
   * Defaults to the page level (40/50) that every page-level slide-over has
   * always used. It exists for ONE case: a slide-over opened from the terminal
   * workspace, which is itself an overlay stack - the expanded-terminal
   * backdrop sits at z-80 and the floating project/session panels occupy the
   * bounded band [90,110] (see LaunchDock's layering note). A page-level
   * slide-over would render *underneath* those. Callers there pass 112, which
   * clears the band while staying below the guided tour (z-120/130) and the
   * terminal's own context menu (z-200).
   */
  zIndex?: number;
  /** Applied to the scrolling body container. Defaults to "" - callers that
   * predate it supply their own padding. */
  bodyClassName?: string;
  /** Optional sticky bottom action row, rendered below the scroll area. */
  footer?: ReactNode;
}) {
  const panelRef = useRef<HTMLDivElement>(null);
  // `render` keeps the panel mounted through the exit transition; `shown`
  // drives the enter/exit transform + opacity.
  const [render, setRender] = useState(open);
  const [shown, setShown] = useState(false);

  // Mount / unmount lifecycle.
  useEffect(() => {
    if (open) {
      setRender(true);
      return;
    }
    setShown(false);
    const t = window.setTimeout(() => setRender(false), prefersReducedMotion() ? 0 : DUR.slow);
    return () => window.clearTimeout(t);
  }, [open]);

  // Open-transition concerns: slide in, focus the panel, lock scroll, and
  // remember what to hand focus back to. Keyed on `open` + `render` ALONE -
  // deliberately NOT on `onClose`. Pages pass `onClose` as an inline arrow and
  // many auto-poll (refreshMs), so re-including it would re-run this effect on
  // every poll and re-`focus()` the panel, stealing focus from whatever the
  // user is in (e.g. an embedded terminal launched from this panel - the
  // "terminal loses focus every few seconds" bug).
  useEffect(() => {
    if (!open || !render) return;
    const panel = panelRef.current;
    const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const unlock = lockScroll(panel);
    const id = requestAnimationFrame(() => {
      setShown(true);
      panel?.focus({ preventScroll: true });
    });
    return () => {
      cancelAnimationFrame(id);
      unlock();
      // Hand focus back only if it is still ours (inside the panel, or lost
      // to <body>); never yank it from something the user moved to.
      const active = document.activeElement;
      const ours = active === document.body || (panel != null && panel.contains(active));
      if (ours && opener && opener.isConnected && (panel == null || !panel.contains(opener))) {
        opener.focus({ preventScroll: true });
      }
    };
  }, [open, render]);

  // Escape-to-close needs the live `onClose`, so it keeps that dep. Adding/
  // removing a keydown listener on re-render is cheap and focus-neutral.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: globalThis.KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  // Focus trap. React events bubble through portals, so a Tab pressed in a
  // popover portalled out of this panel still arrives here: only act when
  // focus really is inside the panel. A nested slide-over wraps first and
  // marks the event handled (defaultPrevented), so the outer one stands down.
  // A terminal (xterm) inside the panel consumes Tab itself and stops it
  // propagating, so a shell's tab completion is unaffected.
  const onPanelKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key !== "Tab" || e.defaultPrevented) return;
    const panel = panelRef.current;
    const active = document.activeElement;
    if (!panel || !(active instanceof HTMLElement) || !(active === panel || panel.contains(active))) {
      return;
    }
    const items = focusableWithin(panel);
    if (items.length === 0) {
      e.preventDefault();
      return;
    }
    const target = trapTarget(items, active, e.shiftKey);
    if (target) {
      e.preventDefault();
      target.focus();
    }
  };

  if (!render) return null;

  return (
    <>
      <div
        aria-hidden
        onClick={onClose}
        // Tailwind's z-40/z-50 remain the default so the rendered class
        // list is unchanged for every existing caller; an explicit
        // zIndex overrides via inline style (which wins over the class).
        style={{
          transition: "opacity var(--dur) var(--ease-out)",
          ...(zIndex != null ? { zIndex } : null),
        }}
        className={clsx("fixed inset-0 z-40 bg-black/60", shown ? "opacity-100" : "opacity-0")}
      />
      <div
        ref={panelRef}
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        onKeyDown={onPanelKeyDown}
        style={{
          width,
          maxWidth: "96vw",
          transition: "transform var(--dur-slow) var(--ease-out)",
          ...(zIndex != null ? { zIndex: zIndex + 2 } : null),
        }}
        className={clsx(
          "fixed inset-y-0 right-0 z-50 flex flex-col border-l border-line-2 bg-bg-1 shadow-drawer focus:outline-none",
          shown ? "translate-x-0" : "translate-x-full",
        )}
      >
        <header className="flex items-start justify-between gap-3 border-b border-line-1 px-5 py-3">
          <div className="min-w-0">
            {/* `truncate` (overflow-hidden + nowrap + ellipsis) is right for a
                plain string title, but a composite ReactNode title (e.g. a
                ToolBadge + SurfaceBadge + IdChip row) needs to be able to wrap
                onto a second line at narrow widths instead of having its nowrap
                ancestor clip the last chip. */}
            <div
              className={clsx(
                "text-[14px] font-semibold text-fg-0",
                typeof title === "string" || typeof title === "number" ? "truncate" : "min-w-0",
              )}
            >
              {title}
            </div>
            {subtitle && (
              <div
                className={clsx(
                  "mt-0.5 text-[11.5px] text-fg-3",
                  typeof subtitle === "string" || typeof subtitle === "number"
                    ? "truncate"
                    : "min-w-0",
                )}
              >
                {subtitle}
              </div>
            )}
          </div>
          <Tooltip content={<>Close <kbd>Esc</kbd></>}>
            <button
              type="button"
              onClick={onClose}
              className="grid h-7 w-7 shrink-0 place-items-center rounded-2 border border-line-2 bg-bg-2 text-[14px] text-fg-2 hover:bg-bg-3 hover:text-fg-0"
              aria-label="Close"
            >
              <Icon icon={X} size="sm" />
            </button>
          </Tooltip>
        </header>
        <div className={clsx("min-h-0 flex-1 overflow-y-auto", bodyClassName)}>{children}</div>
        {footer && (
          <footer className="shrink-0 border-t border-line-1 bg-bg-1 px-5 py-3">{footer}</footer>
        )}
      </div>
    </>
  );
}
