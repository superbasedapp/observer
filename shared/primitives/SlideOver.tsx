import { useEffect, useRef, type ReactNode } from "react";
import { AnimatePresence, motion } from "framer-motion";
import clsx from "clsx";
import { Tooltip } from "./Tooltip";

// Right-side slide-over drawer with backdrop. Escape closes,
// focus moves into the panel on open, scroll lock on body while
// open. Phase 10: framer-motion replaces the prior CSS-translate
// approach so the panel unmounts cleanly on close and the slide
// uses spring physics.
//
// Width defaults to 880px; pages can pass a larger value, and
// SessionDetailPanel passes 1400. We clamp to min(width, 96vw) via
// max-width on the panel container so even on narrow viewports the
// panel stays inside the window (it'll just take ~all of the
// available width on a smaller screen).
export function SlideOver({
  open,
  onClose,
  title,
  subtitle,
  children,
  width = 880,
  zIndex,
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
   * workspace, which is itself an overlay stack — the expanded-terminal
   * backdrop sits at z-80 and the floating project/session panels occupy the
   * bounded band [90,110] (see LaunchDock's layering note). A page-level
   * slide-over would render *underneath* those. Callers there pass 112, which
   * clears the band while staying below the guided tour (z-120/130) and the
   * terminal's own context menu (z-200).
   */
  zIndex?: number;
}) {
  const panelRef = useRef<HTMLDivElement>(null);

  // Open-transition concerns: focus the panel and lock body scroll. Keyed on
  // `open` ALONE — deliberately NOT on `onClose`. Pages pass `onClose` as an
  // inline arrow and many auto-poll (refreshMs), so re-including it here would
  // re-run this effect on every poll and re-`focus()` the panel, stealing focus
  // from whatever the user is in (e.g. an embedded terminal launched from this
  // panel — the "terminal loses focus every few seconds" bug).
  useEffect(() => {
    if (!open) return;
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    panelRef.current?.focus();
    return () => {
      document.body.style.overflow = prevOverflow;
    };
  }, [open]);

  // Escape-to-close needs the live `onClose`, so it keeps that dep. Adding/
  // removing a keydown listener on re-render is cheap and focus-neutral.
  useEffect(() => {
    if (!open) return;
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  return (
    <AnimatePresence>
      {open && (
        <>
          <motion.div
            key="backdrop"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.18, ease: "easeOut" }}
            onClick={onClose}
            // Tailwind's z-40/z-50 remain the default so the rendered class
            // list is byte-identical for every existing caller; an explicit
            // zIndex overrides via inline style (which wins over the class).
            style={zIndex != null ? { zIndex } : undefined}
            className="fixed inset-0 z-40 bg-black/60"
          />
          <motion.div
            key="panel"
            ref={panelRef}
            tabIndex={-1}
            role="dialog"
            aria-modal="true"
            initial={{ x: "100%" }}
            animate={{ x: 0 }}
            exit={{ x: "100%" }}
            transition={{
              type: "spring",
              stiffness: 320,
              damping: 32,
              mass: 0.7,
            }}
            style={{
              width,
              maxWidth: "96vw",
              ...(zIndex != null ? { zIndex: zIndex + 2 } : null),
            }}
            className="fixed inset-y-0 right-0 z-50 flex flex-col border-l border-line-2 bg-bg-1 shadow-drawer focus:outline-none"
          >
            <header className="flex items-start justify-between gap-3 border-b border-line-1 px-5 py-3">
              <div className="min-w-0">
                {/* `truncate` (overflow-hidden + nowrap + ellipsis) is right for a
                    plain string title, but a composite ReactNode title (e.g. a
                    ToolBadge + SurfaceBadge + IdChip row) needs to be able to wrap
                    onto a second line at narrow widths instead of having its nowrap
                    ancestor clip the last chip. Shared with web2's mirror copy. */}
                <div
                  className={clsx(
                    "text-[14px] font-semibold text-fg-0",
                    typeof title === "string" || typeof title === "number"
                      ? "truncate"
                      : "min-w-0",
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
                  ×
                </button>
              </Tooltip>
            </header>
            <div className="min-h-0 flex-1 overflow-y-auto">{children}</div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
}
