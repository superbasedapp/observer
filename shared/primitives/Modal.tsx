import { useEffect, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import clsx from "clsx";
import { X, type LucideIcon } from "lucide-react";
import { Icon } from "./Icon";
import { DUR, prefersReducedMotion } from "../lib/motion";
import { focusableWithin, trapTarget } from "../lib/focusTrap";
import { lockScroll } from "../lib/scrollLock";

// Modal: the one centred dialog for every app (SlideOver's sibling; the
// hand-rolled `fixed inset-0` dialogs folded into it). Same contract as
// SlideOver: Escape and the backdrop close (unless `dismissible` is false,
// e.g. while a submit is in flight), focus moves in on open, Tab wraps
// inside, focus returns to the opener, and the page behind stops scrolling.
// Motion is CSS-owned: the scrim fades and the card scales in from 96%
// (tokens, so reduced motion collapses it); the dialog stays mounted through
// the exit transition, then unmounts.
export function Modal({
  open,
  onClose,
  title,
  subtitle,
  icon,
  children,
  footer,
  width = 520,
  zIndex = 60,
  dismissible = true,
  labelledBy,
  bodyClassName = "px-5 py-4",
  className,
}: {
  open: boolean;
  onClose: () => void;
  /** Header title; omit to render a bare card (then pass `labelledBy`). */
  title?: ReactNode;
  subtitle?: ReactNode;
  icon?: LucideIcon;
  children: ReactNode;
  /** Action row under the body (buttons right-aligned by the caller). */
  footer?: ReactNode;
  width?: number;
  /** Stacking level for the scrim; the card sits one above it. */
  zIndex?: number;
  /** false: Escape / backdrop / the close button do nothing. */
  dismissible?: boolean;
  /** id of an element that names the dialog when there is no `title`. */
  labelledBy?: string;
  bodyClassName?: string;
  className?: string;
}) {
  const cardRef = useRef<HTMLDivElement>(null);
  const titleId = useRef(`sb-modal-${Math.random().toString(36).slice(2, 9)}`).current;
  const [render, setRender] = useState(open);
  const [shown, setShown] = useState(false);

  useEffect(() => {
    if (open) {
      setRender(true);
      return;
    }
    setShown(false);
    const t = window.setTimeout(() => setRender(false), prefersReducedMotion() ? 0 : DUR.slow);
    return () => window.clearTimeout(t);
  }, [open]);

  // Keyed on open + render only (not onClose), for the same reason as
  // SlideOver: an inline onClose re-created by a poll must not re-focus.
  useEffect(() => {
    if (!open || !render) return;
    const card = cardRef.current;
    const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const unlock = lockScroll(card);
    const id = requestAnimationFrame(() => {
      setShown(true);
      const first = card ? focusableWithin(card)[0] : undefined;
      (first ?? card)?.focus({ preventScroll: true });
    });
    return () => {
      cancelAnimationFrame(id);
      unlock();
      const active = document.activeElement;
      const ours = active === document.body || (card != null && card.contains(active));
      if (ours && opener && opener.isConnected && (card == null || !card.contains(opener))) {
        opener.focus({ preventScroll: true });
      }
    };
  }, [open, render]);

  useEffect(() => {
    if (!open || !dismissible) return;
    const onKey = (e: globalThis.KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, dismissible, onClose]);

  const onCardKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key !== "Tab" || e.defaultPrevented) return;
    const card = cardRef.current;
    const active = document.activeElement;
    if (!card || !(active instanceof HTMLElement) || !(active === card || card.contains(active))) return;
    const items = focusableWithin(card);
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
    <div className="fixed inset-0 grid place-items-center p-4 sm:p-6" style={{ zIndex }}>
      <div
        aria-hidden
        onClick={dismissible ? onClose : undefined}
        style={{ transition: "opacity var(--dur) var(--ease-out)" }}
        className={clsx("absolute inset-0 bg-black/60", shown ? "opacity-100" : "opacity-0")}
      />
      <div
        ref={cardRef}
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        aria-labelledby={title != null ? titleId : labelledBy}
        onKeyDown={onCardKeyDown}
        style={{
          width,
          maxWidth: "100%",
          transition: "opacity var(--dur) var(--ease-out), transform var(--dur-slow) var(--ease-out)",
        }}
        className={clsx(
          "relative flex max-h-[calc(100vh-2rem)] flex-col overflow-hidden rounded-4 border border-line-2 bg-bg-1 shadow-drawer focus:outline-none",
          shown ? "scale-100 opacity-100" : "scale-[0.96] opacity-0",
          className,
        )}
      >
        {title != null && (
          <header className="flex items-start justify-between gap-3 border-b border-line-1 px-5 py-3">
            <div className="flex min-w-0 items-start gap-2">
              {icon && <Icon icon={icon} size="md" className="mt-0.5 shrink-0 text-fg-3" />}
              <div className="min-w-0">
                <h2 id={titleId} className="text-[14px] font-semibold text-fg-0">
                  {title}
                </h2>
                {subtitle && <div className="mt-0.5 text-[11.5px] text-fg-3">{subtitle}</div>}
              </div>
            </div>
            {dismissible && (
              <button
                type="button"
                onClick={onClose}
                aria-label="Close"
                className="grid h-7 w-7 shrink-0 place-items-center rounded-2 border border-line-2 bg-bg-2 text-fg-2 hover:bg-bg-3 hover:text-fg-0 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent-ring"
              >
                <Icon icon={X} size="sm" />
              </button>
            )}
          </header>
        )}
        <div className={clsx("min-h-0 flex-1 overflow-y-auto", bodyClassName)}>{children}</div>
        {footer && (
          <footer className="flex shrink-0 flex-wrap items-center justify-end gap-2 border-t border-line-1 px-5 py-3">
            {footer}
          </footer>
        )}
      </div>
    </div>
  );
}
