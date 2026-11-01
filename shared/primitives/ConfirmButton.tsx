import { useCallback, useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import clsx from "clsx";
import type { LucideIcon } from "lucide-react";
import { Button, type ButtonSize, type ButtonVariant } from "./Button";
import { fieldClasses } from "./Input";

// ConfirmButton — the in-place two-step confirm. First click ARMS the
// button (its label becomes "Confirm?"), a second click within
// `timeoutMs` fires; otherwise it disarms itself.
//
// This exists so no app surface calls `window.confirm`: a native modal is
// unstyled, un-themed, blocks the whole page, and cannot say anything the
// surrounding UI does not already show. The pattern is the one the
// enrolment card proved.
//
// `reason` (Agent Access UI lane 0b): a destructive action that records a
// reason (retire, revoke, reject) asks for it INSIDE the armed step instead of
// an always-visible reason box on every row. While armed with a reason the
// control shows the reason field, the confirm button and Cancel, and does NOT
// auto-disarm (typing takes longer than the timeout); Escape or Cancel
// disarms, Enter in the field confirms. onConfirm receives the trimmed reason
// ("" when none was typed).

export type ConfirmReason = {
  /** Accessible name / placeholder of the field (default "Reason (optional)"). */
  label?: string;
  placeholder?: string;
  /** When true the confirm button stays disabled until a reason is typed. */
  required?: boolean;
  /** Max characters (default 200, the server's own audit-detail cap). */
  maxLength?: number;
};

export type ConfirmButtonProps = {
  /** Fires on the confirming click; carries the typed reason when `reason` is set. */
  onConfirm: (reason?: string) => void;
  /** Idle label. */
  children: ReactNode;
  /** Armed label. */
  confirmLabel?: ReactNode;
  /** Rendered beside the button while armed: what is about to happen. */
  armedNote?: ReactNode;
  /** false fires on the first click (the confirm step is conditional). */
  requireConfirm?: boolean;
  /** Auto-disarm delay (not applied while a reason field is shown). */
  timeoutMs?: number;
  variant?: ButtonVariant;
  armedVariant?: ButtonVariant;
  size?: ButtonSize;
  disabled?: boolean;
  loading?: boolean;
  title?: string;
  className?: string;
  /** Leading glyph (Trash2 for delete, Ban for revoke, ...); kept while armed. */
  iconLeft?: LucideIcon;
  /** Render a plain <button> styled only by the caller (`className` idle,
   *  `armedClassName` armed, defaulting to `className`), for a surface with
   *  its own theme (the terminal header). variant / size / iconLeft /
   *  loading / reason do not apply; put a glyph in `children` / `confirmLabel`. */
  unstyled?: boolean;
  /** Unstyled only: the class while armed (default: `className`). */
  armedClassName?: string;
  /** Unstyled only: the armed note's class (default: the muted 11px line). */
  armedNoteClassName?: string;
  /** Accessible name for the button, for an icon-only label. */
  ariaLabel?: string;
  /** Ask for a reason in the armed step (see the file header). */
  reason?: ConfirmReason;
  /** holdArmed keeps the armed step until the operator confirms, presses
   *  Cancel or Escape, or clicks elsewhere, instead of disarming after
   *  `timeoutMs`; the armed step shows a Cancel button (WINNODE item 7: a
   *  publish confirm that reverted after four seconds was easy to miss). */
  holdArmed?: boolean;
};

/** ArmedBehaviour is how an armed ConfirmButton ends. */
export type ArmedBehaviour = {
  /** Auto-disarm delay, or null when the armed step waits for the operator. */
  autoDisarmMs: number | null;
  /** A Cancel button is shown beside the armed button. */
  showCancel: boolean;
  /** A click outside the control disarms it. */
  disarmOnOutsideClick: boolean;
};

/** armedBehaviour is the one rule for how the armed step ends, by the
 *  control's own shape: a reason field or holdArmed waits for the operator,
 *  everything else disarms itself after timeoutMs. */
export function armedBehaviour(p: { withReason: boolean; holdArmed: boolean; timeoutMs: number }): ArmedBehaviour {
  if (p.withReason) return { autoDisarmMs: null, showCancel: true, disarmOnOutsideClick: false };
  if (p.holdArmed) return { autoDisarmMs: null, showCancel: true, disarmOnOutsideClick: true };
  return { autoDisarmMs: p.timeoutMs, showCancel: false, disarmOnOutsideClick: false };
}

export function ConfirmButton({
  onConfirm,
  children,
  confirmLabel = "Confirm?",
  armedNote,
  requireConfirm = true,
  timeoutMs = 4000,
  variant = "danger",
  armedVariant = "danger",
  size = "md",
  disabled,
  loading,
  title,
  className,
  iconLeft,
  unstyled,
  armedClassName,
  armedNoteClassName,
  ariaLabel,
  reason,
  holdArmed = false,
}: ConfirmButtonProps) {
  const [armed, setArmed] = useState(false);
  const [reasonText, setReasonText] = useState("");
  const timer = useRef<number | null>(null);
  const root = useRef<HTMLSpanElement | null>(null);
  const withReason = reason !== undefined && !unstyled && requireConfirm;
  const behaviour = armedBehaviour({ withReason, holdArmed: holdArmed && !unstyled, timeoutMs });

  const clear = useCallback(() => {
    if (timer.current !== null) {
      window.clearTimeout(timer.current);
      timer.current = null;
    }
  }, []);

  useEffect(() => clear, [clear]);

  const disarm = useCallback(() => {
    clear();
    setArmed(false);
    setReasonText("");
  }, [clear]);

  // A control that goes disabled (or stops needing a confirm) must not
  // stay armed behind the operator's back.
  useEffect(() => {
    if (disabled || loading || !requireConfirm) disarm();
  }, [disabled, loading, requireConfirm, disarm]);

  // holdArmed: a click anywhere outside the control, or Escape, disarms it.
  useEffect(() => {
    if (!armed || !behaviour.disarmOnOutsideClick) return;
    const onDown = (e: PointerEvent) => {
      if (root.current && e.target instanceof Node && !root.current.contains(e.target)) disarm();
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") disarm();
    };
    document.addEventListener("pointerdown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("pointerdown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [armed, behaviour.disarmOnOutsideClick, disarm]);

  function fire() {
    const typed = reasonText.trim();
    disarm();
    if (withReason) onConfirm(typed);
    else onConfirm();
  }

  function onClick() {
    if (!requireConfirm) {
      onConfirm();
      return;
    }
    if (armed) {
      if (withReason && reason?.required && reasonText.trim() === "") return;
      fire();
      return;
    }
    setArmed(true);
    clear();
    // No auto-disarm while a reason is being typed, or under holdArmed.
    if (behaviour.autoDisarmMs === null) return;
    timer.current = window.setTimeout(() => {
      timer.current = null;
      setArmed(false);
    }, behaviour.autoDisarmMs);
  }

  const showArmed = armed && requireConfirm;
  if (unstyled) {
    return (
      <span className="inline-flex flex-wrap items-center gap-2">
        <button
          type="button"
          disabled={disabled}
          title={title}
          aria-label={ariaLabel}
          className={showArmed ? (armedClassName ?? className) : className}
          onClick={onClick}
        >
          {showArmed ? confirmLabel : children}
        </button>
        {showArmed && armedNote !== undefined && (
          <span role="status" className={armedNoteClassName ?? "text-[11px] leading-snug text-fg-3"}>
            {armedNote}
          </span>
        )}
      </span>
    );
  }
  const reasonLabel = reason?.label ?? (reason?.required ? "Reason" : "Reason (optional)");
  const reasonMissing = withReason && showArmed && reason?.required === true && reasonText.trim() === "";
  return (
    <span ref={root} className="inline-flex flex-wrap items-center gap-2">
      {withReason && showArmed && (
        <input
          type="text"
          autoFocus
          aria-label={reasonLabel}
          placeholder={reason?.placeholder ?? reasonLabel}
          maxLength={reason?.maxLength ?? 200}
          value={reasonText}
          onChange={(e) => setReasonText(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Escape") {
              // Escape disarms only; marked handled so an enclosing
              // SlideOver / Modal stays open (shared/lib/overlayEscape.ts).
              e.preventDefault();
              e.stopPropagation();
              disarm();
            } else if (e.key === "Enter") {
              e.preventDefault();
              if (!reasonMissing) fire();
            }
          }}
          className={clsx(fieldClasses({ ownWidth: true }), "w-56 max-w-full")}
        />
      )}
      <Button
        variant={showArmed ? armedVariant : variant}
        size={size}
        disabled={disabled || reasonMissing}
        loading={loading}
        title={title}
        className={className}
        iconLeft={iconLeft}
        aria-label={ariaLabel}
        onClick={onClick}
      >
        {showArmed ? confirmLabel : children}
      </Button>
      {behaviour.showCancel && showArmed && (
        <Button variant="ghost" size={size} onClick={disarm}>
          Cancel
        </Button>
      )}
      {showArmed && armedNote !== undefined && (
        <span className="text-[11px] leading-snug text-fg-3">{armedNote}</span>
      )}
    </span>
  );
}
