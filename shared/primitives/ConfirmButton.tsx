import { useCallback, useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import { Button, type ButtonSize, type ButtonVariant } from "./Button";

// ConfirmButton — the in-place two-step confirm. First click ARMS the
// button (its label becomes "Confirm?"), a second click within
// `timeoutMs` fires; otherwise it disarms itself.
//
// This exists so no app surface calls `window.confirm`: a native modal is
// unstyled, un-themed, blocks the whole page, and cannot say anything the
// surrounding UI does not already show. The pattern is the one the
// enrolment card proved.

export type ConfirmButtonProps = {
  onConfirm: () => void;
  /** Idle label. */
  children: ReactNode;
  /** Armed label. */
  confirmLabel?: ReactNode;
  /** Rendered beside the button while armed: what is about to happen. */
  armedNote?: ReactNode;
  /** false fires on the first click (the confirm step is conditional). */
  requireConfirm?: boolean;
  /** Auto-disarm delay. */
  timeoutMs?: number;
  variant?: ButtonVariant;
  armedVariant?: ButtonVariant;
  size?: ButtonSize;
  disabled?: boolean;
  loading?: boolean;
  title?: string;
  className?: string;
};

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
}: ConfirmButtonProps) {
  const [armed, setArmed] = useState(false);
  const timer = useRef<number | null>(null);

  const clear = useCallback(() => {
    if (timer.current !== null) {
      window.clearTimeout(timer.current);
      timer.current = null;
    }
  }, []);

  useEffect(() => clear, [clear]);

  // A control that goes disabled (or stops needing a confirm) must not
  // stay armed behind the operator's back.
  useEffect(() => {
    if (disabled || loading || !requireConfirm) {
      clear();
      setArmed(false);
    }
  }, [disabled, loading, requireConfirm, clear]);

  function onClick() {
    if (!requireConfirm) {
      onConfirm();
      return;
    }
    if (armed) {
      clear();
      setArmed(false);
      onConfirm();
      return;
    }
    setArmed(true);
    clear();
    timer.current = window.setTimeout(() => {
      timer.current = null;
      setArmed(false);
    }, timeoutMs);
  }

  const showArmed = armed && requireConfirm;
  return (
    <span className="inline-flex flex-wrap items-center gap-2">
      <Button
        variant={showArmed ? armedVariant : variant}
        size={size}
        disabled={disabled}
        loading={loading}
        title={title}
        className={className}
        onClick={onClick}
      >
        {showArmed ? confirmLabel : children}
      </Button>
      {showArmed && armedNote !== undefined && (
        <span className="text-[11px] leading-snug text-fg-3">{armedNote}</span>
      )}
    </span>
  );
}
