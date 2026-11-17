import { useCallback, useEffect, useId, useRef, useState } from "react";
import type { CSSProperties, ReactNode, Ref } from "react";
import clsx from "clsx";
import { autoUpdate, flip, FloatingPortal, offset, shift, useFloating } from "@floating-ui/react";
import type { LucideIcon } from "lucide-react";
import { Button, type ButtonSize, type ButtonVariant } from "./Button";
import { fieldClasses } from "./Input";
import {
  ARMED_CLASSES,
  ARMED_DEFAULT_NOTE,
  ARMED_NOTE_FLOAT,
  armedBehaviour,
  armedFlow,
  armedNotePlacement,
  confirmClick,
  type ArmedNoteSide,
} from "./confirmButtonModel";

export { armedBehaviour, type ArmedBehaviour } from "./confirmButtonModel";

// ConfirmButton — the in-place two-step confirm. First click ARMS the
// button (its label becomes "Confirm?", ringed so it reads as armed), a
// second click fires. The armed step waits: it does not revert on its own
// (an opt-in `timeoutMs` still can); a click elsewhere or Escape cancels.
//
// This exists so no app surface calls `window.confirm`: a native modal is
// unstyled, un-themed, blocks the whole page, and cannot say anything the
// surrounding UI does not already show. The pattern is the one the
// enrolment card proved.
//
// The armed note FLOATS under the button (portalled, position: fixed; see
// confirmButtonModel.ts ARMED_NOTE_FLOAT) instead of sitting beside it in the
// control's row, so arming never moves the button: the second click lands on
// the armed button wherever the control sits (a right-aligned table cell, a
// narrow card). The button is described by the note (aria-describedby) and
// the note is a status region, so the armed step is still announced.
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
  /** Shown under the button while armed (floating, never in the button's
   *  row, so it cannot move the button): what is about to happen. */
  armedNote?: ReactNode;
  /** Which side the armed note floats on (default "bottom"); "top" for a
   *  note that refers to content right under the control. */
  armedNoteSide?: ArmedNoteSide;
  /** false fires on the first click (the confirm step is conditional). */
  requireConfirm?: boolean;
  /** Opt-in auto-disarm delay. Unset (the default) the armed step waits
   *  until the second click, a click elsewhere or Escape; it never reverts
   *  silently. Not applied while a reason field is shown. */
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
  /** Unstyled only: the armed note's text class (default: the muted 11px
   *  line). The floating surface around it is the shared one. */
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

export function ConfirmButton(props: ConfirmButtonProps) {
  const {
    onConfirm,
    armedNote,
    armedNoteSide,
    requireConfirm = true,
    timeoutMs,
    disabled,
    loading,
    unstyled,
    armedNoteClassName,
    reason,
    holdArmed = false,
  } = props;
  const [armed, setArmed] = useState(false);
  const [reasonText, setReasonText] = useState("");
  const timer = useRef<number | null>(null);
  const root = useRef<HTMLSpanElement | null>(null);
  const noteId = useId();
  const withReason = reason !== undefined && !unstyled && requireConfirm;
  const behaviour = armedBehaviour({ withReason, holdArmed: holdArmed && !unstyled, timeoutMs });
  const showArmed = armed && requireConfirm;
  // A waiting armed step (no timeout) always says how to cancel; a caller's
  // own note wins.
  const note: ReactNode = armedNote !== undefined ? armedNote : behaviour.autoDisarmMs === null && !withReason ? ARMED_DEFAULT_NOTE : undefined;
  const showNote = showArmed && note !== undefined;
  const reasonMissing = withReason && showArmed && reason?.required === true && reasonText.trim() === "";

  const { refs, floatingStyles } = useFloating({
    open: showNote,
    strategy: ARMED_NOTE_FLOAT.strategy,
    placement: armedNotePlacement(armedNoteSide),
    middleware: [
      offset(ARMED_NOTE_FLOAT.offsetPx),
      flip({ padding: ARMED_NOTE_FLOAT.viewportPaddingPx }),
      shift({ padding: ARMED_NOTE_FLOAT.viewportPaddingPx }),
    ],
    whileElementsMounted: autoUpdate,
  });

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
  // The floating note counts as inside (it is portalled out of the control).
  useEffect(() => {
    if (!armed || !behaviour.disarmOnOutsideClick) return;
    const onDown = (e: PointerEvent) => {
      if (!(e.target instanceof Node)) return;
      const note = refs.floating.current;
      const inside = (root.current?.contains(e.target) ?? false) || (note?.contains(e.target) ?? false);
      if (!inside) disarm();
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
  }, [armed, behaviour.disarmOnOutsideClick, disarm, refs.floating]);

  function fire() {
    const typed = reasonText.trim();
    disarm();
    if (withReason) onConfirm(typed);
    else onConfirm();
  }

  function onClick() {
    const step = confirmClick({ requireConfirm, armed, reasonMissing });
    if (step === "hold") return;
    if (step === "fire") {
      if (requireConfirm) fire();
      else onConfirm();
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

  return (
    <>
      <ConfirmButtonView
        {...props}
        armed={showArmed}
        withReason={withReason}
        showCancel={behaviour.showCancel}
        reasonMissing={reasonMissing}
        reasonText={reasonText}
        noteId={showNote ? noteId : undefined}
        onReasonText={setReasonText}
        onClick={onClick}
        onCancel={disarm}
        onFire={fire}
        rootRef={root}
        buttonRef={refs.setReference}
      />
      {showNote && (
        <ArmedNote
          id={noteId}
          setFloating={refs.setFloating}
          style={floatingStyles}
          textClassName={unstyled ? armedNoteClassName : undefined}
        >
          {note}
        </ArmedNote>
      )}
    </>
  );
}

/** ConfirmButtonViewProps is the stateless body's input: the public props
 *  plus the armed state ConfirmButton owns. */
export type ConfirmButtonViewProps = ConfirmButtonProps & {
  armed: boolean;
  withReason: boolean;
  showCancel: boolean;
  reasonMissing: boolean;
  reasonText: string;
  /** The armed note's id while it is shown (the button is described by it). */
  noteId?: string;
  onReasonText: (v: string) => void;
  onClick: () => void;
  onCancel: () => void;
  onFire: () => void;
  rootRef?: Ref<HTMLSpanElement>;
  buttonRef?: (el: Element | null) => void;
};

/** ConfirmButtonView is ConfirmButton's in-flow row, without state: exactly
 *  the parts armedFlow lists (reason field, button, Cancel) and never the
 *  armed note, which ConfirmButton floats. Exported for render tests. */
export function ConfirmButtonView({
  children,
  confirmLabel = "Confirm?",
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
  ariaLabel,
  reason,
  armed,
  withReason,
  showCancel,
  reasonMissing,
  reasonText,
  noteId,
  onReasonText,
  onClick,
  onCancel,
  onFire,
  rootRef,
  buttonRef,
}: ConfirmButtonViewProps) {
  const reasonLabel = reason?.label ?? (reason?.required ? "Reason" : "Reason (optional)");
  const parts = armedFlow({ armed, withReason, showCancel });
  const button = unstyled ? (
    <button
      key="button"
      ref={buttonRef}
      type="button"
      disabled={disabled}
      title={title}
      aria-label={ariaLabel}
      aria-describedby={noteId}
      className={armed ? (armedClassName ?? className) : className}
      onClick={onClick}
    >
      {armed ? confirmLabel : children}
    </button>
  ) : (
    <Button
      key="button"
      ref={buttonRef}
      variant={armed ? armedVariant : variant}
      size={size}
      disabled={disabled || reasonMissing}
      loading={loading}
      title={title}
      className={clsx(className, armed && ARMED_CLASSES)}
      iconLeft={iconLeft}
      aria-label={ariaLabel}
      aria-describedby={noteId}
      onClick={onClick}
    >
      {armed ? confirmLabel : children}
    </Button>
  );
  return (
    <span ref={rootRef} className="inline-flex flex-wrap items-center gap-2">
      {parts.map((part) => {
        if (part === "button") return button;
        if (part === "cancel") {
          return (
            <Button key="cancel" variant="ghost" size={size} onClick={onCancel}>
              Cancel
            </Button>
          );
        }
        return (
          <input
            key="reason"
            type="text"
            autoFocus
            aria-label={reasonLabel}
            placeholder={reason?.placeholder ?? reasonLabel}
            maxLength={reason?.maxLength ?? 200}
            value={reasonText}
            onChange={(e) => onReasonText(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Escape") {
                // Escape disarms only; marked handled so an enclosing
                // SlideOver / Modal stays open (shared/lib/overlayEscape.ts).
                e.preventDefault();
                e.stopPropagation();
                onCancel();
              } else if (e.key === "Enter") {
                e.preventDefault();
                if (!reasonMissing) onFire();
              }
            }}
            className={clsx(fieldClasses({ ownWidth: true }), "w-56 max-w-full")}
          />
        );
      })}
    </span>
  );
}

// ArmedNote is the floating note: portalled to the body and fixed-positioned
// by floating-ui, so it takes no space in the control's row and no clipping
// ancestor (an overflow-x-auto table, a narrow card) can hide or reflow it.
function ArmedNote({
  id,
  setFloating,
  style,
  textClassName,
  children,
}: {
  id: string;
  setFloating: (el: HTMLElement | null) => void;
  style: CSSProperties;
  textClassName?: string;
  children: ReactNode;
}) {
  const pad = ARMED_NOTE_FLOAT.viewportPaddingPx;
  return (
    <FloatingPortal>
      <div ref={setFloating} style={{ ...style, zIndex: ARMED_NOTE_FLOAT.zIndex }}>
        <div
          id={id}
          role="status"
          className="w-max rounded-md border border-line-3 bg-bg-3 px-2.5 py-1.5 shadow-[var(--shadow-2)]"
          style={{ maxWidth: `min(${ARMED_NOTE_FLOAT.maxWidthPx}px, calc(100vw - ${2 * pad}px))` }}
        >
          <div className={textClassName ?? "text-[11px] leading-snug text-fg-2"}>{children}</div>
        </div>
      </div>
    </FloatingPortal>
  );
}
