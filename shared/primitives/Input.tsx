import clsx from "clsx";
import { useId, type InputHTMLAttributes, type ReactNode } from "react";
import { callerSetsWidth } from "../lib/fieldWidth";

// Input / Select / Textarea share one chrome so a form never drifts field
// by field. The class string is the one the Settings forms already used,
// lifted verbatim; the only addition is a focus ring and an explicit
// disabled fill (`bg-bg-3`) instead of a bare opacity fade, because a
// faded white field on a white light-theme card reads as editable.

/** fieldClasses is the shared control chrome. Exported for the handful of
 *  places that must style a native control directly. `ownWidth` drops the
 *  default `w-full` (the caller sets a width; see lib/fieldWidth.ts). */
export function fieldClasses(opts?: { mono?: boolean; invalid?: boolean; ownWidth?: boolean }): string {
  return clsx(
    !opts?.ownWidth && "w-full",
    "rounded-2 border bg-bg-2 px-2.5 py-1.5 text-[12px] text-fg-1 placeholder:text-fg-4 focus:outline-none disabled:cursor-not-allowed disabled:bg-bg-3 disabled:text-fg-3",
    opts?.mono && "font-mono",
    opts?.invalid
      ? "border-danger/60 focus:border-danger"
      : "border-line-2 focus:border-accent",
  );
}

export type FieldChromeProps = {
  /** Optional label rendered above the control. */
  label?: ReactNode;
  /** Optional help text rendered below the control. */
  help?: ReactNode;
  /** Optional error text rendered below the control; also tints the border. */
  error?: ReactNode;
  /** Monospace value text (paths, keys, TOML values). */
  mono?: boolean;
  className?: string;
};

/** useFieldIds names a field control and its note so FieldShell can tie
 *  them together: the control keeps a caller-given id, else gets a generated
 *  one; `noteId` is the help / error line the control is described by. */
export function useFieldIds(id: string | undefined): { controlId: string; noteId: string } {
  const gen = useId();
  const controlId = id ?? `field-${gen}`;
  return { controlId, noteId: `${controlId}-note` };
}

/** hasFieldNote is true when FieldShell renders a help or error line. */
export function hasFieldNote(help: ReactNode, error: ReactNode): boolean {
  return (error !== undefined && error !== null && error !== "") || help !== undefined;
}

/** FieldShell wraps a control with its optional label / help / error. With
 *  `controlId` the label is a real <label for> (so the control has an
 *  accessible name and a label click focuses it) and the note carries
 *  `noteId` for the control's aria-describedby. */
export function FieldShell({
  label,
  help,
  error,
  controlId,
  noteId,
  children,
}: {
  label?: ReactNode;
  help?: ReactNode;
  error?: ReactNode;
  controlId?: string;
  noteId?: string;
  children: ReactNode;
}) {
  if (label === undefined && help === undefined && error === undefined) {
    return <>{children}</>;
  }
  return (
    <div className="space-y-1">
      {label !== undefined &&
        (controlId ? (
          <label htmlFor={controlId} className="block text-xs font-medium text-fg-2">
            {label}
          </label>
        ) : (
          <div className="text-xs font-medium text-fg-2">{label}</div>
        ))}
      {children}
      {error !== undefined && error !== null && error !== "" ? (
        <div id={noteId} className="text-[11px] leading-snug text-danger">{error}</div>
      ) : (
        help !== undefined && (
          <div id={noteId} className="text-[11px] leading-snug text-fg-3">{help}</div>
        )
      )}
    </div>
  );
}

export type InputProps = Omit<
  InputHTMLAttributes<HTMLInputElement>,
  "className"
> &
  FieldChromeProps;

export function Input({
  label,
  help,
  error,
  mono,
  className,
  ...rest
}: InputProps) {
  const { controlId, noteId } = useFieldIds(rest.id);
  const described = hasFieldNote(help, error) ? noteId : undefined;
  return (
    <FieldShell label={label} help={help} error={error} controlId={controlId} noteId={noteId}>
      <input
        {...rest}
        id={controlId}
        aria-describedby={rest["aria-describedby"] ?? described}
        className={clsx(
          fieldClasses({ mono, invalid: Boolean(error), ownWidth: callerSetsWidth(className) }),
          className,
        )}
      />
    </FieldShell>
  );
}
