import clsx from "clsx";
import type { InputHTMLAttributes, ReactNode } from "react";

// Input / Select / Textarea share one chrome so a form never drifts field
// by field. The class string is the one the Settings forms already used,
// lifted verbatim; the only addition is a focus ring and an explicit
// disabled fill (`bg-bg-3`) instead of a bare opacity fade, because a
// faded white field on a white light-theme card reads as editable.

/** fieldClasses is the shared control chrome. Exported for the handful of
 *  places that must style a native control directly. */
export function fieldClasses(opts?: { mono?: boolean; invalid?: boolean }): string {
  return clsx(
    "w-full rounded-2 border bg-bg-2 px-2.5 py-1.5 text-[12px] text-fg-1 placeholder:text-fg-4 focus:outline-none disabled:cursor-not-allowed disabled:bg-bg-3 disabled:text-fg-3",
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

/** FieldShell wraps a control with its optional label / help / error. */
export function FieldShell({
  label,
  help,
  error,
  children,
}: {
  label?: ReactNode;
  help?: ReactNode;
  error?: ReactNode;
  children: ReactNode;
}) {
  if (label === undefined && help === undefined && error === undefined) {
    return <>{children}</>;
  }
  return (
    <div className="space-y-1">
      {label !== undefined && (
        <div className="text-[10.5px] font-semibold uppercase tracking-[0.06em] text-fg-3">
          {label}
        </div>
      )}
      {children}
      {error !== undefined && error !== null && error !== "" ? (
        <div className="text-[11px] leading-snug text-danger">{error}</div>
      ) : (
        help !== undefined && (
          <div className="text-[11px] leading-snug text-fg-3">{help}</div>
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
  return (
    <FieldShell label={label} help={help} error={error}>
      <input
        {...rest}
        className={clsx(
          fieldClasses({ mono, invalid: Boolean(error) }),
          className,
        )}
      />
    </FieldShell>
  );
}
