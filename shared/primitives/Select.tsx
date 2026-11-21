import clsx from "clsx";
import type { ReactNode, SelectHTMLAttributes } from "react";
import { FieldShell, fieldClasses, hasFieldNote, useFieldIds, type FieldChromeProps } from "./Input";
import { callerSetsWidth } from "../lib/fieldWidth";

export type SelectOption = {
  value: string;
  label?: ReactNode;
  disabled?: boolean;
};

export type SelectProps = Omit<
  SelectHTMLAttributes<HTMLSelectElement>,
  "className" | "children"
> &
  FieldChromeProps & {
    /** Convenience list; plain strings become value === label. */
    options?: (string | SelectOption)[];
    /** Escape hatch for grouped / custom option markup. */
    children?: ReactNode;
  };

export function Select({
  label,
  help,
  error,
  mono,
  className,
  options,
  children,
  ...rest
}: SelectProps) {
  const { controlId, noteId } = useFieldIds(rest.id);
  const described = hasFieldNote(help, error) ? noteId : undefined;
  return (
    <FieldShell label={label} help={help} error={error} controlId={controlId} noteId={noteId}>
      <select
        {...rest}
        id={controlId}
        aria-describedby={rest["aria-describedby"] ?? described}
        className={clsx(
          fieldClasses({ mono, invalid: Boolean(error), ownWidth: callerSetsWidth(className) }),
          className,
        )}
      >
        {children ??
          (options ?? []).map((o) => {
            const opt: SelectOption = typeof o === "string" ? { value: o } : o;
            // Only a bare string shorthand ("") gets the synthesized
            // "(default)" label — a caller that passed an explicit
            // `{ value: "", label: ... }` (including an intentionally
            // empty/falsy label like "" or "(any)") is never overridden.
            const optLabel =
              typeof o === "string"
                ? o === ""
                  ? "(default)"
                  : o
                : (opt.label ?? opt.value);
            return (
              <option key={opt.value} value={opt.value} disabled={opt.disabled}>
                {optLabel}
              </option>
            );
          })}
      </select>
    </FieldShell>
  );
}
