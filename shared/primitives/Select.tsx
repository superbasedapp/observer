import clsx from "clsx";
import type { ReactNode, SelectHTMLAttributes } from "react";
import { FieldShell, fieldClasses, type FieldChromeProps } from "./Input";

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
  return (
    <FieldShell label={label} help={help} error={error}>
      <select
        {...rest}
        className={clsx(
          fieldClasses({ mono, invalid: Boolean(error) }),
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
