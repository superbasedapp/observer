import clsx from "clsx";
import type { TextareaHTMLAttributes } from "react";
import { FieldShell, fieldClasses, hasFieldNote, useFieldIds, type FieldChromeProps } from "./Input";
import { callerSetsWidth } from "../lib/fieldWidth";

export type TextareaProps = Omit<
  TextareaHTMLAttributes<HTMLTextAreaElement>,
  "className"
> &
  FieldChromeProps;

export function Textarea({
  label,
  help,
  error,
  mono,
  className,
  ...rest
}: TextareaProps) {
  const { controlId, noteId } = useFieldIds(rest.id);
  const described = hasFieldNote(help, error) ? noteId : undefined;
  return (
    <FieldShell label={label} help={help} error={error} controlId={controlId} noteId={noteId}>
      <textarea
        {...rest}
        id={controlId}
        aria-describedby={rest["aria-describedby"] ?? described}
        className={clsx(
          fieldClasses({ mono, invalid: Boolean(error), ownWidth: callerSetsWidth(className) }),
          "resize-y",
          className,
        )}
      />
    </FieldShell>
  );
}
