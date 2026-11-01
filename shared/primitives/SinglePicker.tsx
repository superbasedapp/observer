import type { ReactNode } from "react";
import { EntityMultiPicker, type EntityMultiPickerOption } from "./EntityMultiPicker";

// SinglePicker picks ONE value from a known list (lane PICKERS, D-571: a
// known set is picked, never typed). It is EntityMultiPicker in `single`
// mode behind a plain `value: string` / `onChange(string)` API, so a form
// that held a free-text <Input> swaps one control without reshaping its
// state. Options may be plain strings (label = id) or full picker options
// (label, sublabel, group, disabledReason).
//
// `allowFree` keeps the honest escape hatch for a field whose list is only
// a suggestion (a model glob, a new label, a list the server could not
// send): the typed value is offered as "Use <value>". Without it the user
// can only pick. Clearing the chip sets ""; `clearable={false}` is for a
// value that must always be set (no clear, the pick can only be replaced).
export function SinglePicker({
  value,
  onChange,
  options,
  allowFree = false,
  freeLabel = "Use",
  placeholder = "Pick one…",
  disabled,
  loading,
  notice,
  emptyHint,
  ariaLabel,
  className,
  hideIds,
  clearable,
  explicitPick,
  onQueryChange,
}: {
  value: string;
  onChange: (next: string) => void;
  options: readonly (string | EntityMultiPickerOption)[];
  allowFree?: boolean;
  freeLabel?: string;
  placeholder?: string;
  disabled?: boolean;
  loading?: boolean;
  notice?: ReactNode;
  emptyHint?: ReactNode;
  ariaLabel?: string;
  className?: string;
  /** hideIds: see EntityMultiPicker (ids that are internal names stay hidden). */
  hideIds?: boolean;
  /** clearable: see EntityMultiPicker (false: always has a value). */
  clearable?: boolean;
  /** explicitPick: see EntityMultiPicker (Enter never commits an untouched suggestion). */
  explicitPick?: boolean;
  /** onQueryChange: see EntityMultiPicker (the typed text, on every change). */
  onQueryChange?: (query: string) => void;
}) {
  const opts = toPickerOptions(options);
  return (
    <EntityMultiPicker
      single
      options={opts}
      value={value ? [value] : []}
      onChange={(next) => onChange(next[0] ?? "")}
      allowFreeId={allowFree}
      freeIdLabel={freeLabel}
      placeholder={placeholder}
      disabled={disabled}
      loading={loading}
      notice={notice}
      emptyHint={emptyHint}
      ariaLabel={ariaLabel}
      className={className}
      hideIds={hideIds}
      clearable={clearable}
      explicitPick={explicitPick}
      onQueryChange={onQueryChange}
    />
  );
}

/** toPickerOptions turns plain strings into picker options (label = id),
 *  drops empties and keeps the first of any duplicate id. */
export function toPickerOptions(options: readonly (string | EntityMultiPickerOption)[]): EntityMultiPickerOption[] {
  const seen = new Set<string>();
  const out: EntityMultiPickerOption[] = [];
  for (const o of options) {
    const opt = typeof o === "string" ? { id: o, label: o } : o;
    if (!opt.id || seen.has(opt.id)) continue;
    seen.add(opt.id);
    out.push(opt);
  }
  return out;
}
