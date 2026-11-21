import { useState } from "react";
import { EntityMultiPicker, Select } from "@/components/primitives";
import { effectiveChoice, valueForChoice, type ListChoice } from "@/lib/guardSettingsExtras";

/** Three-way editor for a list whose Go field separates nil (engine defaults)
 *  from empty (none): sends null, the list, or []. */
export function NullableListInput({
  value,
  onChange,
  defaultsLabel,
  noneLabel,
  disabled,
  ariaLabel,
}: {
  value: unknown;
  onChange: (v: string[] | null) => void;
  defaultsLabel: string;
  noneLabel: string;
  disabled?: boolean;
  ariaLabel: string;
}) {
  // "Custom list" picked before any entry is typed: the value is still [],
  // which must not snap to None.
  const [customPending, setCustomPending] = useState(false);
  const choice = effectiveChoice(value, customPending);
  const arr = Array.isArray(value) ? value.map(String) : [];
  return (
    <div className="space-y-2">
      <Select
        mono
        disabled={disabled}
        aria-label={ariaLabel}
        options={[
          { value: "defaults", label: defaultsLabel },
          { value: "custom", label: "Custom list" },
          { value: "none", label: noneLabel },
        ]}
        value={choice}
        onChange={(e) => {
          const next = e.target.value as ListChoice;
          setCustomPending(next === "custom");
          onChange(valueForChoice(next, value));
        }}
      />
      {choice === "custom" && (
        <FreeListInput value={arr} onChange={onChange} disabled={disabled} ariaLabel={`${ariaLabel} entries`} />
      )}
    </div>
  );
}

/** FreeListInput edits a list of free values: type one, press Enter, and it
 *  becomes a chip with its own remove. It replaces a comma-separated text box,
 *  whose controlled value dropped a typed comma before the next entry could
 *  follow it. */
export function FreeListInput({
  value,
  onChange,
  disabled,
  ariaLabel,
}: {
  value: string[];
  onChange: (v: string[]) => void;
  disabled?: boolean;
  ariaLabel: string;
}) {
  return (
    <EntityMultiPicker
      options={value.map((id) => ({ id, label: id }))}
      value={value}
      onChange={(next) => onChange(next.map((s) => s.trim()).filter(Boolean))}
      disabled={disabled}
      allowFreeId
      freeIdLabel="Add"
      emptyHint="Type a value and press Enter."
      placeholder="Type a value and press Enter…"
      ariaLabel={ariaLabel}
    />
  );
}
