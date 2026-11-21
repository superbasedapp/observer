import { useState } from "react";
import { Button, Select, SettingRow } from "@/components/primitives";
import {
  PROMPT_DETECTOR_MODES,
  addPickerOptions,
  asOverrides,
  extraOverrideIds,
  type DetectorInfo,
} from "@/lib/guardSettingsExtras";

/** Overrides beyond the fixed detector fields: every override already in the
 *  draft (so one set in config.toml shows), each with a mode control and a
 *  Remove, plus an "Add an override for another detector" picker over the
 *  server's full detector vocabulary. Edits go through the section draft. */
export function DetectorOverrideExtras({
  overrides: raw,
  fixedIds,
  detectors,
  effectiveModes,
  disabled,
  onSet,
  onRemove,
}: {
  overrides: unknown;
  fixedIds: string[];
  detectors: DetectorInfo[];
  effectiveModes: Record<string, string>;
  disabled?: boolean;
  onSet: (id: string, mode: string) => void;
  onRemove: (id: string) => void;
}) {
  const overrides = asOverrides(raw);
  const extras = extraOverrideIds(overrides, fixedIds);
  const options = addPickerOptions(detectors, fixedIds, overrides);
  const [pick, setPick] = useState("");
  const picked = options.find((o) => o.id === pick);
  const classOf = (id: string) => detectors.find((d) => d.id === id)?.class;

  return (
    <div className="space-y-3 border-t border-line-1 pt-3">
      {extras.map((id) => {
        const eff = effectiveModes[id];
        const cls = classOf(id);
        return (
          <SettingRow key={id} label={id} help={cls ? `Class: ${cls}` : undefined}>
            <div className="flex flex-wrap items-center gap-2">
              <Select
                mono
                disabled={disabled}
                options={[...PROMPT_DETECTOR_MODES]}
                value={overrides[id]}
                onChange={(e) => onSet(id, e.target.value)}
              />
              <Button disabled={disabled} onClick={() => onRemove(id)}>
                Remove
              </Button>
              {eff != null && eff !== overrides[id] && (
                <span className="text-[11px] text-warn">effective: {eff} (clamped/overridden by the global mode)</span>
              )}
            </div>
          </SettingRow>
        );
      })}
      <SettingRow
        label="Add an override for another detector"
        help="Pick a detector that has no field above; it starts at its current effective mode."
      >
        <div className="flex flex-wrap items-center gap-2">
          <Select
            mono
            disabled={disabled || options.length === 0}
            aria-label="Detector to override"
            options={[
              { value: "", label: options.length === 0 ? "(no other detectors)" : "Pick a detector…" },
              ...options.map((o) => ({ value: o.id, label: o.label })),
            ]}
            value={picked ? pick : ""}
            onChange={(e) => setPick(e.target.value)}
          />
          <Button
            disabled={disabled || !picked}
            onClick={() => {
              if (!picked) return;
              onSet(picked.id, picked.mode);
              setPick("");
            }}
          >
            Add override
          </Button>
        </div>
      </SettingRow>
    </div>
  );
}
