// Pure helpers for two Settings > Guard gaps that used to be config-file-only:
// prompt-detector overrides beyond the fixed field list, and the
// "engine defaults / custom list / none" choice on the boundary lists.
// No React, no fetch: StructuredConfigSection feeds these.

/** PROMPT_DETECTOR_MODES mirrors internal/config/guardprompt.go
 *  guardPromptModes (validateGuardPrompt's closed vocabulary). */
export const PROMPT_DETECTOR_MODES = ["off", "warn", "ask-once", "block", "redact"] as const;

/** One entry of GET /api/guard/prompt/detectors. */
export type DetectorInfo = {
  id: string;
  class: string;
  default_mode: string;
  effective_mode: string;
  overridden?: boolean;
};

export type DetectorOverrides = Record<string, string>;

/** asOverrides reads the draft's Detectors value (null/absent = none). */
export function asOverrides(v: unknown): DetectorOverrides {
  if (!v || typeof v !== "object" || Array.isArray(v)) return {};
  const out: DetectorOverrides = {};
  for (const [k, val] of Object.entries(v as Record<string, unknown>)) out[k] = String(val);
  return out;
}

/** extraOverrideIds: ids overridden in the draft that have no fixed field,
 *  sorted, so an override set by hand in config.toml is visible. */
export function extraOverrideIds(overrides: DetectorOverrides, fixedIds: readonly string[]): string[] {
  const fixed = new Set(fixedIds);
  return Object.keys(overrides).filter((id) => !fixed.has(id)).sort();
}

export type PickerOption = { id: string; label: string; mode: string };

/** addPickerOptions: detectors with no fixed field and no override yet, each
 *  labelled "id (class)" and defaulting to its current effective mode. */
export function addPickerOptions(
  detectors: readonly DetectorInfo[],
  fixedIds: readonly string[],
  overrides: DetectorOverrides,
): PickerOption[] {
  const skip = new Set([...fixedIds, ...Object.keys(overrides)]);
  return detectors
    .filter((d) => !skip.has(d.id))
    .map((d) => ({
      id: d.id,
      label: d.class ? `${d.id} (${d.class})` : d.id,
      mode: (PROMPT_DETECTOR_MODES as readonly string[]).includes(d.effective_mode)
        ? d.effective_mode
        : "warn",
    }))
    .sort((a, b) => a.id.localeCompare(b.id));
}

/** setOverride returns a new map with id set to mode. */
export function setOverride(overrides: DetectorOverrides, id: string, mode: string): DetectorOverrides {
  return { ...overrides, [id]: mode };
}

/** removeOverride returns a new map without id. */
export function removeOverride(overrides: DetectorOverrides, id: string): DetectorOverrides {
  const { [id]: _drop, ...rest } = overrides;
  return rest;
}

// ---- tri-state list (nil = engine defaults, [] = none, [..] = custom) ----

export type ListChoice = "defaults" | "custom" | "none";

/** choiceOf classifies a draft value: null/undefined = defaults, [] = none. */
export function choiceOf(v: unknown): ListChoice {
  if (v == null) return "defaults";
  if (Array.isArray(v) && v.length === 0) return "none";
  return "custom";
}

/** valueForChoice is the draft value after the user picks a choice. `current`
 *  is the value before; switching to custom keeps any list already there. */
export function valueForChoice(choice: ListChoice, current: unknown): string[] | null {
  if (choice === "defaults") return null;
  if (choice === "none") return [];
  return Array.isArray(current) ? current.map(String) : [];
}

/** effectiveChoice: like choiceOf, but while the user has picked "Custom list"
 *  and not entered an item yet (the value is still []), keep showing Custom
 *  rather than snapping to None. */
export function effectiveChoice(v: unknown, customPending: boolean): ListChoice {
  const c = choiceOf(v);
  return c === "none" && customPending ? "custom" : c;
}
