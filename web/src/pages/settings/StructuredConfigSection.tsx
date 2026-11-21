import type { LucideIcon } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import {
  Button,
  ChartShell,
  EntityMultiPicker,
  Input,
  Select,
  SettingRow,
  SinglePicker,
  Toggle,
  SuccessCheck,
} from "@/components/primitives";
import { KNOWN_ACTION_TYPES } from "@shared/lib/actions";
import type { ConfigResponse } from "@/lib/types";
import { markRestartPending, RESTART_HINT } from "@/lib/restartPending";
import { useApi } from "@/lib/useApi";
import type { FieldDef, OptionSourceId, SectionGroup, SectionSpec } from "./sectionSpecs";
import { keepSelected, type PickOption } from "@/lib/pickerOptions";
import {
  GUARD_RULE_OPTIONS,
  type PickerSource,
  usePricedModels,
  useProjectRootOptions,
  useToolOptions,
} from "@/lib/usePickerSources";

const ACTION_TYPE_OPTIONS: PickOption[] = KNOWN_ACTION_TYPES.map((t) => ({ id: t, label: t }));

type PickerSources = Partial<Record<OptionSourceId, PickerSource>>;

/** specSources lists the option sources a section's fields name, so the
 *  section fetches only the rosters it renders. */
function specSources(spec: SectionSpec): Set<OptionSourceId> {
  const out = new Set<OptionSourceId>();
  for (const f of [...(spec.fields ?? []), ...(spec.groups ?? []).flatMap((g) => g.fields)]) {
    if (f.optionSource) out.add(f.optionSource);
  }
  return out;
}
import { saveConfigSection } from "@/lib/configSectionSave";
import { DetectorOverrideExtras } from "./DetectorOverrideExtras";
import { FreeListInput, NullableListInput } from "./NullableListInput";

// GET /api/guard/prompt/detectors response shape (backend:
// internal/intelligence/dashboard/guard_prompt.go's
// handleGuardPromptDetectors/promptDetectorJSON) — the full detector
// vocabulary scrub.DetectorNames() knows, each with its class, the
// raw configured/default mode, the RESOLVED effective mode after the
// stricter-wins-with-floor clamp, and whether an override is set.
// Only `id` and `effective_mode` are consumed here; the rest is kept
// on the type for completeness/future use.
type PromptDetectorEntry = {
  id: string;
  class: string;
  default_mode: string;
  effective_mode: string;
  overridden: boolean;
};

type PromptDetectorsResponse = {
  detectors: PromptDetectorEntry[];
};

// StructuredConfigSection — per-section structured form. Edits live
// in a local draft; clicking Save POSTs to
// `PUT /api/config/section/<spec.id>` and surfaces the
// "restart required" banner the backend returns.
//
// Field controls are fully editable when the running config supplies
// values; the older read-only mode disappears once the backend
// endpoint is reachable. Errors (4xx/5xx) render inline near the
// Save button so users see what blocked the save.
export function StructuredConfigSection({
  spec,
  config,
  description,
  badge,
  footer,
  readOnly,
  icon,
  onDraftChange,
}: {
  spec: SectionSpec;
  /** The section glyph from the Settings SECTIONS table (card title). */
  icon?: LucideIcon;
  config: ConfigResponse | null;
  description?: string;
  badge?: React.ReactNode;
  footer?: React.ReactNode;
  // Governance can lock a section read-only (docs/plane-a governance
  // posture). No-op / undefined on an ungoverned node.
  readOnly?: boolean;
  // Called with the section's unsaved draft whenever it changes (null while
  // the config has not loaded). The process section feeds its data-volume
  // card from it; sections that pass nothing behave exactly as before.
  onDraftChange?: (draft: Record<string, unknown> | null) => void;
}) {
  // Dynamic select-option sources (D11): fields with `optionsFrom`
  // resolve their option list from the loaded config response, so
  // e.g. the profile selects include user-created profiles.
  const dynamicOptions = useMemo<Record<string, string[] | undefined>>(
    () => ({ profile_names: config?.profile_names }),
    [config],
  );

  // Picker rosters (D-571): fetched only when a field of this section
  // names the source.
  const wanted = useMemo(() => specSources(spec), [spec]);
  const adapters = useToolOptions(wanted.has("adapters"));
  const projectRoots = useProjectRootOptions(wanted.has("project_roots"));
  const pricedModels = usePricedModels(wanted.has("priced_models"));
  const pickers = useMemo<PickerSources>(
    () => ({
      adapters,
      project_roots: projectRoots,
      priced_models: pricedModels,
      action_types: { options: ACTION_TYPE_OPTIONS, loading: false },
      guard_rules: { options: GUARD_RULE_OPTIONS, loading: false },
    }),
    [adapters, projectRoots, pricedModels],
  );

  // Resolved effective-mode sidecar for the "prompt-detectors" GROUP
  // ONLY (fields opted in via FieldDef.showEffectiveMode) — sourced
  // from a SEPARATE fetch to GET /api/guard/prompt/detectors, not from
  // the ConfigResponse prop `dynamicOptions` draws from. "guard" is a
  // grouped section (see spec.groups below): "prompt-detectors" is one
  // of ITS groups, not a top-level spec.id, so the gate checks the
  // groups list rather than spec.id — this fetch never fires for any
  // section/group other than that one.
  const hasPromptDetectorsGroup = Boolean(
    spec.groups?.some((g) => g.id === "prompt-detectors"),
  );
  const detectorsApi = useApi<PromptDetectorsResponse>(
    hasPromptDetectorsGroup ? "/api/guard/prompt/detectors" : null,
  );
  const effectiveModes = useMemo<Record<string, string>>(() => {
    const out: Record<string, string> = {};
    for (const d of detectorsApi.data?.detectors ?? []) {
      out[d.id] = d.effective_mode;
    }
    return out;
  }, [detectorsApi.data]);
  const detectorList = detectorsApi.data?.detectors ?? [];
  // The form payload mirrors the structure of the config section it
  // saves. For grouped sections (Compression has 7 sub-groups across
  // 3 levels of nesting) the draft is the full Compression object;
  // group renderers mutate the nested slot via the path on each
  // SectionGroup.
  const initial = useMemo(
    () => deepClone(resolvePath(config?.config, spec.path)),
    [config, spec.path],
  );
  const [draft, setDraft] = useState<Record<string, unknown> | null>(initial);
  // Keep the draft in sync when the config refreshes (e.g. after a
  // successful save the parent re-fetches /api/config).
  useEffect(() => {
    setDraft(initial);
  }, [initial]);
  useEffect(() => {
    onDraftChange?.(draft);
    // The callback is the parent's state setter; its identity is not a trigger.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [draft]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [savedMsg, setSavedMsg] = useState<string | null>(null);

  const dirty = useMemo(
    () => !deepEq(draft, initial),
    [draft, initial],
  );

  const hasGroups = Boolean(spec.groups && spec.groups.length > 0);

  // Per-field setter — given a sub-path under the section root, set
  // the leaf value while keeping the rest of the object intact.
  function setAt(subPath: string[], value: unknown) {
    setDraft((cur) => {
      const next = deepClone(cur) ?? {};
      let cursor: Record<string, unknown> = next as Record<string, unknown>;
      for (let i = 0; i < subPath.length - 1; i++) {
        const k = subPath[i];
        const v = cursor[k];
        if (!v || typeof v !== "object") cursor[k] = {};
        cursor = cursor[k] as Record<string, unknown>;
      }
      cursor[subPath[subPath.length - 1]] = value;
      return next;
    });
    setSavedMsg(null);
  }

  // Drop one key from the object at subPath (a detector override Remove).
  function removeAt(subPath: string[], key: string) {
    setDraft((cur) => {
      const next = deepClone(cur) ?? {};
      const sub = resolveSub(next, subPath);
      if (sub) delete sub[key];
      return next;
    });
    setSavedMsg(null);
  }

  async function save() {
    if (!draft) return;
    setBusy(true);
    setErr(null);
    setSavedMsg(null);
    try {
      // A field the spec marks `disabled` renders inert (honest-disabled-
      // copy) precisely because no Go consumer reads it — writing it back
      // anyway would still land a dead key in config.toml. Strip only
      // those keys from the OUTGOING payload; the draft itself (and the
      // rest of the section object) is untouched.
      const payload = stripDisabledFields(draft, spec);
      // Previews the masked diff (and any credential-shaped value) in the
      // shell's save dialog, then writes with the confirm token (T-432).
      const out = await saveConfigSection(spec.id, payload);
      if (out.write_mode === "noop") {
        setSavedMsg("Nothing to save; config.toml already says this.");
      } else if (out.restart_required) {
        const keys = out.restart_required_keys.length > 0 ? out.restart_required_keys : undefined;
        setSavedMsg(
          keys && keys.length > 0
            ? `Saved. ${keys.join(", ")} applies after a daemon restart: ${RESTART_HINT}.`
            : `Saved. The change applies after a daemon restart: ${RESTART_HINT}.`,
        );
        // Feed the global restart-pending banner so the reminder
        // survives navigating away from Settings (P1.9) — with the KEYS
        // the daemon classified as bind-at-start (plan §3.3 item 1).
        markRestartPending(spec.id, keys);
      } else {
        setSavedMsg("Saved.");
      }
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  function reset() {
    setDraft(initial);
    setErr(null);
    setSavedMsg(null);
  }

  return (
    <ChartShell
      title={
        <span className="flex items-baseline gap-2">
          {spec.title ?? prettyTitle(spec.id)}
          {badge}
        </span>
      }
      icon={icon}
      sub={description ?? spec.description}
    >
      <div className="space-y-4">
        {spec.fields && spec.fields.length > 0 && (
          <div className="space-y-4">
            {spec.fields.map((f) => (
              <FieldRow
                key={f.id}
                field={f}
                value={pickField(draft, f.id)}
                onChange={(v) => setAt([f.id], v)}
                dynamicOptions={dynamicOptions}
                effectiveModes={effectiveModes}
                pickers={pickers}
              />
            ))}
          </div>
        )}
        {hasGroups &&
          spec.groups!.map((g) => {
            // Build the sub-path relative to the section root. For
            // sections with an empty path[] the group's path is
            // already absolute; otherwise the group path INCLUDES the
            // section prefix and it is stripped here (profiles'
            // ["Profiles","ByProvider"] → ["ByProvider"]).
            const rel =
              spec.path.length === 0
                ? g.path
                : g.path.slice(spec.path.length);
            if (g.hideWhenAbsent && resolveSub(draft, rel) == null) return null;
            return (
              <GroupCard
                key={g.id}
                group={g}
                draft={draft}
                relPath={rel}
                onChange={(field, value) =>
                  setAt([...rel, field], value)
                }
                onRemoveKey={(key) => removeAt(rel, key)}
                detectors={detectorList}
                readOnly={readOnly}
                dynamicOptions={dynamicOptions}
                effectiveModes={effectiveModes}
                pickers={pickers}
              />
            );
          })}
        {!hasGroups && draft == null && (
          <p className="rounded-2 border border-dashed border-line-2 bg-bg-3/40 px-3 py-2 text-[11.5px] text-fg-3">
            Section not present in the running config. Backend may not have
            initialized the defaults yet - restart the daemon (Restart daemon in Settings &gt; Health).
          </p>
        )}
        <div className="flex flex-wrap items-center gap-3 border-t border-line-1 pt-3">
          <Button
            variant="primary"
            onClick={save}
            disabled={!dirty || busy || readOnly}
            loading={busy}
            title={readOnly ? "Managed by your organization" : undefined}
          >
            {busy ? "Saving…" : "Save"}
          </Button>
          <Button
            onClick={reset}
            disabled={!dirty || busy || readOnly}
            title={readOnly ? "Managed by your organization" : undefined}
          >
            Reset
          </Button>
          {savedMsg && (
            <SuccessCheck label={savedMsg} className="!text-[11.5px]" />
          )}
          {err && <span className="text-[11.5px] text-danger">{err}</span>}
        </div>
      </div>
      {footer}
    </ChartShell>
  );
}

function GroupCard({
  group,
  draft,
  relPath,
  onChange,
  onRemoveKey,
  detectors,
  readOnly,
  dynamicOptions,
  effectiveModes,
  pickers,
}: {
  group: SectionGroup;
  draft: Record<string, unknown> | null;
  relPath: string[];
  onChange: (field: string, value: unknown) => void;
  onRemoveKey: (key: string) => void;
  detectors: PromptDetectorEntry[];
  readOnly?: boolean;
  dynamicOptions?: Record<string, string[] | undefined>;
  effectiveModes?: Record<string, string>;
  pickers?: PickerSources;
}) {
  const groupData = useMemo(
    () => resolveSub(draft, relPath),
    [draft, relPath],
  );
  return (
    <section className="rounded-3 border border-line-2 bg-bg-2 p-4">
      <header className="mb-3 border-b border-line-1 pb-2">
        <h4 className="text-[12px] font-semibold uppercase tracking-[0.06em] text-fg-1">
          {group.label}
        </h4>
        {group.description && (
          <p className="mt-1 text-[11.5px] leading-snug text-fg-3">
            {group.description}
          </p>
        )}
      </header>
      <div className="space-y-3">
        {group.fields.map((f) => (
          <FieldRow
            key={f.id}
            field={f}
            value={pickField(groupData, f.id)}
            onChange={(v) => onChange(f.id, v)}
            dynamicOptions={dynamicOptions}
            effectiveModes={effectiveModes}
            pickers={pickers}
          />
        ))}
        {group.id === "prompt-detectors" && (
          <DetectorOverrideExtras
            overrides={groupData}
            fixedIds={group.fields.map((f) => f.id)}
            detectors={detectors}
            effectiveModes={effectiveModes ?? {}}
            disabled={readOnly}
            onSet={(id, mode) => onChange(id, mode)}
            onRemove={onRemoveKey}
          />
        )}
      </div>
    </section>
  );
}

// FieldRow is a thin wrapper over the shared SettingRow: label + help in
// the label column, the typed control beside it, and — for a field the
// spec marks `disabled` — the honest "why" note under the control.
function FieldRow({
  field,
  value,
  onChange,
  dynamicOptions,
  effectiveModes,
  pickers,
}: {
  field: FieldDef;
  value: unknown;
  onChange: (v: unknown) => void;
  dynamicOptions?: Record<string, string[] | undefined>;
  effectiveModes?: Record<string, string>;
  pickers?: PickerSources;
}) {
  return (
    <SettingRow
      label={field.label}
      help={field.help}
      status={
        (field.disabled || field.readOnly) && field.note ? (
          <span className="text-[11px] leading-snug text-warn">{field.note}</span>
        ) : undefined
      }
    >
      <FieldInput
        field={field}
        value={value}
        onChange={onChange}
        dynamicOptions={dynamicOptions}
        effectiveModes={effectiveModes}
        pickers={pickers}
      />
    </SettingRow>
  );
}

function FieldInput({
  field,
  value,
  onChange,
  dynamicOptions,
  effectiveModes,
  pickers,
}: {
  field: FieldDef;
  value: unknown;
  onChange: (v: unknown) => void;
  dynamicOptions?: Record<string, string[] | undefined>;
  effectiveModes?: Record<string, string>;
  pickers?: PickerSources;
}) {
  // A spec may mark a field `disabled` — a key the config still carries but
  // that no consumer reads. It renders inert rather than live, and
  // FieldRow prints the field's `note` under it (honest-disabled-copy). A
  // `readOnly` field renders inert too, but keeps its value in the save.
  const disabled = Boolean(field.disabled || field.readOnly);

  if (field.kind === "bool") {
    const on = Boolean(value);
    return (
      <div className="lg:pt-1">
        <Toggle
          on={on}
          onChange={onChange}
          disabled={disabled}
          label={on ? "enabled" : "disabled"}
        />
      </div>
    );
  }

  if (field.kind === "select") {
    const dynamic = field.optionsFrom
      ? dynamicOptions?.[field.optionsFrom]
      : undefined;
    const options =
      dynamic && dynamic.length > 0 ? dynamic : field.options ?? [];
    // Resolved effective mode (post floor-clamp/off-exemption), shown
    // beside the raw configured value for a "prompt-detectors" field —
    // see FieldDef.showEffectiveMode's doc comment. Absent (undefined)
    // until the /api/guard/prompt/detectors fetch resolves, so nothing
    // renders on first paint or on a daemon too old to serve it.
    const effectiveMode = field.showEffectiveMode
      ? effectiveModes?.[field.id]
      : undefined;
    const rawValue = String(value ?? "");
    const differs = effectiveMode != null && effectiveMode !== rawValue;
    return (
      <div>
        <Select
          mono
          disabled={disabled}
          options={options}
          value={rawValue}
          onChange={(e) => onChange(e.target.value)}
        />
        {effectiveMode != null && (
          <div
            className={
              "mt-1 text-[11px] leading-snug " +
              (differs ? "text-warn" : "text-fg-3")
            }
          >
            effective: {effectiveMode}
            {differs && " (clamped/overridden by the global mode)"}
          </div>
        )}
      </div>
    );
  }

  if (field.kind === "int") {
    return (
      <Input
        mono
        type="number"
        disabled={disabled}
        value={value == null ? "" : Number(value)}
        min={field.min}
        max={field.max}
        step={field.step ?? 1}
        onChange={(e) => {
          const n = e.target.valueAsNumber;
          onChange(Number.isFinite(n) ? n : 0);
        }}
      />
    );
  }

  if (field.kind === "list" && field.nullableList) {
    return (
      <NullableListInput
        value={value}
        onChange={onChange}
        defaultsLabel={field.nullableList.defaultsLabel}
        noneLabel={field.nullableList.noneLabel}
        disabled={disabled}
        ariaLabel={field.label}
      />
    );
  }

  // A list or text field over a known set is a picker (D-571): a closed
  // `options` list or a daemon roster named by `optionSource`. A value the
  // list does not carry (set by hand in config.toml) stays visible.
  const source = field.optionSource ? pickers?.[field.optionSource] : undefined;
  const known: PickOption[] | undefined =
    field.kind === "list" && field.options
      ? field.options.map((o) => ({ id: o, label: o }))
      : source?.options;
  if (field.kind === "list" && known) {
    const arr = (Array.isArray(value) ? value : []).map(String);
    return (
      <EntityMultiPicker
        options={keepSelected(known, arr)}
        value={arr}
        onChange={(next) => onChange(next)}
        disabled={disabled}
        allowFreeId={Boolean(field.allowFree)}
        loading={source?.loading}
        placeholder={field.allowFree ? "Pick, or type a value and press Enter…" : "Pick…"}
        ariaLabel={field.label}
      />
    );
  }
  if (field.kind === "text" && known) {
    const cur = value == null ? "" : String(value);
    return (
      <SinglePicker
        options={keepSelected(known, cur ? [cur] : [])}
        value={cur}
        onChange={(next) => onChange(next)}
        disabled={disabled}
        allowFree={Boolean(field.allowFree)}
        loading={source?.loading}
        placeholder="Pick one…"
        ariaLabel={field.label}
      />
    );
  }

  if (field.kind === "list") {
    const arr = (Array.isArray(value) ? value : []).map(String);
    return <FreeListInput value={arr} onChange={onChange} disabled={disabled} ariaLabel={field.label} />;
  }

  // text
  return (
    <Input
      mono
      type="text"
      disabled={disabled}
      placeholder={field.readOnly ? "none" : undefined}
      value={value == null ? "" : String(value)}
      onChange={(e) => onChange(e.target.value)}
    />
  );
}

function resolvePath(obj: unknown, path: string[]): Record<string, unknown> | null {
  let cur: unknown = obj;
  for (const k of path) {
    if (!cur || typeof cur !== "object") return null;
    cur = (cur as Record<string, unknown>)[k];
  }
  return cur && typeof cur === "object"
    ? (cur as Record<string, unknown>)
    : null;
}

function resolveSub(
  obj: Record<string, unknown> | null,
  path: string[],
): Record<string, unknown> | null {
  let cur: unknown = obj;
  for (const k of path) {
    if (!cur || typeof cur !== "object") return null;
    cur = (cur as Record<string, unknown>)[k];
  }
  return cur && typeof cur === "object"
    ? (cur as Record<string, unknown>)
    : null;
}

function pickField(
  data: Record<string, unknown> | null,
  id: string,
): unknown {
  if (!data) return undefined;
  return data[id];
}

function prettyTitle(id: string): string {
  return id.charAt(0).toUpperCase() + id.slice(1);
}

// stripDisabledFields drops every key whose FieldDef is marked
// `disabled: true` (honest-disabled-copy — the config still carries the
// key but no Go consumer reads it) from the OUTGOING save payload only,
// leaving the rest of the section object — and the caller's `draft`
// state — intact. Walks both the section's flat `fields` and each
// group's `fields` at the group's resolved sub-path.
function stripDisabledFields(
  draft: Record<string, unknown> | null,
  spec: SectionSpec,
): Record<string, unknown> | null {
  if (!draft) return draft;
  const out = deepClone(draft);
  for (const f of spec.fields ?? []) {
    if (f.disabled) delete out[f.id];
  }
  for (const g of spec.groups ?? []) {
    const rel =
      spec.path.length === 0 ? g.path : g.path.slice(spec.path.length);
    const sub = resolveSub(out, rel);
    if (!sub) continue;
    for (const f of g.fields) {
      if (f.disabled) delete sub[f.id];
    }
  }
  return out;
}

function deepClone<T>(v: T): T {
  if (v == null) return v;
  if (typeof v !== "object") return v;
  if (Array.isArray(v))
    return (v as unknown[]).map((x) => deepClone(x)) as unknown as T;
  const out: Record<string, unknown> = {};
  for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
    out[k] = deepClone(val);
  }
  return out as unknown as T;
}

function deepEq(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (a == null || b == null) return false;
  if (typeof a !== typeof b) return false;
  if (typeof a !== "object") return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a)) {
    if ((a as unknown[]).length !== (b as unknown[]).length) return false;
    for (let i = 0; i < (a as unknown[]).length; i++) {
      if (!deepEq((a as unknown[])[i], (b as unknown[])[i])) return false;
    }
    return true;
  }
  const ka = Object.keys(a as object).sort();
  const kb = Object.keys(b as object).sort();
  if (ka.length !== kb.length) return false;
  for (let i = 0; i < ka.length; i++) {
    if (ka[i] !== kb[i]) return false;
    if (!deepEq(
      (a as Record<string, unknown>)[ka[i]],
      (b as Record<string, unknown>)[ka[i]],
    )) return false;
  }
  return true;
}
