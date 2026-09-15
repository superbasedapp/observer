import { useEffect, useMemo, useState } from "react";
import { ChartShell, Toggle } from "@/components/primitives";
import type { ConfigResponse } from "@/lib/types";
import { markRestartPending } from "@/lib/restartPending";
import { useApi } from "@/lib/useApi";
import type { FieldDef, SectionGroup, SectionSpec } from "./sectionSpecs";

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
}: {
  spec: SectionSpec;
  config: ConfigResponse | null;
  description?: string;
  badge?: React.ReactNode;
  footer?: React.ReactNode;
  // Governance can lock a section read-only (docs/plane-a governance
  // posture). No-op / undefined on an ungoverned node.
  readOnly?: boolean;
}) {
  // Dynamic select-option sources (D11): fields with `optionsFrom`
  // resolve their option list from the loaded config response, so
  // e.g. the profile selects include user-created profiles.
  const dynamicOptions = useMemo<Record<string, string[] | undefined>>(
    () => ({ profile_names: config?.profile_names }),
    [config],
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

  async function save() {
    if (!draft) return;
    setBusy(true);
    setErr(null);
    setSavedMsg(null);
    try {
      const res = await fetch(`/api/config/section/${spec.id}`, {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(draft),
      });
      if (!res.ok) {
        const text = await res.text();
        throw new Error(text || `HTTP ${res.status}`);
      }
      const out = await res.json().catch(() => null as null | Record<string, unknown>);
      if (out && out.restart_required) {
        const keys = Array.isArray(out.restart_required_keys)
          ? (out.restart_required_keys as string[])
          : undefined;
        setSavedMsg(
          keys && keys.length > 0
            ? `Saved. Restart the observer daemon to apply ${keys.join(", ")}.`
            : "Saved. Restart the observer daemon to pick up the change.",
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
          {prettyTitle(spec.id)}
          {badge}
        </span>
      }
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
            return (
              <GroupCard
                key={g.id}
                group={g}
                draft={draft}
                relPath={rel}
                onChange={(field, value) =>
                  setAt([...rel, field], value)
                }
                dynamicOptions={dynamicOptions}
                effectiveModes={effectiveModes}
              />
            );
          })}
        {!hasGroups && draft == null && (
          <p className="rounded-2 border border-dashed border-line-2 bg-bg-3/40 px-3 py-2 text-[11.5px] text-fg-3">
            Section not present in the running config. Backend may not have
            initialized the defaults yet - restart the daemon.
          </p>
        )}
        <div className="flex flex-wrap items-center gap-3 border-t border-line-1 pt-3">
          <button
            type="button"
            onClick={save}
            disabled={!dirty || busy || readOnly}
            title={readOnly ? "Managed by your organization" : undefined}
            className="rounded-2 bg-accent px-3 py-1.5 text-[12px] font-semibold text-accent-on transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {busy ? "Saving…" : "Save"}
          </button>
          <button
            type="button"
            onClick={reset}
            disabled={!dirty || busy || readOnly}
            title={readOnly ? "Managed by your organization" : undefined}
            className="rounded-2 border border-line-2 bg-bg-2 px-3 py-1.5 text-[12px] text-fg-2 hover:bg-bg-3 disabled:cursor-not-allowed disabled:opacity-40"
          >
            Reset
          </button>
          {savedMsg && (
            <span className="text-[11.5px] text-success">{savedMsg}</span>
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
  dynamicOptions,
  effectiveModes,
}: {
  group: SectionGroup;
  draft: Record<string, unknown> | null;
  relPath: string[];
  onChange: (field: string, value: unknown) => void;
  dynamicOptions?: Record<string, string[] | undefined>;
  effectiveModes?: Record<string, string>;
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
          />
        ))}
      </div>
    </section>
  );
}

function FieldRow({
  field,
  value,
  onChange,
  dynamicOptions,
  effectiveModes,
}: {
  field: FieldDef;
  value: unknown;
  onChange: (v: unknown) => void;
  dynamicOptions?: Record<string, string[] | undefined>;
  effectiveModes?: Record<string, string>;
}) {
  return (
    <div className="grid grid-cols-1 gap-1.5 lg:grid-cols-[180px_minmax(0,1fr)] lg:items-start lg:gap-4">
      <div className="lg:pt-1.5">
        <div className="text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-2">
          {field.label}
        </div>
        {field.help && (
          <div className="mt-1 text-[11px] leading-snug text-fg-3">
            {field.help}
          </div>
        )}
      </div>
      <FieldInput
        field={field}
        value={value}
        onChange={onChange}
        dynamicOptions={dynamicOptions}
        effectiveModes={effectiveModes}
      />
    </div>
  );
}

function FieldInput({
  field,
  value,
  onChange,
  dynamicOptions,
  effectiveModes,
}: {
  field: FieldDef;
  value: unknown;
  onChange: (v: unknown) => void;
  dynamicOptions?: Record<string, string[] | undefined>;
  effectiveModes?: Record<string, string>;
}) {
  const common =
    "w-full rounded-2 border border-line-2 bg-bg-2 px-2.5 py-1.5 font-mono text-[12px] text-fg-1 placeholder:text-fg-4 focus:border-accent focus:outline-none";

  if (field.kind === "bool") {
    const on = Boolean(value);
    return (
      <div className="lg:pt-1">
        <Toggle
          on={on}
          onChange={onChange}
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
        <select
          className={common}
          value={rawValue}
          onChange={(e) => onChange(e.target.value)}
        >
          {options.map((o) => (
            <option key={o} value={o}>
              {o}
            </option>
          ))}
        </select>
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
      <input
        type="number"
        className={common}
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

  if (field.kind === "list") {
    const arr = Array.isArray(value) ? value : [];
    return (
      <input
        type="text"
        className={common}
        value={arr.join(", ")}
        placeholder="comma-separated"
        onChange={(e) => {
          const items = e.target.value
            .split(",")
            .map((s) => s.trim())
            .filter(Boolean);
          onChange(items);
        }}
      />
    );
  }

  // text
  return (
    <input
      type="text"
      className={common}
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
