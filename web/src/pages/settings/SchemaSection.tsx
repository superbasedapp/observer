import { useEffect, useMemo, useState } from "react";
import clsx from "clsx";
import { ChartShell, Toggle, Tooltip } from "@/components/primitives";
import type { ConfigResponse } from "@/lib/types";
import { markRestartPending } from "@/lib/restartPending";
import {
  firstSentence,
  getByFieldPath,
  groupByTable,
  isScalarKind,
  leavesForSection,
  restartChip,
  sameValue,
  type ConfigKeyPatch,
  type ConfigKeysError,
  type ConfigKeysResponse,
  type ConfigSchemaDescriptor,
  type ConfigSchemaLeaf,
  type LeafGroup,
} from "@/lib/configSchema";

// SchemaSection — the schema-driven settings renderer
// (docs/plans/dashboard-config-management-plan-2026-08-28.md §1.5 / P1-7).
//
// Every leaf of a Settings section that no hand-written form already
// covers renders here from GET /api/config/schema: a typed control per
// kind (bool switch, number, string, enum select, string list, key=value
// map), the block's Go doc comment as help text, a per-key restart chip
// DERIVED from the schema's restart class, a "confirm" badge on the
// sensitive tier, and honest read-only states for secrets ("set" / "not
// set" — never the value, never a replace field: plan §4.3 / C5 refuses
// credential writes through this surface), owner-elsewhere keys (naming
// the owner) and deprecated aliases (naming the replacement).
//
// Save is ONE batched PUT /api/config/keys carrying the etag the values
// were read under; a 409 names the keys that moved underneath and offers a
// reload instead of silently clobbering. A list/map edit re-serializes the
// file (comments elsewhere are lost, .bak keeps the prior version) — the
// UI says so BEFORE the save, once per session, driven by the leaf kind.
//
// Prominence (plan §1.5): primary leaves show; advanced collapse behind a
// per-group disclosure; expert additionally needs the page-level toggle.

const TIER_B_WARNED_KEY = "sb_config_tier_b_warned";

export function SchemaSection({
  section,
  title,
  config,
  schema,
  readOnly,
  excludeFieldPaths,
  onSaved,
  compact,
}: {
  section: string;
  title?: string;
  config: ConfigResponse | null;
  schema: ConfigSchemaDescriptor | null;
  readOnly?: boolean;
  // JSON field paths a hand-written form on the same page already edits.
  excludeFieldPaths?: Set<string>;
  onSaved: () => void;
  // Rendered as a trailing "More settings" card under a bespoke form.
  compact?: boolean;
}) {
  const leaves = useMemo(
    () => (schema ? leavesForSection(schema, section, excludeFieldPaths) : []),
    [schema, section, excludeFieldPaths],
  );
  const groups = useMemo(
    () => (schema ? groupByTable(schema, leaves) : []),
    [schema, leaves],
  );
  const [draft, setDraft] = useState<Record<string, unknown>>({});
  const [showExpert, setShowExpert] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [keyErrors, setKeyErrors] = useState<Record<string, string>>({});
  const [conflict, setConflict] = useState<string[] | null>(null);
  const [savedMsg, setSavedMsg] = useState<string | null>(null);

  // A config refresh (after save / reload) invalidates the draft.
  useEffect(() => {
    setDraft({});
    setConflict(null);
    setKeyErrors({});
  }, [config?.config_etag]);

  const current = (leaf: ConfigSchemaLeaf): unknown =>
    getByFieldPath(config?.config, leaf.field_path);
  const shown = (leaf: ConfigSchemaLeaf): unknown =>
    leaf.path in draft ? draft[leaf.path] : current(leaf);

  const dirtyLeaves = leaves.filter(
    (l) => l.path in draft && !sameValue(draft[l.path], current(l)),
  );
  const dirty = dirtyLeaves.length > 0;

  function setValue(leaf: ConfigSchemaLeaf, v: unknown) {
    setDraft((d) => ({ ...d, [leaf.path]: v }));
    setSavedMsg(null);
    setKeyErrors((ke) => {
      if (!(leaf.path in ke)) return ke;
      const next = { ...ke };
      delete next[leaf.path];
      return next;
    });
  }

  function reset() {
    setDraft({});
    setErr(null);
    setKeyErrors({});
    setConflict(null);
    setSavedMsg(null);
  }

  async function save() {
    if (!config || !dirty) return;
    const tierB = dirtyLeaves.filter((l) => !isScalarKind(l.kind));
    if (tierB.length > 0) {
      let warned = false;
      try {
        warned = sessionStorage.getItem(TIER_B_WARNED_KEY) === "1";
      } catch {
        // no storage: warn every time
      }
      if (!warned) {
        const ok = window.confirm(
          `Saving ${tierB.map((l) => l.path).join(", ")} rewrites ${config.config_path || "config.toml"}.\n\n` +
            "Comments and formatting elsewhere in the file are not preserved (list and table values re-serialize the whole file). " +
            "The previous version is saved to config.toml.bak.\n\nContinue?",
        );
        if (!ok) return;
        try {
          sessionStorage.setItem(TIER_B_WARNED_KEY, "1");
        } catch {
          // ignore
        }
      }
    }
    setBusy(true);
    setErr(null);
    setKeyErrors({});
    setConflict(null);
    setSavedMsg(null);
    const patches: ConfigKeyPatch[] = dirtyLeaves.map((l) => ({
      key: l.path,
      value: draft[l.path],
      was: current(l),
    }));
    try {
      const res = await fetch("/api/config/keys", {
        method: "PUT",
        headers: {
          "content-type": "application/json",
          ...(config.confirm_token ? { "X-Observer-Confirm": config.confirm_token } : {}),
        },
        body: JSON.stringify({ base_etag: config.config_etag ?? "", patches }),
      });
      const text = await res.text();
      let body: unknown = null;
      try {
        body = text ? JSON.parse(text) : null;
      } catch {
        body = null;
      }
      if (!res.ok) {
        const e = (body ?? {}) as ConfigKeysError;
        if (res.status === 409 && e.error === "config_changed") {
          setConflict(e.diverged_keys ?? []);
          setErr(e.message ?? "config.toml changed outside this page");
          return;
        }
        if (e.key_errors && e.key_errors.length > 0) {
          const ke: Record<string, string> = {};
          for (const k of e.key_errors) ke[k.key] = k.message;
          setKeyErrors(ke);
        }
        throw new Error(e.message || text || `HTTP ${res.status}`);
      }
      const out = body as ConfigKeysResponse;
      const parts: string[] = [];
      if (out.applied_live_keys.length > 0) parts.push(`${out.applied_live_keys.length} applied now`);
      if (out.next_spawn_keys.length > 0) parts.push(`${out.next_spawn_keys.length} apply to new sessions`);
      if (out.restart_required_keys.length > 0) parts.push(`${out.restart_required_keys.length} apply on restart`);
      if (out.write_mode === "noop") parts.push("nothing changed");
      let msg = parts.length > 0 ? `Saved - ${parts.join(", ")}.` : "Saved.";
      if (out.write_mode === "reserialize") {
        msg += " The file was re-serialized (comments not preserved; prior version in .bak).";
      }
      setSavedMsg(msg);
      if (out.restart_required_keys.length > 0) {
        markRestartPending(section, out.restart_required_keys);
      }
      onSaved();
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  const hasExpert = leaves.some((l) => l.prominence === "expert");
  const hasSecret = leaves.some((l) => l.secret);

  const body = (
    <div className="space-y-4">
      {!schema && (
        <p className="rounded-2 border border-dashed border-line-2 bg-bg-3/40 px-3 py-2 text-[11.5px] text-fg-3">
          Settings schema unavailable - the schema is served to the owner-local
          dashboard only (GET /api/config/schema is a Local route), or this
          daemon predates it.
        </p>
      )}
      {schema && leaves.length === 0 && !compact && (
        <p className="rounded-2 border border-dashed border-line-2 bg-bg-3/40 px-3 py-2 text-[11.5px] text-fg-3">
          No schema-driven settings map to this section.
        </p>
      )}
      {groups.map((g) => (
        <GroupCard
          key={g.path}
          group={g}
          showExpert={showExpert}
          shown={shown}
          current={current}
          draft={draft}
          keyErrors={keyErrors}
          hasValue={(l) => Boolean(config?.redacted_secrets?.[l.path])}
          onChange={setValue}
          disabled={Boolean(readOnly) || busy}
        />
      ))}
      {(leaves.length > 0 || compact) && (
        <div className="flex flex-wrap items-center gap-3 border-t border-line-1 pt-3">
          <button
            type="button"
            onClick={save}
            disabled={!dirty || busy || readOnly || !config}
            title={readOnly ? "Managed by your organization" : undefined}
            className="rounded-2 bg-accent px-3 py-1.5 text-[12px] font-semibold text-accent-on transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {busy ? "Saving…" : dirty ? `Save ${dirtyLeaves.length} change${dirtyLeaves.length === 1 ? "" : "s"}` : "Save"}
          </button>
          <button
            type="button"
            onClick={reset}
            disabled={!dirty || busy}
            className="rounded-2 border border-line-2 bg-bg-2 px-3 py-1.5 text-[12px] text-fg-2 hover:bg-bg-3 disabled:cursor-not-allowed disabled:opacity-40"
          >
            Reset
          </button>
          {hasExpert && (
            <label className="flex items-center gap-1.5 text-[11px] text-fg-3">
              <input
                type="checkbox"
                checked={showExpert}
                onChange={(e) => setShowExpert(e.target.checked)}
              />
              show expert settings
            </label>
          )}
          {savedMsg && <span className="text-[11.5px] text-success">{savedMsg}</span>}
          {err && !conflict && <span className="text-[11.5px] text-danger">{err}</span>}
        </div>
      )}
      {conflict && (
        <div className="rounded-2 border border-warn/40 bg-warn-soft px-3 py-2 text-[11.5px] text-fg-2">
          <div className="font-semibold text-warn">config.toml changed outside this page</div>
          <div className="mt-0.5">
            {conflict.length > 0 ? (
              <>
                These keys moved under you:{" "}
                <span className="font-mono">{conflict.join(", ")}</span>.
              </>
            ) : (
              <>None of the keys you edited moved, but the file did.</>
            )}{" "}
            Reload to see the current values, then re-apply your edits.
          </div>
          <button
            type="button"
            onClick={() => onSaved()}
            className="mt-2 rounded-2 border border-accent/50 bg-accent/15 px-2 py-0.5 text-accent hover:bg-accent/25"
          >
            Reload values
          </button>
        </div>
      )}
      {hasSecret && (
        <p className="text-[10.5px] text-fg-4">
          Credentials are never shown or written here - set them by editing{" "}
          <span className="font-mono">{config?.config_path || "config.toml"}</span> directly.
        </p>
      )}
    </div>
  );

  if (compact) {
    return (
      <section className="rounded-3 border border-line-2 bg-bg-2 p-4">
        <header className="mb-3 border-b border-line-1 pb-2">
          <h4 className="text-[12px] font-semibold uppercase tracking-[0.06em] text-fg-1">
            More settings
          </h4>
          <p className="mt-1 text-[11.5px] leading-snug text-fg-3">
            Every other key of this section, rendered from the daemon's config
            schema. Scalar edits keep your comments; each key says when it applies.
          </p>
        </header>
        {body}
      </section>
    );
  }
  return (
    <ChartShell
      title={title ?? section}
      sub="Rendered from the daemon's config schema. Scalar edits keep your comments and formatting; each key says whether it applies now, to new sessions, or on restart."
    >
      {body}
    </ChartShell>
  );
}

function GroupCard({
  group,
  showExpert,
  shown,
  current,
  draft,
  keyErrors,
  hasValue,
  onChange,
  disabled,
}: {
  group: LeafGroup;
  showExpert: boolean;
  shown: (l: ConfigSchemaLeaf) => unknown;
  current: (l: ConfigSchemaLeaf) => unknown;
  draft: Record<string, unknown>;
  keyErrors: Record<string, string>;
  hasValue: (l: ConfigSchemaLeaf) => boolean;
  onChange: (l: ConfigSchemaLeaf, v: unknown) => void;
  disabled: boolean;
}) {
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const primary = group.leaves.filter((l) => l.prominence === "primary");
  const advanced = group.leaves.filter((l) => l.prominence === "advanced");
  const expert = showExpert ? group.leaves.filter((l) => l.prominence === "expert") : [];
  const hidden = group.leaves.length - primary.length - advanced.length - expert.length;
  const doc = group.table?.doc;
  return (
    <section className="rounded-3 border border-line-2 bg-bg-2 p-4">
      <header className="mb-3 border-b border-line-1 pb-2">
        <h4 className="font-mono text-[12px] font-semibold text-fg-1">[{group.path}]</h4>
        {doc && (
          <Tooltip content={<span className="whitespace-pre-wrap">{doc}</span>} maxWidth={480}>
            <p tabIndex={0} className="mt-1 cursor-help text-[11.5px] leading-snug text-fg-3 focus:outline-none">
              {firstSentence(doc)}
            </p>
          </Tooltip>
        )}
      </header>
      <div className="space-y-3">
        {primary.map((l) => (
          <LeafRow key={l.path} leaf={l} value={shown(l)} dirty={l.path in draft && !sameValue(draft[l.path], current(l))} error={keyErrors[l.path]} hasValue={hasValue(l)} onChange={onChange} disabled={disabled} />
        ))}
        {advanced.length > 0 && (
          <div className="border-t border-line-1 pt-2">
            <button
              type="button"
              onClick={() => setAdvancedOpen((o) => !o)}
              className="text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-3 hover:text-fg-1"
            >
              {advancedOpen ? "▾" : "▸"} Advanced ({advanced.length})
            </button>
            {advancedOpen && (
              <div className="mt-3 space-y-3">
                {advanced.map((l) => (
                  <LeafRow key={l.path} leaf={l} value={shown(l)} dirty={l.path in draft && !sameValue(draft[l.path], current(l))} error={keyErrors[l.path]} hasValue={hasValue(l)} onChange={onChange} disabled={disabled} />
                ))}
              </div>
            )}
          </div>
        )}
        {expert.length > 0 && (
          <div className="border-t border-line-1 pt-2">
            <div className="text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-3">Expert</div>
            <div className="mt-3 space-y-3">
              {expert.map((l) => (
                <LeafRow key={l.path} leaf={l} value={shown(l)} dirty={l.path in draft && !sameValue(draft[l.path], current(l))} error={keyErrors[l.path]} hasValue={hasValue(l)} onChange={onChange} disabled={disabled} />
              ))}
            </div>
          </div>
        )}
        {hidden > 0 && (
          <p className="text-[10.5px] text-fg-4">
            {hidden} expert setting{hidden === 1 ? "" : "s"} hidden - enable "show expert settings" below.
          </p>
        )}
      </div>
    </section>
  );
}

function LeafRow({
  leaf,
  value,
  dirty,
  error,
  hasValue,
  onChange,
  disabled,
}: {
  leaf: ConfigSchemaLeaf;
  value: unknown;
  dirty: boolean;
  error?: string;
  hasValue: boolean;
  onChange: (l: ConfigSchemaLeaf, v: unknown) => void;
  disabled: boolean;
}) {
  const chip = restartChip(leaf.restart);
  const key = leaf.path.slice(leaf.path.lastIndexOf(".") + 1);
  const editable = !leaf.secret && leaf.tier !== "owner_elsewhere" && leaf.kind !== "table";
  return (
    <div className={clsx("grid grid-cols-1 gap-1.5 lg:grid-cols-[220px_minmax(0,1fr)] lg:items-start lg:gap-4", dirty && "rounded-2 bg-accent/5")}>
      <div className="lg:pt-1.5">
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="font-mono text-[11.5px] font-semibold text-fg-1" title={leaf.path}>
            {key}
          </span>
          <span
            className={clsx(
              "rounded-pill border px-1.5 py-px text-[9px] font-medium uppercase tracking-[0.04em]",
              chip.tone === "ok" && "border-success/40 text-success",
              chip.tone === "info" && "border-line-2 text-fg-3",
              chip.tone === "warn" && "border-warn/40 text-warn",
            )}
            title={
              leaf.restart === "restart"
                ? "Binds at daemon start - the running daemon keeps the old value until restarted"
                : leaf.restart === "next_spawn"
                  ? "Read by each new session / subprocess, not by this daemon"
                  : "An existing hot-reload seam applies this on save"
            }
          >
            {chip.label}
          </span>
          {leaf.tier === "sensitive" && (
            <span className="rounded-pill border border-line-2 px-1.5 py-px text-[9px] font-medium uppercase tracking-[0.04em] text-fg-3" title="Sensitive: saving needs the page's confirm token and writes an audit row">
              confirm
            </span>
          )}
          {leaf.deprecated && (
            <span className="rounded-pill border border-warn/40 px-1.5 py-px text-[9px] font-medium uppercase tracking-[0.04em] text-warn">
              deprecated
            </span>
          )}
        </div>
        {leaf.doc && (
          <div className="mt-1 text-[11px] leading-snug text-fg-3" title={leaf.doc}>
            {firstSentence(leaf.doc)}
          </div>
        )}
        {leaf.deprecated && (
          <div className="mt-1 text-[10.5px] text-warn">{leaf.deprecated}</div>
        )}
        {!editable && !leaf.secret && leaf.owned_by && (
          <div className="mt-1 text-[10.5px] text-fg-4">Read-only here - owned by {leaf.owned_by}</div>
        )}
      </div>
      <div>
        {leaf.secret ? (
          <SecretState hasValue={hasValue} />
        ) : editable ? (
          <LeafInput leaf={leaf} value={value} onChange={(v) => onChange(leaf, v)} disabled={disabled} />
        ) : (
          <ReadOnlyValue value={value} />
        )}
        {error && <div className="mt-1 text-[11px] text-danger">{error}</div>}
      </div>
    </div>
  );
}

function SecretState({ hasValue }: { hasValue: boolean }) {
  return (
    <div className="flex items-center gap-2 lg:pt-1">
      <span
        className={clsx(
          "rounded-pill border px-2 py-px text-[10.5px] font-medium",
          hasValue ? "border-success/40 text-success" : "border-line-2 text-fg-3",
        )}
      >
        {hasValue ? "set" : "not set"}
      </span>
      <span className="text-[10.5px] text-fg-4">credential - never shown; edit config.toml to change</span>
    </div>
  );
}

function ReadOnlyValue({ value }: { value: unknown }) {
  const text =
    value == null
      ? "(unset)"
      : typeof value === "object"
        ? JSON.stringify(value, null, 1).replace(/\n\s*/g, " ")
        : String(value);
  return (
    <pre className="m-0 max-h-[120px] overflow-auto whitespace-pre-wrap rounded-2 border border-line-1 bg-bg-1 px-2.5 py-1.5 font-mono text-[11.5px] text-fg-3">
      {text}
    </pre>
  );
}

function LeafInput({
  leaf,
  value,
  onChange,
  disabled,
}: {
  leaf: ConfigSchemaLeaf;
  value: unknown;
  onChange: (v: unknown) => void;
  disabled: boolean;
}) {
  const common =
    "w-full rounded-2 border border-line-2 bg-bg-2 px-2.5 py-1.5 font-mono text-[12px] text-fg-1 placeholder:text-fg-4 focus:border-accent focus:outline-none disabled:opacity-50";
  switch (leaf.kind) {
    case "bool": {
      const on = Boolean(value);
      return (
        <div className="lg:pt-1">
          <Toggle on={on} onChange={onChange} disabled={disabled} label={on ? "enabled" : "disabled"} />
        </div>
      );
    }
    case "int":
    case "float":
      return (
        <input
          type="number"
          className={common}
          disabled={disabled}
          value={value == null || value === "" ? "" : Number(value)}
          min={leaf.min}
          max={leaf.max}
          step={leaf.kind === "int" ? 1 : "any"}
          onChange={(e) => {
            const n = e.target.valueAsNumber;
            onChange(Number.isFinite(n) ? n : 0);
          }}
        />
      );
    case "string":
      if (leaf.enum && leaf.enum.length > 0) {
        return (
          <select className={common} disabled={disabled} value={String(value ?? "")} onChange={(e) => onChange(e.target.value)}>
            {leaf.enum.map((o) => (
              <option key={o} value={o}>
                {o === "" ? "(default)" : o}
              </option>
            ))}
          </select>
        );
      }
      return (
        <input
          type="text"
          className={common}
          disabled={disabled}
          value={value == null ? "" : String(value)}
          onChange={(e) => onChange(e.target.value)}
        />
      );
    case "string_list": {
      const arr = Array.isArray(value) ? (value as unknown[]).map(String) : [];
      return (
        <ListInput items={arr} onChange={onChange} disabled={disabled} className={common} />
      );
    }
    case "string_map": {
      const obj = value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
      return <MapInput entries={obj} onChange={onChange} disabled={disabled} className={common} />;
    }
    default:
      return <ReadOnlyValue value={value} />;
  }
}

// ListInput edits a []string as one item per line (commas are legal inside
// items such as ignore patterns, so lines, not commas, delimit).
function ListInput({
  items,
  onChange,
  disabled,
  className,
}: {
  items: string[];
  onChange: (v: unknown) => void;
  disabled: boolean;
  className: string;
}) {
  const [text, setText] = useState(items.join("\n"));
  useEffect(() => {
    setText(items.join("\n"));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [items.join("\n")]);
  return (
    <textarea
      className={clsx(className, "min-h-[64px]")}
      disabled={disabled}
      value={text}
      placeholder="one item per line"
      onChange={(e) => {
        setText(e.target.value);
        onChange(
          e.target.value
            .split("\n")
            .map((s) => s.trim())
            .filter(Boolean),
        );
      }}
    />
  );
}

// MapInput edits a map[string]string as `key = value` lines.
function MapInput({
  entries,
  onChange,
  disabled,
  className,
}: {
  entries: Record<string, unknown>;
  onChange: (v: unknown) => void;
  disabled: boolean;
  className: string;
}) {
  const render = (o: Record<string, unknown>) =>
    Object.keys(o)
      .sort()
      .map((k) => `${k} = ${String(o[k] ?? "")}`)
      .join("\n");
  const [text, setText] = useState(render(entries));
  const key = render(entries);
  useEffect(() => {
    setText(key);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);
  return (
    <textarea
      className={clsx(className, "min-h-[64px]")}
      disabled={disabled}
      value={text}
      placeholder="key = value, one per line"
      onChange={(e) => {
        setText(e.target.value);
        const out: Record<string, string> = {};
        for (const line of e.target.value.split("\n")) {
          const i = line.indexOf("=");
          if (i < 0) continue;
          const k = line.slice(0, i).trim();
          if (!k) continue;
          out[k] = line.slice(i + 1).trim();
        }
        onChange(out);
      }}
    />
  );
}
