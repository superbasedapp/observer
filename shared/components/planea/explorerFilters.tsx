import { useEffect, useState } from "react";
import { Search, X } from "lucide-react";
import type { ComboOption } from "../../primitives/ComboChip";
import { Icon } from "../../primitives/Icon";
import { Button } from "../../primitives/Button";
import { Input } from "../../primitives/Input";
import { Toggle } from "../../primitives/Toggle";

// The Plane A explorer's identity and search filters (W3-4, lane B9): the
// same filter names on the org (GET /api/org/obs/trajectories and
// /trace-groups) and on the machine (GET /api/obs/explorer/*), contract
// docs/plans/plane-a-sdk-buildout/contracts/alerts.md. Pure and
// presentational: the value comes in and goes out through props; each app
// turns it into query parameters with explorerQueryParams.

export interface PlaneAExplorerFilters {
  q: string;
  content: boolean;
  service: string;
  environment: string;
  release: string;
  user: string;
  traceTag: string;
  // meta is "key" (has the key) or "key:value" (exact entry).
  meta: string;
}

export const emptyExplorerFilters: PlaneAExplorerFilters = {
  q: "",
  content: false,
  service: "",
  environment: "",
  release: "",
  user: "",
  traceTag: "",
  meta: "",
};

// explorerQueryParams maps the filters onto the shared query parameter names.
export function explorerQueryParams(f: PlaneAExplorerFilters): Record<string, string> {
  const out: Record<string, string> = {
    service: f.service.trim(),
    environment: f.environment.trim(),
    release: f.release.trim(),
    user: f.user.trim(),
    trace_tag: f.traceTag.trim(),
    meta: f.meta.trim(),
    q: f.q.trim(),
  };
  if (f.content && out.q) out.content = "1";
  return out;
}

// explorerFiltersActive reports whether any filter is set.
export function explorerFiltersActive(f: PlaneAExplorerFilters): boolean {
  return Object.values(explorerQueryParams(f)).some((v) => v !== "");
}

const textFields: { key: keyof PlaneAExplorerFilters; label: string; placeholder: string; identity: boolean }[] = [
  { key: "service", label: "Service", placeholder: "checkout-api", identity: false },
  { key: "environment", label: "Environment", placeholder: "prod", identity: false },
  { key: "release", label: "Release", placeholder: "1.4.0", identity: false },
  { key: "user", label: "End user", placeholder: "exact value", identity: true },
  { key: "traceTag", label: "Tag", placeholder: "beta", identity: true },
  { key: "meta", label: "Metadata", placeholder: "key or key:value", identity: true },
];

// ExplorerFilterBar edits a draft and hands the whole set to onChange when
// the user presses Enter or Apply, so typing does not refetch per key.
// identityNote, when set, is shown beside the end user / tag / metadata /
// content inputs (the org says they need read:content). Drawn with the
// shared Input, Toggle and Button (design pass 2026-11-21).
export function ExplorerFilterBar({
  value,
  onChange,
  identityNote,
  contentAvailable = true,
}: {
  value: PlaneAExplorerFilters;
  onChange: (f: PlaneAExplorerFilters) => void;
  identityNote?: string;
  contentAvailable?: boolean;
}) {
  const [draft, setDraft] = useState<PlaneAExplorerFilters>(value);
  useEffect(() => setDraft(value), [value]);
  const apply = () => onChange(draft);
  const set = (k: keyof PlaneAExplorerFilters, v: string | boolean) => setDraft((d) => ({ ...d, [k]: v }));
  return (
    <form
      className="flex flex-wrap items-center gap-2 text-[12px]"
      onSubmit={(e) => {
        e.preventDefault();
        apply();
      }}
      aria-label="Explorer filters"
    >
      <Input
        value={draft.q}
        onChange={(e) => set("q", e.target.value)}
        placeholder="Search span names"
        aria-label="Search span names"
        className="w-48"
      />
      {contentAvailable && (
        <span title={identityNote}>
          <Toggle on={draft.content} onChange={(v) => set("content", v)} label="Include stored content" />
        </span>
      )}
      {textFields.map((f) => (
        <Input
          key={f.key}
          value={draft[f.key] as string}
          onChange={(e) => set(f.key, e.target.value)}
          placeholder={`${f.label}: ${f.placeholder}`}
          aria-label={f.label}
          title={f.identity ? identityNote : undefined}
          className="w-36"
        />
      ))}
      <Button type="submit" size="sm" variant="secondary">
        Apply
      </Button>
      {explorerFiltersActive(value) && (
        <Button size="sm" variant="ghost" onClick={() => onChange(emptyExplorerFilters)}>
          Clear search
        </Button>
      )}
      {identityNote && <span className="text-[11px] text-fg-3">{identityNote}</span>}
    </form>
  );
}

// Trace group-by modes the explorer adds (W3-4); "tag" and "metadata" group
// raw customer text and on the org need read:content.
export const explorerGroupModes: { value: string; label: string }[] = [
  { value: "service", label: "Service" },
  { value: "environment", label: "Environment" },
  { value: "release", label: "Release" },
  { value: "tag", label: "Tag" },
  { value: "metadata", label: "Metadata key" },
];

// explorerValueOptions is a filter chip's option list over the values the
// server listed for a field (end users, services, sessions): an "any"
// sentinel first, then each value. A current value the list does not carry
// (a deep link, a value outside the window) stays selectable, so a chip
// never shows a filter it cannot also clear. Pure.
export function explorerValueOptions(values: readonly string[], current: string, anyLabel: string): ComboOption[] {
  const seen = new Set<string>();
  const list: string[] = [];
  for (const v of values) {
    if (v && !seen.has(v)) {
      seen.add(v);
      list.push(v);
    }
  }
  if (current && !seen.has(current)) list.unshift(current);
  return [
    { value: "", label: anyLabel, searchable: `any all ${anyLabel.toLowerCase()}` },
    ...list.map((v) => ({ value: v, label: v, searchable: v.toLowerCase() })),
  ];
}

// ExplorerSearchInput is a filter row's free-text search at chip height: it
// edits a draft and hands it to onSubmit on Enter (typing does not refetch
// per key); the clear button submits "".
export function ExplorerSearchInput({
  value,
  onSubmit,
  placeholder,
  ariaLabel,
  className,
}: {
  value: string;
  onSubmit: (q: string) => void;
  placeholder: string;
  ariaLabel?: string;
  className?: string;
}) {
  const [draft, setDraft] = useState(value);
  useEffect(() => setDraft(value), [value]);
  return (
    <form
      role="search"
      className={`flex h-7 items-center gap-1.5 rounded-2 border bg-bg-2 px-2 text-[11.5px] focus-within:border-accent ${
        value ? "border-accent/50" : "border-line-2"
      } ${className ?? "w-full sm:w-56"}`}
      onSubmit={(e) => {
        e.preventDefault();
        onSubmit(draft.trim());
      }}
    >
      <Icon icon={Search} size={11} className="shrink-0 text-fg-3" />
      <input
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        placeholder={placeholder}
        aria-label={ariaLabel ?? placeholder}
        className="min-w-0 flex-1 bg-transparent text-fg-1 placeholder:text-fg-4 focus:outline-none"
      />
      {(draft || value) && (
        <button
          type="button"
          aria-label="Clear the search"
          className="shrink-0 text-fg-3 hover:text-fg-1"
          onClick={() => {
            setDraft("");
            onSubmit("");
          }}
        >
          <Icon icon={X} size={11} />
        </button>
      )}
    </form>
  );
}
