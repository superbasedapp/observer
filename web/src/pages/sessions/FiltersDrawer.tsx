import { useEffect, useState } from "react";
import clsx from "clsx";
import { SegmentedControl, SlideOver, Toggle, Tooltip } from "@/components/primitives";
import { shortModel } from "@/lib/models";
import type { Reliability, SessionRow } from "@/lib/types";

// SessionFilters — drawer-managed filter state. Applied locally to
// the page's loaded rows (the backend filters tool / project / days
// server-side; everything else needs the cost-engine join to be
// present, which only happens post-fetch). The chip strip + drawer
// header copy both say "narrows the loaded page" so the operator
// knows widening the window is the way to broaden the visible set.
export type DurationBucket = "any" | "short" | "medium" | "long" | "xlong";
export type SidechainFilter = "any" | "with" | "without";
export type ReliabilityFilter = "any" | Reliability;

export type SessionFilters = {
  models: string[];
  minCostUsd: string;
  maxCostUsd: string;
  minActions: string;
  maxActions: string;
  duration: DurationBucket;
  sidechain: SidechainFilter;
  reliability: ReliabilityFilter;
};

export const EMPTY_FILTERS: SessionFilters = {
  models: [],
  minCostUsd: "",
  maxCostUsd: "",
  minActions: "",
  maxActions: "",
  duration: "any",
  sidechain: "any",
  reliability: "any",
};

const STORAGE_KEY = "sb:sessions:filters:v1";

export function loadFilters(): SessionFilters {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return EMPTY_FILTERS;
    const parsed = JSON.parse(raw) as Partial<SessionFilters>;
    return { ...EMPTY_FILTERS, ...parsed, models: parsed.models ?? [] };
  } catch {
    return EMPTY_FILTERS;
  }
}

export function saveFilters(f: SessionFilters): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(f));
  } catch {
    // localStorage may be unavailable (private mode, quota); ignore.
  }
}

export function activeFilterCount(f: SessionFilters): number {
  let n = 0;
  if (f.models.length > 0) n += 1;
  if (f.minCostUsd.trim() !== "" || f.maxCostUsd.trim() !== "") n += 1;
  if (f.minActions.trim() !== "" || f.maxActions.trim() !== "") n += 1;
  if (f.duration !== "any") n += 1;
  if (f.sidechain !== "any") n += 1;
  if (f.reliability !== "any") n += 1;
  return n;
}

// Apply drawer filters to the loaded sessions page. Filtering is
// linear over the page; the page is capped at PAGE_LIMIT so this is
// cheap. ANDs with the row-search text filter applied separately in
// Sessions.tsx.
export function applyFilters(
  rows: SessionRow[],
  f: SessionFilters,
): SessionRow[] {
  const minCost = parseNum(f.minCostUsd);
  const maxCost = parseNum(f.maxCostUsd);
  const minAct = parseNum(f.minActions);
  const maxAct = parseNum(f.maxActions);
  const [durMin, durMax] = durationRange(f.duration);
  const models = new Set(f.models);
  return rows.filter((r) => {
    if (models.size > 0) {
      const hit = (r.models ?? []).some((m) => models.has(m));
      if (!hit) return false;
    }
    if (minCost != null && r.cost_usd < minCost) return false;
    if (maxCost != null && r.cost_usd > maxCost) return false;
    if (minAct != null && r.total_actions < minAct) return false;
    if (maxAct != null && r.total_actions > maxAct) return false;
    if (durMin != null && r.duration_seconds < durMin) return false;
    if (durMax != null && r.duration_seconds > durMax) return false;
    if (f.sidechain === "with" && r.sidechain_action_count <= 0) return false;
    if (f.sidechain === "without" && r.sidechain_action_count > 0) return false;
    if (f.reliability !== "any") {
      if ((r.cost_reliability ?? "") !== f.reliability) return false;
    }
    return true;
  });
}

function parseNum(s: string): number | null {
  const t = s.trim();
  if (!t) return null;
  const v = Number(t);
  return Number.isFinite(v) ? v : null;
}

function durationRange(b: DurationBucket): [number | null, number | null] {
  switch (b) {
    case "short":
      return [0, 5 * 60];
    case "medium":
      return [5 * 60, 30 * 60];
    case "long":
      return [30 * 60, 2 * 60 * 60];
    case "xlong":
      return [2 * 60 * 60, null];
    default:
      return [null, null];
  }
}

// SessionsFiltersDrawer — slide-over form. Draft state is local so
// the user can preview a combination before committing; Apply pushes
// the draft to the page-level filter state + closes; Reset returns
// the draft to EMPTY_FILTERS; the page-level Clear is on the chip
// strip outside the drawer.
export function SessionsFiltersDrawer({
  open,
  onClose,
  value,
  onApply,
  availableModels,
}: {
  open: boolean;
  onClose: () => void;
  value: SessionFilters;
  onApply: (next: SessionFilters) => void;
  availableModels: string[];
}) {
  const [draft, setDraft] = useState<SessionFilters>(value);
  // Reset draft to committed value whenever the drawer reopens so the
  // user always starts from "what's currently applied".
  useEffect(() => {
    if (open) setDraft(value);
  }, [open, value]);

  const set = <K extends keyof SessionFilters>(
    k: K,
    v: SessionFilters[K],
  ) => setDraft((d) => ({ ...d, [k]: v }));

  const toggleModel = (m: string) => {
    setDraft((d) => {
      const has = d.models.includes(m);
      return {
        ...d,
        models: has ? d.models.filter((x) => x !== m) : [...d.models, m],
      };
    });
  };

  return (
    <SlideOver
      open={open}
      onClose={onClose}
      width={520}
      title="Filter sessions"
      subtitle="Narrows the loaded page below - widen Window for more results"
    >
      <div className="flex h-full flex-col">
        <div className="flex-1 space-y-5 overflow-y-auto px-5 py-4 text-[12px]">
          <Group label="Models" hint={modelHint(availableModels.length)}>
            {availableModels.length === 0 ? (
              <p className="text-[11px] text-fg-3">
                No model strings in the loaded page. Sessions captured before
                the proxy / JSONL model field landed render as Models = -.
              </p>
            ) : (
              <div className="flex flex-wrap gap-1.5">
                {availableModels.map((m) => {
                  const on = draft.models.includes(m);
                  return (
                    <Tooltip
                      key={m}
                      content={<span className="break-all font-mono">{m}</span>}
                      maxWidth={360}
                    >
                      <button
                        type="button"
                        onClick={() => toggleModel(m)}
                        className={clsx(
                          "rounded-pill border px-2 py-0.5 font-mono text-[10.5px] transition-colors",
                          on
                            ? "border-accent bg-accent-soft text-accent"
                            : "border-line-2 bg-bg-2 text-fg-2 hover:bg-bg-3",
                        )}
                      >
                        {shortModel(m)}
                      </button>
                    </Tooltip>
                  );
                })}
              </div>
            )}
          </Group>

          <Group label="Total cost (USD)">
            <div className="flex items-center gap-2">
              <RangeInput
                value={draft.minCostUsd}
                onChange={(v) => set("minCostUsd", v)}
                placeholder="min"
              />
              <span className="text-fg-4">-</span>
              <RangeInput
                value={draft.maxCostUsd}
                onChange={(v) => set("maxCostUsd", v)}
                placeholder="max"
              />
            </div>
          </Group>

          <Group label="Actions per session">
            <div className="flex items-center gap-2">
              <RangeInput
                value={draft.minActions}
                onChange={(v) => set("minActions", v)}
                placeholder="min"
              />
              <span className="text-fg-4">-</span>
              <RangeInput
                value={draft.maxActions}
                onChange={(v) => set("maxActions", v)}
                placeholder="max"
              />
            </div>
          </Group>

          <Group label="Duration">
            <SegmentedControl<DurationBucket>
              options={[
                { value: "any", label: "Any" },
                { value: "short", label: "<5m" },
                { value: "medium", label: "5–30m" },
                { value: "long", label: "30m–2h" },
                { value: "xlong", label: ">2h" },
              ]}
              value={draft.duration}
              onChange={(v) => set("duration", v)}
              size="sm"
            />
          </Group>

          <Group
            label="Sidechain (sub-agent fan-out)"
            hint="Sessions whose actions spawned sub-agents via Claude Code's Agent tool"
          >
            <SegmentedControl<SidechainFilter>
              options={[
                { value: "any", label: "Any" },
                { value: "with", label: "With sidechain" },
                { value: "without", label: "No sidechain" },
              ]}
              value={draft.sidechain}
              onChange={(v) => set("sidechain", v)}
              size="sm"
            />
          </Group>

          <Group
            label="Cost reliability"
            hint="Worst-case reliability across the rows that fed the session totals"
          >
            <div className="flex flex-wrap gap-1.5">
              {(["any", "proxy", "jsonl", "mixed", "scraped"] as const).map(
                (v) => (
                  <PillBtn
                    key={v}
                    on={draft.reliability === v}
                    onClick={() => set("reliability", v as ReliabilityFilter)}
                  >
                    {v}
                  </PillBtn>
                ),
              )}
            </div>
          </Group>

          <Group label="Active drawer filters">
            <div className="flex items-center justify-between">
              <span className="text-[11px] text-fg-3">
                {activeFilterCount(draft)} active
              </span>
              <Toggle
                label="Reset all"
                on={false}
                onChange={() => setDraft(EMPTY_FILTERS)}
              />
            </div>
          </Group>
        </div>

        <footer className="flex shrink-0 items-center justify-between gap-2 border-t border-line-1 bg-bg-2/60 px-5 py-3">
          <button
            type="button"
            onClick={() => setDraft(EMPTY_FILTERS)}
            className="rounded-2 border border-line-2 bg-bg-2 px-3 py-1.5 text-[11px] text-fg-2 hover:bg-bg-3"
          >
            Reset
          </button>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={onClose}
              className="rounded-2 border border-line-2 bg-bg-2 px-3 py-1.5 text-[11px] text-fg-2 hover:bg-bg-3"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={() => onApply(draft)}
              className="rounded-2 border border-accent bg-accent px-3 py-1.5 text-[11px] font-semibold text-accent-on hover:opacity-90"
            >
              Apply
            </button>
          </div>
        </footer>
      </div>
    </SlideOver>
  );
}

function Group({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <section>
      <label className="mb-1.5 block text-[10.5px] font-semibold uppercase tracking-[0.06em] text-fg-3">
        {label}
      </label>
      {hint && <p className="mb-2 text-[10.5px] text-fg-3">{hint}</p>}
      {children}
    </section>
  );
}

function RangeInput({
  value,
  onChange,
  placeholder,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
}) {
  return (
    <input
      type="number"
      inputMode="decimal"
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
      className="h-8 w-[110px] rounded-2 border border-line-2 bg-bg-2 px-2 font-mono text-[11px] tabular-nums text-fg-1 placeholder:text-fg-4 focus:border-accent focus:outline-none"
    />
  );
}

function PillBtn({
  on,
  onClick,
  children,
}: {
  on: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={clsx(
        "rounded-pill border px-2.5 py-0.5 text-[10.5px] transition-colors",
        on
          ? "border-accent bg-accent-soft text-accent"
          : "border-line-2 bg-bg-2 text-fg-2 hover:bg-bg-3",
      )}
    >
      {children}
    </button>
  );
}

function modelHint(n: number): string {
  if (n === 0) return "";
  return `${n} model${n === 1 ? "" : "s"} seen in loaded page`;
}
