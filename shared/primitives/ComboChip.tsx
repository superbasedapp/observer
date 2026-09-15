import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import clsx from "clsx";
import { Tooltip } from "./Tooltip";

// ComboChip — filter-chip button + anchored popover combobox.
// Mirrors design/shell.jsx:155-166 + design/app.css:259-275: icon +
// label + value + optional swatch + chevron in the resting chip;
// popover lists options with type-to-filter and keyboard nav.
//
// Single-select; replace useState in parent. Empty/clear is modelled
// as a sentinel option in `options` (typically value="all"). Caller
// owns the option list — the chip just renders + filters + selects.

export type ComboOption = {
  value: string;
  label: ReactNode;
  // searchable: lower-cased text the type-ahead input matches against.
  // Pages should derive from label + value + side data so models like
  // "anthropic/claude-opus-4-7" match a search for "opus".
  searchable: string;
  // Optional adornment rendered before the label in the popover row.
  // Useful for ToolDot in the Tool filter.
  leading?: ReactNode;
  // Right-side aux text (e.g. action_count).
  rightMeta?: ReactNode;
  // Optional tooltip on the popover row.
  title?: string;
  // When true, the row renders dimmed/non-interactive: clicking or pressing
  // Enter on it is a no-op (the row stays visible with its `title` reason —
  // the honest-disabled-copy convention, never simply hidden). Mirrors a
  // native `<option disabled>`. Optional — every existing caller that never
  // sets this keeps its current always-selectable behavior.
  disabled?: boolean;
  // Optional group heading rendered once, above the first row in `options`
  // whose groupLabel differs from the row before it (mirrors a native
  // `<optgroup label>`). Rows without a groupLabel render ungrouped. Grouping
  // follows the ORDER options are given in — callers should pre-sort by
  // group.
  groupLabel?: string;
};

export function ComboChip({
  value,
  onChange,
  options,
  icon,
  label,
  className,
  popoverWidth = 320,
  placeholder = "Filter…",
  emptyHint = "No matches.",
  buttonValueRender,
  fullWidth = false,
}: {
  value: string;
  onChange: (next: string) => void;
  options: ComboOption[];
  icon?: ReactNode;
  label: string;
  className?: string;
  popoverWidth?: number;
  placeholder?: string;
  emptyHint?: string;
  // When set, overrides the default chip-value rendering. Receives the
  // currently-selected option (or `undefined` when the selected value
  // isn't in the options list). Lets ToolSelect render a ToolDot +
  // pretty label without coupling that detail into the primitive.
  buttonValueRender?: (selected: ComboOption | undefined) => ReactNode;
  // When true, the trigger stretches to fill its container width (space-
  // between label/value and the chevron) instead of the resting inline chip
  // size — for form-field contexts (a modal, a settings panel) where the
  // control should match the width of adjacent inputs. Default false keeps
  // every existing filter-bar caller pixel-identical.
  fullWidth?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [activeIdx, setActiveIdx] = useState(0);
  const rootRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  const selected = options.find((o) => o.value === value);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return options;
    return options.filter((o) => o.searchable.includes(q));
  }, [options, query]);

  // Reset state when the popover opens/closes so each open starts
  // fresh with the active row at the top (the first ENABLED row, so a
  // leading disabled group header row doesn't eat the first Enter).
  useEffect(() => {
    if (open) {
      setQuery("");
      const firstEnabled = options.findIndex((o) => !o.disabled);
      setActiveIdx(firstEnabled >= 0 ? firstEnabled : 0);
      // Focus the search input on next paint so the autofocus
      // doesn't fight the popover's mount animation.
      requestAnimationFrame(() => inputRef.current?.focus());
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  // Click-outside closes.
  useEffect(() => {
    if (!open) return;
    function onDown(e: MouseEvent) {
      if (!rootRef.current) return;
      if (!rootRef.current.contains(e.target as Node)) setOpen(false);
    }
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, [open]);

  // Keep the active option in view as the user navigates.
  useEffect(() => {
    if (!open || !listRef.current) return;
    const el = listRef.current.querySelector<HTMLButtonElement>(
      `[data-idx="${activeIdx}"]`,
    );
    el?.scrollIntoView({ block: "nearest" });
  }, [open, activeIdx]);

  function selectIdx(i: number) {
    const opt = filtered[i];
    // A disabled row (mirrors native `<option disabled>`) can be highlighted
    // via keyboard/hover but never actually chosen — no onChange, popover
    // stays open so the user can pick a different row.
    if (!opt || opt.disabled) return;
    onChange(opt.value);
    setOpen(false);
  }

  // nextEnabledIdx walks from `from` in `dir` (+1/-1), skipping disabled
  // rows, and returns the first enabled index found (or `from` unchanged if
  // every remaining row in that direction is disabled).
  function nextEnabledIdx(from: number, dir: 1 | -1): number {
    let i = from;
    while (i + dir >= 0 && i + dir <= filtered.length - 1) {
      i += dir;
      if (!filtered[i]?.disabled) return i;
    }
    return from;
  }

  function onKey(e: React.KeyboardEvent) {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActiveIdx((i) => nextEnabledIdx(Math.min(i, filtered.length - 1), 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActiveIdx((i) => nextEnabledIdx(i, -1));
    } else if (e.key === "Enter") {
      e.preventDefault();
      selectIdx(activeIdx);
    } else if (e.key === "Escape") {
      e.preventDefault();
      setOpen(false);
    }
  }

  return (
    <div ref={rootRef} className={clsx("relative", fullWidth && "w-full", className)}>
      <Tooltip
        content={`${label}: ${selected?.searchable ?? value}`}
        disabled={open}
      >
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-haspopup="listbox"
        aria-expanded={open}
        className={clsx(
          "flex h-7 items-center gap-1.5 rounded-2 border bg-bg-2 px-2 text-[11px] text-fg-1 transition-colors",
          fullWidth && "w-full justify-between",
          open
            ? "border-accent"
            : "border-line-2 hover:bg-bg-3 hover:text-fg-0",
        )}
      >
        <span className={clsx("flex min-w-0 items-center gap-1.5", fullWidth && "flex-1 truncate")}>
          {icon}
          <span className="text-fg-3">{label}</span>
          {buttonValueRender ? (
            buttonValueRender(selected)
          ) : (
            <b className={clsx("font-semibold text-fg-0", fullWidth && "min-w-0 truncate")}>
              {selected?.label ?? value}
            </b>
          )}
        </span>
        <ChevronDown />
      </button>
      </Tooltip>

      {open && (
        <div
          className={clsx(
            "absolute left-0 top-[calc(100%+4px)] z-50 overflow-hidden rounded-3 border border-line-2 bg-bg-1 shadow-drawer",
            fullWidth && "w-full",
          )}
          style={fullWidth ? undefined : { width: popoverWidth }}
          role="listbox"
          aria-label={label}
        >
          <div className="border-b border-line-1 bg-bg-2/60 px-2 py-1.5">
            <input
              ref={inputRef}
              type="search"
              value={query}
              onChange={(e) => {
                setQuery(e.target.value);
                setActiveIdx(0);
              }}
              onKeyDown={onKey}
              placeholder={placeholder}
              className="h-7 w-full appearance-none rounded-2 border border-line-2 bg-bg-1 px-2 text-[11px] text-fg-1 placeholder:text-fg-4 focus:border-accent focus:outline-none"
            />
          </div>
          <div
            ref={listRef}
            className="max-h-[280px] overflow-y-auto py-1"
            onKeyDown={onKey}
            tabIndex={-1}
          >
            {filtered.length === 0 ? (
              <p className="px-3 py-3 text-[11px] text-fg-3">{emptyHint}</p>
            ) : (
              filtered.map((o, i) => {
                const sel = o.value === value;
                const active = i === activeIdx;
                // A group header renders once, right before the first row
                // whose groupLabel differs from the previous (filtered) row's
                // — mirrors a native <optgroup label>. Rows without a
                // groupLabel never trigger a header.
                const prevGroup = i > 0 ? filtered[i - 1].groupLabel : undefined;
                const showGroupHeader = !!o.groupLabel && o.groupLabel !== prevGroup;
                return (
                  <div key={o.value}>
                    {showGroupHeader && (
                      <div className="mt-1 px-2.5 pb-1 pt-1.5 text-[10px] font-medium uppercase tracking-wide text-fg-4 first:mt-0">
                        {o.groupLabel}
                      </div>
                    )}
                    <Tooltip content={o.title ?? null} side="right" disabled={!o.title}>
                    <button
                      type="button"
                      data-idx={i}
                      role="option"
                      aria-selected={sel}
                      aria-disabled={o.disabled}
                      onMouseEnter={() => setActiveIdx(i)}
                      onClick={() => selectIdx(i)}
                      className={clsx(
                        "flex w-full items-center gap-2 px-2.5 py-1.5 text-left text-[11.5px] transition-colors",
                        o.disabled
                          ? "cursor-not-allowed text-fg-4 opacity-50"
                          : [
                              active ? "bg-bg-3" : "bg-transparent",
                              sel ? "text-accent" : "text-fg-1",
                            ],
                      )}
                    >
                      {o.leading}
                      <span className="min-w-0 flex-1 truncate">{o.label}</span>
                      {o.rightMeta && (
                        <span className="shrink-0 font-mono text-[10.5px] text-fg-3">
                          {o.rightMeta}
                        </span>
                      )}
                      {sel && !o.disabled && <CheckIcon />}
                    </button>
                    </Tooltip>
                  </div>
                );
              })
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function ChevronDown() {
  return (
    <svg
      width="10"
      height="10"
      viewBox="0 0 16 16"
      fill="none"
      aria-hidden
      className="ml-0.5 text-fg-3"
    >
      <path
        d="m4 6 4 4 4-4"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function CheckIcon() {
  return (
    <svg
      width="11"
      height="11"
      viewBox="0 0 16 16"
      fill="none"
      aria-hidden
      className="shrink-0 text-accent"
    >
      <path
        d="m3.5 8.5 3 3 6-6"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}
