import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent as ReactKeyboardEvent,
} from "react";
import clsx from "clsx";

// EntityMultiPicker — a type-to-filter combobox for picking SEVERAL entities
// by id, rendering each pick as a removable chip: label on top, the id as a
// muted mono sublabel underneath. Built for the org-observer fundamentals-fix
// plan §3 W4-1 (docs/plans/org-observer-fundamentals-fix-plan-2026-09-13.md):
// the multi-select primitive `shared/primitives/ComboChip.tsx` never had, and
// the honest replacement for a raw-id text `<Input>` wherever a form needs
// several teams/projects/members/models at once (Budgets bulk-create being
// the first caller).
//
// Pure, like ComboChip: no fetch, no state beyond the popover's own
// open/query/active-index — the caller owns `options` and `value` and reacts
// to `onChange`. Dark/light entirely through design tokens (bg-*/fg-*/
// line-*/accent), so it never needs its own theme branch.
//
// `allowFreeId`: when a list is only PARTIAL (an admin/read gate hid part of
// the roster, or the org has more rows than the caller fetched), typing an id
// nothing in `options` matches and pressing Enter adds it verbatim. This is
// the honest replacement for the raw-id `<Input>` fallback those call sites
// used before this primitive existed — never a silent "can't find it, too
// bad".
export interface EntityMultiPickerOption {
  id: string;
  label: string;
  sublabel?: string;
}

export function EntityMultiPicker({
  options,
  value,
  onChange,
  placeholder = "Type to search…",
  disabled,
  maxVisibleChips,
  allowFreeId = false,
  emptyHint = "No matches.",
  className,
  // single collapses the control to at most one selection — used to adopt
  // this primitive at a site that only ever needs one id today (Settings /
  // Policy / AIGateway's single-subject pickers, W4-5) without a second
  // component to maintain. Picking a new option while one is already
  // selected REPLACES it rather than adding a second chip.
  single = false,
}: {
  options: EntityMultiPickerOption[];
  value: string[];
  onChange: (next: string[]) => void;
  placeholder?: string;
  disabled?: boolean;
  /** Beyond this many chips, the rest collapse into one "+N more" pill. */
  maxVisibleChips?: number;
  allowFreeId?: boolean;
  emptyHint?: string;
  className?: string;
  single?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [activeIdx, setActiveIdx] = useState(0);
  const rootRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  const byID = useMemo(() => {
    const m = new Map<string, EntityMultiPickerOption>();
    for (const o of options) m.set(o.id, o);
    return m;
  }, [options]);

  // Candidates exclude already-picked ids (you pick each entity once) and
  // filter on label + sublabel + id substring match — the same three-field
  // search ComboChip's `searchable` convention covers, done here directly
  // since an entity option carries a fixed shape rather than a caller-built
  // string.
  const selected = new Set(value);
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return options.filter((o) => {
      if (selected.has(o.id)) return false;
      if (!q) return true;
      return (
        o.label.toLowerCase().includes(q) ||
        (o.sublabel ?? "").toLowerCase().includes(q) ||
        o.id.toLowerCase().includes(q)
      );
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [options, query, value]);

  // A free id is offered only when nothing in `options` — filtered or not —
  // already carries that exact id, so allowFreeId can never shadow a real
  // entity the caller's list already resolved.
  const trimmedQuery = query.trim();
  const freeIDCandidate =
    allowFreeId && trimmedQuery !== "" && !byID.has(trimmedQuery) && !selected.has(trimmedQuery)
      ? trimmedQuery
      : null;
  const rowCount = filtered.length + (freeIDCandidate ? 1 : 0);

  useEffect(() => {
    if (open) {
      setActiveIdx(0);
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [open]);

  useEffect(() => {
    if (!open) return;
    function onDown(e: MouseEvent) {
      if (!rootRef.current) return;
      if (!rootRef.current.contains(e.target as Node)) setOpen(false);
    }
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, [open]);

  useEffect(() => {
    if (!open || !listRef.current) return;
    const el = listRef.current.querySelector<HTMLButtonElement>(`[data-idx="${activeIdx}"]`);
    el?.scrollIntoView({ block: "nearest" });
  }, [open, activeIdx]);

  function add(id: string) {
    if (selected.has(id)) return;
    onChange(single ? [id] : [...value, id]);
    setQuery("");
    setActiveIdx(0);
    if (single) setOpen(false);
  }

  function removeAt(idx: number) {
    const next = value.slice();
    next.splice(idx, 1);
    onChange(next);
  }

  function selectRow(i: number) {
    if (i < filtered.length) {
      add(filtered[i].id);
      return;
    }
    if (freeIDCandidate && i === filtered.length) {
      add(freeIDCandidate);
    }
  }

  function onKey(e: ReactKeyboardEvent) {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      if (!open) {
        setOpen(true);
        return;
      }
      setActiveIdx((i) => Math.min(i + 1, Math.max(rowCount - 1, 0)));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActiveIdx((i) => Math.max(i - 1, 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      if (rowCount > 0) selectRow(activeIdx);
    } else if (e.key === "Escape") {
      e.preventDefault();
      setOpen(false);
    } else if (e.key === "Backspace" && query === "" && value.length > 0) {
      // Backspace on an empty input removes the last chip — the standard
      // tag-input affordance, so a mis-pick is one keystroke to undo.
      e.preventDefault();
      removeAt(value.length - 1);
    }
  }

  const visibleCount =
    maxVisibleChips && value.length > maxVisibleChips ? maxVisibleChips : value.length;
  const overflow = value.length - visibleCount;

  return (
    <div ref={rootRef} className={clsx("relative", className)}>
      <div
        onClick={() => {
          if (!disabled) {
            setOpen(true);
            inputRef.current?.focus();
          }
        }}
        className={clsx(
          "flex min-h-[34px] w-full flex-wrap items-center gap-1.5 rounded-2 border bg-bg-2 px-2 py-1.5 text-[12.5px]",
          disabled ? "cursor-not-allowed opacity-60" : "cursor-text",
          open ? "border-accent" : "border-line-2",
        )}
      >
        {value.slice(0, visibleCount).map((id, idx) => {
          const opt = byID.get(id);
          return (
            <span
              key={id}
              className="inline-flex max-w-full items-center gap-1 rounded-2 border border-line-2 bg-bg-1 px-1.5 py-0.5"
            >
              <span className="min-w-0 truncate text-fg-1">{opt?.label ?? id}</span>
              {opt?.label ? (
                <span className="min-w-0 truncate font-mono text-[10px] text-fg-3">{id}</span>
              ) : null}
              {!disabled && (
                <button
                  type="button"
                  aria-label={`Remove ${opt?.label ?? id}`}
                  onClick={(e) => {
                    e.stopPropagation();
                    removeAt(idx);
                  }}
                  className="text-fg-3 hover:text-danger"
                >
                  <RemoveIcon />
                </button>
              )}
            </span>
          );
        })}
        {overflow > 0 && (
          <span className="rounded-2 border border-line-2 bg-bg-1 px-1.5 py-0.5 text-[11px] text-fg-3">
            +{overflow} more
          </span>
        )}
        {(!single || value.length === 0) && (
          <input
            ref={inputRef}
            type="text"
            disabled={disabled}
            value={query}
            onFocus={() => setOpen(true)}
            onChange={(e) => {
              setQuery(e.target.value);
              setOpen(true);
              setActiveIdx(0);
            }}
            onKeyDown={onKey}
            placeholder={value.length === 0 ? placeholder : ""}
            className="min-w-[80px] flex-1 border-none bg-transparent text-fg-1 outline-none placeholder:text-fg-4"
          />
        )}
      </div>

      {open && !disabled && (
        <div
          className="absolute left-0 top-[calc(100%+4px)] z-50 w-full min-w-[220px] overflow-hidden rounded-3 border border-line-2 bg-bg-1 shadow-drawer"
          role="listbox"
          aria-multiselectable="true"
        >
          <div ref={listRef} className="max-h-[280px] overflow-y-auto py-1" tabIndex={-1}>
            {rowCount === 0 ? (
              <p className="px-3 py-3 text-[11px] text-fg-3">{emptyHint}</p>
            ) : (
              <>
                {filtered.map((o, i) => (
                  <button
                    key={o.id}
                    type="button"
                    data-idx={i}
                    role="option"
                    aria-selected={false}
                    onMouseEnter={() => setActiveIdx(i)}
                    onClick={() => selectRow(i)}
                    className={clsx(
                      "flex w-full flex-col items-start px-2.5 py-1.5 text-left text-[11.5px] transition-colors",
                      i === activeIdx ? "bg-bg-3" : "bg-transparent",
                    )}
                  >
                    <span className="w-full truncate text-fg-1">{o.label}</span>
                    <span className="w-full truncate font-mono text-[10px] text-fg-3">
                      {o.sublabel ? `${o.sublabel} · ${o.id}` : o.id}
                    </span>
                  </button>
                ))}
                {freeIDCandidate && (
                  <button
                    type="button"
                    data-idx={filtered.length}
                    role="option"
                    aria-selected={false}
                    onMouseEnter={() => setActiveIdx(filtered.length)}
                    onClick={() => selectRow(filtered.length)}
                    className={clsx(
                      "flex w-full items-center gap-1.5 px-2.5 py-1.5 text-left text-[11.5px] transition-colors",
                      activeIdx === filtered.length ? "bg-bg-3" : "bg-transparent",
                    )}
                  >
                    <span className="text-fg-3">Use id</span>
                    <span className="truncate font-mono text-fg-1">{freeIDCandidate}</span>
                  </button>
                )}
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function RemoveIcon() {
  return (
    <svg width="10" height="10" viewBox="0 0 16 16" fill="none" aria-hidden>
      <path
        d="M4 4l8 8M12 4l-8 8"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinecap="round"
      />
    </svg>
  );
}
