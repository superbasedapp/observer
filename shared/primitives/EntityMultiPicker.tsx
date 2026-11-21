import {
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent as ReactKeyboardEvent,
  type ReactNode,
} from "react";
import clsx from "clsx";
import type { LucideIcon } from "lucide-react";
import { ChevronDown, X } from "lucide-react";
import { Icon } from "./Icon";
import { Spinner } from "./Spinner";
import { chipIdHint } from "../lib/chipId";
import { STABLE_SCROLL_Y } from "../lib/scroll";

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
// to `onChange` (and, for a server-side search, `onQueryChange`). Dark/light
// entirely through design tokens (bg-*/fg-*/line-*/accent), so it never needs
// its own theme branch.
//
// `allowFreeId`: when a list is only PARTIAL (an admin/read gate hid part of
// the roster, or the org has more rows than the caller fetched), typing an id
// nothing in `options` matches and pressing Enter adds it verbatim. This is
// the honest replacement for the raw-id `<Input>` fallback those call sites
// used before this primitive existed — never a silent "can't find it, too
// bad".
//
// Agent Access UI lane 0b additions (all optional; every existing caller is
// unchanged): `loading` (a spinner row instead of "No matches." while the
// list loads), per-option `icon`, `group` (options render under a group
// header in first-appearance order, e.g. "Teams" / "Members" in one mixed
// subject picker) and `disabledReason` (listed, not pickable, reason shown),
// `notice` (a muted line at the top of the list, e.g. "Showing the first 50 -
// type to search"), and `onQueryChange` (the typed query, for a caller that
// searches server-side).
//
// It reads as a dropdown, not a text box (operator report 2026-11-06, the
// Code security Findings filters): a chevron at the right edge that turns
// while the list is open (clicking it while open closes the list), a
// pointer cursor and hover state on the closed field, and the ARIA 1.2
// combobox pattern on the input (role="combobox", aria-expanded,
// aria-controls and aria-activedescendant over the role="listbox" list,
// whose options are not tab stops). A click or focus opens the list, as
// does typing, ArrowDown or Enter; Escape and Tab close it.
export interface EntityMultiPickerOption {
  id: string;
  label: string;
  sublabel?: string;
  /** Optional leading glyph (a person, a team, a server...). */
  icon?: LucideIcon;
  /** Optional group header this option renders under. */
  group?: string;
  /** When set the option is listed but cannot be picked; the reason shows. */
  disabledReason?: string;
}

/**
 * enterRow is the row Enter commits (-1: none). Without explicitPick it is
 * the highlighted row, the first candidate until the person moves. With
 * explicitPick (a list of SUGGESTIONS beside a free value, such as the
 * Folder Selection allow-list: RERUN2 D5) Enter commits a suggestion only
 * after the person moved the highlight onto it with the arrow keys;
 * otherwise it commits the typed free value, or nothing, so an untouched
 * Enter can never add a suggestion the person did not choose.
 */
export function enterRow(s: {
  activeIdx: number;
  moved: boolean;
  pickableLen: number;
  hasFree: boolean;
  explicitPick: boolean;
}): number {
  const rows = s.pickableLen + (s.hasFree ? 1 : 0);
  if (rows === 0) return -1;
  if (!s.explicitPick || s.moved) return Math.min(Math.max(s.activeIdx, 0), rows - 1);
  return s.hasFree ? s.pickableLen : -1;
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
  loading = false,
  loadingHint = "Loading…",
  notice,
  onQueryChange,
  freeIdLabel = "Use id",
  ariaLabel,
  hideIds = false,
  clearable = true,
  explicitPick = false,
}: {
  options: EntityMultiPickerOption[];
  value: string[];
  onChange: (next: string[]) => void;
  placeholder?: string;
  disabled?: boolean;
  /** Beyond this many chips, the rest collapse into one "+N more" pill. */
  maxVisibleChips?: number;
  allowFreeId?: boolean;
  emptyHint?: ReactNode;
  className?: string;
  single?: boolean;
  /** The option list is still loading: show a spinner row, not emptyHint. */
  loading?: boolean;
  loadingHint?: ReactNode;
  /** A muted line rendered at the top of the open list. */
  notice?: ReactNode;
  /** Called with the typed query on every change (server-side search). */
  onQueryChange?: (query: string) => void;
  /** The free-id row's verb (default "Use id"). */
  freeIdLabel?: string;
  /** Accessible name for the search input. */
  ariaLabel?: string;
  /** hideIds keeps option ids out of sight (chips and the list): for a
   * closed vocabulary whose ids are internal names, not something a person
   * recognises. The id is still what onChange reports. */
  hideIds?: boolean;
  /** clearable (default true) lets a person remove a pick (the chip's x and
   * Backspace). False is for a value that must always be set: no x, no
   * Backspace removal, and in `single` mode the search input stays so the
   * pick can still be replaced by mouse or keyboard. */
  clearable?: boolean;
  /** explicitPick: Enter commits a suggestion only after the person moved
   * onto it with the arrow keys (enterRow); a click always picks. */
  explicitPick?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [activeIdx, setActiveIdx] = useState(0);
  // moved: the person moved the highlight with the arrow keys since the
  // list opened or the query last changed (explicitPick's Enter rule).
  const [moved, setMoved] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  // The list's and each option row's DOM ids (aria-controls and
  // aria-activedescendant), as ComboChip spells them.
  const uid = useId().replace(/:/g, "");
  const listId = `picker-${uid}-list`;
  const optId = (i: number) => `picker-${uid}-opt-${i}`;

  const byID = useMemo(() => {
    const m = new Map<string, EntityMultiPickerOption>();
    for (const o of options) m.set(o.id, o);
    return m;
  }, [options]);

  // Candidates exclude already-picked ids (you pick each entity once) and
  // filter on label + sublabel + id substring match — the same three-field
  // search ComboChip's `searchable` convention covers, done here directly
  // since an entity option carries a fixed shape rather than a caller-built
  // string. With groups, candidates are ordered group by group (first
  // appearance), so the keyboard order matches what is drawn.
  const selected = new Set(value);
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    const hits = options.filter((o) => {
      if (selected.has(o.id)) return false;
      if (!q) return true;
      return (
        o.label.toLowerCase().includes(q) ||
        (o.sublabel ?? "").toLowerCase().includes(q) ||
        o.id.toLowerCase().includes(q)
      );
    });
    return orderByGroup(hits);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [options, query, value]);
  // Only enabled candidates take part in keyboard navigation.
  const pickable = useMemo(() => filtered.filter((o) => !o.disabledReason), [filtered]);
  const pickIndex = useMemo(() => {
    const m = new Map<string, number>();
    pickable.forEach((o, i) => m.set(o.id, i));
    return m;
  }, [pickable]);

  // A free id is offered only when nothing in `options` — filtered or not —
  // already carries that exact id, so allowFreeId can never shadow a real
  // entity the caller's list already resolved.
  const trimmedQuery = query.trim();
  const freeIDCandidate =
    allowFreeId && trimmedQuery !== "" && !byID.has(trimmedQuery) && !selected.has(trimmedQuery)
      ? trimmedQuery
      : null;
  const rowCount = pickable.length + (freeIDCandidate ? 1 : 0);

  useEffect(() => {
    if (open) {
      setActiveIdx(0);
      setMoved(false);
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
    onQueryChange?.("");
    setActiveIdx(0);
    if (single) setOpen(false);
  }

  function removeAt(idx: number) {
    const next = value.slice();
    next.splice(idx, 1);
    onChange(next);
  }

  function selectRow(i: number) {
    if (i < pickable.length) {
      add(pickable[i].id);
      return;
    }
    if (freeIDCandidate && i === pickable.length) {
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
      setMoved(true);
      setActiveIdx((i) => Math.min(i + 1, Math.max(rowCount - 1, 0)));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setMoved(true);
      setActiveIdx((i) => Math.max(i - 1, 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      // A closed list opens on Enter, like a select: a row nobody can see
      // is never picked.
      if (!open) {
        setOpen(true);
        return;
      }
      const row = enterRow({ activeIdx, moved, pickableLen: pickable.length, hasFree: freeIDCandidate !== null, explicitPick });
      if (row >= 0) selectRow(row);
    } else if (e.key === "Tab") {
      // Tab leaves the combobox (the rows are not tab stops); close behind it.
      setOpen(false);
    } else if (e.key === "Escape") {
      // An open list owns Escape: close it and mark the key handled so an
      // enclosing SlideOver / Modal stays open (shared/lib/overlayEscape.ts).
      // A closed picker leaves Escape to the overlay.
      if (!open) return;
      e.preventDefault();
      e.stopPropagation();
      setOpen(false);
    } else if (e.key === "Backspace" && clearable && query === "" && value.length > 0) {
      // Backspace on an empty input removes the last chip — the standard
      // tag-input affordance, so a mis-pick is one keystroke to undo.
      e.preventDefault();
      removeAt(value.length - 1);
    }
  }

  const visibleCount =
    maxVisibleChips && value.length > maxVisibleChips ? maxVisibleChips : value.length;
  const overflow = value.length - visibleCount;

  let lastGroup: string | undefined;
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
          "relative flex min-h-[34px] w-full flex-wrap items-center gap-1.5 rounded-2 border bg-bg-2 py-1.5 pl-2 pr-7 text-[12.5px] transition-colors",
          disabled ? "cursor-not-allowed opacity-60" : "cursor-pointer",
          open ? "border-accent" : disabled ? "border-line-2" : "border-line-2 hover:border-line-3 hover:bg-bg-3",
        )}
      >
        {value.slice(0, visibleCount).map((id, idx) => {
          const opt = byID.get(id);
          // The id is a muted hint: hidden when it equals the label,
          // shortened when long; the full id is in the chip's tooltip.
          const idHint = hideIds ? null : chipIdHint(id, opt?.label);
          return (
            <span
              key={id}
              title={hideIds ? (opt?.label ?? id) : opt?.label && opt.label !== id ? `${opt.label} (${id})` : id}
              className="inline-flex max-w-full items-center gap-1 rounded-2 border border-line-2 bg-bg-1 px-1.5 py-0.5"
            >
              {opt?.icon && <Icon icon={opt.icon} size={11} className="shrink-0 text-fg-3" />}
              <span className="min-w-0 truncate text-fg-1">{opt?.label ?? id}</span>
              {idHint ? (
                <span className="shrink-0 font-mono text-[10px] text-fg-4">{idHint}</span>
              ) : null}
              {!disabled && clearable && (
                <button
                  type="button"
                  aria-label={`Remove ${opt?.label ?? id}`}
                  onClick={(e) => {
                    e.stopPropagation();
                    removeAt(idx);
                  }}
                  className="text-fg-3 hover:text-danger"
                >
                  <Icon icon={X} size={10} />
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
        {(!single || value.length === 0 || !clearable) && (
          <input
            ref={inputRef}
            type="text"
            role="combobox"
            aria-haspopup="listbox"
            aria-expanded={open && !disabled}
            aria-controls={open && !disabled ? listId : undefined}
            aria-autocomplete="list"
            aria-activedescendant={open && !disabled && activeIdx < rowCount ? optId(activeIdx) : undefined}
            disabled={disabled}
            value={query}
            aria-label={ariaLabel}
            onFocus={() => setOpen(true)}
            onChange={(e) => {
              setQuery(e.target.value);
              onQueryChange?.(e.target.value);
              setOpen(true);
              setActiveIdx(0);
              setMoved(false);
            }}
            onKeyDown={onKey}
            data-explicit-pick={explicitPick ? "true" : undefined}
            placeholder={value.length === 0 ? placeholder : ""}
            className={clsx(
              "min-w-[80px] flex-1 border-none bg-transparent text-fg-1 outline-none placeholder:text-fg-4",
              disabled ? "cursor-not-allowed" : open ? "cursor-text" : "cursor-pointer",
            )}
          />
        )}
        {/* The dropdown affordance. A click on it while the list is open
            closes the list; otherwise the click reaches the field, which
            opens it. Decorative to assistive tech: the input carries the
            combobox role and its aria-expanded state. */}
        <span
          aria-hidden
          data-picker-chevron
          onMouseDown={(e) => e.preventDefault()}
          onClick={(e) => {
            if (!open) return;
            e.stopPropagation();
            setOpen(false);
          }}
          className="absolute inset-y-0 right-0 flex w-7 items-center justify-center text-fg-3"
        >
          <Icon icon={ChevronDown} size={12} className={clsx("transition-transform", open && !disabled && "rotate-180")} />
        </span>
      </div>

      {open && !disabled && (
        <div
          id={listId}
          className="absolute left-0 top-[calc(100%+4px)] z-50 w-full min-w-[220px] overflow-hidden rounded-3 border border-line-2 bg-bg-1 shadow-drawer"
          role="listbox"
          aria-label={ariaLabel}
          aria-multiselectable={!single}
          aria-busy={loading || undefined}
        >
          <div ref={listRef} className={clsx("max-h-[280px] py-1", STABLE_SCROLL_Y)} tabIndex={-1}>
            {notice && <p className="px-3 pb-1 pt-1.5 text-[10.5px] text-fg-3">{notice}</p>}
            {filtered.length === 0 && !freeIDCandidate ? (
              loading ? (
                <p className="flex items-center gap-2 px-3 py-3 text-[11px] text-fg-3" role="status">
                  <Spinner size={12} label="" />
                  {loadingHint}
                </p>
              ) : (
                <p className="px-3 py-3 text-[11px] text-fg-3">{emptyHint}</p>
              )
            ) : (
              <>
                {filtered.map((o) => {
                  const header =
                    o.group !== undefined && o.group !== lastGroup ? (
                      <p
                        key={`group:${o.group}`}
                        className="px-2.5 pb-0.5 pt-2 text-[10px] font-semibold uppercase tracking-[0.06em] text-fg-3"
                      >
                        {o.group}
                      </p>
                    ) : null;
                  lastGroup = o.group;
                  if (o.disabledReason) {
                    return (
                      <div key={o.id}>
                        {header}
                        <div
                          role="option"
                          aria-selected={false}
                          aria-disabled
                          title={o.disabledReason}
                          className="flex w-full cursor-not-allowed items-start gap-2 px-2.5 py-1.5 text-left text-[11.5px] opacity-60"
                        >
                          {o.icon && <Icon icon={o.icon} size={12} className="mt-0.5 shrink-0 text-fg-3" />}
                          <span className="flex min-w-0 flex-col">
                            <span className="w-full truncate text-fg-2">{o.label}</span>
                            <span className="w-full truncate text-[10px] text-fg-3">{o.disabledReason}</span>
                          </span>
                        </div>
                      </div>
                    );
                  }
                  const i = pickIndex.get(o.id) ?? 0;
                  return (
                    <div key={o.id}>
                      {header}
                      <button
                        type="button"
                        id={optId(i)}
                        data-idx={i}
                        role="option"
                        tabIndex={-1}
                        aria-selected={false}
                        onMouseEnter={() => setActiveIdx(i)}
                        onClick={() => selectRow(i)}
                        className={clsx(
                          "flex w-full items-start gap-2 px-2.5 py-1.5 text-left text-[11.5px] transition-colors",
                          i === activeIdx ? "bg-bg-3" : "bg-transparent",
                        )}
                      >
                        {o.icon && <Icon icon={o.icon} size={12} className="mt-0.5 shrink-0 text-fg-3" />}
                        <span className="flex min-w-0 flex-1 flex-col">
                          <span className="w-full truncate text-fg-1">{o.label}</span>
                          <span className="w-full truncate font-mono text-[10px] text-fg-3">
                            {hideIds ? (o.sublabel ?? "") : o.sublabel ? `${o.sublabel} · ${o.id}` : o.id}
                          </span>
                        </span>
                      </button>
                    </div>
                  );
                })}
                {loading && (
                  <p className="flex items-center gap-2 px-3 py-1.5 text-[10.5px] text-fg-3" role="status">
                    <Spinner size={10} label="" />
                    {loadingHint}
                  </p>
                )}
                {freeIDCandidate && (
                  <button
                    type="button"
                    id={optId(pickable.length)}
                    data-idx={pickable.length}
                    role="option"
                    tabIndex={-1}
                    aria-selected={false}
                    onMouseEnter={() => setActiveIdx(pickable.length)}
                    onClick={() => selectRow(pickable.length)}
                    className={clsx(
                      "flex w-full items-center gap-1.5 px-2.5 py-1.5 text-left text-[11.5px] transition-colors",
                      activeIdx === pickable.length ? "bg-bg-3" : "bg-transparent",
                    )}
                  >
                    <span className="text-fg-3">{freeIdLabel}</span>
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

/** orderByGroup keeps ungrouped options first (in their order), then each
 *  group's options together in the order the group first appears. Stable. */
function orderByGroup(opts: EntityMultiPickerOption[]): EntityMultiPickerOption[] {
  if (!opts.some((o) => o.group !== undefined)) return opts;
  const order: (string | undefined)[] = [];
  for (const o of opts) if (!order.includes(o.group)) order.push(o.group);
  order.sort((a, b) => (a === undefined ? -1 : b === undefined ? 1 : 0));
  return order.flatMap((g) => opts.filter((o) => o.group === g));
}
