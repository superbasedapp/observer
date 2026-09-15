import { useRef, type ReactNode } from "react";
import clsx from "clsx";

// TabStrip — the dashboard's one horizontal tab control.
//
// WHY A PRIMITIVE. The session-detail panel is the first surface to need
// tabs; SegmentedControl (the existing `role=tablist`) is a compact 2–3
// option pill toggle sized for a table header, not a top-level navigation
// bar. Rather than fork a second, private copy inside SessionDetailPanel,
// this lives here so the next surface that needs tabs extends ONE
// implementation (CLAUDE.md "fix systemically" / module-boundary rule 1).
//
// HONEST DISABLING. A tab may be disabled, and when it is, `disabledReason`
// is REQUIRED — it becomes the tooltip and must name the exact missing
// dependency, following the dashboard's standing honest-disabled-copy rule.
// A disabled tab with a vague reason is the same failure as a confident zero.
//
// MOBILE. The strip scrolls horizontally rather than wrapping: five tabs on a
// 360px-wide phone would otherwise become a two-row block that pushes the KPI
// band off-screen. `overflow-x-auto` + `whitespace-nowrap` + no shrink keeps
// it one row at every width; `scrollbar-none` is deliberately NOT used so a
// desktop trackpad user still sees the affordance if it overflows.

export type TabDef<T extends string> = {
  id: T;
  label: string;
  /** Optional trailing count (e.g. the message total). Rendered in mono. */
  count?: number | null;
  /** When true the tab is not selectable; `disabledReason` is then required. */
  disabled?: boolean;
  /** Names the exact missing dependency. Shown as the tab's title tooltip. */
  disabledReason?: string;
  /** Optional trailing dot, for "this tab has something notable". */
  dot?: "warn" | "danger" | null;
};

export function TabStrip<T extends string>({
  tabs,
  value,
  onChange,
  idPrefix,
  className,
}: {
  tabs: TabDef<T>[];
  value: T;
  onChange: (id: T) => void;
  /** Prefix for the generated `id` / `aria-controls` pair. */
  idPrefix: string;
  className?: string;
}): ReactNode {
  const stripRef = useRef<HTMLDivElement>(null);

  // Roving arrow-key navigation across the enabled tabs, per the WAI-ARIA
  // tabs pattern. Home/End jump to the ends.
  function onKeyDown(e: React.KeyboardEvent<HTMLDivElement>) {
    const usable = tabs.filter((t) => !t.disabled);
    if (usable.length === 0) return;
    const at = usable.findIndex((t) => t.id === value);
    let next = -1;
    if (e.key === "ArrowRight") next = (at + 1) % usable.length;
    else if (e.key === "ArrowLeft")
      next = (at - 1 + usable.length) % usable.length;
    else if (e.key === "Home") next = 0;
    else if (e.key === "End") next = usable.length - 1;
    if (next < 0) return;
    e.preventDefault();
    const target = usable[next];
    onChange(target.id);
    stripRef.current
      ?.querySelector<HTMLButtonElement>(`#${idPrefix}-tab-${target.id}`)
      ?.focus();
  }

  return (
    <div
      ref={stripRef}
      role="tablist"
      aria-label="Session detail sections"
      onKeyDown={onKeyDown}
      className={clsx(
        "flex items-stretch gap-0.5 overflow-x-auto border-b border-line-2",
        className,
      )}
    >
      {tabs.map((t) => {
        const active = t.id === value && !t.disabled;
        return (
          <button
            key={t.id}
            id={`${idPrefix}-tab-${t.id}`}
            type="button"
            role="tab"
            aria-selected={active}
            aria-controls={`${idPrefix}-panel-${t.id}`}
            aria-disabled={t.disabled || undefined}
            // Only the active tab is in the tab order; arrow keys move within
            // the strip (WAI-ARIA roving tabindex).
            tabIndex={active ? 0 : -1}
            disabled={t.disabled}
            title={t.disabled ? t.disabledReason : undefined}
            onClick={() => !t.disabled && onChange(t.id)}
            className={clsx(
              "shrink-0 whitespace-nowrap border-b-2 px-3 py-2 text-[12px] transition-colors focus:outline-none focus-visible:ring-1 focus-visible:ring-accent-ring",
              t.disabled
                ? "cursor-not-allowed border-transparent text-fg-4"
                : active
                  ? "border-accent font-semibold text-fg-0"
                  : "border-transparent text-fg-3 hover:text-fg-1",
            )}
          >
            {t.label}
            {t.count != null && (
              <span className="ml-1.5 font-mono text-[10px] text-fg-4 tabular-nums">
                {t.count}
              </span>
            )}
            {t.dot && (
              <span
                className={clsx(
                  "ml-1.5 inline-block h-1.5 w-1.5 rounded-full align-middle",
                  t.dot === "danger" ? "bg-danger" : "bg-warn",
                )}
              />
            )}
          </button>
        );
      })}
    </div>
  );
}
