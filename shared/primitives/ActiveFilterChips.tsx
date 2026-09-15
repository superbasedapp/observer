import clsx from "clsx";
import { Tooltip } from "./Tooltip";

// ActiveFilterChips — generic active-filter strip. Pages compute the
// chips array (label + onClear per active filter) and pass it in. The
// primitive owns layout, styling, and the trailing "clear all" link.
// Mirrors `design/page-actions.jsx:114-125`.
export type FilterChip = {
  label: React.ReactNode;
  onClear: () => void;
  title?: string;
};

export function ActiveFilterChips({
  chips,
  onClearAll,
  className,
  caption = "active filters",
}: {
  chips: FilterChip[];
  onClearAll?: () => void;
  className?: string;
  caption?: string;
}) {
  if (chips.length === 0) return null;
  return (
    <div
      className={clsx(
        "flex flex-wrap items-center gap-1.5 border-b border-line-1 pb-2",
        className,
      )}
    >
      <span className="text-[10px] font-semibold uppercase tracking-[0.06em] text-fg-3">
        {caption}
      </span>
      {chips.map((c, i) => (
        <Tooltip key={i} content={c.title ?? "Remove filter"}>
          <button
            type="button"
            onClick={c.onClear}
            className="inline-flex items-center gap-1 rounded-pill border border-accent/40 bg-accent-soft px-2 py-0.5 text-[10.5px] text-accent transition-colors hover:bg-accent-soft/70"
          >
            {c.label}
            <span aria-hidden className="text-fg-3 hover:text-fg-1">
              ×
            </span>
          </button>
        </Tooltip>
      ))}
      {onClearAll && (
        <button
          type="button"
          onClick={onClearAll}
          className="ml-1 text-[10.5px] text-fg-3 underline-offset-2 hover:text-fg-1 hover:underline"
        >
          clear all
        </button>
      )}
    </div>
  );
}
