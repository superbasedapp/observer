import { useRef, useState } from "react";
import clsx from "clsx";
import { Columns3 } from "lucide-react";
import { Icon, Tooltip } from "@/components/primitives";
import { AnchoredPopover } from "@/components/primitives/AnchoredPopover";
import { costLabel } from "@/lib/format";
import {
  SESSION_COLUMNS,
  hiddenCount,
  toggleColumn,
  type ColumnOverrides,
  type ResolvedColumns,
  type SessionColumnSpec,
} from "@/lib/sessionColumns";

// pickerLabel is a column's name in the picker; Total $ follows the cost
// display, like its header.
export function pickerLabel(c: SessionColumnSpec): string {
  return c.id === "cost" ? costLabel(c.label, "Total tokens") : c.label;
}

// ColumnsPicker is the Sessions toolbar's column checklist: every optional
// column from the one column table (lib/sessionColumns), checked when it is
// on screen, with "no room" on a default column the fit rule dropped.
// Checking a column is an explicit choice the fit rule never overrides;
// Reset clears every choice. The page owns the choices and stores them.
export function ColumnsPicker({
  resolved,
  overrides,
  scoring,
  onChange,
}: {
  resolved: ResolvedColumns;
  overrides: ColumnOverrides;
  scoring: boolean;
  onChange: (next: ColumnOverrides) => void;
}) {
  const [open, setOpen] = useState(false);
  const triggerRef = useRef<HTMLButtonElement | null>(null);
  const hidden = hiddenCount(resolved);
  const rows = SESSION_COLUMNS.filter((c) => !c.locked && (scoring || !c.scoring));
  const chosen = Object.keys(overrides).length > 0;
  return (
    <>
      <Tooltip
        content={
          hidden > 0
            ? `Show or hide columns (${hidden} hidden). Hidden fields stay in each session's details.`
            : "Show or hide columns"
        }
        maxWidth={300}
      >
        <button
          ref={triggerRef}
          type="button"
          aria-haspopup="dialog"
          aria-expanded={open}
          onClick={() => setOpen((o) => !o)}
          className={clsx(
            "inline-flex items-center gap-1.5 rounded-2 border px-2.5 py-1 text-[11px]",
            open
              ? "border-accent/50 bg-accent-soft text-accent"
              : "border-line-2 bg-bg-2 text-fg-2 hover:bg-bg-3",
          )}
        >
          <Icon icon={Columns3} size="xs" />
          Columns
          {hidden > 0 && (
            <span className="rounded-pill bg-bg-4 px-1.5 py-px font-mono text-[9.5px] leading-none text-fg-3">
              {hidden}
            </span>
          )}
        </button>
      </Tooltip>
      <AnchoredPopover
        open={open}
        anchorRef={triggerRef}
        ariaLabel="Table columns"
        width={232}
        onDismiss={() => setOpen(false)}
      >
        <div className="py-1">
          <p className="px-3 pb-1.5 pt-1 text-[10.5px] leading-snug text-fg-3">
            Hidden fields stay in each session's details.
          </p>
          <ul>
            {rows.map((c) => {
              const shown = resolved.shown.includes(c.id);
              const noRoom = resolved.autoHidden.includes(c.id);
              return (
                <li key={c.id}>
                  <label className="flex cursor-pointer items-center gap-2 px-3 py-1 text-[11.5px] text-fg-2 hover:bg-bg-2 hover:text-fg-0">
                    <input
                      type="checkbox"
                      checked={shown}
                      onChange={() => onChange(toggleColumn(overrides, c.id, shown))}
                      className="h-3 w-3 shrink-0 accent-accent"
                    />
                    <span className="min-w-0 flex-1 truncate">{pickerLabel(c)}</span>
                    {noRoom && (
                      <span className="shrink-0 text-[10px] text-fg-4">no room</span>
                    )}
                  </label>
                </li>
              );
            })}
          </ul>
          <div className="mt-1 border-t border-line-1 px-3 pb-0.5 pt-1.5">
            <button
              type="button"
              disabled={!chosen}
              onClick={() => onChange({})}
              className="text-[11px] text-fg-3 hover:text-fg-1 disabled:cursor-not-allowed disabled:opacity-40"
            >
              Reset to defaults
            </button>
          </div>
        </div>
      </AnchoredPopover>
    </>
  );
}
