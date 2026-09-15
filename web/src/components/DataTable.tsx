import { useEffect, useRef, useState, type ReactNode } from "react";
import clsx from "clsx";
import {
  flexRender,
  getCoreRowModel,
  getSortedRowModel,
  type ColumnDef,
  type SortingState,
  useReactTable,
} from "@tanstack/react-table";

export type DataTableProps<T> = {
  data: T[];
  columns: ColumnDef<T, any>[];
  onRowClick?: (row: T) => void;
  emptyMessage?: ReactNode;
  // Minimum table width before horizontal scroll kicks in. Big
  // tables (Sessions / Actions) tend to overflow on narrow screens.
  minWidth?: number;
  initialSort?: SortingState;
  // Controlled server-side sorting. When BOTH `sorting` and `onSortingChange`
  // are provided, the table delegates ordering to the server (manualSorting)
  // and does NOT reorder rows client-side — the parent feeds in the
  // server-sorted page and re-fetches on header clicks. When omitted, the
  // table keeps its built-in client-side sort over `data` (initialSort seed).
  sorting?: SortingState;
  onSortingChange?: (s: SortingState) => void;
  rowKey: (row: T) => string;
  // Render alternating row backgrounds. Matches design's
  // `.dtable.zebra` modifier (`design/app.css:530-531`).
  zebra?: boolean;
  // Apply sticky header positioning. Header stays visible when the
  // wrapper scrolls — design's default for the data table
  // (`design/app.css:501-502`). Requires the parent wrapper to be a
  // scroll container with a fixed height; otherwise stickyness is a
  // no-op.
  stickyHeader?: boolean;
  // Loading state — when true, an indeterminate stripe sweeps across
  // the header row and empty-state copy swaps to "Loading…" so a
  // refetch never reads as "no data". Set to actions.loading or its
  // page-equivalent on every refetch-capable table.
  loading?: boolean;
  // Column-width strategy.
  //
  //   "auto"  (default) — the browser sizes columns from their content.
  //           Every pre-existing table keeps exactly this behaviour.
  //   "fixed" — CSS `table-layout: fixed`: the per-column `meta.width`
  //           budget below is authoritative, so ONE long value (a deep
  //           project path, a 16-character tool label) can no longer
  //           inflate its column and push the trailing columns past the
  //           right edge. Extra container width is handed back to the
  //           columns in proportion to their declared widths.
  //
  // Use "fixed" only on tables whose columns ALL declare `meta.width`.
  layout?: "auto" | "fixed";
};

// scrollEdges reports whether a horizontal scroll container is currently
// clipping content on either side, so the table can draw an edge fade
// (the "there is more table over here" affordance the plain scrollbar
// alone does not give on overlay-scrollbar platforms).
type ScrollEdges = { left: boolean; right: boolean };

export function DataTable<T>({
  data,
  columns,
  onRowClick,
  emptyMessage = "No data.",
  minWidth = 760,
  initialSort = [],
  sorting: controlledSorting,
  onSortingChange,
  rowKey,
  zebra,
  stickyHeader,
  loading,
  layout = "auto",
}: DataTableProps<T>) {
  const [internalSorting, setInternalSorting] = useState<SortingState>(initialSort);
  // Controlled (server-side) when the parent supplies both the state and the
  // change handler; otherwise fall back to internal client-side sorting.
  const manual = controlledSorting !== undefined && onSortingChange !== undefined;
  const sorting = manual ? controlledSorting : internalSorting;

  const table = useReactTable({
    data,
    columns,
    state: { sorting },
    onSortingChange: manual
      ? (updater) =>
          onSortingChange(
            typeof updater === "function" ? updater(sorting) : updater,
          )
      : setInternalSorting,
    manualSorting: manual,
    getCoreRowModel: getCoreRowModel(),
    // In manual mode the server already ordered the rows; a client sort model
    // would re-sort the page locally, defeating the global server sort.
    ...(manual ? {} : { getSortedRowModel: getSortedRowModel() }),
  });

  // Edge-fade state for the horizontal scroll container. Recomputed on
  // scroll and on any resize of the container (ResizeObserver), so the
  // affordance is honest at every viewport width and after a refetch.
  const scrollRef = useRef<HTMLDivElement>(null);
  const [edges, setEdges] = useState<ScrollEdges>({ left: false, right: false });
  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    const measure = () => {
      const max = el.scrollWidth - el.clientWidth;
      const next: ScrollEdges = {
        left: el.scrollLeft > 1,
        right: max > 1 && el.scrollLeft < max - 1,
      };
      // Functional compare: a scroll event fires per frame and an
      // unconditional setState would re-render the whole table on each.
      setEdges((cur) =>
        cur.left === next.left && cur.right === next.right ? cur : next,
      );
    };
    measure();
    el.addEventListener("scroll", measure, { passive: true });
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => {
      el.removeEventListener("scroll", measure);
      ro.disconnect();
    };
  }, [data, columns]);

  // scrollByPage nudges the wrapper by ~60% of its visible width, so the
  // edge buttons page through the hidden columns instead of creeping.
  const scrollByPage = (dir: 1 | -1) => {
    const el = scrollRef.current;
    if (!el) return;
    el.scrollBy({
      left: dir * Math.max(160, Math.round(el.clientWidth * 0.6)),
      behavior: "smooth",
    });
  };

  const leafColumns = table.getVisibleLeafColumns();
  const hasWidths = leafColumns.some((c) => c.columnDef.meta?.width != null);

  return (
    <div className="relative">
      {loading && (
        <span
          aria-hidden
          className="pointer-events-none absolute left-0 right-0 top-0 z-20 h-[2px] overflow-hidden"
        >
          <span className="block h-full w-1/3 animate-[datatable-stripe_1.1s_linear_infinite] bg-accent/70" />
        </span>
      )}
      {/* Edge fades + a paging button per clipped side. Both are rendered
          only while content is actually clipped there, so a table that fits
          shows no false affordance.

          The button is what makes the overflow OBVIOUS: the wrapper's own
          horizontal scrollbar sits under the LAST row, which on a 50-row
          table is far below the fold, so it is not a discoverable control.
          These sit level with the header row, always in view. */}
      {edges.left && (
        <>
          <span
            aria-hidden
            className="pointer-events-none absolute inset-y-0 left-0 z-10 w-6 bg-gradient-to-r from-bg-2 to-transparent"
          />
          <ScrollEdgeButton
            side="left"
            onClick={() => scrollByPage(-1)}
          />
        </>
      )}
      {edges.right && (
        <>
          <span
            aria-hidden
            className="pointer-events-none absolute inset-y-0 right-0 z-10 w-6 bg-gradient-to-l from-bg-2 to-transparent"
          />
          <ScrollEdgeButton
            side="right"
            onClick={() => scrollByPage(1)}
          />
        </>
      )}
      <div ref={scrollRef} className="table-scroll-x overflow-x-auto">
      <table
        className={clsx(
          "w-full text-left text-[11.5px]",
          layout === "fixed" && "table-fixed",
        )}
        style={{ minWidth }}
      >
        {hasWidths && (
          <colgroup>
            {leafColumns.map((c) => (
              <col
                key={c.id}
                style={
                  c.columnDef.meta?.width != null
                    ? { width: c.columnDef.meta.width }
                    : undefined
                }
              />
            ))}
          </colgroup>
        )}
        <thead className="text-[10px] uppercase tracking-[0.06em] text-fg-3">
          {table.getHeaderGroups().map((hg) => (
            <tr key={hg.id} className="border-b border-line-2">
              {hg.headers.map((h) => {
                const canSort = h.column.getCanSort();
                const sorted = h.column.getIsSorted();
                const right = h.column.columnDef.meta?.align === "right";
                return (
                  <th
                    key={h.id}
                    className={clsx(
                      "group/th whitespace-nowrap bg-bg-2 py-2 font-medium",
                      right ? "px-1.5 text-right" : "px-2",
                      stickyHeader && "sticky top-0 z-10",
                      canSort && "cursor-pointer select-none hover:text-fg-1",
                    )}
                    onClick={canSort ? h.column.getToggleSortingHandler() : undefined}
                  >
                    <span className="inline-flex max-w-full items-center gap-0.5 align-middle">
                      {flexRender(h.column.columnDef.header, h.getContext())}
                      {canSort && (
                        // The neutral "·" placeholder costs ~12px in EVERY
                        // sortable header, which across a 15-column table is
                        // a whole column's worth of width. Reserve the space
                        // only for the column that is actually sorted, and
                        // reveal the affordance on header hover otherwise.
                        <span
                          aria-hidden
                          className={clsx(
                            "shrink-0 overflow-hidden text-fg-4 transition-[width,opacity]",
                            sorted
                              ? "w-2.5 opacity-100"
                              : "w-0 opacity-0 group-hover/th:w-2.5 group-hover/th:opacity-100",
                          )}
                        >
                          {sorted === "asc" ? "↑" : sorted === "desc" ? "↓" : "·"}
                        </span>
                      )}
                    </span>
                  </th>
                );
              })}
            </tr>
          ))}
        </thead>
        <tbody>
          {table.getRowModel().rows.length === 0 ? (
            <tr>
              <td
                colSpan={columns.length}
                className="px-4 py-8 text-center text-[12px] text-fg-3"
              >
                {loading ? (
                  <span className="inline-flex items-center gap-2 text-fg-2">
                    <span
                      aria-hidden
                      className="inline-block h-3 w-3 animate-spin rounded-full border border-line-3 border-t-accent"
                    />
                    Loading…
                  </span>
                ) : (
                  emptyMessage
                )}
              </td>
            </tr>
          ) : (
            table.getRowModel().rows.map((r, i) => (
              <tr
                key={rowKey(r.original)}
                className={clsx(
                  // `group` lets a cell reveal hover/focus-only affordances
                  // (e.g. the Sessions table's compact rating trigger) via
                  // group-hover:/group-focus-within: without each cell
                  // wiring its own mouseenter/leave state.
                  "group border-b border-line-1 last:border-b-0 transition-colors",
                  zebra && i % 2 === 1 && "bg-bg-3/50",
                  onRowClick && "cursor-pointer hover:bg-bg-3",
                )}
                onClick={onRowClick ? () => onRowClick(r.original) : undefined}
              >
                {r.getVisibleCells().map((c) => (
                  <td
                    key={c.id}
                    className={clsx(
                      "py-1.5",
                      // Right-aligned numeric cells must never wrap —
                      // breaking "$1,234.56" onto two lines ruins the
                      // column. Left cells (project paths) may still
                      // truncate or wrap as their own cell decides.
                      // They also take tighter side padding: numerics are
                      // narrow, and 2 x 2px per column is real budget on a
                      // wide table.
                      c.column.columnDef.meta?.align === "right"
                        ? "whitespace-nowrap px-1.5 text-right tabular-nums"
                        : "px-2",
                      // truncate: the cell owns a hard width budget, so
                      // anything longer is clipped here rather than allowed
                      // to widen the column.
                      c.column.columnDef.meta?.truncate && "overflow-hidden",
                      c.column.columnDef.meta?.mono && "font-mono text-fg-2",
                    )}
                  >
                    {flexRender(c.column.columnDef.cell, c.getContext())}
                  </td>
                ))}
              </tr>
            ))
          )}
        </tbody>
      </table>
      </div>
    </div>
  );
}

// ScrollEdgeButton is the always-in-view "there are more columns this way"
// control, pinned level with the header row on whichever side is clipped.
function ScrollEdgeButton({
  side,
  onClick,
}: {
  side: "left" | "right";
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-label={`Scroll table ${side}`}
      title={`More columns to the ${side}. Click to scroll.`}
      className={clsx(
        "absolute top-1 z-20 grid h-5 w-5 place-items-center rounded-full border border-line-2 bg-bg-2 text-[11px] leading-none text-fg-2 shadow-drawer transition-colors hover:border-accent/60 hover:bg-bg-3 hover:text-fg-0 focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-ring)]",
        side === "left" ? "left-1" : "right-1",
      )}
    >
      <span aria-hidden>{side === "left" ? "‹" : "›"}</span>
    </button>
  );
}

// Extend TanStack ColumnMeta so column defs can declare align/mono.
declare module "@tanstack/react-table" {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  interface ColumnMeta<TData extends unknown, TValue> {
    align?: "left" | "right";
    mono?: boolean;
    // Declared width in px, emitted as a <colgroup> <col width>. Under
    // layout="fixed" it is authoritative (and scaled proportionally when
    // the container is wider than the sum); under the default "auto"
    // layout it is a strong hint the browser may still stretch.
    width?: number;
    // Clip anything that exceeds the column's width budget instead of
    // letting it push the table wider. Pair with a cell that truncates
    // its own text (TruncatedPath, `truncate`) so the clip reads as an
    // ellipsis rather than a hard cut.
    truncate?: boolean;
  }
}

export function Pagination({
  page,
  limit,
  total,
  onPage,
  loading,
}: {
  page: number;
  limit: number;
  total: number;
  onPage: (p: number) => void;
  loading?: boolean;
}) {
  const maxPage = Math.max(1, Math.ceil(total / limit));
  const start = total === 0 ? 0 : (page - 1) * limit + 1;
  const end = Math.min(total, page * limit);
  return (
    <div className="flex items-center justify-between gap-3 pt-3 text-[11px] text-fg-3">
      <span>
        {start.toLocaleString()}–{end.toLocaleString()} of{" "}
        {total.toLocaleString()}
        {loading && <span className="ml-2 text-fg-4">loading…</span>}
      </span>
      <div className="flex items-center gap-1">
        <PagerBtn onClick={() => onPage(1)} disabled={page <= 1}>
          «
        </PagerBtn>
        <PagerBtn onClick={() => onPage(page - 1)} disabled={page <= 1}>
          ‹
        </PagerBtn>
        <span className="px-1 tabular-nums text-fg-2">
          page {page} / {maxPage}
        </span>
        <PagerBtn onClick={() => onPage(page + 1)} disabled={page >= maxPage}>
          ›
        </PagerBtn>
        <PagerBtn onClick={() => onPage(maxPage)} disabled={page >= maxPage}>
          »
        </PagerBtn>
      </div>
    </div>
  );
}

function PagerBtn({
  children,
  onClick,
  disabled,
}: {
  children: ReactNode;
  onClick: () => void;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className="grid h-6 w-6 place-items-center rounded-1 border border-line-2 bg-bg-2 text-fg-2 transition-colors hover:bg-bg-3 hover:text-fg-0 disabled:cursor-not-allowed disabled:opacity-30"
    >
      {children}
    </button>
  );
}
