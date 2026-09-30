import { Fragment, memo, useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import clsx from "clsx";
import {
  flexRender,
  getCoreRowModel,
  getSortedRowModel,
  type Column,
  type ColumnDef,
  type Row,
  type SortingState,
  useReactTable,
} from "@tanstack/react-table";
import { Icon } from "./Icon";
import { InlineLoading, Spinner } from "./Spinner";
import { Tooltip } from "./Tooltip";
import {
  ArrowDown,
  ArrowUp,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  ChevronsUpDown,
  type LucideIcon,
} from "lucide-react";

// DataTable: the ONE sortable / paginated record table for every application
// surface (web/ node tables, web2/ org list pages). Promoted into shared/
// from the two app copies (web/src/components/DataTable.tsx and
// web2/src/components/DataTable.tsx are now one-line re-export shims), once
// @tanstack/react-table was hoisted to the workspace root. The merge keeps
// every prop either app used: web's layout / rowClassName / meta.width /
// meta.truncate / scroll-edge affordance, and web2's inline row expansion
// (expandedKey + renderExpanded). Pure: no fetch, no router, no app state.
// Client-side sort over `data` by default; controlled server-side sort when
// the parent passes both `sorting` and `onSortingChange`.

// SORT_GLYPH is the header sort indicator per TanStack sort state; "none"
// is the hover hint on a sortable-but-unsorted column.
const SORT_GLYPH: Record<"asc" | "desc" | "none", LucideIcon> = {
  asc: ArrowUp,
  desc: ArrowDown,
  none: ChevronsUpDown,
};

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
  // Optional per-row class (e.g. `sb-fade-up` on a row that arrived on a
  // live poll). Additive: omitted, every row renders exactly as before.
  rowClassName?: (row: T) => string | undefined;
  // Inline row expansion (from web2's copy). When `renderExpanded` is
  // provided and `expandedKey` equals rowKey(row) for a row on the current
  // page, a full-width sub-row rendered by `renderExpanded` is inserted
  // directly beneath that row, so expansion content stays visually attached
  // to the row that opened it. Both optional; omitting them changes nothing.
  expandedKey?: string | null;
  renderExpanded?: (row: T) => ReactNode;
  // Progressive rendering for long, UNPAGINATED tables (a Projects list of
  // hundreds of rows put ~10k nodes in the DOM). When set, only the first
  // `incrementalRows` rows of the (sorted) row model render; the next batch
  // renders as the end of the table nears the viewport (IntersectionObserver
  // with a generous margin, so scrolling never meets a gap) or on the "Show
  // more" button, which keeps every row reachable by keyboard. Sorting still
  // runs over ALL rows. Omitted, every row renders exactly as before.
  incrementalRows?: number;
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
  rowClassName,
  expandedKey,
  renderExpanded,
  incrementalRows,
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
  // scroll and on any resize of the container OR of the table inside it
  // (ResizeObserver on both), so the affordance is honest at every viewport
  // width and after a refetch that changed the table's width. Observing the
  // table replaces re-running the effect on every `data`/`columns` identity
  // change, which forced a synchronous layout (scrollWidth) per render on
  // tables fed an inline array.
  const scrollRef = useRef<HTMLDivElement>(null);
  const tableRef = useRef<HTMLTableElement>(null);
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
    if (tableRef.current) ro.observe(tableRef.current);
    return () => {
      el.removeEventListener("scroll", measure);
      ro.disconnect();
    };
  }, []);

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

  // Row clicks go through a ref so the memoized rows below keep a stable
  // handler while the parent passes a fresh inline closure every render.
  const onRowClickRef = useRef(onRowClick);
  onRowClickRef.current = onRowClick;
  const handleRowClick = useCallback((row: T) => onRowClickRef.current?.(row), []);

  const allRows = table.getRowModel().rows;
  const batch = incrementalRows != null && incrementalRows > 0 ? incrementalRows : 0;
  const [shownCount, setShownCount] = useState(batch);
  const bodyRows = batch > 0 ? allRows.slice(0, Math.max(batch, shownCount)) : allRows;
  const hiddenCount = allRows.length - bodyRows.length;
  const moreRef = useRef<HTMLTableRowElement>(null);
  const showMore = useCallback(() => setShownCount((n) => Math.max(n, batch) + batch), [batch]);
  useEffect(() => {
    const el = moreRef.current;
    if (hiddenCount <= 0 || !el || typeof IntersectionObserver === "undefined") return;
    // Re-observed after every batch: if the sentinel is still near the
    // viewport the initial callback grows the table again.
    const io = new IntersectionObserver(
      (entries) => {
        if (entries.some((e) => e.isIntersecting)) showMore();
      },
      { rootMargin: "1200px 0px" },
    );
    io.observe(el);
    return () => io.disconnect();
  }, [hiddenCount, shownCount, showMore]);

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
        ref={tableRef}
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
                      "group/th whitespace-nowrap bg-bg-2 py-head font-medium",
                      right ? "px-cell-num text-right" : "px-cell",
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
                          <Icon icon={SORT_GLYPH[sorted || "none"]} size={10} />
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
          {allRows.length === 0 ? (
            <tr>
              <td
                colSpan={columns.length}
                className="px-4 py-8 text-center text-[12px] text-fg-3"
              >
                {loading ? <InlineLoading /> : emptyMessage}
              </td>
            </tr>
          ) : (
            bodyRows.map((r, i) => (
              <Fragment key={rowKey(r.original)}>
                <DataTableRow<T>
                  row={r}
                  original={r.original}
                  index={r.index}
                  rowId={r.id}
                  columns={leafColumns}
                  striped={!!zebra && i % 2 === 1}
                  extraClass={rowClassName?.(r.original)}
                  onRowClick={onRowClick ? handleRowClick : undefined}
                />
                {renderExpanded && expandedKey === rowKey(r.original) && (
                  <tr className="border-b border-line-1">
                    <td colSpan={leafColumns.length} className="bg-bg-1/60 px-3 py-2.5">
                      {renderExpanded(r.original)}
                    </td>
                  </tr>
                )}
              </Fragment>
            ))
          )}
          {hiddenCount > 0 && (
            <tr ref={moreRef}>
              <td colSpan={leafColumns.length} className="px-4 py-2 text-center">
                <button
                  type="button"
                  onClick={showMore}
                  className="text-[11px] text-fg-3 underline-offset-2 hover:text-fg-1 hover:underline"
                >
                  Show more ({hiddenCount.toLocaleString()} remaining)
                </button>
              </td>
            </tr>
          )}
        </tbody>
      </table>
      </div>
    </div>
  );
}

type DataTableRowProps<T> = {
  row: Row<T>;
  // The props below are what the memo compares (see sameRow).
  original: T;
  index: number;
  rowId: string;
  columns: Column<T, unknown>[];
  striped: boolean;
  extraClass: string | undefined;
  onRowClick: ((row: T) => void) | undefined;
};

// sameRow: a body row re-renders only when its record, its position, the
// visible columns (a new column-def array, e.g. a cell closure over new
// state) or its classes change. The record keeps its identity across polls
// that did not change it (the query cache shares unchanged subtrees), so a
// poll re-renders only the rows that actually changed, not every cell of
// every row - the Sessions table re-rendered ~50 rows x 15 cells (and one
// Tooltip each) on every tick. The TanStack Row object itself is rebuilt
// whenever `data` changes, so it is deliberately NOT compared.
function sameRow<T>(a: DataTableRowProps<T>, b: DataTableRowProps<T>): boolean {
  return (
    a.original === b.original &&
    a.index === b.index &&
    a.rowId === b.rowId &&
    a.columns === b.columns &&
    a.striped === b.striped &&
    a.extraClass === b.extraClass &&
    a.onRowClick === b.onRowClick
  );
}

function DataTableRowImpl<T>({ row, striped, extraClass, onRowClick }: DataTableRowProps<T>) {
  return (
    <tr
      className={clsx(
        // `group` lets a cell reveal hover/focus-only affordances
        // (e.g. the Sessions table's compact rating trigger) via
        // group-hover:/group-focus-within: without each cell
        // wiring its own mouseenter/leave state.
        // Row hover on every table (not only clickable ones);
        // the pointer cursor still marks a clickable row.
        "group border-b border-line-1 last:border-b-0 transition-colors hover:bg-bg-3",
        striped && "bg-bg-3/50",
        onRowClick && "cursor-pointer",
        extraClass,
      )}
      onClick={onRowClick ? () => onRowClick(row.original) : undefined}
    >
      {row.getVisibleCells().map((c) => (
        <td
          key={c.id}
          className={clsx(
            "py-row",
            // Right-aligned numeric cells must never wrap —
            // breaking "$1,234.56" onto two lines ruins the
            // column. Left cells (project paths) may still
            // truncate or wrap as their own cell decides.
            // They also take tighter side padding: numerics are
            // narrow, and 2 x 2px per column is real budget on a
            // wide table.
            c.column.columnDef.meta?.align === "right"
              ? "whitespace-nowrap px-cell-num text-right tabular-nums"
              : "px-cell",
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
  );
}

const DataTableRow = memo(DataTableRowImpl, sameRow) as <T>(
  props: DataTableRowProps<T>,
) => ReturnType<typeof DataTableRowImpl>;

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
    <Tooltip content={`More columns to the ${side}. Click to scroll.`}>
    <button
      type="button"
      onClick={onClick}
      aria-label={`Scroll table ${side}`}
      className={clsx(
        "absolute top-1 z-20 grid h-5 w-5 place-items-center rounded-pill border border-line-2 bg-bg-2 text-caption leading-none text-fg-2 shadow-drawer transition-colors hover:border-accent/60 hover:bg-bg-3 hover:text-fg-0 focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-ring)]",
        side === "left" ? "left-1" : "right-1",
      )}
    >
      <Icon icon={side === "left" ? ChevronLeft : ChevronRight} size="xs" />
    </button>
    </Tooltip>
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
        {loading && <Spinner className="ml-2 align-[-2px]" />}
      </span>
      <div className="flex items-center gap-1">
        <PagerBtn onClick={() => onPage(1)} disabled={page <= 1} label="First page">
          <Icon icon={ChevronsLeft} size="xs" />
        </PagerBtn>
        <PagerBtn onClick={() => onPage(page - 1)} disabled={page <= 1} label="Previous page">
          <Icon icon={ChevronLeft} size="xs" />
        </PagerBtn>
        <span className="px-1 tabular-nums text-fg-2">
          page {page} / {maxPage}
        </span>
        <PagerBtn onClick={() => onPage(page + 1)} disabled={page >= maxPage} label="Next page">
          <Icon icon={ChevronRight} size="xs" />
        </PagerBtn>
        <PagerBtn onClick={() => onPage(maxPage)} disabled={page >= maxPage} label="Last page">
          <Icon icon={ChevronsRight} size="xs" />
        </PagerBtn>
      </div>
    </div>
  );
}

function PagerBtn({
  children,
  onClick,
  disabled,
  label,
}: {
  children: ReactNode;
  onClick: () => void;
  disabled?: boolean;
  label: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      aria-label={label}
      title={label}
      className="grid h-6 w-6 place-items-center rounded-1 border border-line-2 bg-bg-2 text-fg-2 transition-colors hover:bg-bg-3 hover:text-fg-0 disabled:cursor-not-allowed disabled:opacity-30"
    >
      {children}
    </button>
  );
}
