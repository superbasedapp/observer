import clsx from "clsx";
import type { ReactNode } from "react";

// Table — a data table that is ALWAYS inside its own horizontal scroll
// container. Every hand-rolled table that forgot the wrapper is a page
// that scrolls sideways as a whole at phone width; this primitive makes
// forgetting impossible.
//
// `minWidth` / `maxHeight` are inline styles on purpose: Tailwind cannot
// see an arbitrary class built from a prop.

export type TableProps = {
  /** The `<tr>` (or rows) placed inside the styled `<thead>`. */
  head?: ReactNode;
  /** The `<tr>` rows placed inside `<tbody>`. */
  children?: ReactNode;
  /** Below this width the wrapper scrolls instead of squashing columns. */
  minWidth?: number;
  /** Caps the body height and scrolls vertically. */
  maxHeight?: number;
  /** Pins the header while the body scrolls (needs `maxHeight`). */
  stickyHead?: boolean;
  /** Body text size. Enum rather than a class so callers never collide
   *  with the base `text-*` utility (Tailwind resolves collisions by
   *  stylesheet order, not by attribute order). */
  size?: "sm" | "md";
  /** Shrink-to-content instead of filling the container. */
  fit?: boolean;
  className?: string;
  tableClassName?: string;
};

const SIZE_CLASS: Record<"sm" | "md", string> = {
  sm: "text-[11px]",
  md: "text-[11.5px]",
};

let warnedStickyHeadWithoutMaxHeight = false;

export function Table({
  head,
  children,
  minWidth,
  maxHeight,
  stickyHead,
  size = "md",
  fit,
  className,
  tableClassName,
}: TableProps) {
  // stickyHead only means anything once the body actually scrolls under a
  // fixed viewport (`maxHeight`) — without it there's no scroll container
  // for the header to stick within, so the prop would silently no-op
  // (or worse, `sticky` against the page scroll). Warn once in dev rather
  // than ship a header that looks pinned in the design but isn't live.
  const effectiveStickyHead = stickyHead && maxHeight !== undefined;
  // `shared/` is consumed by three apps with different global type setups
  // (not all carry @types/node or vite/client) — read NODE_ENV through
  // globalThis with an inline type rather than the ambient `process`
  // identifier so this compiles everywhere.
  const nodeEnv = (
    globalThis as { process?: { env?: { NODE_ENV?: string } } }
  ).process?.env?.NODE_ENV;
  if (
    stickyHead &&
    maxHeight === undefined &&
    !warnedStickyHeadWithoutMaxHeight &&
    nodeEnv !== "production"
  ) {
    warnedStickyHeadWithoutMaxHeight = true;
    // eslint-disable-next-line no-console
    console.warn("Table: stickyHead has no effect without maxHeight");
  }
  return (
    <div
      className={clsx(
        "overflow-x-auto",
        maxHeight !== undefined && "overflow-y-auto",
        className,
      )}
      style={maxHeight !== undefined ? { maxHeight } : undefined}
    >
      <table
        className={clsx(
          "border-collapse text-left",
          fit ? "w-auto" : "w-full",
          SIZE_CLASS[size],
          tableClassName,
        )}
        style={minWidth !== undefined ? { minWidth } : undefined}
      >
        {head !== undefined && (
          <thead
            className={clsx(
              "text-[10px] uppercase tracking-[0.06em] text-fg-3 [&_th]:border-b [&_th]:border-line-2",
              effectiveStickyHead && "sticky top-0 z-[1] bg-bg-2",
            )}
          >
            {head}
          </thead>
        )}
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}
