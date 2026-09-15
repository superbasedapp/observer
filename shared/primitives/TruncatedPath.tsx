import clsx from "clsx";
import type { ReactNode } from "react";
import { Tooltip } from "./Tooltip";

// TruncatedPath — the ONE primitive for rendering a long, unbreakable
// string (a project root / source file / git remote / session id /
// model id / URL) inside a flex or grid child on a narrow viewport.
//
// The mobile-overflow class of bug (operator report 2026-07): a long
// path with no spaces cannot wrap, so in a flex/grid child WITHOUT a
// shrink allowance it forces the child — and the whole page — wider
// than the phone viewport, breaking every layout downstream. Two
// things fix it, and this primitive bundles both so no call site has
// to remember them:
//
//   1. STRUCTURAL: the text renders in a `block min-w-0 truncate`
//      span. `min-w-0` is the load-bearing bit — a flex/grid child
//      defaults to `min-width:auto` (= its content's intrinsic
//      width), which is exactly what refuses to shrink. Callers still
//      owe `min-w-0` on the intermediate flex ancestors; see the
//      sweep in the mobile-overflow pass.
//   2. TAIL-PRESERVING: paths are recognised by their TAIL (the leaf
//      file / final dir), but CSS `text-overflow:ellipsis` clips the
//      RIGHT — i.e. the tail. We flip the inline base direction to
//      RTL so the ellipsis lands at the HEAD instead
//      (`…observer/marketing`), and re-assert LTR on the content with
//      a leading U+200E LRM + `unicode-bidi:isolate` so the path's own
//      characters keep their natural left-to-right order and the
//      leading "/" doesn't get reordered to the far edge. This is
//      width-responsive: it shows as much of the tail as the column
//      allows, unlike a fixed "last two segments" JS truncation.
//
// The full value is always available on hover / focus via a themed
// Tooltip (mono, wrapping), so nothing is ever hidden — only
// visually compacted.
//
// Consolidates the seven ad-hoc `shortPath` / `shortProject` /
// `shortProjectPath` copies that previously lived in Overview,
// Sessions, Live, Cache, Patterns, Discovery, and CommandPalette.
export function TruncatedPath({
  value,
  className,
  title,
  tooltipMaxWidth = 420,
}: {
  // The full string to render (never mutated — the tooltip shows it verbatim).
  value: string;
  // Extra classes for sizing / colour / font on the visible span.
  className?: string;
  // Tooltip body override. Defaults to the full `value`, mono + wrapping.
  title?: ReactNode;
  // Tooltip bubble max width. Default 420px.
  tooltipMaxWidth?: number;
}) {
  const body =
    title ?? <span className="break-all font-mono">{value}</span>;
  return (
    <Tooltip content={body} maxWidth={tooltipMaxWidth}>
      <span
        dir="rtl"
        tabIndex={0}
        // block + min-w-0 lets the span shrink inside a flex/grid
        // child; truncate = overflow-hidden + nowrap + ellipsis.
        // text-left keeps the (LTR) content left-aligned even though
        // the base direction is RTL for ellipsis placement.
        className={clsx(
          "block min-w-0 cursor-help truncate text-left focus:outline-none",
          className,
        )}
      >
        {/* <bdi> isolates the path as its own LTR run (its first
            strong char is latin), so the glyphs keep natural
            left-to-right order and the leading "/" doesn't reorder,
            while the container's RTL base direction keeps the ellipsis
            at the head. */}
        <bdi dir="ltr">{value}</bdi>
      </span>
    </Tooltip>
  );
}
