import clsx from "clsx";
import type { ReactNode } from "react";

// MarkTile: a framed square holding one brand mark from a shared mark table
// (a TOOL_LOGOS mono mark, a HOST_MARKS or MODEL_FAMILY_MARKS entry: paths on
// a 24px grid, painted in currentColor), or, when the caller has no mark for
// the thing, an honest monogram of its name. It is a picture, not a control:
// no tab stop and no tooltip, so it can sit inside a button or a list row.
// The caller resolves which mark to draw (a table lookup, never a name
// branch here); `color` is a CSS colour such as a --tool-* var.
export function MarkTile({
  mark,
  letter,
  size = 32,
  color,
  className,
}: {
  /** The mark's SVG children (24px grid). Omit for a monogram. */
  mark?: ReactNode;
  /** The monogram letter shown when there is no mark. */
  letter?: string;
  size?: number;
  /** Mark colour; the frame tints from it. Defaults to the text colour. */
  color?: string;
  className?: string;
}) {
  const tint = color ?? "var(--fg-2)";
  const radius = Math.max(4, Math.round(size * 0.24));
  const glyph = Math.round(size * 0.6);
  return (
    <span
      aria-hidden
      className={clsx("inline-grid shrink-0 place-items-center", className)}
      style={{
        width: size,
        height: size,
        borderRadius: radius,
        color: tint,
        background: `color-mix(in oklab, ${tint} 12%, var(--bg-3))`,
        border: `1px solid color-mix(in oklab, ${tint} 28%, transparent)`,
      }}
    >
      {mark ? (
        <svg width={glyph} height={glyph} viewBox="0 0 24 24" fill="currentColor" fillRule="evenodd">
          {mark}
        </svg>
      ) : (
        <span className="font-semibold leading-none" style={{ fontSize: Math.round(size * 0.46) }}>
          {letter || "?"}
        </span>
      )}
    </span>
  );
}
