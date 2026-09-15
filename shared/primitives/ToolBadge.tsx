import clsx from "clsx";
import { toolMeta } from "../lib/tools";
import { ToolGlyph } from "../lib/icons";
import { Tooltip } from "./Tooltip";

// ToolDot — bare provider-colored dot. Kept for compact contexts
// (FilterBar chips, palette rows) where the framed square is too
// loud. Use ToolGlyphFrame for tabular cells.
export function ToolDot({
  tool,
  size = 8,
  className,
}: {
  tool: string;
  size?: number;
  className?: string;
}) {
  const meta = toolMeta(tool);
  return (
    <span
      className={clsx("inline-block shrink-0 rounded-full", className)}
      style={{
        width: size,
        height: size,
        background: meta.colorVar,
      }}
    />
  );
}

// ToolGlyphFrame — tinted rounded-square frame wrapping the per-tool
// glyph at the design's exact treatment (18% bg, 35% border, glyph in
// the tool's color via currentColor). Used inside ToolBadge and any
// other surface that wants the boxed glyph mark.
export function ToolGlyphFrame({
  tool,
  size = 18,
  className,
}: {
  tool: string;
  size?: number;
  className?: string;
}) {
  const meta = toolMeta(tool);
  const radius = Math.max(3, Math.round(size * 0.22));
  const glyphSize = Math.round(size * 0.75);
  return (
    <Tooltip content={meta.label}>
      <span
        tabIndex={0}
        className={clsx(
          "inline-grid shrink-0 place-items-center focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-ring)]",
          className,
        )}
        style={{
          width: size,
          height: size,
          borderRadius: radius,
          background: `color-mix(in oklab, ${meta.colorVar} 18%, transparent)`,
          border: `1px solid color-mix(in oklab, ${meta.colorVar} 35%, transparent)`,
          color: meta.colorVar,
        }}
      >
        <ToolGlyph tool={tool} size={glyphSize} />
      </span>
    </Tooltip>
  );
}

export function ToolBadge({
  tool,
  showLabel = true,
  className,
}: {
  tool: string;
  showLabel?: boolean;
  className?: string;
}) {
  const meta = toolMeta(tool);
  return (
    <span
      className={clsx(
        "inline-flex items-center gap-1.5 rounded-pill border border-line-2 bg-bg-2 py-0.5 pl-0.5 pr-2 text-[11px] font-medium text-fg-1",
        !showLabel && "pr-0.5",
        className,
      )}
    >
      <ToolGlyphFrame tool={tool} size={16} />
      {showLabel && <span>{meta.label}</span>}
    </span>
  );
}
