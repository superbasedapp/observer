import clsx from "clsx";
import { toolMeta } from "../lib/tools";
import { ToolGlyph } from "../lib/icons";
import { TOOL_LOGOS, TOOL_PIPS } from "../lib/toolLogos";
import { Tooltip } from "./Tooltip";

// Tool marks for every app (web / web2 / webcloud). Since the 2026-09-28
// visual upgrade:
//   1. the glyph is the vendor's real logo (via ToolGlyph → TOOL_LOGOS);
//   2. keys that share a mark with a sibling (cline / cline-cli, the five
//      *-web browser rails, cowork, grokbot, kiro-crew, ...) carry a small
//      surface PIP in the bottom-right corner, so the pair stays tellable
//      apart even with the label hidden. The pip comes from the generated
//      table (TOOL_LOGOS[tool].pip), never a tool-name branch.

// ToolDot — bare provider-colored dot. Kept for compact contexts
// (FilterBar chips, palette rows) where the framed square is too loud.
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
      style={{ width: size, height: size, background: meta.colorVar }}
    />
  );
}

// ToolGlyphFrame — tinted rounded-square frame (18% bg, 35% border) with the
// logo in the tool's color via currentColor, plus the optional surface pip.
export function ToolGlyphFrame({
  tool,
  size = 18,
  pip = true,
  className,
}: {
  tool: string;
  size?: number;
  /** Set false where a SurfaceBadge already sits next to the frame. */
  pip?: boolean;
  className?: string;
}) {
  const meta = toolMeta(tool);
  const radius = Math.max(3, Math.round(size * 0.22));
  // Logos are filled marks that touch their viewBox edges, so 72% (not the
  // old stroke glyphs' 75%) keeps them off the frame border.
  const glyphSize = Math.round(size * 0.72);
  const pipKind = pip ? TOOL_LOGOS[tool]?.pip : undefined;
  const pipSize = Math.max(8, Math.round(size * 0.5));
  return (
    <Tooltip content={meta.label}>
      <span
        tabIndex={0}
        className={clsx(
          "relative inline-grid shrink-0 place-items-center focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-ring)]",
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
        {pipKind && (
          <span
            aria-hidden
            className="absolute grid place-items-center rounded-full bg-bg-2"
            style={{
              right: -3,
              bottom: -3,
              width: pipSize,
              height: pipSize,
              boxShadow: "0 0 0 1px var(--line-3)",
            }}
          >
            <svg
              width={Math.round(pipSize * 0.8)}
              height={Math.round(pipSize * 0.8)}
              viewBox="0 0 24 24"
              aria-hidden
            >
              {TOOL_PIPS[pipKind]}
            </svg>
          </span>
        )}
      </span>
    </Tooltip>
  );
}

export function ToolBadge({
  tool,
  showLabel = true,
  pip = true,
  className,
}: {
  tool: string;
  showLabel?: boolean;
  /** Set false where a SurfaceBadge already sits next to the badge. */
  pip?: boolean;
  className?: string;
}) {
  const meta = toolMeta(tool);
  return (
    <span
      className={clsx(
        "inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-pill border border-line-2 bg-bg-2 py-0.5 pl-0.5 pr-2 text-[11px] font-medium text-fg-1",
        !showLabel && "pr-0.5",
        className,
      )}
    >
      <ToolGlyphFrame tool={tool} size={16} pip={pip} />
      {showLabel && <span>{meta.label}</span>}
    </span>
  );
}

// ToolStack — overlapping tool frames for a row that spans several tools
// (a project, a developer, a team). Shows up to `max`, then "+N". Pair with
// .sb-tool-stack from motion-additions.css (hover fans the stack out).
export function ToolStack({
  tools,
  max = 4,
  size = 18,
  className,
}: {
  tools: string[];
  max?: number;
  size?: number;
  className?: string;
}) {
  const shown = tools.slice(0, max);
  const rest = tools.length - shown.length;
  return (
    <span className={clsx("sb-tool-stack", className)}>
      {shown.map((t) => (
        <ToolGlyphFrame key={t} tool={t} size={size} pip={false} className="bg-bg-2" />
      ))}
      {rest > 0 && (
        <span
          className="inline-grid place-items-center rounded-pill bg-bg-4 px-1 text-[10px] font-medium text-fg-2"
          style={{ height: size, minWidth: size }}
        >
          +{rest}
        </span>
      )}
    </span>
  );
}
