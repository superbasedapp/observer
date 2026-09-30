import { TOOL_LOGOS } from "./toolLogos";
import { toolMeta } from "./tools";

// ToolGlyph — the per-tool mark: the vendor's real logo from the generated
// TOOL_LOGOS table (./toolLogos.tsx; regenerate with design/brand-icons).
// shared/lib/icons.tsx re-exports it, so importers of the old abstract marks
// keep working unchanged.
//
// Unknown tools (a tool id the frontend table hasn't learned yet) get a
// MONOGRAM of the label's first letter instead of the old anonymous dot, so a
// new adapter is still recognisable before its logo lands.
export function ToolGlyph({
  tool,
  size = 12,
  className,
}: {
  tool: string;
  size?: number;
  className?: string;
}) {
  const logo = TOOL_LOGOS[tool];
  if (logo) {
    return (
      <svg
        width={size}
        height={size}
        viewBox="0 0 24 24"
        fill="currentColor"
        fillRule="evenodd"
        className={className}
        aria-hidden
      >
        {logo.mono}
      </svg>
    );
  }
  const letter = (toolMeta(tool).label || tool || "?").trim().charAt(0).toUpperCase();
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" className={className} aria-hidden>
      <text
        x="12"
        y="12"
        dy=".36em"
        textAnchor="middle"
        fontSize="17"
        fontWeight="700"
        fontFamily="Inter, ui-sans-serif, system-ui, sans-serif"
        fill="currentColor"
      >
        {letter}
      </text>
    </svg>
  );
}
