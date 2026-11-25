// ToolGlyph re-export, kept for the importers of this path (ToolBadge).
//
// This file used to hold the legacy named UI icons (EyeIcon, ClockIcon, ...),
// thin wrappers that drew a lucide glyph through <Icon>. Since 2026-09-28
// lucide-react is the ONE base UI icon family (operator decision D2): code
// imports lucide icons and renders <Icon icon={X} /> directly, and the last
// wrapper users moved onto that, so the wrappers are gone. Brand marks (tool /
// model / host / IdP logos, the superbased mark) are NOT icons and never go
// through here. ToolGlyph, the per-tool mark (the vendor's real logo), lives in
// ./toolGlyph.tsx.

export { ToolGlyph } from "./toolGlyph";
