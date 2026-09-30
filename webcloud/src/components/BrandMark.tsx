import { BrandMark as SharedBrandMark } from "@shared/primitives/BrandMark";

// BrandMark: the SuperBased mark, now the shared SVG (shared/primitives/
// BrandMark.tsx) in --brand-blueprint, like every other surface. It used to
// be a typed U+259E glyph tinted var(--brand-blue, var(--accent)); --brand-blue
// was never defined, so the portal's mark rendered accent-blue instead of
// Blueprint. `size` keeps its old meaning (the glyph's font size), so call
// sites are unchanged. Purely presentational.
export function BrandMark({ size = 21 }: { size?: number }) {
  return <SharedBrandMark size={Math.round(size * 0.8)} title="SuperBased" className="shrink-0" />;
}

// BrandLockup: the mark plus the lowercase "superbased" wordmark, matching
// the dashboard's Brand component (web/src/components/Sidebar.tsx). No
// "Cloud" suffix, no gradient, no title case.
export function BrandLockup({ size = 21 }: { size?: number }) {
  return (
    <span className="brand">
      <BrandMark size={size} />
      <span className="brand-word mono">superbased</span>
    </span>
  );
}
