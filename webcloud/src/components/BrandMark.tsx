// BrandMark — the SuperBased glyph mark, matching the local dashboard's
// Sidebar Brand treatment exactly: the bare U+259E ("QUADRANT UPPER RIGHT
// AND LOWER LEFT") glyph set in the mono face and tinted Blueprint blue.
// This is the standalone glyph — NOT a badge box, no rounded-rect, no
// shadow. Rendered next to the "superbased" wordmark in the top nav and
// on the sign-in / consent cards. Purely presentational.

export function BrandMark({ size = 21 }: { size?: number }) {
  return (
    <span
      className="brand-mark mono"
      style={{ fontSize: size }}
      role="img"
      aria-label="SuperBased"
    >
      {"▞"}
    </span>
  );
}

// BrandLockup — the mark plus the lowercase "superbased" wordmark, matching
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
