import clsx from "clsx";

// BrandMark — the SuperBased mark as SVG (the favicon's geometry: a Blueprint
// badge holding two squares in the U+259E quadrant arrangement), used by the
// three sidebars, web2's Login and webcloud. It replaced a typed "▞"
// character, which fell back to the OS monospace font whenever the loaded
// font subset lacked the Block Elements range (and was tinted --accent in
// webcloud, a brand drift). SVG renders identically everywhere and can
// animate. Colour comes from --brand-blueprint (tokens.css).
//
//   variant="badge" → the app-icon look (blue tile, white squares)
//   variant="glyph" → squares only, in Blueprint (sidebar wordmark lockup)
export function BrandMark({
  size = 20,
  variant = "glyph",
  className,
  title,
}: {
  size?: number;
  variant?: "badge" | "glyph";
  className?: string;
  /** Accessible name; omit when a visible wordmark sits next to it. */
  title?: string;
}) {
  const a11y = title ? { role: "img" as const, "aria-label": title } : { "aria-hidden": true };
  if (variant === "badge") {
    return (
      <svg width={size} height={size} viewBox="0 0 512 512" className={className} {...a11y}>
        <rect width="512" height="512" rx="112" fill="var(--brand-blueprint, #2647E8)" />
        <rect x="256" y="112" width="144" height="144" fill="var(--brand-blueprint-ink, #fff)" />
        <rect x="112" y="256" width="144" height="144" fill="var(--brand-blueprint-ink, #fff)" />
      </svg>
    );
  }
  return (
    <svg width={size} height={size} viewBox="0 0 288 288" className={className} {...a11y}>
      <rect x="144" y="0" width="144" height="144" rx="14" fill="var(--brand-blueprint, #2647E8)" />
      <rect x="0" y="144" width="144" height="144" rx="14" fill="var(--brand-blueprint, #2647E8)" />
    </svg>
  );
}

// BrandLoader — the mark's two squares hop to the other diagonal and back.
// For full-page / panel / suspense loads whose shape is not known yet (a
// shaped skeleton is better when it is). CSS: .sb-brand-loader in
// shared/styles/motion.css; reduced motion freezes it. The pre-mount boot
// screen in each app's index.html draws the same mark with inline CSS.
export function BrandLoader({
  size = 28,
  label = "Loading",
  className,
}: {
  size?: number;
  label?: string;
  className?: string;
}) {
  return (
    <span
      role="status"
      aria-label={label}
      className={clsx("sb-brand-loader", className)}
      style={{ ["--sb-loader-size" as string]: `${size}px` }}
    />
  );
}
