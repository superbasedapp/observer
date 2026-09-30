import type { LucideIcon, LucideProps } from "lucide-react";

// Icon — the ONE wrapper every app uses for a UI icon (lucide-react), so the
// size scale and stroke weight are decided once instead of per call site.
//
// Why a wrapper: lucide draws on a 24px box at stroke 2, the hand-rolled
// shared set on a 16px box at stroke 1.4. At the dashboards' 12-16px sizes a
// raw lucide icon reads ~40% heavier than its neighbours. The wrapper pins
// strokeWidth 1.75 with absoluteStrokeWidth off, which lands within ~0.1px of
// the existing set at size 14, and snaps sizes to a 4-step scale.
//
// Brand marks (tool / model / host / IdP logos, the SuperBased mark) are NOT
// icons in this sense — they stay in their generated tables.

export type IconSize = "xs" | "sm" | "md" | "lg" | "xl";
const SIZE: Record<IconSize, number> = { xs: 12, sm: 14, md: 16, lg: 20, xl: 32 };

export function Icon({
  icon: Glyph,
  size = "sm",
  label,
  className,
  ...rest
}: {
  icon: LucideIcon;
  size?: IconSize | number;
  /** Accessible name. Omit for decorative icons next to visible text. */
  label?: string;
  className?: string;
} & Omit<LucideProps, "size" | "ref">) {
  const px = typeof size === "number" ? size : SIZE[size];
  return (
    <Glyph
      size={px}
      strokeWidth={1.75}
      className={className}
      aria-hidden={label ? undefined : true}
      aria-label={label}
      role={label ? "img" : undefined}
      focusable={false}
      {...rest}
    />
  );
}
