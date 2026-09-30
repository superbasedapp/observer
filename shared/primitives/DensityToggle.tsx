import clsx from "clsx";
import { SegmentedControl } from "./SegmentedControl";
import { DENSITY, type DensityMode } from "../lib/density";

// DensityToggle - the "Comfortable / Compact" switch. Pure: the value comes
// in, the choice goes out through onChange; persistence and the <html>
// data-density stamp belong to the caller (shared/lib/useDensity).
//
// `labels` decides how the plain-word labels show (the icons always show):
//   always     - visible at every width
//   responsive - visually hidden below `sm`, visible from `sm` up (a tight
//                phone top bar keeps the icons; screen readers keep the words)
//   wide       - visually hidden below `lg`, visible from `lg` up
//   hidden     - visually hidden at every width (still read by screen readers)

type LabelMode = "always" | "responsive" | "wide" | "hidden";

// LABEL_CLASS: label mode -> static classes on the label span.
const LABEL_CLASS: Record<LabelMode, string> = {
  always: "",
  responsive: "sr-only sm:not-sr-only",
  wide: "sr-only lg:not-sr-only",
  hidden: "sr-only",
};

export function DensityToggle({
  value,
  onChange,
  labels = "always",
  size = "sm",
  className,
}: {
  value: DensityMode;
  onChange: (mode: DensityMode) => void;
  labels?: LabelMode;
  size?: "sm" | "md";
  className?: string;
}) {
  return (
    <div
      role="group"
      aria-label="Density"
      title="Density"
      className={clsx("inline-flex", className)}
    >
      <SegmentedControl<DensityMode>
        size={size}
        value={value}
        onChange={onChange}
        options={DENSITY.map((row) => ({
          value: row.mode,
          icon: row.icon,
          label: <span className={LABEL_CLASS[labels] || undefined}>{row.label}</span>,
        }))}
      />
    </div>
  );
}
