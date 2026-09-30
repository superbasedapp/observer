import clsx from "clsx";
import type { ReactNode } from "react";
import type { LucideIcon } from "lucide-react";
import { Icon } from "./Icon";
import type { Tone } from "../lib/tone";
import { Tooltip } from "./Tooltip";

// The variant set IS the vocabulary Tone (shared/lib/tone.ts).
type Variant = Tone;

const VARIANT_CLASS: Record<Variant, string> = {
  neutral: "border-line-2 bg-bg-2 text-fg-2",
  success: "border-success/30 bg-success-soft text-success",
  warn: "border-warn/30 bg-warn-soft text-warn",
  danger: "border-danger/30 bg-danger-soft text-danger",
  info: "border-info/30 bg-info-soft text-info",
  accent: "border-accent/30 bg-accent-soft text-accent",
};

/** PillCase - how a Pill transforms its text: lowercase (the design's
 *  `.pill` default), uppercase (a status / theme chip), or as written. */
export type PillCase = "lower" | "upper" | "none";

// CASE_CLASS - the text transform + letter-spacing per PillCase. `lower` is
// the design's `.pill` spec exactly (lowercase, 0.02em); `upper` matches the
// app's uppercase micro-labels (0.06em) so an uppercase chip reads as the
// same family; `none` leaves the text as written (free-text content such as
// a digest theme) at the default spacing.
const CASE_CLASS: Record<PillCase, string> = {
  lower: "lowercase tracking-[0.02em]",
  upper: "uppercase tracking-[0.06em]",
  none: "normal-case tracking-[0.02em]",
};

// Pill renders a small tagged label; an optional title surfaces as a
// themed Tooltip on hover/focus instead of the browser-default
// system tooltip. `icon` draws a vocabulary glyph (shared/lib/vocabIcons)
// at 11px before the text; `spin` turns it for an in-flight state
// (running / queued), frozen under reduced motion. `case` picks the text
// transform (CASE_CLASS; default "lower", today's rendering).
export function Pill({
  children,
  variant = "neutral",
  className,
  title,
  icon,
  spin,
  case: textCase = "lower",
}: {
  children: ReactNode;
  variant?: Variant;
  className?: string;
  title?: ReactNode;
  icon?: LucideIcon;
  spin?: boolean;
  case?: PillCase;
}) {
  const pill = (
    <span
      tabIndex={title ? 0 : undefined}
      className={clsx(
        // Design's `.pill` spec: font 10px weight 600, padding 1px 7px;
        // text-transform + letter-spacing come from CASE_CLASS (default
        // lowercase, 0.02em).
        "inline-flex items-center gap-1 rounded-pill border px-[7px] py-[1px] text-[10px] font-semibold leading-[1.4]",
        CASE_CLASS[textCase],
        title && "cursor-help focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-ring)]",
        VARIANT_CLASS[variant],
        className,
      )}
    >
      {icon && <Icon icon={icon} size={11} className={clsx("shrink-0", spin && "animate-spin")} />}
      {children}
    </span>
  );
  if (!title) return pill;
  return <Tooltip content={title}>{pill}</Tooltip>;
}
