import clsx from "clsx";
import type { ReactNode } from "react";
import { Tooltip } from "./Tooltip";

type Variant = "neutral" | "success" | "warn" | "danger" | "info" | "accent";

const VARIANT_CLASS: Record<Variant, string> = {
  neutral: "border-line-2 bg-bg-2 text-fg-2",
  success: "border-success/30 bg-success-soft text-success",
  warn: "border-warn/30 bg-warn-soft text-warn",
  danger: "border-danger/30 bg-danger-soft text-danger",
  info: "border-info/30 bg-info-soft text-info",
  accent: "border-accent/30 bg-accent-soft text-accent",
};

// Pill renders a small tagged label; an optional title surfaces as a
// themed Tooltip on hover/focus instead of the browser-default
// system tooltip.
export function Pill({
  children,
  variant = "neutral",
  className,
  title,
}: {
  children: ReactNode;
  variant?: Variant;
  className?: string;
  title?: ReactNode;
}) {
  const pill = (
    <span
      tabIndex={title ? 0 : undefined}
      className={clsx(
        // Design's `.pill` spec: font 10px weight 600, padding 1px 7px,
        // text-transform lowercase, letter-spacing 0.02em.
        "inline-flex items-center gap-1 rounded-pill border px-[7px] py-[1px] text-[10px] font-semibold lowercase leading-[1.4] tracking-[0.02em]",
        title && "cursor-help focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-ring)]",
        VARIANT_CLASS[variant],
        className,
      )}
    >
      {children}
    </span>
  );
  if (!title) return pill;
  return <Tooltip content={title}>{pill}</Tooltip>;
}
