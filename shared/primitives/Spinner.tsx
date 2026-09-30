import clsx from "clsx";
import { LoaderCircle } from "lucide-react";
import { Icon, type IconSize } from "./Icon";

// Spinner: the one small in-flight indicator (lucide LoaderCircle through
// <Icon>, turning; reduced motion freezes it via the motion.css catch-all).
// Use it where the shape of what is loading is unknown and a shaped skeleton
// is not possible; prefer ChartState / Skeleton shapes when it is.
export function Spinner({
  size = "sm",
  label = "Loading",
  className,
}: {
  size?: IconSize | number;
  /** Accessible name; set "" when a visible label sits next to it. */
  label?: string;
  className?: string;
}) {
  return (
    <Icon
      icon={LoaderCircle}
      size={size}
      label={label || undefined}
      className={clsx("shrink-0 animate-spin text-fg-3", className)}
    />
  );
}

// Text size + glyph per InlineLoading size: "md" for a panel body, "sm" for
// a header, a count or a table row.
const INLINE_SIZE = {
  sm: { text: "text-[11px] gap-1.5", glyph: "xs" },
  md: { text: "text-[12px] gap-2", glyph: "sm" },
} as const satisfies Record<string, { text: string; glyph: IconSize }>;

// InlineLoading: a Spinner plus a short muted label ("Loading sessions"),
// replacing the bare "Loading..." text lines. `block` centres it in a padded
// row for an empty panel body.
export function InlineLoading({
  label = "Loading",
  block,
  size = "md",
  className,
}: {
  label?: string;
  block?: boolean;
  size?: keyof typeof INLINE_SIZE;
  className?: string;
}) {
  const sz = INLINE_SIZE[size];
  return (
    <span
      role="status"
      className={clsx(
        "inline-flex items-center text-fg-3",
        sz.text,
        block && "flex w-full justify-center py-6",
        className,
      )}
    >
      <Spinner label="" size={sz.glyph} />
      {label}
    </span>
  );
}
