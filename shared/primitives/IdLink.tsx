import clsx from "clsx";
import type { ReactNode } from "react";
import { Tooltip } from "./Tooltip";

// idLinkClass — the `.id-link` visual treatment as one shared constant:
// a mono accent-colored id with a dotted underline (3px offset) that
// brightens to accent-strong on hover. Owned here and consumed by BOTH
// id-rendering primitives — IdLink (non-navigating) and EntityLink
// (navigating, EntityLink.tsx) — so the two can never drift apart.
export function idLinkClass(className?: string): string {
  return clsx(
    "inline cursor-pointer font-mono text-[11px] text-accent transition-colors hover:text-accent-strong",
    // Dotted underline matches design — 3px offset puts the dots just
    // below the descender line.
    "underline decoration-dotted decoration-accent/50 underline-offset-[3px] hover:decoration-accent-strong",
    className,
  );
}

// IdLink — design's `.id-link` primitive (`design/app.css:543-551`).
// Renders a mono accent-colored ID with a dotted underline (3px
// offset) that brightens to accent-strong on hover. Used wherever a
// session-id / message-id / hash is rendered as a clickable inline
// label. When `onClick` is provided, mounts as a button so it picks
// up tabbable + accessible behavior; otherwise mounts as a span.
//
// `title` (optional) renders as a themed Tooltip rather than the
// browser-default system tooltip — most callers pass the full ID
// here while showing a truncated version in `children`, so the
// tooltip body wraps mono-styled.
export function IdLink({
  children,
  onClick,
  title,
  className,
}: {
  children: ReactNode;
  onClick?: () => void;
  title?: ReactNode;
  className?: string;
}) {
  const base = idLinkClass(className);
  const tooltipContent =
    typeof title === "string" ? (
      <span className="break-all font-mono">{title}</span>
    ) : (
      title
    );
  const element = onClick ? (
    <button
      type="button"
      onClick={(e) => {
        e.stopPropagation();
        onClick();
      }}
      className={base}
    >
      {children}
    </button>
  ) : (
    <span className={base}>{children}</span>
  );
  if (!title) return element;
  return <Tooltip content={tooltipContent}>{element}</Tooltip>;
}
