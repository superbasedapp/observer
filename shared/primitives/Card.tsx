import clsx from "clsx";
import type { ReactNode } from "react";
import { UpdatingBadge, staleClass } from "./Motion";
import type { LucideIcon } from "lucide-react";
import { Icon } from "./Icon";

// Card — the plain panel chrome (`rounded-3 border border-line-2 bg-bg-2`,
// padded by `p-card`: the --density-card-pad token, 16px comfortable = the
// old p-4) that the app surfaces repeat by hand dozens of times, with an
// optional header row. Distinct from ChartShell, which is the bigger
// titled section container with its own header treatment; Card is the
// sub-panel that lives INSIDE a section.
//
// A control nested in a Card must never fill with `bg-bg-1`: that token
// equals `bg-bg-2` in the light theme, so the control disappears into the
// card. Use `bg-bg-3` (see Button / JsonPreview).

export type CardProps = {
  title?: ReactNode;
  /** Optional lucide glyph before the title (drawn through <Icon>). */
  icon?: LucideIcon;
  /** One line under the title. */
  sub?: ReactNode;
  /** Right-aligned header slot (buttons, pills). */
  actions?: ReactNode;
  /** Renders the title in monospace (a config table path, a model id). */
  monoTitle?: boolean;
  className?: string;
  bodyClassName?: string;
  /** Body dims: its data belongs to the previous filter (new one in flight). */
  stale?: boolean;
  /** Shows the small "Updating" chip in the header (revalidating). */
  updating?: boolean;
  /** "danger" marks a danger zone: a visible danger border and a faint
   * danger wash at the top, so the destructive section reads as one.
   * "featured" marks the one recommended option in a set (a plan card): an
   * accent border, a faint accent wash and a soft accent glow. */
  tone?: "default" | "danger" | "featured";
  /** DOM id, e.g. the target of an in-page jump nav. */
  id?: string;
  children?: ReactNode;
};

// CARD_TONE_CLASS: tone -> static border / wash / glow classes (tokens only).
const CARD_TONE_CLASS: Record<NonNullable<CardProps["tone"]>, string> = {
  default: "border-line-2",
  danger: "border-danger/45 bg-[image:linear-gradient(180deg,var(--danger-soft),transparent_60%)]",
  featured:
    "border-accent/55 bg-[image:linear-gradient(180deg,var(--accent-soft),transparent_45%)] shadow-[0_0_0_1px_var(--accent-ring),0_12px_40px_-16px_var(--accent-ring)]",
};

export function Card({
  title,
  icon,
  sub,
  actions,
  monoTitle,
  className,
  bodyClassName,
  stale,
  updating,
  tone = "default",
  id,
  children,
}: CardProps) {
  const busy = !!(updating || stale);
  const hasHeader =
    title !== undefined || sub !== undefined || actions !== undefined || busy;
  return (
    <section
      id={id}
      className={clsx(
        "rounded-3 border bg-bg-2 p-card",
        CARD_TONE_CLASS[tone],
        // A jump-nav target lands a little below the top edge.
        id && "scroll-mt-4",
        className,
      )}
    >
      {hasHeader && (
        <header className="mb-3 flex flex-wrap items-start justify-between gap-2 border-b border-line-1 pb-2">
          <div className="min-w-0">
            {title !== undefined && (
              <h4
                className={clsx(
                  "flex items-center gap-1.5 text-[12px] font-semibold text-fg-1",
                  monoTitle
                    ? "font-mono"
                    : "uppercase tracking-[0.06em]",
                )}
              >
                {icon && <Icon icon={icon} size="sm" className="shrink-0 text-fg-3" />}
                {title}
              </h4>
            )}
            {sub !== undefined && (
              <p className="mt-1 text-[11.5px] leading-snug text-fg-3">{sub}</p>
            )}
          </div>
          {(actions !== undefined || busy) && (
            <div className="flex shrink-0 flex-wrap items-center gap-2">
              <UpdatingBadge show={busy} />
              {actions}
            </div>
          )}
        </header>
      )}
      <div className={clsx(staleClass(stale), bodyClassName)}>{children}</div>
    </section>
  );
}
