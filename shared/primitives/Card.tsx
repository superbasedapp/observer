import clsx from "clsx";
import type { ReactNode } from "react";

// Card — the plain panel chrome (`rounded-3 border border-line-2 bg-bg-2
// p-4`) that the app surfaces repeat by hand dozens of times, with an
// optional header row. Distinct from ChartShell, which is the bigger
// titled section container with its own header treatment; Card is the
// sub-panel that lives INSIDE a section.
//
// A control nested in a Card must never fill with `bg-bg-1`: that token
// equals `bg-bg-2` in the light theme, so the control disappears into the
// card. Use `bg-bg-3` (see Button / JsonPreview).

export type CardProps = {
  title?: ReactNode;
  /** One line under the title. */
  sub?: ReactNode;
  /** Right-aligned header slot (buttons, pills). */
  actions?: ReactNode;
  /** Renders the title in monospace (a config table path, a model id). */
  monoTitle?: boolean;
  className?: string;
  bodyClassName?: string;
  children?: ReactNode;
};

export function Card({
  title,
  sub,
  actions,
  monoTitle,
  className,
  bodyClassName,
  children,
}: CardProps) {
  const hasHeader = title !== undefined || sub !== undefined || actions !== undefined;
  return (
    <section
      className={clsx("rounded-3 border border-line-2 bg-bg-2 p-4", className)}
    >
      {hasHeader && (
        <header className="mb-3 flex flex-wrap items-start justify-between gap-2 border-b border-line-1 pb-2">
          <div className="min-w-0">
            {title !== undefined && (
              <h4
                className={clsx(
                  "text-[12px] font-semibold text-fg-1",
                  monoTitle
                    ? "font-mono"
                    : "uppercase tracking-[0.06em]",
                )}
              >
                {title}
              </h4>
            )}
            {sub !== undefined && (
              <p className="mt-1 text-[11.5px] leading-snug text-fg-3">{sub}</p>
            )}
          </div>
          {actions !== undefined && (
            <div className="flex shrink-0 flex-wrap items-center gap-2">
              {actions}
            </div>
          )}
        </header>
      )}
      <div className={bodyClassName}>{children}</div>
    </section>
  );
}
