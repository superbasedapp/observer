import clsx from "clsx";
import { useEffect, useState } from "react";
import type { LucideIcon } from "lucide-react";
import { Icon } from "./Icon";

// SectionNav: a sticky row of chips that jump to sections of a long page and
// highlight the one in view. For pages that grew into one long column
// (Analysis). Pure presentational: the page places an element with each
// item's id where the section starts; this component only observes those.

export type SectionNavItem = {
  id: string;
  label: string;
  /** Optional glyph before the label (the section card's own icon). */
  icon?: LucideIcon;
  /** "danger" tints a destructive section's chip (e.g. delete my data). */
  tone?: "danger";
};

// Chip colours: [inactive, active] per tone.
const CHIP_TONE = {
  default: [
    "border-line-2 text-fg-2 hover:border-line-3 hover:text-fg-0",
    "border-accent/50 bg-accent-soft text-accent",
  ],
  danger: [
    "border-danger/40 text-danger hover:border-danger/60",
    "border-danger/60 bg-danger-soft text-danger",
  ],
} as const;

export function SectionNav({
  items,
  className,
}: {
  items: SectionNavItem[];
  className?: string;
}) {
  const [active, setActive] = useState(items[0]?.id ?? "");
  useEffect(() => {
    if (typeof IntersectionObserver === "undefined") return;
    const els = items
      .map((i) => document.getElementById(i.id))
      .filter((e): e is HTMLElement => e != null);
    if (els.length === 0) return;
    const obs = new IntersectionObserver(
      (entries) => {
        const hit = entries
          .filter((e) => e.isIntersecting)
          .sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top)[0];
        if (hit) setActive(hit.target.id);
      },
      // A section is "current" once its anchor crosses the top third.
      { rootMargin: "0px 0px -66% 0px", threshold: 0 },
    );
    els.forEach((e) => obs.observe(e));
    return () => obs.disconnect();
  }, [items]);

  return (
    <nav
      aria-label="On this page"
      className={clsx(
        "sticky top-0 z-20 -mx-4 flex gap-1.5 overflow-x-auto border-b border-line-1 bg-bg-0/85 px-4 py-2 backdrop-blur sm:-mx-6 sm:px-6",
        className,
      )}
    >
      {items.map((it) => (
        <a
          key={it.id}
          href={`#${it.id}`}
          aria-current={active === it.id ? "true" : undefined}
          onClick={(e) => {
            const el = document.getElementById(it.id);
            if (!el) return;
            e.preventDefault();
            setActive(it.id);
            el.scrollIntoView({ behavior: "smooth", block: "start" });
          }}
          className={clsx(
            "sb-press inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-pill border px-2.5 py-1 text-[11.5px] font-medium transition-colors duration-fast focus:outline-none focus-visible:ring-2 focus-visible:ring-accent-ring",
            CHIP_TONE[it.tone ?? "default"][active === it.id ? 1 : 0],
          )}
        >
          {it.icon && <Icon icon={it.icon} size="xs" className="shrink-0" />}
          {it.label}
        </a>
      ))}
    </nav>
  );
}
