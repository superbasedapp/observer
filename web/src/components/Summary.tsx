import clsx from "clsx";
import type { ReactNode } from "react";
import { ChevronRight } from "lucide-react";
import { Icon } from "@/components/primitives";

// Summary: the `<summary>` of a native `<details>` disclosure, with a lucide
// chevron in place of the browser's own triangle marker (a Unicode glyph
// that rendered in a different weight and grid on every OS). The chevron
// turns when the parent `<details>` is open; the rotation keys off the
// `open` attribute, so it needs no `group` class on the parent and nested
// disclosures cannot trigger each other. Keyboard behaviour stays native.
export function Summary({
  children,
  className,
}: {
  children: ReactNode;
  /** Text size / colour / padding; the flex row and marker are fixed here. */
  className?: string;
}) {
  return (
    <summary
      className={clsx(
        "flex cursor-pointer list-none items-center gap-1 [&::-webkit-details-marker]:hidden",
        className,
      )}
    >
      <Icon
        icon={ChevronRight}
        size={12}
        className="shrink-0 transition-transform [details[open]>summary>&]:rotate-90"
      />
      {children}
    </summary>
  );
}
