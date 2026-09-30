import clsx from "clsx";
import { CircleHelp } from "lucide-react";
import { Icon, Tooltip } from "@/components/primitives";

// HelpInd is the inline indicator a column header / tile / chart can
// render to flag "there's help for this entity." Hovering shows the
// one-liner via the themed Tooltip primitive; clicking opens the
// drawer scrolled to the entry.
//
// Lives outside HelpDrawer.tsx so importing it does NOT drag the
// 164-entry registry into the shell chunk. The delegated click
// handler in App.tsx is what actually opens the drawer.
export function HelpInd({
  id,
  className,
}: {
  id: string;
  className?: string;
}) {
  return (
    <Tooltip
      content={
        <span className="block">
          Click for help <span className="text-fg-3">·</span> press{" "}
          <kbd>?</kbd> for the full drawer
        </span>
      }
      side="top"
      maxWidth={240}
    >
      <button
        type="button"
        data-help-id={id}
        aria-label="Show help"
        className={clsx(
          "ml-1 inline-flex h-3.5 w-3.5 items-center justify-center rounded-pill text-fg-3 hover:text-accent focus:text-accent focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-ring)]",
          className,
        )}
      >
        <Icon icon={CircleHelp} size={13} />
      </button>
    </Tooltip>
  );
}

// TitleWithHelp pairs a text title with an inline HelpInd. Designed
// to be passed as ChartShell's `title` prop (ReactNode-typed).
export function TitleWithHelp({
  text,
  helpId,
}: {
  text: string;
  helpId: string;
}) {
  return (
    <span className="inline-flex items-center">
      {text}
      <HelpInd id={helpId} />
    </span>
  );
}
