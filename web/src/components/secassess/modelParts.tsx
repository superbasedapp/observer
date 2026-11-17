import { useCallback, useEffect, useLayoutEffect, useRef, useState, type ReactNode, type RefObject } from "react";
import clsx from "clsx";
import { ArrowDown, ArrowUp, ArrowUpDown } from "lucide-react";
import type { Tone } from "@shared/lib/tone";
import { Icon } from "@/components/primitives";
import { writeClipboard } from "@/lib/clipboard";

// modelParts holds the small pieces every part of the assessment model view
// shares: the tone to text-colour table, the sub-heading and "the agent says"
// tag, the sort button of a table header and the copy hook. The words of the
// closed values (statuses, frameworks, kinds) are in lib/secAssessModel.
// Presentational; nothing here reads the network.

/** TONE_TEXT is a tone's text colour, for a line that is not a pill. */
export const TONE_TEXT: Readonly<Record<Tone, string>> = {
  neutral: "text-fg-3",
  success: "text-success",
  warn: "text-warn",
  danger: "text-danger",
  info: "text-info",
  accent: "text-accent",
};

/** SubHeading is the small label over a block of the model view, an h3 under the dialog's h2. `agent` adds the "the agent says" tag. */
export function SubHeading({ children, agent, className }: { children: ReactNode; agent?: boolean; className?: string }) {
  return (
    <h3 className={clsx("m-0 flex flex-wrap items-baseline gap-x-2 text-[12px] font-medium text-fg-2", className)}>
      {children}
      {agent && <AgentTag />}
    </h3>
  );
}

/** The horizontal padding of the shared table's expanded cell (px-3), taken off the width the content is given. */
const EXPANDED_PAD = 12;

/** ExpandedFit keeps an opened row's content as wide as the visible part of the table instead of as wide as the table. The shared table lays out at a minimum width and scrolls sideways, and a row opened inside it is as wide as the whole table, so on a phone every line of the opened row (a CVSS vector, a sentence) ran off the right edge and could only be read by panning the table. The content is made sticky at the scroller's left edge and as wide as the scroller, so it wraps inside what is on screen and stays put while the table's columns pan. When the table is not scrolling the width is the table's own, so nothing changes. */
export function ExpandedFit({ children }: { children: ReactNode }) {
  const ref = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState<number | undefined>(undefined);
  useLayoutEffect(() => {
    const el = ref.current;
    const scroller = el?.closest<HTMLElement>(".table-scroll-x");
    if (!el || !scroller) return;
    const measure = () => {
      const w = scroller.clientWidth - 2 * EXPANDED_PAD;
      setWidth(w > 0 ? w : undefined);
    };
    measure();
    if (typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver(measure);
    ro.observe(scroller);
    return () => ro.disconnect();
  }, []);
  return (
    <div ref={ref} data-testid="assess-expanded-fit" style={width === undefined ? undefined : { position: "sticky", left: EXPANDED_PAD, width }}>
      {children}
    </div>
  );
}

/** SortButton is a table header's sort control: a real button (the shared table's own header click is mouse only), named "Sort by <name>", with the direction in its name once it is the sort. */
export function SortButton({
  label,
  name,
  dir,
  onSort,
}: {
  label: string;
  /** The column as the button names it ("band"). */
  name: string;
  /** The direction when this column is the sort, else undefined. */
  dir: "asc" | "desc" | undefined;
  onSort: () => void;
}) {
  const state = dir === undefined ? "" : dir === "asc" ? ", sorted ascending" : ", sorted descending";
  return (
    <button
      type="button"
      aria-label={`Sort by ${name}${state}`}
      data-sort-key={name}
      onClick={onSort}
      className="inline-flex items-center gap-1 rounded-1 uppercase tracking-[0.06em] hover:text-fg-1 focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-ring)]"
    >
      {label}
      <Icon icon={dir === undefined ? ArrowUpDown : dir === "asc" ? ArrowUp : ArrowDown} size="xs" className={dir === undefined ? "text-fg-4" : "text-accent"} />
    </button>
  );
}

// useLayoutEffect warns when rendered on the server (the component tests render to a string); the effect is only needed in a browser.
const useBrowserLayoutEffect = typeof window === "undefined" ? useEffect : useLayoutEffect;

/** useSortFocus keeps a keyboard on the sort button it pressed. A new sort starts the shared table over (its key changes, so the next batches start again at the first), which re-creates the header buttons and would drop focus to the page; this puts focus back on the button pressed. Focusing it also brings the top of the restarted list into view, so a sort pressed far down a long list does not leave the end-of-list sentinel in view and load every batch in a chain.
 *  Put `ref` on the element that holds the table, call `pressed(name)` from the sort handler, and pass a value that changes with every sort as `sortToken`. */
export function useSortFocus(sortToken: string): { ref: RefObject<HTMLDivElement>; pressed: (name: string) => void } {
  const ref = useRef<HTMLDivElement>(null);
  const want = useRef<string | null>(null);
  useBrowserLayoutEffect(() => {
    const name = want.current;
    if (name === null) return;
    want.current = null;
    // The names are the closed sort keys of the two tables; none holds a quote.
    ref.current?.querySelector<HTMLElement>(`button[data-sort-key="${name}"]`)?.focus();
  }, [sortToken]);
  const pressed = useCallback((name: string) => {
    want.current = name;
  }, []);
  return { ref, pressed };
}

/** AgentTag marks text as the agent's own claim. */
export function AgentTag() {
  return <span className="text-[10.5px] font-normal normal-case tracking-normal text-fg-3">the agent says</span>;
}

/** AgentText is a block of text the agent wrote, shown as text. */
export function AgentText({ children, className }: { children: ReactNode; className?: string }) {
  return <p className={clsx("m-0 min-w-0 whitespace-pre-wrap break-words text-[12px] text-fg-1", className)}>{children}</p>;
}

/** CopyState is the copy hook's answer: nothing asked, copied, or the browser refused. */
export type CopyState = "idle" | "copied" | "failed";

/** useCopy copies text through the dashboard's one clipboard seam and reports the outcome for a moment. */
export function useCopy(): { status: CopyState; copy: (text: string) => void } {
  const [status, setStatus] = useState<CopyState>("idle");
  useEffect(() => {
    if (status === "idle") return;
    const t = window.setTimeout(() => setStatus("idle"), 2500);
    return () => window.clearTimeout(t);
  }, [status]);
  const copy = useCallback((text: string) => {
    void writeClipboard(text).then((r) => setStatus(r === "failed" ? "failed" : "copied"));
  }, []);
  return { status, copy };
}

/** CopyNote is the "Copied" confirmation line. It renders nothing while idle. */
export function CopyNote({ status, testId }: { status: CopyState; testId?: string }) {
  if (status === "idle") return null;
  return (
    <span role="status" data-testid={testId} className={clsx("text-[11.5px]", status === "copied" ? "text-success" : "text-warn")}>
      {status === "copied" ? "Copied" : "The browser did not allow copying. Select the text and copy it by hand."}
    </span>
  );
}
