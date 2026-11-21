import { useEffect, useMemo, useRef, useState } from "react";
import clsx from "clsx";
import { Play } from "lucide-react";
import { Icon } from "../../primitives/Icon";
import { Pill } from "../../primitives/Pill";
import { SlideOver } from "../../primitives/SlideOver";

// HelpDrawer: the help drawer CHROME every app shares (search, the grouped
// expandable entries, scroll-to-entry, the tour button, the key hints). Pure:
// the CONTENT is injected. Each app keeps its own registry, its own category
// labels and its own filtering (the node withholds help for pages hidden on
// a managed machine and words some entries per posture) and passes the
// result here; the tour is a callback, so shared never imports an app's
// tour provider. Opened by the app's delegated `[data-help-id]` listener
// (HelpInd) and the global `?` key.

/** HelpDrawerEntry is the structural shape of an app's help entry. */
export type HelpDrawerEntry = {
  id: string;
  category: string;
  title: string;
  /** One-liner shown in the hover tooltip and the collapsed row. */
  oneLiner: string;
  detail?: string;
  formula?: string;
  source?: string;
  example?: string;
  /** Cross-links by id, rendered as chips. */
  related?: string[];
};

/** HelpDrawerCategory: one section, in display order. */
export type HelpDrawerCategory = { id: string; label: string };

/** groupHelpEntries groups entries by the given category order (pure). */
export function groupHelpEntries<E extends HelpDrawerEntry>(
  entries: readonly E[],
  categories: readonly HelpDrawerCategory[],
): Array<{ category: HelpDrawerCategory; items: E[] }> {
  return categories
    .map((category) => ({ category, items: entries.filter((e) => e.category === category.id) }))
    .filter((g) => g.items.length > 0);
}

/** filterHelpEntries is the drawer's search (title, one-liner, detail). */
export function filterHelpEntries<E extends HelpDrawerEntry>(entries: readonly E[], query: string): E[] {
  const q = query.trim().toLowerCase();
  if (!q) return [...entries];
  return entries.filter(
    (e) =>
      e.title.toLowerCase().includes(q) ||
      e.oneLiner.toLowerCase().includes(q) ||
      (e.detail ?? "").toLowerCase().includes(q),
  );
}

export function HelpDrawer({
  open,
  onClose,
  initialId,
  entries,
  categories,
  onTour,
  zIndex,
}: {
  open: boolean;
  onClose: () => void;
  initialId?: string | null;
  entries: readonly HelpDrawerEntry[];
  categories: readonly HelpDrawerCategory[];
  /** Starts the app's guided tour; the button is omitted without it. */
  onTour?: () => void;
  /**
   * The drawer's stacking level (SlideOver's zIndex). An app whose help can
   * be opened from inside a dialog or another overlay passes a level above
   * them, so the drawer never opens behind the control that asked for it;
   * omitted, the page level every slide-over uses.
   */
  zIndex?: number;
}) {
  const [query, setQuery] = useState("");
  const [activeId, setActiveId] = useState<string | null>(null);
  const itemRefs = useRef<Map<string, HTMLLIElement>>(new Map());

  // Sync the externally-supplied initialId into local state on open.
  useEffect(() => {
    if (open) setActiveId(initialId ?? null);
  }, [open, initialId]);

  // Scroll the active entry into view when the drawer opens (or when the
  // user clicks a different HelpInd while the drawer is already open). The
  // two-frame wait gives SlideOver's transition + the expanded body's layout
  // pass time to settle before measuring scroll offsets; without it an
  // entry deep in the registry opened at the top of the list.
  useEffect(() => {
    if (!open || !activeId) return;
    const el = itemRefs.current.get(activeId);
    if (!el) return;
    const id = requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        el.scrollIntoView({ block: "center", behavior: "smooth" });
      });
    });
    return () => cancelAnimationFrame(id);
  }, [open, activeId]);

  const filtered = useMemo(() => filterHelpEntries(entries, query), [entries, query]);
  const grouped = useMemo(() => groupHelpEntries(filtered, categories), [filtered, categories]);

  return (
    <SlideOver
      open={open}
      onClose={onClose}
      title="Help"
      subtitle={`${entries.length} entries · search anything · press ? to toggle`}
      width={560}
      zIndex={zIndex}
    >
      <div className="flex h-full flex-col">
        {onTour && (
          <div className="border-b border-line-1 px-4 pt-4">
            <button
              type="button"
              onClick={() => {
                onClose();
                onTour();
              }}
              className="flex w-full items-center justify-center gap-1.5 rounded-2 border border-accent/40 bg-accent-soft px-3 py-2 text-[12px] font-semibold text-accent transition-colors hover:bg-accent/20"
            >
              <Icon icon={Play} size="xs" /> Take the product tour
            </button>
          </div>
        )}
        <div className="border-b border-line-1 p-4">
          <input
            type="search"
            autoFocus
            placeholder="Search help…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="h-9 w-full rounded-2 border border-line-2 bg-bg-2 px-3 text-[12px] text-fg-1 placeholder:text-fg-4 focus:border-accent focus:outline-none"
          />
        </div>
        <div className="min-h-0 flex-1 overflow-y-auto p-4">
          {filtered.length === 0 ? (
            <div className="rounded-2 border border-dashed border-line-2 px-4 py-6 text-center text-[12px] text-fg-3">
              No help entries match &quot;{query}&quot;.
            </div>
          ) : (
            grouped.map(({ category, items }) => (
              <section key={category.id} className="mb-5">
                <h3 className="mb-2 text-[10px] font-semibold uppercase tracking-[0.08em] text-fg-3">
                  {category.label} · {items.length}
                </h3>
                <ul className="space-y-2">
                  {items.map((e) => (
                    <HelpItem
                      key={e.id}
                      entry={e}
                      expanded={activeId === e.id}
                      onToggle={() => setActiveId((cur) => (cur === e.id ? null : e.id))}
                      liRef={(el) => {
                        if (el) itemRefs.current.set(e.id, el);
                        else itemRefs.current.delete(e.id);
                      }}
                    />
                  ))}
                </ul>
              </section>
            ))
          )}
        </div>
        <footer className="border-t border-line-1 bg-bg-2 px-4 py-2 text-[10.5px] text-fg-3">
          <kbd className="rounded-1 border border-line-3 bg-bg-3 px-1.5 py-0.5 font-mono">?</kbd>{" "}
          toggles ·{" "}
          <kbd className="rounded-1 border border-line-3 bg-bg-3 px-1.5 py-0.5 font-mono">Esc</kbd>{" "}
          closes
        </footer>
      </div>
    </SlideOver>
  );
}

function HelpItem({
  entry,
  expanded,
  onToggle,
  liRef,
}: {
  entry: HelpDrawerEntry;
  expanded: boolean;
  onToggle: () => void;
  liRef?: (el: HTMLLIElement | null) => void;
}) {
  const hasBody = Boolean(
    entry.detail || entry.formula || entry.source || entry.example || entry.related?.length,
  );
  return (
    <li
      ref={liRef}
      className={clsx(
        "rounded-2 border bg-bg-2 transition-colors",
        expanded ? "border-accent/40" : "border-line-1 hover:border-line-3",
      )}
    >
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={hasBody ? expanded : undefined}
        className="flex w-full items-start gap-2 px-3 py-2 text-left"
      >
        <div className="min-w-0 flex-1">
          <div className="flex items-baseline gap-1.5">
            <span className="text-[12px] font-semibold text-fg-1">{entry.title}</span>
            <code className="text-[10px] text-fg-4">{entry.id}</code>
          </div>
          <p className="mt-0.5 text-[11.5px] text-fg-2">{entry.oneLiner}</p>
        </div>
      </button>
      {expanded && hasBody && (
        <div className="space-y-2 border-t border-line-1 px-3 py-2 text-[11.5px] text-fg-2">
          {entry.detail && <p>{entry.detail}</p>}
          {entry.formula && <Block label="Formula" mono text={entry.formula} />}
          {entry.source && <Block label="Source" text={entry.source} />}
          {entry.example && <Block label="Example" mono text={entry.example} />}
          {entry.related && entry.related.length > 0 && (
            <div className="flex flex-wrap gap-1">
              {entry.related.map((id) => (
                <Pill key={id}>{id}</Pill>
              ))}
            </div>
          )}
        </div>
      )}
    </li>
  );
}

function Block({ label, text, mono }: { label: string; text: string; mono?: boolean }) {
  return (
    <div>
      <div className="mb-0.5 text-[10px] font-semibold uppercase tracking-[0.06em] text-fg-3">{label}</div>
      {mono ? (
        <pre className="m-0 overflow-x-auto rounded-1 bg-bg-1 px-2 py-1 font-mono text-[11px] text-fg-1">{text}</pre>
      ) : (
        <p className="text-fg-2">{text}</p>
      )}
    </div>
  );
}
