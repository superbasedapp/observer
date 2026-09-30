import { useEffect, useMemo, useRef, useState } from "react";
import clsx from "clsx";
import {
  Icon,
  Pill,
  SlideOver,
} from "@/components/primitives";
import {
  helpByCategory,
  HELP_REGISTRY,
  type HelpCategory,
  type HelpEntry,
} from "@/lib/help";
import { useTour } from "@/components/tour/TourProvider";
import { Play } from "lucide-react";

const CATEGORY_LABEL: Record<HelpCategory, string> = {
  tab: "Tabs",
  tile: "KPI tiles",
  chart: "Charts",
  column: "Columns",
  filter: "Filters",
  metric: "Metrics",
  calc: "Calculations",
  glossary: "Glossary",
};

export function HelpDrawer({
  open,
  onClose,
  initialId,
}: {
  open: boolean;
  onClose: () => void;
  initialId?: string | null;
}) {
  const [query, setQuery] = useState("");
  const [activeId, setActiveId] = useState<string | null>(null);
  const itemRefs = useRef<Map<string, HTMLLIElement>>(new Map());
  const { startTour } = useTour();

  // Sync the externally-supplied initialId into local state on open.
  useEffect(() => {
    if (open) setActiveId(initialId ?? null);
  }, [open, initialId]);

  // Scroll the active entry into view when the drawer opens (or when
  // the user clicks a different HelpInd while the drawer is already
  // open). Two-frame wait gives SlideOver's transform + the expanded
  // body's layout pass time to settle before measuring scroll offsets.
  // Without this, opening "tab.cost" from the Cost tab landed at the
  // top of the registry — the user had to scroll through Tabs +
  // KPI tiles + Charts + Columns to find their entry. Per
  // [[feedback-fix-systemically]] this fixes every HelpInd at once;
  // each indicator was claiming "scroll to entry" semantics in its
  // doc comment but the drawer never delivered.
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

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return HELP_REGISTRY;
    return HELP_REGISTRY.filter(
      (e) =>
        e.title.toLowerCase().includes(q) ||
        e.oneLiner.toLowerCase().includes(q) ||
        (e.detail ?? "").toLowerCase().includes(q),
    );
  }, [query]);

  const grouped = useMemo(() => {
    const map: Record<HelpCategory, HelpEntry[]> = helpByCategory();
    // Filter each category against the search result.
    const allowed = new Set(filtered.map((e) => e.id));
    for (const c of Object.keys(map) as HelpCategory[]) {
      map[c] = map[c].filter((e) => allowed.has(e.id));
    }
    return map;
  }, [filtered]);

  return (
    <SlideOver
      open={open}
      onClose={onClose}
      title="Help"
      subtitle={`${HELP_REGISTRY.length} entries · search anything · press ? to toggle`}
      width={560}
    >
      <div className="flex h-full flex-col">
        <div className="border-b border-line-1 px-4 pt-4">
          <button
            type="button"
            onClick={() => {
              onClose();
              startTour();
            }}
            className="flex w-full items-center justify-center gap-1.5 rounded-2 border border-accent/40 bg-accent-soft px-3 py-2 text-[12px] font-semibold text-accent transition-colors hover:bg-accent/20"
          >
            <Icon icon={Play} size="xs" /> Take the product tour
          </button>
        </div>
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
            (Object.keys(grouped) as HelpCategory[]).map((cat) => {
              const items = grouped[cat];
              if (!items.length) return null;
              return (
                <section key={cat} className="mb-5">
                  <h3 className="mb-2 text-[10px] font-semibold uppercase tracking-[0.08em] text-fg-3">
                    {CATEGORY_LABEL[cat]} · {items.length}
                  </h3>
                  <ul className="space-y-2">
                    {items.map((e) => (
                      <HelpItem
                        key={e.id}
                        entry={e}
                        expanded={activeId === e.id}
                        onToggle={() =>
                          setActiveId((cur) => (cur === e.id ? null : e.id))
                        }
                        liRef={(el) => {
                          if (el) itemRefs.current.set(e.id, el);
                          else itemRefs.current.delete(e.id);
                        }}
                      />
                    ))}
                  </ul>
                </section>
              );
            })
          )}
        </div>
        <footer className="border-t border-line-1 bg-bg-2 px-4 py-2 text-[10.5px] text-fg-3">
          <kbd className="rounded-1 border border-line-3 bg-bg-3 px-1.5 py-0.5 font-mono">
            ?
          </kbd>{" "}
          toggles · <kbd className="rounded-1 border border-line-3 bg-bg-3 px-1.5 py-0.5 font-mono">Esc</kbd>{" "}
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
  entry: HelpEntry;
  expanded: boolean;
  onToggle: () => void;
  liRef?: (el: HTMLLIElement | null) => void;
}) {
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
        className="flex w-full items-start gap-2 px-3 py-2 text-left"
      >
        <div className="min-w-0 flex-1">
          <div className="flex items-baseline gap-1.5">
            <span className="text-[12px] font-semibold text-fg-1">
              {entry.title}
            </span>
            <code className="text-[10px] text-fg-4">{entry.id}</code>
          </div>
          <p className="mt-0.5 text-[11.5px] text-fg-2">{entry.oneLiner}</p>
        </div>
      </button>
      {expanded && (entry.detail || entry.formula || entry.source || entry.example) && (
        <div className="space-y-2 border-t border-line-1 px-3 py-2 text-[11.5px] text-fg-2">
          {entry.detail && <p>{entry.detail}</p>}
          {entry.formula && (
            <div>
              <div className="mb-0.5 text-[10px] font-semibold uppercase tracking-[0.06em] text-fg-3">
                Formula
              </div>
              <pre className="m-0 rounded-1 bg-bg-1 px-2 py-1 font-mono text-[11px] text-fg-1">
                {entry.formula}
              </pre>
            </div>
          )}
          {entry.source && (
            <div>
              <div className="mb-0.5 text-[10px] font-semibold uppercase tracking-[0.06em] text-fg-3">
                Source
              </div>
              <p className="text-fg-2">{entry.source}</p>
            </div>
          )}
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

// HelpInd moved to ./HelpInd.tsx so eager primitives (StatCard etc.)
// can import it without dragging the 164-entry registry into the
// shell chunk. Re-exported here for callers that still want the
// HelpDrawer barrel.
export { HelpInd } from "@/components/HelpInd";
