import clsx from "clsx";
import { TONE_COLOR, type Tone } from "../lib/tone";
import { Tooltip } from "./Tooltip";

// NodeHealthGrid - one small square per node (a developer machine, a
// collector), coloured by its contact / health state from a closed
// vocabulary table the caller passes as `of` (web2 passes its NODE_CONTACT),
// with a themed Tooltip naming the node and the state. A state the table
// does not know renders neutral grey and is labelled by its raw id (unknown
// means unknown). A glance at the fleet, not a replacement for the table
// below it. Promoted from web2 (web2/src/components/NodeHealthGrid.tsx is now
// a re-export shim). Pure: no fetch, state or router.
export type NodeHealthCell = {
  /** Stable React key. */
  key: string;
  /** What the tooltip calls the node (hostname, developer, collector id). */
  name: string;
  /** The vocabulary value (e.g. healthy / stale / offline / never_seen). */
  state: string | null | undefined;
  /** Optional extra tooltip line (last seen, version). */
  detail?: string;
};

/**
 * NodeHealthVocab is the part of a closed-vocabulary definition the grid
 * reads: each value's tone and optional label. Structural, so an app's own
 * vocabulary def (web2's VocabDef, which also carries glyphs and hints) is
 * passed as is.
 */
export type NodeHealthVocab = {
  entries: Readonly<Record<string, { tone: Tone; label?: string }>>;
};

/** nodeHealthView resolves one state: its tone ("neutral" when unknown) and
 *  its label (the raw id, or "unknown" for an empty state, when the table
 *  has no label). The same fallbacks as web2's vocabView. */
function nodeHealthView(of: NodeHealthVocab, state: string | null | undefined): { tone: Tone; label: string } {
  const key = state ?? "";
  const entry = Object.prototype.hasOwnProperty.call(of.entries, key) ? of.entries[key] : undefined;
  return { tone: entry?.tone ?? "neutral", label: entry?.label ?? (key || "unknown") };
}

export function NodeHealthGrid({
  nodes,
  of,
  label = "Node health",
  max = 400,
  className,
}: {
  nodes: readonly NodeHealthCell[];
  /** The contact / health vocabulary the states resolve against. */
  of: NodeHealthVocab;
  /** Accessible name of the grid. */
  label?: string;
  /** Cap on squares drawn; the rest are counted in a trailing note. */
  max?: number;
  className?: string;
}) {
  if (nodes.length === 0) return null;
  const shown = nodes.slice(0, max);
  const extra = nodes.length - shown.length;
  return (
    <div role="list" aria-label={label} className={clsx("flex flex-wrap items-center gap-1", className)}>
      {shown.map((n) => {
        const v = nodeHealthView(of, n.state);
        const text = `${n.name}: ${v.label}`;
        return (
          <Tooltip
            key={n.key}
            content={
              <span className="flex flex-col">
                <span className="font-medium">{n.name}</span>
                <span>{v.label}</span>
                {n.detail && <span className="text-fg-3">{n.detail}</span>}
              </span>
            }
          >
            <span
              role="listitem"
              tabIndex={0}
              aria-label={text}
              className="sb-scale-in inline-block h-3 w-3 rounded-[3px] focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-ring)]"
              style={{ background: TONE_COLOR[v.tone] }}
            />
          </Tooltip>
        );
      })}
      {extra > 0 && <span className="ml-1 text-[11px] text-fg-3">+{extra} more</span>}
    </div>
  );
}
