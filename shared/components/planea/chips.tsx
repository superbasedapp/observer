import { HostMark } from "../../primitives/BrandGlyphs";
import { ModelId } from "../../primitives/ModelId";
import { TooltipSpan } from "../../primitives/Tooltip";
import { VocabDefPill as VocabPill } from "../../primitives/VocabDefPill";
import { EVAL_VERDICT, evalLabelVerdict, SPAN_KIND } from "../../lib/obsVocab";
import type { PlaneAEvalChip as ObsEvalChip } from "./types";

// Shared chip helpers (promoted from web2/src/pages/obs/chips.tsx, B5-0;
// web2 keeps a re-export shim) for the Trajectory explorer's Traces / Spans / Sessions
// tabs (web2/src/pages/obs/Trajectories.tsx, SpansTab.tsx, SessionsTab.tsx)
// and the inspector panel.

// KindChip: one span kind, tone + glyph from SPAN_KIND (lib/vocabs/obs.ts).
export function KindChip({ kind }: { kind: string }) {
  return <VocabPill of={SPAN_KIND} value={kind || "other"}>{kind || "span"}</VocabPill>;
}


function abbreviateName(name: string, max = 12): string {
  if (!name) return "eval";
  return name.length > max ? `${name.slice(0, max - 1)}…` : name;
}

// EvalChips renders up to 3 compact content-free eval chips (name + label —
// never the rationale, which stays behind the audited eval-item viewer).
// Each chip's tooltip spells out "name label score" in full.
export function EvalChips({ evals, max = 2 }: { evals?: ObsEvalChip[]; max?: number }) {
  if (!evals || evals.length === 0) {
    return <span className="text-[12px] text-fg-4">-</span>;
  }
  // Up to `max` chips on one line (no wrap): the rest collapse into +N so a
  // heavily-evaluated trace cannot double the row height or widen the
  // table; the +N title lists what was folded. Dense tables pass max={1}.
  const shown = evals.slice(0, max);
  const extra = evals.length - shown.length;
  return (
    <span className="inline-flex items-center gap-1 whitespace-nowrap">
      {shown.map((e, i) => (
        <VocabPill
          key={`${e.name}-${i}`}
          of={EVAL_VERDICT}
          value={evalLabelVerdict(e.label)}
          className="whitespace-nowrap"
          title={`${e.name} ${e.label} ${e.score}`}
        >
          {abbreviateName(e.name)}: {e.label}
        </VocabPill>
      ))}
      {extra > 0 && (
        <TooltipSpan
          className="text-caption text-fg-3"
          content={evals
            .slice(max)
            .map((e) => `${e.name}: ${e.label}`)
            .join(", ")}
        >
          +{extra}
        </TooltipSpan>
      )}
    </span>
  );
}

// ErrorCountBadge — small red count badge for "N span errors under this
// trajectory/session", shown next to a Status pill only when count > 0.
export function ErrorCountBadge({ count }: { count?: number }) {
  if (!count || count <= 0) return null;
  return (
    <TooltipSpan
      className="inline-flex min-w-[16px] items-center justify-center rounded-pill border border-danger/30 bg-danger-soft px-[5px] py-[1px] text-micro font-semibold text-danger"
      content={`${count} span error${count === 1 ? "" : "s"}`}
    >
      {count}
    </TooltipSpan>
  );
}

// ModelCell — "model · provider", dot-separated, muted. The model carries its
// FAMILY mark (ModelId -> table-driven modelFamily()) and the provider its
// HOST mark (HostMark -> hostIdFor(); nothing for an unknown host) - the two
// stay distinct, so a Bedrock-hosted Claude reads "[claude] model · [bedrock]
// bedrock". Renders a dash when neither is present (both fields are
// best-effort enrichment, absent on spans/traces the node couldn't resolve a
// model for).
export function ModelCell({ model, provider }: { model?: string; provider?: string }) {
  if (!model && !provider) return <span className="text-[12px] text-fg-4">-</span>;
  // Bounded widths so long registry ids ("nvidia/nemotron-3.5-lightning:free
  // · openrouter") cannot blow a table row out to horizontal scroll; the
  // full pair stays one hover away in the title. `truncate` only engages on
  // a sized block, hence the max-w on the flex children.
  return (
    <span className="inline-flex items-center gap-1 text-[12px]" title={[model, provider].filter(Boolean).join(" · ")}>
      {model ? (
        <ModelId model={model} mono={false} markSize={11} className="max-w-[112px]" />
      ) : (
        <span className="text-fg-4">unknown</span>
      )}
      {provider && (
        <>
          <span className="text-fg-4">·</span>
          <span className="inline-flex max-w-[64px] items-center gap-1 text-fg-3">
            <HostMark host={provider} size={11} />
            <span className="truncate">{provider}</span>
          </span>
        </>
      )}
    </span>
  );
}

// truncatePreview trims a content preview to ~n chars for a dense single-line
// cell, always ending clean (no chopped word left dangling with no marker).
export function truncatePreview(s: string | undefined, n = 90): string {
  if (!s) return "";
  const t = s.replace(/\s+/g, " ").trim();
  return t.length > n ? `${t.slice(0, n - 1)}…` : t;
}
