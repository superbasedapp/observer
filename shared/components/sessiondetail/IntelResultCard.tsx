import type { ReactNode } from "react";
import { Pill } from "../../primitives";
import { fmtInt } from "../../lib/format";
import type { IntelResultLike } from "../../lib/types";
import { type RenderCost } from "./cost";

// IntelResultCard — the ONE presentational card for an org-served Cloud
// Intelligence per-session result, rendered identically by the org session
// drawer (web2) and the node session drawer (web). It is pure: it fetches
// nothing, routes nowhere, reads no app state, and leaves dollar rendering to
// an injected `renderCost` slot (the org passes <Money>; the node passes
// nothing, because its cache carries no cost). See docs/app-design-system.md
// and docs/plans/org-served-cloud-intelligence-plan-2026-09-10.md §3.5 (W8c).
//
// Honesty rules it follows:
//   - a session with no result renders `emptyMessage` verbatim, never an empty
//     title or a zeroed cost;
//   - every meta field (provider / model / job state / tokens / cost) is
//     optional and is OMITTED when absent rather than shown as a blank or a
//     zero — the node cache simply does not carry them;
//   - taxonomy tags and model-suggested tags are visually distinguished so a
//     reader can tell an applied classification from a suggestion.

const JOB_STATE_VARIANT: Record<string, "neutral" | "success" | "warn" | "danger" | "info" | "accent"> = {
  queued: "info",
  running: "accent",
  done: "success",
  parked: "warn",
  failed: "danger",
};

// NarrativeList renders one labelled bullet list, or nothing at all when the
// list is absent or empty - an absent field is rendered as absence, never as
// an empty heading (a result stored before the narrative fields existed
// carries none of them).
function NarrativeList({ label, items }: { label: string; items?: string[] }): ReactNode {
  if (!items || items.length === 0) return null;
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-[10px] uppercase tracking-[0.05em] text-fg-4">{label}</span>
      <ul className="list-disc space-y-0.5 pl-4">
        {items.map((s, i) => (
          <li key={`${label}-${i}`} className="text-[11px] leading-snug text-fg-2">
            {s}
          </li>
        ))}
      </ul>
    </div>
  );
}

export interface IntelResultCardProps {
  // result is the normalized enrichment; null renders the honest empty state.
  result: IntelResultLike | null;
  // emptyMessage names the exact missing piece ("no enrichment for this
  // session", "not yet enriched", ...) when result is null.
  emptyMessage: string;
  // generatedAtLabel prefixes the timestamp: "generated" on the org (its
  // created_at), "fetched" on the node (its pull time). Default "generated".
  generatedAtLabel?: string;
  // renderCost renders the provider cost as a node; omitted => no cost row
  // (the node cache has no cost figure to show).
  renderCost?: RenderCost;
  className?: string;
}

// IntelResultCard renders the card. The wrapper is the same
// bordered session-detail section the sibling panels use.
export function IntelResultCard({
  result,
  emptyMessage,
  generatedAtLabel = "generated",
  renderCost,
  className,
}: IntelResultCardProps): ReactNode {
  return (
    <section
      className={
        "rounded-3 border border-line-2 bg-bg-2 px-4 py-3 " + (className ?? "")
      }
    >
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <span className="text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-3">
          Session enrichment
        </span>
        {result?.jobState && (
          <Pill variant={JOB_STATE_VARIANT[result.jobState] ?? "neutral"}>
            {result.jobState}
          </Pill>
        )}
      </div>

      {!result ? (
        <p className="text-[11.5px] leading-snug text-fg-3">{emptyMessage}</p>
      ) : (
        <div className="space-y-2.5">
          {/* Title + confidence */}
          <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
            <span className="text-[13px] font-medium text-fg-1">
              {result.title || "(no title)"}
            </span>
            {result.confidence && (
              <Pill variant="info">{result.confidence} confidence</Pill>
            )}
          </div>

          {result.description && (
            <p className="text-[11.5px] leading-snug text-fg-2">
              {result.description}
            </p>
          )}

          {/* Taxonomy tags (applied) and suggested tags (not yet applied),
              kept visually distinct so one is not mistaken for the other. */}
          {((result.taxonomyTags && result.taxonomyTags.length > 0) ||
            (result.suggestedTags && result.suggestedTags.length > 0)) && (
            <div className="flex flex-col gap-1.5">
              {result.taxonomyTags && result.taxonomyTags.length > 0 && (
                <div className="flex flex-wrap items-center gap-1">
                  <span className="text-[10px] uppercase tracking-[0.05em] text-fg-4">
                    tags
                  </span>
                  {result.taxonomyTags.map((t, i) => (
                    <Pill key={`tax-${t}-${i}`} variant="neutral">
                      {t}
                    </Pill>
                  ))}
                </div>
              )}
              {result.suggestedTags && result.suggestedTags.length > 0 && (
                <div className="flex flex-wrap items-center gap-1">
                  <span className="text-[10px] uppercase tracking-[0.05em] text-fg-4">
                    suggested
                  </span>
                  {result.suggestedTags.map((t, i) => (
                    <Pill key={`sug-${t}-${i}`} variant="accent">
                      {t}
                    </Pill>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* The narrative half, in reading order. evidenceRefs are
              deliberately NOT rendered: "a136" / "m5" / "activity_mix" are
              server-side grounding tokens, and listing them is what made this
              card read as a dump of identifiers instead of an answer. */}
          <NarrativeList label="what was done" items={result.workDone} />
          <NarrativeList label="plans" items={result.plansImplemented} />
          <NarrativeList label="issues found" items={result.issuesFound} />
          <NarrativeList label="failures" items={result.failures} />
          <NarrativeList label="next steps" items={result.nextSteps} />
          <NarrativeList label="limitations" items={result.limitations} />

          {/* Footer: generation metadata. provider/model/tokens/cost are all
              optional - each is omitted when absent rather than zeroed. */}
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 pt-0.5 text-[10.5px] text-fg-4">
            {result.generatedAt && (
              <span>
                {generatedAtLabel} {result.generatedAt}
              </span>
            )}
            {result.provider && (
              <span>
                provider {result.provider}
                {result.model ? ` · ${result.model}` : ""}
              </span>
            )}
            {!result.provider && result.model && <span>model {result.model}</span>}
            {(result.tokensIn != null || result.tokensOut != null) && (
              <span>
                {fmtInt(result.tokensIn ?? 0)} in / {fmtInt(result.tokensOut ?? 0)} out
              </span>
            )}
            {renderCost && result.costUsd != null && (
              <span>{renderCost(result.costUsd, { kind: "total" })}</span>
            )}
            {result.schemaVersion && <span>schema {result.schemaVersion}</span>}
          </div>
        </div>
      )}
    </section>
  );
}
