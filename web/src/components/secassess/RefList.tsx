import clsx from "clsx";
import type { Tone } from "@shared/lib/tone";
import { Pill } from "@/components/primitives";
import type { ModelRef } from "@/lib/secAssessModel";

// RefList shows the places in the project an agent cited, each with what
// Observer found when it looked: the file and line, and the word for the
// reference's state. The state is Observer's own finding. "Found near the
// cited line" says the text the agent quoted is on a code line near the cited
// line; it does not say a control works. The quoted text is the agent's and
// is shown as text.

/** The words of a reference state, in the one table the model view reads. */
const REF_STATE_WORDS: Readonly<Record<string, { label: string; tone: Tone }>> = {
  found: { label: "Found near the cited line", tone: "success" },
  exists: { label: "Location exists, nothing matched", tone: "neutral" },
  claimed_not_found: { label: "Claimed, not found", tone: "warn" },
  missing: { label: "File or line not found", tone: "warn" },
  invalid: { label: "Malformed", tone: "warn" },
  unchecked: { label: "Not checked", tone: "neutral" },
};

/** refStateWords is a reference state in words. A state this view does not know, and no state at all, read as not checked. */
export function refStateWords(state: string | undefined): { label: string; tone: Tone } {
  if (state !== undefined && Object.prototype.hasOwnProperty.call(REF_STATE_WORDS, state)) return REF_STATE_WORDS[state];
  return REF_STATE_WORDS.unchecked;
}

/** refLocation is "path:line" (or "path:line-end" for a range, or the bare path when no line is cited). */
export function refLocation(r: ModelRef): string {
  const path = r?.path ?? "";
  if (typeof r?.line !== "number" || r.line <= 0) return path;
  const end = typeof r.end_line === "number" && r.end_line > r.line ? `-${r.end_line}` : "";
  return `${path}:${r.line}${end}`;
}

/** The line shown when a claim cites no place in the code. */
export const NO_PLACE_CITED = "No place in the code is cited.";

export function RefList({ refs, emptyText = NO_PLACE_CITED, className }: { refs?: ModelRef[]; emptyText?: string; className?: string }) {
  const list = (refs ?? []).filter((r) => r != null);
  if (list.length === 0) {
    return (
      <p className={clsx("m-0 text-[11.5px] text-fg-3", className)} data-testid="assess-refs-none">
        {emptyText}
      </p>
    );
  }
  return (
    <ul className={clsx("m-0 list-none space-y-1 p-0", className)} data-testid="assess-refs">
      {list.map((r, i) => {
        const w = refStateWords(r.state);
        return (
          <li key={i} className="flex min-w-0 flex-wrap items-baseline gap-x-2 gap-y-0.5 text-[11.5px]" data-ref-state={r.state ?? "unchecked"}>
            <code className="min-w-0 break-all font-mono text-[11px] text-fg-1">{refLocation(r)}</code>
            <Pill variant={w.tone} case="none">
              {w.label}
            </Pill>
            {r.state === "found" && typeof r.match_line === "number" && <span className="text-fg-3">{`at line ${r.match_line}`}</span>}
            {r.needle && (
              <span className="basis-full min-w-0 break-words text-fg-3">
                {"The agent quoted "}
                <code className="font-mono text-[11px] text-fg-2">{r.needle}</code>
              </span>
            )}
          </li>
        );
      })}
    </ul>
  );
}
