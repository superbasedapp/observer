import type { Tone } from "@shared/lib/tone";
import { InfoDisclosure } from "@/components/primitives";
import { HelpInd } from "@/components/HelpInd";
import { howCheckedLines, limitsFor, plural, type ModelIssue, type ModelRecord } from "@/lib/secAssessModel";
import { SubHeading, TONE_TEXT } from "./modelParts";

// LimitsStrip is the "how this was checked" content: what Observer did and did
// not do in sentences, the issues its check found (each a sentence; the
// check's row and code are under the issue's details), and the honest limits
// of this kind of assessment, open by default. The limits are written once, in
// lib/secAssessModel (the plan's list of what an agent-run assessment can
// never claim); this strip only lists them.

/** The issue severities in the order they are listed, with their words. */
const SEVERITY_ORDER: readonly { severity: ModelIssue["severity"]; title: string; tone: Tone }[] = [
  { severity: "refused", title: "Refused", tone: "danger" },
  { severity: "dropped", title: "Left out", tone: "warn" },
  { severity: "warn", title: "Warnings", tone: "neutral" },
];

export function LimitsStrip({ record, auditLine }: { record: ModelRecord; /** The run's git check line, when the run has one. */ auditLine?: { text: string; tone: Tone } | null }) {
  const lines = howCheckedLines(record);
  const issues = record.result?.report?.issues ?? [];
  const more = record.result?.report?.issues_more ?? 0;
  const limits = limitsFor(record.contract);
  return (
    <div className="min-w-0 space-y-4" data-testid="assess-limits">
      <div className="space-y-1.5">
        <SubHeading>How this was checked</SubHeading>
        <ul className="m-0 list-none space-y-1 p-0 text-[12px]" aria-label="How this was checked">
          {lines.map((l, i) => (
            <li key={i} className={l.tone === "neutral" ? "text-fg-2" : TONE_TEXT[l.tone]} data-testid="assess-checked-line">
              {l.text}
            </li>
          ))}
          {auditLine && (
            <li className={auditLine.tone === "neutral" ? "text-fg-2" : TONE_TEXT[auditLine.tone]} data-testid="assess-checked-audit">
              {auditLine.text}
            </li>
          )}
        </ul>
      </div>

      {(issues.length > 0 || more > 0) && (
        <div className="space-y-2" data-testid="assess-issues">
          <SubHeading>{`Issues the check found (${issues.length}${more > 0 ? ` listed, ${more} more counted` : ""})`}</SubHeading>
          {SEVERITY_ORDER.map((g) => {
            const group = issues.filter((i) => i.severity === g.severity);
            if (group.length === 0) return null;
            return (
              <div key={g.severity} className="space-y-1">
                <p className={`m-0 text-[11.5px] font-medium ${TONE_TEXT[g.tone]}`}>{`${g.title} (${group.length})`}</p>
                <ul className="m-0 list-none space-y-1 p-0">
                  {group.map((i, n) => (
                    <li key={n} data-testid="assess-issue" className="min-w-0 break-words border-l-2 border-line-2 pl-3 text-[12px] text-fg-2">
                      <div>{i.message}</div>
                      <InfoDisclosure summary="Details" className="mt-0.5">
                        <p className="m-0 text-[11.5px] text-fg-3" data-testid="assess-issue-technical">
                          {"Raised by check "}
                          <code className="font-mono text-[11px] text-fg-2">{i.row}</code>
                          {", code "}
                          <code className="font-mono text-[11px] text-fg-2">{i.code}</code>
                          {i.path ? <>{", at "}<code className="break-all font-mono text-[11px] text-fg-2">{i.path}</code></> : null}
                        </p>
                      </InfoDisclosure>
                    </li>
                  ))}
                </ul>
              </div>
            );
          })}
          {more > 0 && (
            <p className="m-0 text-[11.5px] text-warn" data-testid="assess-issues-more">
              {`${more} more ${plural(more, "issue is", "issues are")} counted but not listed`}
            </p>
          )}
        </div>
      )}

      <div className="space-y-1.5">
        <div className="flex items-center">
          <SubHeading>What this assessment cannot tell you</SubHeading>
          <HelpInd id="card.code_security_assess_checked" />
        </div>
        <InfoDisclosure summary={`${limits.length} limits`} defaultOpen>
          <ol className="m-0 list-none space-y-2 p-0" aria-label="Honest limits">
            {limits.map((l) => (
              <li key={l.id} data-testid="assess-limit" data-limit-id={l.id} className="text-[12px] text-fg-2">
                {l.text}
              </li>
            ))}
          </ol>
        </InfoDisclosure>
      </div>
    </div>
  );
}
