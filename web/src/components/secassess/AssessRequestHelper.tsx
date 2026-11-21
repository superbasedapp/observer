import { HelpInd } from "@/components/HelpInd";
import { Pill } from "@/components/primitives";
import { ASSESS_HELPER_SETTING, assessHelperView, type AssessProbePlan } from "@/lib/secAssess";
import { AssessSettingLink } from "./AssessSettingLink";

// AssessRequestHelper is what a penetration test or red team plan says about
// the request helper (docs/plans/security-assessments-depth-plan-2026-11-14.md
// W5b): the two small files Observer writes into the run folder before the
// agent starts, where they go, the request budget and pace they apply, and that
// the log they write is a file the agent can write. When the helper is off (a
// setting) or left out (no python3 in the sandbox) nothing is written, and the
// block says that every finding's evidence reads No log. It claims nothing
// about the target. The words are lib/secAssess assessHelperView's.

export function AssessRequestHelper({ probe }: { probe: AssessProbePlan }) {
  const v = assessHelperView(probe);
  if (!v) return null;
  return (
    <section aria-labelledby="assess-helper-h" className="space-y-1.5" data-testid="assess-helper" data-helper-state={v.state}>
      <h3 id="assess-helper-h" className="m-0 flex items-center gap-2 text-[12px] font-medium text-fg-2">
        <span className="inline-flex items-center">
          Request helper
          <HelpInd id="card.code_security_assess_probe" />
        </span>
        <Pill variant={v.state === "on" ? "info" : "neutral"} case="none">
          {v.state === "on" ? "Written before the start" : v.state === "off" ? "Off" : "Left out"}
        </Pill>
      </h3>
      <p className="m-0 break-words text-fg-2" data-testid="assess-helper-lead">
        {v.lead}
      </p>
      {v.files.length > 0 && (
        <>
          <ul className="m-0 flex list-none flex-wrap gap-1.5 p-0" aria-label="Files written into the run folder" data-testid="assess-helper-files">
            {v.files.map((f) => (
              <li key={f}>
                <code className="rounded-1 border border-line-2 bg-bg-2 px-1.5 py-0.5 font-mono text-[11.5px] text-fg-1">{f}</code>
              </li>
            ))}
          </ul>
          {v.dir && (
            <p className="m-0 break-words text-[11.5px] text-fg-3" data-testid="assess-helper-dir">
              {"In the run folder "}
              <code className="break-all font-mono text-[11px] text-fg-2">{v.dir}</code>
              {" in the project."}
            </p>
          )}
        </>
      )}
      {v.facts.map((t) => (
        <p key={t} className="m-0 break-words text-[11.5px] text-fg-3">
          {t}
        </p>
      ))}
      {/* An off helper is a setting: the line that names it links to it (N-10). A helper left out for want of python3 is not a setting, so it has no link. */}
      {v.state === "off" && (
        <p className="m-0 text-[11.5px]">
          <AssessSettingLink settingKey={ASSESS_HELPER_SETTING} />
        </p>
      )}
    </section>
  );
}
