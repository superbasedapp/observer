import { HelpInd } from "@/components/HelpInd";
import { Pill } from "@/components/primitives";
import {
  ASSESS_ENV_TOP_LEVEL,
  assessEnvFilesLine,
  assessEnvLine,
  assessPreflightRows,
  assessSafetyRows,
  assessToolLine,
  type AssessEnv,
  type AssessPreflightNote,
  type AssessSafetyRow,
  type AssessToolRow,
} from "@/lib/secAssess";

// AssessBeforeStart is what a penetration test or red team plan says before the
// run starts (docs/plans/security-assessments-depth-plan-2026-11-14.md W4.2 to
// W4.6): the facts Observer noticed in the project's files (advice, never a
// refusal), the environment files at the top level of the project's folder that
// the sandbox can read (those in subfolders are not counted, and the sentence
// says so), the tools in the sandbox, and how each safety rule is held: by the
// task alone, or with a check of Observer's own that prevents it, looks at it
// afterwards or only lets you stop the run. The two lists are folded: they are
// reference, not something to act on. It claims nothing about the project:
// Observer reads file names and a few well-known files from outside the
// sandbox, and says where it cannot tell.

export function AssessBeforeStart({
  preflight,
  env,
  tools,
  safety,
}: {
  preflight?: AssessPreflightNote[];
  env?: AssessEnv;
  tools?: AssessToolRow[];
  safety?: AssessSafetyRow[];
}) {
  const rows = assessPreflightRows(preflight);
  const envLine = assessEnvLine(env);
  const filesLine = envLine ? assessEnvFilesLine(env) : "";
  const toolRows = tools ?? [];
  const safetyRows = assessSafetyRows(safety);
  if (rows.length === 0 && !envLine && toolRows.length === 0 && safetyRows.length === 0) return null;
  return (
    <section aria-labelledby="assess-before-h" className="space-y-2" data-testid="assess-before">
      <h3 id="assess-before-h" className="m-0 flex items-center text-[12px] font-medium text-fg-2">
        Before it starts
        <HelpInd id="card.code_security_assess_start" />
      </h3>

      {rows.length > 0 && (
        <ul className="m-0 list-none space-y-1.5 p-0" aria-label="Facts noticed in the project" data-testid="assess-preflight">
          {rows.map((r) => (
            <li key={r.id} className="flex flex-wrap items-start gap-x-2 gap-y-0.5" data-testid={`assess-preflight-${r.id}`}>
              <Pill variant={r.tone} case="none">
                {r.label}
              </Pill>
              <span className="min-w-0 flex-1 basis-56 break-words text-fg-2">{r.text}</span>
            </li>
          ))}
        </ul>
      )}

      {envLine && (
        <div className="space-y-0.5" data-testid="assess-env">
          <p className="m-0 break-words text-fg-2">{envLine}</p>
          {filesLine && <p className="m-0 break-words text-[11.5px] text-fg-3">{filesLine}</p>}
          <p className="m-0 break-words text-[11.5px] text-fg-3" data-testid="assess-env-top-level">
            {ASSESS_ENV_TOP_LEVEL}
          </p>
        </div>
      )}

      {toolRows.length > 0 && (
        <details className="text-fg-2" data-testid="assess-tools">
          <summary className="cursor-pointer text-[11.5px] font-medium text-fg-3 hover:text-fg-1">Tools in the sandbox</summary>
          <ul className="m-0 mt-1.5 list-none space-y-1.5 border-l-2 border-line-2 p-0 pl-3">
            {toolRows.map((t) => (
              <li key={t.id} className="space-y-0.5" data-testid={`assess-tool-${t.id}`}>
                <span className="break-all font-mono text-[11.5px] text-fg-1">{t.command}</span>
                <span className="block break-words text-[11.5px] text-fg-2">{assessToolLine(t)}</span>
              </li>
            ))}
          </ul>
          <p className="m-0 mt-1.5 text-[11.5px] text-fg-3">
            Observer looks in the sandbox&apos;s standard folders from outside, and the agent is told to check for each tool itself.
          </p>
        </details>
      )}

      {safetyRows.length > 0 && (
        <details className="text-fg-2" data-testid="assess-safety">
          <summary className="cursor-pointer text-[11.5px] font-medium text-fg-3 hover:text-fg-1">What holds each rule</summary>
          <ul className="m-0 mt-1.5 list-none space-y-1.5 border-l-2 border-line-2 p-0 pl-3">
            {safetyRows.map((r) => (
              <li key={r.id} className="space-y-0.5" data-testid={`assess-safety-${r.id}`}>
                <div className="flex flex-wrap items-start gap-x-2 gap-y-0.5">
                  <span className="min-w-0 flex-1 basis-56 break-words text-fg-1">{r.rule}</span>
                  <Pill variant={r.tone} case="none" className="max-w-full">
                    {r.held}
                  </Pill>
                </div>
                {r.where.map((w) => (
                  <span key={w} className="block break-words text-[11.5px] text-fg-3">
                    {w}
                  </span>
                ))}
              </li>
            ))}
          </ul>
        </details>
      )}
    </section>
  );
}
