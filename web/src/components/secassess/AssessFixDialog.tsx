import { useEffect } from "react";
import { Bot } from "lucide-react";
import { Button, Modal, Pill, Skeleton } from "@/components/primitives";
import { TitleWithHelp } from "@/components/HelpInd";
import { useOptionalLaunchDock } from "@/components/LaunchDock";
import { TaskPromptBlock } from "@/components/TaskPromptBlock";
import { apiReason } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import {
  FIX_NEXT_WORDS,
  FIX_TASK_WORDS,
  assessFixPlanPath,
  fixChooseBlock,
  fixErrorWords,
  fixItemWord,
  fixPlaceText,
  fixPlaceWords,
  fixPlanHeadline,
  fixPlanNotes,
  fixRetryHelps,
  fixTaskFor,
  type AssessFixItemKind,
  type AssessFixPlan,
} from "@/lib/secAssessFix";
import { SubHeading } from "./modelParts";

// AssessFixDialog is the fix plan of one threat or pen test finding (depth
// plan W6b, decision D24), modelled on the Findings tab's FixWithAgentDialog:
// it reads the task the server would give an agent (GET
// /api/security/assessments/fix), shows the project, the places the task
// lists, Observer's notes and the exact task, and says what happens next:
// "Choose agent" closes this dialog and opens the New terminal dialog in task
// mode, where the developer picks the agent and the sandbox. The agent edits
// the project in its live folder, so this dialog says so before anything
// starts. The task is Observer's wording and the places Observer located,
// never the assessment agent's prose, and nothing here changes the model or a
// finding.

export function AssessFixDialog({
  open,
  run,
  item,
  itemKind,
  onClose,
}: {
  open: boolean;
  run: string;
  item: string;
  /** What the item is, for the subtitle while the plan is being read. */
  itemKind: AssessFixItemKind;
  onClose: () => void;
}) {
  const dock = useOptionalLaunchDock();
  const plan = useApi<AssessFixPlan>(open && run !== "" && item !== "" ? assessFixPlanPath(run, item) : null);
  const data = plan.data;
  const block = fixChooseBlock(data, dock != null, plan.isStale || plan.isRefreshing);

  // This dialog sits over the model view, which also closes on Escape (a
  // listener on the document). An Escape here is caught first, on the window,
  // and stopped, so it closes this dialog and not the model view under it (the
  // same rule as the confirm dialog's).
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Escape" || e.defaultPrevented) return;
      e.preventDefault();
      e.stopPropagation();
      onClose();
    };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, [open, onClose]);

  function choose() {
    if (!data || block !== null || !dock) return;
    const task = fixTaskFor(data);
    onClose();
    dock.openNewTerminalWithTask(task);
  }

  // The reason Choose agent is off is text in the footer, not a tooltip on a
  // disabled button (a keyboard user cannot focus one). The folder case is said
  // in the body already.
  const blockShown = block !== null && (data?.project.on_disk ?? true);
  const chooseBtn = (
    <Button
      variant="primary"
      iconLeft={Bot}
      disabled={block !== null}
      aria-describedby={blockShown ? "assess-fix-block" : undefined}
      onClick={choose}
      data-testid="assess-fix-choose"
    >
      Choose agent
    </Button>
  );
  const notes = data ? fixPlanNotes(data) : [];

  return (
    <Modal
      open={open}
      onClose={onClose}
      zIndex={80}
      title={<TitleWithHelp text="Fix with an agent" helpId="card.code_security_assess_fix" />}
      subtitle={`${fixItemWord(data?.item_kind ?? itemKind)} ${item}`}
      width={640}
      bodyClassName="px-5 py-4"
      footer={
        <div className="flex items-center justify-end gap-2">
          {data && blockShown && (
            <p id="assess-fix-block" className="m-0 mr-auto text-[11.5px] text-fg-2" data-testid="assess-fix-block">
              {block}.
            </p>
          )}
          <Button variant="ghost" onClick={onClose} data-testid="assess-fix-cancel">
            Cancel
          </Button>
          {data && chooseBtn}
        </div>
      }
    >
      <div className="space-y-4 text-[12.5px]" data-testid="assess-fix-plan">
        {plan.loading && !data && (
          <div className="space-y-2" role="status" aria-label="Loading the task">
            <p className="m-0 text-fg-3">Loading the task</p>
            <Skeleton className="h-10 w-full" />
            <Skeleton className="h-24 w-full" />
          </div>
        )}
        {plan.notInstalled && <p className="m-0 text-fg-2">Code security is not installed on this machine, so there is nothing to fix from here.</p>}
        {plan.error && !plan.notInstalled && !data && (
          <div className="space-y-2">
            <p role="alert" className="m-0 text-fg-1" data-testid="assess-fix-error">
              {fixErrorWords(plan.error) ?? `The task could not be read: ${apiReason(plan.error)}`}
            </p>
            {fixRetryHelps(plan.error) && (
              <Button size="sm" variant="secondary" onClick={plan.reload} data-testid="assess-fix-retry">
                Retry
              </Button>
            )}
          </div>
        )}
        {data && (
          <>
            <p className="m-0 text-fg-1" data-testid="assess-fix-headline">
              {fixPlanHeadline(data)}
            </p>

            <section aria-label="Project" className="space-y-1.5">
              <SubHeading>Project</SubHeading>
              <div className="flex flex-wrap items-center gap-2" data-testid="assess-fix-project">
                <span className="min-w-0 break-words font-medium text-fg-1">{data.project.name || data.project.root_path}</span>
                {!data.project.on_disk && (
                  <Pill variant="warn" case="none">
                    Not on this machine
                  </Pill>
                )}
              </div>
              <span className="block break-all font-mono text-[11px] text-fg-3">{data.project.root_path}</span>
              {!data.project.on_disk && (
                <p className="m-0 text-[11.5px] text-fg-3">{"This project's folder is not on this machine, so an agent cannot be started on it from here."}</p>
              )}
            </section>

            <section aria-label="Places in the task" className="space-y-1.5">
              <SubHeading>Places in the task</SubHeading>
              <ul className="m-0 list-none space-y-1 p-0" data-testid="assess-fix-places">
                {data.places.map((p, i) => {
                  const w = fixPlaceWords(p.state);
                  return (
                    <li key={i} className="flex min-w-0 flex-wrap items-baseline gap-x-2 gap-y-0.5 text-[11.5px]" data-place-state={p.state}>
                      <code className="min-w-0 break-all font-mono text-[11px] text-fg-1">{fixPlaceText(p)}</code>
                      <Pill variant={w.tone} case="none">
                        {w.label}
                      </Pill>
                    </li>
                  );
                })}
              </ul>
            </section>

            {notes.length > 0 && (
              <div className="space-y-1" data-testid="assess-fix-notes">
                {notes.map((n, i) => (
                  <p key={i} className="m-0 text-[11.5px] text-fg-2">
                    {n}
                  </p>
                ))}
              </div>
            )}

            <section aria-label="The task the agent gets" className="space-y-1.5">
              <SubHeading>The task the agent gets</SubHeading>
              <TaskPromptBlock text={data.prompt} testId="assess-fix-prompt" />
              <p className="m-0 text-[11.5px] text-fg-2" data-testid="assess-fix-next">
                {FIX_NEXT_WORDS}
              </p>
              <p className="m-0 text-[11.5px] text-fg-3">{FIX_TASK_WORDS}</p>
            </section>
          </>
        )}
      </div>
    </Modal>
  );
}
