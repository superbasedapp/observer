import { useState } from "react";
import { Bot } from "lucide-react";
import { Button, Modal, Pill, Skeleton, TooltipSpan } from "@/components/primitives";
import { HelpInd, TitleWithHelp } from "@/components/HelpInd";
import { useOptionalLaunchDock } from "@/components/LaunchDock";
import { TaskPromptBlock } from "@/components/TaskPromptBlock";
import { apiCache, useApi } from "@/lib/useApi";
import { apiReason } from "@/lib/api";
import { fmtInt } from "@/lib/format";
import {
  FIX_ATTEMPTS_PATH,
  fixPlanHeadline,
  fixPlanPath,
  fixProjectNote,
  fixTaskFor,
  type FixPlan,
  type FixPlanProject,
  type FixSelection,
} from "@/lib/securityFix";

// FixWithAgentDialog is the fix plan (docs/plans/fix-findings-with-agent-
// plan-2026-11-13.md section 1): the open findings a selection resolves to
// (one finding, a group, or the current filter; GET /api/security/fix/plan
// reads its own rows and forces status=open), split by project, with the
// exact task prompt of the chosen project. One launch is one project:
// "Choose agent" opens the New terminal dialog in task mode for that
// project (lib/terminalTask.ts), and the developer comes back for the next.
// A project whose folder is not on this machine is listed, disabled, with
// why. Nothing here changes a finding.

/** The reason "Choose agent" is disabled, or null. */
function chooseBlock(project: FixPlanProject | null, dockReady: boolean): string | null {
  if (!project) return "Pick a project first";
  if (!project.on_disk) return "This project's folder is not on this machine";
  if (!dockReady) return "The terminal dock is not available on this page";
  return null;
}

export function FixWithAgentDialog({
  selection,
  subtitle,
  onClose,
}: {
  /** The selection; null keeps the dialog closed. */
  selection: FixSelection | null;
  /** What was selected, in words ("This finding", "Group: GHSA-...", "The filtered findings"). */
  subtitle?: string;
  onClose: () => void;
}) {
  const dock = useOptionalLaunchDock();
  const plan = useApi<FixPlan>(selection ? fixPlanPath(selection) : null);
  const [picked, setPicked] = useState<string | null>(null);
  const data = plan.data;
  const projects = data?.projects ?? [];
  const chosen = projects.find((p) => p.project_root_hash === picked) ?? projects.find((p) => p.on_disk) ?? null;
  const block = chooseBlock(chosen, dock != null);

  function choose() {
    if (!selection || !data || !chosen || block || !dock) return;
    const task = fixTaskFor(selection, data, chosen, () => apiCache.invalidate(FIX_ATTEMPTS_PATH));
    onClose();
    dock.openNewTerminalWithTask(task);
  }

  const chooseBtn = (
    <Button variant="primary" iconLeft={Bot} disabled={block !== null} onClick={choose}>
      Choose agent
    </Button>
  );

  return (
    <Modal
      open={selection != null}
      onClose={onClose}
      title={<TitleWithHelp text="Fix with an agent" helpId="card.code_security_fix" />}
      subtitle={subtitle}
      width={640}
      bodyClassName="px-5 py-4"
      footer={
        <div className="flex items-center justify-end gap-2">
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          {data && projects.length > 0 && (block ? <TooltipSpan content={block}>{chooseBtn}</TooltipSpan> : chooseBtn)}
        </div>
      }
    >
      <div className="space-y-4 text-[12.5px]" data-testid="code-security-fix-plan">
        {plan.loading && !data && (
          <div className="space-y-2" role="status" aria-label="Loading the fix plan">
            <p className="m-0 text-fg-3">Loading the fix plan</p>
            <Skeleton className="h-10 w-full" />
            <Skeleton className="h-24 w-full" />
          </div>
        )}
        {plan.notInstalled && (
          <p className="m-0 text-fg-2">Code security is not installed on this machine, so there is nothing to fix from here.</p>
        )}
        {plan.error && !plan.notInstalled && (
          <div className="space-y-2">
            <p role="alert" className="m-0 text-danger">
              {`The fix plan could not be read: ${apiReason(plan.error)}`}
            </p>
            <Button size="sm" variant="secondary" onClick={plan.reload}>
              Retry
            </Button>
          </div>
        )}
        {data && (
          <>
            <p className="m-0 flex items-center text-fg-1">
              {fixPlanHeadline(data)}
              <HelpInd id="card.code_security_fix_plan" />
            </p>
            {projects.length > 0 && (
              <section aria-labelledby="fix-plan-projects" className="space-y-2">
                <h3 id="fix-plan-projects" className="m-0 text-[11px] font-medium uppercase tracking-wide text-fg-3">
                  Project
                </h3>
                <ul className="m-0 max-h-56 list-none space-y-1.5 overflow-auto p-0">
                  {projects.map((p) => {
                    const note = fixProjectNote(p);
                    const selected = chosen?.project_root_hash === p.project_root_hash;
                    return (
                      <li key={p.project_root_hash}>
                        <label
                          className={`flex items-start gap-2 rounded-2 border px-2.5 py-2 ${selected ? "border-accent/60 bg-accent/5" : "border-line-2"} ${p.on_disk ? "cursor-pointer" : "opacity-70"}`}
                          data-testid="code-security-fix-project"
                        >
                          <input
                            type="radio"
                            name="fix-plan-project"
                            className="mt-0.5"
                            checked={selected}
                            disabled={!p.on_disk}
                            onChange={() => setPicked(p.project_root_hash)}
                          />
                          <span className="min-w-0 flex-1">
                            <span className="flex flex-wrap items-center gap-2">
                              <span className="font-medium text-fg-1">{p.name || p.root_path}</span>
                              <Pill variant="neutral">{`${fmtInt(p.findings)} ${p.findings === 1 ? "finding" : "findings"}`}</Pill>
                            </span>
                            <span className="block break-all font-mono text-[11px] text-fg-3">{p.root_path}</span>
                            {note && <span className="block text-[11.5px] text-fg-3">{note}</span>}
                          </span>
                        </label>
                      </li>
                    );
                  })}
                </ul>
              </section>
            )}
            {chosen && (
              <section aria-labelledby="fix-plan-prompt" className="space-y-1.5">
                <h3 id="fix-plan-prompt" className="m-0 text-[11px] font-medium uppercase tracking-wide text-fg-3">
                  The task the agent gets
                </h3>
                <TaskPromptBlock text={chosen.prompt} testId="code-security-fix-prompt" />
                <p className="m-0 text-[11.5px] text-fg-3">
                  Next you pick the agent. The launch policy, the sandbox and your organization's rules apply as for
                  any new terminal. A rescan decides whether each finding cleared.
                </p>
              </section>
            )}
          </>
        )}
      </div>
    </Modal>
  );
}
