import { Gavel } from "lucide-react";
import { ChartShell, InlineLoading } from "@/components/primitives";
import { TitleWithHelp } from "@/components/HelpInd";
import { StatusTile } from "@/components/security/StatusTile";
import { useApi } from "@/lib/useApi";
import { judgeHeadline, judgeTiles, type OrgPromptJudgeStatus } from "@/lib/orgPromptJudge";

// OrgPromptJudgeCard is the Security page's view of the organization's
// coding-agent prompt judge on this machine (lane adm-p2). Read-only: the
// same facts `observer guard status` prints, from GET
// /api/guard/prompt/judge. It has no switch: on an organization-managed
// machine the judge is disclosed, not opted into, and an individual machine
// never runs it.
export function OrgPromptJudgeCard() {
  const api = useApi<OrgPromptJudgeStatus>("/api/guard/prompt/judge");
  const s = api.data;
  const head = s ? judgeHeadline(s) : null;
  const tiles = s ? judgeTiles(s) : [];
  return (
    <ChartShell
      title={<TitleWithHelp text="Organization prompt judge" helpId="card.security_org_prompt_judge" />}
      icon={Gavel}
      sub="Whether your organization's LLM judge reads the prompts you type on this machine, and what happens when it cannot answer. Nothing here is prompt text."
    >
      {api.loading && !s ? (
        <InlineLoading />
      ) : api.error ? (
        <p className="text-small text-danger">{api.error.message}</p>
      ) : s && head ? (
        <div className="space-y-3">
          <p className={head.tone === "warn" ? "text-small text-warn" : "text-small text-fg-1"}>{head.text}</p>
          {s.disclosure && <p className="text-caption text-fg-2">{s.disclosure}</p>}
          {s.active && s.engine_linked === false && (
            <p className="text-caption text-warn">
              This build has no admission engine: prompts are flagged (refused under a strict enforced policy), never
              evaluated.
            </p>
          )}
          {tiles.length > 0 && (
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
              {tiles.map((t) => (
                <StatusTile key={t.label} label={t.label} value={t.value} tone={t.tone} sub={t.sub} />
              ))}
            </div>
          )}
          {s.active && s.judge_route && (
            <p className="text-caption text-fg-3">
              Judge route: {s.judge_route}. Every prompt-gate hook asks it, whatever your local guard settings say.
            </p>
          )}
          {s.available && (s.residuals ?? []).length > 0 && (
            <div>
              <div className="text-caption font-medium text-fg-2">What it does not cover</div>
              <ul className="mt-1 list-inside list-disc space-y-0.5 text-caption text-fg-3">
                {(s.residuals ?? []).map((r) => (
                  <li key={r}>{r}</li>
                ))}
              </ul>
            </div>
          )}
          <p className="text-caption text-fg-3">
            CLI: <span className="font-mono">observer guard status</span> and{" "}
            <span className="font-mono">observer org status</span>.
          </p>
        </div>
      ) : null}
    </ChartShell>
  );
}
