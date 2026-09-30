import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { IdLink, Table, Tooltip } from "@/components/primitives";
import { ChartState } from "@/components/ChartState";
import { HelpInd } from "@/components/HelpInd";
import { describeTruncation, TruncationBanner } from "@/components/projectdetail/TruncationBanner";
import { fetchJSON } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { fmtInt, fmtRelative } from "@/lib/format";
import type { VocabEntry } from "@shared/lib/vocabEntry";
import { VocabPill } from "@shared/lib/vocabPill";
import type {
  ProjectPromptGradeResponse,
  ProjectPromptGradeTier,
  ProjectPromptRow,
  ProjectPromptsResponse,
  ProjectPromptStatus,
} from "@/lib/types";
import { CodeCommentSplit } from "@shared/primitives/CodeCommentSplit";

const LIMIT = 500;

// isOrgDataJudgeRefusal detects the JUDGE-1 data-authority refusal
// (internal/dataauthority.JudgeEgressAllowed via
// cmd/observer/alignment_wire.go::alignmentJudgeAdapter.AllowInput): the
// tier-J judge declining to run because this prompt's session belongs to
// the org and the configured judge endpoint is not org-approved. Rendered
// with the same calm, non-alarming honesty treatment
// web/src/components/sessiondetail/CloudRow.tsx already uses for its
// "excluded: organization-owned" copy, rather than as a generic failure.
function isOrgDataJudgeRefusal(reason: string): boolean {
  return reason.includes("belongs to the org");
}

// PROMPT_STATUS - the ONE presentation row per prompt -> commit status
// (internal/projectroi.Link, R4): tone + label; glyph from
// VOCAB_ICONS.promptStatus.
const PROMPT_STATUS: Readonly<Record<ProjectPromptStatus, VocabEntry>> = {
  committed: { tone: "success" },
  partial: { tone: "warn" },
  uncommitted: { tone: "neutral" },
  superseded: { tone: "neutral" },
  no_edits: { tone: "neutral", label: "no edits" },
};

// PromptsTab — prompt -> commit chains (plan §3.5 PromptsTab). Attribution
// rule stated on the page verbatim (R4/R10): an AI edit belongs to the last
// prompt before it in its session; a commit carries a prompt when it
// touches those files after the prompt within the configured window; reach
// is file-level, not verified line survival; reverts still count; merges
// never do.

export function PromptsTab({ projectId, days }: { projectId: number; days: number }) {
  const navigate = useNavigate();
  const prompts = useApi<ProjectPromptsResponse>(
    `/api/project/${projectId}/prompts`,
    { days, limit: LIMIT },
    [projectId, days],
  );
  const [rows, setRows] = useState<ProjectPromptRow[] | null>(null);
  const effectiveRows = rows ?? prompts.data?.rows ?? [];
  const truncationNote = describeTruncation(prompts.data, "prompts");

  const onGraded = (actionId: number, next: ProjectPromptRow) => {
    setRows((cur) => {
      const base = cur ?? prompts.data?.rows ?? [];
      return base.map((r) => (r.action_id === actionId ? next : r));
    });
  };

  return (
    <div className="space-y-3">
      <p className="flex items-start gap-1 rounded-2 border border-line-2 bg-bg-2 px-3 py-2 text-[11px] text-fg-3">
        <span>
          An AI edit belongs to the last prompt before it in its session; a commit carries a
          prompt when it touches those files after the prompt within the configured link window;
          reach is file-level, not verified line survival; reverts still count; merges never do.
        </span>
        <HelpInd id="glossary.projects_attribution" />
      </p>

      {truncationNote && <TruncationBanner>{truncationNote}</TruncationBanner>}

      {effectiveRows.length >= LIMIT && (
        <p className="text-[10.5px] text-fg-3">
          Showing the last {LIMIT.toLocaleString()} prompts in this window.
        </p>
      )}

      <ChartState
        loading={prompts.loading && !prompts.data}
        error={prompts.error}
        denied={prompts.denied}
        deniedPermission={prompts.deniedPermission}
        empty={!prompts.loading && effectiveRows.length === 0}
        emptyHint="No prompts in this window."
        height={200}
      >
        <Table
          head={
            <tr>
              <th className="py-1.5 font-medium">When</th>
              <th className="py-1.5 font-medium">Tool</th>
              <th className="py-1.5 font-medium">Prompt</th>
              <th className="py-1.5 text-right font-medium">Edits</th>
              <th className="py-1.5 font-medium">Commits</th>
              <th className="py-1.5 font-medium">Status</th>
              <th className="py-1.5 font-medium">Alignment</th>
              <th className="py-1.5 pr-1 font-medium" />
            </tr>
          }
        >
          {effectiveRows.map((p) => (
            <PromptRowLine
              key={p.action_id}
              projectId={projectId}
              p={p}
              onOpenSession={(id) => navigate(`/sessions?session=${encodeURIComponent(id)}`)}
              onGraded={(next) => onGraded(p.action_id, next)}
            />
          ))}
        </Table>
      </ChartState>
    </div>
  );
}

function PromptRowLine({
  projectId,
  p,
  onOpenSession,
  onGraded,
}: {
  projectId: number;
  p: ProjectPromptRow;
  onOpenSession: (sessionId: string) => void;
  onGraded: (next: ProjectPromptRow) => void;
}) {
  const [grading, setGrading] = useState(false);
  const [gradeError, setGradeError] = useState<string | null>(null);

  // Prefer the local/configured judge tier (cheaper, no cloud consent) over
  // Cloud Intelligence when both are offered for this prompt; a caller with
  // only one tier available gets that one.
  const tier: ProjectPromptGradeTier | null = p.grade_available?.judge
    ? "judge"
    : p.grade_available?.cloud
      ? "cloud"
      : null;

  return (
    <tr className="border-b border-line-1 last:border-0 align-top">
      <td className="py-1.5 pr-2 text-fg-3">{fmtRelative(p.at)}</td>
      <td className="py-1.5 pr-2">
        <span className="font-mono text-[10.5px] text-fg-2">{p.tool}</span>
      </td>
      <td className="max-w-[260px] py-1.5 pr-2">
        <div className="truncate text-fg-1">{p.preview}</div>
        <IdLink onClick={() => onOpenSession(p.session_id)} className="text-[10px]">
          {p.session_id.slice(0, 8)}
        </IdLink>
      </td>
      <td className="py-1.5 pr-2 text-right tabular-nums text-fg-3">
        {fmtInt(p.edits.files)} files
        {p.edits.split?.comment_share != null && (
          <div className="text-[10px] text-fg-4">
            <CodeCommentSplit split={p.edits.split} variant="share" /> comments
          </div>
        )}
      </td>
      <td className="py-1.5 pr-2">
        <div className="flex flex-wrap gap-1">
          {p.commits.map((c) => (
            <Tooltip key={c.id} content={c.subject}>
              <span tabIndex={0} className="font-mono text-[10.5px] text-fg-2 focus:outline-none">
                {c.sha.slice(0, 7)}
              </span>
            </Tooltip>
          ))}
          {p.commits.length === 0 && <span className="text-fg-4">-</span>}
        </div>
      </td>
      <td className="py-1.5 pr-2">
        <span className="inline-flex items-center gap-1">
          <VocabPill vocab="promptStatus" table={PROMPT_STATUS} value={p.status} />
          {p.status_uncertain && (
            <Tooltip content="Row caps hit on this window's AI edits and/or commits - this status could change if the missing rows were included.">
              <span className="cursor-help text-[10px] text-fg-4">(caps)</span>
            </Tooltip>
          )}
        </span>
      </td>
      <td className="py-1.5 pr-2">
        <AlignmentCell p={p} />
      </td>
      <td className="py-1.5 pr-1 text-right">
        <GradeButton
          projectId={projectId}
          p={p}
          tier={tier}
          grading={grading}
          setGrading={setGrading}
          gradeError={gradeError}
          setGradeError={setGradeError}
          onGraded={onGraded}
        />
      </td>
    </tr>
  );
}

function AlignmentCell({ p }: { p: ProjectPromptRow }) {
  if (!p.alignment) {
    return <span className="text-[10.5px] text-fg-4">not graded</span>;
  }
  const a = p.alignment;
  return (
    <Tooltip
      content={
        <div className="max-w-[280px] space-y-1 text-[10.5px]">
          {a.delivered.length > 0 && <div>delivered: {a.delivered.join(", ")}</div>}
          {a.missed.length > 0 && <div>missed: {a.missed.join(", ")}</div>}
          {a.extra.length > 0 && <div>extra: {a.extra.join(", ")}</div>}
        </div>
      }
      maxWidth={300}
    >
      <span className="cursor-help text-[10.5px] text-fg-2">
        <span className="font-mono text-fg-3">{a.tier}</span> · {fmtInt(a.delivered.length)}{" "}
        delivered
        {a.missed.length > 0 ? `, ${fmtInt(a.missed.length)} missed` : ""}
      </span>
    </Tooltip>
  );
}

function GradeButton({
  projectId,
  p,
  tier,
  grading,
  setGrading,
  gradeError,
  setGradeError,
  onGraded,
}: {
  projectId: number;
  p: ProjectPromptRow;
  tier: ProjectPromptGradeTier | null;
  grading: boolean;
  setGrading: (v: boolean) => void;
  gradeError: string | null;
  setGradeError: (v: string | null) => void;
  onGraded: (next: ProjectPromptRow) => void;
}) {
  const disabledReason = tier == null ? p.grade_available?.reason || "no grading tier available" : undefined;

  const onClick = async () => {
    if (!tier) return;
    setGrading(true);
    setGradeError(null);
    try {
      const resp = await fetchJSON<ProjectPromptGradeResponse>(
        `/api/project/${projectId}/prompts/${encodeURIComponent(String(p.action_id))}/grade`,
        undefined,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ tier }),
        },
      );
      if (resp.status === "ok" && resp.alignment) {
        onGraded({ ...p, alignment: resp.alignment });
      } else if (resp.status === "not_available") {
        setGradeError(resp.reason || "grading not available");
      } else {
        setGradeError("grading queued - check back shortly");
      }
    } catch (e) {
      setGradeError(e instanceof Error ? e.message : String(e));
    } finally {
      setGrading(false);
    }
  };

  return (
    <div className="flex flex-col items-end gap-0.5">
      <Tooltip content={disabledReason ?? `Grade with ${tier}`}>
        <button
          type="button"
          disabled={!tier || grading}
          onClick={() => void onClick()}
          className="rounded-2 border border-line-2 bg-bg-2 px-2 py-0.5 text-[10.5px] text-fg-2 hover:bg-bg-3 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {grading ? "Grading…" : "Grade"}
        </button>
      </Tooltip>
      {gradeError && (
        <span
          className={`max-w-[160px] text-right text-[9.5px] ${
            isOrgDataJudgeRefusal(gradeError) ? "text-fg-3" : "text-warn"
          }`}
        >
          {isOrgDataJudgeRefusal(gradeError) ? `org-owned session: ${gradeError}` : gradeError}
        </span>
      )}
    </div>
  );
}
