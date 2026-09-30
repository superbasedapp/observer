import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Icon, IdLink, Pill, Table, Tooltip } from "@/components/primitives";
import { CodeCommentSplit } from "@shared/primitives/CodeCommentSplit";
import { ownerReasonMeta, SHARE_BASIS_TIP } from "@/components/projectdetail/commitOwner";
import { ChartState } from "@/components/ChartState";
import { describeTruncation, TruncationBanner } from "@/components/projectdetail/TruncationBanner";
import { useApi } from "@/lib/useApi";
import { fmtInt, fmtPct, fmtRelative, fmtShortId, fmtUSD } from "@/lib/format";
import type { ProjectCommitOwner, ProjectCommitRow, ProjectCommitsResponse } from "@/lib/types";
import { ChevronDown, ChevronRight } from "lucide-react";

const LIMIT = 500;

// CommitsTab — the commit ledger (plan §3.5 CommitsTab): sha, subject,
// when, files, +/-, AI files, spend; a row expands to the prompts linked to
// it. `is_merge` / `!reachable` render as chips rather than being hidden or
// excluded (R2/R4.7: a revert or an off-branch commit still carries its
// attribution and is never deleted from the ledger).
//
// The Owner column names the session that owned the commit (the server's
// ownership rule, docs/projects-page.md "Commit ownership"); a commit with
// no owner says why ("none (human)", "merge", "not on branch") and never
// shows a guessed session. The expanded row lists every contributing
// session with its share and the AI code-vs-comment split it carried.

export function CommitsTab({ projectId, days }: { projectId: number; days: number }) {
  const [expanded, setExpanded] = useState<number | null>(null);
  const navigate = useNavigate();

  const commits = useApi<ProjectCommitsResponse>(
    `/api/project/${projectId}/commits`,
    { days, limit: LIMIT },
    [projectId, days],
  );
  const rows = commits.data?.rows ?? [];
  const truncationNote = describeTruncation(commits.data, "commits");

  return (
    <div className="space-y-3">
      {truncationNote && <TruncationBanner>{truncationNote}</TruncationBanner>}
      {rows.length >= LIMIT && (
        <p className="text-[10.5px] text-fg-3">
          Showing the last {LIMIT.toLocaleString()} commits in this window.
        </p>
      )}
      <ChartState
        loading={commits.loading && !commits.data}
        error={commits.error}
        denied={commits.denied}
        deniedPermission={commits.deniedPermission}
        empty={!commits.loading && rows.length === 0}
        emptyHint="No commits captured for this project in this window. Commit capture reads a local `git log` on the checked-out branch (HEAD) - see the Overview tab if it's unavailable."
        height={200}
      >
        <Table
          head={
            <tr>
              <th className="w-4 py-1.5" />
              <th className="py-1.5 font-medium">Commit</th>
              <th className="py-1.5 text-right font-medium">When</th>
              <th className="py-1.5 text-right font-medium">Files</th>
              <th className="py-1.5 text-right font-medium">+/-</th>
              <th className="py-1.5 text-right font-medium">AI files</th>
              <th className="py-1.5 pl-3 font-medium">Owner</th>
              <th className="py-1.5 pr-1 text-right font-medium">Spend</th>
            </tr>
          }
        >
          {rows.map((c) => (
            <CommitRows
              key={c.id}
              c={c}
              open={expanded === c.id}
              onToggle={() => setExpanded((cur) => (cur === c.id ? null : c.id))}
              onOpenSession={(id) => navigate(`/sessions?session=${encodeURIComponent(id)}`)}
            />
          ))}
        </Table>
      </ChartState>
    </div>
  );
}

function CommitRows({
  c,
  open,
  onToggle,
  onOpenSession,
}: {
  c: ProjectCommitRow;
  open: boolean;
  onToggle: () => void;
  onOpenSession: (sessionId: string) => void;
}) {
  return (
    <>
      <tr
        onClick={onToggle}
        className="cursor-pointer border-b border-line-1 last:border-0 hover:bg-bg-3/40"
      >
        <td className="py-1.5 text-center text-fg-4">
          <Icon icon={open ? ChevronDown : ChevronRight} size="xs" className="inline-block" />
        </td>
        <td className="py-1.5">
          <div className="flex items-center gap-1.5">
            <span className="font-mono text-[11px] text-fg-1">{c.sha.slice(0, 7)}</span>
            {c.is_merge && <Pill variant="neutral">merge</Pill>}
            {!c.reachable && (
              <Pill variant="warn" title="This sha fell out of the checked-out branch's history on a later scan - the row is kept, not deleted.">
                off-branch
              </Pill>
            )}
          </div>
          <div className="mt-0.5 max-w-[380px] truncate text-[11px] text-fg-2">{c.subject}</div>
        </td>
        <td className="py-1.5 text-right tabular-nums text-fg-3">{fmtRelative(c.committed_at)}</td>
        <td className="py-1.5 text-right tabular-nums text-fg-3">{fmtInt(c.files)}</td>
        <td className="py-1.5 text-right tabular-nums text-fg-3">
          <span className="text-success">+{fmtInt(c.added)}</span>{" "}
          <span className="text-danger">-{fmtInt(c.deleted)}</span>
        </td>
        <td className="py-1.5 text-right tabular-nums text-fg-3">{fmtInt(c.ai_files)}</td>
        <td className="py-1.5 pl-3">
          <OwnerCell owner={c.owner} onOpenSession={onOpenSession} />
        </td>
        <td className="py-1.5 pr-1 text-right tabular-nums text-fg-1">{fmtUSD(c.spend_usd)}</td>
      </tr>
      {open && (
        <tr className="border-b border-line-1 last:border-0 bg-bg-2/60">
          <td />
          <td colSpan={7} className="py-2 pr-3">
            <CommitOwnershipDetail c={c} onOpenSession={onOpenSession} />
            {c.prompts.length === 0 ? (
              <p className="text-[11px] text-fg-4">No prompts linked to this commit.</p>
            ) : (
              <ul className="space-y-1">
                {c.prompts.map((p) => (
                  <li key={p.action_id} className="flex items-center gap-2 text-[11px]">
                    <span className="text-fg-4">{fmtRelative(p.at)}</span>
                    <IdLink onClick={() => onOpenSession(p.session_id)}>
                      {p.session_id.slice(0, 8)}
                    </IdLink>
                    <span className="min-w-0 flex-1 truncate text-fg-2">{p.preview}</span>
                  </li>
                ))}
              </ul>
            )}
          </td>
        </tr>
      )}
    </>
  );
}

// OwnerCell renders the owning session as a link (reason in the tooltip), or
// the honest no-owner label. It stops the click so following the link does
// not also toggle the row.
function OwnerCell({
  owner,
  onOpenSession,
}: {
  owner: ProjectCommitOwner | undefined;
  onOpenSession: (sessionId: string) => void;
}) {
  if (!owner) return <span className="text-fg-4">-</span>;
  const meta = ownerReasonMeta(owner.reason);
  if (!owner.session_id) {
    return (
      <Tooltip content={meta.tip}>
        <span tabIndex={0} className="text-[11px] text-fg-3 focus:outline-none">
          {meta.label}
        </span>
      </Tooltip>
    );
  }
  const sessionId = owner.session_id;
  return (
    <span onClick={(e) => e.stopPropagation()} className="inline-flex items-center gap-1.5">
      <IdLink onClick={() => onOpenSession(sessionId)} title={`${sessionId} - owner: ${meta.tip}`}>
        {fmtShortId(sessionId, 8)}
      </IdLink>
      {owner.contributors.length > 1 && (
        <span className="text-[10.5px] text-fg-4">+{owner.contributors.length - 1}</span>
      )}
    </span>
  );
}

// CommitOwnershipDetail is the expanded row's ownership block: the AI code
// vs comment lines the commit carried, then every contributing session
// ranked by the ownership rule with its share.
function CommitOwnershipDetail({
  c,
  onOpenSession,
}: {
  c: ProjectCommitRow;
  onOpenSession: (sessionId: string) => void;
}) {
  const owner = c.owner;
  if (!owner) return null;
  const meta = ownerReasonMeta(owner.reason);
  return (
    <div className="mb-2 space-y-1.5 border-b border-line-1 pb-2 text-[11px]">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <span className="text-fg-3">AI lines carried:</span>
        <CodeCommentSplit split={c.ai_split} />
        <span className="text-fg-3">
          Owner: <span className="text-fg-2">{meta.label}</span>
        </span>
      </div>
      {owner.contributors.length === 0 ? (
        <p className="text-fg-4">{meta.tip}</p>
      ) : (
        <ul className="space-y-1">
          {owner.contributors.map((k, i) => (
            <li key={k.session_id} className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
              <IdLink onClick={() => onOpenSession(k.session_id)} title={k.session_id}>
                {fmtShortId(k.session_id, 8)}
              </IdLink>
              {i === 0 && owner.session_id === k.session_id ? (
                <Pill variant="accent">owner</Pill>
              ) : (
                <span className="text-fg-4">contributor</span>
              )}
              <Tooltip content={owner.share_basis ? SHARE_BASIS_TIP[owner.share_basis] : undefined}>
                <span tabIndex={0} className="font-mono text-fg-2 focus:outline-none">
                  {fmtPct(k.share, 0)} share
                </span>
              </Tooltip>
              <span className="text-fg-3">
                {fmtInt(k.files)} file{k.files === 1 ? "" : "s"} · {fmtInt(k.prompts)} prompt{k.prompts === 1 ? "" : "s"}
              </span>
              <CodeCommentSplit split={k.split} compact />
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
