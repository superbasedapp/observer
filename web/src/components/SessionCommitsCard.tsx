import { useNavigate } from "react-router-dom";
import clsx from "clsx";
import { CircleCheck, CircleX, ExternalLink, GitPullRequestArrow, Monitor, Upload } from "lucide-react";
import { ChartState } from "@/components/ChartState";
import { Button, Icon, IdLink, Pill, Tooltip } from "@/components/primitives";
import { VocabPill } from "@shared/lib/vocabPill";
import { describeTruncation, TruncationBanner } from "@/components/projectdetail/TruncationBanner";
import { ownerReasonMeta, SHARE_BASIS_TIP } from "@/components/projectdetail/commitOwner";
import { CodeCommentSplit } from "@shared/primitives/CodeCommentSplit";
import { sessionCommitsPath, sessionDeliveryPath } from "@/lib/api";
import { fmtInt, fmtPct, fmtRelative, fmtShortId } from "@/lib/format";
import { useApi } from "@/lib/useApi";
import type { SessionCommitRow, SessionCommitsResponse, SessionDelivery, SessionDeliveryRow } from "@/lib/types";
import {
  LANDING_KIND,
  LANDING_STATUS,
  PR_CHIP,
  entry,
  facetSentence,
  landingDetail,
  prChipKey,
  prChipLabel,
  sessionHeadline,
  type SessionHeadline,
  CODE_HOSTS_HREF,
} from "@/lib/deliveryModel";
import { COMMIT_CAPTURE } from "@/lib/vocabTones";

// SessionCommitsCard - the session detail's "Commits" section (operator ask
// 2026-09-28: "track which session owned a git commit"). Reads GET
// /api/session/<id>/commits, the session side of the same ownership rule the
// Projects commit ledger shows (docs/projects-page.md "Commit ownership").
//
// Honesty rules this card holds:
//  - A commit is listed only when one of this session's prompts' AI edits
//    reached it within the link window; the card never implies the session
//    wrote the whole commit. Files and lines are what THIS session carried.
//  - "owner" means the server's ownership rule picked this session; a
//    co-contributed commit says "contributed" and links the owning session.
//  - An empty list says why: no commit reached within the window, or commit
//    capture is not available for the project - never a bare "0".
//  - The code-vs-comment split renders through CodeCommentSplit only.
export function SessionCommitsCard({ sessionId }: { sessionId: string }) {
  const navigate = useNavigate();
  const res = useApi<SessionCommitsResponse>(sessionCommitsPath(sessionId), undefined, [sessionId]);
  // Delivery (D-689): where each commit went. A failed or empty read leaves
  // the card exactly as it was; delivery adds, never hides.
  const del = useApi<SessionDelivery>(sessionDeliveryPath(sessionId), undefined, [sessionId]);
  const deliveryByCommit = new Map<number, SessionDeliveryRow>();
  for (const r of del.data?.rows ?? []) deliveryByCommit.set(r.commit_id, r);
  const headline = del.data
    ? sessionHeadline(del.data.rows, {
        defaultBranch: del.data.default_branch,
        providerLinked: del.data.provider_linked,
        rel: (iso?: string) => (iso ? fmtRelative(iso) : "at an unknown time"),
      })
    : null;
  const data = res.data;
  const rows = data?.rows ?? [];
  const captureOk = !data?.commit_capture || data.commit_capture === "ok";
  const truncationNote = describeTruncation(data, "this session's commits");
  const openSession = (id: string) => navigate(`/sessions?session=${encodeURIComponent(id)}`);

  return (
    <section className="mt-5 rounded-3 border border-line-2 bg-bg-2 px-4 py-3">
      <div className="flex items-center justify-between gap-2">
        <span className="text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-3">Commits</span>
        {data && rows.length > 0 && (
          <span className="text-[10px] tabular-nums text-fg-3">
            {fmtInt(rows.length)} commit{rows.length === 1 ? "" : "s"} · {fmtInt(rows.filter((r) => r.owner).length)} owned
          </span>
        )}
      </div>
      <p className="mt-1 text-[10.5px] text-fg-3">
        Git commits on the checked-out branch that carried files this session's prompts had the AI edit, within the
        {data ? ` ${data.link_window_days}-day` : ""} link window. Files and lines are this session's contribution, not
        the whole commit.
      </p>

      {headline && rows.length > 0 && (
        <DeliveryHeadline h={headline} providerLinked={del.data?.provider_linked ?? false} onConnect={() => navigate(CODE_HOSTS_HREF)} />
      )}

      {truncationNote && (
        <div className="mt-2">
          <TruncationBanner>{truncationNote}</TruncationBanner>
        </div>
      )}

      <ChartState loading={res.loading && !data} error={res.error} denied={res.denied} deniedPermission={res.deniedPermission} empty={false} height={72}>
        {data &&
          (rows.length === 0 ? (
            <p className="mt-2 text-[11px] text-fg-3">
              {!data.project_id
                ? "This session belongs to no project, so no commits can be linked to it."
                : !captureOk
                  ? `Commit capture not available for this project: ${COMMIT_CAPTURE[data.commit_capture!]?.tip ?? data.commit_capture} Commits cannot be linked until it is.`
                  : `No commits reached from this session's prompts within the ${data.link_window_days}-day link window.`}
            </p>
          ) : (
            <ul className="mt-2 divide-y divide-line-1">
              {rows.map((r) => (
                <CommitLine key={r.id} r={r} delivery={deliveryByCommit.get(r.id)} onOpenSession={openSession} />
              ))}
            </ul>
          ))}
      </ChartState>
    </section>
  );
}

function CommitLine({
  r,
  delivery,
  onOpenSession,
}: {
  r: SessionCommitRow;
  delivery?: SessionDeliveryRow;
  onOpenSession: (id: string) => void;
}) {
  const meta = ownerReasonMeta(r.reason);
  return (
    <li className="flex flex-col gap-1 py-2 text-[11px]">
      <div className="flex min-w-0 items-center gap-2">
        <span className="font-mono text-fg-1">{r.sha.slice(0, 7)}</span>
        <span className="min-w-0 flex-1 truncate text-fg-2">{r.subject}</span>
        <span className="shrink-0 tabular-nums text-fg-4">{fmtRelative(r.committed_at)}</span>
      </div>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        {r.owner ? (
          <Tooltip content={meta.tip}>
            <span tabIndex={0} className="focus:outline-none">
              <Pill variant="accent">owner</Pill>
            </span>
          </Tooltip>
        ) : (
          <span className="inline-flex items-center gap-1 text-fg-3">
            contributed, owned by
            {r.owner_session_id ? (
              <IdLink onClick={() => onOpenSession(r.owner_session_id!)} title={`${r.owner_session_id} - ${meta.tip}`}>
                {fmtShortId(r.owner_session_id, 8)}
              </IdLink>
            ) : (
              <span>{meta.label}</span>
            )}
          </span>
        )}
        <Tooltip content={r.share_basis ? SHARE_BASIS_TIP[r.share_basis] : undefined}>
          <span tabIndex={0} className="font-mono text-fg-2 focus:outline-none">
            {fmtPct(r.share, 0)} share
          </span>
        </Tooltip>
        <span className="text-fg-3">
          {fmtInt(r.files)} file{r.files === 1 ? "" : "s"} · {fmtInt(r.prompts)} prompt{r.prompts === 1 ? "" : "s"}
        </span>
        <CodeCommentSplit split={r.split} compact />
      </div>
      {delivery && <DeliveryLine d={delivery} />}
    </li>
  );
}

// HEADLINE_ICON is the headline glyph per kind (the tone comes from the model).
const HEADLINE_ICON: Record<SessionHeadline["kind"], typeof CircleCheck> = {
  landed_pr: GitPullRequestArrow,
  landed_local: CircleCheck,
  in_review: GitPullRequestArrow,
  blocked: CircleX,
  pushed: Upload,
  local: Monitor,
  closed: CircleX,
  abandoned: CircleX,
  mixed: GitPullRequestArrow,
  pending: Monitor,
};

const HEADLINE_BOX: Record<SessionHeadline["tone"], string> = {
  success: "border-success/30 bg-success-soft/60",
  info: "border-info/30 bg-info-soft/60",
  warn: "border-warn/30 bg-warn-soft/60",
  danger: "border-danger/30 bg-danger-soft/60",
  neutral: "border-line-2 bg-bg-3/60",
};

// DeliveryHeadline is the one sentence at the top of the card: where this
// session's work went (landed in PR #N, in review and blocked, pushed, local
// only, closed unmerged), with the PR link and, when PR state needs it, the
// way to connect a code host.
function DeliveryHeadline({ h, providerLinked, onConnect }: { h: SessionHeadline; providerLinked: boolean; onConnect: () => void }) {
  return (
    <div role="status" className={clsx("mt-2 flex flex-col gap-2 rounded-2 border px-3 py-2 text-[11px] text-fg-2 sm:flex-row sm:items-center", HEADLINE_BOX[h.tone])}>
      <span className="flex min-w-0 flex-1 items-start gap-2">
        <Icon icon={HEADLINE_ICON[h.kind]} size="sm" className="mt-0.5 shrink-0 text-fg-2" />
        <span className="min-w-0">
          <span className="font-semibold text-fg-1">{h.title}</span> {h.body}
        </span>
      </span>
      {h.pr?.url ? (
        <Button size="sm" variant="secondary" iconRight={ExternalLink} href={h.pr.url} target="_blank" rel="noreferrer noopener">
          Open PR #{h.pr.number}
        </Button>
      ) : !providerLinked && (h.kind === "landed_local" || h.kind === "pushed") ? (
        <Button size="sm" variant="secondary" onClick={onConnect}>
          Connect a code host
        </Button>
      ) : null}
    </div>
  );
}

// DeliveryLine is one commit's "Delivery" line: its landing chips, the PR it
// is in (linked to the code host) and the first blocking reason.
function DeliveryLine({ d }: { d: SessionDeliveryRow }) {
  if (!d.evaluated || !d.landing) {
    return (
      <div className="flex items-center gap-2 text-fg-3">
        <span className="w-14 shrink-0 text-fg-4">Delivery</span>
        <span>not evaluated yet</span>
      </div>
    );
  }
  const l = d.landing;
  const pr = d.pr;
  const detail = landingDetail(l, Boolean(pr));
  const facets = pr && (pr.state === "open" || pr.state === "draft") ? facetSentence(pr) : null;
  return (
    <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-fg-3">
      <span className="w-14 shrink-0 text-fg-4">Delivery</span>
      {pr ? (
        <VocabPill vocab="deliveryPR" table={PR_CHIP} value={prChipKey(pr)} title={PR_CHIP[prChipKey(pr)]?.tip} className={clsx(pr.stale && "opacity-60")}>
          {prChipLabel(pr)}
        </VocabPill>
      ) : (
        <VocabPill vocab="landingStatus" table={LANDING_STATUS} value={l.status} title={entry(LANDING_STATUS, l.status).tip} />
      )}
      {l.kind && !(pr && pr.merge_method && pr.state === "merged") && (
        <VocabPill vocab="landingKind" table={LANDING_KIND} value={l.kind} title={entry(LANDING_KIND, l.kind).tip} />
      )}
      {pr?.url && (
        <a href={pr.url} target="_blank" rel="noreferrer noopener" className="inline-flex items-center gap-0.5 text-accent hover:underline">
          PR #{pr.number}
          <Icon icon={ExternalLink} size="xs" />
        </a>
      )}
      {facets && <span>{facets}</span>}
      {detail && <span>{detail}</span>}
    </div>
  );
}
