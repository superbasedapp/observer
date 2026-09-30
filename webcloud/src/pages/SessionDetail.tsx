import { useCallback, useMemo, useState } from "react";
import { FadeIn } from "@shared/primitives/Motion";
import { Icon } from "@shared/primitives/Icon";
import { ChevronLeft, Pencil } from "lucide-react";
import { Skeleton } from "@shared/primitives/Skeleton";
import { invalidatePortal, portalCache, usePortalQuery } from "../lib/query";
import { CardSkeleton, ErrorPanel } from "../components/LoadState";
import { Link, useParams } from "react-router-dom";
import {
  CorrectionConflict,
  getSessionDetail,
  newIdempotencyKey,
  postCorrection,
} from "../api";
import type {
  ResultBody,
  ResultCorrection,
  SessionDetailView,
  SessionResult,
} from "../api";
import { Pill } from "@shared/primitives/Pill";
import { ModelId } from "@shared/primitives/ModelId";
import { CopyOnClick } from "@shared/primitives/CopyOnClick";
import { fmtDateTime, fmtShortId } from "@shared/lib/format";
import { Button } from "@shared/primitives/Button";
import { SuccessCheck } from "@shared/primitives/SuccessCheck";
import { Card } from "@shared/primitives/Card";
import { Input } from "@shared/primitives/Input";
import { Textarea } from "@shared/primitives/Textarea";
import { ToolBadge } from "@shared/primitives/ToolBadge";
import { IntelResultCard } from "@shared/components/sessiondetail/IntelResultCard";
import type { IntelResultLike } from "@shared/lib/types";
import { PageHeader } from "@shared/primitives/PageHeader";
import { routeIcon } from "../lib/nav";

// Session detail (divergence plan §3 W6c / D12, D21; operator ruling R6). Shows
// every result for one session, the head result marked, superseded ones marked,
// each result's immutable AI original plus its append-only revision history. The
// head result can be corrected inline: the save sends the result's current ETag
// as If-Match and a fresh idempotency key, and on a 412 (someone else changed it
// first) it re-reads the server's current ETag and retries once — the user's
// Save is the latest explicit act, which R6 says wins, so re-applying their
// values on the fresh tag is correct rather than a blind clobber. A correction
// NEVER overwrites the AI original; it appends a revision.

function splitTags(raw: string): string[] {
  return raw
    .split(",")
    .map((t) => t.trim())
    .filter((t) => t.length > 0);
}

interface Effective {
  title: string;
  description: string;
  taxonomy: string[];
  suggested: string[];
}

// effective overlays the AI original with each revision in seq order — the
// current value of every field after the user's edits.
function effectiveOf(r: SessionResult): Effective {
  let title = r.result?.title ?? "";
  let description = r.result?.description ?? "";
  let taxonomy = r.result?.taxonomy_tags ?? [];
  let suggested = r.result?.suggested_tags ?? [];
  const revs = r.revisions
    .slice()
    .sort((a, b) => a.revision_seq - b.revision_seq);
  for (const rev of revs) {
    const c = rev.correction;
    if (c.title !== undefined) title = c.title;
    if (c.description !== undefined) description = c.description;
    if (c.taxonomy_tags !== undefined) taxonomy = c.taxonomy_tags;
    if (c.suggested_tags !== undefined) suggested = c.suggested_tags;
  }
  return { title, description, taxonomy: taxonomy ?? [], suggested: suggested ?? [] };
}

function TagList({ label, tags }: { label: string; tags: string[] }) {
  if (tags.length === 0) {
    return (
      <div className="kv">
        <span className="kv-key">{label}</span>
        <span className="kv-val muted">none</span>
      </div>
    );
  }
  return (
    <div className="kv">
      <span className="kv-key">{label}</span>
      <span className="kv-val tag-row">
        {tags.map((t) => (
          <Pill key={t} variant="neutral">
            {t}
          </Pill>
        ))}
      </span>
    </div>
  );
}

// RevisionList renders the append-only edit history, newest first, naming only
// the fields each revision changed.
function RevisionList({ r }: { r: SessionResult }) {
  if (r.revisions.length === 0) {
    return <p className="muted small">No edits yet - this is the AI original.</p>;
  }
  const revs = r.revisions
    .slice()
    .sort((a, b) => b.revision_seq - a.revision_seq);
  return (
    <ul className="revision-list">
      {revs.map((rev) => {
        const c = rev.correction;
        const who = rev.editor === "user" ? "You" : rev.editor;
        return (
          <li key={rev.revision_seq} className="revision-row">
            <div className="revision-head">
              <span className="revision-seq">rev {rev.revision_seq}</span>
              <span className="muted small">
                {who} · via {rev.source} · {fmtDateTime(rev.created_at)}
              </span>
            </div>
            <div className="revision-changes">
              {c.title !== undefined && (
                <div className="kv">
                  <span className="kv-key">Title</span>
                  <span className="kv-val">{c.title || <em>cleared</em>}</span>
                </div>
              )}
              {c.description !== undefined && (
                <div className="kv">
                  <span className="kv-key">Description</span>
                  <span className="kv-val">
                    {c.description || <em>cleared</em>}
                  </span>
                </div>
              )}
              {c.taxonomy_tags !== undefined && (
                <TagList label="Taxonomy tags" tags={c.taxonomy_tags} />
              )}
              {c.suggested_tags !== undefined && (
                <TagList label="Suggested tags" tags={c.suggested_tags} />
              )}
            </div>
          </li>
        );
      })}
    </ul>
  );
}

function EditForm({
  result,
  onCancel,
  onSaved,
  reload,
}: {
  result: SessionResult;
  onCancel: () => void;
  /** Called after a successful save, once the editor has closed. */
  onSaved: () => void;
  reload: () => Promise<void>;
}) {
  const eff = useMemo(() => effectiveOf(result), [result]);
  // Form state seeds ONCE from the effective values (useState initializer); a
  // conflict-reload updates the `result` prop but keeps the user's typed edits.
  const [title, setTitle] = useState(eff.title);
  const [description, setDescription] = useState(eff.description);
  const [taxonomy, setTaxonomy] = useState(eff.taxonomy.join(", "));
  const [suggested, setSuggested] = useState(eff.suggested.join(", "));
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [conflictNote, setConflictNote] = useState<string | null>(null);

  async function save() {
    const t = title.trim();
    if (t === "") {
      setSaveError("Title cannot be empty.");
      return;
    }
    setSaving(true);
    setSaveError(null);
    setConflictNote(null);
    const correction: ResultCorrection = {
      title: t,
      description: description,
      taxonomy_tags: splitTags(taxonomy),
      suggested_tags: splitTags(suggested),
    };
    // One Save is one intent: the same idempotency key is reused across the
    // auto-retry so a benign network replay is idempotent.
    const key = newIdempotencyKey();
    try {
      await postCorrection(result.result_id, result.etag, key, correction);
    } catch (err) {
      if (err instanceof CorrectionConflict && err.freshEtag) {
        // Re-read-and-retry once against the server's current ETag.
        try {
          await postCorrection(result.result_id, err.freshEtag, key, correction);
        } catch (err2) {
          setSaving(false);
          if (err2 instanceof CorrectionConflict) {
            setConflictNote(
              "This result changed again while saving. The latest version is" +
                " loaded below - review it and save once more to apply your" +
                " edit on top.",
            );
            await reload();
          } else {
            setSaveError(err2 instanceof Error ? err2.message : "save failed");
          }
          return;
        }
      } else {
        setSaving(false);
        setSaveError(err instanceof Error ? err.message : "save failed");
        return;
      }
    }
    // Success (first attempt or the retry): reload to show the new revision and
    // ETag, then close the editor.
    await reload();
    setSaving(false);
    onCancel();
    onSaved();
  }

  return (
    <div className="edit-form">
      {conflictNote && <div className="banner banner-warn">{conflictNote}</div>}
      {saveError && <div className="banner banner-error">{saveError}</div>}
      <label htmlFor="edit-title" className="field-label">Title</label>
      <Input
        id="edit-title"
        type="text"
        value={title}
        onChange={(e) => setTitle(e.target.value)}
        placeholder="Session title"
      />
      <label htmlFor="edit-desc" className="field-label">Description</label>
      <Textarea
        id="edit-desc"
        value={description}
        onChange={(e) => setDescription(e.target.value)}
        rows={3}
        placeholder="A short description (optional)"
      />
      <label htmlFor="edit-tax" className="field-label">Taxonomy tags</label>
      <Input
        id="edit-tax"
        type="text"
        value={taxonomy}
        onChange={(e) => setTaxonomy(e.target.value)}
        placeholder="comma, separated, tags"
      />
      <label htmlFor="edit-sug" className="field-label">Suggested tags</label>
      <Input
        id="edit-sug"
        type="text"
        value={suggested}
        onChange={(e) => setSuggested(e.target.value)}
        placeholder="comma, separated, tags"
      />
      <div className="edit-actions">
        <Button variant="ghost" size="sm" onClick={onCancel} disabled={saving}>
          Cancel
        </Button>
        <Button variant="primary" size="sm" onClick={save} loading={saving}>
          {saving ? "Saving" : "Save correction"}
        </Button>
      </div>
      <p className="muted small">
        Saving appends a revision - the AI original is kept unchanged, and your
        edit becomes the current title, description and tags.
      </p>
    </div>
  );
}

// toIntelResult is the ONE boundary between the portal's result wire shape
// (ResultBody plus the user's revisions) and the shared IntelResultCard's
// IntelResultLike. The card shows what the session reads as NOW: the effective
// title, description and tags (the AI original overlaid with every revision),
// and the AI body's never-edited parts (confidence, the five narrative lists,
// limitations). A portal result carries no job state, provider, model, token
// or cost figure, so none is set and the card omits them rather than showing a
// guess. evidence_refs are never mapped: the card never renders them.
function toIntelResult(eff: Effective, ai: ResultBody | undefined): IntelResultLike {
  const list = (items: string[] | null | undefined): string[] | undefined =>
    items && items.length > 0 ? items : undefined;
  return {
    title: eff.title,
    description: eff.description || undefined,
    taxonomyTags: eff.taxonomy,
    suggestedTags: eff.suggested,
    confidence: ai?.confidence || undefined,
    workDone: list(ai?.work_done),
    plansImplemented: list(ai?.plans_implemented),
    issuesFound: list(ai?.issues_found),
    failures: list(ai?.failures),
    nextSteps: list(ai?.next_steps),
    limitations: list(ai?.limitations),
    schemaVersion: ai?.schema_version || undefined,
  };
}

// RESULT_BADGES: the flags a result can carry, walked in order; each row that
// applies draws its pill.
const RESULT_BADGES: readonly {
  label: string;
  variant: "accent" | "neutral" | "danger" | "info";
  applies: (r: SessionResult, isHead: boolean) => boolean;
}[] = [
  { label: "Current", variant: "accent", applies: (_r, isHead) => isHead },
  { label: "Superseded", variant: "neutral", applies: (r) => r.superseded },
  { label: "Deleted", variant: "danger", applies: (r) => r.tombstoned },
  { label: "Edited", variant: "info", applies: (r) => r.revisions.length > 0 && !r.tombstoned },
];

function ResultCard({
  result,
  isHead,
  editing,
  saved,
  onEdit,
  onCancel,
  onSaved,
  reload,
}: {
  result: SessionResult;
  isHead: boolean;
  editing: boolean;
  /** A correction to this result was just saved (draws the success check). */
  saved: boolean;
  onEdit: () => void;
  onCancel: () => void;
  onSaved: () => void;
  reload: () => Promise<void>;
}) {
  const eff = effectiveOf(result);
  const ai = result.result;
  const canEdit = isHead && !result.tombstoned;

  return (
    <div className="mb-4">
      <div className="result-head">
        <div className="result-badges">
          {RESULT_BADGES.filter((b) => b.applies(result, isHead)).map((b) => (
            <Pill key={b.label} variant={b.variant}>
              {b.label}
            </Pill>
          ))}
        </div>
        <span className="muted small">{fmtDateTime(result.created_at)}</span>
      </div>

      {/* What the session reads as now, through the shared enrichment card.
          A tombstoned result renders the card's honest empty state. */}
      <IntelResultCard
        result={result.tombstoned ? null : toIntelResult(eff, ai)}
        emptyMessage="This result was deleted. Its text was tombstoned and is no longer available."
      />

      {!result.tombstoned && (
        <Card className="mt-2">
          {canEdit && !editing && (
            <div className="result-actions flex flex-wrap items-center gap-3">
              <Button size="sm" iconLeft={Pencil} onClick={onEdit}>
                Edit title, description &amp; tags
              </Button>
              {saved && <SuccessCheck label="Correction saved" />}
            </div>
          )}

          {editing && (
            <EditForm result={result} onCancel={onCancel} onSaved={onSaved} reload={reload} />
          )}

          {/* AI original - kept immutable forever (R6). The narrative lists
              are never edited, so they are rendered ONCE, in the card above. */}
          {ai && result.revisions.length > 0 && (
            <div className="result-section result-original">
              <div className="result-section-label">AI original</div>
              <div className="kv">
                <span className="kv-key">Title</span>
                <span className="kv-val">{ai.title || <span className="muted">Untitled</span>}</span>
              </div>
              {ai.description && (
                <div className="kv">
                  <span className="kv-key">Description</span>
                  <span className="kv-val">{ai.description}</span>
                </div>
              )}
              <TagList label="Taxonomy tags" tags={ai.taxonomy_tags ?? []} />
              <TagList label="Suggested tags" tags={ai.suggested_tags ?? []} />
            </div>
          )}

          {/* Edit history. */}
          <div className="result-section">
            <div className="result-section-label">Edit history</div>
            <RevisionList r={result} />
          </div>
        </Card>
      )}
    </div>
  );
}

export function SessionDetail() {
  const params = useParams();
  const id = params.id ?? "";
  const [editingResultId, setEditingResultId] = useState<string | null>(null);
  // The result whose correction was just saved; cleared when any editor opens.
  const [savedResultId, setSavedResultId] = useState<string | null>(null);
  // Keyed on the session id, WITHOUT keep-previous: following a link to
  // another session shows its skeleton, never the previous session's
  // content under the new URL.
  const key = `session:${id}`;
  const q = usePortalQuery<SessionDetailView>(key, () => getSessionDetail(id));
  const detail = q.data;
  const error = q.error;
  const loading = q.loading;

  // reload after a correction: refetch this session (awaited, so the edit
  // form sees the new revision) and refresh the list's effective titles.
  const reload = useCallback(async (): Promise<void> => {
    await portalCache.fetch(key, () => getSessionDetail(id), {
      force: true,
      foreground: true,
    });
    invalidatePortal("sessions:first");
  }, [key, id]);

  const headResultId = detail?.head_result_id ?? "";

  const headTitle = useMemo(() => {
    if (!detail) return "";
    const head = detail.results.find((r) => r.result_id === headResultId);
    if (!head) return "";
    return effectiveOf(head).title;
  }, [detail, headResultId]);

  return (
    <div>
      <p className="page-intro">
        <Link className="back-link" to="/sessions">
          <Icon icon={ChevronLeft} size="sm" /> All sessions
        </Link>
      </p>

      {error && !detail && (
        <ErrorPanel variant="page" what="session" error={error} onRetry={q.reload} />
      )}
      {loading && !error && (
        <div className="flex flex-col gap-4" role="status" aria-label="Loading">
          <Skeleton className="h-6 w-2/3" />
          <Skeleton className="h-3 w-1/2" />
          <div className="rounded-3 border border-line-2 bg-bg-2 p-4">
            <CardSkeleton lines={5} />
          </div>
        </div>
      )}

      {detail && (
        <FadeIn key={detail.cloud_session_id}>
          <PageHeader
            title={headTitle.trim() || "Untitled session"}
            icon={routeIcon("/sessions")}
            className="mb-2"
          />
          <div className="session-meta detail-meta">
            <ToolBadge tool={detail.tool} />
            {detail.model_family && (
              <>
                <span className="session-dot" aria-hidden>
                  ·
                </span>
                <ModelId model={detail.model_family} mono={false} markSize={12} />
              </>
            )}
            <span className="session-dot" aria-hidden>
              ·
            </span>
            <span>{fmtDateTime(detail.created_at)}</span>
            <span className="session-dot" aria-hidden>
              ·
            </span>
            <CopyOnClick value={detail.cloud_session_id} className="mono muted">
              {fmtShortId(detail.cloud_session_id)}
            </CopyOnClick>
          </div>

          {detail.results.length === 0 ? (
            <Card className="mb-4">
              <p className="muted">This session has no enrichment results.</p>
            </Card>
          ) : (
            detail.results.map((r) => (
              <ResultCard
                key={r.result_id}
                result={r}
                isHead={r.result_id === headResultId}
                editing={editingResultId === r.result_id}
                saved={savedResultId === r.result_id}
                onEdit={() => {
                  setSavedResultId(null);
                  setEditingResultId(r.result_id);
                }}
                onCancel={() => setEditingResultId(null)}
                onSaved={() => setSavedResultId(r.result_id)}
                reload={reload}
              />
            ))
          )}
        </FadeIn>
      )}
    </div>
  );
}
