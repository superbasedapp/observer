import { useCallback, useEffect, useMemo, useState } from "react";
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
import { CopyOnClick } from "@shared/primitives/CopyOnClick";
import { fmtDateTime, fmtShortId } from "@shared/lib/format";

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
          <span key={t} className="tag-pill">
            {t}
          </span>
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
  reload,
}: {
  result: SessionResult;
  onCancel: () => void;
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
  }

  return (
    <div className="edit-form">
      {conflictNote && <div className="banner banner-warn">{conflictNote}</div>}
      {saveError && <div className="banner banner-error">{saveError}</div>}
      <label htmlFor="edit-title">Title</label>
      <input
        id="edit-title"
        type="text"
        value={title}
        onChange={(e) => setTitle(e.target.value)}
        placeholder="Session title"
      />
      <label htmlFor="edit-desc">Description</label>
      <textarea
        id="edit-desc"
        className="edit-textarea"
        value={description}
        onChange={(e) => setDescription(e.target.value)}
        rows={3}
        placeholder="A short description (optional)"
      />
      <label htmlFor="edit-tax">Taxonomy tags</label>
      <input
        id="edit-tax"
        type="text"
        value={taxonomy}
        onChange={(e) => setTaxonomy(e.target.value)}
        placeholder="comma, separated, tags"
      />
      <label htmlFor="edit-sug">Suggested tags</label>
      <input
        id="edit-sug"
        type="text"
        value={suggested}
        onChange={(e) => setSuggested(e.target.value)}
        placeholder="comma, separated, tags"
      />
      <div className="edit-actions">
        <button className="btn btn-ghost btn-sm" onClick={onCancel} disabled={saving}>
          Cancel
        </button>
        <button className="btn btn-primary" onClick={save} disabled={saving}>
          {saving ? "Saving..." : "Save correction"}
        </button>
      </div>
      <p className="muted small">
        Saving appends a revision - the AI original is kept unchanged, and your
        edit becomes the current title, description and tags.
      </p>
    </div>
  );
}

// NarrativeSections renders the enrichment's reader-facing half: the five
// narrative lists in reading order, then the limitations, each omitted when
// absent or empty. It renders NOTHING at all when the result carries none of
// them, which is the back-compat case for every result stored before the
// fields existed.
function NarrativeSections({ ai }: { ai: ResultBody }) {
  const sections: Array<[string, string[] | null | undefined]> = [
    ["What was done", ai.work_done],
    ["Plans", ai.plans_implemented],
    ["Issues found", ai.issues_found],
    ["Failures", ai.failures],
    ["Next steps", ai.next_steps],
    ["Limitations", ai.limitations],
  ];
  const present = sections.filter(([, items]) => items && items.length > 0);
  if (present.length === 0) return null;
  return (
    <div className="result-section">
      {present.map(([label, items]) => (
        <div className="kv" key={label}>
          <span className="kv-key">{label}</span>
          <span className="kv-val">
            <ul className="mini-list">
              {(items ?? []).map((s, i) => (
                <li key={i}>{s}</li>
              ))}
            </ul>
          </span>
        </div>
      ))}
    </div>
  );
}

function ResultCard({
  result,
  isHead,
  editing,
  onEdit,
  onCancel,
  reload,
}: {
  result: SessionResult;
  isHead: boolean;
  editing: boolean;
  onEdit: () => void;
  onCancel: () => void;
  reload: () => Promise<void>;
}) {
  const eff = effectiveOf(result);
  const ai = result.result;
  const canEdit = isHead && !result.tombstoned;

  return (
    <div className="card result-card">
      <div className="result-head">
        <div className="result-badges">
          {isHead && <Pill variant="accent">Current</Pill>}
          {result.superseded && <Pill variant="neutral">Superseded</Pill>}
          {result.tombstoned && <Pill variant="danger">Deleted</Pill>}
          {result.revisions.length > 0 && !result.tombstoned && (
            <Pill variant="info">Edited</Pill>
          )}
        </div>
        <span className="muted small">{fmtDateTime(result.created_at)}</span>
      </div>

      {result.tombstoned ? (
        <p className="muted">
          This result was deleted. Its text was tombstoned and is no longer
          available.
        </p>
      ) : (
        <>
          {/* Current effective metadata — what the session reads as now. */}
          <div className="result-section">
            <div className="result-section-label">Current</div>
            <div className="kv">
              <span className="kv-key">Title</span>
              <span className="kv-val strong">
                {eff.title || <span className="muted">Untitled</span>}
              </span>
            </div>
            {eff.description && (
              <div className="kv">
                <span className="kv-key">Description</span>
                <span className="kv-val">{eff.description}</span>
              </div>
            )}
            <TagList label="Taxonomy tags" tags={eff.taxonomy} />
            <TagList label="Suggested tags" tags={eff.suggested} />
          </div>

          {/* The narrative half of the enrichment: what was done, whether the
              stated plans landed, what is broken, what failed, what to do
              next - then, separately labelled, what the analysis could NOT
              see. None of these are user-editable, so they read off the AI
              body directly. Every one is optional: a result stored before
              these fields existed renders nothing here rather than an empty
              heading. evidence_refs are deliberately never rendered - they
              are server-side grounding tokens ("a136", "m5",
              "activity_mix"), not an answer for a human. */}
          {ai && <NarrativeSections ai={ai} />}

          {canEdit && !editing && (
            <div className="result-actions">
              <button className="btn btn-sm" onClick={onEdit}>
                Edit title, description &amp; tags
              </button>
            </div>
          )}

          {editing && (
            <EditForm result={result} onCancel={onCancel} reload={reload} />
          )}

          {/* AI original — kept immutable forever (R6). */}
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
              {ai.confidence && (
                <div className="kv">
                  <span className="kv-key">Confidence</span>
                  <span className="kv-val">{ai.confidence}</span>
                </div>
              )}
              {/* Limitations (and the five narrative lists) are never edited,
                  so they are rendered ONCE, in the NarrativeSections block
                  above, rather than duplicated in this immutable-original
                  view alongside the fields an edit can actually change. */}
            </div>
          )}

          {/* Edit history. */}
          <div className="result-section">
            <div className="result-section-label">Edit history</div>
            <RevisionList r={result} />
          </div>
        </>
      )}
    </div>
  );
}

export function SessionDetail() {
  const params = useParams();
  const id = params.id ?? "";
  const [detail, setDetail] = useState<SessionDetailView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [editingResultId, setEditingResultId] = useState<string | null>(null);

  const reload = useCallback(async (): Promise<void> => {
    try {
      const d = await getSessionDetail(id);
      setDetail(d);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "failed to load");
    }
  }, [id]);

  useEffect(() => {
    let live = true;
    setLoading(true);
    getSessionDetail(id)
      .then((d) => {
        if (live) {
          setDetail(d);
          setError(null);
        }
      })
      .catch((err: unknown) => {
        if (live) setError(err instanceof Error ? err.message : "failed to load");
      })
      .finally(() => {
        if (live) setLoading(false);
      });
    return () => {
      live = false;
    };
  }, [id]);

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
          <span aria-hidden>‹</span> All sessions
        </Link>
      </p>

      {error && (
        <div className="banner banner-error">Could not load session: {error}</div>
      )}
      {loading && !error && <div className="muted">Loading session...</div>}

      {detail && (
        <>
          <h1>{headTitle.trim() || "Untitled session"}</h1>
          <div className="session-meta detail-meta">
            <span className="mono">{detail.tool}</span>
            {detail.model_family && (
              <>
                <span className="session-dot" aria-hidden>
                  ·
                </span>
                <span>{detail.model_family}</span>
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
            <div className="card">
              <p className="muted">This session has no enrichment results.</p>
            </div>
          ) : (
            detail.results.map((r) => (
              <ResultCard
                key={r.result_id}
                result={r}
                isHead={r.result_id === headResultId}
                editing={editingResultId === r.result_id}
                onEdit={() => setEditingResultId(r.result_id)}
                onCancel={() => setEditingResultId(null)}
                reload={reload}
              />
            ))
          )}
        </>
      )}
    </div>
  );
}
