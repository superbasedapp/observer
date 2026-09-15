import { useEffect, useRef, useState } from "react";
import { Pencil } from "lucide-react";
import { Pill } from "@/components/primitives";
import { CopyOnClick } from "@/components/CopyOnClick";
import { useApi } from "@/lib/useApi";
import { fmtShortId } from "@/lib/format";
import { postSessionTags } from "@/lib/api";
import {
  CLASSIFY_REMOTE_BLOCKED_MSG,
  canClassifySessions,
} from "@/lib/remote";
import type { CloudSessionResponse, SessionTagsResponse } from "@/lib/types";

// CLOUD_ID_TOOLTIP is the honesty copy explaining the pseudonym chip — shown
// here and in CloudRow (sessiondetail/CloudRow.tsx) so both surfaces read
// identically.
const CLOUD_ID_TOOLTIP =
  "This is the pseudonym the cloud service knows this session by. Your local session id never leaves this machine.";

// TITLE_MAX_LENGTH mirrors the server's <= 200-char rule (store.MaxTitleLen).
const TITLE_MAX_LENGTH = 200;

// strList narrows an unknown payload field to a clean string list. Every
// narrative field on the contract is a plain string array; a foreign or older
// payload that carries something else contributes nothing rather than
// rendering raw JSON.
function strList(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((s): s is string => typeof s === "string") : [];
}

// NarrativeSection renders one titled bullet list, or nothing when the list is
// empty. The five narrative sections plus Limitations all read the same way.
function NarrativeSection({
  label,
  items,
  muted,
}: {
  label: string;
  items: string[];
  muted?: boolean;
}) {
  if (items.length === 0) return null;
  return (
    <div className="mt-2 first:mt-0">
      <p className="text-[10px] uppercase tracking-[0.05em] text-fg-4">{label}</p>
      <ul
        className={
          "mt-1 list-disc space-y-0.5 pl-4 text-[11.5px] leading-snug " +
          (muted ? "text-fg-3" : "text-fg-2")
        }
      >
        {items.map((s, i) => (
          <li key={i}>{s}</li>
        ))}
      </ul>
    </div>
  );
}

// SessionEnrichmentHeader surfaces the session's TITLE + DESCRIPTION at the
// very top of the session detail panel — the "what was this session about"
// summary that previously existed only buried at the bottom of the Overview
// tab (CloudRow), and only for a cloud-enriched session.
//
// The EFFECTIVE title is resolved in priority order: the developer's own
// title (session_annotations.title, migration 116 — set here or from the
// Sessions list row) > the cloud per-field override (an earlier edit of the
// AI's suggestion) > the AI's own suggestion. Rendered for every account —
// the description/confidence/narrative block is never gated behind a paid
// tier — so a session with no cloud enrichment at all still gets an editable
// title slot, just without the AI content beneath it.
//
// The block beneath the description answers, in order: what was done, whether
// the stated plans landed, what issues were found, what failed, what to do
// next, and finally what the analysis could NOT see. evidence_refs are NOT
// rendered: they are grounding tokens for the server's citation check
// (internal/cloudserver/jobs/luna.go, FE3), and showing them is what produced
// the bullet list of "a136 / m5 / activity_mix" this block replaces.
export function SessionEnrichmentHeader({ sessionId }: { sessionId: string }) {
  const annotation = useApi<SessionTagsResponse>(
    `/api/session/${sessionId}/tags`,
    undefined,
    [sessionId],
  );
  const cloud = useApi<CloudSessionResponse>(
    `/api/cloud/session/${sessionId}`,
    undefined,
    [sessionId],
  );
  const view = cloud.data?.result;
  const ai = view?.result;

  const userTitle = annotation.data?.title ?? "";
  const cloudOverrideTitle = view?.overrides?.title?.user_value ?? "";
  const aiTitle = typeof ai?.title === "string" ? ai.title : "";
  const effectiveTitle = userTitle || cloudOverrideTitle || aiTitle;
  const usingUserTitle = userTitle !== "" && effectiveTitle === userTitle;
  const usingCloudOverride = !usingUserTitle && cloudOverrideTitle !== "" && effectiveTitle === cloudOverrideTitle;

  const description = typeof ai?.description === "string" ? ai.description : "";
  const confidence = typeof ai?.confidence === "string" ? ai.confidence : "";
  const limitations = strList(ai?.limitations);
  // The five narrative lists. evidence_refs is deliberately NOT read here: a
  // ref-id ("a136", "m5") and an evidence section name ("activity_mix") are
  // internal grounding tokens for the server-side check, never something to
  // show a developer.
  const workDone = strList(ai?.work_done);
  const plansImplemented = strList(ai?.plans_implemented);
  const issuesFound = strList(ai?.issues_found);
  const failures = strList(ai?.failures);
  const nextSteps = strList(ai?.next_steps);
  const hasNarrative =
    workDone.length > 0 ||
    plansImplemented.length > 0 ||
    issuesFound.length > 0 ||
    failures.length > 0 ||
    nextSteps.length > 0 ||
    limitations.length > 0;

  const classifyBlocked = !canClassifySessions();
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState("");
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    if (editing) inputRef.current?.focus();
  }, [editing]);

  // Reset any in-progress edit when the panel switches to a different
  // session (the component doesn't remount because sessionId is a prop, not
  // a key, in SessionDetailPanel).
  useEffect(() => {
    setEditing(false);
    setErr(null);
  }, [sessionId]);

  function startEdit() {
    if (classifyBlocked) return;
    setDraft(userTitle);
    setErr(null);
    setEditing(true);
  }

  async function save() {
    if (saving) return;
    const value = draft.trim().slice(0, TITLE_MAX_LENGTH);
    setSaving(true);
    setErr(null);
    try {
      await postSessionTags(sessionId, { title: value });
      setEditing(false);
      annotation.reload();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  }

  function onKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === "Enter") {
      e.preventDefault();
      void save();
    } else if (e.key === "Escape") {
      e.preventDefault();
      setEditing(false);
      setErr(null);
    }
  }

  // Nothing to show and nothing being edited: no locked/empty box.
  if (!effectiveTitle && !description && !editing) {
    if (classifyBlocked) return null;
    return (
      <section className="rounded-3 border border-line-2 bg-bg-2 px-4 py-2">
        <button
          type="button"
          onClick={startEdit}
          className="inline-flex items-center gap-1 text-[11.5px] text-fg-3 hover:text-accent"
        >
          <Pencil size={11} aria-hidden />
          Add a title for this session
        </button>
      </section>
    );
  }

  return (
    <section className="rounded-3 border border-line-2 bg-bg-2 px-4 py-3">
      <div className="mb-1.5 flex flex-wrap items-center gap-1.5">
        {!usingUserTitle && ai && <Pill variant="accent">AI</Pill>}
        {(usingUserTitle || usingCloudOverride) && <Pill variant="success">your edit</Pill>}
        {confidence && (
          <span className="text-[10px] uppercase tracking-[0.05em] text-fg-4">
            {confidence} confidence
          </span>
        )}
        <span className="ml-auto flex items-center gap-1.5">
          {ai && (
            <span className="text-[10px] uppercase tracking-[0.05em] text-fg-4">
              Cloud enrichment
            </span>
          )}
          {cloud.data?.cloud_session_id && (
            <CopyOnClick
              value={cloud.data.cloud_session_id}
              title={CLOUD_ID_TOOLTIP}
              className="rounded-1 border border-line-2 bg-bg-1 px-1.5 py-0.5 font-mono text-[10px] normal-case tracking-normal text-fg-3 hover:text-accent"
            >
              cloud id: {fmtShortId(cloud.data.cloud_session_id)}
            </CopyOnClick>
          )}
        </span>
      </div>

      {editing ? (
        <div className="flex items-center gap-2">
          <input
            ref={inputRef}
            type="text"
            value={draft}
            maxLength={TITLE_MAX_LENGTH}
            placeholder="Title this session"
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={onKeyDown}
            onBlur={() => void save()}
            className="w-full rounded-2 border border-line-2 bg-bg-1 px-2 py-1 text-[15px] font-semibold text-fg-1 outline-none focus:border-accent"
          />
          {saving && <span className="text-[10px] text-fg-4">saving…</span>}
        </div>
      ) : (
        <div className="group flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
          {effectiveTitle ? (
            <h3 className="text-[15px] font-semibold leading-tight text-fg-1">
              {effectiveTitle}
            </h3>
          ) : (
            <h3 className="text-[15px] font-semibold leading-tight text-fg-4">
              Untitled session
            </h3>
          )}
          {!classifyBlocked && (
            <button
              type="button"
              onClick={startEdit}
              title={usingUserTitle ? "Edit your title" : "Set your own title"}
              className="opacity-0 transition-opacity hover:text-accent group-hover:opacity-100"
            >
              <Pencil size={11} aria-hidden />
            </button>
          )}
          {classifyBlocked && (
            <span title={CLASSIFY_REMOTE_BLOCKED_MSG} className="text-[10px] text-fg-4">
              (read-only here)
            </span>
          )}
          {!usingUserTitle && aiTitle && aiTitle !== effectiveTitle && (
            <span className="text-[11px] text-fg-4 line-through">AI: {aiTitle}</span>
          )}
        </div>
      )}
      {err && (
        <p className="mt-1 text-[10.5px] text-danger" role="alert">
          {err}
        </p>
      )}

      {description && (
        <p className="mt-1.5 text-[12px] leading-snug text-fg-2">
          {description}
        </p>
      )}

      {hasNarrative && (
        <div className="mt-2 border-t border-line-2 pt-2">
          <NarrativeSection label="What was done" items={workDone} />
          <NarrativeSection label="Plans" items={plansImplemented} />
          <NarrativeSection label="Issues found" items={issuesFound} />
          <NarrativeSection label="Failures" items={failures} />
          <NarrativeSection label="Next steps" items={nextSteps} />
          {/* Limitations are what the enrichment could NOT observe - an
              honesty qualifier, never a to-do list. Labelled as such. */}
          <NarrativeSection label="Limitations" items={limitations} muted />
        </div>
      )}
    </section>
  );
}
