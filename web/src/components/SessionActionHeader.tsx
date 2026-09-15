import { useEffect, useRef, useState } from "react";
import clsx from "clsx";
import { AnchoredPopover } from "@/components/primitives/AnchoredPopover";
import { HandoffCard } from "@/components/HandoffCard";
import { JumpInButton } from "@/components/JumpInButton";
import { ResumeButton } from "@/components/ResumeButton";
import { TagPill } from "@/components/TagPill";
import { FavoriteStar, RatingChip, TagEditor } from "@/components/TagEditor";
import { postSessionTags } from "@/lib/api";
import {
  CLASSIFY_REMOTE_BLOCKED_MSG,
  canClassifySessions,
} from "@/lib/remote";
import type { SessionDetail } from "@/lib/types";

// SessionActionHeader — the session detail panel's action strip.
//
// WHY IT EXISTS (measured, 2026-08-01). SessionDetailPanel rendered 17 top-
// level blocks in one flat scroll, all visual siblings. The three verbs that
// act on the session — Jump in, Resume, Continue in… — sat at blocks 11-13,
// roughly two and a half screens below the fold, underneath four separate cost
// analyses. Directly under the title sat a permanently-expanded note textarea
// that, on a session with no note, spent the most valuable strip on the page
// displaying a placeholder.
//
// This component is a RE-WRAP, not a rewrite: it renders the exact same
// JumpInButton / ResumeButton / HandoffCard components, with the exact same
// props, at the top of the scroll body instead of the middle, and pins them
// with `position: sticky` so they never scroll away. Their internals — the
// attach-liveness polling, the honest-disabled copy, the resume capability
// dispatch — are untouched. Deleting this component and putting the three
// children back where they were restores the previous layout exactly.
//
// WHICH VERBS SHOW. The proposal that motivated this change asked for "only
// the verbs applicable to that session". That is already what ships, and it is
// deliberately NOT tightened here: ResumeButton returns null while the session
// is live-attachable (Jump in owns that case), while JumpInButton stays visible
// and DISABLED with a tooltip naming the exact missing dependency. Hiding a
// disabled verb outright would put its reason out of reach, which the
// honest-disabled-copy rule exists to prevent — a hidden Jump in looks like a
// missing feature, a disabled one explains that no live daemon-owned terminal
// is bound to this session and how to make one.
//
// MOBILE. Sticky is gated at `lg` (1024px), the same line the rest of the
// dashboard's mobile pass uses (see lib/useMediaQuery MobileTerminalQuery).
// Below it the strip is static — still first in the scroll, but not eating a
// phone viewport. Above it the strip is additionally capped at 42vh with its
// own scroll, so no future growth of a child card can swallow the panel.

export function SessionActionHeader({
  d,
  watchable,
  onWatch,
  onFilterTag,
  onAnnotationChange,
}: {
  d: SessionDetail;
  /** Passed straight through to JumpInButton — the parent still owns the
   * recently-active judgement. */
  watchable: boolean;
  onWatch: () => void;
  onFilterTag?: (tag: string) => void;
  onAnnotationChange?: (
    sessionId: string,
    next: { tags: string[]; favorite: boolean; note: string; rating: number },
  ) => void;
}) {
  return (
    <div
      className={clsx(
        // Bleed through the parent's px-5/pt-3 so the strip spans the panel
        // edge-to-edge and sits flush against the drawer header.
        "-mx-5 -mt-3 border-b border-line-1 bg-bg-1 px-5 pb-2.5 pt-2.5",
        "lg:sticky lg:top-0 lg:z-20 lg:max-h-[42vh] lg:overflow-y-auto",
      )}
    >
      <SessionAnnotationChips
        // Remount per session so the note reseeds from the new session's
        // server value. Keying on the id also means the 8s detail poll can't
        // clobber a half-typed note: after mount this component owns its state.
        key={d.id}
        sessionId={d.id}
        initialTags={d.tags ?? []}
        initialFavorite={d.favorite === true}
        initialNote={d.note ?? ""}
        initialRating={d.rating ?? 0}
        onFilterTag={onFilterTag}
        onAnnotationChange={onAnnotationChange}
      />
      {/* The three verbs, verbatim. `[&>section]:mt-0` neutralises the mt-5
          each card carries for its old stacked position — a presentational
          override on the wrapper, not an edit to the cards. */}
      <div className="mt-2 flex flex-wrap items-start gap-3 [&>section]:mt-0 [&>section]:min-w-[260px] [&>section]:flex-1">
        <JumpInButton
          sessionId={d.id}
          tool={d.tool}
          watchable={watchable}
          onWatch={onWatch}
        />
        <ResumeButton sessionId={d.id} tool={d.tool} resume={d.resume} />
        <HandoffCard sessionId={d.id} tool={d.tool} />
      </div>
    </div>
  );
}

// NOTE_MAX_LENGTH mirrors the server's ≤500-char rule (plan §0.3). Enforced
// here as a maxLength + counter so the operator sees the ceiling instead of
// discovering it via a rejected save.
const NOTE_MAX_LENGTH = 500;

// SessionAnnotationChips — favorite star, tag pills + editor, and the note.
// Moved here from SessionDetailPanel (where it was `SessionAnnotations`) with
// its state machine byte-for-byte intact; the ONE change is presentational:
// the note is a chip that opens a popover instead of an always-expanded
// textarea, so a session with no note costs one chip instead of a two-row box.
//
// It owns the annotation state after mount (the parent keys it by session id)
// so neither the 8s detail poll nor an in-flight save can clobber a note the
// operator is mid-way through typing. Every mutation goes through the ONE
// POST /api/session/<id>/tags endpoint and adopts the server's reply.
//
// Owning the state must NOT mean ignoring the server forever, though. The
// component tracks the last SERVER-CONFIRMED note (serverNoteRef, advanced both
// by poll adoption and by its own POST replies) and reconciles each poll
// against it:
//
//   - server value unchanged                  → nothing happens (the common case)
//   - changed, box not focused, draft == last → ADOPT it (a note written from
//     the CLI or another device now shows up, which it never did before)
//   - changed with local edits in the box     → keep the draft and raise a
//     "changed elsewhere" hint; neither side is silently overwritten, and the
//     operator's next blur is an explicit last-write-wins save
function SessionAnnotationChips({
  sessionId,
  initialTags,
  initialFavorite,
  initialNote,
  initialRating,
  onFilterTag,
  onAnnotationChange,
}: {
  sessionId: string;
  initialTags: string[];
  initialFavorite: boolean;
  initialNote: string;
  initialRating: number;
  onFilterTag?: (tag: string) => void;
  onAnnotationChange?: (
    sessionId: string,
    next: { tags: string[]; favorite: boolean; note: string; rating: number },
  ) => void;
}) {
  const [tags, setTags] = useState<string[]>(initialTags);
  const [favorite, setFavorite] = useState(initialFavorite);
  const [rating, setRating] = useState(initialRating);
  // saved = the last value the server confirmed; draft = what's in the box.
  // Save-on-blur only fires when they differ, so tabbing through the field
  // costs nothing.
  const [saved, setSaved] = useState(initialNote);
  const [draft, setDraft] = useState(initialNote);
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  // externalNote is set when a poll delivered a DIFFERENT server note while the
  // box held unsaved local edits. It drives the "changed elsewhere" hint only —
  // it never rewrites the draft.
  const [externalNote, setExternalNote] = useState<string | null>(null);
  const [noteOpen, setNoteOpen] = useState(false);
  const noteRef = useRef<HTMLTextAreaElement | null>(null);
  const noteTriggerRef = useRef<HTMLButtonElement | null>(null);
  // serverNoteRef is the last note value THIS component has seen the server
  // confirm, from a poll it adopted or from one of its own POST replies. It is
  // the baseline the poll reconciliation compares against; a ref (not state) so
  // the reconcile effect can read it without listing it as a dependency and
  // re-running on its own write.
  const serverNoteRef = useRef(initialNote);
  // draftRef mirrors draft for the same reason — the effect must key on the
  // incoming server value alone.
  const draftRef = useRef(draft);
  draftRef.current = draft;
  // savingRef is the note's SINGLE-FLIGHT latch (mirrors TagEditor's busyRef).
  // It exists because the note now lives in a popover: clicking outside fires
  // the textarea's blur AND the popover's dismiss in the same tick, and both
  // want to save. `saved` state hasn't advanced yet when the second one runs,
  // so without this latch the pair would POST the same note twice.
  const savingRef = useRef(false);
  // Classification POSTs are Execute-class and unreachable from a paired remote
  // device, so the note is read-only there (the star + tag editor gate
  // themselves inside TagEditor.tsx).
  const classifyBlocked = !canClassifySessions();

  // Reconcile each poll's server note against the last confirmed one.
  useEffect(() => {
    const prev = serverNoteRef.current;
    if (initialNote === prev) return;
    serverNoteRef.current = initialNote;
    const focused =
      typeof document !== "undefined" && document.activeElement === noteRef.current;
    setSaved(initialNote);
    if (!focused && draftRef.current === prev) {
      // Clean box, no local edits → the external value is simply the truth.
      setDraft(initialNote);
      setExternalNote(null);
      return;
    }
    if (draftRef.current === initialNote) {
      // The draft already says exactly what the server now says — there is no
      // conflict to warn about, whoever typed it.
      setExternalNote(null);
      return;
    }
    // Local edits present (or the operator is typing right now): keep them and
    // say so. Blurring saves the draft over the external value — an explicit,
    // visible last-write-wins rather than a silent one.
    setExternalNote(initialNote);
  }, [initialNote]);

  // Focus the textarea when the popover opens, after the portal has painted.
  useEffect(() => {
    if (!noteOpen) return;
    const id = requestAnimationFrame(() => noteRef.current?.focus());
    return () => cancelAnimationFrame(id);
  }, [noteOpen]);

  const report = (next: {
    tags: string[];
    favorite: boolean;
    note: string;
    rating: number;
  }) => onAnnotationChange?.(sessionId, next);

  // adoptServerNote folds a POST reply's note into local state without
  // clobbering an in-progress draft, and advances the poll baseline so the
  // reconcile effect doesn't mistake our own write for an external one.
  function adoptServerNote(serverNote: string) {
    const prev = serverNoteRef.current;
    serverNoteRef.current = serverNote;
    setSaved(serverNote);
    if (draftRef.current === prev) {
      setDraft(serverNote);
      setExternalNote(null);
    } else if (serverNote !== prev && draftRef.current !== serverNote) {
      setExternalNote(serverNote);
    }
  }

  async function toggleFavorite() {
    const before = favorite;
    setFavorite(!before);
    setErr(null);
    try {
      const r = await postSessionTags(sessionId, { favorite: !before });
      setFavorite(r.favorite);
      setTags(r.tags ?? []);
      setRating(r.rating);
      adoptServerNote(r.note ?? "");
      report({ tags: r.tags ?? [], favorite: r.favorite, note: r.note ?? "", rating: r.rating });
    } catch (e) {
      setFavorite(before);
      setErr(e instanceof Error ? e.message : String(e));
    }
  }

  // saveRating writes the 1-10 overall score (0 = clear) optimistically, then
  // reconciles against the server reply — mirrors toggleFavorite.
  async function saveRating(next: number) {
    const before = rating;
    setRating(next);
    setErr(null);
    try {
      const r = await postSessionTags(sessionId, { rating: next });
      setRating(r.rating);
      setFavorite(r.favorite);
      setTags(r.tags ?? []);
      adoptServerNote(r.note ?? "");
      report({ tags: r.tags ?? [], favorite: r.favorite, note: r.note ?? "", rating: r.rating });
    } catch (e) {
      setRating(before);
      setErr(e instanceof Error ? e.message : String(e));
    }
  }

  async function saveNote() {
    if (classifyBlocked) return;
    if (savingRef.current) return;
    const value = draft.slice(0, NOTE_MAX_LENGTH);
    if (value === saved) return;
    savingRef.current = true;
    setSaving(true);
    setErr(null);
    try {
      const r = await postSessionTags(sessionId, { note: value });
      const serverNote = r.note ?? "";
      // Our own write IS the new server truth: seed the baseline directly
      // (adoptServerNote would read the pre-save baseline and mis-file this as
      // an external change).
      serverNoteRef.current = serverNote;
      setSaved(serverNote);
      setDraft(serverNote);
      setExternalNote(null);
      setFavorite(r.favorite);
      setTags(r.tags ?? []);
      setRating(r.rating);
      report({ tags: r.tags ?? [], favorite: r.favorite, note: serverNote, rating: r.rating });
    } catch (e) {
      // Keep the operator's text in the box — losing typed prose on a failed
      // save would be worse than a stale-looking field. `saved` stays put, so
      // the next blur retries.
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      savingRef.current = false;
      setSaving(false);
    }
  }

  const dirty = draft !== saved;
  const hasNote = saved.trim() !== "";

  return (
    <section className="flex flex-wrap items-center gap-2">
      <FavoriteStar favorite={favorite} onToggle={() => void toggleFavorite()} />
      {/* Rating is a collapsed chip + popover (RatingChip) so a 10-star row no
          longer eats the header width. */}
      <RatingChip rating={rating} onRate={(next) => void saveRating(next)} />
      {tags.length === 0 ? (
        <span className="text-[11px] text-fg-4">no tags</span>
      ) : (
        tags.map((t) => (
          <TagPill
            key={t}
            tag={t}
            onClick={onFilterTag ? (tag) => onFilterTag(tag) : undefined}
          />
        ))
      )}
      <TagEditor
        sessionId={sessionId}
        tags={tags}
        label={tags.length > 0 ? "edit tags" : "+ tag"}
        onTagsChange={(next) => {
          setTags(next);
          report({ tags: next, favorite, note: saved, rating });
        }}
        onError={(m) => setErr(m)}
      />

      {/* Note chip. Carries a filled dot when the session HAS a note, so the
          collapsed state still answers "is there anything written here?" at a
          glance — the one thing the old always-open textarea told you for
          free. */}
      <button
        ref={noteTriggerRef}
        type="button"
        aria-haspopup="dialog"
        aria-expanded={noteOpen}
        title={
          classifyBlocked
            ? CLASSIFY_REMOTE_BLOCKED_MSG
            : hasNote
              ? "Read or edit this session's note"
              : "Add a note - why this session matters"
        }
        onClick={() => setNoteOpen((o) => !o)}
        className={clsx(
          "inline-flex items-center gap-1 rounded-2 border px-1.5 py-0.5 text-[10.5px] transition-colors",
          noteOpen
            ? "border-accent bg-accent-soft text-accent"
            : "border-line-2 bg-bg-2 text-fg-3 hover:bg-bg-3 hover:text-fg-1",
        )}
      >
        <span
          aria-hidden
          className={clsx(
            "inline-block h-1.5 w-1.5 rounded-full",
            hasNote ? "bg-accent" : "border border-line-3 bg-transparent",
          )}
        />
        {hasNote ? "note" : "+ note"}
      </button>

      {/* Status that used to live beside the textarea, kept inline so an
          unsaved / saving / failed note is visible with the popover CLOSED. */}
      <span className="ml-auto flex items-center gap-2 font-mono text-[10px] text-fg-4">
        {saving && <span>saving…</span>}
        {!saving && dirty && !classifyBlocked && (
          <span className="text-warn">unsaved</span>
        )}
        {externalNote !== null && (
          <span
            className="text-warn"
            title="This note changed elsewhere while you were editing - your text is kept; saving writes it over theirs."
          >
            changed elsewhere
          </span>
        )}
      </span>
      {err && (
        <span className="w-full text-[10.5px] text-danger" role="alert">
          {err}
        </span>
      )}

      <AnchoredPopover
        open={noteOpen}
        anchorRef={noteTriggerRef}
        ariaLabel="Session note"
        width={360}
        reflowKey={externalNote !== null}
        onDismiss={(reason) => {
          if (reason === "escape") {
            // Escape discards the local edit and keeps whatever the server
            // has — the same contract the inline textarea's Escape had. It no
            // longer also closes the whole drawer (AnchoredPopover stops the
            // event before SlideOver's document-level handler sees it).
            setDraft(saved);
            setExternalNote(null);
            setNoteOpen(false);
            return;
          }
          // Clicking away / scrolling saves, exactly like blurring the old
          // inline textarea did.
          void saveNote();
          setNoteOpen(false);
        }}
      >
        <div className="flex items-baseline justify-between gap-2 border-b border-line-1 bg-bg-2/60 px-3 py-1.5">
          <span className="text-[10px] font-semibold uppercase tracking-[0.06em] text-fg-3">
            Note
          </span>
          <span className="font-mono text-[10px] text-fg-4">
            {draft.length}/{NOTE_MAX_LENGTH}
          </span>
        </div>
        <div className="px-3 py-2">
          <textarea
            ref={noteRef}
            value={draft}
            maxLength={NOTE_MAX_LENGTH}
            rows={5}
            readOnly={classifyBlocked}
            title={classifyBlocked ? CLASSIFY_REMOTE_BLOCKED_MSG : undefined}
            placeholder={
              classifyBlocked
                ? "Note - read-only on a paired device"
                : "Note - why this session matters (saved when you click away)…"
            }
            onChange={(e) => setDraft(e.target.value)}
            onBlur={() => void saveNote()}
            className={clsx(
              "w-full resize-y rounded-2 border border-line-2 bg-bg-1 px-2 py-1.5 text-[11.5px] leading-[1.5] text-fg-1 placeholder:text-fg-4 focus:border-accent focus:outline-none",
              classifyBlocked && "cursor-not-allowed opacity-70",
            )}
          />
          {externalNote !== null && (
            <p className="mt-1 text-[10.5px] text-warn">
              Note changed elsewhere while you were editing - your text is kept;
              clicking away saves it over theirs. Press Esc to discard yours and
              keep the other version.
            </p>
          )}
          {classifyBlocked && (
            <p className="mt-1 text-[10.5px] text-fg-4">
              {CLASSIFY_REMOTE_BLOCKED_MSG}
            </p>
          )}
          {err && <p className="mt-1 text-[10.5px] text-danger">{err}</p>}
          {!classifyBlocked && (
            <p className="mt-1 text-[10px] text-fg-4">
              Saved when you click away · <kbd>Esc</kbd> discards
            </p>
          )}
        </div>
      </AnchoredPopover>
    </section>
  );
}
