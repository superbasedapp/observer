// configSave.ts is the save model of a settings card that edits a draft of
// one config block and saves it with one PUT (Settings > Sandbox isolation;
// live check D-5). It is pure: the card owns the state and the requests, and
// this file decides what the state becomes on each event.
//
// Two defects it closes:
//
//   - A save whose PUT returned 200 still read "Unsaved changes". The card
//     compared the draft against the last GET and relied on a reload after
//     the save; the shared query cache joins a GET already in flight, so that
//     reload could hand back the pre-save response. Now a save adopts the
//     PUT's own response (the saved block and the new etag) as the baseline,
//     and a read still carrying an etag a save superseded is ignored.
//   - A save could start from a stale closure. The card reads the state from
//     one place (a ref over this state) when Save is clicked, and a save that
//     cannot start says why instead of doing nothing.

/** The fields a config GET answers with that this model reads. */
export type ConfigLoaded<C> = { block: C; etag: string };

/** The fields a config PUT answers with that this model reads. */
export type ConfigSaved<C> = { block?: C; etag?: string };

/** ConfigSaveState is one card's draft and the saved baseline it is compared to. */
export type ConfigSaveState<C> = {
  /** The saved block the draft is compared against ("unsaved changes"). */
  base: C | null;
  /** The config file's etag for base (what a save sends as base_etag). */
  etag: string;
  /** What the person is editing. */
  draft: C | null;
  /** Etags a save replaced: a read that still carries one is stale. */
  superseded: string[];
};

/** emptySave is the state before the first read. */
export function emptySave<C>(): ConfigSaveState<C> {
  return { base: null, etag: "", draft: null, superseded: [] };
}

/**
 * applyLoaded folds a GET into the state, by an ordered rule set:
 *   1. a read carrying an etag a save superseded is stale: ignored;
 *   2. a read of the same file (same etag) while the person has edits keeps
 *      the edits (a refetch must not wipe a draft);
 *   3. otherwise the read is the new baseline and the draft.
 */
export function applyLoaded<C>(
  s: ConfigSaveState<C>,
  loaded: ConfigLoaded<C>,
  equal: (a: C | null, b: C | null) => boolean,
): ConfigSaveState<C> {
  if (loaded.etag !== "" && s.superseded.includes(loaded.etag)) return s;
  if (s.base !== null && loaded.etag === s.etag && !equal(s.draft, s.base)) {
    return { ...s, base: loaded.block };
  }
  return { ...s, base: loaded.block, etag: loaded.etag, draft: loaded.block };
}

/** editDraft applies an edit to the draft (no draft yet: nothing changes). */
export function editDraft<C>(s: ConfigSaveState<C>, edit: (draft: C) => C): ConfigSaveState<C> {
  return s.draft === null ? s : { ...s, draft: edit(s.draft) };
}

/**
 * applySaved folds a successful PUT: the block the server saved (else the
 * one sent) is both the baseline and the draft, its etag is current, and the
 * etag the save started from is superseded.
 */
export function applySaved<C>(s: ConfigSaveState<C>, sent: C, fromEtag: string, saved: ConfigSaved<C>): ConfigSaveState<C> {
  const block = saved.block ?? sent;
  const etag = saved.etag ?? "";
  const superseded = fromEtag !== "" && fromEtag !== etag && !s.superseded.includes(fromEtag) ? [...s.superseded, fromEtag] : s.superseded;
  return { base: block, etag, draft: block, superseded };
}

/** isDirty: the draft differs from the saved baseline. */
export function isDirty<C>(s: ConfigSaveState<C>, equal: (a: C | null, b: C | null) => boolean): boolean {
  return s.draft !== null && !equal(s.draft, s.base);
}

/** SaveStart is whether a click on Save may send the PUT, and why not. */
export type SaveStart = { ok: true } | { ok: false; why: string };

/** canStartSave: one save at a time, a loaded draft, and a confirm token. */
export function canStartSave<C>(s: ConfigSaveState<C>, busy: boolean, confirmToken: string | undefined): SaveStart {
  if (busy) return { ok: false, why: "A save is already in progress." };
  if (s.draft === null) return { ok: false, why: "The configuration has not loaded yet; reload the page." };
  if (!confirmToken) return { ok: false, why: "The settings are not ready (no confirm token); reload the page." };
  return { ok: true };
}

/**
 * runSave sends the draft once through put and returns the state after it.
 * put receives the draft and the etag it was edited from.
 */
export async function runSave<C, R extends ConfigSaved<C>>(
  s: ConfigSaveState<C>,
  put: (draft: C, baseEtag: string) => Promise<R>,
): Promise<{ state: ConfigSaveState<C>; reply: R }> {
  if (s.draft === null) throw new Error("runSave: no draft");
  const sent = s.draft;
  const reply = await put(sent, s.etag);
  return { state: applySaved(s, sent, s.etag, reply), reply };
}

/** SaveErrorView is how a failed config Save is shown. */
export type SaveErrorView = { message: string; conflict: boolean };

/** CONFIG_CONFLICT_MSG is the plain words of a 409 on a config Save: the
 *  file changed since the editor read it (D5: a setup step's Undo on the same
 *  page rewrote it, and the Save showed the raw `api 409 {json}`). */
export const CONFIG_CONFLICT_MSG =
  "The configuration changed since this page read it (another change, such as a setup step or its Undo, saved it first), so nothing was saved. Reload to see the current values, then make your change again.";

/** saveErrorView turns a Save's error into plain words: a 409 is a conflict
 *  the person resolves with a reload; anything else keeps its message. */
export function saveErrorView(e: unknown): SaveErrorView {
  const status = typeof e === "object" && e !== null && "status" in e ? (e as { status: unknown }).status : undefined;
  if (status === 409) return { message: CONFIG_CONFLICT_MSG, conflict: true };
  return { message: e instanceof Error ? e.message : String(e), conflict: false };
}
