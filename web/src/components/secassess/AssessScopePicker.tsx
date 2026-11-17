import { useState } from "react";
import { X } from "lucide-react";
import { Button, Input, Pill } from "@/components/primitives";
import { HelpInd } from "@/components/HelpInd";
import { assessNoteDraftFor, assessScopeChoiceLine, assessScopeToggle, assessTypeLabel, type AssessNoteDraft, type AssessScope } from "@/lib/secAssess";

// AssessScopePicker is the threat model's scope (docs/plans/security-
// assessments-depth-plan-2026-11-14.md W3.3): the folders the developer wants
// modelled, ticked from the project's top level or typed, and a note in their
// own words. By default the whole project is covered. It decides nothing: the
// server validates every place (and says why it refused one), and the task text
// the dialog shows is the server's. A change here is a new plan read, so the
// text the developer reads is the text that starts.
//
// The note applies when the field loses focus or on Enter, so the plan is not
// read again on every keystroke. The task carries a note whether or not any
// place is chosen. A place typed but not yet added is not in the task; the
// dialog's button says so until it is added or cleared.
//
// What is typed in the note field is local until it applies, but it follows the
// note the dialog holds: when that changes (another project, a plan read again,
// a note the server cleaned) the field is reset to it (assessNoteDraftFor), so
// the field never shows a note the dialog's choices do not hold.

export function AssessScopePicker({
  scope,
  paths,
  note,
  typed,
  locked,
  onPaths,
  onNote,
  onTyped,
}: {
  scope: AssessScope;
  /** The places the developer chose (what the plan is read with). */
  paths: string[];
  /** The note applied so far. */
  note: string;
  /** The place being typed. */
  typed: string;
  /** A run held for the organization: its scope is fixed. */
  locked: boolean;
  onPaths: (paths: string[]) => void;
  onNote: (note: string) => void;
  onTyped: (typed: string) => void;
}) {
  const [noteState, setNoteState] = useState<AssessNoteDraft>({ text: note, seen: note });
  // Derived state: a note that changed under the field resets it during this
  // render (React re-renders at once, before anything is painted); the same
  // object comes back when nothing changed, so this does not loop.
  const synced = assessNoteDraftFor(noteState, note);
  if (synced !== noteState) setNoteState(synced);
  const draft = synced.text;
  const setDraft = (text: string) => setNoteState({ text, seen: synced.seen });
  const [err, setErr] = useState("");
  const refused = scope.refused ?? [];
  const refusedPaths = new Set(refused.map((r) => r.path));
  const maxPaths = scope.max_paths > 0 ? scope.max_paths : 8;
  const maxNote = scope.max_note > 0 ? scope.max_note : 200;

  function toggle(place: string, on: boolean) {
    const r = assessScopeToggle(paths, place, on, maxPaths);
    setErr(r.error ?? "");
    if (!r.error) onPaths(r.paths);
  }

  function add() {
    const r = assessScopeToggle(paths, typed, true, maxPaths);
    setErr(r.error ?? "");
    if (r.error) return;
    onPaths(r.paths);
    onTyped("");
  }

  function commitNote() {
    onNote(draft.trim());
  }

  return (
    <section aria-labelledby="assess-scope-h" className="space-y-2" data-testid="assess-scope">
      <h3 id="assess-scope-h" className="m-0 flex items-center text-[12px] font-medium text-fg-2">
        Scope
        <HelpInd id="card.code_security_assess_scope" />
      </h3>
      <p className="m-0 break-words text-fg-2" data-testid="assess-scope-line">
        {assessScopeChoiceLine(scope)}
      </p>

      {scope.dirs.length > 0 && (
        <ul
          className="m-0 grid max-h-48 list-none grid-cols-1 gap-1 overflow-y-auto p-0 sm:grid-cols-2"
          aria-label="Folders at the top of the project"
          data-testid="assess-scope-dirs"
        >
          {scope.dirs.map((d) => (
            <li key={d} className="min-w-0">
              <label className="flex cursor-pointer items-center gap-2 rounded-2 border border-line-2 px-2.5 py-1">
                <input
                  type="checkbox"
                  checked={paths.includes(d)}
                  disabled={locked}
                  onChange={(e) => toggle(d, e.target.checked)}
                  data-testid={`assess-scope-dir-${d}`}
                />
                <span className="min-w-0 break-all font-mono text-[11.5px] text-fg-1">{d}</span>
              </label>
            </li>
          ))}
        </ul>
      )}

      {!locked && (
        <form
          className="flex flex-wrap items-end gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            add();
          }}
        >
          <div className="min-w-0 flex-1 basis-56">
            <Input
              mono
              label={assessTypeLabel("a folder or file in the project", scope.dirs.length > 0)}
              placeholder="internal/db"
              value={typed}
              onChange={(e) => onTyped(e.target.value)}
              help="From the project's folder, with forward slashes, for example cmd/api."
              data-testid="assess-scope-input"
            />
          </div>
          <Button type="submit" size="sm" variant="secondary" disabled={typed.trim() === ""}>
            Add
          </Button>
        </form>
      )}

      {paths.length > 0 && (
        <div className="space-y-1">
          <ul className="m-0 flex list-none flex-wrap gap-1.5 p-0" aria-label="Places chosen" data-testid="assess-scope-chips">
            {paths.map((p) => (
              <li key={p} className="min-w-0 max-w-full" data-testid={`assess-scope-chip-${p}`}>
                <Pill variant={refusedPaths.has(p) ? "warn" : "info"} case="none" className="max-w-full">
                  <span className="min-w-0 break-all font-mono">{p}</span>
                  {!locked && (
                    <button
                      type="button"
                      aria-label={`Remove ${p} from the scope`}
                      className="inline-flex shrink-0 items-center rounded-1 hover:text-fg-1 focus:outline-none focus-visible:ring-1 focus-visible:ring-accent-ring"
                      onClick={() => toggle(p, false)}
                    >
                      <X size={11} aria-hidden />
                    </button>
                  )}
                </Pill>
              </li>
            ))}
          </ul>
          <p className="m-0 text-[11.5px] text-fg-3">{`${paths.length} of ${maxPaths} places chosen.`}</p>
        </div>
      )}
      {err && (
        <p role="alert" className="m-0 break-words text-danger" data-testid="assess-scope-error">
          {err}
        </p>
      )}

      {refused.length > 0 && (
        <ul className="m-0 list-none space-y-0.5 p-0 text-warn [overflow-wrap:anywhere]" aria-label="Places that were not accepted" data-testid="assess-scope-refused">
          {refused.map((r) => (
            <li key={r.path}>
              <span className="break-all font-mono">{r.path}</span>: {r.reason}
            </li>
          ))}
        </ul>
      )}

      <Input
        label="A note for the agent (optional)"
        placeholder="For example: the payment flow only matters this week"
        maxLength={maxNote}
        value={draft}
        disabled={locked}
        onChange={(e) => setDraft(e.target.value)}
        onBlur={commitNote}
        onKeyDown={(e) => {
          if (e.key === "Enter") {
            e.preventDefault();
            commitNote();
          }
        }}
        help={`${draft.length} of ${maxNote} characters. It goes into the task as your own words, when you press Enter or move on.`}
        data-testid="assess-scope-note"
      />
    </section>
  );
}
