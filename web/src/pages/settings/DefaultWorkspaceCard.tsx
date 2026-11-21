import { useState } from "react";
import { Button, Pill } from "@/components/primitives";
import { HelpInd } from "@/components/HelpInd";
import { useApi } from "@/lib/useApi";
import { ConfigSaveCancelled, saveConfigEdit } from "@/lib/configSectionSave";
import { apiErrorMessage } from "@/lib/enrolment";
import {
  CARD_SUB,
  DEFAULT_WORKSPACE_PATH,
  folderProblem,
  putBody,
  savedWords,
  statusLine,
  type DefaultWorkspaceView,
} from "@/lib/defaultWorkspace";

// DefaultWorkspaceCard - Terminals > Settings and Settings > Terminal
// "Default workspace". Observer's own scratch folder ([workspace].default_dir;
// unset = <home>/observer-workspace), offered when a step needs a folder that
// is not one of your projects (the hosted sandbox consent step today). Every
// write goes through saveConfigEdit like every other config save: a dry run
// (the daemon checks the folder and writes nothing), the shell's review
// dialog with the exact file change, then the real PUT with the owner-local
// confirm token, which creates the folder before it saves. Reset clears the
// key, so the file never records the built-in folder.

const INPUT =
  "w-full rounded-2 border border-line-2 bg-bg-1 px-2 py-1 font-mono text-[12px] text-fg-1 placeholder:text-fg-4";

export function DefaultWorkspaceCard({ readOnly = false }: { readOnly?: boolean }) {
  const v = useApi<DefaultWorkspaceView>(DEFAULT_WORKSPACE_PATH);
  const [editing, setEditing] = useState(false);
  const [dir, setDir] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [saved, setSaved] = useState("");

  const view = v.data;
  if (!view) return null;

  async function save(next: string | null) {
    setErr("");
    setSaved("");
    if (next !== null) {
      const problem = folderProblem(next);
      if (problem) {
        setErr(problem);
        return;
      }
    }
    setBusy(true);
    try {
      const r = await saveConfigEdit<{ warning?: string }>(
        DEFAULT_WORKSPACE_PATH,
        "workspace",
        putBody(next),
        view?.confirm_token ? { "X-Observer-Confirm": view.confirm_token } : {},
        { title: next === null ? "Use the built-in default workspace" : "Default workspace" },
      );
      setSaved(savedWords(next === null, r.warning));
      setEditing(false);
      setDir("");
      v.reload();
    } catch (e) {
      if (e instanceof ConfigSaveCancelled) return;
      setErr(apiErrorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="mt-6 space-y-3 rounded-3 border border-line-2 bg-bg-2 p-4" data-testid="default-workspace">
      <header className="flex items-baseline justify-between gap-3">
        <h4 className="text-[13px] font-semibold text-fg-0">
          Default workspace <HelpInd id="glossary.default_workspace" />
        </h4>
        <Pill variant={view.problem ? "warn" : view.builtin ? "neutral" : "success"}>
          {view.problem ? "needs a change" : view.builtin ? "built-in" : "your choice"}
        </Pill>
      </header>
      <p className="text-[11px] text-fg-3">{CARD_SUB}</p>

      <div className="space-y-1">
        <code className="block break-all rounded-2 border border-line-2 bg-bg-3 px-2 py-1 font-mono text-[11px] text-fg-2" data-testid="default-workspace-dir">
          {view.dir || "No folder"}
        </code>
        <p className={view.problem ? "text-[11px] text-warn" : "text-[11px] text-fg-3"}>{statusLine(view)}</p>
      </div>

      {!readOnly && !editing && (
        <div className="flex flex-wrap items-center gap-2">
          <Button
            size="sm"
            variant="secondary"
            disabled={busy}
            onClick={() => {
              setErr("");
              setSaved("");
              setDir(view.dir);
              setEditing(true);
            }}
          >
            Change folder
          </Button>
          {!view.builtin && (
            <Button size="sm" variant="ghost" disabled={busy} loading={busy} onClick={() => void save(null)}>
              Use the built-in folder
            </Button>
          )}
        </div>
      )}

      {!readOnly && editing && (
        <div className="space-y-2" data-testid="default-workspace-form">
          <input
            className={INPUT}
            aria-label="Default workspace folder"
            placeholder={view.builtin_dir || "Full path of a folder, e.g. /home/you/observer-workspace or C:\\Users\\you\\observer-workspace"}
            value={dir}
            disabled={busy}
            onChange={(e) => setDir(e.target.value)}
          />
          <p className="text-[11px] text-fg-3">
            Pick a new or empty folder. It must not be your home folder, a drive root, inside Observer's data folder, inside a git
            repository or a folder that holds your projects. When you save, Observer creates it and sets it up with a marker file and
            its own git repository.
          </p>
          <div className="flex flex-wrap items-center gap-2">
            <Button size="sm" variant="primary" disabled={busy} loading={busy} onClick={() => void save(dir)}>
              Save
            </Button>
            <Button
              size="sm"
              variant="ghost"
              disabled={busy}
              onClick={() => {
                setEditing(false);
                setErr("");
              }}
            >
              Cancel
            </Button>
            <span className="text-[11px] text-fg-3">You see the exact config.toml change before anything is written.</span>
          </div>
        </div>
      )}

      {saved && <p className="text-[11px] text-fg-2">{saved}</p>}
      {err && <p className="text-[11px] text-danger">{err}</p>}
    </section>
  );
}
