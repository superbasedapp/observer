import { useState } from "react";
import { Button, Pill } from "@/components/primitives";
import { useApi } from "@/lib/useApi";
import { markRestartPending } from "@/lib/restartPending";
import { ConfigSaveCancelled, saveConfigEdit, shellConfigSavePreview } from "@/lib/configSectionSave";
import { NO_PREVIEW_MESSAGE } from "@/lib/configSectionSaveCore";
import { apiErrorMessage } from "@/lib/enrolment";
import type { TerminalSessionsMeta } from "@/lib/types";
import {
  CARD_SUB,
  LAUNCH_TOOL_PATHS_PATH,
  addableTools,
  pathItems,
  pathProblem,
  putBody,
  savedWords,
  type LaunchToolPathsView,
} from "@/lib/launchToolPaths";

// LaunchToolPathsCard - Settings -> Terminal "Launch binary paths". The
// [launch.tools.<tool>].path overrides: an absolute program path that wins over
// the PATH lookup when `observer <tool>` (or the New Terminal dialog) starts a
// tool. Every write goes through saveConfigEdit, like every other config save:
// a dry run (the daemon checks it and writes nothing), the shell's review
// dialog with the exact file change, then the real PUT with the owner-local
// confirm token at the etag the review was computed against. A path with no
// program file there stops before the dialog and keeps the path box editable.

const INPUT =
  "w-full rounded-2 border border-line-2 bg-bg-1 px-2 py-1 font-mono text-[12px] text-fg-1 placeholder:text-fg-4";
const SELECT = "rounded-2 border border-line-2 bg-bg-1 px-2 py-1 text-[12px] text-fg-1";
const NOTHING_THERE = "Nothing is at that path on this machine. Saving needs a program file there.";

/** What the user is changing: a tool and its new path (null = remove). */
type Draft = { tool: string; path: string | null };

export function LaunchToolPathsCard({ readOnly = false }: { readOnly?: boolean }) {
  const v = useApi<LaunchToolPathsView>(LAUNCH_TOOL_PATHS_PATH);
  const sessions = useApi<TerminalSessionsMeta>("/api/terminal/sessions");
  // The row being changed (its path input), or "+" for the add form.
  const [editing, setEditing] = useState<string | null>(null);
  const [tool, setTool] = useState("");
  const [path, setPath] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [saved, setSaved] = useState("");

  const view = v.data;
  if (!view) return null;
  const items = pathItems(view.paths);
  const addable = addableTools(sessions.data?.launchable_tools, view.paths);

  function reset() {
    setEditing(null);
    setTool("");
    setPath("");
  }

  async function save(d: Draft) {
    setErr("");
    setSaved("");
    const draft: Draft = { tool: d.tool, path: d.path === null ? null : d.path.trim() };
    if (draft.path !== null) {
      const problem = draft.tool === "" ? "Choose a tool." : pathProblem(draft.path);
      if (problem) {
        setErr(problem);
        return;
      }
    }
    const shell = shellConfigSavePreview();
    let missing = false;
    setBusy(true);
    try {
      const r = await saveConfigEdit<{ exists?: boolean }>(
        LAUNCH_TOOL_PATHS_PATH,
        "launch",
        putBody(draft.tool, draft.path),
        view?.confirm_token ? { "X-Observer-Confirm": view.confirm_token } : {},
        {
          title:
            draft.path === null ? `Remove the ${draft.tool} launch path` : `Launch binary path for ${draft.tool}`,
          prompt: async (req) => {
            // The dry run allows a missing file and reports it; the real save
            // refuses one, so say so here instead of offering that Save.
            if (draft.path !== null && (req.dryRun as { exists?: boolean }).exists === false) {
              missing = true;
              return false;
            }
            if (!shell) throw new Error(NO_PREVIEW_MESSAGE);
            return shell(req);
          },
        },
      );
      const restart = r.restart_required === true;
      if (restart) markRestartPending("terminal", ["launch.tools"]);
      setSaved(savedWords(restart, draft.path === null));
      reset();
      v.reload();
    } catch (e) {
      if (e instanceof ConfigSaveCancelled) {
        if (missing) setErr(NOTHING_THERE);
        return;
      }
      setErr(apiErrorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  const draftTool = editing === "+" ? tool : (editing ?? "");

  return (
    <section className="mt-6 space-y-3 rounded-3 border border-line-2 bg-bg-2 p-4" data-testid="launch-tool-paths">
      <header className="flex items-baseline justify-between gap-3">
        <h4 className="text-[13px] font-semibold text-fg-0">Launch binary paths</h4>
        {items.length > 0 && <Pill variant="neutral">{items.length} set</Pill>}
      </header>
      <p className="text-[11px] text-fg-3">{CARD_SUB}</p>

      {items.length === 0 && editing === null && (
        <p className="text-[11px] text-fg-3">No tool has a path set. Every launch looks its program up.</p>
      )}

      <ul className="space-y-2">
        {items.map((it) => (
          <li key={it.tool} className="space-y-1">
            <div className="flex flex-wrap items-center gap-2 text-[12px]">
              <span className="font-medium text-fg-1">{it.tool}</span>
              <span className="min-w-0 break-all font-mono text-[11px] text-fg-2">{it.path}</span>
              {it.nothingThere && <Pill variant="warn">nothing there</Pill>}
              {!readOnly && editing !== it.tool && (
                <span className="ml-auto flex gap-2">
                  <Button
                    size="sm"
                    variant="ghost"
                    disabled={busy}
                    onClick={() => {
                      reset();
                      setErr("");
                      setSaved("");
                      setEditing(it.tool);
                      setPath(it.path);
                    }}
                  >
                    Change
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    disabled={busy}
                    onClick={() => {
                      reset();
                      void save({ tool: it.tool, path: null });
                    }}
                  >
                    Remove
                  </Button>
                </span>
              )}
            </div>
            {it.nothingThere && <p className="text-[11px] text-warn">{it.note}</p>}
          </li>
        ))}
      </ul>

      {!readOnly && editing === null && addable.length > 0 && (
        <Button
          size="sm"
          variant="secondary"
          disabled={busy}
          onClick={() => {
            reset();
            setErr("");
            setSaved("");
            setEditing("+");
          }}
        >
          Add a path for another tool
        </Button>
      )}

      {!readOnly && editing !== null && (
        <div className="space-y-2" data-testid="launch-tool-paths-form">
          <div className="flex flex-wrap items-center gap-2">
            {editing === "+" ? (
              <select
                className={SELECT}
                aria-label="Tool"
                value={tool}
                disabled={busy}
                onChange={(e) => setTool(e.target.value)}
              >
                <option value="">Choose a tool</option>
                {addable.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
            ) : (
              <span className="text-[12px] font-medium text-fg-1">{editing}</span>
            )}
          </div>
          <input
            className={INPUT}
            aria-label="Path to the program"
            placeholder="Full path to the program, e.g. /usr/local/bin/tool or C:\Tools\tool.exe"
            value={path}
            disabled={busy}
            onChange={(e) => setPath(e.target.value)}
          />
          <div className="flex flex-wrap items-center gap-2">
            <Button size="sm" variant="primary" disabled={busy} onClick={() => void save({ tool: draftTool, path })}>
              Save
            </Button>
            <Button size="sm" variant="ghost" disabled={busy} onClick={reset}>
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
