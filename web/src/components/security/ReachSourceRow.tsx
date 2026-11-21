import { useCallback, useEffect, useState } from "react";
import { Button, Pill, SinglePicker } from "@/components/primitives";
import { projectPickerOptions } from "@/lib/securityComponents";
import {
  reachSourceCanRun,
  reachSourceCapsLine,
  reachSourceHeading,
  reachSourceIsolationLine,
  reachSourceRunLine,
  type ReachSourceStatus,
} from "@/lib/reachSource";

// ReachSourceRow - the Scanners card's Go source check row (OS and CI
// vulnerability scanning plan section 14.5 item 3b, 3b-src). The check runs
// osv-scanner's Go call analysis once per go.mod, which runs this machine's
// Go toolchain on the project's code, so it is opt-in per project and runs
// only when the developer clicks Run (or runs `observer security scan
// --reach go-source`). Every switch and the Run button are human clicks on
// this owner-local surface, each a write carrying the confirm token its
// route's GET minted; an agent cannot do any of it (guard rule R-165 denies
// the route, the verbs and the record).
//
// Working surface: calm register, zero delight elements.

const ROUTE = "/api/security/reach/go-source";

/** A project the row can show: its root hash and its label. */
export type ReachSourceProject = { project_root_hash: string; label: string; active?: boolean };

/** ProjectPicker is the searchable single project field (active projects first, then idle) the Scanners rows share. */
export function ProjectPicker({
  projects,
  value,
  onChange,
  disabled,
  testId,
}: {
  projects: ReachSourceProject[];
  value: string;
  onChange: (hash: string) => void;
  disabled?: boolean;
  testId?: string;
}) {
  return (
    <div className="max-w-md" data-testid={testId}>
      <SinglePicker
        value={value}
        onChange={(next) => next && onChange(next)}
        options={projectPickerOptions(projects)}
        clearable={false}
        hideIds
        disabled={disabled}
        placeholder="Search projects"
        ariaLabel="Project"
      />
    </div>
  );
}

const routeFor = (project: string, run = false) => `${ROUTE}${run ? "/run" : ""}?project=${encodeURIComponent(project)}`;

async function readStatus(project: string): Promise<ReachSourceStatus> {
  const res = await fetch(routeFor(project));
  if (!res.ok) throw new Error((await res.text()).trim() || `HTTP ${res.status}`);
  return (await res.json()) as ReachSourceStatus;
}

/** write re-reads the route for a fresh confirm token, then sends. */
async function write(project: string, run: boolean, body: object): Promise<ReachSourceStatus> {
  const got = await readStatus(project);
  const res = await fetch(routeFor(project, run), {
    method: run ? "POST" : "PUT",
    headers: { "content-type": "application/json", ...(got.confirm_token ? { "X-Observer-Confirm": got.confirm_token } : {}) },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(text.trim() || `HTTP ${res.status}`);
  return JSON.parse(text) as ReachSourceStatus;
}

/** ReachSourceRow is the row: a project picker and its Go source check. */
export function ReachSourceRow({ projects }: { projects: ReachSourceProject[] }) {
  const [project, setProject] = useState(projectPickerOptions(projects)[0]?.id ?? "");
  const [view, setView] = useState<ReachSourceStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const load = useCallback(() => {
    if (!project) return () => {};
    let live = true;
    readStatus(project)
      .then((v) => live && setView(v))
      .catch((e: unknown) => live && setErr(e instanceof Error ? e.message : String(e)));
    return () => {
      live = false;
    };
  }, [project]);
  useEffect(() => {
    setView(null);
    setErr(null);
    return load();
  }, [load]);
  // While a run is going, re-read every 5 s.
  useEffect(() => {
    if (!view?.running) return;
    const t = setInterval(() => load(), 5000);
    return () => clearInterval(t);
  }, [view?.running, load]);
  async function act(run: boolean, body: object) {
    setBusy(true);
    setErr(null);
    try {
      setView(await write(project, run, body));
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }
  if (projects.length === 0) return null;
  return (
    <div className="space-y-2 border-t border-line-1 pt-3 text-[12.5px]" data-testid="scanner-reach-source">
      <div className="text-fg-2">Go source check (function-level, per go.mod)</div>
      {projects.length > 1 && (
        <ProjectPicker projects={projects} value={project} onChange={setProject} disabled={busy} testId="scanner-reach-source-project" />
      )}
      {view ? (
        <ReachSourceView
          view={view}
          busy={busy}
          onOptIn={(enabled, allowUnisolated) => void act(false, { enabled, allow_unisolated: allowUnisolated })}
          onRun={() => void act(true, {})}
        />
      ) : null}
      {err && <p className="m-0 text-danger">{err}</p>}
    </div>
  );
}

/** ReachSourceView is the row's body: the opt-in, the isolation override,
 *  the Run button and each go.mod's stored answer. */
export function ReachSourceView({
  view,
  busy,
  onOptIn,
  onRun,
}: {
  view: ReachSourceStatus;
  busy: boolean;
  onOptIn: (enabled: boolean, allowUnisolated: boolean) => void;
  onRun: () => void;
}) {
  const usable = view.compiled && view.selected;
  return (
    <div className="space-y-2" data-testid="scanner-reach-source-view">
      <p className="m-0 text-fg-3" data-testid="scanner-reach-source-heading">
        {view.compiled && !view.selected ? "Off. Turn on the Go source check with the scanner switches above." : reachSourceHeading(view)}
      </p>
      <div className="flex flex-wrap items-center gap-3">
        <label className="flex items-center gap-2 text-fg-1">
          <input
            type="checkbox"
            checked={view.opted_in}
            disabled={busy || !usable}
            onChange={() => onOptIn(!view.opted_in, view.allow_unisolated)}
            aria-label="Opt this project in to the Go source check"
          />
          <span>Opted in</span>
        </label>
        <label className="flex items-center gap-2 text-fg-1">
          <input
            type="checkbox"
            checked={view.allow_unisolated}
            disabled={busy || !usable || !view.opted_in}
            onChange={() => onOptIn(true, !view.allow_unisolated)}
            aria-label="Allow the Go source check to run without isolation"
          />
          <span>Run without isolation where it is not available</span>
        </label>
        <Button size="sm" variant="secondary" disabled={busy || !reachSourceCanRun(view)} onClick={onRun} data-testid="scanner-reach-source-run">
          {view.running ? "Running…" : "Run the check"}
        </Button>
      </div>
      <p className="m-0 text-fg-3">{reachSourceIsolationLine(view)}</p>
      <p className="m-0 text-fg-3">{reachSourceCapsLine(view)}</p>
      {view.last_error ? <p className="m-0 text-danger">Last run: {view.last_error}</p> : null}
      {view.runs.length > 0 ? (
        <ul className="m-0 list-none space-y-1.5 p-0">
          {view.runs.map((r) => (
            <li key={r.target} className="flex flex-wrap items-center gap-2" data-testid="scanner-reach-source-gomod">
              <span className="font-mono text-fg-2">{r.target}</span>
              <Pill variant={r.reason ? "warn" : r.called > 0 ? "danger" : "neutral"}>{reachSourceRunLine(r)}</Pill>
            </li>
          ))}
        </ul>
      ) : null}
      <p className="m-0 text-[11.5px] text-fg-3">{view.text}</p>
    </div>
  );
}
