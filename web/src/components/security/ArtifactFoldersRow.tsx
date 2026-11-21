import { useEffect, useState } from "react";
import { Pill, Select } from "@/components/primitives";
import { artifactHeading, artifactStateLine, type ArtifactFolder, type ArtifactFolders } from "@/lib/artifactFolders";

// ArtifactFoldersRow - the Scanners card's build artifact folders row (OS
// and CI vulnerability scanning plan section 14.6, M3L-2 item 4; operator
// ruling 2026-11-05). Full artifact scanning is opt-in per folder: the
// candidate folders of a project (bin/, dist/, target/release/ and the like)
// are found by folder name and file header only and listed with what their
// headers say they hold; each is off until the developer switches it on
// here, with `observer security scan artifacts enable`, or names it for one
// run with `observer security scan --artifacts`.
//
// A switch is a human click on this owner-local surface: a PUT carrying the
// confirm token its route's GET minted. Nothing is switched on for the
// developer, and an agent cannot do it (guard rule R-165 denies the route,
// the verbs and the record).
//
// Working surface: calm register, zero delight elements.

const ROUTE = "/api/security/artifacts";

/** A project the row can show: its root hash and its label. */
export type ArtifactProject = { project_root_hash: string; label: string };

const routeFor = (project: string) => `${ROUTE}?project=${encodeURIComponent(project)}`;

/** setArtifact re-reads the route for a fresh confirm token, then PUTs. */
async function setArtifact(project: string, dir: string, enabled: boolean): Promise<ArtifactFolders> {
  const res = await fetch(routeFor(project));
  if (!res.ok) throw new Error((await res.text()).trim() || `HTTP ${res.status}`);
  const got = (await res.json()) as ArtifactFolders;
  const put = await fetch(routeFor(project), {
    method: "PUT",
    headers: { "content-type": "application/json", ...(got.confirm_token ? { "X-Observer-Confirm": got.confirm_token } : {}) },
    body: JSON.stringify({ dir, enabled }),
  });
  const text = await put.text();
  if (!put.ok) throw new Error(text.trim() || `HTTP ${put.status}`);
  return JSON.parse(text) as ArtifactFolders;
}

/** ArtifactFoldersRow is the row: a project picker and its folders. */
export function ArtifactFoldersRow({ projects }: { projects: ArtifactProject[] }) {
  const [project, setProject] = useState(projects[0]?.project_root_hash ?? "");
  const [view, setView] = useState<ArtifactFolders | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    if (!project) return;
    let live = true;
    setView(null);
    setErr(null);
    fetch(routeFor(project))
      .then(async (res) => {
        if (!res.ok) throw new Error((await res.text()).trim() || `HTTP ${res.status}`);
        return (await res.json()) as ArtifactFolders;
      })
      .then((v) => live && setView(v))
      .catch((e: unknown) => live && setErr(e instanceof Error ? e.message : String(e)));
    return () => {
      live = false;
    };
  }, [project]);
  async function toggle(f: ArtifactFolder) {
    setBusy(true);
    setErr(null);
    try {
      setView(await setArtifact(project, f.dir, !f.enabled));
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }
  if (projects.length === 0) return null;
  return (
    <div className="space-y-2 border-t border-line-1 pt-3 text-[12.5px]" data-testid="scanner-artifacts">
      <div className="text-fg-2">Build artifact folders</div>
      {projects.length > 1 && (
        <Select
          label="Project"
          value={project}
          disabled={busy}
          onChange={(e) => setProject(e.target.value)}
          options={projects.map((p) => ({ value: p.project_root_hash, label: p.label }))}
          data-testid="scanner-artifacts-project"
        />
      )}
      {view ? <ArtifactFoldersView view={view} busy={busy} onToggle={(f) => void toggle(f)} /> : null}
      {err && <p className="m-0 text-danger">{err}</p>}
    </div>
  );
}

/** ArtifactFoldersView is the folders list: each folder, what its headers
 *  say it holds, and its switch. */
export function ArtifactFoldersView({
  view,
  busy,
  onToggle,
}: {
  view: ArtifactFolders;
  busy: boolean;
  onToggle: (f: ArtifactFolder) => void;
}) {
  return (
    <div className="space-y-2" data-testid="scanner-artifacts-view">
      <p className="m-0 text-fg-3" data-testid="scanner-artifacts-heading">
        {artifactHeading(view)}
      </p>
      <ul className="m-0 list-none space-y-1.5 p-0">
        {view.folders.map((f) => (
          <li key={f.dir} className="flex flex-wrap items-center gap-2" data-testid="scanner-artifact-folder">
            <label className="flex items-center gap-2 text-fg-1">
              <input
                type="checkbox"
                checked={f.enabled}
                disabled={busy || !view.driver_compiled}
                onChange={() => onToggle(f)}
                aria-label={`Scan the build artifacts in ${f.dir}`}
              />
              <span className="font-mono text-fg-2">{f.dir}/</span>
            </label>
            <Pill variant={f.enabled ? "success" : "neutral"}>{artifactStateLine(f)}</Pill>
            <span className="text-fg-3">
              {f.summary}
              {f.truncated ? " (more than shown)" : ""}
            </span>
          </li>
        ))}
      </ul>
      <p className="m-0 text-[11.5px] text-fg-3">{view.text}</p>
    </div>
  );
}
