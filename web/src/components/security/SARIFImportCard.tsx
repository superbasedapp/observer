import { useState } from "react";
import { Button, Card, Select } from "@/components/primitives";
import { useApi } from "@/lib/useApi";
import {
  SARIF_IMPORT_ROUTE,
  sarifReportLine,
  sarifUploadBody,
  sarifUploadCheck,
  type SARIFImportReport,
  type SARIFImportResponse,
  type SARIFImportTool,
} from "@/lib/sarifImport";

// The Code security page's SARIF upload (component
// security.scan.sarif-import, lane SEC-P4): the developer picks one SARIF
// file a tool they ran themselves wrote, names the tool and the project,
// and the file is recorded through the same import as `observer security
// import-sarif`. The route answers 404 unless the component and
// security.code are selected (opt-in), so an install that never chose it
// sees no card. The route is owner-local and the POST carries the confirm
// token the GET minted. Findings are flag only and close nothing.
//
// Working surface: calm register, zero delight elements.

// label is the project's name (lib/codeSecurity.ts projectLabel); a row
// without one falls back to a short hash marked as such, never a bare hash
// (which reads as a git commit id).
export type SARIFImportProject = { project_root_hash: string; label?: string };

export function SARIFImportCard({ projects, onImported }: { projects: SARIFImportProject[]; onImported?: () => void }) {
  const api = useApi<SARIFImportResponse>(SARIF_IMPORT_ROUTE);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<{ ok: boolean; text: string } | null>(null);
  if (!api.data?.tools) return null;
  const data = api.data;
  async function upload(project: string, tool: string, file: File) {
    setBusy(true);
    setNote(null);
    try {
      const text = await file.text();
      const refused = sarifUploadCheck(text, data.max_bytes);
      if (refused) throw new Error(refused);
      // A fresh token: the page may have been open longer than the last one.
      const res0 = await fetch(SARIF_IMPORT_ROUTE);
      if (!res0.ok) throw new Error((await res0.text()) || `HTTP ${res0.status}`);
      const got = (await res0.json()) as SARIFImportResponse;
      const res = await fetch(SARIF_IMPORT_ROUTE, {
        method: "POST",
        headers: { "content-type": "application/json", "X-Observer-Confirm": got.confirm_token ?? "" },
        body: sarifUploadBody(project, tool, text),
      });
      const body = await res.text();
      if (!res.ok) throw new Error(body.trim() || `HTTP ${res.status}`);
      const out = JSON.parse(body) as { report: SARIFImportReport };
      setNote({ ok: true, text: sarifReportLine(out.report) });
      onImported?.();
    } catch (e: unknown) {
      setNote({ ok: false, text: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
    }
  }
  return <SARIFImportCardView tools={data.tools} maxBytes={data.max_bytes} projects={projects} busy={busy} note={note} onUpload={upload} />;
}

/** SARIFImportCardView is the card's markup, pure in its props (tests render it). */
export function SARIFImportCardView({
  tools,
  maxBytes,
  projects,
  busy,
  note,
  onUpload,
}: {
  tools: SARIFImportTool[];
  maxBytes: number;
  projects: SARIFImportProject[];
  busy: boolean;
  note: { ok: boolean; text: string } | null;
  onUpload: (project: string, tool: string, file: File) => void;
}) {
  const [project, setProject] = useState(projects[0]?.project_root_hash ?? "");
  const [tool, setTool] = useState(tools[0]?.id ?? "");
  const [file, setFile] = useState<File | null>(null);
  const chosen = project || projects[0]?.project_root_hash || "";
  return (
    <Card title="Import SARIF" sub="Findings from a scanner you ran yourself, flag only, each with an inferred lineage to the latest AI edit of its file">
      <div className="space-y-3 text-[12.5px]" data-testid="sarif-import-card">
        {projects.length === 0 ? (
          <p className="m-0 text-fg-3">No projects yet: a project appears once an AI tool session runs in it.</p>
        ) : (
          <>
            <div className="grid gap-3 sm:grid-cols-2">
              <Select
                label="Project"
                value={chosen}
                onChange={(e) => setProject(e.target.value)}
                options={projects.map((p) => ({ value: p.project_root_hash, label: p.label ?? `Unknown project (${p.project_root_hash.slice(0, 8)})` }))}
              />
              <Select label="Tool" value={tool} onChange={(e) => setTool(e.target.value)} options={tools.map((t) => ({ value: t.id, label: t.label }))} />
            </div>
            <label className="block text-fg-2">
              SARIF file (at most {Math.floor(maxBytes / (1 << 20))} MB)
              <input
                type="file"
                accept=".sarif,.json,application/json"
                className="mt-1 block"
                data-testid="sarif-import-file"
                onChange={(e) => setFile(e.target.files?.[0] ?? null)}
              />
            </label>
            <Button variant="primary" disabled={busy || !file || !chosen || !tool} onClick={() => file && onUpload(chosen, tool, file)}>
              {busy ? "Importing..." : "Import"}
            </Button>
          </>
        )}
        <p className="m-0 text-fg-3">
          Observer never runs the tool. An import adds findings and closes none, so it never shows a project clean.
        </p>
        {note && <p className={note.ok ? "m-0 text-fg-2" : "m-0 text-danger"}>{note.text}</p>}
      </div>
    </Card>
  );
}
