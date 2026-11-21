import { useId, useState } from "react";
import { Copy, FileDown } from "lucide-react";
import { Button, TooltipSpan } from "@/components/primitives";
import { HelpInd } from "@/components/HelpInd";
import { useMediaQuery } from "@/lib/useMediaQuery";
import type { AssessModelResponse } from "@/lib/secAssessModel";
import type { AssessRun } from "@/lib/secAssess";
import {
  EXPORT_DOWNLOADS,
  EXPORT_DOWNLOAD_NONE,
  EXPORT_DOWNLOAD_NOTE,
  assessExportPath,
  exportErrorWords,
  exportFileName,
  type ExportDownload,
} from "@/lib/secAssessFix";
import { CopyNote, useCopy } from "./modelParts";

// ExportMenu is the row of export buttons in the model dialog's footer: two
// copies from the answer already in memory (the diagram source and the checked
// model as JSON) and two downloads (a Markdown report and the checked model as
// a JSON file; depth plan W6b). A copy requests nothing. A download reads
// GET /api/security/assessments/export, which Observer builds from the stored,
// checked copy of the model: it is not the agent's own report, and recognised
// secrets are hidden in it while hiding is on. A refusal is said in words next
// to the buttons and is never saved as a file.
//
// All four are plain buttons in the dialog's footer, in its tab order, so a
// keyboard reaches each (a menu opened from a button is not in the dialog's
// focus trap and was out of reach). A download keeps its button enabled while
// the file is made, so focus stays where it was.
//
// On a phone the four buttons and their two notes would fill the screen before
// the first row of the model, so below NARROW_QUERY they sit behind one
// "Copy and download" button (a disclosure in the footer, not a menu) and the
// footer holds that button and Close. On a wider window nothing changes.

export type ExportItem = {
  id: "diagram" | "model";
  label: string;
  /** What the copy is, said under the buttons. */
  description: string;
  /** The text to copy, built when the button is pressed (a large model is not turned to text until it is wanted). */
  text: () => string;
};

/** exportItems lists what this answer can export: the diagram source (a threat model with one) and the checked model as JSON (any answer that holds a model). */
export function exportItems(data: AssessModelResponse): ExportItem[] {
  const items: ExportItem[] = [];
  const source = data?.mermaid?.source;
  if (source) {
    items.push({
      id: "diagram",
      label: "Copy diagram source",
      description: "The Mermaid source of the data-flow diagram, to paste into any Mermaid viewer.",
      text: () => source,
    });
  }
  const model = data?.record?.result?.tm ?? data?.record?.result?.pt;
  if (model) {
    items.push({
      id: "model",
      label: "Copy checked model",
      description: "The checked copy as Observer shows it, as JSON, with recognised secrets hidden while hiding is on. It is not the agent's file as written.",
      text: () => JSON.stringify(model, null, 2),
    });
  }
  return items;
}

/** exportDownloadsAvailable is whether the answer holds a model the two downloads can render: the same condition as the copy of the checked model. */
export function exportDownloadsAvailable(data: AssessModelResponse | null | undefined): boolean {
  return !!(data?.record?.result?.tm ?? data?.record?.result?.pt);
}

/** The sentence under the buttons when there is a model to copy. */
export const EXPORT_NOTE =
  "The copy is the checked model as Observer shows it, with recognised secrets hidden while hiding is on. It is not the agent's file as written.";

/** saveBlob hands a file to the browser as a download and releases it. */
function saveBlob(blob: Blob, name: string): void {
  const href = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = href;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.setTimeout(() => URL.revokeObjectURL(href), 0);
}

/** downloadExport reads one export of a run and saves it. It returns the words of a refusal or a failure, or "" when the file was saved; nothing is saved for a refusal. */
export async function downloadExport(run: string, d: ExportDownload): Promise<string> {
  try {
    const res = await fetch(assessExportPath(run, d.format));
    if (!res.ok) return exportErrorWords(res.status, await res.text().catch(() => ""));
    const blob = await res.blob();
    saveBlob(blob, exportFileName(res.headers.get("content-disposition"), run, d.format));
    return "";
  } catch {
    return "The download could not be made. Nothing was saved.";
  }
}

/** NARROW_QUERY is the width below which the export buttons sit behind one disclosure button: a phone, where four buttons and two notes cover the model. A width, not a pointer: this is layout, and a narrowed desktop window has the same problem. */
export const NARROW_QUERY = "(max-width: 639px)";

/** NARROW_BODY_CLASS is the opened disclosure's box on a phone: the footer is part of the dialog and the model is what the person came to read, so the box is capped at about a quarter of the screen and scrolls inside itself (N-15). Before the cap, opening it made the footer about 60% of the screen and left about 90 px of the model. Its buttons stay in the dialog's tab order, and a scrolled-to button scrolls into view when focused. */
export const NARROW_BODY_CLASS = "flex min-w-0 max-h-[24vh] basis-full flex-wrap items-center gap-2 overflow-y-auto overscroll-contain p-0.5";

export function ExportMenu({
  data,
  run,
  narrow: narrowOverride,
  expanded = false,
}: {
  data: AssessModelResponse | null;
  run: AssessRun;
  /** Force the narrow (true) or the wide (false) layout, instead of reading the window's width. */
  narrow?: boolean;
  /** The narrow layout's disclosure starts open. */
  expanded?: boolean;
}) {
  const measured = useMediaQuery(NARROW_QUERY);
  const narrow = narrowOverride ?? measured;
  const [asked, setAsked] = useState(expanded);
  const bodyId = useId();
  const shown = !narrow || asked;
  const { status, copy } = useCopy();
  const [busy, setBusy] = useState<ExportDownload["format"] | null>(null);
  const [failure, setFailure] = useState("");
  const items = data ? exportItems(data) : [];
  const canDownload = exportDownloadsAvailable(data);

  async function save(d: ExportDownload) {
    if (busy !== null) return;
    setBusy(d.format);
    setFailure("");
    const words = await downloadExport(run.id, d);
    setFailure(words);
    setBusy(null);
  }

  return (
    <div className="flex min-w-0 flex-wrap items-center gap-2" data-run-id={run.id} data-testid="assess-export">
      {narrow && (
        <Button size="sm" variant="secondary" aria-expanded={shown} aria-controls={bodyId} data-testid="assess-export-toggle" onClick={() => setAsked(!asked)}>
          Copy and download
        </Button>
      )}
      {shown && (
        <div id={bodyId} className={narrow ? NARROW_BODY_CLASS : "contents"} data-testid="assess-export-body">
          {items.length === 0 ? (
            <TooltipSpan content="There is no model to copy from this run.">
              <Button size="sm" variant="secondary" iconLeft={Copy} disabled data-testid="assess-export-model">
                Copy checked model
              </Button>
            </TooltipSpan>
          ) : (
            items.map((it) => (
              <Button key={it.id} size="sm" variant="secondary" iconLeft={Copy} data-testid={`assess-export-${it.id}`} onClick={() => copy(it.text())}>
                {it.label}
              </Button>
            ))
          )}
          {EXPORT_DOWNLOADS.map((d) =>
            canDownload ? (
              <Button key={d.format} size="sm" variant="secondary" iconLeft={FileDown} data-testid={d.testId} aria-busy={busy === d.format} onClick={() => void save(d)}>
                {d.label}
              </Button>
            ) : (
              <TooltipSpan key={d.format} content={EXPORT_DOWNLOAD_NONE}>
                <Button size="sm" variant="secondary" iconLeft={FileDown} disabled data-testid={d.testId}>
                  {d.label}
                </Button>
              </TooltipSpan>
            ),
          )}
          <CopyNote status={status} testId="assess-export-copied" />
          {busy !== null && (
            <span role="status" className="text-[11.5px] text-fg-3" data-testid="assess-export-download-busy">
              Making the file
            </span>
          )}
          {failure !== "" && (
            <span role="alert" className="min-w-0 text-[11.5px] text-warn" data-testid="assess-export-download-error">
              {failure}
            </span>
          )}
          {items.length > 0 && (
            <p className="m-0 basis-full text-[11px] text-fg-3" data-testid="assess-export-note">
              {EXPORT_NOTE}
            </p>
          )}
          {canDownload && (
            <p className="m-0 basis-full text-[11px] text-fg-3" data-testid="assess-export-download-note">
              {EXPORT_DOWNLOAD_NOTE}
              <HelpInd id="card.code_security_assess_export" />
            </p>
          )}
        </div>
      )}
    </div>
  );
}
