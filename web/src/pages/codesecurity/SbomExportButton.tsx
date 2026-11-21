import { useState } from "react";
import { Button, Tooltip } from "@/components/primitives";
import { dastErrorText } from "./DastCard";

// SbomExportButton is a Projects tab row's "Export SBOM" (component
// security.deps; security coverage gaps plan
// docs/plans/security-coverage-gaps-plan-2026-11-13.md section 3): it reads
// GET /api/security/sbom?project=<hash>, the project's CycloneDX document
// rendered from the inventory its last dependency scan stored, and saves it
// as a file. A refusal (no inventory yet, the component not selected) is
// shown on the button, never saved as a file. Owner-local route; nothing is
// sent anywhere.
//
// Working surface: calm register, zero delight elements.

/** sbomHref is the export route for one project. */
export function sbomHref(hash: string): string {
  return `/api/security/sbom?project=${encodeURIComponent(hash)}`;
}

/** sbomFileName reads the download's file name from Content-Disposition,
 *  falling back to a name built from the project hash. */
export function sbomFileName(disposition: string | null, hash: string): string {
  const m = /filename="([^"]+)"/.exec(disposition ?? "");
  return m?.[1] || `project-${hash.slice(0, 8)}.sbom.cdx.json`;
}

export function SbomExportButton({ hash, disabled }: { hash: string; disabled?: boolean }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  async function download() {
    setBusy(true);
    setErr(null);
    try {
      const res = await fetch(sbomHref(hash));
      if (!res.ok) throw new Error(dastErrorText(res.status, await res.text()));
      const blob = await res.blob();
      const href = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = href;
      a.download = sbomFileName(res.headers.get("content-disposition"), hash);
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(href), 0);
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }
  return <SbomExportButtonView busy={busy} disabled={disabled} error={err} onExport={() => void download()} />;
}

/** SbomExportButtonView is the button, pure in its props (tests render it). */
export function SbomExportButtonView({
  busy,
  disabled,
  error,
  onExport,
}: {
  busy: boolean;
  disabled?: boolean;
  error: string | null;
  onExport: () => void;
}) {
  const button = (
    <Button
      size="sm"
      variant="secondary"
      disabled={busy || disabled}
      data-testid="sbom-export"
      onClick={(e) => {
        e.stopPropagation();
        onExport();
      }}
    >
      {busy ? "Exporting..." : "Export SBOM"}
    </Button>
  );
  if (!error) return button;
  return (
    <span className="inline-flex items-center gap-1.5">
      {button}
      <Tooltip content={error}>
        <span className="text-[11.5px] text-danger" data-testid="sbom-export-error">
          not exported
        </span>
      </Tooltip>
    </span>
  );
}
