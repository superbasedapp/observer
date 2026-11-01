// scannerDB - the pure half of the Scanners card's OSV database accept
// (components security.scan.scalibr and security.scan.osv; operator ruling
// PT-19 (2): ask once, then automatic).
//
// Nothing is downloaded until the developer accepts once, here (a confirm
// dialog that shows the size and the source) or with `observer security
// scan db accept`; after that the refreshes are automatic. Before the
// accept the card says what is owed and never reads a project clean.

/** The download's state (GET /api/security/scanners `db`). */
export type ScannerDBStatus = {
  accepted: boolean;
  accepted_at?: string;
  accepted_on?: string;
  by?: string;
  approx_mb: number;
  source: string;
  text: string;
  managed: boolean;
  /** The download gate's first closed reason; absent when it may run. */
  blocked?: string;
  installed: number;
};

/** GET /api/security/scanners/db. */
export type ScannerDBResponse = { status: ScannerDBStatus; confirm_token?: string };

export type ScannerDBStage = "managed" | "waiting" | "accepted";

/**
 * scannerDBStage is the card's state: managed (the org mirror supplies the
 * databases, nothing to accept), waiting (no accept yet: nothing is
 * downloaded) or accepted. Null when the daemon does not report it.
 */
export function scannerDBStage(s: ScannerDBStatus | null | undefined): ScannerDBStage | null {
  if (!s) return null;
  if (s.managed) return "managed";
  return s.accepted ? "accepted" : "waiting";
}

/** scannerDBLine is the card's one line for the stage (no em dashes: copy rule). */
export function scannerDBLine(s: ScannerDBStatus): string {
  switch (scannerDBStage(s)) {
    case "managed":
      return "Managed node: the OSV databases come from your organization's mirror, not from the public bucket.";
    case "waiting":
      return `Databases not downloaded: accept to download about ${s.approx_mb} MB from ${s.source}. Until then dependencies show as not scanned.`;
    default: {
      const when = s.accepted_at ? new Date(s.accepted_at).toLocaleString() : "";
      const who = s.by ? `, ${s.by}` : "";
      return `Database download accepted ${when} (${s.accepted_on ?? "?"}${who}); refreshes are automatic.`;
    }
  }
}

/** scannerDBAcceptLabel is the dialog's accept button. */
export function scannerDBAcceptLabel(s: ScannerDBStatus): string {
  return `Accept and download about ${s.approx_mb} MB`;
}
