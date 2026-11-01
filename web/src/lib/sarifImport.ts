// sarifImport - the pure half of the Code security page's SARIF upload
// (component security.scan.sarif-import, lane SEC-P4).
//
// The developer picks one SARIF file a tool they ran themselves wrote; the
// upload sends its exact text to the owner-local route, which records it
// through the same import as `observer security import-sarif`. Findings
// are flag only, carry an inferred lineage and close nothing: an import
// never shows a project clean.

/** The upload route. GET returns the picker, the cap and the confirm token. */
export const SARIF_IMPORT_ROUTE = "/api/security/import-sarif";

export type SARIFImportTool = { id: string; label: string };

/** GET /api/security/import-sarif. */
export type SARIFImportResponse = {
  tools: SARIFImportTool[];
  max_bytes: number;
  confirm_token?: string;
};

/** One import's report (the CLI's `--json` shape). */
export type SARIFImportReport = {
  project_root_hash: string;
  tool: string;
  outcome: string;
  reason?: string;
  findings: number;
  new: number;
  with_lineage: number;
  refused?: Record<string, number>;
  truncated?: boolean;
};

/** byteLength is the UTF-8 size of text, what the server's cap counts. */
export function byteLength(text: string): number {
  return new TextEncoder().encode(text).length;
}

/**
 * sarifUploadCheck is the client side of the cap and the shape: null when
 * the file may be sent, else the reason it is not. The server checks the
 * same again; this only saves a wasted upload.
 */
export function sarifUploadCheck(text: string, maxBytes: number): string | null {
  if (text.trim() === "") return "The file is empty.";
  if (maxBytes > 0 && byteLength(text) > maxBytes) {
    return `The file is over the ${Math.floor(maxBytes / (1 << 20))} MB SARIF limit.`;
  }
  try {
    const v: unknown = JSON.parse(text);
    if (v === null || typeof v !== "object" || Array.isArray(v)) return "The file is not a SARIF log (a JSON object).";
  } catch {
    return "The file is not JSON, so it cannot be a SARIF log.";
  }
  return null;
}

/**
 * sarifUploadBody is the POST body: the project and the tool, and the
 * file's own text unchanged (so the server reads the bytes the tool wrote).
 * Call it only after sarifUploadCheck passed.
 */
export function sarifUploadBody(project: string, tool: string, text: string): string {
  return `{"project":${JSON.stringify(project)},"tool":${JSON.stringify(tool)},"sarif":${text}}`;
}

/** sarifReportLine is the one-line result, the CLI's own words. */
export function sarifReportLine(r: SARIFImportReport): string {
  let line = `Imported ${r.findings} finding(s) from ${r.tool} (${r.new} new, ${r.with_lineage} with an inferred AI-edit lineage); outcome ${r.outcome}`;
  if (r.reason) line += ` (${r.reason.replaceAll("_", " ")})`;
  line += ".";
  const refused = Object.entries(r.refused ?? {}).reduce((n, [, c]) => n + c, 0);
  if (refused > 0) line += ` ${refused} result(s) refused.`;
  if (r.truncated) line += " The file held more results than the cap; the rest were not imported.";
  return line;
}
