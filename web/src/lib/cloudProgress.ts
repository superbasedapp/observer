import type { CloudEnrichmentProgress } from "./types";
import type { CloudChipVariant } from "./cloud";

type ProgressMeta = {
  label: string;
  message: string;
  variant: CloudChipVariant;
  blocksEnrichment: boolean;
  syncLabel?: string;
};

// Upload acceptance is distinct from a locally available enrichment result.
export function cloudProgressMeta(progress?: CloudEnrichmentProgress): ProgressMeta {
  switch (progress?.state) {
    case "idle": return { label: "Not enriched", message: "Choose this session to preview and enrich it. Automatic enrichment can stay off.", variant: "neutral", blocksEnrichment: false };
    case "pending": return { label: "Queued for enrichment", message: "Your request is saved and waiting to upload. You do not need to submit it again. You can close this panel; the next cloud sync will try the upload.", variant: "info", blocksEnrichment: true, syncLabel: "Upload queued request" };
    case "sending": return { label: "Uploading session", message: "This session is being uploaded. You do not need to submit it again. You can close this panel and check its status later.", variant: "info", blocksEnrichment: true };
    case "sent": return { label: "Awaiting enrichment result", message: "Your session was uploaded. Its enrichment result has not reached this node yet. You can close this panel; the result will appear after a cloud sync retrieves it.", variant: "info", blocksEnrichment: true, syncLabel: "Check for result" };
    case "failed_retryable": return { label: progress.last_error === "http_429" ? "Waiting for allowance or capacity" : "Upload needs retry", message: progress.last_error === "http_429" ? "The service could not accept this request yet. It remains queued. Wait for allowance or service capacity, then retry this request; do not create another one." : "The upload did not finish. Your request is saved; retry its upload without submitting a new enrichment.", variant: "warn", blocksEnrichment: true, syncLabel: "Retry upload" };
    case "reconfirmation_required": return { label: "Review needed", message: "The session or its consent changed. Preview the current data and confirm again before it can be uploaded.", variant: "warn", blocksEnrichment: false };
    case "failed_terminal": return { label: "Enrichment request failed", message: "This request will not retry automatically. Review the session and submit a new request when you are ready.", variant: "danger", blocksEnrichment: false };
    case "cancelled": return { label: "Request cancelled", message: "This request is no longer queued. You can preview and confirm a new request.", variant: "neutral", blocksEnrichment: false };
    case "complete": return { label: "Enrichment ready", message: "The enrichment result is available below.", variant: "success", blocksEnrichment: false };
    default: return { label: "Status unavailable", message: "Request status is unavailable. Refresh the status before submitting so an existing request is not duplicated.", variant: "neutral", blocksEnrichment: true };
  }
}

export function cloudProgressAction(progress: CloudEnrichmentProgress | undefined, enriched: boolean): string {
  if (!progress) return enriched ? "View enrichment" : "Enrich session";
  switch (progress.state) {
    case "idle": case "cancelled": case "failed_terminal": return "Enrich session";
    case "complete": return "View enrichment";
    case "pending": return "Queued · view status";
    case "sending": return "Uploading · view status";
    case "sent": return "Awaiting result · view status";
    case "failed_retryable": return "Retry needed · view status";
    case "reconfirmation_required": return "Review enrichment";
    default: return "View enrichment status";
  }
}
