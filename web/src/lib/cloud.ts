// Shared vocabulary for the node-local Cloud Intelligence surfaces (plan
// §6 CI-P5). The outbox state machine lives in internal/store/cloudlocal.go;
// this mirrors its closed vocabulary for the UI (chip tone + human meaning) so
// the config section and the session Cloud row read identically. Node-local
// only — nothing here reflects hosted-service state.

import { fetchJSON } from "@/lib/api";
import { fmtDateTime } from "@/lib/format";
import type {
  CloudActionResponse,
  CloudPreviewResponse,
  CloudPurpose,
  CloudStatusResponse,
  CloudSyncState,
} from "@/lib/types";

export type CloudChipVariant =
  | "neutral"
  | "success"
  | "warn"
  | "danger"
  | "info"
  | "accent";

type CloudStateMeta = {
  label: string;
  variant: CloudChipVariant;
  meaning: string;
};

// CLOUD_OUTBOX_STATES maps each outbox state to a chip tone + an honest,
// specific explanation. reconfirmation_required is the one that most needs its
// meaning spelled out — it is never auto-sent.
export const CLOUD_OUTBOX_STATES: Record<string, CloudStateMeta> = {
  pending: {
    label: "Queued",
    variant: "info",
    meaning:
      "Queued for upload. The next cloud sync will try to send this request.",
  },
  reconfirmation_required: {
    label: "Review needed",
    variant: "warn",
    meaning:
      "The session changed since you confirmed the preview (a local edit, a scrubber upgrade, a schema bump, or an invalidated receipt). It will never auto-send and the confirmed digests are never auto-updated - re-preview and confirm (`observer cloud consent --session <id>`) to re-enqueue the new bytes.",
  },
  sending: {
    label: "Uploading",
    variant: "info",
    meaning: "The rebuilt bytes matched the receipt and were handed off to upload.",
  },
  sent: {
    label: "Uploaded",
    variant: "info",
    meaning: "Upload accepted. This does not mean the enrichment result is ready.",
  },
  failed_retryable: {
    label: "Retry needed",
    variant: "warn",
    meaning: "The send failed with a retryable error class; the next sync may re-attempt it.",
  },
  failed_terminal: {
    label: "Failed",
    variant: "danger",
    meaning: "A terminal failure state; this item will not retry.",
  },
  cancelled: {
    label: "Cancelled",
    variant: "neutral",
    meaning:
      "Cancelled because its consent receipt was cancelled (e.g. consent revoked) while it was not yet terminal.",
  },
};

// cloudStateMeta returns the metadata for a state, defaulting to a neutral chip
// echoing the raw state for any value not in the closed set (honest, never
// fabricated).
export function cloudStateMeta(state: string): CloudStateMeta {
  return (
    CLOUD_OUTBOX_STATES[state] ?? {
      label: state,
      variant: "neutral",
      meaning: "Unknown outbox state.",
    }
  );
}

// CLOUD_PURPOSE_SETS mirrors the SINGLE table-driven source of truth for
// which purposes a chosen purpose discloses under — cmd/observer/cloud.go's
// cloudPurposeSet (structural → itself alone; bounded → itself plus
// structural, which it always implies). This copy exists ONLY so the UI can
// show an honest "which purposes still need a standing grant" line before
// Confirm; the server (internal/intelligence/dashboard/cloud_account.go,
// itself commented as mirroring cloudPurposeSet) is what actually computes
// and enforces the set — this table must never drift from that comment.
export const CLOUD_PURPOSE_SETS: Record<CloudPurpose, CloudPurpose[]> = {
  structural_activity_insights: ["structural_activity_insights"],
  bounded_context_enrichment: [
    "structural_activity_insights",
    "bounded_context_enrichment",
  ],
};

// CLOUD_PURPOSE_LABELS is the human-facing name for each purpose, used by the
// session-card purpose choice and the Settings consent-grants table.
export const CLOUD_PURPOSE_LABELS: Record<string, string> = {
  structural_activity_insights: "Title only",
  bounded_context_enrichment: "Title, tags and description",
};

// CLOUD_SYNC_POLL_MAX_MS bounds the client-side poll loop below at roughly
// the daemon's own cloudSyncTimeout (10 minutes) — a hung child should read
// as "taking a long time", never as an infinite spinner.
const CLOUD_SYNC_POLL_MAX_MS = 10 * 60 * 1000;
const CLOUD_SYNC_POLL_INTERVAL_MS = 2000;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// runCloudSync POSTs /api/cloud/sync and polls /api/cloud/sync/state every
// 2s until the run finishes, returning the final state. Shared by every
// "Sync now" affordance (the account card, the session-card row, and the
// tail of the Confirm-and-enrich flow) so they all drain/poll identically.
export async function runCloudSync(sessionId?: string): Promise<CloudSyncState> {
  await fetchJSON<CloudSyncState>("/api/cloud/sync", undefined, {
    method: "POST",
    ...(sessionId ? {
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ session_id: sessionId }),
    } : {}),
  });
  return pollCloudSync(sessionId);
}

// pollCloudSync polls an already-started sync run to completion — the tail
// half of runCloudSync, exposed separately for a caller (Confirm-and-enrich)
// that starts the run itself via a different endpoint sequence.
export async function pollCloudSync(sessionId?: string): Promise<CloudSyncState> {
  const deadline = Date.now() + CLOUD_SYNC_POLL_MAX_MS;
  for (;;) {
    const st = await fetchJSON<CloudSyncState>("/api/cloud/sync/state");
    if (sessionId && st.session_id !== sessionId) {
      throw new Error("Another sync has started. Check this session's enrichment status before retrying.");
    }
    if (!st.running) return st;
    if (Date.now() > deadline) {
      throw new Error(
        "Sync is taking longer than expected - check Settings → Cloud Intelligence for its status.",
      );
    }
    await sleep(CLOUD_SYNC_POLL_INTERVAL_MS);
  }
}

// cloudFmtWhen renders an RFC3339 timestamp for the node-local Cloud
// Intelligence surfaces — a one-line shim over the shared `fmtDateTime` (kept
// as its own export so every existing importer is unchanged; formerly its
// own toLocaleString() implementation, since folded into the shared helper
// every application surface now uses for an instant shown to a reader).
export function cloudFmtWhen(iso: string): string {
  return fmtDateTime(iso);
}

// cloudOutputTail returns the last chunk of a CLI command's combined output
// for an inline error line — the same "keep the tail" discipline the daemon
// itself uses for its own bounded buffers. "" in, "" out (never fabricates
// an error when the child produced none).
export function cloudOutputTail(output: string, maxChars = 400): string {
  const t = output.trim();
  if (t.length <= maxChars) return t;
  return "…" + t.slice(t.length - maxChars);
}

// cloudAuthorityMeta describes a session's data-authority classification for
// the session Cloud row badge.
export function cloudAuthorityMeta(authority: string): {
  label: string;
  variant: CloudChipVariant;
} {
  switch (authority) {
    case "personal":
      return { label: "personal", variant: "success" };
    case "org":
      return { label: "org-owned", variant: "neutral" };
    default:
      return { label: "unknown authority", variant: "neutral" };
  }
}

// cloudProviderNotAccepting reports whether a sync's output says the hosted
// enrichment provider is still behind the pre-approval boundary (the CLI
// prints "waiting on provider" / "not accepting jobs yet" for jobs parked
// provider_policy_unverified). The card uses it to say "queued, no result
// will come back yet" instead of implying a result is on its way.
export function cloudProviderNotAccepting(output: string): boolean {
  return /not accepting jobs yet|waiting on provider/.test(output);
}

// ---------------------------------------------------------------------------
// W2 value-upgrade additions (2026-09-15): the developer-facing enrichment
// POLICY (the standing INTENT for per-session enrichment — see migration
// 115's header comment) and the content-free "What we sent" ledger. These
// types mirror the Go wire shapes the dashboard now serves
// (internal/intelligence/dashboard/cloud_policy.go); they live here rather
// than in lib/types.ts (owned by another concurrent change) but are plain
// structural types, so they compose with the existing Cloud* types by
// intersection wherever a response gained new fields.
// ---------------------------------------------------------------------------

// CloudEnrichLevel mirrors store.CloudEnrichLevel — the closed three-value
// vocabulary for how much a background enrichment pass is allowed to send.
export type CloudEnrichLevel = "off" | "titles" | "excerpts";

// CloudEnrichPolicyView is the `policy` block GET /api/cloud/status now
// carries (null = no policy row yet, i.e. never turned on).
export type CloudEvidenceSettings = {
  version: number;
  user_messages: number;
  assistant_messages: number;
  failure_classes: number;
  action_summaries: number;
  excerpt_bytes: number;
  milestones: boolean;
  outcomes: boolean;
};

export type CloudEnrichPolicyView = {
  evidence_settings?: CloudEvidenceSettings | null;
  level: CloudEnrichLevel;
  background: boolean;
  policy_version: string;
  source: string;
  updated_at: string;
  since?: string;
};

// CloudStatusWithPolicy is CloudStatusResponse plus the three W2 additions
// (`policy`, `disclosure`, `policy_version`) the dashboard now serves on the
// same endpoint. Defined here as an intersection, rather than editing
// CloudStatusResponse itself, so this file stays the single owner of the W2
// wire additions.
export type CloudStatusWithPolicy = CloudStatusResponse & {
  policy: CloudEnrichPolicyView | null;
  disclosure: string;
  policy_version: string;
  // W3 (background by default, 2026-09-15): the outcome of the most recent
  // `observer cloud sync` run (dashboard-spawned, auto-sync, or manual — they
  // all write the same node-local row), null when it has never run.
  last_sync: CloudSyncLastView | null;
  // Honest, simply-derived provider posture: "waiting" iff the last sync
  // reported waiting_provider > 0; "accepting" iff it moved something (sent
  // or results) with waiting_provider == 0; "unknown" otherwise (never
  // synced, or nothing moved either way).
  provider_state: "accepting" | "waiting" | "unknown";
};

// CloudSyncLastView is the `last_sync` block on CloudStatusWithPolicy.
// Content-free: counts and a closed error class only.
export type CloudSyncLastView = {
  started_at: string;
  finished_at: string;
  ok: boolean;
  sent: number;
  waiting_provider: number;
  reconfirm: number;
  failed: number;
  results: number;
  sign_in_expired: boolean;
  error_class?: string;
};

// CLOUD_ENRICH_LEVEL_LABELS is the human-facing name for each policy level,
// shared by the Settings "Turn on Cloud Intelligence" card and the session
// card's "Uses your Cloud Intelligence setting" sub-line so the two surfaces
// never drift.
export const CLOUD_ENRICH_LEVEL_LABELS: Record<CloudEnrichLevel, string> = {
  off: "Off",
  titles: "Name and tag my sessions",
  excerpts: "Name, tag and describe my sessions",
};

// cloudPurposeForLevel maps a policy level to the consent purpose a
// background or one-click enrichment run at that level discloses under —
// the UI mirror of cmd/observer/cloud.go's PurposeName. "off" has no
// purpose (ok=false).
export function cloudPurposeForLevel(
  level: CloudEnrichLevel,
): CloudPurpose | null {
  if (level === "titles") return "structural_activity_insights";
  if (level === "excerpts") return "bounded_context_enrichment";
  return null;
}

// cloudEnable POSTs /api/cloud/enable — the dashboard equivalent of
// `observer cloud enable`. withExcerpts picks the "excerpts" vs "titles"
// level; background controls whether the daemon may enqueue enrichment on
// its own after a session ends.
export async function cloudEnable(
  withExcerpts: boolean,
  background: boolean,
  evidenceSettings?: CloudEvidenceSettings,
): Promise<CloudActionResponse> {
  return fetchJSON<CloudActionResponse>("/api/cloud/enable", undefined, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ with_excerpts: withExcerpts, background, evidence_settings: evidenceSettings }),
  });
}

// cloudDisable POSTs /api/cloud/disable — the dashboard equivalent of
// `observer cloud disable`. Cancels queued-but-unsent session evidence;
// never signs out and never deletes results already received.
export async function cloudDisable(): Promise<CloudActionResponse> {
  return fetchJSON<CloudActionResponse>("/api/cloud/disable", undefined, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({}),
  });
}

// cloudPreviewByReceipt POSTs /api/cloud/preview {receipt_id} — the ledger's
// "Show exact bytes" action. Rebuilds and previews the exact bytes a
// per-session receipt bound, locally and without any network call (same
// preview the session card runs by session id + purpose).
export async function cloudPreviewByReceipt(
  receiptID: string,
): Promise<CloudPreviewResponse> {
  return fetchJSON<CloudPreviewResponse>("/api/cloud/preview", undefined, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ receipt_id: receiptID }),
  });
}

// CloudLedgerReceipt is one consent receipt as the ledger reports it —
// content-free by construction (store.ListCloudLedger never selects payload
// bytes, titles, or excerpts).
export type CloudLedgerReceipt = {
  evidence_settings_json?: string;
  id: string;
  purpose: string;
  grant_mode: string;
  endpoint: string;
  created_at: string;
  review_at?: string | null;
  invalidated_at?: string | null;
  live: boolean;
};

// CloudLedgerItem is one outbox item queued under a ledger receipt.
export type CloudLedgerItem = {
  id: string;
  session_id: string;
  kind: string;
  state: string;
  retry_count: number;
  last_error?: string;
  created_at: string;
  updated_at: string;
};

// CloudLedgerResult is the current (non-superseded) synced result for a
// session_evidence receipt, if any has been pulled back.
export type CloudLedgerResult = {
  id: string;
  session_id: string;
  model_route: string;
  tokens: number;
  cost_usd: number;
  received_at: string;
};

// CloudLedgerEntry pairs one receipt with the outbox items queued under it
// and, when applicable, the result that came back.
export type CloudLedgerEntry = {
  receipt: CloudLedgerReceipt;
  items: CloudLedgerItem[];
  result: CloudLedgerResult | null;
};

// CloudLedgerResponse is GET /api/cloud/ledger.
export type CloudLedgerResponse = {
  entries: CloudLedgerEntry[];
  total_receipts: number;
};

// ---------------------------------------------------------------------------
// W3 additions (background by default, 2026-09-15): the Sessions-page poll
// that notices a newly-arrived enrichment result and raises a toast.
// ---------------------------------------------------------------------------

// CloudEventResult is one enrichment result GET /api/cloud/events reports.
export type CloudEventResult = {
  result_id: string;
  session_id: string;
  title: string;
  received_at: string;
};

// CloudEventsResponse is GET /api/cloud/events.
export type CloudEventsResponse = {
  results: CloudEventResult[];
  now: string;
};

// cloudFetchEvents polls GET /api/cloud/events. `since` omitted lets the
// server default to its own lookback window (currently 15 minutes).
export async function cloudFetchEvents(since?: string): Promise<CloudEventsResponse> {
  return fetchJSON<CloudEventsResponse>(
    "/api/cloud/events",
    since ? { since } : undefined,
  );
}

// ---------------------------------------------------------------------------
// W5 additions (value-upgrade plan, 2026-09-15): the account PLAN GET
// /api/cloud/status now carries, and the weekly project DIGESTS
// `observer cloud sync` pulls back for a project.
// ---------------------------------------------------------------------------

// CloudPlanView is the `plan` block GET /api/cloud/status now carries (null
// = unknown — no sync has ever reported a plan, or every usage fetch so far
// has failed). digest_weekly / results_retention_days stay nullable all the
// way here: null means "this device does not know", never a fabricated
// false/zero, so the UI must never render a "locked" card off a null value.
export type CloudPlanView = {
  name: string;
  label: string;
  daily_cap?: number;
  monthly_cap?: number;
  digest_weekly: boolean | null;
  results_retention_days: number | null;
  as_of?: string;
};

// CloudStatusWithDigestPlan extends CloudStatusWithPolicy with the `plan`
// field, defined as a further intersection (same reason CloudStatusWithPolicy
// itself is one) rather than editing CloudStatusResponse directly.
export type CloudStatusWithDigestPlan = CloudStatusWithPolicy & {
  plan: CloudPlanView | null;
};

// CloudDigestResult mirrors cloudcontract.DigestResult — the validated body
// of one weekly project digest.
export type CloudDigestResult = {
  headline: string;
  themes: string[];
  cost_trend: string;
  recurring_error_classes: string[];
  unfinished_threads: string[];
  suggested_next_session: string;
  session_count: number;
  period_start: string;
  period_end: string;
  confidence: "low" | "medium" | "high";
  limitations: string[];
  schema_version: string;
};

// CloudDigestEntry is one row GET /api/cloud/digests reports.
export type CloudDigestEntry = {
  id: string;
  local_project_id: string;
  cloud_project_id: string;
  period_start: string;
  period_end: string;
  received_at: string;
  result: CloudDigestResult;
};

// CloudDigestsResponse is GET /api/cloud/digests.
export type CloudDigestsResponse = {
  digests: CloudDigestEntry[];
};

// cloudFetchDigests fetches GET /api/cloud/digests. `projectRoot` follows
// the SAME convention every other dashboard filter uses — the project's
// root path, not an internal numeric id — and is resolved server-side;
// omitted, it lists digests across every project on this device.
export async function cloudFetchDigests(
  projectRoot?: string,
  limit?: number,
): Promise<CloudDigestsResponse> {
  const params: Record<string, string | number> = {};
  if (projectRoot) params.project = projectRoot;
  if (limit) params.limit = limit;
  return fetchJSON<CloudDigestsResponse>(
    "/api/cloud/digests",
    Object.keys(params).length ? params : undefined,
  );
}

// cloudEvidenceSettingsSummary describes a receipt's frozen limits without content.
export function cloudEvidenceSettingsSummary(raw: string): string {
  try {
    const s = JSON.parse(raw) as CloudEvidenceSettings;
    if (s.version !== 1) return "Evidence limits unavailable";
    return `Up to ${s.user_messages} user messages, ${s.assistant_messages} assistant replies, ${s.failure_classes} failure categories; ${s.action_summaries} tool summaries; ${s.excerpt_bytes} bytes per message. Milestones ${s.milestones ? "included" : "excluded"}; outcomes ${s.outcomes ? "included" : "excluded"}.`;
  } catch {
    return "Evidence limits unavailable";
  }
}
