// orgIntel.ts is the pure model of the node's ORG-PLANE Cloud Intelligence
// surface (Settings > Org enrichment, the global consent banner): the wire
// types of GET /api/intel/status and the copy tables both components render.
// No React, no fetch: node --test imports it directly.
//
// Design: docs/plans/cloud-intelligence-parity-design-2026-10-03.md sections
// 3.3 (consent and notice screens) and 3.7 (compulsory consent).

import { orgDisplayLabelSentence } from "./orgName.ts";
import type { Fix } from "./needsSetting.ts";
import { orgPlaceLink, placeLink, type OrgPlace, type Place } from "./settingsPlaces.ts";
import type { OrgIntelResultRow } from "./types";

export type OrgIntelClass = "unenrolled" | "individual" | "managed";

export type OrgIntelRequirement = {
  enabled: boolean;
  provider_label: string;
  model: string;
  evidence_level: string;
  purposes: string[];
  developer_actions: boolean;
  per_developer_daily_cap: number;
  require_individual_consent: boolean;
  requirement_version: number;
  required_since?: string;
  deadline_days: number;
  doc_version: number;
  received_at?: string;
  // Parity phase 4: the background sweep for this member (false = on demand
  // only) and its bounds (the node's defaults when the org sent none).
  background?: boolean;
  per_developer_monthly_cap?: number;
  quiet_minutes?: number;
  min_actions?: number;
  max_age_days?: number;
};

// OrgIntelRail is a managed machine's result-rail readout (ruling Q2): the
// reason in plain words when org enrichment does not run here.
export type OrgIntelRail = {
  on: boolean;
  reason: "on" | "no_policy" | "policy_not_in_force" | "no_authority" | "not_raised" | string;
  message: string;
};

export type OrgIntelConsent = {
  event: "accept" | "withdraw" | "leave" | string;
  requirement_version: number;
  evidence_level?: string;
  purposes?: string[];
  disclosure_digest?: string;
  consent_mode?: string;
  created_at: string;
};

export type OrgIntelReceipt = {
  kind: string;
  count: number;
  detail?: string;
  created_at: string;
};

export type OrgIntelStatus = {
  class: OrgIntelClass;
  org_name?: string;
  requirement?: OrgIntelRequirement;
  disclosure?: string;
  disclosure_digest?: string;
  org_enabled: boolean;
  required: boolean;
  pending: boolean;
  pending_reason?: "not_accepted" | "terms_changed" | string;
  covered: boolean;
  config_opt_in: boolean;
  effective_opt_in: boolean;
  notice_only: boolean;
  deadline_at?: string;
  deadline_passed: boolean;
  active?: OrgIntelConsent;
  history: OrgIntelConsent[];
  receipts: OrgIntelReceipt[];
  cached_results: number;
  managed_rail?: OrgIntelRail;
  note?: string;
  /** The team dashboard's origin, when the node knows a safe address. */
  org_dashboard?: string;
  /** "personal" when this machine is connected to the person's own
   *  personal dashboard (they are its only admin), else "team" or absent. */
  dashboard_kind?: string;
};

export type OrgIntelStatusResponse = {
  confirm_token: string;
  status: OrgIntelStatus;
};

// ORG_INTEL_LEVEL_LABELS names each evidence level in plain words (the CLI's
// orgIntelLevelLabel, cmd/observer/intel.go, and the org dashboard's
// evidenceLevelLabel say the same). "Title only" names a purpose, never a level.
export const ORG_INTEL_LEVEL_LABELS: Record<string, string> = {
  structural: "Metadata only",
  titles: "Metadata and first prompt",
  excerpts: "Metadata and bounded excerpts",
};

export function orgIntelLevelLabel(level: string | undefined): string {
  return ORG_INTEL_LEVEL_LABELS[level ?? ""] ?? ORG_INTEL_LEVEL_LABELS.structural;
}

// ORG_INTEL_PURPOSE_LABELS mirrors the personal plane's purpose names.
export const ORG_INTEL_PURPOSE_LABELS: Record<string, string> = {
  structural_activity_insights: "Title only",
  bounded_context_enrichment: "Title, tags and description",
};

export function orgIntelPurposeLabel(p: string): string {
  return ORG_INTEL_PURPOSE_LABELS[p] ?? p;
}

// orgIntelBackgroundLine says what the org's background sweep does for this
// member, in plain words.
export function orgIntelBackgroundLine(r: Pick<OrgIntelRequirement, "background" | "quiet_minutes" | "min_actions" | "max_age_days">): string {
  if (r.background === false) return "Off: sessions are enriched on demand only";
  const quiet = r.quiet_minutes ?? 30;
  const min = r.min_actions ?? 3;
  const age = r.max_age_days ?? 7;
  return `On: sessions idle ${quiet} min with at least ${min} actions, up to ${age} days old`;
}

// ORG_INTEL_EVENT_LABELS names each consent history event.
export const ORG_INTEL_EVENT_LABELS: Record<string, string> = {
  accept: "Accepted",
  withdraw: "Withdrawn",
  leave: "Ended (left the organization)",
};

// ORG_INTEL_RECEIPT_LABELS names each local audit receipt.
export const ORG_INTEL_RECEIPT_LABELS: Record<string, string> = {
  managed_notice_shown: "Organization notice shown",
  cache_swept_unconsented: "Results cached without your consent removed",
  cache_cleared_on_leave: "Results removed on leaving",
  consent_report_refused: "Consent could not be sent (retried on the next sync)",
  tombstones_applied: "Results the organization purged removed",
};

// orgIntelOrgName names the org through the one owner of that rule
// (orgDisplayLabel, T-160; review M4-14): an id-shaped value never renders.
export function orgIntelOrgName(st: Pick<OrgIntelStatus, "org_name">): string {
  return orgDisplayLabelSentence(st.org_name);
}

// orgIntelIsPersonal reports a personal dashboard: its org is named
// "Personal", so an org-level status names the dashboard instead and speaks
// to its only admin, the person (shared/lib/twoDashboards.ts wording).
export function orgIntelIsPersonal(st: Pick<OrgIntelStatus, "dashboard_kind"> | null | undefined): boolean {
  return st?.dashboard_kind === "personal";
}

// OrgIntelPhase is what the Settings section renders, decided by an ordered
// table (first match wins), one test row per entry.
export type OrgIntelPhase =
  | "unenrolled"
  | "no_terms"
  | "managed_notice"
  | "org_off"
  | "pending_required"
  | "terms_changed"
  | "accepted"
  | "not_opted_in";

const PHASE_RULES: ReadonlyArray<{ phase: OrgIntelPhase; match: (s: OrgIntelStatus) => boolean }> = [
  { phase: "unenrolled", match: (s) => s.class === "unenrolled" },
  { phase: "no_terms", match: (s) => !s.requirement },
  { phase: "managed_notice", match: (s) => s.notice_only },
  { phase: "terms_changed", match: (s) => s.pending && s.pending_reason === "terms_changed" },
  { phase: "pending_required", match: (s) => s.pending },
  { phase: "org_off", match: (s) => !s.org_enabled },
  { phase: "accepted", match: (s) => s.effective_opt_in },
  { phase: "not_opted_in", match: () => true },
];

export function orgIntelPhase(s: OrgIntelStatus): OrgIntelPhase {
  return PHASE_RULES.find((r) => r.match(s))!.phase;
}

export const ORG_INTEL_PHASES: readonly OrgIntelPhase[] = PHASE_RULES.map((r) => r.phase);

// OrgIntelFixRule is the way forward of a status: a place on this machine
// (the person changes it here) and/or a team-dashboard place (only the
// organization's admins change it). Neither means this page itself is the
// place (the consent card) or nothing is off.
type OrgIntelFixRule = { place?: Place; org?: OrgPlace };

// ORG_INTEL_PHASE_FIX is one row per Settings phase. A managed machine whose
// rail does not run is the org's to change (orgIntelFix).
export const ORG_INTEL_PHASE_FIX: Record<OrgIntelPhase, OrgIntelFixRule> = {
  unenrolled: { place: "account" },
  no_terms: { org: "org_session_enrichment" },
  managed_notice: {},
  org_off: { org: "org_session_enrichment" },
  pending_required: {},
  terms_changed: {},
  accepted: {},
  not_opted_in: {},
};

function fixOfRule(s: OrgIntelStatus, r: OrgIntelFixRule): Fix {
  return {
    settings: r.place ? placeLink(r.place) : null,
    org: r.org ? orgPlaceLink(s.org_dashboard, r.org, s.dashboard_kind) : null,
  };
}

// orgIntelFix is the way forward of the Settings section's status.
export function orgIntelFix(s: OrgIntelStatus): Fix {
  const phase = orgIntelPhase(s);
  if (phase === "managed_notice" && s.managed_rail && !s.managed_rail.on) {
    return fixOfRule(s, { org: "org_session_enrichment" });
  }
  return fixOfRule(s, ORG_INTEL_PHASE_FIX[phase]);
}

// orgIntelBanner is the global pending-consent banner (design 3.7 step 3):
// shown on every page while an individual node has a compulsory requirement
// it has not accepted. null when there is nothing to say.
export function orgIntelBanner(s: OrgIntelStatus | null | undefined): { title: string; text: string } | null {
  if (!s || s.class !== "individual" || !s.pending) return null;
  const org = orgIntelOrgName(s);
  if (s.pending_reason === "terms_changed") {
    return {
      title: "Updated terms",
      text: `${org} changed its AI summaries terms. Enrichment continues under the terms you accepted until you review the new ones.`,
    };
  }
  const deadline = s.deadline_passed
    ? " The deadline has passed, so the team may refuse this machine's data until you choose."
    : "";
  return {
    title: "Consent required",
    text: `${org} now requires AI summaries. Accept, or leave the team.${deadline}`,
  };
}

// orgIntelBannerDismissKey scopes a dismissal to the exact terms, so a newer
// requirement version shows the banner again.
export function orgIntelBannerDismissKey(s: OrgIntelStatus): string {
  return `sbo-intel-banner:${s.org_name ?? ""}:${s.requirement?.requirement_version ?? 0}:${s.pending_reason ?? ""}`;
}

// OrgSessionsBanner is the Sessions-list banner for org-plane sessions (ruling
// Q6): on an enrolled machine whose listed sessions are on the org plane it
// describes org enrichment, its state and the org's terms, never personal
// sign-in. mode "mixed" means personal sessions are listed too, so the page
// also shows the personal banner.
export type OrgSessionsBanner = {
  mode: "org" | "mixed";
  title: string;
  state: string;
  text: string;
  terms: string;
  link: string;
  /** The team-dashboard place, when only the organization's admins can
   *  change the state (not set up, off, not running). */
  org: Fix["org"];
};

// SESSIONS_BANNER_RULES decides the org banner's state, first match wins, one
// test row per entry.
const SESSIONS_BANNER_RULES: ReadonlyArray<{
  state: string;
  match: (s: OrgIntelStatus) => boolean;
  text: (s: OrgIntelStatus, org: string) => string;
  /** Set when only the organization's admins can change this state. */
  org?: OrgPlace;
}> = [
  {
    state: "Not set up",
    match: (s) => !s.requirement,
    text: (s, org) =>
      orgIntelIsPersonal(s)
        ? "Your personal dashboard has not published enrichment terms yet. Nothing is sent from this machine."
        : `${org} has not published enrichment terms yet. Nothing is sent from this machine.`,
    org: "org_session_enrichment",
  },
  {
    state: "Off",
    match: (s) => !s.org_enabled,
    text: (s, org) =>
      orgIntelIsPersonal(s)
        ? "Your personal dashboard has session enrichment off. Nothing is sent from this machine."
        : `${org} has team AI summaries turned off. Nothing is sent from this machine.`,
    org: "org_session_enrichment",
  },
  {
    state: "Not running",
    match: (s) => s.class === "managed" && !!s.managed_rail && !s.managed_rail.on,
    text: (s, org) => s.managed_rail?.message || `Team AI summaries are not running on this machine yet under ${org}'s terms.`,
    org: "org_session_enrichment",
  },
  {
    state: "Running",
    match: (s) => s.class === "managed",
    text: (_s, org) => `This machine is managed: ${org} decides, and team AI summaries run here under its terms. There is nothing to accept.`,
  },
  {
    state: "Terms changed",
    match: (s) => s.pending && s.pending_reason === "terms_changed",
    text: (_s, org) => `${org} changed its terms. Enrichment continues under the terms you accepted until you review the new ones in Settings, Team AI summaries.`,
  },
  {
    state: "Your answer needed",
    match: (s) => s.pending,
    text: (_s, org) => `${org} requires team AI summaries. Accept, or leave the team, in Settings, Team AI summaries.`,
  },
  {
    state: "Accepted",
    match: (s) => s.effective_opt_in,
    text: (_s, org) => `You accepted ${org}'s terms, so ${org} enriches these sessions on its own server and model.`,
  },
  {
    state: "Not accepted",
    match: () => true,
    text: (_s, org) => `You have not accepted ${org}'s terms, so nothing is sent from this machine for these sessions. Review them in Settings, Team AI summaries.`,
  },
];

const PLACE_TEAM_SUMMARIES = placeLink("team_summaries").href;

export const ORG_SESSIONS_BANNER_STATES: readonly string[] = SESSIONS_BANNER_RULES.map((r) => r.state);

// orgIntelSessionsBanner returns the org banner for the listed sessions'
// planes, or null when none of them is on the org plane (or the machine is not
// enrolled), in which case the page shows the personal banner alone.
export function orgIntelSessionsBanner(s: OrgIntelStatus | null | undefined, planes: readonly SessionEnrichPlane[]): OrgSessionsBanner | null {
  if (!s || s.class === "unenrolled" || !planes.includes("org")) return null;
  const org = orgIntelOrgName(s);
  const rule = SESSIONS_BANNER_RULES.find((r) => r.match(s))!;
  const mode = planes.includes("personal") ? "mixed" : "org";
  let text = rule.text(s, org);
  if (mode === "mixed") text += " Sessions marked personal use your own AI summaries, described below.";
  const r = s.requirement;
  const terms = r ? `${r.provider_label} / ${r.model} · ${orgIntelLevelLabel(r.evidence_level)} · Background: ${orgIntelBackgroundLine(r)}` : "";
  return {
    mode,
    title: `Team AI summaries · ${rule.state}`,
    state: rule.state,
    text,
    terms,
    link: PLACE_TEAM_SUMMARIES,
    org: rule.org ? orgPlaceLink(s.org_dashboard, rule.org, s.dashboard_kind) : null,
  };
}

// ---------------------------------------------------------------------------
// Parity phase 3: per-session org-plane actions (design 3.2). The wire types of
// GET /api/intel/session/{id}, GET /api/intel/preview, POST /api/intel/enrich
// and GET /api/intel/ledger, and the pure decisions the session card and the
// ledger render.

export type OrgIntelActions = {
  preview: boolean;
  enrich: boolean;
  needs_preview: boolean;
  reason?: string;
  reason_text?: string;
  // The way forward for `reason` (internal/orgintel.ActionReasonFix): a place
  // on this machine and/or the team-dashboard place only the org's admins
  // change. Read with needsSetting.fixOf.
  settings?: string;
  settings_label?: string;
  org_settings?: string;
  org_settings_label?: string;
  org_dashboard_kind?: string;
};

export type OrgIntelSubmission = {
  id: number;
  session_id: string;
  purpose: string;
  evidence_level: string;
  trigger: "background" | "developer" | string;
  state: string;
  reason?: string;
  job_id?: number;
  evidence_content_digest: string;
  upload_digest: string;
  size_bytes: number;
  attempts: number;
  next_at?: string;
  created_at: string;
  updated_at: string;
  bytes_held: boolean;
  bytes?: string;
};

export type OrgIntelSessionView = {
  session_id: string;
  authority: "org" | "personal" | "unknown" | string;
  org_name?: string;
  /** "personal" or "team" (OrgIntelStatus.dashboard_kind). */
  dashboard_kind?: string;
  class: OrgIntelClass;
  actions: OrgIntelActions;
  latest?: OrgIntelSubmission;
  submissions: number;
  enriched: boolean;
  // The cached org result (the same row GET /api/session/<id>/org-intel
  // carries); typed loosely here and mapped by the card.
  result?: OrgIntelResultRow;
};

export type OrgIntelSessionResponse = {
  confirm_token: string;
  session: OrgIntelSessionView;
};

export type OrgIntelPreview = {
  session_id: string;
  org_name?: string;
  evidence_level: string;
  purpose: string;
  evidence_content_digest: string;
  upload_digest: string;
  size_bytes: number;
  actions: number;
  excerpts: number;
  notice_only: boolean;
  bytes: string;
};

export type OrgIntelEnrichResult = {
  submission: OrgIntelSubmission;
  queued: boolean;
  sent: boolean;
  message: string;
};

export type OrgIntelLedger = {
  org_name?: string;
  rows: OrgIntelSubmission[];
};

export function orgIntelSessionPath(sessionId: string): string {
  return `/api/intel/session/${encodeURIComponent(sessionId)}`;
}

export function orgIntelPreviewPath(sessionId: string): string {
  return `/api/intel/preview?session_id=${encodeURIComponent(sessionId)}`;
}

export const ORG_INTEL_LEDGER_PATH = "/api/intel/ledger";

// ORG_INTEL_SUBMISSION_STATES names each outbox state in plain words, with
// the pill tone it renders in.
export const ORG_INTEL_SUBMISSION_STATES: Record<string, { label: string; tone: "neutral" | "info" | "success" | "warn" | "danger" }> = {
  pending: { label: "Queued", tone: "info" },
  failed_retryable: { label: "Waiting to retry", tone: "warn" },
  submitted: { label: "Sent", tone: "success" },
  duplicate: { label: "Already sent", tone: "neutral" },
  already_enriched: { label: "Already enriched", tone: "neutral" },
  refused: { label: "Refused", tone: "danger" },
};

export function orgIntelSubmissionState(state: string): { label: string; tone: "neutral" | "info" | "success" | "warn" | "danger" } {
  return ORG_INTEL_SUBMISSION_STATES[state] ?? { label: state, tone: "neutral" };
}

export const ORG_INTEL_TRIGGER_LABELS: Record<string, string> = {
  background: "Background",
  developer: "You",
};

// OrgIntelCardMode is what the session card shows, decided by an ordered table
// (first match wins), one test row per entry.
export type OrgIntelCardMode = "hidden" | "result_only" | "unavailable" | "actions";

const CARD_RULES: ReadonlyArray<{ mode: OrgIntelCardMode; match: (v: OrgIntelSessionView) => boolean }> = [
  // A session that is not the org's and has no cached org result: nothing to
  // say (the personal plane's own row covers it). Quiet by design.
  { mode: "hidden", match: (v) => v.authority !== "org" && !v.enriched },
  { mode: "result_only", match: (v) => v.authority !== "org" },
  // An org session the developer can do nothing with, and nothing to show
  // yet: say why once (an org that has not turned it on, consent not given).
  { mode: "unavailable", match: (v) => !v.actions.preview && !v.enriched && !v.latest },
  { mode: "actions", match: () => true },
];

export function orgIntelCardMode(v: OrgIntelSessionView): OrgIntelCardMode {
  return CARD_RULES.find((r) => r.match(v))!.mode;
}

export const ORG_INTEL_CARD_MODES: readonly OrgIntelCardMode[] = CARD_RULES.map((r) => r.mode);

// orgIntelEnrichButton decides the Enrich button: its label, whether it is
// enabled, and the hint under it. `previewDigest` is the upload digest of the
// preview on screen ("" when none).
export function orgIntelEnrichButton(
  v: OrgIntelSessionView,
  previewDigest: string,
): { show: boolean; label: string; enabled: boolean; hint?: string } {
  if (!v.actions.enrich) return { show: false, label: "", enabled: false };
  const label = v.enriched || v.latest ? "Re-enrich" : "Enrich";
  if (v.actions.needs_preview && !previewDigest) {
    return { show: true, label, enabled: false, hint: "Preview the evidence first; you confirm exactly what is sent." };
  }
  return { show: true, label: v.actions.needs_preview ? `Confirm and ${label.toLowerCase()}` : label, enabled: true };
}

// sessionEffectiveTitle is the Sessions list's title: the developer's own
// title, then the personal-plane AI title, then the org-plane AI title
// (design 3.2), with which source supplied it.
export function sessionEffectiveTitle(row: { title?: string; cloud_title?: string; org_title?: string }): {
  text: string;
  source: "user" | "cloud" | "org" | "none";
} {
  if (row.title) return { text: row.title, source: "user" };
  if (row.cloud_title) return { text: row.cloud_title, source: "cloud" };
  if (row.org_title) return { text: row.org_title, source: "org" };
  return { text: "", source: "none" };
}

// SessionEnrichPlane is which Cloud Intelligence plane a session belongs to
// (ruling Q3): a session captured while enrolled is the organization's, every
// other session is the developer's own personal plane.
export type SessionEnrichPlane = "org" | "personal";

export function sessionEnrichPlane(row: { enrich_plane?: string }): SessionEnrichPlane {
  return row.enrich_plane === "org" ? "org" : "personal";
}

// orgPlaneEnrichAction is the Sessions list button label for an org-plane
// session (the personal plane keeps lib/cloudProgress's labels).
export function orgPlaneEnrichAction(row: { org_title?: string }): string {
  return row.org_title ? "View team AI summaries" : "Team AI summaries";
}

// SESSION_ENRICH_PLANE_COPY says, on the button tooltip and in the drawer,
// which plane enriches the session.
export const SESSION_ENRICH_PLANE_COPY: Record<SessionEnrichPlane, { tooltip: string; drawerTitle: string; drawerNote: string }> = {
  org: {
    tooltip: "Captured while this machine was connected to a team: summarized by your team, on its own server and model",
    drawerTitle: "Team AI summaries",
    drawerNote:
      "This session was captured while this machine was connected to a team, so it belongs to the team: your team summarizes it on its own server and model, under the terms in Settings, Team AI summaries.",
  },
  personal: {
    tooltip: "Open this session's personal AI summaries status and controls",
    drawerTitle: "Session enrichment",
    drawerNote: "This session uses your personal AI summaries: you choose what is sent and when.",
  },
};
