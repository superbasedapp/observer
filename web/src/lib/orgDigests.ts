// Pure helpers for the developer's view of the weekly org project digests
// (T-490, GET /api/intel/digests). The org server scopes the rows to the
// projects this member works in; this file only decides what the card says.

import type { Place } from "./settingsPlaces.ts";

export const ORG_DIGESTS_PATH = "/api/intel/digests";

export type OrgDigest = {
  project_id: string;
  project_label?: string;
  week_start: string;
  period_end?: string;
  session_count: number;
  headline: string;
  themes?: string[];
  recurring_error_classes?: string[];
  unfinished_threads?: string[];
  suggested_next_session?: string;
  updated_at?: string;
};

export type OrgDigestsResponse = {
  state: string;
  org_name?: string;
  projects: number;
  withheld?: string;
  digests: OrgDigest[];
};

/** A notice the card shows instead of digests. `place` is where this
 *  machine changes it (settingsPlaces), when it can. */
export type OrgDigestNotice = { tone: "muted" | "warn"; text: string; place?: Place };

// NOTICE_RULES is an ordered table (first match wins): the sentence the card
// shows when it has no digest to render. null means "render the digests".
const NOTICE_RULES: ReadonlyArray<{ match: (r: OrgDigestsResponse) => boolean; notice: (org: string) => OrgDigestNotice | null }> = [
  { match: (r) => r.state === "not_enrolled", notice: () => ({ tone: "muted", text: "This machine is not connected to an organization, so there are no organization project digests here. Connect it in Settings > Account.", place: "account" }) },
  { match: (r) => r.state === "not_supported", notice: (org) => ({ tone: "muted", text: `${org} does not offer weekly project digests: its server predates them, or project digests are turned off. That is set on the online dashboard, not on this machine.` }) },
  { match: (r) => r.state === "auth_failed", notice: (org) => ({ tone: "warn", text: `${org} refused this machine's credentials. Check the connection in Settings > Account.`, place: "account" }) },
  { match: (r) => r.state === "channel_off", notice: (org) => ({ tone: "muted", text: `${org} has organization intelligence switched off. That is set on the online dashboard, not on this machine.` }) },
  { match: (r) => r.state === "unreachable" || r.state === "malformed", notice: (org) => ({ tone: "warn", text: `Could not read the digests from ${org} right now. Try again later.` }) },
  { match: (r) => r.state !== "ok", notice: () => ({ tone: "warn", text: "The digests are not available right now." }) },
  { match: (r) => r.withheld === "posture", notice: (org) => ({ tone: "muted", text: `${org} does not share its enrichment with this machine: it is enrolled as an individual without an organization enrichment consent.` }) },
  { match: (r) => r.projects === 0, notice: () => ({ tone: "muted", text: "No sessions from this machine's member in the last 90 days, so there is no project to show a digest for." }) },
  { match: (r) => r.digests.length === 0, notice: () => ({ tone: "muted", text: "No finished weekly digest yet for the projects you work in." }) },
  { match: () => true, notice: () => null },
];

export function orgDigestNotice(r: OrgDigestsResponse): OrgDigestNotice | null {
  const org = r.org_name?.trim() || "Your organization";
  return NOTICE_RULES.find((rule) => rule.match(r))!.notice(org);
}

export type OrgDigestProject = { projectId: string; label: string; latest: OrgDigest; previous: OrgDigest[] };

// groupOrgDigests folds the rows into one entry per project (the server sends
// newest week first per project), keeping the server's project order.
export function groupOrgDigests(rows: OrgDigest[]): OrgDigestProject[] {
  const out: OrgDigestProject[] = [];
  const index = new Map<string, OrgDigestProject>();
  for (const d of rows) {
    const hit = index.get(d.project_id);
    if (hit) {
      hit.previous.push(d);
      continue;
    }
    const p: OrgDigestProject = {
      projectId: d.project_id,
      label: d.project_label?.trim() || `Project ${d.project_id.slice(0, 8)}`,
      latest: d,
      previous: [],
    };
    index.set(d.project_id, p);
    out.push(p);
  }
  return out;
}

// weekLabel renders a digest's period ("Week of 2026-09-21 to 2026-09-27").
export function weekLabel(d: OrgDigest): string {
  return d.period_end ? `Week of ${d.week_start} to ${d.period_end}` : `Week of ${d.week_start}`;
}
