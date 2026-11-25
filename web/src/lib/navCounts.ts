import { fmtInt } from "../../../shared/lib/format.ts";
import type { OpenIssueCounts, StatusSnapshot } from "./types.ts";

// navCounts.ts: the sidebar's count badges (the number in each nav row's
// right gutter), derived from one GET /api/status snapshot. Pure, so the
// Sidebar renders what this returns and the node tests pin it.
//
// Every Monitor, Analyze and Optimize page carries a badge, except the ones
// in UNBADGED_NAV_IDS (each with its reason). The Configure group stays
// unbadged: its pages hold settings, not records (Messages keeps its own
// unread badge, drawn by the Sidebar from the messages summary).
//
// Most badges are lifetime row counts; the ones that are not say so in
// their title (Live: the last 15 minutes, Overview: the last 24 hours,
// Code security: issues open now). A count the daemon did not send (an
// older daemon, or a build without the module) has no entry, so its badge
// hides instead of showing a bogus 0.

/** One nav row's badge: the number, and what it counts (the hover title
 *  and the screen-reader label). */
export type NavCount = { value: number; title: string };

/** A badge per nav item id; an id with no entry has no badge. */
export type NavCounts = Record<string, NavCount>;

/** The empty map, shared so a pending or failed read keeps one identity. */
export const NO_NAV_COUNTS: NavCounts = {};

function plural(n: number, one: string, many: string): string {
  return `${fmtInt(n)} ${n === 1 ? one : many}`;
}

const allTime = (n: number): string => `${fmtInt(n)} in total, all time`;

/** openIssuesTitle reads like the Code security page header: open issues,
 *  each counted once, with the critical and high ones named. */
export function openIssuesTitle(c: OpenIssueCounts): string {
  return `${plural(c.total, "open issue", "open issues")} (${fmtInt(c.critical)} critical, ${fmtInt(c.high)} high)`;
}

/** One badge rule: which nav item, how to read its number off the snapshot
 *  (null or undefined: no badge), and how its title says what it counts. */
type NavCountRule = {
  id: string;
  read: (s: StatusSnapshot) => number | null | undefined;
  title: (n: number, s: StatusSnapshot) => string;
};

// NAV_COUNT_RULES is the badge table, in nav order. Each row's comment says
// what the number is when it is not simply its page's own table.
const NAV_COUNT_RULES: readonly NavCountRule[] = [
  // Monitor
  // Sessions with any action, API turn or token row in the last 24 hours.
  {
    id: "overview",
    read: (s) => s.counts.active_sessions_24h,
    title: (n) => `${plural(n, "session", "sessions")} active in the last 24 hours`,
  },
  // The same activity definition over /api/live's 15-minute window.
  {
    id: "live",
    read: (s) => s.counts.live_sessions,
    title: (n) => `${plural(n, "session", "sessions")} active in the last 15 minutes`,
  },
  { id: "sessions", read: (s) => s.counts.sessions, title: allTime },
  { id: "actions", read: (s) => s.counts.actions, title: allTime },
  { id: "projects", read: (s) => s.counts.projects, title: allTime },
  // Guard verdicts (guard_events).
  { id: "security", read: (s) => s.counts.guard_events, title: allTime },
  // Open issues, counted as the page header counts them (by issue, open).
  {
    id: "code-security",
    read: (s) => s.counts.open_issues?.total,
    title: (n, s) =>
      openIssuesTitle({ total: n, critical: s.counts.open_issues?.critical ?? 0, high: s.counts.open_issues?.high ?? 0 }),
  },
  // The search corpus IS the FTS5 excerpt index, the same substrate the
  // Compression badge counts, surfaced here as "how much is searchable".
  { id: "search", read: (s) => s.counts.action_excerpts, title: allTime },
  // Analyze
  { id: "cost", read: (s) => s.counts.api_turns, title: allTime },
  // The coding plan and API balance accounts added on the page.
  { id: "plans", read: (s) => s.counts.plan_accounts, title: allTime },
  { id: "analysis", read: (s) => s.counts.token_usage, title: allTime },
  // Distinct tools that ever recorded an action.
  { id: "tools", read: (s) => s.per_tool_last_seen?.length ?? 0, title: allTime },
  // Optimize
  { id: "compression", read: (s) => s.counts.action_excerpts, title: allTime },
  { id: "cache", read: (s) => s.counts.cache_events, title: allTime },
  // The advisor's active suggestions (its digest's total).
  { id: "suggestions", read: (s) => s.counts.suggestions, title: allTime },
  { id: "routing", read: (s) => s.counts.router_decisions, title: allTime },
  { id: "benchmarks", read: (s) => s.counts.benchmark_runs, title: allTime },
  { id: "discovery", read: (s) => s.counts.file_state, title: allTime },
  // Learned project patterns (project_patterns), not projects.
  { id: "patterns", read: (s) => s.counts.project_patterns, title: allTime },
];

/** The nav ids navCounts can badge, in nav order. */
export const NAV_COUNT_IDS: readonly string[] = NAV_COUNT_RULES.map((r) => r.id);

/** The Monitor, Analyze and Optimize pages that carry no badge, and why. */
export const UNBADGED_NAV_IDS: Readonly<Record<string, string>> = {
  // /api/status must not read Plane A's separate obs store (the
  // tests/invariant/obs_boundary_test.go boundary), and the Egress page's
  // own read, /api/obs/egress/status, re-verifies the whole decision hash
  // chain on every call: too costly to poll from the always-mounted nav.
  egress: "no cheap count: the egress status read verifies the whole decision chain",
  // The rest of Your apps (Plane A lane B5): the same boundary keeps
  // /api/status off the obs store, and the pages' own reads are window
  // aggregates, not a count worth polling from the nav.
  "app-traces": "no cheap count: /api/status never reads the obs store (obs boundary)",
  "app-sessions": "no cheap count: /api/status never reads the obs store (obs boundary)",
  "app-analytics": "an aggregate page, not a list",
  "app-end-users": "no cheap count: /api/status never reads the obs store (obs boundary)",
  "app-evals": "no cheap count: /api/status never reads the obs store (obs boundary)",
  "app-scores": "no cheap count: /api/status never reads the obs store (obs boundary)",
  "app-prompts": "configuration, not records",
  "app-alerts": "the breaching state is the page's own evaluation, not a status count",
  "app-model-calls": "configuration, not records: the machine's app lanes",
  policies: "configuration, not records (moved from Configure into Your apps)",
};

/** navCounts maps each nav item id to its badge from one status snapshot. */
export function navCounts(s?: StatusSnapshot | null): NavCounts {
  if (!s?.counts) return NO_NAV_COUNTS;
  const out: NavCounts = {};
  for (const r of NAV_COUNT_RULES) {
    const n = r.read(s);
    if (n == null || !Number.isFinite(n)) continue;
    out[r.id] = { value: n, title: r.title(n, s) };
  }
  return out;
}
